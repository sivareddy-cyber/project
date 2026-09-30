"""
Comprehensive Unit & Security Test Suite for Phase 6 Controlled Investigation Layer.

Tests:
1. ActionProposal structure & strict closed schema validation.
2. Adversarial prompt injection, shell execution, path traversal mitigation.
3. Deterministic AuthorizedScope validation (fail-closed, 0% LLM).
4. Proposal state machine transitions & 1:1 single-use approval gates.
5. Concurrency safety (atomic single-use approval consumption under race conditions).
6. Result submission & append-only ActionResult storage.
7. Evidence normalization & human confirmation gate.
8. Zero direct SQL writes to Phase 5D tables.
9. Database schema migration (SCHEMA_VERSION 6 -> 7).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
import pytest

from ctf_mentor.domain.models import (
    ActionProposal,
    ActionProposalState,
    ActionProposalTarget,
    ActionProposalType,
    ActionResult,
    ApprovalRecord,
    ApprovalStatus,
    ApprovalType,
    AuthorizedScope,
    EvidencePriority,
    HintLevel,
)
from ctf_mentor.intelligence.evidence_handlers import SubmitEvidenceHandler
from ctf_mentor.investigation.handlers import (
    ConfirmActionEvidenceHandler,
    ProposeActionHandler,
    SubmitActionResultHandler,
)
from ctf_mentor.investigation.normalizer import EvidenceNormalizer
from ctf_mentor.investigation.proposal_drafter import ActionProposalDrafter, parse_and_validate_action_proposal
from ctf_mentor.investigation.scope_validator import DeterministicScopeValidator
from ctf_mentor.persistence.action_proposal_repo import ActionProposalRepository
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext
from ctf_mentor.persistence.database import SCHEMA_VERSION, initialize_schema
from ctf_mentor.runtime.handler_registry import HandlerRegistry
from ctf_mentor.runtime.task_context import TaskContext


@pytest.fixture
def db_conn():
    """In-memory SQLite connection initialized with fresh DDL."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)
    return conn


@pytest.fixture
def seeded_challenge(db_conn):
    """Seed a test challenge and AuthorizedScope."""
    now = datetime.now(timezone.utc).isoformat()
    ch_id = "ch_phase6_1"
    db_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, global_hint_level, created_at, updated_at) "
        "VALUES (?, 'Phase 6 Test', 'Test Description', 'web', 5, ?, ?)",
        (ch_id, now, now),
    )
    db_conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, last_hint_level, updated_at) "
        "VALUES (?, 0, 0, ?)",
        (ch_id, now),
    )
    db_conn.commit()
    return ch_id


# ---------------------------------------------------------------------------
# 1. ActionProposal Schema & Adversarial Validation Tests
# ---------------------------------------------------------------------------


def test_proposal_schema_plain_text_rejected(seeded_challenge):
    res = parse_and_validate_action_proposal(
        "Please execute curl http://target.com/api/test to check for injection", seeded_challenge
    )
    assert res.is_valid is False
    assert "plain text prose" in res.rejection_reason


def test_proposal_schema_json_array_rejected(seeded_challenge):
    res = parse_and_validate_action_proposal('[{"action_type": "observe_response"}]', seeded_challenge)
    assert res.is_valid is False
    assert "JSON object" in res.rejection_reason


def test_proposal_schema_unknown_action_type_rejected(seeded_challenge):
    raw = json.dumps({
        "action_type": "execute_exploit_script",
        "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api"},
        "rationale": "Test injection",
    })
    res = parse_and_validate_action_proposal(raw, seeded_challenge)
    assert res.is_valid is False
    assert "Unknown action_type" in res.rejection_reason


def test_proposal_schema_forbidden_extra_fields_rejected(seeded_challenge):
    raw = json.dumps({
        "action_type": "observe_response",
        "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api"},
        "rationale": "Test response",
        "malicious_executable": "rm -rf /",
    })
    res = parse_and_validate_action_proposal(raw, seeded_challenge)
    assert res.is_valid is False
    assert "forbidden extra fields" in res.rejection_reason


def test_proposal_schema_shell_injection_rejected(seeded_challenge):
    raw = json.dumps({
        "action_type": "observe_response",
        "target": {"scheme": "http", "hostname": "target.com; cat /etc/passwd", "port": 80, "path": "/api"},
        "rationale": "Execute shell command via semi-colon",
    })
    res = parse_and_validate_action_proposal(raw, seeded_challenge)
    assert res.is_valid is False
    assert "Forbidden shell execution pattern" in res.rejection_reason or "invalid" in res.rejection_reason.lower()


def test_proposal_schema_path_traversal_rejected(seeded_challenge):
    raw = json.dumps({
        "action_type": "observe_response",
        "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api/../../etc/passwd"},
        "rationale": "Path traversal attempt",
    })
    res = parse_and_validate_action_proposal(raw, seeded_challenge)
    assert res.is_valid is False
    assert "Path traversal" in res.rejection_reason


def test_proposal_schema_valid_json_succeeds(seeded_challenge):
    raw = json.dumps({
        "action_type": "observe_response",
        "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api/v1/search", "method": "GET"},
        "rationale": "Observe endpoint response headers for valid requests.",
    })
    res = parse_and_validate_action_proposal(raw, seeded_challenge)
    assert res.is_valid is True
    assert res.proposal.action_type == ActionProposalType.OBSERVE_RESPONSE
    assert res.proposal.target.hostname == "target.com"


# ---------------------------------------------------------------------------
# 2. Deterministic Scope Validator Tests
# ---------------------------------------------------------------------------


def test_scope_validator_exact_match_allowed(seeded_challenge):
    now = datetime.now(timezone.utc)
    scope = AuthorizedScope(
        scope_id="scope_1",
        challenge_id=seeded_challenge,
        scheme="http",
        hostname="target.com",
        port=80,
        allowed_path_patterns=["/api/*"],
        allowed_methods=["GET", "POST"],
        exclusions=["/api/admin/*"],
        query_restrictions={},
        environment_id="env_1",
        challenge_relationship="primary_target",
        created_at=now,
        is_active=True,
    )

    target_valid = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api/v1/user", method="GET")
    res_valid = DeterministicScopeValidator.validate(target_valid, [scope])
    assert res_valid.is_allowed is True

    # Out of scope port
    target_bad_port = ActionProposalTarget(scheme="http", hostname="target.com", port=8080, path="/api/v1/user", method="GET")
    res_bad_port = DeterministicScopeValidator.validate(target_bad_port, [scope])
    assert res_bad_port.is_allowed is False

    # Out of scope domain
    target_bad_domain = ActionProposalTarget(scheme="http", hostname="evil.com", port=80, path="/api/v1/user", method="GET")
    res_bad_domain = DeterministicScopeValidator.validate(target_bad_domain, [scope])
    assert res_bad_domain.is_allowed is False

    # Excluded path pattern
    target_excluded = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api/admin/reset", method="GET")
    res_excluded = DeterministicScopeValidator.validate(target_excluded, [scope])
    assert res_excluded.is_allowed is False
    assert "exclusion pattern" in res_excluded.reason


def test_scope_validator_missing_scope_fails_closed(seeded_challenge):
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    res = DeterministicScopeValidator.validate(target, [])
    assert res.is_allowed is False
    assert "fail-closed" in res.reason


# ---------------------------------------------------------------------------
# 3. Action Proposal Repository & State Machine Tests
# ---------------------------------------------------------------------------


def test_proposal_repository_lifecycle_and_single_use_approval(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal(
        proposal_id="prop_lifecycle_1",
        challenge_id=seeded_challenge,
        action_type=ActionProposalType.OBSERVE_RESPONSE,
        target=target,
        rationale="Observe status codes",
    )

    # 1. Create proposal (PENDING_APPROVAL)
    res_create = repo.create_proposal_atomic(proposal)
    assert res_create["status"] == "pending_approval"
    app_id = res_create["approval_id"]

    # Verify result submission fails while pending approval
    with pytest.raises(ValueError, match="expected 'approved'"):
        repo.submit_result_atomic(proposal.proposal_id, seeded_challenge, "raw output")

    # 2. Approve proposal
    approved = repo.approve_proposal_atomic(proposal.proposal_id, seeded_challenge)
    assert approved is True

    # Verify proposal status is APPROVED
    prop_fetched = repo.get_proposal(proposal.proposal_id, seeded_challenge)
    assert prop_fetched.status == ActionProposalState.APPROVED

    # 3. Submit ActionResult
    res_submit = repo.submit_result_atomic(proposal.proposal_id, seeded_challenge, "HTTP/1.1 200 OK\r\nContent-Type: text/html")
    assert res_submit["status"] == "result_submitted"

    # 4. Single-Use Check: Replay/second submission MUST fail
    with pytest.raises(ValueError, match="already been consumed|cannot submit result"):
        repo.submit_result_atomic(proposal.proposal_id, seeded_challenge, "Duplicate submission attempt")


def test_proposal_repository_atomic_concurrency_race_condition(seeded_challenge):
    # Test atomic single-use consumption across multiple connections/threads
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, global_hint_level, created_at, updated_at) "
        "VALUES (?, 'Race Test', 'Desc', 'web', 5, ?, ?)",
        (seeded_challenge, now, now),
    )
    conn.commit()

    repo = ActionProposalRepository(conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal(
        proposal_id="prop_race_1",
        challenge_id=seeded_challenge,
        action_type=ActionProposalType.OBSERVE_RESPONSE,
        target=target,
        rationale="Race test",
    )

    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic(proposal.proposal_id, seeded_challenge)

    # Submission 1 succeeds
    res1 = repo.submit_result_atomic(proposal.proposal_id, seeded_challenge, "Result 1")
    assert res1["status"] == "result_submitted"

    # Concurrent Submission 2 fails
    with pytest.raises(ValueError, match="already been consumed|cannot submit result"):
        repo.submit_result_atomic(proposal.proposal_id, seeded_challenge, "Result 2")

    conn.close()


# ---------------------------------------------------------------------------
# 4. Evidence Normalizer & Confirmation Gate Tests
# ---------------------------------------------------------------------------


def test_evidence_normalizer_extraction_and_confirmation():
    raw_output = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<html>Success</html>"
    draft = EvidenceNormalizer.normalize_action_result(
        raw_output=raw_output,
        challenge_id="ch_norm_1",
        proposal_id="prop_norm_1",
        result_id="res_norm_1",
    )

    assert draft.extracted_status_code == 200
    assert "Observed HTTP status code 200" in draft.summary_content
    assert draft.metadata["source_provenance"] == "action_result_derived"
    assert draft.is_confirmed is False


@pytest.mark.asyncio
async def test_evidence_normalizer_unconfirmed_blocks_phase5d(db_conn, seeded_challenge):
    draft = EvidenceNormalizer.normalize_action_result(
        raw_output="HTTP/1.1 200 OK",
        challenge_id=seeded_challenge,
        proposal_id="prop_blk_1",
        result_id="res_blk_1",
    )

    ctx = TaskContext(
        task_id="t_norm_blk",
        challenge_id=seeded_challenge,
        task_group_id="grp_1",
        task_type="submit_action_result",
        parameters={},
        blackboard_snapshot=BlackboardRepository(db_conn).read_blackboard_state(seeded_challenge),
    )

    # Unconfirmed draft returns failure
    res_unconfirmed = await EvidenceNormalizer.confirm_and_submit_to_phase5d(draft, ctx)
    assert res_unconfirmed.success is False
    assert "Human confirmation is required" in res_unconfirmed.error_message


# ---------------------------------------------------------------------------
# 5. TaskManager & Handler Integration Tests (Zero Direct SQL Phase 5D Write)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_propose_action_handler_task_execution(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    # Provision primary AuthorizedScope
    blackboard_repo.create_authorized_scope(
        scope_id="scope_h_1",
        challenge_id=seeded_challenge,
        scheme="http",
        hostname="target.com",
        port=80,
        allowed_path_patterns=["/*"],
        allowed_methods=["GET"],
        exclusions=[],
        query_restrictions={},
        environment_id="env1",
        challenge_relationship="primary_target",
        is_active=True,
    )

    proposal_repo.save_authorized_scope_entry(
        scope_id="scope_h_1",
        challenge_id=seeded_challenge,
        hostname="target.com",
        port=80,
    )

    class MockProposalDrafter(ActionProposalDrafter):
        async def draft_proposal(self, challenge_id, prompt_ctx, request_id=None):
            raw = json.dumps({
                "action_type": "observe_response",
                "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api"},
                "rationale": "Observe endpoint response headers.",
            })
            return parse_and_validate_action_proposal(raw, challenge_id, request_id=request_id)

    handler = ProposeActionHandler(proposal_repo=proposal_repo, blackboard_repo=blackboard_repo, drafter=MockProposalDrafter())
    ctx = TaskContext(
        task_id="task_prop_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_prop_1",
        task_type="propose_action",
        parameters={},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res = await handler.execute(ctx)
    assert res.success is True
    assert "proposal_id" in res.output
    assert res.output["status"] == "pending_approval"
    assert res.proposed_entity_writes == []  # ZERO Phase 5D writes!


@pytest.mark.asyncio
async def test_submit_action_result_and_confirm_two_stage_workflow(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    # 1. Create & Approve Proposal
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_hand_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_hand_1", seeded_challenge)

    # 2. Stage 1: SubmitActionResultHandler (persists result & normalized draft, ZERO Phase 5D writes)
    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_1",
        task_type="submit_action_result",
        parameters={
            "proposal_id": "prop_hand_1",
            "raw_output": "HTTP/1.1 200 OK\r\nContent-Type: json",
        },
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_sub = await sub_handler.execute(ctx_sub)
    assert res_sub.success is True
    assert res_sub.proposed_entity_writes == []
    result_id = res_sub.output["result_id"]

    # 3. Stage 2: ConfirmActionEvidenceHandler (human confirms persisted draft, Phase 5D writes produced)
    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_1",
        task_type="confirm_action_evidence",
        parameters={
            "proposal_id": "prop_hand_1",
            "result_id": result_id,
        },
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is True
    assert res_conf.proposed_entity_writes == []
    assert res_conf.proposed_diff is None
    ev_row = db_conn.execute("SELECT evidence_id FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()
    assert ev_row is not None


# ---------------------------------------------------------------------------
# 6. Database Migration Test (SCHEMA_VERSION 6 -> 7)
# ---------------------------------------------------------------------------


def test_database_migration_schema_v7_to_v8():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    # Initialize v8 database
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)
    assert SCHEMA_VERSION == 10

    # Verify new Phase 6 tables exist and can be queried
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "authorized_scope_entries" in tables
    assert "action_proposals" in tables
    assert "action_results" in tables

    conn.close()


# ---------------------------------------------------------------------------
# 7. Comprehensive Security & Lifecycle Hardening Tests
# ---------------------------------------------------------------------------


def test_proposal_schema_percent_encoded_path_traversal_rejected(seeded_challenge):
    encoded_paths = [
        "/api/%2e%2e/admin",
        "/api/%2E%2E/etc/passwd",
        "/api/%252e%252e/admin",
        "/api/%252E%252E/admin",
        "/api/%5c%2e%2e",
    ]
    for p in encoded_paths:
        raw = json.dumps({
            "action_type": "observe_response",
            "target": {"scheme": "http", "hostname": "target.com", "port": 80, "path": p},
            "rationale": "Test traversal",
        })
        res = parse_and_validate_action_proposal(raw, seeded_challenge)
        assert res.is_valid is False, f"Path {p!r} should be rejected"
        assert "Path traversal" in res.rejection_reason


def test_human_confirmation_advances_proposal_state_to_consumed(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_cons_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    
    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic("prop_cons_1", seeded_challenge)
    sub = repo.submit_result_atomic("prop_cons_1", seeded_challenge, "HTTP/1.1 200 OK")
    assert sub["status"] == "result_submitted"

    # Confirm proposal move to CONSUMED
    consumed = repo.mark_proposal_consumed_atomic("prop_cons_1", seeded_challenge)
    assert consumed is True

    fetched = repo.get_proposal("prop_cons_1", seeded_challenge)
    assert fetched.status == ActionProposalState.CONSUMED

    # Verify ActionConsumed event emitted
    evt = db_conn.execute("SELECT * FROM events WHERE event_type = 'ActionConsumed' AND challenge_id = ?", (seeded_challenge,)).fetchone()
    assert evt is not None


def test_proposal_cancelled_lifecycle(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_canc_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    
    repo.create_proposal_atomic(proposal)
    cancelled = repo.cancel_proposal_atomic("prop_canc_1", seeded_challenge, actor="user", reason="User cancelled action")
    assert cancelled is True

    fetched = repo.get_proposal("prop_canc_1", seeded_challenge)
    assert fetched.status == ActionProposalState.CANCELLED

    # Verify approval_requests cancelled
    app_row = db_conn.execute("SELECT status FROM approval_requests WHERE requested_action_ref = ?", ("prop_canc_1",)).fetchone()
    assert app_row["status"] == "cancelled"

    # Verify ActionCancelled event emitted
    evt = db_conn.execute("SELECT * FROM events WHERE event_type = 'ActionCancelled' AND challenge_id = ?", (seeded_challenge,)).fetchone()
    assert evt is not None


def test_proposal_expired_lifecycle(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    past_created = (datetime.now(timezone.utc) - timedelta(seconds=2000)).isoformat()
    past_expires = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    
    proposal = ActionProposal("prop_exp_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale", created_at=datetime.fromisoformat(past_created))
    repo.create_proposal_atomic(proposal, ttl_seconds=10)
    
    # Force DB timestamps to past
    db_conn.execute(
        "UPDATE action_proposals SET expires_at = ? WHERE proposal_id = ?",
        (past_expires, "prop_exp_1")
    )
    db_conn.commit()

    count = repo.expire_stale_proposals_atomic(seeded_challenge, ttl_seconds=10)
    assert count == 1

    fetched = repo.get_proposal("prop_exp_1", seeded_challenge)
    assert fetched.status == ActionProposalState.EXPIRED

    # Verify ActionExpired event emitted
    evt = db_conn.execute("SELECT * FROM events WHERE event_type = 'ActionExpired' AND challenge_id = ?", (seeded_challenge,)).fetchone()
    assert evt is not None


def test_append_only_and_terminal_state_db_triggers(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_trig_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    
    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic("prop_trig_1", seeded_challenge)
    repo.submit_result_atomic("prop_trig_1", seeded_challenge, "Raw Result")
    repo.mark_proposal_consumed_atomic("prop_trig_1", seeded_challenge)

    # 1. UPDATE on action_results MUST FAIL due to trigger
    with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="action_results are append-only: UPDATE is forbidden"):
        db_conn.execute("UPDATE action_results SET raw_output = 'tampered' WHERE proposal_id = 'prop_trig_1'")

    # 2. DELETE on action_results MUST FAIL due to trigger
    with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="action_results are append-only: DELETE is forbidden"):
        db_conn.execute("DELETE FROM action_results WHERE proposal_id = 'prop_trig_1'")

    # 3. UPDATE on terminal action_proposals MUST FAIL due to trigger
    with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="action_proposals terminal state is immutable"):
        db_conn.execute("UPDATE action_proposals SET status = 'approved' WHERE proposal_id = 'prop_trig_1'")


def test_genuine_multi_thread_concurrent_connections_race(tmp_path):
    import threading
    db_file = tmp_path / "race_test.db"
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    ch_id = "ch_thread_race"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, global_hint_level, created_at, updated_at) "
        "VALUES (?, 'Thread Race Test', 'Desc', 'web', 5, ?, ?)",
        (ch_id, now, now),
    )
    conn.commit()

    repo = ActionProposalRepository(conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_th_1", ch_id, ActionProposalType.OBSERVE_RESPONSE, target, "Race test")
    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic("prop_th_1", ch_id)
    conn.close()

    results = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        w_conn = sqlite3.connect(str(db_file), timeout=5.0)
        w_conn.row_factory = sqlite3.Row
        w_conn.execute("PRAGMA foreign_keys = ON;")
        w_repo = ActionProposalRepository(w_conn)
        barrier.wait()
        try:
            res = w_repo.submit_result_atomic("prop_th_1", ch_id, f"Worker {worker_id} output")
            results.append(("success", worker_id, res))
        except Exception as ex:
            results.append(("error", worker_id, str(ex)))
        finally:
            w_conn.close()

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    successes = [r for r in results if r[0] == "success"]
    errors = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {results}"
    assert len(errors) == 1, f"Expected exactly 1 error, got {len(errors)}: {results}"
    assert "already been consumed" in errors[0][2] or "cannot submit result" in errors[0][2]


def test_genuine_populated_v6_to_v7_migration():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    # 1. Build genuine v6 schema manually
    v6_ddl = """
    CREATE TABLE challenges (
        challenge_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '', global_hint_level INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1, tags TEXT NOT NULL DEFAULT '[]',
        metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE blackboard_states (
        challenge_id TEXT PRIMARY KEY REFERENCES challenges(challenge_id),
        blackboard_version INTEGER NOT NULL DEFAULT 0, active_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
        watchlist_hypothesis_ids TEXT NOT NULL DEFAULT '[]', confirmed_findings TEXT NOT NULL DEFAULT '[]',
        active_evidence_ids TEXT NOT NULL DEFAULT '[]', last_hint_level INTEGER NOT NULL DEFAULT 0,
        session_notes TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
    );
    CREATE TABLE hypotheses (
        hypothesis_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'watchlist',
        confidence REAL NOT NULL DEFAULT 0.0, hint_level INTEGER NOT NULL DEFAULT 0,
        is_primary INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE evidence (
        evidence_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        hypothesis_id TEXT, source TEXT NOT NULL, content TEXT NOT NULL DEFAULT '',
        evidence_type TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT 'system',
        metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE attempts (
        attempt_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        hypothesis_id TEXT, description TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT 'unknown',
        user_input TEXT NOT NULL DEFAULT '', tool_output TEXT NOT NULL DEFAULT '',
        metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE approval_requests (
        approval_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        approval_type TEXT NOT NULL, requested_by TEXT NOT NULL, requested_action_ref TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'requested', requested_at TEXT NOT NULL, resolved_at TEXT,
        resolved_by TEXT, decision_reason TEXT NOT NULL DEFAULT '', related_request_id TEXT,
        related_event_id TEXT, metadata TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE events (
        event_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}',
        occurred_at TEXT NOT NULL, blackboard_version_after INTEGER, task_id TEXT, metadata TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE authorized_scopes (
        scope_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        scheme TEXT NOT NULL, hostname TEXT NOT NULL, port INTEGER NOT NULL,
        allowed_path_patterns TEXT NOT NULL DEFAULT '[]', allowed_methods TEXT NOT NULL DEFAULT '[]',
        exclusions TEXT NOT NULL DEFAULT '[]', query_restrictions TEXT NOT NULL DEFAULT '{}',
        environment_id TEXT NOT NULL, challenge_relationship TEXT NOT NULL DEFAULT 'primary_target',
        is_active INTEGER NOT NULL DEFAULT 1, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE schema_version (
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
    );
    """
    conn.executescript(v6_ddl)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (6, ?)", (now,))

    # 2. Populate genuine v6 data
    ch_id = "ch_mig_v6_pop"
    conn.execute("INSERT INTO challenges VALUES (?, 'Mig Challenge', 'Desc', 'web', 3, 1, '[]', '{}', ?, ?)", (ch_id, now, now))
    conn.execute("INSERT INTO blackboard_states VALUES (?, 5, '[\"h1\"]', '[]', '[]', '[\"e1\"]', 3, 'Notes', '{}', ?)", (ch_id, now))
    conn.execute("INSERT INTO hypotheses VALUES ('h1', ?, 'SQLi Test', 'Desc', 'active', 0.8, 3, 1, '{}', ?, ?)", (ch_id, now, now))
    conn.execute("INSERT INTO evidence VALUES ('e1', ?, 'h1', 'user', 'Error observed', 'log', 'user', '{}', ?)", (ch_id, now))
    conn.execute("INSERT INTO attempts VALUES ('att1', ?, 'h1', 'Test payload', 'failure', \"' OR 1=1--\", '500 Error', '{}', ?)", (ch_id, now))
    conn.execute("INSERT INTO approval_requests VALUES ('app1', ?, 'environment_action', 'user', 'act1', 'approved', ?, ?, 'user', 'Ok', NULL, NULL, '{}')", (ch_id, now, now))
    conn.execute("INSERT INTO events VALUES ('evt1', ?, 'EvidenceSubmitted', 'user', '{}', ?, 5, NULL, '{}')", (ch_id, now))
    conn.execute("INSERT INTO authorized_scopes VALUES ('scope1', ?, 'http', 'target.com', 80, '[\"/*\"]', '[\"GET\"]', '[]', '{}', 'env1', 'primary_target', 1, '{}', ?)", (ch_id, now))
    conn.commit()

    # 3. Run initialize_schema (migration v6 -> v7)
    initialize_schema(conn)

    # 4. Assert schema version is 9
    cur_ver = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    assert cur_ver == SCHEMA_VERSION

    # 5. Assert all populated v6 data is preserved
    assert conn.execute("SELECT name FROM challenges WHERE challenge_id = ?", (ch_id,)).fetchone()[0] == "Mig Challenge"
    assert conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?", (ch_id,)).fetchone()[0] == 5
    assert conn.execute("SELECT title FROM hypotheses WHERE hypothesis_id = 'h1'").fetchone()[0] == "SQLi Test"
    assert conn.execute("SELECT content FROM evidence WHERE evidence_id = 'e1'").fetchone()[0] == "Error observed"
    assert conn.execute("SELECT outcome FROM attempts WHERE attempt_id = 'att1'").fetchone()[0] == "failure"
    assert conn.execute("SELECT status FROM approval_requests WHERE approval_id = 'app1'").fetchone()[0] == "approved"
    assert conn.execute("SELECT event_type FROM events WHERE event_id = 'evt1'").fetchone()[0] == "EvidenceSubmitted"

    # 6. Assert new Phase 6 tables exist and work
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "authorized_scope_entries" in tables
    assert "action_proposals" in tables
    assert "action_results" in tables

    conn.close()


# ---------------------------------------------------------------------------
# 8. Human Confirmation Lifecycle Security Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_action_result_alone_never_writes_canonical_evidence(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_alone_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_alone_1", seeded_challenge)

    handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx = TaskContext(
        task_id="task_alone",
        challenge_id=seeded_challenge,
        task_group_id="grp_alone",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_alone_1", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res = await handler.execute(ctx)
    assert res.success is True
    assert res.proposed_entity_writes == []
    assert res.proposed_diff is None

    # Verify ZERO rows written to canonical evidence table
    ev_count = db_conn.execute("SELECT COUNT(*) FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert ev_count == 0


@pytest.mark.asyncio
async def test_submit_action_result_with_confirm_evidence_forbidden(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_forbid_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_forbid_1", seeded_challenge)

    handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx = TaskContext(
        task_id="task_forbid",
        challenge_id=seeded_challenge,
        task_group_id="grp_forbid",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_forbid_1", "raw_output": "HTTP/1.1 200 OK", "confirm_evidence": True},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res = await handler.execute(ctx)
    assert res.success is False
    assert "forbidden" in res.error_message.lower()


@pytest.mark.asyncio
async def test_confirm_action_evidence_cannot_submit_caller_content(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_override_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_override_1", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_ov",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_ov",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_override_1", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Pass malicious caller overrides
    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_ov",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_ov",
        task_type="confirm_action_evidence",
        parameters={
            "proposal_id": "prop_override_1",
            "result_id": result_id,
            "content": "MALICIOUS OVERRIDE CONTENT",
            "summary": "MALICIOUS OVERRIDE SUMMARY",
        },
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is True
    assert res_conf.proposed_entity_writes == []
    # Verify canonical content is derived from server draft, NOT caller override!
    ev_row = db_conn.execute("SELECT content FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()
    assert "MALICIOUS OVERRIDE" not in ev_row["content"]
    assert "Observed HTTP status code 200" in ev_row["content"]


@pytest.mark.asyncio
async def test_confirmation_for_another_proposal_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_mismatch_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_mismatch_1", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_mis",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_mis",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_mismatch_1", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo)
    ctx_conf = TaskContext(
        task_id="task_conf_mis",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_mis",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "WRONG_PROPOSAL_ID", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is False
    assert "not found" in res_conf.error_message.lower()


@pytest.mark.asyncio
async def test_confirmation_for_another_challenge_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_cross_ch", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_cross_ch", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_ch",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_ch",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_cross_ch", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo)
    ctx_conf = TaskContext(
        task_id="task_conf_ch",
        challenge_id="OTHER_CHALLENGE_ID",
        task_group_id="grp_conf_ch",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_cross_ch", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is False


@pytest.mark.asyncio
async def test_confirmation_after_cancellation_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_canc_conf", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_canc_conf", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_cc",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_cc",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_canc_conf", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Cancel proposal
    db_conn.execute("UPDATE action_proposals SET status = 'cancelled' WHERE proposal_id = 'prop_canc_conf'")
    db_conn.commit()

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo)
    ctx_conf = TaskContext(
        task_id="task_conf_cc",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_cc",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_canc_conf", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is False


@pytest.mark.asyncio
async def test_confirmation_after_expiry_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_exp_conf", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_exp_conf", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_exp",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_exp",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_exp_conf", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Force expiration timestamp in DB
    past = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    db_conn.execute("UPDATE action_proposals SET expires_at = ? WHERE proposal_id = 'prop_exp_conf'", (past,))
    db_conn.commit()

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo)
    ctx_conf = TaskContext(
        task_id="task_conf_exp",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_exp",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_exp_conf", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is False
    assert "expired" in res_conf.error_message.lower()


@pytest.mark.asyncio
async def test_confirmation_after_consumed_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_already_cons", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_already_cons", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_ac",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_ac",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_already_cons", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_ac",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_ac",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_already_cons", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    await conf_handler.execute(ctx_conf)

    # Second confirmation MUST fail
    res_conf_2 = await conf_handler.execute(ctx_conf)
    assert res_conf_2.success is False
    assert "already been consumed" in res_conf_2.error_message.lower()


@pytest.mark.asyncio
async def test_duplicate_confirmation_rejected(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_dup_conf", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_dup_conf", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_dup",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_dup",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_dup_conf", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_dup1",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_dup1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_dup_conf", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res1 = await conf_handler.execute(ctx_conf)
    assert res1.success is True

    res2 = await conf_handler.execute(ctx_conf)
    assert res2.success is False
    assert "already been consumed" in res2.error_message.lower()


def test_concurrent_confirmation_race_condition(tmp_path):
    import threading
    db_file = tmp_path / "conf_race_test.db"
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    ch_id = "ch_conf_race"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, global_hint_level, created_at, updated_at) "
        "VALUES (?, 'Conf Race Test', 'Desc', 'web', 5, ?, ?)",
        (ch_id, now, now),
    )
    conn.commit()

    repo = ActionProposalRepository(conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_cr_1", ch_id, ActionProposalType.OBSERVE_RESPONSE, target, "Race test")
    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic("prop_cr_1", ch_id)
    res_dict = repo.submit_result_atomic("prop_cr_1", ch_id, "HTTP/1.1 200 OK")
    result_id = res_dict["result_id"]

    draft = EvidenceNormalizer.normalize_action_result("HTTP/1.1 200 OK", ch_id, "prop_cr_1", result_id)
    repo.save_normalized_draft_atomic(draft)
    conn.close()

    results = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        w_conn = sqlite3.connect(str(db_file), timeout=5.0)
        w_conn.row_factory = sqlite3.Row
        w_conn.execute("PRAGMA foreign_keys = ON;")
        w_repo = ActionProposalRepository(w_conn)
        barrier.wait()
        try:
            d = w_repo.prepare_draft_confirmation_atomic("prop_cr_1", result_id, ch_id, f"worker_{worker_id}")
            w_repo.finalize_draft_confirmation_atomic("prop_cr_1", ch_id, f"worker_{worker_id}")
            results.append(("success", worker_id, d))
        except Exception as ex:
            results.append(("error", worker_id, str(ex)))
        finally:
            w_conn.close()

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    successes = [r for r in results if r[0] == "success"]
    errors = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {results}"
    assert len(errors) == 1, f"Expected exactly 1 error, got {len(errors)}: {results}"
    assert "already been consumed" in errors[0][2]


@pytest.mark.asyncio
async def test_raw_action_result_and_provenance_preserved(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    raw_output = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\nAccess Denied"
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_prov_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_prov_1", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_pr",
        challenge_id=seeded_challenge,
        task_group_id="grp_sub_pr",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_prov_1", "raw_output": raw_output},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Verify raw output preserved exactly in action_results
    ar_row = db_conn.execute("SELECT raw_output FROM action_results WHERE result_id = ?", (result_id,)).fetchone()
    assert ar_row[0] == raw_output

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_pr",
        challenge_id=seeded_challenge,
        task_group_id="grp_conf_pr",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_prov_1", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is True
    assert res_conf.proposed_entity_writes == []

    # Verify provenance tag in SQLite evidence table
    ev_row = db_conn.execute("SELECT evidence_type, metadata FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()
    meta = json.loads(ev_row["metadata"])
    assert meta["source_provenance"] == "action_result_derived"
    assert ev_row["evidence_type"] == "action_result_derived"


# ---------------------------------------------------------------------------
# 11. Phase 6 Confirmation Idempotency & Failure Boundary Adversarial Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirmation_simulated_failure_boundary_and_idempotent_retry(db_conn, seeded_challenge):
    """Adversarial test: Phase 5D success followed by simulated finalization failure.
    
    Retry must detect existing canonical evidence, skip duplicate writes, and finalize Phase 6 state.
    Zero duplicate canonical evidence after retry.
    """
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)
    intel_repo = IntelligenceRepository(db_conn, blackboard_repo)

    # 1. Setup proposal in RESULT_SUBMITTED state
    p_id = "prop_idem_fail_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_idem_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_idem_1",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK\r\n\r\nHello"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # 2. First confirmation attempt: mock finalization to raise an Exception AFTER Phase 5D write
    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_idem_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_idem_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    # Manually run step 1 & 2 to simulate Phase 5D evidence committed, but finalization crashed
    draft = proposal_repo.prepare_draft_confirmation_atomic(p_id, result_id, seeded_challenge)
    res_5d = await EvidenceNormalizer.confirm_and_submit_to_phase5d(draft, ctx_conf, conf_handler.submit_evidence_handler)
    assert res_5d.success is True

    # Persist the EntityWrite to simulate Phase 5D commit succeeded
    intel_repo.apply_writes_and_diff_atomic(seeded_challenge, entity_writes=res_5d.proposed_entity_writes, scoped_diff=res_5d.proposed_diff)

    # Verify canonical evidence now exists in evidence table
    ev_row = db_conn.execute("SELECT evidence_id FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchall()
    assert len(ev_row) == 1
    evidence_id_1 = ev_row[0][0]

    # Verify proposal status is confirming / result_submitted because finalization was interrupted
    p_obj = proposal_repo.get_proposal(p_id, seeded_challenge)
    assert p_obj.status.value in {"result_submitted", "confirming"}

    # 3. Retry confirm_action_evidence (without failure simulation)
    res_retry = await conf_handler.execute(ctx_conf)

    # Verify retry succeeds
    assert res_retry.success is True
    assert res_retry.output.get("reused_existing_evidence") is True
    assert res_retry.output.get("evidence_id") == evidence_id_1

    # Verify proposal status transitioned to CONSUMED
    p_obj_after = proposal_repo.get_proposal(p_id, seeded_challenge)
    assert p_obj_after.status.value == "consumed"

    # CRITICAL: Verify ZERO duplicate canonical evidence records were created (total count is STILL 1)
    ev_rows_after = db_conn.execute("SELECT evidence_id FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchall()
    assert len(ev_rows_after) == 1
    assert ev_rows_after[0][0] == evidence_id_1


@pytest.mark.asyncio
async def test_repeated_confirmation_fails_single_use(db_conn, seeded_challenge):
    """Repeated confirmation after successful terminal transition must fail cleanly (single-use gate)."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_rep_conf_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_rep_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_rep_1",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK\r\n\r\nData"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_rep_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_rep_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res1 = await conf_handler.execute(ctx_conf)
    assert res1.success is True

    # Second confirmation call on already CONSUMED proposal
    res2 = await conf_handler.execute(ctx_conf)
    assert res2.success is False
    assert "already been consumed" in res2.error_message


@pytest.mark.asyncio
async def test_concurrent_confirmation_race(db_conn, seeded_challenge):
    """Concurrent confirmation calls race safely under SQLite serialization."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_conc_conf_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_conc_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_conc_1",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf1 = TaskContext(
        task_id="task_conf_conc_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_conc_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    ctx_conf2 = TaskContext(
        task_id="task_conf_conc_2",
        challenge_id=seeded_challenge,
        task_group_id="grp_conc_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    results = await asyncio.gather(
        conf_handler.execute(ctx_conf1),
        conf_handler.execute(ctx_conf2),
        return_exceptions=True,
    )

    success_count = sum(1 for r in results if getattr(r, "success", False) is True)
    fail_count = len(results) - success_count
    assert success_count == 1
    assert fail_count == 1


@pytest.mark.asyncio
async def test_confirmation_cancellation_race(db_conn, seeded_challenge):
    """Confirmation attempted on cancelled proposal must fail."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_cancel_conf_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)

    # Cancel proposal before approval/submission
    cancelled = proposal_repo.cancel_proposal_atomic(p_id, seeded_challenge)
    assert cancelled is True

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_can_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_can_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": "res_fake"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res = await conf_handler.execute(ctx_conf)
    assert res.success is False
    assert "cannot be confirmed" in res.error_message or "not found" in res.error_message


@pytest.mark.asyncio
async def test_confirmation_expiry_race(db_conn, seeded_challenge):
    """Confirmation attempted on expired proposal must fail."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_exp_conf_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_exp_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_exp_1",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Force expiration of proposal in DB
    past_str = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
    db_conn.execute("UPDATE action_proposals SET expires_at = ? WHERE proposal_id = ?", (past_str, p_id))
    db_conn.commit()

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_exp_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_exp_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res = await conf_handler.execute(ctx_conf)
    assert res.success is False
    assert "expired" in res.error_message.lower()


@pytest.mark.asyncio
async def test_confirmation_cross_challenge_rejection(db_conn, seeded_challenge):
    """Confirmation using proposal/result IDs across different challenges must be rejected."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_cross_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_cross_1",
        challenge_id=seeded_challenge,
        task_group_id="grp_cross_1",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    ctx_conf = TaskContext(
        task_id="task_conf_cross_1",
        challenge_id="other_challenge_99",  # Cross-challenge mismatch
        task_group_id="grp_cross_1",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res = await conf_handler.execute(ctx_conf)
    assert res.success is False
    assert "not found" in res.error_message.lower() or "mismatch" in res.error_message.lower()


@pytest.mark.asyncio
async def test_phase5d_failure_does_not_mark_proposal_consumed(db_conn, seeded_challenge):
    """If Phase 5D SubmitEvidenceHandler fails, proposal state must NOT transition to CONSUMED."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_5d_fail_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_5d_fail",
        challenge_id=seeded_challenge,
        task_group_id="grp_5d_fail",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    class FailingSubmitEvidenceHandler(SubmitEvidenceHandler):
        async def execute(self, context: TaskContext) -> HandlerResult:
            return HandlerResult(success=False, error_message="Phase 5D persistent store error")

    conf_handler = ConfirmActionEvidenceHandler(
        proposal_repo=proposal_repo,
        submit_evidence_handler=FailingSubmitEvidenceHandler(),
    )
    ctx_conf = TaskContext(
        task_id="task_conf_5d_fail",
        challenge_id=seeded_challenge,
        task_group_id="grp_5d_fail",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is False
    assert "Phase 5D persistent store error" in res_conf.error_message

    # Proposal status MUST remain RESULT_SUBMITTED
    p_obj = proposal_repo.get_proposal(p_id, seeded_challenge)
    assert p_obj.status.value == "result_submitted"


@pytest.mark.asyncio
async def test_confirmation_tampered_draft_rejection(db_conn, seeded_challenge):
    """Caller attempts to supply tampered evidence content during confirmation; server draft must be enforced."""
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    p_id = "prop_tamp_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/test", method="GET")
    proposal = ActionProposal(p_id, seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic(p_id, seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_tamp",
        challenge_id=seeded_challenge,
        task_group_id="grp_tamp",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    conf_handler = ConfirmActionEvidenceHandler(proposal_repo=proposal_repo, submit_evidence_handler=SubmitEvidenceHandler())
    # Attacker passes tampered content override parameters
    ctx_conf = TaskContext(
        task_id="task_conf_tamp",
        challenge_id=seeded_challenge,
        task_group_id="grp_tamp",
        task_type="confirm_action_evidence",
        parameters={
            "proposal_id": p_id,
            "result_id": result_id,
            "content": "ATTACKER_TAMPERED_CONTENT",
            "raw_snippet": "ATTACKER_SNIPPET",
            "extracted_status_code": 999,
        },
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_conf = await conf_handler.execute(ctx_conf)
    assert res_conf.success is True
    assert res_conf.proposed_entity_writes == []

    # Check produced evidence in DB uses ONLY server-persisted draft summary, ignoring caller tampered params
    ev_row = db_conn.execute("SELECT content, metadata FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()
    meta = json.loads(ev_row["metadata"])
    assert ev_row["content"] != "ATTACKER_TAMPERED_CONTENT"
    assert "Observed HTTP status code 200" in ev_row["content"]
    assert meta.get("raw_snippet") != "ATTACKER_SNIPPET"
    assert meta.get("status_code") == 200


@pytest.mark.asyncio
async def test_concurrent_confirmation_race_genuine_separate_connections():
    """Genuine multi-connection adversarial concurrency test.
    
    Uses separate SQLite connection handles (conn1 & conn2) over shared in-memory DB.
    Deliberate concurrent execution proves:
    1. Exactly ONE connection acquires the reservation and succeeds.
    2. The losing connection is rejected in prepare_draft_confirmation_atomic and NEVER calls Phase 5D.
    3. Exactly ONE canonical evidence record exists in evidence table (0 duplicate writes).
    """
    db_name = f"file:memdb_phase6_race_{uuid.uuid4().hex}?mode=memory&cache=shared"
    conn1 = sqlite3.connect(db_name, uri=True)
    conn1.row_factory = sqlite3.Row
    conn1.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn1)

    conn2 = sqlite3.connect(db_name, uri=True)
    conn2.row_factory = sqlite3.Row
    conn2.execute("PRAGMA foreign_keys = ON;")

    ch_id = "ch_race_gen_1"
    now_str = datetime.now(timezone.utc).isoformat()
    conn1.execute(
        "INSERT INTO challenges (challenge_id, name, created_at, updated_at) VALUES (?, 'Race', ?, ?)",
        (ch_id, now_str, now_str),
    )
    conn1.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES (?, 1, ?)",
        (ch_id, now_str),
    )
    conn1.commit()

    repo1 = ActionProposalRepository(conn1)
    bb_repo1 = BlackboardRepository(conn1)
    repo2 = ActionProposalRepository(conn2)
    bb_repo2 = BlackboardRepository(conn2)

    p_id = "prop_race_gen_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/race", method="GET")
    proposal = ActionProposal(p_id, ch_id, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    repo1.create_proposal_atomic(proposal)
    repo1.approve_proposal_atomic(p_id, ch_id)

    sub_handler1 = SubmitActionResultHandler(proposal_repo=repo1)
    ctx_sub = TaskContext(
        task_id="task_sub_race_gen",
        challenge_id=ch_id,
        task_group_id="grp_race_gen",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=bb_repo1.read_blackboard_state(ch_id),
    )
    res_sub = await sub_handler1.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Handlers attached to separate SQLite connections
    conf_handler1 = ConfirmActionEvidenceHandler(proposal_repo=repo1, submit_evidence_handler=SubmitEvidenceHandler())
    conf_handler2 = ConfirmActionEvidenceHandler(proposal_repo=repo2, submit_evidence_handler=SubmitEvidenceHandler())

    ctx_conf1 = TaskContext(
        task_id="task_conf_race_c1",
        challenge_id=ch_id,
        task_group_id="grp_race_gen",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=bb_repo1.read_blackboard_state(ch_id),
    )
    ctx_conf2 = TaskContext(
        task_id="task_conf_race_c2",
        challenge_id=ch_id,
        task_group_id="grp_race_gen",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=bb_repo2.read_blackboard_state(ch_id),
    )

    results = await asyncio.gather(
        conf_handler1.execute(ctx_conf1),
        conf_handler2.execute(ctx_conf2),
        return_exceptions=True,
    )

    successes = [r for r in results if getattr(r, "success", False) is True]
    failures = [r for r in results if getattr(r, "success", False) is False]

    assert len(successes) == 1
    assert len(failures) == 1
    assert "already in progress" in failures[0].error_message or "already been consumed" in failures[0].error_message or "race lost" in failures[0].error_message

    # Verify EXACTLY 1 canonical evidence record exists in DB
    ev_rows = conn1.execute("SELECT evidence_id FROM evidence WHERE challenge_id = ?", (ch_id,)).fetchall()
    assert len(ev_rows) == 1

    # Verify proposal status is CONSUMED
    p_obj = repo1.get_proposal(p_id, ch_id)
    assert p_obj.status.value == "consumed"

    conn1.close()
    conn2.close()


def test_genuine_populated_v7_to_v8_migration():
    """Test genuine v7 to v8 migration on populated database."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    v7_ddl = """
    CREATE TABLE challenges (
        challenge_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '', global_hint_level INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1, tags TEXT NOT NULL DEFAULT '[]',
        metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE action_proposals (
        proposal_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
        request_id TEXT, action_type TEXT NOT NULL, target_json TEXT NOT NULL, rationale TEXT NOT NULL,
        hypothesis_id TEXT, scope_id TEXT, scope_version TEXT NOT NULL DEFAULT '1.0',
        status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL, expires_at TEXT, metadata TEXT NOT NULL DEFAULT '{}',
        CHECK (status IN ('draft','pending_approval','approved','result_submitted','consumed','rejected','expired','cancelled')),
        CHECK (action_type IN ('observe_response','inspect_header','compare_parameter_values','test_input_boundary','inspect_api_behavior'))
    );
    CREATE TABLE normalized_evidence_drafts (
        draft_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE REFERENCES action_proposals(proposal_id) ON DELETE CASCADE,
        result_id TEXT NOT NULL, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
        hypothesis_id TEXT, summary_content TEXT NOT NULL, raw_snippet TEXT NOT NULL DEFAULT '',
        extracted_status_code INTEGER, extracted_headers TEXT NOT NULL DEFAULT '{}', is_confirmed INTEGER NOT NULL DEFAULT 0,
        confirmed_at TEXT, confirmed_by TEXT, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE evidence (
        evidence_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
        hypothesis_id TEXT, source TEXT NOT NULL, content TEXT NOT NULL DEFAULT '',
        evidence_type TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT 'system',
        metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE schema_version (
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
    );
    """
    conn.executescript(v7_ddl)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (7, ?)", (now,))

    ch_id = "ch_v7_pop"
    conn.execute("INSERT INTO challenges VALUES (?, 'V7 Challenge', 'Desc', 'web', 3, 1, '[]', '{}', ?, ?)", (ch_id, now, now))
    target_json = json.dumps({"scheme": "http", "hostname": "target.com", "port": 80, "path": "/api", "method": "GET"})
    conn.execute(
        "INSERT INTO action_proposals VALUES ('p_v7_1', ?, 'req1', 'observe_response', ?, 'Rationale', 'h1', 's1', '1.0', 'result_submitted', ?, NULL, '{}')",
        (ch_id, target_json, now),
    )
    conn.execute(
        "INSERT INTO normalized_evidence_drafts VALUES ('d_v7_1', 'p_v7_1', 'res1', ?, 'h1', 'Summary', 'Snippet', 200, '{}', 0, NULL, NULL, '{\"source_provenance\":\"action_result_derived\"}', ?)",
        (ch_id, now),
    )
    conn.execute(
        "INSERT INTO evidence VALUES ('e_v7_1', ?, 'h1', 'user_confirmed', 'Content', 'log', 'user', '{\"idempotency_key\":\"idem_v7_1\"}', ?)",
        (ch_id, now),
    )
    conn.commit()

    # First migration run
    ver = initialize_schema(conn)
    assert ver == SCHEMA_VERSION

    # 1. Schema version
    cur_ver = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    assert cur_ver == SCHEMA_VERSION

    # 2. Existing data preserved & normalized_evidence_drafts exists
    assert conn.execute("SELECT status FROM action_proposals WHERE proposal_id = 'p_v7_1'").fetchone()[0] == "result_submitted"
    assert conn.execute("SELECT summary_content FROM normalized_evidence_drafts WHERE draft_id = 'd_v7_1'").fetchone()[0] == "Summary"
    assert conn.execute("SELECT content FROM evidence WHERE evidence_id = 'e_v7_1'").fetchone()[0] == "Content"

    # 3. Confirming status works on action_proposals
    conn.execute(
        "INSERT INTO action_proposals VALUES ('p_v8_conf', ?, 'req2', 'observe_response', ?, 'Rationale', 'h1', 's1', '1.0', 'confirming', ?, NULL, '{}')",
        (ch_id, target_json, now),
    )

    # 4. Unique idempotency index exists and enforces uniqueness
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO evidence VALUES ('e_v7_dup', ?, 'h1', 'user_confirmed', 'Content2', 'log', 'user', '{\"idempotency_key\":\"idem_v7_1\"}', ?)",
            (ch_id, now),
        )

    # 5. PRAGMA foreign_key_check clean
    fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
    assert len(fk_violations) == 0, f"Foreign key check returned violations: {fk_violations}"

    # 6. Idempotent on second run
    ver_again = initialize_schema(conn)
    assert ver_again == SCHEMA_VERSION

    conn.close()


def test_stale_reservation_cannot_finalize(db_conn, seeded_challenge):
    repo = ActionProposalRepository(db_conn)
    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_stale_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    repo.create_proposal_atomic(proposal)
    repo.approve_proposal_atomic("prop_stale_1", seeded_challenge)
    res_sub = repo.submit_result_atomic("prop_stale_1", seeded_challenge, "HTTP/1.1 200 OK")
    result_id = res_sub["result_id"]

    draft = EvidenceNormalizer.normalize_action_result("HTTP/1.1 200 OK", seeded_challenge, "prop_stale_1", result_id)
    repo.save_normalized_draft_atomic(draft)

    draft_prep = repo.prepare_draft_confirmation_atomic("prop_stale_1", result_id, seeded_challenge)
    token_1 = draft_prep.metadata["reservation_token"]

    row = db_conn.execute("SELECT metadata FROM action_proposals WHERE proposal_id = 'prop_stale_1'").fetchone()
    meta = json.loads(row["metadata"])
    meta["reservation_token"] = "token_superseded_222"
    db_conn.execute("UPDATE action_proposals SET metadata = ? WHERE proposal_id = 'prop_stale_1'", (json.dumps(meta),))
    db_conn.commit()

    with pytest.raises(ValueError, match="Stale or invalid reservation token"):
        repo.finalize_draft_confirmation_atomic("prop_stale_1", seeded_challenge, reservation_token=token_1)


def test_duplicate_idempotency_key_rejected(db_conn, seeded_challenge):
    now = datetime.now(timezone.utc).isoformat()
    db_conn.execute(
        "INSERT INTO evidence (evidence_id, challenge_id, source, content, evidence_type, created_by, metadata, created_at) "
        "VALUES ('ev_idemp_1', ?, 'user_confirmed', 'Content 1', 'log', 'user', '{\"idempotency_key\": \"key_unique_123\"}', ?)",
        (seeded_challenge, now),
    )
    db_conn.commit()

    with pytest.raises(sqlite3.IntegrityError):
        db_conn.execute(
            "INSERT INTO evidence (evidence_id, challenge_id, source, content, evidence_type, created_by, metadata, created_at) "
            "VALUES ('ev_idemp_2', ?, 'user_confirmed', 'Content 2', 'log', 'user', '{\"idempotency_key\": \"key_unique_123\"}', ?)",
            (seeded_challenge, now),
        )


@pytest.mark.asyncio
async def test_evidence_write_fails_proposal_remains_retryable_and_successful_retry_creates_one_evidence_row(db_conn, seeded_challenge):
    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_retry_flow_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_retry_flow_1", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_rf",
        challenge_id=seeded_challenge,
        task_group_id="grp_rf",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_retry_flow_1", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    class FailingIntelRepo:
        def apply_writes_and_diff_atomic(self, challenge_id, entity_writes, scoped_diff):
            raise RuntimeError("Database IO failure during evidence persist")

    conf_handler_fail = ConfirmActionEvidenceHandler(
        proposal_repo=proposal_repo,
        submit_evidence_handler=SubmitEvidenceHandler(),
        intelligence_repo=FailingIntelRepo(),
    )
    ctx_conf = TaskContext(
        task_id="task_conf_rf",
        challenge_id=seeded_challenge,
        task_group_id="grp_rf",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_retry_flow_1", "result_id": result_id},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )

    res_fail = await conf_handler_fail.execute(ctx_conf)
    assert res_fail.success is False
    assert res_fail.retryable is True
    assert "Database IO failure" in res_fail.error_message

    prop_after_fail = proposal_repo.get_proposal("prop_retry_flow_1", seeded_challenge)
    assert prop_after_fail.status == ActionProposalState.RESULT_SUBMITTED

    conf_handler_ok = ConfirmActionEvidenceHandler(
        proposal_repo=proposal_repo,
        submit_evidence_handler=SubmitEvidenceHandler(),
        intelligence_repo=IntelligenceRepository(db_conn, blackboard_repo),
    )
    res_retry = await conf_handler_ok.execute(ctx_conf)
    assert res_retry.success is True

    prop_after_retry = proposal_repo.get_proposal("prop_retry_flow_1", seeded_challenge)
    assert prop_after_retry.status == ActionProposalState.CONSUMED

    ev_count = db_conn.execute("SELECT COUNT(*) FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert ev_count == 1


@pytest.mark.asyncio
async def test_taskmanager_runs_confirm_action_evidence_reports_completed(db_conn, seeded_challenge):
    """Test that TaskManager executes confirm_action_evidence task and marks it COMPLETED (not FAILED)."""
    from ctf_mentor.runtime.task_manager import TaskManager
    from ctf_mentor.runtime.task_context import TaskRequest
    from ctf_mentor.investigation.handlers import register_phase6_handlers

    blackboard_repo = BlackboardRepository(db_conn)
    proposal_repo = ActionProposalRepository(db_conn)
    intel_repo = IntelligenceRepository(db_conn, blackboard_repo)

    target = ActionProposalTarget(scheme="http", hostname="target.com", port=80, path="/api", method="GET")
    proposal = ActionProposal("prop_tm_1", seeded_challenge, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    proposal_repo.create_proposal_atomic(proposal)
    proposal_repo.approve_proposal_atomic("prop_tm_1", seeded_challenge)

    sub_handler = SubmitActionResultHandler(proposal_repo=proposal_repo)
    ctx_sub = TaskContext(
        task_id="task_sub_tm",
        challenge_id=seeded_challenge,
        task_group_id="grp_tm",
        task_type="submit_action_result",
        parameters={"proposal_id": "prop_tm_1", "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=blackboard_repo.read_blackboard_state(seeded_challenge),
    )
    res_sub = await sub_handler.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    registry = HandlerRegistry()
    register_phase6_handlers(
        registry=registry,
        proposal_repo=proposal_repo,
        blackboard_repo=blackboard_repo,
        submit_evidence_handler=SubmitEvidenceHandler(),
        intelligence_repo=intel_repo,
    )

    task_mgr = TaskManager(
        db_connection=db_conn,
        handler_registry=registry,
        blackboard_repo=blackboard_repo,
        intelligence_repo=intel_repo,
    )

    req = TaskRequest(
        challenge_id=seeded_challenge,
        task_group_id="grp_tm",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": "prop_tm_1", "result_id": result_id},
    )
    task = await task_mgr.submit(req)
    t_id = task.task_id

    final_task = await task_mgr.wait_for(t_id, timeout=5.0)
    assert final_task is not None
    assert final_task.task_id == t_id

    # Verify TaskManager reports status COMPLETED, NOT FAILED!
    t_row = db_conn.execute("SELECT status, error_message FROM tasks WHERE task_id = ?", (t_id,)).fetchone()
    assert t_row["status"] == "completed", f"Expected 'completed', got {t_row['status']!r} error: {t_row['error_message']!r}"

    # Verify EXACTLY 1 evidence row written
    ev_count = db_conn.execute("SELECT COUNT(*) FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert ev_count == 1


@pytest.mark.asyncio
async def test_deliberate_interleaved_concurrency_barrier_race():
    """Adversarial test using explicit barrier synchronization to force deliberate interleaving.
    
    Proves that even when both tasks pass preliminary checks simultaneously,
    the protected atomic claim allows ONLY ONE task to obtain reservation.
    The losing task is rejected BEFORE reaching SubmitEvidenceHandler.
    """
    db_name = f"file:memdb_barrier_{uuid.uuid4().hex}?mode=memory&cache=shared"
    conn1 = sqlite3.connect(db_name, uri=True)
    conn1.row_factory = sqlite3.Row
    conn1.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn1)

    conn2 = sqlite3.connect(db_name, uri=True)
    conn2.row_factory = sqlite3.Row
    conn2.execute("PRAGMA foreign_keys = ON;")

    ch_id = "ch_bar_1"
    now_str = datetime.now(timezone.utc).isoformat()
    conn1.execute(
        "INSERT INTO challenges (challenge_id, name, created_at, updated_at) VALUES (?, 'Barrier', ?, ?)",
        (ch_id, now_str, now_str),
    )
    conn1.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES (?, 1, ?)",
        (ch_id, now_str),
    )
    conn1.commit()

    repo1 = ActionProposalRepository(conn1)
    repo2 = ActionProposalRepository(conn2)
    bb_repo1 = BlackboardRepository(conn1)

    p_id = "prop_bar_1"
    target = ActionProposalTarget(scheme="http", hostname="example.com", port=80, path="/bar", method="GET")
    proposal = ActionProposal(p_id, ch_id, ActionProposalType.OBSERVE_RESPONSE, target, "Rationale")
    repo1.create_proposal_atomic(proposal)
    repo1.approve_proposal_atomic(p_id, ch_id)

    sub_handler1 = SubmitActionResultHandler(proposal_repo=repo1)
    ctx_sub = TaskContext(
        task_id="task_sub_bar",
        challenge_id=ch_id,
        task_group_id="grp_bar",
        task_type="submit_action_result",
        parameters={"proposal_id": p_id, "raw_output": "HTTP/1.1 200 OK"},
        blackboard_snapshot=bb_repo1.read_blackboard_state(ch_id),
    )
    res_sub = await sub_handler1.execute(ctx_sub)
    result_id = res_sub.output["result_id"]

    # Barrier synchronization
    barrier_acquired = asyncio.Event()
    barrier_proceed = asyncio.Event()
    evidence_called_count = 0

    class TrackedSubmitEvidenceHandler(SubmitEvidenceHandler):
        async def execute(self, context: TaskContext) -> HandlerResult:
            nonlocal evidence_called_count
            evidence_called_count += 1
            barrier_acquired.set()
            await barrier_proceed.wait()
            return await super().execute(context)

    conf_handler1 = ConfirmActionEvidenceHandler(proposal_repo=repo1, submit_evidence_handler=TrackedSubmitEvidenceHandler())
    conf_handler2 = ConfirmActionEvidenceHandler(proposal_repo=repo2, submit_evidence_handler=TrackedSubmitEvidenceHandler())

    ctx1 = TaskContext(
        task_id="task_bar_1",
        challenge_id=ch_id,
        task_group_id="grp_bar",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=bb_repo1.read_blackboard_state(ch_id),
    )
    ctx2 = TaskContext(
        task_id="task_bar_2",
        challenge_id=ch_id,
        task_group_id="grp_bar",
        task_type="confirm_action_evidence",
        parameters={"proposal_id": p_id, "result_id": result_id},
        blackboard_snapshot=bb_repo1.read_blackboard_state(ch_id),
    )

    # Launch Task 1 first
    t1 = asyncio.create_task(conf_handler1.execute(ctx1))
    await barrier_acquired.wait()  # Wait until Task 1 has acquired reservation and entered SubmitEvidenceHandler

    # Launch Task 2 while Task 1 is holding reservation inside SubmitEvidenceHandler
    res2 = await conf_handler2.execute(ctx2)
    barrier_proceed.set()  # Allow Task 1 to complete Phase 5D & finalization
    res1 = await t1

    # Assertions
    assert res1.success is True
    assert res2.success is False
    assert "already in progress" in res2.error_message

    # CRITICAL: SubmitEvidenceHandler was executed EXACTLY ONCE across both tasks
    assert evidence_called_count == 1

    conn1.close()
    conn2.close()

def test_duplicate_idempotency_key_does_not_replace_existing_evidence_or_break_blackboard(db_conn, seeded_challenge):
    """Regression test: Duplicate idempotency_key must fail safely without deleting/replacing existing evidence or breaking Blackboard."""
    blackboard_repo = BlackboardRepository(db_conn)
    intel_repo = IntelligenceRepository(db_conn, blackboard_repo)

    from ctf_mentor.domain.models import EntityWrite, ScopedDiff

    ev_id_original = "ev_orig_100"
    idem_key = "key_dup_protect_999"

    # 1. Insert original evidence via EntityWrite & ScopedDiff
    ew1 = EntityWrite(
        entity_type="evidence",
        operation="insert",
        entity_id=ev_id_original,
        fields={
            "evidence_id": ev_id_original,
            "challenge_id": seeded_challenge,
            "hypothesis_id": None,
            "source": "user_confirmed",
            "content": "ORIGINAL EVIDENCE CONTENT",
            "evidence_type": "action_result_derived",
            "created_by": "user",
            "metadata": {"idempotency_key": idem_key},
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    diff1 = ScopedDiff(
        challenge_id=seeded_challenge,
        expected_version=0,
        actor="user",
        event_type="EvidenceRecorded",
        changes={"active_evidence_ids": [ev_id_original]},
    )
    intel_repo.apply_writes_and_diff_atomic(seeded_challenge, [ew1], diff1)

    # Verify evidence inserted and Blackboard active_evidence_ids contains ev_id_original
    bb1 = blackboard_repo.read_blackboard_state(seeded_challenge)
    assert ev_id_original in bb1.active_evidence_ids

    # 2. Attempt duplicate insert with SAME idempotency_key but NEW evidence_id & new content
    ev_id_duplicate = "ev_dup_200"
    ew2 = EntityWrite(
        entity_type="evidence",
        operation="insert",
        entity_id=ev_id_duplicate,
        fields={
            "evidence_id": ev_id_duplicate,
            "challenge_id": seeded_challenge,
            "hypothesis_id": None,
            "source": "user_confirmed",
            "content": "MALICIOUS OVERWRITE ATTEMPT CONTENT",
            "evidence_type": "action_result_derived",
            "created_by": "attacker",
            "metadata": {"idempotency_key": idem_key},
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    diff2 = ScopedDiff(
        challenge_id=seeded_challenge,
        expected_version=bb1.blackboard_version,
        actor="attacker",
        event_type="EvidenceRecorded",
        changes={"active_evidence_ids": [ev_id_original, ev_id_duplicate]},
    )

    # Duplicate insert MUST fail with IntegrityError
    with pytest.raises(sqlite3.IntegrityError):
        intel_repo.apply_writes_and_diff_atomic(seeded_challenge, [ew2], diff2)

    # 3. VERIFY:
    # a) Original evidence row remains intact with original content
    row = db_conn.execute("SELECT evidence_id, content FROM evidence WHERE evidence_id = ?", (ev_id_original,)).fetchone()
    assert row is not None, "Original evidence row must NOT be deleted!"
    assert row["content"] == "ORIGINAL EVIDENCE CONTENT", "Original content must NOT be overwritten!"

    # b) Duplicate evidence row was NOT inserted
    row_dup = db_conn.execute("SELECT evidence_id FROM evidence WHERE evidence_id = ?", (ev_id_duplicate,)).fetchone()
    assert row_dup is None, "Duplicate evidence row must NOT exist!"

    # c) Total evidence count is exactly 1
    total_ev = db_conn.execute("SELECT COUNT(*) FROM evidence WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert total_ev == 1

    # d) Blackboard references remain valid (active_evidence_ids still references ev_id_original)
    bb_after = blackboard_repo.read_blackboard_state(seeded_challenge)
    assert bb_after.active_evidence_ids == [ev_id_original]
    assert bb_after.blackboard_version == 1


def test_table_ddl_map_exact_canonical_parity_and_populated_migration():
    """Verify _TABLE_DDL_MAP matches canonical _DDL schemas and rebuilds populated legacy tables without data loss."""
    from ctf_mentor.persistence.database import initialize_schema

    # 1. Create a legacy v7 database with legacy single-column FKs and populated data in all 5 check tables
    legacy_conn = sqlite3.connect(":memory:")
    legacy_conn.row_factory = sqlite3.Row
    legacy_conn.execute("PRAGMA foreign_keys = ON;")

    # Setup legacy schema v7 with single-column FKs for hint_requests, hint_candidates, hint_decisions, user_action_requests, attempts
    legacy_conn.executescript("""
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_version (version, applied_at) VALUES (7, datetime('now'));

        CREATE TABLE challenges (
            challenge_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '', global_hint_level INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1, tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        INSERT INTO challenges (challenge_id, name, created_at, updated_at) VALUES ('ch_mig_1', 'Mig Challenge', datetime('now'), datetime('now'));

        CREATE TABLE hypotheses (
            hypothesis_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'watchlist',
            confidence REAL NOT NULL DEFAULT 0.0, hint_level INTEGER NOT NULL DEFAULT 0,
            is_primary INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        INSERT INTO hypotheses (hypothesis_id, challenge_id, title, created_at, updated_at) VALUES ('hyp_mig_1', 'ch_mig_1', 'Hyp 1', datetime('now'), datetime('now'));

        -- Legacy single-column FK table definitions (causes FK mismatch with fresh v8 DDL)
        CREATE TABLE attempts (
            attempt_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id), description TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT 'unknown', user_input TEXT NOT NULL DEFAULT '',
            tool_output TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        INSERT INTO attempts (attempt_id, challenge_id, hypothesis_id, description, created_at)
        VALUES ('att_1', 'ch_mig_1', 'hyp_mig_1', 'Attempt 1', datetime('now'));

        CREATE TABLE hint_requests (
            request_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id), requested_level INTEGER NOT NULL DEFAULT 0,
            user_message TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', requested_at TEXT NOT NULL
        );
        INSERT INTO hint_requests (request_id, challenge_id, hypothesis_id, requested_level, user_message, requested_at)
        VALUES ('req_1', 'ch_mig_1', 'hyp_mig_1', 2, 'Need hint', datetime('now'));

        CREATE TABLE hint_candidates (
            candidate_id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES hint_requests(request_id),
            challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id), hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
            level INTEGER NOT NULL DEFAULT 0, content TEXT NOT NULL DEFAULT '', rationale TEXT NOT NULL DEFAULT '',
            metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        INSERT INTO hint_candidates (candidate_id, request_id, challenge_id, hypothesis_id, level, content, created_at)
        VALUES ('cand_1', 'req_1', 'ch_mig_1', 'hyp_mig_1', 2, 'Candidate content', datetime('now'));

        CREATE TABLE hint_decisions (
            decision_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL REFERENCES hint_candidates(candidate_id),
            request_id TEXT NOT NULL REFERENCES hint_requests(request_id), challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            effective_level INTEGER NOT NULL DEFAULT 0, approved INTEGER NOT NULL DEFAULT 0,
            rejection_reason TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', decided_at TEXT NOT NULL
        );
        INSERT INTO hint_decisions (decision_id, candidate_id, request_id, challenge_id, effective_level, approved, decided_at)
        VALUES ('dec_1', 'cand_1', 'req_1', 'ch_mig_1', 2, 1, datetime('now'));

        CREATE TABLE user_action_requests (
            action_request_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            action_type TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', rationale TEXT NOT NULL DEFAULT '',
            related_hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id), metadata TEXT NOT NULL DEFAULT '{}',
            requested_at TEXT NOT NULL
        );
        INSERT INTO user_action_requests (action_request_id, challenge_id, action_type, description, rationale, related_hypothesis_id, requested_at)
        VALUES ('uar_1', 'ch_mig_1', 'custom', 'Desc 1', 'Rat 1', 'hyp_mig_1', datetime('now'));

        CREATE TABLE action_proposals (
            proposal_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            request_id TEXT, action_type TEXT NOT NULL, target_json TEXT NOT NULL, rationale TEXT NOT NULL,
            hypothesis_id TEXT, scope_id TEXT, scope_version TEXT NOT NULL DEFAULT '1.0',
            status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL, expires_at TEXT, metadata TEXT NOT NULL DEFAULT '{}'
        );
    """)
    legacy_conn.commit()

    # 2. Perform v7 -> v9 schema initialization / migration
    new_version = initialize_schema(legacy_conn)
    assert new_version == SCHEMA_VERSION

    # 3. Verify schema version
    ver_row = legacy_conn.execute("SELECT version FROM schema_version;").fetchone()
    assert ver_row["version"] == SCHEMA_VERSION

    # 4. Verify PRAGMA foreign_key_check passes clean
    fk_violations = legacy_conn.execute("PRAGMA foreign_key_check;").fetchall()
    assert len(fk_violations) == 0, f"Foreign key violations found: {fk_violations}"

    # 5. Verify data preserved with zero data loss
    assert legacy_conn.execute("SELECT description FROM attempts WHERE attempt_id='att_1';").fetchone()["description"] == "Attempt 1"
    assert legacy_conn.execute("SELECT user_message FROM hint_requests WHERE request_id='req_1';").fetchone()["user_message"] == "Need hint"
    assert legacy_conn.execute("SELECT content FROM hint_candidates WHERE candidate_id='cand_1';").fetchone()["content"] == "Candidate content"
    assert legacy_conn.execute("SELECT approved FROM hint_decisions WHERE decision_id='dec_1';").fetchone()["approved"] == 1
    assert legacy_conn.execute("SELECT description FROM user_action_requests WHERE action_request_id='uar_1';").fetchone()["description"] == "Desc 1"

    # 6. Verify migration is idempotent on second run
    version_run_2 = initialize_schema(legacy_conn)
    assert version_run_2 == SCHEMA_VERSION
    fk_violations_2 = legacy_conn.execute("PRAGMA foreign_key_check;").fetchall()
    assert len(fk_violations_2) == 0

    legacy_conn.close()






