"""
Tests for Phase 6A Common Investigation Framework.
"""

import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from ctf_mentor.domain.investigation_models import (
    ConcreteInvestigationResult,
    InvestigationResult,
    InvestigationSession,
    InvestigationSessionStatus,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationTarget,
    TargetType,
)
from ctf_mentor.domain.models import ActionResult, Challenge, HintLevel
from ctf_mentor.investigation.investigation_handlers import (
    ConfirmStepResultTaskHandler,
    SubmitStepResultTaskHandler,
    register_phase6a_handlers,
)
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import SCHEMA_VERSION, initialize_schema
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.runtime.handler_registry import HandlerRegistry
from ctf_mentor.runtime.task_context import TaskContext, TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


@pytest.fixture
def db_conn():
    """Create in-memory SQLite connection initialized to schema v10."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def bb_repo(db_conn):
    return BlackboardRepository(db_conn)


@pytest.fixture
def seeded_challenge(bb_repo):
    ch_id = f"ch_6a_{uuid.uuid4().hex[:8]}"
    ch = Challenge(
        challenge_id=ch_id,
        name="Phase 6A Challenge",
        description="Phase 6A Test Challenge",
        category="web",
        global_hint_level=HintLevel.L3,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    bb_repo.create_challenge(ch)
    return ch_id


# ---------------------------------------------------------------------------
# A. Session Creation Tests
# ---------------------------------------------------------------------------


def test_session_creation_success(db_conn, seeded_challenge):
    """Test creating an InvestigationSession for a valid challenge."""
    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge, metadata={"env": "test"})

    assert sess is not None
    assert sess.session_id.startswith("sess_")
    assert sess.challenge_id == seeded_challenge
    assert sess.status == InvestigationSessionStatus.ACTIVE
    assert sess.metadata == {"env": "test"}

    fetched = inv_repo.get_session(sess.session_id, seeded_challenge)
    assert fetched is not None
    assert fetched.session_id == sess.session_id


def test_session_creation_invalid_challenge_fails(db_conn):
    """Test session creation for non-existent challenge fails closed."""
    inv_repo = InvestigationRepository(db_conn)
    with pytest.raises(ValueError) as exc:
        inv_repo.create_session_atomic("non_existent_ch_999")
    assert "does not exist" in str(exc.value)


def test_multiple_sessions_per_challenge(db_conn, seeded_challenge):
    """Test multiple investigation sessions can exist for a single challenge."""
    inv_repo = InvestigationRepository(db_conn)
    sess1 = inv_repo.create_session_atomic(seeded_challenge)
    sess2 = inv_repo.create_session_atomic(seeded_challenge)

    assert sess1.session_id != sess2.session_id
    assert sess1.challenge_id == seeded_challenge
    assert sess2.challenge_id == seeded_challenge


# ---------------------------------------------------------------------------
# B. Session Isolation Tests
# ---------------------------------------------------------------------------


def test_session_cross_challenge_isolation(db_conn, bb_repo, seeded_challenge):
    """Test retrieving session using mismatched challenge_id returns None."""
    ch_id_2 = f"ch_6a_other_{uuid.uuid4().hex[:8]}"
    bb_repo.create_challenge(
        Challenge(
            challenge_id=ch_id_2,
            name="Other Challenge",
            description="Other",
            category="web",
            global_hint_level=HintLevel.L1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    )

    inv_repo = InvestigationRepository(db_conn)
    sess1 = inv_repo.create_session_atomic(seeded_challenge)

    cross_fetched = inv_repo.get_session(sess1.session_id, ch_id_2)
    assert cross_fetched is None


# ---------------------------------------------------------------------------
# C. Target Model & Fail-Closed Validation Tests
# ---------------------------------------------------------------------------


def test_target_vocabulary_validation():
    """Test target validation for all closed TargetType values."""
    t_http = InvestigationTarget(TargetType.HTTP_TARGET, {"hostname": "target.com", "port": 80})
    assert t_http.target_type == TargetType.HTTP_TARGET

    with pytest.raises(ValueError):
        InvestigationTarget(TargetType.HTTP_TARGET, {"hostname": "target.com"})

    t_file = InvestigationTarget(TargetType.FILE_TARGET, {"path": "/var/log/app.log"})
    assert t_file.target_type == TargetType.FILE_TARGET
    with pytest.raises(ValueError):
        InvestigationTarget(TargetType.FILE_TARGET, {})

    t_pcap = InvestigationTarget(TargetType.PCAP_TARGET, {"pcap_path": "/dumps/traffic.pcap"})
    assert t_pcap.target_type == TargetType.PCAP_TARGET

    t_bin = InvestigationTarget(TargetType.BINARY_TARGET, {"binary_name": "elf_chall"})
    assert t_bin.target_type == TargetType.BINARY_TARGET

    t_mem = InvestigationTarget(TargetType.MEMORY_TARGET, {"dump_id": "mem_001"})
    assert t_mem.target_type == TargetType.MEMORY_TARGET

    t_cloud = InvestigationTarget(TargetType.CLOUD_TARGET, {"resource_id": "arn:aws:s3:::bucket"})
    assert t_cloud.target_type == TargetType.CLOUD_TARGET

    t_text = InvestigationTarget(TargetType.TEXT_TARGET, {"query_or_text": "search string"})
    assert t_text.target_type == TargetType.TEXT_TARGET

    with pytest.raises(ValueError):
        InvestigationTarget("UNKNOWN_TARGET", {"foo": "bar"})


# ---------------------------------------------------------------------------
# D. InvestigationStep & Full Lifecycle Tests (draft -> consumed)
# ---------------------------------------------------------------------------


def test_investigation_result_durable_persistence_and_raw_output_roundtrip(db_conn, seeded_challenge):
    """H1 & Test Quality: Test that InvestigationResult content (raw_output, outcome, provenance_hash) is durably persisted and re-readable."""
    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge)

    step_id = f"step_raw_{uuid.uuid4().hex[:8]}"
    step = InvestigationStep(
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        step_type="inspect_payload",
        target=InvestigationTarget(TargetType.HTTP_TARGET, {"hostname": "target.com", "port": 80}),
        rationale="Raw output persistence check",
        status=InvestigationStepStatus.DRAFT,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    inv_repo.create_step_atomic(step)
    inv_repo.approve_step_atomic(step_id, seeded_challenge)

    raw_marker = f"UNIQUE_RAW_OUTPUT_MARKER_{uuid.uuid4().hex}"
    result_id = f"res_dur_{uuid.uuid4().hex[:8]}"

    inv_result = ConcreteInvestigationResult(
        result_id=result_id,
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        outcome="success",
        raw_output=raw_marker,
        result_type="HTTP_RESPONSE",
        data_json='{"status_code": 200}',
        provenance_hash="hash_abc_123",
        submitted_by="investigator",
    )

    submit_res = inv_repo.submit_step_result_atomic(step_id, seeded_challenge, inv_result)
    assert submit_res["status"] == "result_submitted"

    # Re-read persisted result directly from InvestigationRepository
    persisted = inv_repo.get_result(step_id, seeded_challenge)
    assert persisted is not None
    assert persisted.result_id == result_id
    assert persisted.step_id == step_id
    assert persisted.session_id == sess.session_id
    assert persisted.challenge_id == seeded_challenge
    assert persisted.raw_output == raw_marker
    assert persisted.outcome == "success"
    assert persisted.result_type == "HTTP_RESPONSE"
    assert persisted.data_json == '{"status_code": 200}'
    assert persisted.provenance_hash == "hash_abc_123"
    assert persisted.submitted_by == "investigator"

    # Re-read directly via SQL query on investigation_results table to verify append-only DB storage
    row = db_conn.execute("SELECT raw_output, outcome_status, provenance_hash FROM investigation_results WHERE step_id = ?", (step_id,)).fetchone()
    assert row is not None
    assert row["raw_output"] == raw_marker
    assert row["outcome_status"] == "success"
    assert row["provenance_hash"] == "hash_abc_123"


def test_full_step_lifecycle_draft_to_consumed(db_conn, seeded_challenge):
    """H2: Test full approved lifecycle: draft -> pending_approval -> approved -> result_submitted -> confirming -> consumed."""
    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge)

    step_id = f"step_e2e_{uuid.uuid4().hex[:8]}"
    step = InvestigationStep(
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        step_type="analyze_dump",
        target=InvestigationTarget(TargetType.MEMORY_TARGET, {"dump_id": "mem_dump_01"}),
        rationale="Memory dump analysis",
        status=InvestigationStepStatus.DRAFT,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    # 1. draft -> pending_approval
    res1 = inv_repo.create_step_atomic(step)
    assert res1["status"] == "pending_approval"

    # 2. pending_approval -> approved
    inv_repo.approve_step_atomic(step_id, seeded_challenge)
    s2 = inv_repo.get_step(step_id, seeded_challenge)
    assert s2.status == InvestigationStepStatus.APPROVED

    # 3. approved -> result_submitted
    inv_result = ConcreteInvestigationResult(
        result_id=f"res_e2e_{uuid.uuid4().hex[:8]}",
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        outcome="success",
        raw_output="Dump analysis completed",
    )
    inv_repo.submit_step_result_atomic(step_id, seeded_challenge, inv_result)
    s3 = inv_repo.get_step(step_id, seeded_challenge)
    assert s3.status == InvestigationStepStatus.RESULT_SUBMITTED

    # 4. result_submitted -> confirming
    conf_res = inv_repo.confirm_step_result_atomic(step_id, seeded_challenge)
    assert conf_res["status"] == "confirming"
    token = conf_res["reservation_token"]

    s4 = inv_repo.get_step(step_id, seeded_challenge)
    assert s4.status == InvestigationStepStatus.CONFIRMING

    # 5. confirming -> consumed
    fin_res = inv_repo.finalize_step_confirmation_atomic(step_id, seeded_challenge, reservation_token=token)
    assert fin_res["status"] == "consumed"

    s5 = inv_repo.get_step(step_id, seeded_challenge)
    assert s5.status == InvestigationStepStatus.CONSUMED

    # 6. Verify consumed is terminal and immutable: further status update must fail closed via DB trigger!
    with pytest.raises(sqlite3.IntegrityError, match="terminal state is immutable"):
        db_conn.execute("UPDATE investigation_steps SET status = 'approved' WHERE step_id = ?", (step_id,))


def test_invalid_lifecycle_transitions_fail_closed(db_conn, seeded_challenge):
    """Test that invalid lifecycle transitions (e.g. submitting result for unapproved step) fail closed."""
    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge)

    step_id = f"step_inv_{uuid.uuid4().hex[:8]}"
    step = InvestigationStep(
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        step_type="inspect",
        target=InvestigationTarget(TargetType.TEXT_TARGET, {"query_or_text": "query"}),
        rationale="Invalid transition test",
        status=InvestigationStepStatus.DRAFT,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    inv_repo.create_step_atomic(step)  # status: pending_approval

    inv_result = ConcreteInvestigationResult(
        result_id="res_inv_1",
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        outcome="success",
        raw_output="unapproved result",
    )

    # Submitting result on pending_approval step MUST fail
    with pytest.raises(ValueError, match="Expected 'approved'"):
        inv_repo.submit_step_result_atomic(step_id, seeded_challenge, inv_result)

    # Confirming step not in result_submitted MUST fail
    with pytest.raises(ValueError, match="Expected 'result_submitted'"):
        inv_repo.confirm_step_result_atomic(step_id, seeded_challenge)

    # Finalizing step with invalid token MUST fail
    inv_repo.approve_step_atomic(step_id, seeded_challenge)
    inv_repo.submit_step_result_atomic(step_id, seeded_challenge, inv_result)
    inv_repo.confirm_step_result_atomic(step_id, seeded_challenge)

    with pytest.raises(ValueError, match="Stale or invalid reservation token"):
        inv_repo.finalize_step_confirmation_atomic(step_id, seeded_challenge, reservation_token="bogus_token_123")


# ---------------------------------------------------------------------------
# E. Protocol Compatibility Tests
# ---------------------------------------------------------------------------


def test_investigation_result_protocol_structural_compatibility():
    """M1: Test that InvestigationResult Protocol structural typing works with ConcreteInvestigationResult, ActionResult, and custom objects."""
    # 1. ConcreteInvestigationResult satisfies Protocol
    c_res = ConcreteInvestigationResult(
        result_id="r1",
        step_id="s1",
        session_id="sess1",
        challenge_id="ch1",
        outcome="success",
        raw_output="output",
    )
    assert isinstance(c_res, InvestigationResult)

    # 2. ActionResult satisfies Protocol (has result_id, challenge_id, outcome, raw_output)
    a_res = ActionResult(
        result_id="ar1",
        proposal_id="p1",
        challenge_id="ch1",
        raw_output="output",
        outcome="success",
    )
    assert isinstance(a_res, InvestigationResult)

    # 3. Custom domain class satisfying structural protocol
    class CustomDomainResult:
        def __init__(self):
            self.result_id = "custom_1"
            self.challenge_id = "ch1"
            self.outcome = "success"
            self.raw_output = "custom raw output"

    custom_obj = CustomDomainResult()
    assert isinstance(custom_obj, InvestigationResult)

    # 4. Incomplete object missing raw_output fails isinstance protocol check
    class IncompleteResult:
        def __init__(self):
            self.result_id = "inc_1"
            self.challenge_id = "ch1"
            self.outcome = "success"

    inc_obj = IncompleteResult()
    assert not isinstance(inc_obj, InvestigationResult)


# ---------------------------------------------------------------------------
# F. Cross-Challenge Result Rejection Test
# ---------------------------------------------------------------------------


def test_cross_challenge_result_rejection(db_conn, bb_repo, seeded_challenge):
    """Test submitting or getting results with cross-challenge IDs is rejected or isolated."""
    ch_id_2 = f"ch_6a_other_{uuid.uuid4().hex[:8]}"
    bb_repo.create_challenge(
        Challenge(
            challenge_id=ch_id_2,
            name="Other Challenge 3",
            description="Other",
            category="web",
            global_hint_level=HintLevel.L1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
    )

    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge)

    step_id = f"step_cross_res_{uuid.uuid4().hex[:8]}"
    step = InvestigationStep(
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        step_type="inspect",
        target=InvestigationTarget(TargetType.TEXT_TARGET, {"query_or_text": "text"}),
        rationale="Cross result check",
        status=InvestigationStepStatus.DRAFT,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    inv_repo.create_step_atomic(step)
    inv_repo.approve_step_atomic(step_id, seeded_challenge)

    inv_result = ConcreteInvestigationResult(
        result_id="res_cross_1",
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        outcome="success",
        raw_output="data",
    )
    inv_repo.submit_step_result_atomic(step_id, seeded_challenge, inv_result)

    # Fetching result using wrong challenge_id MUST return None
    assert inv_repo.get_result(step_id, ch_id_2) is None


# ---------------------------------------------------------------------------
# G. Migration Tests (v9 -> v10)
# ---------------------------------------------------------------------------


def test_v9_to_v10_migration_preserves_data():
    """Verify legacy v9 database upgrades cleanly to v10 with investigation_results table."""
    legacy_conn = sqlite3.connect(":memory:")
    legacy_conn.row_factory = sqlite3.Row
    legacy_conn.execute("PRAGMA foreign_keys = ON;")

    # Setup legacy schema v9
    legacy_conn.executescript("""
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_version (version, applied_at) VALUES (9, datetime('now'));

        CREATE TABLE challenges (
            challenge_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '', global_hint_level INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1, tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        INSERT INTO challenges (challenge_id, name, created_at, updated_at) VALUES ('ch_mig_v9', 'Mig Challenge v9', datetime('now'), datetime('now'));

        CREATE TABLE investigation_sessions (
            session_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}', CHECK (status IN ('active','paused','completed','terminated')),
            UNIQUE (session_id, challenge_id)
        );
        INSERT INTO investigation_sessions VALUES ('sess_v9_1', 'ch_mig_v9', 'active', datetime('now'), datetime('now'), '{}');
    """)
    legacy_conn.commit()

    # Upgrade to target schema version
    new_version = initialize_schema(legacy_conn)
    assert new_version == SCHEMA_VERSION == 10

    # Verify schema_version
    ver_row = legacy_conn.execute("SELECT version FROM schema_version;").fetchone()
    assert ver_row["version"] == 10

    # Verify foreign_key_check clean
    fk_violations = legacy_conn.execute("PRAGMA foreign_key_check;").fetchall()
    assert len(fk_violations) == 0

    # Verify investigation_results table exists
    tables = [r[0] for r in legacy_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "investigation_results" in tables

    # Verify existing session data preserved
    sess_row = legacy_conn.execute("SELECT status FROM investigation_sessions WHERE session_id='sess_v9_1';").fetchone()
    assert sess_row["status"] == "active"

    legacy_conn.close()


# ---------------------------------------------------------------------------
# H. Execution Boundary Verification
# ---------------------------------------------------------------------------


def test_execution_boundary_zero_external_adapters():
    """Verify Phase 6A modules do NOT import subprocess, socket, aiohttp, or httpx."""
    import inspect
    import ctf_mentor.domain.investigation_models as inv_models
    import ctf_mentor.persistence.investigation_repo as inv_repo
    import ctf_mentor.investigation.investigation_handlers as inv_handlers

    modules = [inv_models, inv_repo, inv_handlers]
    forbidden_terms = ["subprocess", "socket", "aiohttp", "httpx", "urllib.request", "playwright", "selenium"]

    for mod in modules:
        source = inspect.getsource(mod)
        for term in forbidden_terms:
            assert term not in source.lower(), f"Forbidden execution term {term!r} found in module {mod.__name__}"


# ---------------------------------------------------------------------------
# I. TaskManager Integration Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_taskmanager_executes_submit_and_confirm_step_result(db_conn, seeded_challenge):
    """Test TaskManager executes submit_step_result and confirm_step_result tasks and marks step as CONSUMED."""
    inv_repo = InvestigationRepository(db_conn)
    sess = inv_repo.create_session_atomic(seeded_challenge)

    step_id = f"step_tm_{uuid.uuid4().hex[:8]}"
    step = InvestigationStep(
        step_id=step_id,
        session_id=sess.session_id,
        challenge_id=seeded_challenge,
        step_type="inspect_headers",
        target=InvestigationTarget(TargetType.HTTP_TARGET, {"hostname": "target.com", "port": 80}),
        rationale="TM test step",
        status=InvestigationStepStatus.DRAFT,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    inv_repo.create_step_atomic(step)
    inv_repo.approve_step_atomic(step_id, seeded_challenge)

    registry = HandlerRegistry()
    register_phase6a_handlers(registry, inv_repo)

    task_mgr = TaskManager(
        db_connection=db_conn,
        handler_registry=registry,
        blackboard_repo=BlackboardRepository(db_conn),
    )

    # 1. TaskManager submit_step_result
    req_sub = TaskRequest(
        challenge_id=seeded_challenge,
        task_group_id="grp_tm_6a",
        task_type="submit_step_result",
        parameters={
            "step_id": step_id,
            "result_id": "res_tm_100",
            "outcome": "success",
            "raw_output": "HTTP/1.1 200 OK",
        },
    )

    task_sub = await task_mgr.submit(req_sub)
    final_sub = await task_mgr.wait_for(task_sub.task_id, timeout=5.0)
    assert final_sub is not None
    assert final_sub.status.value == "completed"

    step_after_sub = inv_repo.get_step(step_id, seeded_challenge)
    assert step_after_sub.status == InvestigationStepStatus.RESULT_SUBMITTED

    # 2. TaskManager confirm_step_result
    req_conf = TaskRequest(
        challenge_id=seeded_challenge,
        task_group_id="grp_tm_6a",
        task_type="confirm_step_result",
        parameters={
            "step_id": step_id,
        },
    )

    task_conf = await task_mgr.submit(req_conf)
    final_conf = await task_mgr.wait_for(task_conf.task_id, timeout=5.0)
    assert final_conf is not None
    assert final_conf.status.value == "completed"

    step_after_conf = inv_repo.get_step(step_id, seeded_challenge)
    assert step_after_conf.status == InvestigationStepStatus.CONSUMED

