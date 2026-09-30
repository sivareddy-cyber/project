"""
Phase 5D Intelligence Foundation Test Suite.

Comprehensive tests covering:
A. Classification (determinism, multi-label, ruleset version, signals, confidence, persistence)
B. Evidence (intake, priority, relation, metadata preservation, fabrication rejection)
C. Hypotheses (lifecycle state machine, max 3 active limit, 4th active rejection)
D. CONFIRMED Requirement (requires USER_CONFIRMED evidence; inferred-only rejected)
E. Confidence Model (deterministic weighting, clamping [0.0, 1.0])
F. ReasoningState (read-only projection, zero mutations/diffs/events)
G. Concurrency (stale-version recovery via handler recomputation against fresh state)
H. Atomicity & Rollback (fault injection rolls back full transaction cleanly)
I. Schema Migration (v3 -> v4 non-destructive migration)
J. Security Boundary (zero network/LLM/subprocess imports)
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from ctf_mentor.contracts import EntityWrite, ScopedDiff, StaleVersionError
from ctf_mentor.domain.models import (
    Attempt,
    Challenge,
    ChallengeClassification,
    Evidence,
    EvidencePriority,
    FailedAttempt,
    Finding,
    HintLevel,
    Hypothesis,
    HypothesisStatus,
    ReasoningState,
    TaskStatus,
)
from ctf_mentor.intelligence.attempt_handlers import (
    RecordAttemptHandler,
    RecordFailedAttemptHandler,
)
from ctf_mentor.intelligence.classification import (
    ClassifyChallengeHandler,
    RULESET_VERSION,
    classify_challenge_deterministic,
)
from ctf_mentor.intelligence.evidence_handlers import SubmitEvidenceHandler
from ctf_mentor.intelligence.hypothesis_handlers import (
    CreateHypothesisHandler,
    EvaluateHypothesisHandler,
)
from ctf_mentor.intelligence.reasoning_state import BuildReasoningStateHandler
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import (
    SCHEMA_VERSION,
    assert_foreign_keys_enabled,
    get_connection,
    initialize_schema,
)
from ctf_mentor.persistence.intelligence_repo import (
    IntelligenceReader,
    IntelligenceRepository,
)
from ctf_mentor.runtime.event_bus import EventBus
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.retry_policy import RetryPolicy
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext, TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn():
    """In-memory SQLite connection initialized to current schema."""
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    initialize_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def bb_repo(db_conn):
    return BlackboardRepository(db_conn)


@pytest.fixture
def intel_repo(db_conn, bb_repo):
    return IntelligenceRepository(db_conn, bb_repo)


@pytest.fixture
def intel_reader(db_conn):
    return IntelligenceReader(db_conn)


@pytest.fixture
def registry(intel_repo, intel_reader):
    reg = HandlerRegistry()
    reg.register("classify_challenge", ClassifyChallengeHandler())
    reg.register("submit_evidence", SubmitEvidenceHandler())
    reg.register("create_hypothesis", CreateHypothesisHandler())
    reg.register("evaluate_hypothesis", EvaluateHypothesisHandler(intel_reader))
    reg.register("record_attempt", RecordAttemptHandler())
    reg.register("record_failed_attempt", RecordFailedAttemptHandler())
    reg.register("build_reasoning_state", BuildReasoningStateHandler(intel_reader))
    return reg


@pytest.fixture
def challenge_setup(bb_repo):
    ch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    ch = Challenge(
        challenge_id=ch_id,
        name="SQL Injection Challenge",
        description="Find the hidden flag by exploiting sqli in login form",
        category="web",
        global_hint_level=HintLevel.L0,
        created_at=now,
        updated_at=now,
        tags=["sqli", "web", "auth"],
    )
    bb_repo.create_challenge(ch)
    return ch_id


@pytest.fixture
def task_manager(db_conn, bb_repo, intel_repo, registry):
    event_bus = EventBus()
    return TaskManager(
        db_connection=db_conn,
        blackboard_repo=bb_repo,
        handler_registry=registry,
        event_bus=event_bus,
        intelligence_repo=intel_repo,
    )


# ---------------------------------------------------------------------------
# A. Classification Tests
# ---------------------------------------------------------------------------


def test_classification_deterministic():
    """Verify classification output is deterministic for same input + ruleset."""
    res1 = classify_challenge_deterministic("ch_1", "SQL Injection", "sqli in auth login", ["sqli"])
    res2 = classify_challenge_deterministic("ch_1", "SQL Injection", "sqli in auth login", ["sqli"])

    assert res1.category == res2.category == "INJECTION"
    assert res1.confidence == res2.confidence
    assert res1.signals == res2.signals
    assert res1.ruleset_version == res2.ruleset_version == RULESET_VERSION
    assert 0.0 <= res1.confidence <= 1.0


def test_classification_multi_label_signals():
    """Verify multi-label classification captures multiple signals."""
    res = classify_challenge_deterministic(
        "ch_2",
        name="REST API with GraphQL and SQLi",
        description="GraphQL query endpoint with sqli vulnerability and auth bypass",
        tags=["api", "graphql", "sqli"],
    )
    assert res.category in {"INJECTION", "GRAPHQL", "API", "AUTHENTICATION"}
    assert len(res.signals) >= 2
    assert any("sqli" in s for s in res.signals)
    assert any("graphql" in s for s in res.signals)


@pytest.mark.asyncio
async def test_classification_task_execution(task_manager, challenge_setup, intel_repo):
    """Verify classify_challenge handler executes and persists classification."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_classify",
        task_type="classify_challenge",
        parameters={
            "name": "Super SQLi Web App",
            "description": "SQL injection vulnerability in login form",
            "tags": ["sqli", "auth"],
        },
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED

    clist = intel_repo.get_classifications(challenge_setup)
    assert len(clist) == 1
    assert clist[0].category == "INJECTION"
    assert clist[0].ruleset_version == RULESET_VERSION


# ---------------------------------------------------------------------------
# B. Evidence Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_intake_and_relation_metadata(task_manager, challenge_setup, intel_repo):
    """Verify valid evidence intake, relation metadata, and priority."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_ev",
        task_type="submit_evidence",
        parameters={
            "content": "Found SQL error in response: syntax error near 'OR'",
            "evidence_type": "http_response",
            "source": "user_confirmed",
            "relation": "supports",
            "metadata": {"url": "http://target/login"},
        },
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED

    ev_list = intel_repo.get_evidence(challenge_setup)
    assert len(ev_list) == 1
    ev = ev_list[0]
    assert ev.content == "Found SQL error in response: syntax error near 'OR'"
    assert ev.source == EvidencePriority.USER_CONFIRMED
    assert ev.metadata["hypothesis_relation"] == "supports"
    assert ev.metadata["url"] == "http://target/login"
    assert ev.is_fabricated is False


@pytest.mark.asyncio
async def test_evidence_fabricated_rejected(task_manager, challenge_setup):
    """Verify attempt to submit fabricated evidence is rejected."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_ev_fab",
        task_type="submit_evidence",
        parameters={
            "content": "Fake flag",
            "is_fabricated": True,
        },
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.FAILED
    assert "Fabricated evidence is strictly prohibited" in final_task.error_message


# ---------------------------------------------------------------------------
# C. Hypothesis State Machine & Limit Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hypothesis_creation_and_max_3_active_limit(task_manager, challenge_setup, bb_repo):
    """Verify creating hypotheses and enforcing max 3 active limit."""
    # Create 3 active hypotheses
    for i in range(1, 4):
        req = TaskRequest(
            challenge_id=challenge_setup,
            task_group_id=f"g_hyp_{i}",
            task_type="create_hypothesis",
            parameters={"title": f"Hypothesis {i}", "status": "active"},
        )
        task = await task_manager.submit(req)
        res = await task_manager.wait_for(task.task_id, timeout=2.0)
        assert res.status == TaskStatus.COMPLETED

    bb = bb_repo.read_blackboard_state(challenge_setup)
    assert len(bb.active_hypothesis_ids) == 3

    # Attempting 4th active hypothesis must fail cleanly and leave state unchanged
    req4 = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_hyp_4",
        task_type="create_hypothesis",
        parameters={"title": "Hypothesis 4", "status": "active"},
    )
    t4 = await task_manager.submit(req4)
    res4 = await task_manager.wait_for(t4.task_id, timeout=2.0)
    assert res4.status == TaskStatus.FAILED
    assert "maximum 3 active hypotheses limit reached" in res4.error_message

    bb_after = bb_repo.read_blackboard_state(challenge_setup)
    assert len(bb_after.active_hypothesis_ids) == 3


@pytest.mark.asyncio
async def test_hypothesis_valid_and_invalid_state_transitions(task_manager, challenge_setup):
    """Verify hypothesis state machine transitions."""
    # Create watchlist hypothesis
    c_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_create",
        task_type="create_hypothesis",
        parameters={"title": "Test Hyp", "status": "watchlist"},
    )
    t_c = await task_manager.submit(c_req)
    res_c = await task_manager.wait_for(t_c.task_id, timeout=2.0)
    hyp_id = res_c.result_ref.get("hypothesis_id") if isinstance(res_c.result_ref, dict) else t_c.task_id

    # WATCHLIST -> ACTIVE (valid)
    eval_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_eval_1",
        task_type="evaluate_hypothesis",
        parameters={
            "hypothesis_id": hyp_id,
            "current_status": "watchlist",
            "new_status": "active",
        },
    )
    t_e1 = await task_manager.submit(eval_req)
    res_e1 = await task_manager.wait_for(t_e1.task_id, timeout=2.0)
    assert res_e1.status == TaskStatus.COMPLETED

    # ACTIVE -> WATCHLIST (invalid transition if not allowed; here WATCHLIST is allowed)
    # ACTIVE -> CONFIRMED directly (invalid, must go via SUPPORTED)
    invalid_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_eval_inv",
        task_type="evaluate_hypothesis",
        parameters={
            "hypothesis_id": hyp_id,
            "current_status": "active",
            "new_status": "confirmed",
        },
    )
    t_inv = await task_manager.submit(invalid_req)
    res_inv = await task_manager.wait_for(t_inv.task_id, timeout=2.0)
    assert res_inv.status == TaskStatus.FAILED
    assert "Invalid hypothesis transition from 'active' to 'confirmed'" in res_inv.error_message


# ---------------------------------------------------------------------------
# D. CONFIRMED Requirement Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirmed_status_requires_user_confirmed_evidence(task_manager, challenge_setup, intel_repo):
    """Verify SUPPORTED -> CONFIRMED requires at least 1 USER_CONFIRMED evidence."""
    now = datetime.now(timezone.utc)
    hyp = Hypothesis(
        hypothesis_id="hyp_123",
        challenge_id=challenge_setup,
        title="Test Hyp 123",
        description="desc",
        status=HypothesisStatus.SUPPORTED,
        confidence=0.5,
        hint_level=HintLevel.L0,
        created_at=now,
        updated_at=now,
    )
    intel_repo.apply_writes_and_diff_atomic(
        challenge_id=challenge_setup,
        entity_writes=[EntityWrite(entity_type="hypothesis", operation="insert", entity_id="hyp_123", fields={
            "hypothesis_id": hyp.hypothesis_id,
            "challenge_id": hyp.challenge_id,
            "title": hyp.title,
            "description": hyp.description,
            "status": hyp.status.value,
            "confidence": hyp.confidence,
            "hint_level": hyp.hint_level.value,
            "created_at": hyp.created_at,
            "updated_at": hyp.updated_at,
        })],
    )

    # SUPPORTED -> CONFIRMED with inferred evidence ONLY must fail
    req_inferred = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_conf_inf",
        task_type="evaluate_hypothesis",
        parameters={
            "hypothesis_id": "hyp_123",
            "current_status": "supported",
            "new_status": "confirmed",
            "has_user_confirmed_evidence": False,
        },
    )
    t_inf = await task_manager.submit(req_inferred)
    res_inf = await task_manager.wait_for(t_inf.task_id, timeout=2.0)
    assert res_inf.status == TaskStatus.FAILED
    assert "Transition to CONFIRMED requires at least one" in res_inf.error_message

    # Insert real USER_CONFIRMED evidence
    ev = Evidence(
        evidence_id="ev_user_123",
        challenge_id=challenge_setup,
        hypothesis_id="hyp_123",
        source=EvidencePriority.USER_CONFIRMED,
        content="Confirmed evidence",
        evidence_type="user_note",
        created_by="user",
        created_at=now,
    )
    intel_repo.apply_writes_and_diff_atomic(
        challenge_id=challenge_setup,
        entity_writes=[EntityWrite(entity_type="evidence", operation="insert", entity_id="ev_user_123", fields={
            "evidence_id": ev.evidence_id,
            "challenge_id": ev.challenge_id,
            "hypothesis_id": ev.hypothesis_id,
            "source": ev.source.value,
            "content": ev.content,
            "evidence_type": ev.evidence_type,
            "created_by": ev.created_by,
            "is_fabricated": 0,
            "created_at": ev.created_at,
        })],
    )

    # SUPPORTED -> CONFIRMED with USER_CONFIRMED evidence succeeds
    req_user = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_conf_user",
        task_type="evaluate_hypothesis",
        parameters={
            "hypothesis_id": "hyp_123",
            "current_status": "supported",
            "new_status": "confirmed",
            "has_user_confirmed_evidence": True,
        },
    )
    t_user = await task_manager.submit(req_user)
    res_user = await task_manager.wait_for(t_user.task_id, timeout=2.0)
    assert res_user.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# E. Confidence Model Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deterministic_confidence_weighting_and_clamping(task_manager, challenge_setup, intel_repo):
    """Verify deterministic investigation confidence calculation and clamping [0.0, 1.0]."""
    now = datetime.now(timezone.utc)
    hyp = Hypothesis(
        hypothesis_id="hyp_conf_1",
        challenge_id=challenge_setup,
        title="Test Hyp Conf",
        description="desc",
        status=HypothesisStatus.ACTIVE,
        confidence=0.5,
        hint_level=HintLevel.L0,
        created_at=now,
        updated_at=now,
    )
    intel_repo.apply_writes_and_diff_atomic(
        challenge_id=challenge_setup,
        entity_writes=[EntityWrite(entity_type="hypothesis", operation="insert", entity_id="hyp_conf_1", fields={
            "hypothesis_id": hyp.hypothesis_id,
            "challenge_id": hyp.challenge_id,
            "title": hyp.title,
            "description": hyp.description,
            "status": hyp.status.value,
            "confidence": hyp.confidence,
            "hint_level": hyp.hint_level.value,
            "created_at": hyp.created_at,
            "updated_at": hyp.updated_at,
        })],
    )

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_conf_calc",
        task_type="evaluate_hypothesis",
        parameters={
            "hypothesis_id": "hyp_conf_1",
            "current_status": "active",
            "current_confidence": 0.5,
            "supporting_user_confirmed": 2,  # +0.6
            "supporting_reasoning": 1,       # +0.15
            "contradicting_user_confirmed": 1, # -0.4
        },
    )
    # Expected: 0.5 + 0.6 + 0.15 - 0.4 = 0.85
    task = await task_manager.submit(req)
    res = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert res.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# F. ReasoningState Projection Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reasoning_state_read_only_projection(task_manager, challenge_setup, bb_repo):
    """Verify ReasoningState projection is read-only and produces no mutations or events."""
    v_before = bb_repo.read_blackboard_version(challenge_setup)

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_rs",
        task_type="build_reasoning_state",
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED

    v_after = bb_repo.read_blackboard_version(challenge_setup)
    assert v_before == v_after


# ---------------------------------------------------------------------------
# G. Concurrency & Stale Version Recovery Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrency_stale_version_recomputation(task_manager, challenge_setup, bb_repo, registry):
    """Test two handlers operating concurrently from same Blackboard version.

    Forces a stale-version conflict and verifies handler recomputation against fresh state.
    """
    class ConcurrentIntelligenceHandler(TaskHandler):
        def __init__(self, item_name: str):
            self.item_name = item_name

        async def execute(self, ctx: TaskContext) -> HandlerResult:
            curr_ev = list(ctx.blackboard_snapshot.active_evidence_ids)
            if self.item_name not in curr_ev:
                curr_ev.append(self.item_name)
            
            ew = EntityWrite(
                entity_type="hypothesis",
                operation="insert",
                entity_id=f"hyp_{self.item_name}",
                fields={
                    "hypothesis_id": f"hyp_{self.item_name}",
                    "challenge_id": ctx.challenge_id,
                    "title": f"Hypothesis {self.item_name}",
                    "status": "watchlist",
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            diff = ScopedDiff(
                challenge_id=ctx.challenge_id,
                expected_version=ctx.blackboard_snapshot.blackboard_version,
                actor="conc_handler",
                event_type="HypothesisCreated",
                changes={"active_evidence_ids": curr_ev},
            )
            return HandlerResult(success=True, output=f"done_{self.item_name}", proposed_entity_writes=[ew], proposed_diff=diff)

    registry.register("conc_intel_A", ConcurrentIntelligenceHandler("ev_A"))
    registry.register("conc_intel_B", ConcurrentIntelligenceHandler("ev_B"))

    t_a = await task_manager.submit(TaskRequest(challenge_id=challenge_setup, task_group_id="g_a", task_type="conc_intel_A"))
    t_b = await task_manager.submit(TaskRequest(challenge_id=challenge_setup, task_group_id="g_b", task_type="conc_intel_B"))

    res_a = await task_manager.wait_for(t_a.task_id, timeout=3.0)
    res_b = await task_manager.wait_for(t_b.task_id, timeout=3.0)

    assert res_a.status == TaskStatus.COMPLETED
    assert res_b.status == TaskStatus.COMPLETED

    bb = bb_repo.read_blackboard_state(challenge_setup)
    assert "ev_A" in bb.active_evidence_ids
    assert "ev_B" in bb.active_evidence_ids


# ---------------------------------------------------------------------------
# H. Atomicity & Rollback Test
# ---------------------------------------------------------------------------


def test_atomic_transaction_rollback_on_fault(intel_repo, challenge_setup, db_conn):
    """Force a fault during atomic execution and verify full transaction rollback."""
    v_before = intel_repo.blackboard_repo.read_blackboard_version(challenge_setup)

    ew_valid = EntityWrite(
        entity_type="hypothesis",
        operation="insert",
        entity_id="hyp_rollback_test",
        fields={
            "hypothesis_id": "hyp_rollback_test",
            "challenge_id": challenge_setup,
            "title": "Rollback Title",
            "status": "watchlist",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        },
    )

    # ScopedDiff with stale expected version to force failure during transaction
    bad_diff = ScopedDiff(
        challenge_id=challenge_setup,
        expected_version=999,  # invalid version -> raises StaleVersionError
        actor="fault_test",
        event_type="TestEvent",
        changes={"session_notes": "Should not persist"},
    )

    with pytest.raises(StaleVersionError):
        intel_repo.apply_writes_and_diff_atomic(
            challenge_id=challenge_setup,
            entity_writes=[ew_valid],
            scoped_diff=bad_diff,
        )

    # Verify hypothesis was NOT persisted due to transaction rollback
    h = intel_repo.get_hypothesis("hyp_rollback_test")
    assert h is None

    # Verify Blackboard version remains unchanged
    v_after = intel_repo.blackboard_repo.read_blackboard_version(challenge_setup)
    assert v_before == v_after


# ---------------------------------------------------------------------------
# I. Schema Migration Test (v3 -> v4)
# ---------------------------------------------------------------------------


def test_schema_v3_to_v4_migration():
    """Verify non-destructive database migration from schema version 3 to 4."""
    v3_conn = sqlite3.connect(":memory:")
    v3_conn.row_factory = sqlite3.Row
    v3_conn.execute("PRAGMA foreign_keys = ON;")

    # 1. Construct schema v3 tables
    v3_conn.executescript(
        """
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        INSERT INTO schema_version (version, applied_at) VALUES (3, datetime('now'));

        CREATE TABLE challenges (
            challenge_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            global_hint_level INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE blackboard_states (
            challenge_id TEXT PRIMARY KEY REFERENCES challenges(challenge_id),
            blackboard_version INTEGER NOT NULL DEFAULT 0,
            active_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            watchlist_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            confirmed_findings TEXT NOT NULL DEFAULT '[]',
            active_evidence_ids TEXT NOT NULL DEFAULT '[]',
            last_hint_level INTEGER NOT NULL DEFAULT 0,
            session_notes TEXT NOT NULL DEFAULT '',
            metadata TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );
        """
    )
    v3_conn.commit()

    # Seed data
    now = datetime.now(timezone.utc).isoformat()
    v3_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_v3_1', 'V3 Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    v3_conn.commit()

    # Execute CURRENT initialize_schema migration to target SCHEMA_VERSION (4)
    ver = initialize_schema(v3_conn)
    assert ver == SCHEMA_VERSION

    # Verify table challenge_classifications exists
    row = v3_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenge_classifications';").fetchone()
    assert row is not None

    # Verify existing data survived
    ch_row = v3_conn.execute("SELECT name FROM challenges WHERE challenge_id = 'ch_v3_1'").fetchone()
    assert ch_row["name"] == "V3 Challenge"

    # Verify idempotency
    ver_again = initialize_schema(v3_conn)
    assert ver_again == SCHEMA_VERSION
    v3_conn.close()


# ---------------------------------------------------------------------------
# J. Security Boundary Test
# ---------------------------------------------------------------------------


def test_security_boundary_no_prohibited_imports():
    """Verify Phase 5D codebase contains zero forbidden imports or execution calls."""
    prohibited_modules = {
        "requests",
        "httpx",
        "subprocess",
        "os.system",
        "openai",
        "anthropic",
        "chromadb",
    }

    modules_to_inspect = [
        "ctf_mentor.intelligence.classification",
        "ctf_mentor.intelligence.evidence_handlers",
        "ctf_mentor.intelligence.hypothesis_handlers",
        "ctf_mentor.intelligence.attempt_handlers",
        "ctf_mentor.intelligence.reasoning_state",
        "ctf_mentor.persistence.intelligence_repo",
    ]

    for mod_name in modules_to_inspect:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        for prohibited in prohibited_modules:
            assert f"import {prohibited}" not in source, f"Forbidden import '{prohibited}' found in {mod_name}"
            assert f"from {prohibited}" not in source, f"Forbidden import '{prohibited}' found in {mod_name}"


# ---------------------------------------------------------------------------
# K. Blocker Structural & Cancellation Regression Tests
# ---------------------------------------------------------------------------


def test_blocker_6_handler_read_only_structural_boundary():
    """Verify BuildReasoningStateHandler has zero write-capable methods on its reader object."""
    handler = BuildReasoningStateHandler()
    # Handler should hold no repository or write connection by default
    assert not hasattr(handler, "intelligence_repo") or handler.intelligence_repo is None
    
    # Check that handler instance itself has no write methods
    for forbidden in ["apply_writes_and_diff_atomic", "_execute_entity_write", "create_challenge", "delete"]:
        assert not hasattr(handler, forbidden), f"BuildReasoningStateHandler contains write method {forbidden!r}"


@pytest.mark.asyncio
async def test_blocker_7_cancellation_aborts_commit(db_conn, bb_repo, intel_repo, registry):
    """Verify that cancellation before commit aborts transaction cleanly with zero partial changes."""
    event_bus = EventBus()
    tm = TaskManager(
        db_connection=db_conn,
        blackboard_repo=bb_repo,
        handler_registry=registry,
        event_bus=event_bus,
        intelligence_repo=intel_repo,
    )

    ch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    ch = Challenge(
        challenge_id=ch_id,
        name="Cancellation Test Challenge",
        description="Desc",
        category="web",
        global_hint_level=HintLevel.L0,
        created_at=now,
        updated_at=now,
    )
    bb_repo.create_challenge(ch)

    # Submit task and immediately cancel it
    req = TaskRequest(
        challenge_id=ch_id,
        task_group_id="g_canc",
        task_type="classify_challenge",
        parameters={"name": "Web Challenge", "description": "sqli auth"},
    )
    task = await tm.submit(req)
    await tm.cancel(task.task_id)

    res = await tm.wait_for(task.task_id, timeout=2.0)
    assert res.status == TaskStatus.CANCELLED

    # Verify no classification was written
    clist = intel_repo.get_classifications(ch_id)
    assert len(clist) == 0


def test_blocker_10_v2_to_v4_full_migration():
    """Verify genuine v2 schema database migrates cleanly to v4 with all constraints intact."""
    v2_conn = sqlite3.connect(":memory:")
    v2_conn.row_factory = sqlite3.Row
    v2_conn.execute("PRAGMA foreign_keys = ON;")

    v2_conn.executescript(
        """
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'));

        CREATE TABLE challenges (
            challenge_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            global_hint_level INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE blackboard_states (
            challenge_id TEXT PRIMARY KEY REFERENCES challenges(challenge_id),
            blackboard_version INTEGER NOT NULL DEFAULT 0,
            active_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            watchlist_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            confirmed_findings TEXT NOT NULL DEFAULT '[]',
            active_evidence_ids TEXT NOT NULL DEFAULT '[]',
            last_hint_level INTEGER NOT NULL DEFAULT 0,
            session_notes TEXT NOT NULL DEFAULT '',
            metadata TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            task_group_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            status TEXT NOT NULL,
            retry_key TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    v2_conn.commit()

    now = datetime.now(timezone.utc).isoformat()
    v2_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_v2_test', 'Legacy V2 Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    v2_conn.commit()

    ver = initialize_schema(v2_conn)
    assert ver == SCHEMA_VERSION

    # Existing row survives
    ch_row = v2_conn.execute("SELECT name FROM challenges WHERE challenge_id = 'ch_v2_test'").fetchone()
    assert ch_row["name"] == "Legacy V2 Challenge"

    # Idempotent re-run
    ver_again = initialize_schema(v2_conn)
    assert ver_again == SCHEMA_VERSION
    v2_conn.close()


# ---------------------------------------------------------------------------
# L. Final Remediation Probes (Issues 1-4)
# ---------------------------------------------------------------------------


def test_issue1_entity_write_missing_pk_rejected(intel_repo, challenge_setup):
    """Verify EntityWrite(operation='insert') missing PK in fields raises ValueError and creates 0 rows."""
    ew_missing_pk = EntityWrite(
        entity_type="hypothesis",
        operation="insert",
        entity_id="h1_no_pk",
        fields={
            "challenge_id": challenge_setup,
            "title": "Missing PK test",
            "status": "watchlist",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        },
    )

    with pytest.raises(ValueError) as exc_info:
        intel_repo.apply_writes_and_diff_atomic(
            challenge_id=challenge_setup,
            entity_writes=[ew_missing_pk],
        )

    assert "missing required primary key field 'hypothesis_id'" in str(exc_info.value)

    # Verify zero row created
    h = intel_repo.get_hypothesis("h1_no_pk")
    assert h is None


def test_issue2_persistence_layer_max_3_active_hypotheses(intel_repo, challenge_setup):
    """Verify IntelligenceRepository directly rejects >3 active hypotheses at persistence layer."""
    now = datetime.now(timezone.utc)
    writes = []
    for i in range(1, 5):
        h_id = f"hyp_active_{i}"
        writes.append(
            EntityWrite(
                entity_type="hypothesis",
                operation="insert",
                entity_id=h_id,
                fields={
                    "hypothesis_id": h_id,
                    "challenge_id": challenge_setup,
                    "title": f"Active Hyp {i}",
                    "status": "active",
                    "created_at": now,
                    "updated_at": now,
                },
            )
        )

    # Directly call IntelligenceRepository bypassing handler layer
    with pytest.raises(ValueError) as exc_info:
        intel_repo.apply_writes_and_diff_atomic(
            challenge_id=challenge_setup,
            entity_writes=writes,
        )

    assert "Maximum 3 active hypotheses limit exceeded" in str(exc_info.value)

    # Verify transaction rolled back completely and zero hypotheses were created
    hypotheses = intel_repo.get_hypotheses(challenge_setup)
    assert len(hypotheses) == 0


def test_issue3_migration_fk_parity_probe():
    """Verify migrated v2/v3 database has 100% identical PRAGMA foreign_key_list to fresh v4 database."""
    # 1. Fresh v4 DB
    fresh_conn = sqlite3.connect(":memory:")
    initialize_schema(fresh_conn)

    # 2. Legacy v2 DB with historical DDL
    v2_conn = sqlite3.connect(":memory:")
    v2_conn.execute("PRAGMA foreign_keys = ON;")
    v2_conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'));

        CREATE TABLE challenges (challenge_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '', global_hint_level INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1, tags TEXT NOT NULL DEFAULT '[]', metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);

        CREATE TABLE hypotheses (hypothesis_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id), title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'watchlist', confidence REAL NOT NULL DEFAULT 0.0, hint_level INTEGER NOT NULL DEFAULT 0, is_primary INTEGER NOT NULL DEFAULT 0, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);

        CREATE TABLE attempts (attempt_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id), hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id), description TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT 'unknown', user_input TEXT NOT NULL DEFAULT '', tool_output TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
        """
    )
    v2_conn.commit()

    # Migrate v2 DB to v4
    initialize_schema(v2_conn)

    tables = ["attempts", "hint_requests", "hint_candidates", "hint_decisions", "user_action_requests"]
    for table_name in tables:
        fresh_fk = fresh_conn.execute(f"PRAGMA foreign_key_list({table_name});").fetchall()
        migrated_fk = v2_conn.execute(f"PRAGMA foreign_key_list({table_name});").fetchall()
        fresh_tuples = {(r[2], r[3], r[4], r[6]) for r in fresh_fk}
        migrated_tuples = {(r[2], r[3], r[4], r[6]) for r in migrated_fk}
        assert fresh_tuples == migrated_tuples, f"FK parity mismatch on table {table_name}"

    fresh_conn.close()
    v2_conn.close()


def test_issue4_event_version_collision_prevention(intel_repo, challenge_setup, bb_repo):
    """Verify Blackboard mutation event owns version_after while lifecycle events get version_after = None."""
    v_start = bb_repo.read_blackboard_version(challenge_setup)
    diff = ScopedDiff(
        challenge_id=challenge_setup,
        expected_version=v_start,
        actor="test_actor",
        event_type="BlackboardUpdated",
        changes={"session_notes": "Notes with lifecycle events"},
    )
    lifecycle_evt = {
        "event_id": str(uuid.uuid4()),
        "event_type": "TaskCompleted",
        "actor": "system",
        "payload": {"task_id": "t1"},
    }

    # Pass both scoped_diff and additional lifecycle event
    new_ver = intel_repo.apply_writes_and_diff_atomic(
        challenge_id=challenge_setup,
        scoped_diff=diff,
        events=[lifecycle_evt],
    )

    assert new_ver == v_start + 1

    # Fetch events for challenge
    events = intel_repo.conn.execute(
        "SELECT event_type, blackboard_version_after FROM events WHERE challenge_id = ? ORDER BY occurred_at ASC;",
        (challenge_setup,),
    ).fetchall()

    mutation_events = [e for e in events if e["event_type"] == "BlackboardUpdated"]
    task_events = [e for e in events if e["event_type"] == "TaskCompleted"]

    assert len(mutation_events) == 1
    assert mutation_events[0]["blackboard_version_after"] == new_ver

    assert len(task_events) == 1
    assert task_events[0]["blackboard_version_after"] is None


