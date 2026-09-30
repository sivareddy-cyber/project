"""
Comprehensive Test Suite for Phase 5E — Deterministic Reasoning Foundation & Remediation.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import threading
from datetime import datetime, timezone
import pytest

from ctf_mentor.contracts import StaleVersionError
from ctf_mentor.domain.models import (
    Attempt,
    BlackboardState,
    Challenge,
    ChallengeClassification,
    Evidence,
    FailedAttempt,
    Hypothesis,
    HypothesisStatus,
    HintLevel,
    TaskStatus,
)
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import SCHEMA_VERSION, initialize_schema
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.canonical import canonicalize_json, compute_result_hash
from ctf_mentor.reasoning.contracts import (
    EvidenceTier,
    GapType,
    HypothesisPosture,
    HypothesisPrediction,
    HypothesisRelation,
    HypothesisRelationType,
    InvestigationLink,
    InvestigationLinkType,
    LinkStatus,
    PredictionStatus,
    ReasoningRunStatus,
    TaskOrigin,
)
from ctf_mentor.reasoning.engine import ReasoningEngine
from ctf_mentor.reasoning.evidence_analysis import analyze_evidence_for_hypotheses
from ctf_mentor.reasoning.gaps import detect_information_gaps
from ctf_mentor.reasoning.handlers import (
    AnalyzeInvestigationHandler,
    RecordHypothesisRelationHandler,
    RecordInvestigationLinkHandler,
    RecordPredictionHandler,
    register_phase5e_handlers,
)
from ctf_mentor.reasoning.hypothesis_eval import evaluate_hypotheses
from ctf_mentor.reasoning.proposals import generate_investigation_proposals
from ctf_mentor.reasoning.view import ReasoningView, build_reasoning_view
from ctf_mentor.runtime.handler_registry import HandlerRegistry
from ctf_mentor.runtime.task_context import TaskContext, TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)
    return conn


@pytest.fixture
def seeded_challenge(db_conn):
    now = datetime.now(timezone.utc).isoformat()
    db_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_5e_1', 'Test 5E Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    db_conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) "
        "VALUES ('ch_5e_1', 0, ?)",
        (now,),
    )
    db_conn.execute(
        "INSERT INTO hypotheses (hypothesis_id, challenge_id, title, description, status, confidence, hint_level, created_at, updated_at) "
        "VALUES ('h1', 'ch_5e_1', 'IDOR Vulnerability', 'Desc', 'active', 0.5, 0, ?, ?)",
        (now, now),
    )
    db_conn.execute(
        "INSERT INTO hypotheses (hypothesis_id, challenge_id, title, description, status, confidence, hint_level, created_at, updated_at) "
        "VALUES ('h2', 'ch_5e_1', 'Broken Authentication', 'Desc', 'active', 0.4, 0, ?, ?)",
        (now, now),
    )
    db_conn.commit()
    return "ch_5e_1"


# ==============================================================================
# A. Golden Reasoning Tests
# ==============================================================================


def test_golden_reasoning_reproducible_hash(db_conn, seeded_challenge):
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()

    result1 = engine.analyze(view, run_sequence=1)
    result2 = engine.analyze(view, run_sequence=1)

    assert result1.result_hash == result2.result_hash
    assert len(result1.result_hash) == 64
    assert result1.input_fingerprint == view.input_fingerprint
    assert len(result1.assessments) == 2


# ==============================================================================
# B. Determinism Tests
# ==============================================================================


def test_determinism_dictionary_order_independence():
    dict1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    dict2 = {"a": 1, "c": [3, 2, 1], "b": 2}

    assert canonicalize_json(dict1) == canonicalize_json(dict2)
    assert compute_result_hash(dict1) == compute_result_hash(dict2)


# ==============================================================================
# C. Evidence Tests
# ==============================================================================


def test_evidence_tier_scoring_and_independence_grouping():
    now = datetime.now(timezone.utc)
    h1 = Hypothesis("h1", "c1", "Title", "Desc", HypothesisStatus.ACTIVE, 0.5, HintLevel.L0, now, now)

    e1 = Evidence("e1", "c1", "h1", "user_confirmed", "content1", "note", now, "user", False, {"independence_group": "group_a"})
    e2 = Evidence("e2", "c1", "h1", "user_confirmed", "content2", "note", now, "user", False, {"independence_group": "group_a"})

    res = analyze_evidence_for_hypotheses([h1], [e1, e2], [], set())
    assert res["h1"]["support_strength"] == 1000


def test_evidence_diagnosticity_discount_for_competing_hypotheses():
    now = datetime.now(timezone.utc)
    h1 = Hypothesis("h1", "c1", "Title1", "Desc", HypothesisStatus.ACTIVE, 0.5, HintLevel.L0, now, now)
    e1 = Evidence("e1", "c1", "h1", "reasoning_inference", "content", "note", now, "system", False)

    competing_pairs = {("h1", "h2"), ("h2", "h1")}
    res = analyze_evidence_for_hypotheses([h1], [e1], [], competing_pairs)
    assert res["h1"]["support_strength"] == 560


# ==============================================================================
# D. Hypothesis Postures & Confirmation Eligibility Gate Tests
# ==============================================================================


def test_hypothesis_postures_and_user_confirmed_gate():
    now = datetime.now(timezone.utc)
    h1 = Hypothesis("h1", "c1", "Title", "Desc", HypothesisStatus.ACTIVE, 0.5, HintLevel.L0, now, now)

    metrics = {
        "h1": {
            "support_strength": 800,
            "contradiction_strength": 0,
            "evidence_quality": 1000,
            "evidence_coverage": 500,
            "user_confirmed_count": 0,
        }
    }

    asmts = evaluate_hypotheses("run1", "c1", [h1], metrics)
    assert asmts[0].posture == HypothesisPosture.SUPPORTED_CANDIDATE
    assert asmts[0].is_confirmation_eligible is False

    metrics["h1"]["user_confirmed_count"] = 1
    asmts2 = evaluate_hypotheses("run1", "c1", [h1], metrics)
    assert asmts2[0].is_confirmation_eligible is True


# ==============================================================================
# E. Information Gap Detection Tests
# ==============================================================================


def test_detect_all_typed_information_gaps(db_conn, seeded_challenge):
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    res = engine.analyze(view)

    gap_types = {g["gap_type"] for g in res.detected_gaps}
    assert GapType.NO_OR_LOW_CLASSIFICATION.value in gap_types
    assert GapType.NO_USER_CONFIRMED_SUPPORT.value in gap_types
    assert GapType.HYPOTHESIS_WITHOUT_PREDICTIONS.value in gap_types


# ==============================================================================
# F. Investigation Proposals Safety Tests
# ==============================================================================


def test_proposals_contain_no_executable_commands_or_payloads(db_conn, seeded_challenge):
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    res = engine.analyze(view)

    forbidden_patterns = ["curl ", "nc ", "python -c", "OR 1=1", "SELECT ", "../", "<script>", "/bin/sh", "rm -rf"]

    for prop in res.proposals:
        text = f"{prop.title} {prop.description} {prop.rationale}".lower()
        for pat in forbidden_patterns:
            assert pat not in text, f"Forbidden pattern {pat!r} found in proposal"


# ==============================================================================
# REMEDIATION BLOCKER 1: Reasoning Record Immutability & Triggers
# ==============================================================================


def test_blocker1_reasoning_records_and_tables_are_immutable(db_conn, seeded_challenge):
    repo = ReasoningRepository(db_conn)
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    candidate = engine.analyze(view)

    run_rec = repo.record_reasoning_result_atomic(candidate)

    # 1. Direct SQL UPDATE on reasoning_runs MUST FAIL via trigger
    with pytest.raises(sqlite3.Error, match="reasoning_runs are immutable"):
        db_conn.execute("UPDATE reasoning_runs SET status = 'failed' WHERE run_id = ?", (run_rec.run_id,))

    # 2. Direct SQL DELETE on reasoning_runs MUST FAIL via trigger
    with pytest.raises(sqlite3.Error, match="reasoning_runs are immutable"):
        db_conn.execute("DELETE FROM reasoning_runs WHERE run_id = ?", (run_rec.run_id,))

    # 3. Direct SQL UPDATE on hypothesis_assessments MUST FAIL via trigger
    with pytest.raises(sqlite3.Error, match="hypothesis_assessments are immutable"):
        db_conn.execute("UPDATE hypothesis_assessments SET posture = 'refuted_candidate'")

    # 4. Direct SQL DELETE on hypothesis_assessments MUST FAIL via trigger
    with pytest.raises(sqlite3.Error, match="hypothesis_assessments are immutable"):
        db_conn.execute("DELETE FROM hypothesis_assessments")


# ==============================================================================
# REMEDIATION BLOCKER 2: Cross-Challenge Validation
# ==============================================================================


def test_blocker2_cross_challenge_validation_rejection(db_conn, seeded_challenge):
    repo = ReasoningRepository(db_conn)
    now = datetime.now(timezone.utc).isoformat()

    # Create Challenge B
    db_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_5e_B', 'Challenge B', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    db_conn.execute(
        "INSERT INTO hypotheses (hypothesis_id, challenge_id, title, description, status, confidence, hint_level, created_at, updated_at) "
        "VALUES ('h_B1', 'ch_5e_B', 'Hypothesis B1', 'Desc', 'active', 0.5, 0, ?, ?)",
        (now, now),
    )
    db_conn.execute(
        "INSERT INTO evidence (evidence_id, challenge_id, hypothesis_id, source, content, evidence_type, created_at) "
        "VALUES ('ev_B1', 'ch_5e_B', 'h_B1', 'user_confirmed', 'Content B', 'note', ?)",
        (now,),
    )
    db_conn.commit()

    # Attempt 1: Link Evidence from Challenge B into Challenge A -> REJECTED
    link_cross = InvestigationLink(
        link_id="l_cross_1",
        challenge_id=seeded_challenge,  # Challenge A
        source_id="ev_B1",  # Belongs to Challenge B
        source_type="evidence",
        target_id="h1",  # Belongs to Challenge A
        target_type="hypothesis",
        relation_type=InvestigationLinkType.SUPPORTS,
    )
    with pytest.raises(ValueError, match="Cross-challenge violation"):
        repo.record_investigation_link(link_cross)

    # Attempt 2: Relation between Hypothesis in Challenge A and Hypothesis in Challenge B -> REJECTED
    rel_cross = HypothesisRelation(
        relation_id="rel_cross_1",
        challenge_id=seeded_challenge,
        source_hypothesis_id="h1",  # Challenge A
        target_hypothesis_id="h_B1",  # Challenge B
        relation_type=HypothesisRelationType.COMPETES,
    )
    with pytest.raises(ValueError, match="Cross-challenge violation"):
        repo.record_hypothesis_relation(rel_cross)

    # Attempt 3: Prediction for Hypothesis B submitted for Challenge A -> REJECTED
    pred_cross = HypothesisPrediction(
        prediction_id="pred_cross_1",
        challenge_id=seeded_challenge,
        hypothesis_id="h_B1",  # Challenge B
        description="Desc",
        expected_observation="Obs",
        status=PredictionStatus.UNTESTED,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="Cross-challenge violation"):
        repo.record_prediction(pred_cross)


# ==============================================================================
# REMEDIATION BLOCKER 3: Same-Fingerprint Reasoning Dedup & Race Safety
# ==============================================================================


def test_blocker3_same_fingerprint_deduplication(db_conn, seeded_challenge):
    repo = ReasoningRepository(db_conn)
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    candidate = engine.analyze(view, run_sequence=1)

    # Submission 1
    run1 = repo.record_reasoning_result_atomic(candidate)
    assert run1.run_sequence == 1

    # Submission 2 (same result/fingerprint/hash)
    run2 = repo.record_reasoning_result_atomic(candidate)

    # DEDUP: Returns exact same run_id without creating duplicate row
    assert run2.run_id == run1.run_id
    assert run2.run_sequence == 1

    total_runs = db_conn.execute("SELECT COUNT(*) FROM reasoning_runs WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert total_runs == 1


# ==============================================================================
# REMEDIATION BLOCKER 4: RecordPredictionHandler Rewrite
# ==============================================================================


@pytest.mark.asyncio
async def test_blocker4_record_prediction_handler_uses_reasoning_repo(db_conn, seeded_challenge):
    repo = ReasoningRepository(db_conn)
    handler = RecordPredictionHandler(reasoning_repo=repo)

    bb_state = BlackboardRepository(db_conn).read_blackboard_state(seeded_challenge)
    ctx = TaskContext(
        task_id="t_pred_1",
        challenge_id=seeded_challenge,
        task_group_id="g_pred",
        task_type="record_prediction",
        parameters={
            "hypothesis_id": "h1",
            "description": "Test SQL Injection prediction",
            "expected_observation": "Error status 500 on quote input",
        },
        blackboard_snapshot=bb_state,
    )

    res = await handler.execute(ctx)
    assert res.success is True
    assert len(res.proposed_entity_writes) == 0  # CRITICAL: zero Phase 5D entity writes!

    # Verify prediction row was correctly persisted in hypothesis_predictions
    pred_row = db_conn.execute(
        "SELECT description, status FROM hypothesis_predictions WHERE hypothesis_id = 'h1'"
    ).fetchone()
    assert pred_row is not None
    assert pred_row["description"] == "Test SQL Injection prediction"
    assert pred_row["status"] == "untested"

    # Verify PredictionRecorded Event was emitted
    evt = db_conn.execute("SELECT event_type FROM events WHERE event_type = 'PredictionRecorded'").fetchone()
    assert evt is not None


# ==============================================================================
# REMEDIATION ADDITIONAL ISSUE 5: Task Handler Registration
# ==============================================================================


def test_issue5_handler_registration_discoverability(db_conn):
    registry = HandlerRegistry()
    repo = ReasoningRepository(db_conn)
    register_phase5e_handlers(registry, reasoning_repo=repo)

    required_task_types = [
        "analyze_investigation",
        "record_prediction",
        "record_investigation_link",
        "record_hypothesis_relation",
    ]

    for tt in required_task_types:
        assert registry.has_handler(tt), f"Handler for {tt!r} is not registered"
        handler = registry.get(tt)
        assert handler is not None


# ==============================================================================
# REMEDIATION ADDITIONAL ISSUE 6: Genuine v4 -> v5 Migration Test
# ==============================================================================


def test_issue6_genuine_v4_to_v5_schema_migration():
    """Verify genuine v4 schema database with realistic data migrates cleanly to v5."""
    v4_conn = sqlite3.connect(":memory:")
    v4_conn.row_factory = sqlite3.Row
    v4_conn.execute("PRAGMA foreign_keys = ON;")

    # 1. Build genuine v4 schema
    v4_conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_version (version, applied_at) VALUES (4, datetime('now'));

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

        CREATE TABLE hypotheses (
            hypothesis_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'watchlist',
            confidence REAL NOT NULL DEFAULT 0.0,
            hint_level INTEGER NOT NULL DEFAULT 0,
            is_primary INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (hypothesis_id, challenge_id)
        );

        CREATE TABLE challenge_classifications (
            classification_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            category TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.0,
            signals TEXT NOT NULL DEFAULT '[]',
            ruleset_version TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    v4_conn.commit()

    # 2. Seed representative v4 data
    now = datetime.now(timezone.utc).isoformat()
    v4_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_v4_mig', 'V4 Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    v4_conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) "
        "VALUES ('ch_v4_mig', 1, ?)",
        (now,),
    )
    v4_conn.execute(
        "INSERT INTO hypotheses (hypothesis_id, challenge_id, title, status, created_at, updated_at) "
        "VALUES ('h_v4_1', 'ch_v4_mig', 'V4 Hypothesis', 'active', ?, ?)",
        (now, now),
    )
    v4_conn.commit()

    # 3. Run initialize_schema() migration from v4 to latest version
    ver = initialize_schema(v4_conn)
    assert ver == SCHEMA_VERSION

    # 4. Verify v4 data survives
    ch_row = v4_conn.execute("SELECT name FROM challenges WHERE challenge_id = 'ch_v4_mig'").fetchone()
    assert ch_row["name"] == "V4 Challenge"

    h_row = v4_conn.execute("SELECT title FROM hypotheses WHERE hypothesis_id = 'h_v4_1'").fetchone()
    assert h_row["title"] == "V4 Hypothesis"

    # 5. Verify all Phase 5E tables exist
    v5_tables = [
        "hypothesis_predictions",
        "investigation_links",
        "hypothesis_relations",
        "reasoning_runs",
        "hypothesis_assessments",
    ]
    for tbl in v5_tables:
        row = v4_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tbl,)).fetchone()
        assert row is not None, f"Table {tbl} missing after schema migration"

    # 6. Verify idempotency on re-run
    ver_again = initialize_schema(v4_conn)
    assert ver_again == SCHEMA_VERSION
    v4_conn.close()


# ==============================================================================
# Security & State Non-Mutation Tests
# ==============================================================================


def test_reasoning_execution_leaves_phase5d_state_unchanged(db_conn, seeded_challenge):
    hyp_count_before = db_conn.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
    ev_count_before = db_conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    bb_ver_before = db_conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]

    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    candidate = engine.analyze(view)

    repo = ReasoningRepository(db_conn)
    repo.record_reasoning_result_atomic(candidate)

    hyp_count_after = db_conn.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
    ev_count_after = db_conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    bb_ver_after = db_conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]

    assert hyp_count_before == hyp_count_after
    assert ev_count_before == ev_count_after
    assert bb_ver_before == bb_ver_after


def test_phase5e_security_boundary_no_prohibited_imports():
    import ast
    from pathlib import Path

    prohibited = {"requests", "urllib", "httpx", "aiohttp", "subprocess", "claude", "openai", "chromadb", "vector", "burp"}
    reasoning_dir = Path("ctf_mentor/reasoning")

    for py_file in reasoning_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_base = alias.name.split(".")[0]
                    assert mod_base not in prohibited, f"Prohibited import {alias.name!r} in {py_file}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod_base = node.module.split(".")[0]
                    assert mod_base not in prohibited, f"Prohibited import {node.module!r} in {py_file}"


def test_concurrent_same_fingerprint_reasoning_dedup(tmp_path):
    """Verify concurrent identical reasoning submissions deduplicate race-safely via sqlite WAL."""
    db_file = tmp_path / "test_concurrency.db"
    conn_main = sqlite3.connect(str(db_file), isolation_level=None)
    conn_main.execute("PRAGMA foreign_keys = ON;")
    conn_main.execute("PRAGMA journal_mode = WAL;")
    initialize_schema(conn_main)

    now = datetime.now(timezone.utc).isoformat()
    conn_main.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_conc_1', 'Conc Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    conn_main.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES ('ch_conc_1', 0, ?)",
        (now,),
    )
    conn_main.execute(
        "INSERT INTO hypotheses (hypothesis_id, challenge_id, title, status, created_at, updated_at) VALUES ('h1', 'ch_conc_1', 'H1', 'active', ?, ?)",
        (now, now),
    )
    conn_main.close()

    view_conn = sqlite3.connect(str(db_file), isolation_level=None)
    view_conn.execute("PRAGMA foreign_keys = ON;")
    view = build_reasoning_view(view_conn, "ch_conc_1")
    candidate = ReasoningEngine().analyze(view)
    view_conn.close()

    barrier = threading.Barrier(2)
    results = [None, None]
    exceptions = [None, None]

    def worker(idx):
        try:
            conn = sqlite3.connect(str(db_file), isolation_level=None, timeout=10.0)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            repo = ReasoningRepository(conn)
            barrier.wait()
            res = repo.record_reasoning_result_atomic(candidate)
            results[idx] = res
            conn.close()
        except Exception as ex:
            exceptions[idx] = ex

    t1 = threading.Thread(target=worker, args=(0,))
    t2 = threading.Thread(target=worker, args=(1,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert exceptions[0] is None and exceptions[1] is None, f"Threads raised errors: {exceptions}"
    assert results[0] is not None and results[1] is not None
    assert results[0].run_id == results[1].run_id


# ==============================================================================
# REMEDIATION FINAL AUDIT: Real TaskManager Persistence & Fail-Closed Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_real_task_manager_analyze_investigation_persistence(db_conn, seeded_challenge):
    """Verify real TaskManager -> AnalyzeInvestigationHandler -> ReasoningRepository path.

    1. Create a real SQLite database.
    2. Seed a challenge.
    3. Register AnalyzeInvestigationHandler with ReasoningRepository.
    4. Submit an actual TaskManager request: task_type = "analyze_investigation".
    5. Wait for completion.
    6. Assert task status == COMPLETED.
    7. Assert exactly one reasoning_runs row exists.
    8. Assert hypothesis_assessments exist where applicable.
    9. Assert ReasoningRunRecorded event exists.
    10. Assert Phase 5D tables are unchanged.
    11. Assert persisted result hash is replay-verifiable.
    """
    bb_repo = BlackboardRepository(db_conn)
    reasoning_repo = ReasoningRepository(db_conn)
    registry = HandlerRegistry()
    register_phase5e_handlers(registry, reasoning_repo=reasoning_repo)

    tm = TaskManager(
        db_connection=db_conn,
        blackboard_repo=bb_repo,
        handler_registry=registry,
    )

    # Initial Phase 5D table counts & version
    hyp_count_before = db_conn.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
    ev_count_before = db_conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    bb_ver_before = db_conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]

    # Submit task
    req = TaskRequest(
        challenge_id=seeded_challenge,
        task_group_id="grp_reasoning_1",
        task_type="analyze_investigation",
        parameters={},
    )
    task = await tm.submit(req)
    completed_task = await tm.wait_for(task.task_id, timeout=5.0)

    # 6. Assert task status == COMPLETED
    assert completed_task.status == TaskStatus.COMPLETED

    # 7. Assert exactly one reasoning_runs row exists
    runs_rows = db_conn.execute("SELECT * FROM reasoning_runs WHERE challenge_id = ?", (seeded_challenge,)).fetchall()
    assert len(runs_rows) == 1
    run_row = runs_rows[0]
    assert run_row["status"] == "completed"
    output_ref = completed_task.result_ref if isinstance(completed_task.result_ref, dict) else json.loads(completed_task.result_ref)
    assert output_ref["run_id"] == run_row["run_id"]

    # 8. Assert hypothesis_assessments exist where applicable
    assessments_rows = db_conn.execute(
        "SELECT * FROM hypothesis_assessments WHERE run_id = ?", (run_row["run_id"],)
    ).fetchall()
    assert len(assessments_rows) == 2  # seeded_challenge has 2 hypotheses (h1, h2)

    # 9. Assert ReasoningRunRecorded event exists
    event_row = db_conn.execute(
        "SELECT * FROM events WHERE event_type = 'ReasoningRunRecorded' AND challenge_id = ?",
        (seeded_challenge,),
    ).fetchone()
    assert event_row is not None

    # 10. Assert Phase 5D tables are unchanged
    hyp_count_after = db_conn.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
    ev_count_after = db_conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    bb_ver_after = db_conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?", (seeded_challenge,)).fetchone()[0]
    assert hyp_count_before == hyp_count_after
    assert ev_count_before == ev_count_after
    assert bb_ver_before == bb_ver_after

    # 11. Assert persisted result hash is replay-verifiable
    view = build_reasoning_view(db_conn, seeded_challenge)
    engine = ReasoningEngine()
    fresh_result = engine.analyze(view, run_sequence=1)
    assert fresh_result.result_hash == run_row["result_hash"]
    assert fresh_result.input_fingerprint == run_row["input_fingerprint"]


@pytest.mark.asyncio
async def test_analyze_investigation_handler_missing_repo_fails_closed(seeded_challenge):
    handler = AnalyzeInvestigationHandler(reasoning_repo=None)
    ctx = TaskContext(
        task_id="t1",
        challenge_id=seeded_challenge,
        task_group_id="g1",
        task_type="analyze_investigation",
        parameters={},
        blackboard_snapshot=None,
    )
    res = await handler.execute(ctx)
    assert res.success is False
    assert res.retryable is False
    assert "ReasoningRepository is required" in res.error_message


@pytest.mark.asyncio
async def test_record_prediction_handler_missing_repo_fails_closed(seeded_challenge):
    handler = RecordPredictionHandler(reasoning_repo=None)
    ctx = TaskContext(
        task_id="t1",
        challenge_id=seeded_challenge,
        task_group_id="g1",
        task_type="record_prediction",
        parameters={"hypothesis_id": "h1", "description": "test"},
        blackboard_snapshot=None,
    )
    res = await handler.execute(ctx)
    assert res.success is False
    assert res.retryable is False
    assert "ReasoningRepository is required" in res.error_message


@pytest.mark.asyncio
async def test_record_investigation_link_handler_missing_repo_fails_closed(seeded_challenge):
    handler = RecordInvestigationLinkHandler(reasoning_repo=None)
    ctx = TaskContext(
        task_id="t1",
        challenge_id=seeded_challenge,
        task_group_id="g1",
        task_type="record_investigation_link",
        parameters={
            "source_id": "e1",
            "source_type": "evidence",
            "target_id": "h1",
            "target_type": "hypothesis",
            "relation_type": "supports",
        },
        blackboard_snapshot=None,
    )
    res = await handler.execute(ctx)
    assert res.success is False
    assert res.retryable is False
    assert "ReasoningRepository is required" in res.error_message


@pytest.mark.asyncio
async def test_record_hypothesis_relation_handler_missing_repo_fails_closed(seeded_challenge):
    handler = RecordHypothesisRelationHandler(reasoning_repo=None)
    ctx = TaskContext(
        task_id="t1",
        challenge_id=seeded_challenge,
        task_group_id="g1",
        task_type="record_hypothesis_relation",
        parameters={
            "source_hypothesis_id": "h1",
            "target_hypothesis_id": "h2",
            "relation_type": "competes",
        },
        blackboard_snapshot=None,
    )
    res = await handler.execute(ctx)
    assert res.success is False
    assert res.retryable is False
    assert "ReasoningRepository is required" in res.error_message

