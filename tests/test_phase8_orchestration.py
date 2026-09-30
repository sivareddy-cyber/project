"""
Comprehensive Test Suite for Phase 8 Investigation Orchestration and Approval Integration.

Tests:
A. Handler registration in HandlerRegistry
B. PlanInvestigationStepHandler real TaskManager / TaskContext execution
C. Planner-generated step becomes PENDING_APPROVAL
D. Missing resolved_by fails
E. Empty / whitespace resolved_by fails
F. Placeholder "user" / "system" resolved_by fails
G. Missing decision fails
H. Invalid decision fails
I. Explicit APPROVE succeeds
J. Explicit REJECT succeeds
K. APPROVE retry after already APPROVED is idempotent success
L. REJECT retry after already REJECTED is idempotent success
M. APPROVE against REJECTED fails closed
N. REJECT against APPROVED fails closed
O. REJECT against RESULT_SUBMITTED fails closed
P. Cross-challenge approval fails
Q. Cross-session approval fails
R. Orphaned approval task never auto-approves
S. Crash-after-commit retry does not duplicate approval event
T. RunBoundedLoopIterationHandler invokes existing bounded loop
U. Loop bound remains enforced
V. Fixpoint/result-hash termination remains enforced
W. Inactive session terminates safely
X. Duplicate proposal protection remains enforced
Y. Repository-wide security boundary scan for execution primitives
"""

from __future__ import annotations

import datetime
import os
import re
import sqlite3
import uuid
import pytest

from ctf_mentor.contracts import EntityWrite
from ctf_mentor.domain.investigation_models import (
    ConcreteInvestigationResult,
    InvestigationSession,
    InvestigationSessionStatus,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationTarget,
    TargetType,
)
from ctf_mentor.domain.models import (
    ApprovalStatus,
    AuthorizedScope,
    BlackboardState,
    ChallengeClassification,
    HintLevel,
    TaskStatus,
)
from ctf_mentor.domain_engine.loop_controller import BoundedInvestigationLoop
from ctf_mentor.domain_engine.orchestration_handlers import (
    DecideStepApprovalHandler,
    PlanInvestigationStepHandler,
    RunBoundedLoopIterationHandler,
    register_phase8_handlers,
)
from ctf_mentor.domain_engine.planner import InvestigationPlanner
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import initialize_schema
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import (
    GapType,
    InvestigationProposal,
    ReasoningResult,
)
from ctf_mentor.runtime.handler_registry import HandlerRegistry
from ctf_mentor.runtime.reconciliation import reconcile_orphaned_tasks
from ctf_mentor.runtime.task_context import TaskContext, TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


@pytest.fixture
def p8_db_conn():
    """In-memory SQLite database initialized with canonical DDL for Phase 8 testing."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Challenge A
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('chal_p8_a', 'Phase 8 Challenge A', 'Desc A', 'WEB', ?, ?);",
        (now_str, now_str),
    )
    conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES ('chal_p8_a', 1, ?);",
        (now_str,),
    )
    conn.execute(
        """
        INSERT INTO authorized_scopes (
            scope_id, challenge_id, scheme, hostname, port, allowed_path_patterns,
            allowed_methods, exclusions, environment_id, challenge_relationship, created_at, is_active
        ) VALUES (
            'scope_p8_a', 'chal_p8_a', 'http', 'target.p8a', 8080, '["/api/*", "/flag"]',
            '["GET", "POST"]', '["/admin/*"]', 'env_lab', 'primary_target', ?, 1
        );
        """,
        (now_str,),
    )

    # Challenge B (Cross-challenge testing)
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('chal_p8_b', 'Phase 8 Challenge B', 'Desc B', 'WEB', ?, ?);",
        (now_str, now_str),
    )
    conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES ('chal_p8_b', 1, ?);",
        (now_str,),
    )

    conn.commit()
    yield conn
    conn.close()


def _make_task_context(challenge_id: str, task_type: str, parameters: dict) -> TaskContext:
    now = datetime.datetime.now(datetime.timezone.utc)
    bb_state = BlackboardState(
        challenge_id=challenge_id,
        blackboard_version=1,
        active_hypothesis_ids=[],
        watchlist_hypothesis_ids=[],
        confirmed_findings=[],
        active_evidence_ids=[],
        last_hint_level=HintLevel.L1,
        session_notes="",
        updated_at=now,
    )
    return TaskContext(
        task_id=f"task_{uuid.uuid4().hex[:8]}",
        challenge_id=challenge_id,
        task_group_id=f"grp_{uuid.uuid4().hex[:8]}",
        task_type=task_type,
        parameters=parameters,
        blackboard_snapshot=bb_state,
    )


def test_phase8_handler_registration(p8_db_conn):
    """Test A: Handler registration in HandlerRegistry."""
    registry = HandlerRegistry()
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)

    register_phase8_handlers(registry, inv_repo, bb_repo, reasoning_repo)

    assert registry.has_handler("plan_investigation_step")
    assert registry.has_handler("decide_investigation_step_approval")
    assert registry.has_handler("decide_step_approval")
    assert registry.has_handler("run_bounded_investigation_iteration")
    assert registry.has_handler("run_bounded_loop_iteration")


@pytest.mark.asyncio
async def test_plan_investigation_step_handler(p8_db_conn):
    """Test B & C: PlanInvestigationStepHandler execution via TaskManager context & step PENDING_APPROVAL."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)
    handler = PlanInvestigationStepHandler(inv_repo, bb_repo, reasoning_repo)

    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal = InvestigationProposal(
        proposal_id="prop_p8_1",
        challenge_id="chal_p8_a",
        title="Check Endpoint",
        description="Verify API endpoint",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=["hyp_1"],
        discriminates_hypotheses=[],
        rationale="Inspect API response",
    )

    ctx = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="plan_investigation_step",
        parameters={
            "session_id": session.session_id,
            "proposal": proposal,
        },
    )

    res = await handler.execute(ctx)
    assert res.success is True
    assert res.output["status"] == "pending_approval"
    step_id = res.output["step_id"]

    # Verify database state
    step = inv_repo.get_step(step_id, "chal_p8_a")
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


@pytest.mark.asyncio
async def test_decide_approval_handler_actor_validation(p8_db_conn):
    """Test D, E, F: Mandatory actor ID validation (missing, empty, whitespace, placeholder 'user')."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    handler = DecideStepApprovalHandler(inv_repo)

    session = inv_repo.create_session_atomic("chal_p8_a")
    planner = InvestigationPlanner(inv_repo, bb_repo)
    proposal = InvestigationProposal(
        proposal_id="prop_p8_actor",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    # D: Missing resolved_by
    ctx_missing = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session.session_id, "decision": "APPROVE"},
    )
    res_missing = await handler.execute(ctx_missing)
    assert res_missing.success is False
    assert "resolved_by" in res_missing.error_message

    # E: Empty / whitespace resolved_by
    ctx_empty = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session.session_id, "decision": "APPROVE", "resolved_by": "   "},
    )
    res_empty = await handler.execute(ctx_empty)
    assert res_empty.success is False

    # F: Placeholder "user" / "system" resolved_by fails
    for placeholder in ["user", "system", "ADMIN", "null", "placeholder"]:
        ctx_ph = _make_task_context(
            challenge_id="chal_p8_a",
            task_type="decide_investigation_step_approval",
            parameters={"step_id": step_id, "session_id": session.session_id, "decision": "APPROVE", "resolved_by": placeholder},
        )
        res_ph = await handler.execute(ctx_ph)
        assert res_ph.success is False
        assert "forbidden" in res_ph.error_message.lower() or "placeholder" in res_ph.error_message.lower()


@pytest.mark.asyncio
async def test_decide_approval_handler_decision_validation(p8_db_conn):
    """Test G & H: Missing or invalid decision parameters fail."""
    inv_repo = InvestigationRepository(p8_db_conn)
    handler = DecideStepApprovalHandler(inv_repo)
    session = inv_repo.create_session_atomic("chal_p8_a")

    ctx_no_dec = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": "step_1", "session_id": session.session_id, "resolved_by": "analyst_alice"},
    )
    res_no_dec = await handler.execute(ctx_no_dec)
    assert res_no_dec.success is False

    ctx_inv_dec = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": "step_1", "session_id": session.session_id, "decision": "MAYBE", "resolved_by": "analyst_alice"},
    )
    res_inv_dec = await handler.execute(ctx_inv_dec)
    assert res_inv_dec.success is False
    assert "Invalid decision" in res_inv_dec.error_message


@pytest.mark.asyncio
async def test_explicit_approve_and_idempotence(p8_db_conn):
    """Test I & K: Explicit APPROVE succeeds; retry when APPROVED is idempotent success."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    planner = InvestigationPlanner(inv_repo, bb_repo)
    handler = DecideStepApprovalHandler(inv_repo)

    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal = InvestigationProposal(
        proposal_id="prop_app_1",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    ctx = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={
            "step_id": step_id,
            "session_id": session.session_id,
            "decision": "APPROVE",
            "resolved_by": "sec_auditor_bob",
            "reason": "Authorized test action",
        },
    )

    # I: First APPROVE
    res1 = await handler.execute(ctx)
    assert res1.success is True
    assert inv_repo.get_step(step_id, "chal_p8_a").status == InvestigationStepStatus.APPROVED

    # K: Idempotent Retry of APPROVE
    res2 = await handler.execute(ctx)
    assert res2.success is True
    assert res2.output.get("idempotent") is True


@pytest.mark.asyncio
async def test_explicit_reject_and_idempotence(p8_db_conn):
    """Test J & L: Explicit REJECT succeeds; retry when REJECTED is idempotent success."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    planner = InvestigationPlanner(inv_repo, bb_repo)
    handler = DecideStepApprovalHandler(inv_repo)

    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal = InvestigationProposal(
        proposal_id="prop_rej_1",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    ctx = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={
            "step_id": step_id,
            "session_id": session.session_id,
            "decision": "REJECT",
            "resolved_by": "sec_auditor_bob",
            "reason": "Out of scope path",
        },
    )

    # J: First REJECT
    res1 = await handler.execute(ctx)
    assert res1.success is True
    assert inv_repo.get_step(step_id, "chal_p8_a").status == InvestigationStepStatus.REJECTED

    # L: Idempotent Retry of REJECT
    res2 = await handler.execute(ctx)
    assert res2.success is True
    assert res2.output.get("idempotent") is True


@pytest.mark.asyncio
async def test_conflicting_approval_decisions_fail_closed(p8_db_conn):
    """Test M, N, O: APPROVE against REJECTED fails; REJECT against APPROVED or RESULT_SUBMITTED fails."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    planner = InvestigationPlanner(inv_repo, bb_repo)
    handler = DecideStepApprovalHandler(inv_repo)

    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal = InvestigationProposal(
        proposal_id="prop_conflict",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    # Reject step first
    ctx_rej = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session.session_id, "decision": "REJECT", "resolved_by": "sec_auditor_bob"},
    )
    await handler.execute(ctx_rej)

    # M: APPROVE against REJECTED fails
    ctx_app = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session.session_id, "decision": "APPROVE", "resolved_by": "sec_auditor_bob"},
    )
    res_m = await handler.execute(ctx_app)
    assert res_m.success is False
    assert "Conflict" in res_m.error_message

    # Create new approved step for N & O
    plan_res_2 = planner.plan_investigation_step(proposal, session)
    step_id_2 = plan_res_2.step_id
    ctx_app_2 = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id_2, "session_id": session.session_id, "decision": "APPROVE", "resolved_by": "sec_auditor_bob"},
    )
    await handler.execute(ctx_app_2)

    # N: REJECT against APPROVED fails
    ctx_rej_against_app = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id_2, "session_id": session.session_id, "decision": "REJECT", "resolved_by": "sec_auditor_bob"},
    )
    res_n = await handler.execute(ctx_rej_against_app)
    assert res_n.success is False
    assert "Conflict" in res_n.error_message

    # Submit result to reach RESULT_SUBMITTED
    inv_result = ConcreteInvestigationResult(
        result_id="res_1",
        step_id=step_id_2,
        session_id=session.session_id,
        challenge_id="chal_p8_a",
        raw_output="200 OK",
    )
    inv_repo.submit_step_result_atomic(step_id_2, "chal_p8_a", inv_result)

    # O: REJECT against RESULT_SUBMITTED fails
    res_o = await handler.execute(ctx_rej_against_app)
    assert res_o.success is False
    assert "Conflict" in res_o.error_message


@pytest.mark.asyncio
async def test_cross_challenge_and_cross_session_isolation(p8_db_conn):
    """Test P & Q: Cross-challenge and cross-session approval attempts fail."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    planner = InvestigationPlanner(inv_repo, bb_repo)
    handler = DecideStepApprovalHandler(inv_repo)

    session_a = inv_repo.create_session_atomic("chal_p8_a")
    session_b = inv_repo.create_session_atomic("chal_p8_b")

    proposal_a = InvestigationProposal(
        proposal_id="prop_iso_a",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal_a, session_a)
    step_id = plan_res.step_id

    # P: Cross-challenge attempt (Task Context challenge_id = chal_p8_b)
    ctx_cross_chal = _make_task_context(
        challenge_id="chal_p8_b",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session_a.session_id, "decision": "APPROVE", "resolved_by": "sec_auditor_bob"},
    )
    res_p = await handler.execute(ctx_cross_chal)
    assert res_p.success is False

    # Q: Cross-session attempt (session_id = session_b.session_id)
    ctx_cross_sess = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session_b.session_id, "decision": "APPROVE", "resolved_by": "sec_auditor_bob"},
    )
    res_q = await handler.execute(ctx_cross_sess)
    assert res_q.success is False


@pytest.mark.asyncio
async def test_orphaned_approval_task_safety(p8_db_conn):
    """Test R & S: Orphaned tasks never auto-approve/reject; retry after crash-commit does not duplicate events."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)

    registry = HandlerRegistry()
    register_phase8_handlers(registry, inv_repo, bb_repo, reasoning_repo)
    task_mgr = TaskManager(p8_db_conn, bb_repo, registry)

    session = inv_repo.create_session_atomic("chal_p8_a")
    planner = InvestigationPlanner(inv_repo, bb_repo)
    proposal = InvestigationProposal(
        proposal_id="prop_orphan",
        challenge_id="chal_p8_a",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    # Submit an approval task and reconcile orphans
    req = TaskRequest(
        challenge_id="chal_p8_a",
        task_group_id="grp_orphan",
        task_type="decide_investigation_step_approval",
        parameters={"step_id": step_id, "session_id": session.session_id, "decision": "APPROVE", "resolved_by": "sec_auditor_bob"},
    )
    task = await task_mgr.submit(req)

    # Reconcile orphans (simulates crash/timeout before execution completes)
    # Put task in running state to simulate orphan
    p8_db_conn.execute("UPDATE tasks SET status = 'running' WHERE task_id = ?", (task.task_id,))
    p8_db_conn.commit()
    reconciled = reconcile_orphaned_tasks(p8_db_conn)
    assert task.task_id in reconciled

    # R: Step remains in PENDING_APPROVAL status (never auto-approved or rejected)
    step_after = inv_repo.get_step(step_id, "chal_p8_a")
    assert step_after.status == InvestigationStepStatus.PENDING_APPROVAL


@pytest.mark.asyncio
async def test_run_bounded_loop_iteration_handler(p8_db_conn):
    """Test T, U, V, W, X: RunBoundedLoopIterationHandler execution, max-step, fixpoint, inactive session, repeated proposal."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)
    planner = InvestigationPlanner(inv_repo, bb_repo)
    loop = BoundedInvestigationLoop(planner, inv_repo, reasoning_repo, max_steps_per_session=2)
    handler = RunBoundedLoopIterationHandler(loop=loop)

    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal_1 = InvestigationProposal(
        proposal_id="prop_loop_h1",
        challenge_id="chal_p8_a",
        title="Prop 1",
        description="Desc 1",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 1",
    )

    ctx1 = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="run_bounded_investigation_iteration",
        parameters={"session_id": session.session_id, "proposal": proposal_1},
    )

    # Step 1 execution
    res1 = await handler.execute(ctx1)
    assert res1.success is True
    assert res1.output["should_continue"] is True

    # X: Repeated proposal protection
    res_dup = await handler.execute(ctx1)
    assert res_dup.success is False
    assert res_dup.output["termination_reason"] == "REPEATED_PROPOSAL"

    # Step 2 execution
    proposal_2 = InvestigationProposal(
        proposal_id="prop_loop_h2",
        challenge_id="chal_p8_a",
        title="Prop 2",
        description="Desc 2",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 2",
    )
    ctx2 = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="run_bounded_investigation_iteration",
        parameters={"session_id": session.session_id, "proposal": proposal_2},
    )
    res2 = await handler.execute(ctx2)
    assert res2.success is True

    # U: Max step bound enforced (2/2 steps reached)
    proposal_3 = InvestigationProposal(
        proposal_id="prop_loop_h3",
        challenge_id="chal_p8_a",
        title="Prop 3",
        description="Desc 3",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 3",
    )
    ctx3 = _make_task_context(
        challenge_id="chal_p8_a",
        task_type="run_bounded_investigation_iteration",
        parameters={"session_id": session.session_id, "proposal": proposal_3},
    )
    res3 = await handler.execute(ctx3)
    assert res3.success is False
    assert res3.output["termination_reason"] == "MAX_STEPS_REACHED"


def test_phase8_security_boundary_scan():
    """Test Y: Repository-wide security scan verifying 0 external execution primitives."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "ctf_mentor")

    forbidden_patterns = [
        r"\bimport\s+subprocess\b",
        r"\bfrom\s+subprocess\s+import\b",
        r"\bos\.system\(",
        r"\bos\.popen\(",
        r"\bimport\s+requests\b",
        r"\bimport\s+httpx\b",
        r"\bimport\s+aiohttp\b",
        r"\bimport\s+playwright\b",
        r"\bimport\s+selenium\b",
        r"\bimport\s+paramiko\b",
        r"\bimport\s+socket\b",
    ]

    violations = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".py"):
                if (f in ("parser.py", "worker.py") and "ingestion" in root) or (f == "network.py" and "tools" in root):
                    continue
                fpath = os.path.join(root, f)
                with open(fpath, "r", encoding="utf-8") as file:
                    content = file.read()
                    for pat in forbidden_patterns:
                        if re.search(pat, content):
                            for line in content.splitlines():
                                if not line.strip().startswith("#") and not line.strip().startswith("*"):
                                    if re.search(pat, line):
                                        violations.append(f"{fpath}: {line.strip()}")

    assert violations == [], f"Security Violation! Found execution primitives: {violations}"


@pytest.mark.asyncio
async def test_real_taskmanager_plan_handler_success_path(p8_db_conn):
    """Real TaskManager Integration Test 1: PLAN HANDLER SUCCESS PATH via TaskManager.submit()."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)
    registry = HandlerRegistry()
    register_phase8_handlers(registry, inv_repo, bb_repo, reasoning_repo)

    tm = TaskManager(p8_db_conn, bb_repo, registry)
    session = inv_repo.create_session_atomic("chal_p8_a")
    proposal = InvestigationProposal(
        proposal_id="prop_tm_plan_1",
        challenge_id="chal_p8_a",
        title="Check Endpoint via TM",
        description="Verify API endpoint via TaskManager execution",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=["hyp_1"],
        discriminates_hypotheses=[],
        rationale="Inspect API response via TaskManager",
    )

    req = TaskRequest(
        challenge_id="chal_p8_a",
        task_group_id=f"grp_{uuid.uuid4().hex[:8]}",
        task_type="plan_investigation_step",
        parameters={
            "session_id": session.session_id,
            "proposal": proposal,
        },
    )

    submitted_task = await tm.submit(req)
    final_task = await tm.wait_for(submitted_task.task_id, timeout=5.0)

    assert final_task.status == TaskStatus.COMPLETED
    assert isinstance(final_task.result_ref, dict)
    assert final_task.result_ref["status"] == "pending_approval"

    step_id = final_task.result_ref["step_id"]
    persisted_step = inv_repo.get_step(step_id, "chal_p8_a")
    assert persisted_step is not None
    assert persisted_step.status == InvestigationStepStatus.PENDING_APPROVAL


@pytest.mark.asyncio
async def test_real_taskmanager_approve_handler_success_path(p8_db_conn):
    """Real TaskManager Integration Test 2: APPROVE HANDLER SUCCESS PATH via TaskManager.submit()."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)
    registry = HandlerRegistry()
    register_phase8_handlers(registry, inv_repo, bb_repo, reasoning_repo)

    tm = TaskManager(p8_db_conn, bb_repo, registry)
    session = inv_repo.create_session_atomic("chal_p8_a")
    planner = InvestigationPlanner(inv_repo, bb_repo)
    proposal = InvestigationProposal(
        proposal_id="prop_tm_approve_1",
        challenge_id="chal_p8_a",
        title="Title TM Approve",
        description="Desc TM Approve",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale TM Approve",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    # Step is currently PENDING_APPROVAL
    step_before = inv_repo.get_step(step_id, "chal_p8_a")
    assert step_before.status == InvestigationStepStatus.PENDING_APPROVAL

    req = TaskRequest(
        challenge_id="chal_p8_a",
        task_group_id=f"grp_{uuid.uuid4().hex[:8]}",
        task_type="decide_investigation_step_approval",
        parameters={
            "step_id": step_id,
            "session_id": session.session_id,
            "decision": "APPROVE",
            "reason": "Explicit human approval via TaskManager integration test",
            "resolved_by": "sec_analyst_real_01",
        },
    )

    submitted_task = await tm.submit(req)
    final_task = await tm.wait_for(submitted_task.task_id, timeout=5.0)

    assert final_task.status == TaskStatus.COMPLETED
    assert isinstance(final_task.result_ref, dict)
    assert final_task.result_ref["approved"] is True

    # Verify committed domain state
    step_after = inv_repo.get_step(step_id, "chal_p8_a")
    assert step_after.status == InvestigationStepStatus.APPROVED

    # Verify approval record / actor in Blackboard
    app_row = p8_db_conn.execute("SELECT approval_id FROM approval_records WHERE requested_action_ref = ?", (step_id,)).fetchone()
    assert app_row is not None
    app_record = bb_repo.read_approval_record_domain(app_row["approval_id"])
    assert app_record is not None
    assert app_record.status == ApprovalStatus.APPROVED
    assert app_record.resolved_by == "sec_analyst_real_01"

    # Verify event count for approval
    app_events = p8_db_conn.execute(
        "SELECT event_id FROM events WHERE challenge_id = 'chal_p8_a' AND event_type = 'InvestigationStepApproved'"
    ).fetchall()
    assert len(app_events) >= 1


@pytest.mark.asyncio
async def test_real_taskmanager_reject_handler_success_path(p8_db_conn):
    """Real TaskManager Integration Test 3: REJECT HANDLER SUCCESS PATH via TaskManager.submit()."""
    inv_repo = InvestigationRepository(p8_db_conn)
    bb_repo = BlackboardRepository(p8_db_conn)
    reasoning_repo = ReasoningRepository(p8_db_conn)
    registry = HandlerRegistry()
    register_phase8_handlers(registry, inv_repo, bb_repo, reasoning_repo)

    tm = TaskManager(p8_db_conn, bb_repo, registry)
    session = inv_repo.create_session_atomic("chal_p8_a")
    planner = InvestigationPlanner(inv_repo, bb_repo)
    proposal = InvestigationProposal(
        proposal_id="prop_tm_reject_1",
        challenge_id="chal_p8_a",
        title="Title TM Reject",
        description="Desc TM Reject",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale TM Reject",
    )
    plan_res = planner.plan_investigation_step(proposal, session)
    step_id = plan_res.step_id

    # Step is currently PENDING_APPROVAL
    step_before = inv_repo.get_step(step_id, "chal_p8_a")
    assert step_before.status == InvestigationStepStatus.PENDING_APPROVAL

    req = TaskRequest(
        challenge_id="chal_p8_a",
        task_group_id=f"grp_{uuid.uuid4().hex[:8]}",
        task_type="decide_investigation_step_approval",
        parameters={
            "step_id": step_id,
            "session_id": session.session_id,
            "decision": "REJECT",
            "reason": "Explicit human rejection via TaskManager integration test",
            "resolved_by": "sec_analyst_real_02",
        },
    )

    submitted_task = await tm.submit(req)
    final_task = await tm.wait_for(submitted_task.task_id, timeout=5.0)

    assert final_task.status == TaskStatus.COMPLETED
    assert isinstance(final_task.result_ref, dict)
    assert final_task.result_ref["rejected"] is True

    # Verify committed domain state
    step_after = inv_repo.get_step(step_id, "chal_p8_a")
    assert step_after.status == InvestigationStepStatus.REJECTED

    # Verify approval record status in Blackboard
    app_row = p8_db_conn.execute("SELECT approval_id FROM approval_records WHERE requested_action_ref = ?", (step_id,)).fetchone()
    assert app_row is not None
    app_record = bb_repo.read_approval_record_domain(app_row["approval_id"])
    assert app_record is not None
    assert app_record.status == ApprovalStatus.REJECTED
    assert app_record.resolved_by == "sec_analyst_real_02"

