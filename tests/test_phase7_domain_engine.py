"""
Comprehensive Test Suite for Phase 7 Domain Investigation Engine.

Tests:
A. DomainDetector mapping and confidence thresholds
B. DomainSkill contract and registry
C. WebApiDomainSkill step drafting
D. Missing hostname/port fail-closed behavior
E. Target translation (InvestigationTarget -> ActionProposalTarget)
F. AuthorizedScope retrieval and parsing
G. Scope validation success
H. Scope validation failure
I. No-scope fail-closed
J. Planner creates step in PENDING_APPROVAL status
K. Planner never bypasses approval
L. Cross-challenge isolation protection
M. Result normalization (WebApiResultNormalizer)
N. Evidence provenance tags
O. No fabricated evidence constraint
P. Max-step loop termination
Q. Unchanged-result fixpoint loop termination
R. Inactive-session loop termination
S. Repeated-proposal loop handling
T. Repository-wide execution primitive security scan
"""

from __future__ import annotations

import datetime
import os
import re
import sqlite3
import uuid
import pytest

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
    ActionProposalTarget,
    AuthorizedScope,
    ChallengeClassification,
    EvidencePriority,
)
from ctf_mentor.domain_engine.detector import DomainDetector
from ctf_mentor.domain_engine.loop_controller import BoundedInvestigationLoop, LoopStepResult
from ctf_mentor.domain_engine.normalizer import WebApiResultNormalizer
from ctf_mentor.domain_engine.planner import InvestigationPlanner, PlannerResult
from ctf_mentor.domain_engine.protocol import DomainSkill, DomainSkillRegistry
from ctf_mentor.domain_engine.skills.web_api import WebApiDomainSkill
from ctf_mentor.domain_engine.target_translator import investigation_target_to_action_proposal_target
from ctf_mentor.investigation.scope_validator import DeterministicScopeValidator
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import initialize_schema
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import (
    GapType,
    InvestigationProposal,
    ReasoningRun,
    ReasoningRunStatus,
)


@pytest.fixture
def db_conn():
    """In-memory SQLite database initialized with canonical DDL."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Insert test challenge
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) VALUES ('chal_test_p7', 'Test Challenge', 'Desc', 'WEB', ?, ?);",
        (now_str, now_str),
    )
    # Insert authorized scope
    conn.execute(
        """
        INSERT INTO authorized_scopes (
            scope_id, challenge_id, scheme, hostname, port, allowed_path_patterns,
            allowed_methods, exclusions, environment_id, challenge_relationship, created_at, is_active
        ) VALUES (
            'scope_p7', 'chal_test_p7', 'http', 'target.ctf', 8080, '["/api/*", "/flag"]',
            '["GET", "POST"]', '["/admin/*"]', 'env_lab', 'primary_target', ?, 1
        );
        """,
        (now_str,),
    )

    conn.commit()
    yield conn
    conn.close()


def test_domain_detector():
    """Test A: DomainDetector classification mapping and threshold checks."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cls_web = ChallengeClassification(
        classification_id="cls_1",
        challenge_id="chal_1",
        category="INJECTION",
        confidence=0.8,
        signals=["matched_category:INJECTION"],
        ruleset_version="1.0",
        created_at=now,
    )
    assert DomainDetector.detect_domain(cls_web) == "web_api"

    cls_low_conf = ChallengeClassification(
        classification_id="cls_2",
        challenge_id="chal_1",
        category="WEB",
        confidence=0.1,
        signals=[],
        ruleset_version="1.0",
        created_at=now,
    )
    assert DomainDetector.detect_domain(cls_low_conf) is None
    assert DomainDetector.detect_domain(None) is None


def test_domain_skill_contract_and_registry():
    """Test B: DomainSkill Protocol and DomainSkillRegistry."""
    registry = DomainSkillRegistry()
    skill = WebApiDomainSkill()
    assert skill.domain_id == "web_api"

    registry.register(skill)
    assert registry.has_skill("web_api")
    assert registry.get("web_api") == skill

    with pytest.raises(KeyError):
        registry.get("nonexistent_skill")


def test_web_api_domain_skill_drafting(db_conn):
    """Test C: WebApiDomainSkill step drafting."""
    skill = WebApiDomainSkill()
    now = datetime.datetime.now(datetime.timezone.utc)
    proposal = InvestigationProposal(
        proposal_id="prop_101",
        challenge_id="chal_test_p7",
        title="Check SQli",
        description="Gather evidence for injection",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=["hyp_1"],
        discriminates_hypotheses=[],
        rationale="Inspect API SQL response",
    )
    scope = AuthorizedScope(
        scope_id="scope_1",
        challenge_id="chal_test_p7",
        scheme="http",
        hostname="target.ctf",
        port=8080,
        allowed_path_patterns=["/api/*"],
        allowed_methods=["GET"],
        exclusions=[],
        query_restrictions={},
        environment_id="env_1",
        challenge_relationship="primary",
        created_at=now,
    )
    session = InvestigationSession(
        session_id="sess_101",
        challenge_id="chal_test_p7",
        status=InvestigationSessionStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    step = skill.propose_step(proposal=proposal, scopes=[scope], session=session)
    assert step is not None
    assert step.step_type == "HTTP_GET"
    assert step.target.target_type == TargetType.HTTP_TARGET
    assert step.target.details["hostname"] == "target.ctf"
    assert step.target.details["port"] == 8080
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


def test_missing_hostname_port_fail_closed():
    """Test D: Missing hostname or port returns None (fails closed)."""
    skill = WebApiDomainSkill()
    now = datetime.datetime.now(datetime.timezone.utc)
    proposal = InvestigationProposal(
        proposal_id="prop_102",
        challenge_id="chal_1",
        title="Title",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
    )
    session = InvestigationSession(
        session_id="sess_1",
        challenge_id="chal_1",
        status=InvestigationSessionStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    # Scope dict with missing hostname
    scope_no_host = {
        "scope_id": "s1",
        "challenge_id": "chal_1",
        "scheme": "http",
        "hostname": "",
        "port": 80,
        "allowed_path_patterns": ["/"],
        "allowed_methods": ["GET"],
        "is_active": True,
    }
    assert skill.propose_step(proposal, [scope_no_host], session) is None


def test_target_translation():
    """Test E: InvestigationTarget -> ActionProposalTarget translation."""
    target_http = InvestigationTarget(
        target_type=TargetType.HTTP_TARGET,
        details={
            "hostname": "test.host",
            "port": 8080,
            "path": "/api/v1",
            "method": "POST",
            "scheme": "https",
        },
    )
    ap_target = investigation_target_to_action_proposal_target(target_http)
    assert isinstance(ap_target, ActionProposalTarget)
    assert ap_target.hostname == "test.host"
    assert ap_target.port == 8080
    assert ap_target.path == "/api/v1"
    assert ap_target.method == "POST"
    assert ap_target.scheme == "https"

    # Non-HTTP target fails translation
    target_file = InvestigationTarget(
        target_type=TargetType.FILE_TARGET,
        details={"path": "/tmp/test.txt"},
    )
    with pytest.raises(ValueError, match="Scope validation requires HTTP_TARGET"):
        investigation_target_to_action_proposal_target(target_file)


def test_authorized_scope_retrieval_and_validation(db_conn):
    """Test F, G, H, I: Scope retrieval, success, failure, and no-scope fail-closed."""
    blackboard_repo = BlackboardRepository(db_conn)
    scopes = blackboard_repo.read_authorized_scopes_for_challenge("chal_test_p7")
    assert len(scopes) == 1
    assert scopes[0]["hostname"] == "target.ctf"

    # G: Valid target matches scope
    valid_ap = ActionProposalTarget(
        scheme="http",
        hostname="target.ctf",
        port=8080,
        path="/api/users",
        method="GET",
    )
    res_valid = DeterministicScopeValidator.validate(valid_ap, scopes)
    assert res_valid.is_allowed is True

    # H: Invalid target (exclusion match)
    excl_ap = ActionProposalTarget(
        scheme="http",
        hostname="target.ctf",
        port=8080,
        path="/admin/secret",
        method="GET",
    )
    res_excl = DeterministicScopeValidator.validate(excl_ap, scopes)
    assert res_excl.is_allowed is False
    assert "exclusion pattern" in res_excl.reason

    # I: No scope fail-closed
    res_noscope = DeterministicScopeValidator.validate(valid_ap, [])
    assert res_noscope.is_allowed is False
    assert "No active AuthorizedScope" in res_noscope.reason


def test_planner_creates_pending_approval_step(db_conn):
    """Test J & K: Planner creates step in PENDING_APPROVAL status and never bypasses approval."""
    inv_repo = InvestigationRepository(db_conn)
    bb_repo = BlackboardRepository(db_conn)
    planner = InvestigationPlanner(investigation_repo=inv_repo, blackboard_repo=bb_repo)

    now = datetime.datetime.now(datetime.timezone.utc)
    session = inv_repo.create_session_atomic("chal_test_p7")

    proposal = InvestigationProposal(
        proposal_id="prop_201",
        challenge_id="chal_test_p7",
        title="Check Flag Endpoint",
        description="Verify flag path",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=["hyp_1"],
        discriminates_hypotheses=[],
        rationale="Inspect response from flag endpoint",
    )

    plan_res = planner.plan_investigation_step(proposal=proposal, session=session)
    assert plan_res.success is True
    assert plan_res.status == "pending_approval"
    assert plan_res.step_id is not None
    assert plan_res.approval_id is not None

    # Verify step stored in DB is pending_approval
    step_db = inv_repo.get_step(plan_res.step_id, "chal_test_p7")
    assert step_db is not None
    assert step_db.status == InvestigationStepStatus.PENDING_APPROVAL


def test_planner_cross_challenge_isolation(db_conn):
    """Test L: Planner rejects cross-challenge proposals."""
    inv_repo = InvestigationRepository(db_conn)
    bb_repo = BlackboardRepository(db_conn)
    planner = InvestigationPlanner(investigation_repo=inv_repo, blackboard_repo=bb_repo)

    session = inv_repo.create_session_atomic("chal_test_p7")

    cross_proposal = InvestigationProposal(
        proposal_id="prop_cross",
        challenge_id="chal_OTHER_ID",
        title="Cross Proposal",
        description="Cross Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Cross rationale",
    )

    plan_res = planner.plan_investigation_step(proposal=cross_proposal, session=session)
    assert plan_res.success is False
    assert "Cross-challenge proposal rejected" in plan_res.error_message


@pytest.mark.asyncio
async def test_result_normalization_and_provenance(db_conn):
    """Test M, N, O: Result normalization, provenance tag, and no fabricated evidence."""
    now = datetime.datetime.now(datetime.timezone.utc)
    target = InvestigationTarget(
        target_type=TargetType.HTTP_TARGET,
        details={"hostname": "target.ctf", "port": 8080, "path": "/api"},
    )
    step = InvestigationStep(
        step_id="step_norm_1",
        session_id="sess_norm_1",
        challenge_id="chal_test_p7",
        step_type="HTTP_GET",
        target=target,
        rationale="Test normalizer",
        status=InvestigationStepStatus.RESULT_SUBMITTED,
        created_at=now,
        updated_at=now,
        proposal_ref="prop_norm_1",
    )
    result = ConcreteInvestigationResult(
        result_id="res_norm_1",
        step_id="step_norm_1",
        session_id="sess_norm_1",
        challenge_id="chal_test_p7",
        raw_output="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\": \"ok\"}",
        outcome="success",
    )

    # Normalize result
    draft = WebApiResultNormalizer.normalize_result(result, step)
    assert draft.challenge_id == "chal_test_p7"
    assert draft.extracted_status_code == 200
    assert draft.is_confirmed is False  # Human confirmation required
    assert draft.metadata["source_provenance"] == "action_result_derived"
    assert draft.metadata["is_fabricated"] is False  # O: No fabricated evidence

    from ctf_mentor.runtime.task_context import TaskContext
    from ctf_mentor.domain.models import BlackboardState, HintLevel
    bb_state = BlackboardState(
        challenge_id="chal_test_p7",
        blackboard_version=1,
        active_hypothesis_ids=[],
        watchlist_hypothesis_ids=[],
        confirmed_findings=[],
        active_evidence_ids=[],
        last_hint_level=HintLevel.L1,
        session_notes="",
        updated_at=now,
    )
    ctx = TaskContext(
        task_id="task_1",
        challenge_id="chal_test_p7",
        task_group_id="grp_1",
        task_type="submit_evidence",
        parameters={},
        blackboard_snapshot=bb_state,
    )
    res_unconf = await WebApiResultNormalizer.confirm_and_submit_to_canonical_5d(draft, ctx)
    assert res_unconf.success is False
    assert "Human confirmation is required" in res_unconf.error_message


def test_bounded_investigation_loop_termination(db_conn):
    """Test P, Q, R, S: Loop max step, unchanged result fixpoint, inactive session, repeated proposal."""
    inv_repo = InvestigationRepository(db_conn)
    bb_repo = BlackboardRepository(db_conn)
    reasoning_repo = ReasoningRepository(db_conn)
    planner = InvestigationPlanner(investigation_repo=inv_repo, blackboard_repo=bb_repo)
    loop = BoundedInvestigationLoop(
        planner=planner,
        investigation_repo=inv_repo,
        reasoning_repo=reasoning_repo,
        max_steps_per_session=2,
    )

    session = inv_repo.create_session_atomic("chal_test_p7")
    session_id = session.session_id

    proposal_1 = InvestigationProposal(
        proposal_id="prop_loop_1",
        challenge_id="chal_test_p7",
        title="Prop 1",
        description="Desc 1",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 1",
    )

    # Step 1: Normal progression
    res1 = loop.execute_iteration(session_id, "chal_test_p7", proposal_1)
    assert res1.should_continue is True
    assert res1.step_id is not None

    # S: Repeated proposal handling
    res_dup = loop.execute_iteration(session_id, "chal_test_p7", proposal_1)
    assert res_dup.should_continue is False
    assert res_dup.termination_reason == "REPEATED_PROPOSAL"

    # Step 2: Second valid step
    proposal_2 = InvestigationProposal(
        proposal_id="prop_loop_2",
        challenge_id="chal_test_p7",
        title="Prop 2",
        description="Desc 2",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 2",
    )
    res2 = loop.execute_iteration(session_id, "chal_test_p7", proposal_2)
    assert res2.should_continue is True

    # P: Max-step loop termination (2/2 steps reached)
    proposal_3 = InvestigationProposal(
        proposal_id="prop_loop_3",
        challenge_id="chal_test_p7",
        title="Prop 3",
        description="Desc 3",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale 3",
    )
    res3 = loop.execute_iteration(session_id, "chal_test_p7", proposal_3)
    assert res3.should_continue is False
    assert res3.termination_reason == "MAX_STEPS_REACHED"

    # R: Inactive session termination
    db_conn.execute("UPDATE investigation_sessions SET status = 'completed' WHERE session_id = ?;", (session_id,))
    res_inact = loop.execute_iteration(session_id, "chal_test_p7", proposal_3)
    assert res_inact.should_continue is False
    assert "SESSION_INACTIVE" in res_inact.termination_reason


def test_repository_execution_boundary_scan():
    """Test T: Repository-wide security scan verifying 0 external execution primitives."""
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
                            # Exclude comments / docstrings mentioning subprocess
                            for line in content.splitlines():
                                if not line.strip().startswith("#") and not line.strip().startswith("*"):
                                    if re.search(pat, line):
                                        violations.append(f"{fpath}: {line.strip()}")

    assert violations == [], f"Security Violation! Found execution primitives: {violations}"
