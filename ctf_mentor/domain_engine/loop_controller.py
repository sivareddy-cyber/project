"""
BoundedInvestigationLoop for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Deterministic bounded controller; ZERO infinite investigation loops.
2. Enforces configurable max_steps_per_session (default = 5).
3. Verifies active session status (session.status == ACTIVE).
4. Deterministic termination when reasoning result is unchanged (result_hash fixpoint).
5. Prevents repeated execution of identical proposals.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from ctf_mentor.domain.investigation_models import InvestigationSession, InvestigationSessionStatus
from ctf_mentor.domain_engine.planner import InvestigationPlanner, PlannerResult
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import InvestigationProposal, ReasoningRun

logger = logging.getLogger(__name__)


@dataclass
class LoopStepResult:
    """Result of a single iteration of BoundedInvestigationLoop."""

    should_continue: bool
    termination_reason: Optional[str] = None
    planner_result: Optional[PlannerResult] = None
    step_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class BoundedInvestigationLoop:
    """Controller enforcing loop termination conditions for Phase 7 domain engine."""

    def __init__(
        self,
        planner: InvestigationPlanner,
        investigation_repo: InvestigationRepository,
        reasoning_repo: ReasoningRepository,
        max_steps_per_session: int = 5,
    ) -> None:
        if max_steps_per_session < 1:
            raise ValueError("max_steps_per_session must be >= 1")

        self.planner = planner
        self.investigation_repo = investigation_repo
        self.reasoning_repo = reasoning_repo
        self.max_steps_per_session = max_steps_per_session

    def get_session_step_count(self, session_id: str) -> int:
        """Count total investigation steps persisted for a session."""
        cursor = self.investigation_repo.conn.execute(
            "SELECT COUNT(*) FROM investigation_steps WHERE session_id = ?;",
            (session_id,),
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def is_proposal_already_drafted(self, session_id: str, proposal_id: str) -> bool:
        """Check if an investigation step referencing proposal_id already exists for session."""
        cursor = self.investigation_repo.conn.execute(
            "SELECT COUNT(*) FROM investigation_steps WHERE session_id = ? AND proposal_ref = ?;",
            (session_id, proposal_id),
        )
        row = cursor.fetchone()
        return bool(row and row[0] > 0)

    def execute_iteration(
        self,
        session_id: str,
        challenge_id: str,
        proposal: InvestigationProposal,
        previous_result_hash: Optional[str] = None,
        domain_id: str = "web_api",
    ) -> LoopStepResult:
        """Execute one bounded investigation loop step iteration."""
        # 1. Verify Active Session Requirement
        session = self.investigation_repo.get_session(session_id, challenge_id)
        if not session:
            return LoopStepResult(
                should_continue=False,
                termination_reason="SESSION_NOT_FOUND",
            )

        if session.status != InvestigationSessionStatus.ACTIVE:
            return LoopStepResult(
                should_continue=False,
                termination_reason=f"SESSION_INACTIVE_{session.status.value.upper()}",
            )

        # 2. Check Max Steps Per Session Limit
        current_step_count = self.get_session_step_count(session_id)
        if current_step_count >= self.max_steps_per_session:
            logger.info(
                f"Session '{session_id}' reached max step limit ({current_step_count}/{self.max_steps_per_session}). Terminating loop."
            )
            return LoopStepResult(
                should_continue=False,
                termination_reason="MAX_STEPS_REACHED",
                details={"step_count": current_step_count, "max_steps": self.max_steps_per_session},
            )

        # 3. Check Reasoning Fixpoint (Unchanged Reasoning Result Hash)
        latest_run = self.reasoning_repo.get_latest_reasoning_run(challenge_id)
        if latest_run and previous_result_hash:
            if latest_run.result_hash == previous_result_hash:
                logger.info(
                    f"Reasoning result hash unchanged ({latest_run.result_hash}). Terminating loop due to fixpoint."
                )
                return LoopStepResult(
                    should_continue=False,
                    termination_reason="UNCHANGED_REASONING_RESULT",
                    details={"result_hash": latest_run.result_hash},
                )

        # 4. Check Duplicate/Repeated Proposal Handling
        if proposal and self.is_proposal_already_drafted(session_id, proposal.proposal_id):
            logger.info(f"Proposal '{proposal.proposal_id}' already drafted in session '{session_id}'. Terminating loop.")
            return LoopStepResult(
                should_continue=False,
                termination_reason="REPEATED_PROPOSAL",
                details={"proposal_id": proposal.proposal_id},
            )

        # 5. Plan Step via InvestigationPlanner
        planner_res = self.planner.plan_investigation_step(
            proposal=proposal,
            session=session,
            domain_id=domain_id,
        )

        if not planner_res.success:
            return LoopStepResult(
                should_continue=False,
                termination_reason=f"PLANNER_FAILED_{planner_res.error_message}",
                planner_result=planner_res,
            )

        return LoopStepResult(
            should_continue=True,
            termination_reason=None,
            planner_result=planner_res,
            step_id=planner_res.step_id,
            details={"result_hash": latest_run.result_hash if latest_run else None},
        )
