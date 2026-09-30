"""
TaskHandlers for Phase 8 Investigation Orchestration and Approval Integration.

LOCKED SECURITY INVARIANTS:
1. Thin TaskManager adapters around Phase 7 InvestigationPlanner & BoundedInvestigationLoop.
2. DecideStepApprovalHandler strictly enforces explicit human actor ID (resolved_by). Placeholder/default values (e.g. "user") are REJECTED.
3. Idempotent retry safety: Retrying APPROVE on APPROVED step or REJECT on REJECTED step is success without duplicate events. Conflicting transitions fail closed.
4. Orphan tasks NEVER automatically approve or reject investigation steps.
5. ZERO autonomous execution primitives (0 subprocess, sockets, HTTP clients, browser automation, or LLM tool calls).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Set

from ctf_mentor.domain.investigation_models import InvestigationStepStatus
from ctf_mentor.domain_engine.loop_controller import BoundedInvestigationLoop
from ctf_mentor.domain_engine.planner import InvestigationPlanner
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import GapType, InvestigationProposal
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

logger = logging.getLogger(__name__)

FORBIDDEN_ACTOR_IDS: Set[str] = {
    "user",
    "system",
    "none",
    "null",
    "unknown",
    "admin",
    "default",
    "placeholder",
    "anonymous",
}


def _parse_proposal_from_params_or_repo(
    params: Dict[str, Any],
    challenge_id: str,
    reasoning_repo: Optional[ReasoningRepository],
) -> Optional[InvestigationProposal]:
    """Extract or reconstruct InvestigationProposal from task parameters or latest ReasoningRun."""
    raw_prop = params.get("proposal")
    if isinstance(raw_prop, InvestigationProposal):
        return raw_prop

    if isinstance(raw_prop, dict):
        try:
            return InvestigationProposal(
                proposal_id=str(raw_prop["proposal_id"]),
                challenge_id=challenge_id,
                title=str(raw_prop.get("title", "")),
                description=str(raw_prop.get("description", "")),
                gap_type=GapType(raw_prop.get("gap_type", GapType.NO_USER_CONFIRMED_SUPPORT.value)),
                target_hypothesis_ids=list(raw_prop.get("target_hypothesis_ids", [])),
                discriminates_hypotheses=list(raw_prop.get("discriminates_hypotheses", [])),
                rationale=str(raw_prop.get("rationale", "")),
                metadata=dict(raw_prop.get("metadata", {})),
            )
        except Exception as ex:
            logger.warning("Failed to parse proposal dict from parameters: %s", ex)

    if reasoning_repo:
        latest_run = reasoning_repo.get_latest_reasoning_run(challenge_id)
        if latest_run and latest_run.canonical_result:
            try:
                canonical_data = json.loads(latest_run.canonical_result)
                proposals_raw = canonical_data.get("proposals", [])
                target_prop_id = params.get("proposal_id")
                for p_dict in proposals_raw:
                    if not target_prop_id or p_dict.get("proposal_id") == target_prop_id:
                        return InvestigationProposal(
                            proposal_id=str(p_dict["proposal_id"]),
                            challenge_id=challenge_id,
                            title=str(p_dict.get("title", "")),
                            description=str(p_dict.get("description", "")),
                            gap_type=GapType(p_dict.get("gap_type", GapType.NO_USER_CONFIRMED_SUPPORT.value)),
                            target_hypothesis_ids=list(p_dict.get("target_hypothesis_ids", [])),
                            discriminates_hypotheses=list(p_dict.get("discriminates_hypotheses", [])),
                            rationale=str(p_dict.get("rationale", "")),
                            metadata=dict(p_dict.get("metadata", {})),
                        )
            except Exception as ex:
                logger.warning("Failed to parse proposals from latest ReasoningRun: %s", ex)

    return None


class PlanInvestigationStepHandler(TaskHandler):
    """TaskHandler for 'plan_investigation_step' task type."""

    def __init__(
        self,
        investigation_repo: Optional[InvestigationRepository] = None,
        blackboard_repo: Optional[BlackboardRepository] = None,
        reasoning_repo: Optional[ReasoningRepository] = None,
        planner: Optional[InvestigationPlanner] = None,
    ) -> None:
        self.investigation_repo = investigation_repo
        self.blackboard_repo = blackboard_repo
        self.reasoning_repo = reasoning_repo
        self.planner = planner

        if not self.planner and self.investigation_repo and self.blackboard_repo:
            self.planner = InvestigationPlanner(
                investigation_repo=self.investigation_repo,
                blackboard_repo=self.blackboard_repo,
            )

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.investigation_repo or not self.planner:
            return HandlerResult(
                success=False,
                error_message="InvestigationRepository and InvestigationPlanner are required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        session_id = params.get("session_id")
        if not session_id:
            return HandlerResult(
                success=False,
                error_message="Parameter 'session_id' is required.",
                retryable=False,
            )

        session = self.investigation_repo.get_session(session_id, ctx.challenge_id)
        if not session:
            return HandlerResult(
                success=False,
                error_message=f"Session {session_id!r} not found for challenge {ctx.challenge_id!r}.",
                retryable=False,
            )

        proposal = _parse_proposal_from_params_or_repo(params, ctx.challenge_id, self.reasoning_repo)
        if not proposal:
            return HandlerResult(
                success=False,
                error_message=f"No valid InvestigationProposal found for challenge '{ctx.challenge_id}'.",
                retryable=False,
            )

        domain_id = params.get("domain_id", "web_api")
        ttl_seconds = int(params.get("ttl_seconds", 3600))

        plan_res = self.planner.plan_investigation_step(
            proposal=proposal,
            session=session,
            domain_id=domain_id,
            ttl_seconds=ttl_seconds,
        )

        if not plan_res.success:
            return HandlerResult(
                success=False,
                error_message=f"InvestigationPlanner failed: {plan_res.error_message}",
                retryable=False,
            )

        return HandlerResult(
            success=True,
            output={
                "step_id": plan_res.step_id,
                "approval_id": plan_res.approval_id,
                "status": plan_res.status,
                "details": plan_res.details,
            },
        )


class DecideStepApprovalHandler(TaskHandler):
    """TaskHandler for 'decide_investigation_step_approval' task type."""

    def __init__(self, investigation_repo: Optional[InvestigationRepository] = None) -> None:
        self.investigation_repo = investigation_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.investigation_repo:
            return HandlerResult(
                success=False,
                error_message="InvestigationRepository is required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        step_id = params.get("step_id")
        session_id = params.get("session_id")
        decision_raw = params.get("decision")
        reason = str(params.get("reason") or params.get("decision_reason") or "").strip()
        resolved_by_raw = params.get("resolved_by")

        if not step_id or not session_id:
            return HandlerResult(
                success=False,
                error_message="Parameters 'step_id' and 'session_id' are required.",
                retryable=False,
            )

        if not decision_raw or not isinstance(decision_raw, str):
            return HandlerResult(
                success=False,
                error_message="Parameter 'decision' is required and must be a string ('APPROVE' or 'REJECT').",
                retryable=False,
            )

        decision = decision_raw.strip().upper()
        if decision not in {"APPROVE", "REJECT"}:
            return HandlerResult(
                success=False,
                error_message=f"Invalid decision '{decision_raw}'. Must be 'APPROVE' or 'REJECT'.",
                retryable=False,
            )

        # MANDATORY ACTOR ID VALIDATION
        if not resolved_by_raw or not isinstance(resolved_by_raw, str) or not resolved_by_raw.strip():
            return HandlerResult(
                success=False,
                error_message="Explicit human actor ID ('resolved_by') is required and cannot be empty.",
                retryable=False,
            )

        resolved_by = resolved_by_raw.strip()
        if resolved_by.lower() in FORBIDDEN_ACTOR_IDS:
            return HandlerResult(
                success=False,
                error_message=f"Placeholder actor ID {resolved_by!r} is forbidden for human approval decisions.",
                retryable=False,
            )

        # Fetch step and validate ownership
        step = self.investigation_repo.get_step(step_id, ctx.challenge_id)
        if not step:
            return HandlerResult(
                success=False,
                error_message=f"InvestigationStep {step_id!r} not found for challenge {ctx.challenge_id!r}.",
                retryable=False,
            )

        if step.challenge_id != ctx.challenge_id or step.session_id != session_id:
            return HandlerResult(
                success=False,
                error_message=f"Cross-challenge or cross-session validation failed for step {step_id!r}.",
                retryable=False,
            )

        current_status = step.status

        # --- APPROVE PATH ---
        if decision == "APPROVE":
            if current_status == InvestigationStepStatus.APPROVED:
                return HandlerResult(
                    success=True,
                    output={
                        "step_id": step_id,
                        "challenge_id": ctx.challenge_id,
                        "session_id": session_id,
                        "status": "approved",
                        "idempotent": True,
                        "message": "Step was already approved.",
                    },
                )

            if current_status in {
                InvestigationStepStatus.REJECTED,
                InvestigationStepStatus.CANCELLED,
                InvestigationStepStatus.EXPIRED,
                InvestigationStepStatus.CONSUMED,
                InvestigationStepStatus.RESULT_SUBMITTED,
                InvestigationStepStatus.CONFIRMING,
            }:
                return HandlerResult(
                    success=False,
                    error_message=f"Conflict: Cannot APPROVE step '{step_id}' currently in state '{current_status.value}'.",
                    retryable=False,
                )

            try:
                self.investigation_repo.approve_step_atomic(
                    step_id=step_id,
                    challenge_id=ctx.challenge_id,
                    user_id=resolved_by,
                    decision_reason=reason,
                )
                return HandlerResult(
                    success=True,
                    output={
                        "step_id": step_id,
                        "challenge_id": ctx.challenge_id,
                        "session_id": session_id,
                        "status": "approved",
                        "approved": True,
                        "idempotent": False,
                    },
                )
            except Exception as ex:
                fresh_step = self.investigation_repo.get_step(step_id, ctx.challenge_id)
                if fresh_step and fresh_step.status == InvestigationStepStatus.APPROVED:
                    return HandlerResult(
                        success=True,
                        output={
                            "step_id": step_id,
                            "challenge_id": ctx.challenge_id,
                            "session_id": session_id,
                            "status": "approved",
                            "approved": True,
                            "idempotent": True,
                            "message": "Step was approved by concurrent/retry transaction.",
                        },
                    )
                return HandlerResult(
                    success=False,
                    error_message=f"Approval failed: {ex}",
                    retryable=False,
                )

        # --- REJECT PATH ---
        if decision == "REJECT":
            if current_status == InvestigationStepStatus.REJECTED:
                return HandlerResult(
                    success=True,
                    output={
                        "step_id": step_id,
                        "challenge_id": ctx.challenge_id,
                        "session_id": session_id,
                        "status": "rejected",
                        "rejected": True,
                        "idempotent": True,
                        "message": "Step was already rejected.",
                    },
                )

            if current_status in {
                InvestigationStepStatus.APPROVED,
                InvestigationStepStatus.RESULT_SUBMITTED,
                InvestigationStepStatus.CONFIRMING,
                InvestigationStepStatus.CONSUMED,
                InvestigationStepStatus.CANCELLED,
                InvestigationStepStatus.EXPIRED,
            }:
                return HandlerResult(
                    success=False,
                    error_message=f"Conflict: Cannot REJECT step '{step_id}' currently in state '{current_status.value}'.",
                    retryable=False,
                )

            if current_status not in {InvestigationStepStatus.PENDING_APPROVAL, InvestigationStepStatus.DRAFT}:
                return HandlerResult(
                    success=False,
                    error_message=f"Step '{step_id}' must be in pending_approval status to reject, found '{current_status.value}'.",
                    retryable=False,
                )

            try:
                self.investigation_repo.reject_step_atomic(
                    step_id=step_id,
                    challenge_id=ctx.challenge_id,
                    user_id=resolved_by,
                    decision_reason=reason,
                )
                return HandlerResult(
                    success=True,
                    output={
                        "step_id": step_id,
                        "challenge_id": ctx.challenge_id,
                        "session_id": session_id,
                        "status": "rejected",
                        "rejected": True,
                        "idempotent": False,
                    },
                )
            except Exception as ex:
                fresh_step = self.investigation_repo.get_step(step_id, ctx.challenge_id)
                if fresh_step and fresh_step.status == InvestigationStepStatus.REJECTED:
                    return HandlerResult(
                        success=True,
                        output={
                            "step_id": step_id,
                            "challenge_id": ctx.challenge_id,
                            "session_id": session_id,
                            "status": "rejected",
                            "rejected": True,
                            "idempotent": True,
                            "message": "Step was rejected by concurrent/retry transaction.",
                        },
                    )
                return HandlerResult(
                    success=False,
                    error_message=f"Rejection failed: {ex}",
                    retryable=False,
                )

        return HandlerResult(success=False, error_message="Unhandled decision path.", retryable=False)


class RunBoundedLoopIterationHandler(TaskHandler):
    """TaskHandler for 'run_bounded_investigation_iteration' task type."""

    def __init__(
        self,
        loop: Optional[BoundedInvestigationLoop] = None,
        investigation_repo: Optional[InvestigationRepository] = None,
        blackboard_repo: Optional[BlackboardRepository] = None,
        reasoning_repo: Optional[ReasoningRepository] = None,
    ) -> None:
        self.loop = loop
        self.investigation_repo = investigation_repo
        self.blackboard_repo = blackboard_repo
        self.reasoning_repo = reasoning_repo

        if not self.loop and self.investigation_repo and self.blackboard_repo and self.reasoning_repo:
            planner = InvestigationPlanner(
                investigation_repo=self.investigation_repo,
                blackboard_repo=self.blackboard_repo,
            )
            self.loop = BoundedInvestigationLoop(
                planner=planner,
                investigation_repo=self.investigation_repo,
                reasoning_repo=self.reasoning_repo,
            )

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.loop:
            return HandlerResult(
                success=False,
                error_message="BoundedInvestigationLoop is required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        session_id = params.get("session_id")
        if not session_id:
            return HandlerResult(
                success=False,
                error_message="Parameter 'session_id' is required.",
                retryable=False,
            )

        proposal = _parse_proposal_from_params_or_repo(params, ctx.challenge_id, self.reasoning_repo)
        previous_result_hash = params.get("previous_result_hash")
        domain_id = params.get("domain_id", "web_api")

        loop_res = self.loop.execute_iteration(
            session_id=session_id,
            challenge_id=ctx.challenge_id,
            proposal=proposal,
            previous_result_hash=previous_result_hash,
            domain_id=domain_id,
        )

        return HandlerResult(
            success=loop_res.should_continue,
            output={
                "should_continue": loop_res.should_continue,
                "termination_reason": loop_res.termination_reason,
                "step_id": loop_res.step_id,
                "details": loop_res.details,
            },
        )


def register_phase8_handlers(
    registry: HandlerRegistry,
    investigation_repo: InvestigationRepository,
    blackboard_repo: BlackboardRepository,
    reasoning_repo: ReasoningRepository,
    planner: Optional[InvestigationPlanner] = None,
    loop: Optional[BoundedInvestigationLoop] = None,
) -> None:
    """Register all Phase 8 TaskHandlers into the provided HandlerRegistry."""
    plan_handler = PlanInvestigationStepHandler(
        investigation_repo=investigation_repo,
        blackboard_repo=blackboard_repo,
        reasoning_repo=reasoning_repo,
        planner=planner,
    )
    decide_handler = DecideStepApprovalHandler(
        investigation_repo=investigation_repo,
    )
    loop_handler = RunBoundedLoopIterationHandler(
        loop=loop,
        investigation_repo=investigation_repo,
        blackboard_repo=blackboard_repo,
        reasoning_repo=reasoning_repo,
    )

    registry.register("plan_investigation_step", plan_handler)
    registry.register("decide_investigation_step_approval", decide_handler)
    registry.register("decide_step_approval", decide_handler)
    registry.register("run_bounded_investigation_iteration", loop_handler)
    registry.register("run_bounded_loop_iteration", loop_handler)
