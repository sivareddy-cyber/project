"""
TaskHandlers for Phase 6A Common Investigation Framework via TaskManager.

LOCKED SECURITY INVARIANTS:
1. Non-executing boundary: Handlers represent, validate, and record results without external action execution.
2. SubmitStepResultTaskHandler verifies human approval gate before recording externally supplied InvestigationResult.
3. Handlers receive read-only TaskContext and communicate through TaskManager / HandlerResult contracts.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ctf_mentor.domain.investigation_models import ConcreteInvestigationResult, InvestigationResult
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class SubmitStepResultTaskHandler(TaskHandler):
    """TaskHandler for 'submit_step_result' task type."""

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
        result_id = params.get("result_id")
        outcome = params.get("outcome", "success")
        raw_output = params.get("raw_output", "")
        submitted_by = params.get("submitted_by", "user")

        if not step_id or not result_id:
            return HandlerResult(
                success=False,
                error_message="Both step_id and result_id are required.",
                retryable=False,
            )

        step = self.investigation_repo.get_step(step_id, ctx.challenge_id)
        if not step:
            return HandlerResult(
                success=False,
                error_message=f"InvestigationStep {step_id!r} not found for challenge {ctx.challenge_id!r}.",
                retryable=False,
            )

        inv_result = ConcreteInvestigationResult(
            result_id=result_id,
            step_id=step_id,
            session_id=step.session_id,
            challenge_id=ctx.challenge_id,
            outcome=outcome,
            raw_output=raw_output,
            submitted_by=submitted_by,
        )

        try:
            res_dict = self.investigation_repo.submit_step_result_atomic(
                step_id=step_id,
                challenge_id=ctx.challenge_id,
                result=inv_result,
            )
            return HandlerResult(
                success=True,
                output=res_dict,
                proposed_entity_writes=[],
            )
        except Exception as ex:
            return HandlerResult(
                success=False,
                error_message=f"Submitting step result failed: {ex}",
                retryable=False,
            )


class ConfirmStepResultTaskHandler(TaskHandler):
    """TaskHandler for 'confirm_step_result' task type."""

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
        if not step_id:
            return HandlerResult(
                success=False,
                error_message="step_id is required.",
                retryable=False,
            )

        try:
            prep_dict = self.investigation_repo.confirm_step_result_atomic(
                step_id=step_id,
                challenge_id=ctx.challenge_id,
            )
            token = prep_dict["reservation_token"]
            fin_dict = self.investigation_repo.finalize_step_confirmation_atomic(
                step_id=step_id,
                challenge_id=ctx.challenge_id,
                reservation_token=token,
            )
            return HandlerResult(
                success=True,
                output=fin_dict,
                proposed_entity_writes=[],
            )
        except Exception as ex:
            return HandlerResult(
                success=False,
                error_message=f"Confirming step result failed: {ex}",
                retryable=False,
            )


def register_phase6a_handlers(
    registry: HandlerRegistry,
    investigation_repo: InvestigationRepository,
) -> None:
    """Register all Phase 6A TaskHandlers into HandlerRegistry."""
    registry.register(
        "submit_step_result",
        SubmitStepResultTaskHandler(investigation_repo=investigation_repo),
    )
    registry.register(
        "confirm_step_result",
        ConfirmStepResultTaskHandler(investigation_repo=investigation_repo),
    )

