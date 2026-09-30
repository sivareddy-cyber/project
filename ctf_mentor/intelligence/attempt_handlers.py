"""
Attempt handlers for CTF Mentor/Copilot Phase 5D.

Handles recording of user attempts and failed attempt invariants.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ctf_mentor.contracts import EntityWrite
from ctf_mentor.domain.models import Attempt, FailedAttempt
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

ALLOWED_OUTCOMES = {"success", "failure", "partial", "unknown"}


class RecordAttemptHandler(TaskHandler):
    """Handler for recording a user attempt."""

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        description = params.get("description", "").strip()
        if not description:
            return HandlerResult(success=False, error_message="Attempt description must not be empty.")

        outcome = params.get("outcome", "unknown")
        if outcome not in ALLOWED_OUTCOMES:
            return HandlerResult(
                success=False,
                error_message=f"Invalid outcome {outcome!r}. Must be one of {sorted(ALLOWED_OUTCOMES)}",
            )

        att_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        hypothesis_id = params.get("hypothesis_id")
        user_input = params.get("user_input", "")
        tool_output = params.get("tool_output", "")
        metadata = params.get("metadata", {})

        attempt = Attempt(
            attempt_id=att_id,
            challenge_id=context.challenge_id,
            hypothesis_id=hypothesis_id,
            description=description,
            outcome=outcome,
            created_at=now,
            user_input=user_input,
            tool_output=tool_output,
            metadata=metadata,
        )

        ew = EntityWrite(
            entity_type="attempt",
            operation="insert",
            entity_id=att_id,
            fields={
                "attempt_id": attempt.attempt_id,
                "challenge_id": attempt.challenge_id,
                "hypothesis_id": attempt.hypothesis_id,
                "description": attempt.description,
                "outcome": attempt.outcome,
                "user_input": attempt.user_input,
                "tool_output": attempt.tool_output,
                "metadata": attempt.metadata,
                "created_at": attempt.created_at,
            },
        )

        return HandlerResult(
            success=True,
            output=attempt,
            proposed_entity_writes=[ew],
        )


class RecordFailedAttemptHandler(TaskHandler):
    """Handler for recording a failed attempt to prevent re-execution."""

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        hypothesis_id = params.get("hypothesis_id")
        if not hypothesis_id:
            return HandlerResult(success=False, error_message="hypothesis_id is required for failed_attempt.")

        target = params.get("target", "").strip()
        if not target:
            return HandlerResult(success=False, error_message="target is required for failed_attempt.")

        description = params.get("description", "")
        do_not_repeat_unless = params.get("do_not_repeat_unless", "")
        attempt_id = params.get("attempt_id")
        metadata = params.get("metadata", {})

        fa_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        fa = FailedAttempt(
            failed_attempt_id=fa_id,
            challenge_id=context.challenge_id,
            hypothesis_id=hypothesis_id,
            target=target,
            description=description,
            failed_at=now,
            do_not_repeat_unless=do_not_repeat_unless,
            attempt_id=attempt_id,
            metadata=metadata,
        )

        ew = EntityWrite(
            entity_type="failed_attempt",
            operation="insert",
            entity_id=fa_id,
            fields={
                "failed_attempt_id": fa.failed_attempt_id,
                "challenge_id": fa.challenge_id,
                "hypothesis_id": fa.hypothesis_id,
                "attempt_id": fa.attempt_id,
                "target": fa.target,
                "description": fa.description,
                "do_not_repeat_unless": fa.do_not_repeat_unless,
                "metadata": fa.metadata,
                "failed_at": fa.failed_at,
            },
        )

        return HandlerResult(
            success=True,
            output=fa,
            proposed_entity_writes=[ew],
        )
