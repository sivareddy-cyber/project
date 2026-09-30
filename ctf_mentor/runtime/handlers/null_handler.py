"""
Null/Echo test handler for Phase 5C Runtime Orchestration Foundation.

Used ONLY to prove end-to-end task manager pipeline and testing.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from ctf_mentor.contracts import ScopedDiff
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class NullHandler(TaskHandler):
    """Null/Echo test handler that returns echo output or proposed ScopedDiff."""

    def __init__(self, delay_seconds: float = 0.0, should_fail: bool = False, fail_message: str = "NullHandler intentional failure") -> None:
        self.delay_seconds = delay_seconds
        self.should_fail = should_fail
        self.fail_message = fail_message

    async def execute(self, context: TaskContext) -> HandlerResult:
        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)

        if context.is_cancelled():
            return HandlerResult(success=False, error_message="Task cancelled during execution")

        if self.should_fail or context.parameters.get("should_fail", False):
            msg = context.parameters.get("fail_message", self.fail_message)
            return HandlerResult(success=False, error_message=msg)

        echo_val = context.parameters.get("echo", "null_ok")
        proposed_changes = context.parameters.get("proposed_changes")
        
        proposed_diff: Optional[ScopedDiff] = None
        if proposed_changes:
            event_type = context.parameters.get("event_type", f"task_{context.task_type}_completed")
            actor = context.parameters.get("actor", f"task:{context.task_type}")
            # Note: expected_version will be filled/overwritten by TaskManager at application time
            proposed_diff = ScopedDiff(
                challenge_id=context.challenge_id,
                expected_version=0,
                actor=actor,
                event_type=event_type,
                changes=proposed_changes,
            )

        return HandlerResult(
            success=True,
            output=echo_val,
            proposed_diff=proposed_diff,
        )
