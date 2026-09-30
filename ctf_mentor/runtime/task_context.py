"""
Task context and data models for Phase 5C Runtime Orchestration.

Defines:
- TaskRequest: Immutable task submission request
- TaskContext: Execution context supplied to TaskHandlers (read-only snapshot)
- HandlerResult: Output returned by TaskHandlers (proposes ScopedDiff, no direct DB write)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ctf_mentor.contracts import EntityWrite, ScopedDiff
from ctf_mentor.domain.models import BlackboardState
from ctf_mentor.reasoning.contracts import TaskOrigin
from ctf_mentor.runtime.retry_policy import RetryPolicy


@dataclass
class TaskRequest:
    """Task submission request payload."""

    challenge_id: str
    task_group_id: str
    task_type: str
    parameters: dict[str, Any] = field(default_factory=dict)
    retry_policy: Optional[RetryPolicy] = None
    depends_on_task_ids: list[str] = field(default_factory=list)
    requires_approval: bool = False
    approval_id: Optional[str] = None
    supersedes_task_group_id: Optional[str] = None
    timeout_seconds: Optional[float] = None
    origin: TaskOrigin = TaskOrigin.USER
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.challenge_id:
            raise ValueError("challenge_id must not be empty")
        if not self.task_group_id:
            raise ValueError("task_group_id must not be empty")
        if not self.task_type:
            raise ValueError("task_type must not be empty")


@dataclass
class TaskContext:
    """Execution context passed to TaskHandlers.

    CRITICAL SECURITY INVARIANT:
    Handlers MUST NOT receive:
    - raw SQLite connection
    - Blackboard repository write access
    - arbitrary persistence access

    Handlers receive only a read-only snapshot of BlackboardState and context details.
    """

    task_id: str
    challenge_id: str
    task_group_id: str
    task_type: str
    parameters: dict[str, Any]
    blackboard_snapshot: BlackboardState
    _cancellation_event: asyncio.Event = field(default_factory=asyncio.Event)

    def is_cancelled(self) -> bool:
        """Check if cancellation was requested for this task."""
        return self._cancellation_event.is_set()


@dataclass
class HandlerResult:
    """Output returned by a TaskHandler after execution.

    Handlers propose results, optional ScopedDiff, and optional proposed_entity_writes.
    They do NOT directly mutate Blackboard or SQLite.
    """

    success: bool
    output: Any = None
    error_message: str = ""
    proposed_diff: Optional[ScopedDiff] = None
    proposed_entity_writes: list[EntityWrite] = field(default_factory=list)
    retryable: bool = True

