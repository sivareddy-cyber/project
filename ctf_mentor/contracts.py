"""
Neutral shared value contracts and persistence exceptions for CTF Mentor/Copilot.

This module defines contracts shared between domain and persistence layers without
introducing reversed dependencies (domain -> persistence is strictly forbidden).

Contracts:
- ScopedDiff: Describes a mutation payload for Blackboard state
- StaleVersionError: Exception raised when Blackboard optimistic locking fails
- StaleApprovalError: Exception raised when Approval optimistic locking fails
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class StaleVersionError(Exception):
    """Raised when a Blackboard update encounters an outdated expected_version.

    The stale writer must never overwrite a newer Blackboard state.

    Architecture contract (LOCKED):
      Version = 1
      Writer A expects version 1  → succeeds → version becomes 2
      Writer B expects version 1  → raises StaleVersionError
    """

    def __init__(self, challenge_id: str, expected: int, found: int) -> None:
        self.challenge_id = challenge_id
        self.expected = expected
        self.found = found
        super().__init__(
            f"StaleVersionError: challenge_id={challenge_id!r} "
            f"expected version={expected}, found={found}"
        )


class StaleApprovalError(Exception):
    """Raised when an ApprovalRecord transition encounters a modified current status.

    The stale writer must never overwrite a concurrent approval decision.
    """

    def __init__(self, approval_id: str, expected_status: str, found_status: str) -> None:
        self.approval_id = approval_id
        self.expected_status = expected_status
        self.found_status = found_status
        super().__init__(
            f"StaleApprovalError: approval_id={approval_id!r} "
            f"expected status={expected_status!r}, found={found_status!r}"
        )


class TaskExecutionError(Exception):
    """Raised when task execution fails unrecoverably."""
    pass


class TaskNotFoundError(Exception):
    """Raised when a requested task_id is not found."""
    pass


class DuplicateTaskError(Exception):
    """Raised when an active task with the same dedup key exists."""
    pass


class DependencyError(Exception):
    """Raised when a task dependency constraint is violated."""
    pass


@dataclass
class ScopedDiff:
    """Describes a scoped mutation to apply to the Blackboard.

    Fields must be from the ALLOWED_BLACKBOARD_FIELDS whitelist.
    The repository layer validates both field names and values before any SQL.
    """

    challenge_id: str
    expected_version: int
    actor: str
    event_type: str
    changes: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.changes:
            raise ValueError("ScopedDiff.changes must not be empty")


ALLOWED_ENTITY_TYPES = {
    "hypothesis",
    "evidence",
    "finding",
    "attempt",
    "failed_attempt",
    "classification",
}

ALLOWED_ENTITY_OPERATIONS = {
    "insert",
    "update",
}


@dataclass
class EntityWrite:
    """Describes a proposed database entity mutation from a TaskHandler.

    Handlers do NOT perform SQL operations directly. They return EntityWrite objects
    inside HandlerResult.proposed_entity_writes, which are validated and executed
    atomically by IntelligenceRepository.
    """

    entity_type: str
    operation: str
    entity_id: str
    fields: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.entity_type or self.entity_type not in ALLOWED_ENTITY_TYPES:
            raise ValueError(
                f"Invalid entity_type {self.entity_type!r}. Must be one of {sorted(ALLOWED_ENTITY_TYPES)}"
            )
        if not self.operation or self.operation not in ALLOWED_ENTITY_OPERATIONS:
            raise ValueError(
                f"Invalid operation {self.operation!r}. Must be one of {sorted(ALLOWED_ENTITY_OPERATIONS)}"
            )
        if not self.entity_id:
            raise ValueError("entity_id must not be empty")
        if not self.fields:
            raise ValueError("EntityWrite.fields must not be empty")

