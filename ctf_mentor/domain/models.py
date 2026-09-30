"""
Canonical domain models for CTF Mentor/Copilot.

These are the LOCKED contracts as specified in the architecture.
No SQL logic lives here. No persistence logic lives here.
These are pure Python dataclasses/enums representing the domain.

Do NOT create duplicate versions of these models.
Do NOT silently change their contracts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HintLevel(int, Enum):
    """Locked hint level model.

    L0 = Reflect
    L1 = Concept
    L2 = Observation Target
    L3 = Technique Class
    L4 = Narrowed Direction
    L5 = Detailed Guidance
    L6 = Full Walkthrough  (requires explicit user confirmation)
    """

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5
    L6 = 6


class HypothesisStatus(str, Enum):
    """Locked hypothesis lifecycle states."""

    WATCHLIST = "watchlist"
    ACTIVE = "active"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    DISPROVED = "disproved"
    CONFIRMED = "confirmed"


class EvidencePriority(str, Enum):
    """Locked evidence priority ordering.

    Higher priority sources take precedence in conflict resolution.
    """

    USER_CONFIRMED = "user_confirmed"       # highest
    REASONING_INFERENCE = "reasoning_inference"
    SKILL_INFERENCE = "skill_inference"     # lowest


class TaskStatus(str, Enum):
    """Locked task lifecycle states."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ApprovalStatus(str, Enum):
    """Locked approval lifecycle states."""

    REQUESTED = "requested"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalType(str, Enum):
    """Types of approvals that require human confirmation."""

    ENVIRONMENT_ACTION = "environment_action"
    L6_WALKTHROUGH = "l6_walkthrough"
    CONNECTOR_EVIDENCE_TRUST = "connector_evidence_trust"
    ACTION_PROPOSAL = "action_proposal"
    INVESTIGATION_STEP = "investigation_step"


class DependencyType(str, Enum):
    """Task dependency type."""

    HARD = "hard"   # blocks execution
    SOFT = "soft"   # failure does not kill critical path


# ---------------------------------------------------------------------------
# 1. Challenge
# ---------------------------------------------------------------------------


@dataclass
class Challenge:
    """Represents a single CTF challenge being worked on.

    challenge_id is always a UUID string.
    global_hint_level is the ceiling for all hints in this challenge.
    Every Challenge must have an associated AuthorizedScope.
    """

    challenge_id: str
    name: str
    description: str
    category: str
    global_hint_level: HintLevel
    created_at: datetime
    updated_at: datetime
    blackboard_version: int = 0
    is_active: bool = True
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.challenge_id:
            raise ValueError("challenge_id must not be empty")


# ---------------------------------------------------------------------------
# 2. Evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """A piece of evidence collected or inferred during investigation."""

    evidence_id: str
    challenge_id: str
    hypothesis_id: Optional[str]
    source: EvidencePriority
    content: str
    evidence_type: str          # e.g. "network_capture", "file_content", "user_note"
    created_at: datetime
    created_by: str             # "user", "reasoning_engine", "skill:<name>"
    is_fabricated: bool = False  # MUST always be False; fabrication is prohibited
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.is_fabricated:
            raise ValueError("Fabricated evidence is prohibited by architecture contract.")


# ---------------------------------------------------------------------------
# 3. Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A derived conclusion or notable observation from evidence."""

    finding_id: str
    challenge_id: str
    hypothesis_id: Optional[str]
    summary: str
    detail: str
    confidence: float           # 0.0 – 1.0
    created_at: datetime
    evidence_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


# ---------------------------------------------------------------------------
# 4. Hypothesis
# ---------------------------------------------------------------------------


@dataclass
class Hypothesis:
    """An investigation hypothesis.

    Maximum 3 ACTIVE hypotheses at a time; rest sit on the watchlist.
    Hint level is per-hypothesis and is one component of the effective ceiling.
    """

    hypothesis_id: str
    challenge_id: str
    title: str
    description: str
    status: HypothesisStatus
    confidence: float           # 0.0 – 1.0
    hint_level: HintLevel
    created_at: datetime
    updated_at: datetime
    is_primary: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


# ---------------------------------------------------------------------------
# 5. Attempt
# ---------------------------------------------------------------------------


@dataclass
class Attempt:
    """Records a user attempt on a challenge/hypothesis."""

    attempt_id: str
    challenge_id: str
    hypothesis_id: Optional[str]
    description: str
    outcome: str                # "success", "failure", "partial", "unknown"
    created_at: datetime
    user_input: str = ""
    tool_output: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 6. FailedAttempt
# ---------------------------------------------------------------------------


@dataclass
class FailedAttempt:
    """Records a failed attempt with context to prevent re-execution.

    Scope: (target, hypothesis_id).
    do_not_repeat_unless captures the condition under which a retry is allowed.
    """

    failed_attempt_id: str
    challenge_id: str
    hypothesis_id: str
    target: str                     # the specific target attempted
    description: str
    failed_at: datetime
    do_not_repeat_unless: str = ""  # structured condition or empty
    attempt_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 7. BlackboardState
# ---------------------------------------------------------------------------


@dataclass
class BlackboardState:
    """The single source of truth for a challenge's current investigation state.

    blackboard_version drives optimistic concurrency.
    Only the Blackboard persistence layer may mutate persisted state.
    """

    challenge_id: str
    blackboard_version: int
    active_hypothesis_ids: list[str]
    watchlist_hypothesis_ids: list[str]
    confirmed_findings: list[str]
    active_evidence_ids: list[str]
    last_hint_level: HintLevel
    session_notes: str
    updated_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.active_hypothesis_ids) > 3:
            raise ValueError(
                f"Maximum 3 active hypotheses; got {len(self.active_hypothesis_ids)}"
            )


# ---------------------------------------------------------------------------
# 8. HintRequest
# ---------------------------------------------------------------------------


@dataclass
class HintRequest:
    """A user request for a hint."""

    request_id: str
    challenge_id: str
    hypothesis_id: Optional[str]
    requested_level: HintLevel
    user_message: str
    requested_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 9. HintCandidate
# ---------------------------------------------------------------------------


@dataclass
class HintCandidate:
    """A candidate hint generated by the Hint Engine."""

    candidate_id: str
    request_id: str
    challenge_id: str
    hypothesis_id: Optional[str]
    level: HintLevel
    content: str
    rationale: str
    created_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 10. HintDecision
# ---------------------------------------------------------------------------


@dataclass
class HintDecision:
    """The final Spoiler Guard decision on a hint candidate."""

    decision_id: str
    candidate_id: str
    request_id: str
    challenge_id: str
    effective_level: HintLevel      # min(challenge, hypothesis, requested)
    approved: bool
    rejection_reason: str           # empty string if approved
    decided_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 11. UserActionRequest
# ---------------------------------------------------------------------------


@dataclass
class UserActionRequest:
    """A request for the user to perform or authorise an action.

    The AI never acts autonomously. It requests; the user decides.
    """

    action_request_id: str
    challenge_id: str
    action_type: str
    description: str
    rationale: str
    requested_at: datetime
    related_hypothesis_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 12. UserActionResult
# ---------------------------------------------------------------------------


@dataclass
class UserActionResult:
    """The result of a user-performed or user-authorised action."""

    result_id: str
    action_request_id: str
    challenge_id: str
    outcome: str
    raw_output: str
    submitted_at: datetime
    submitted_by: str = "user"
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 13. RAGQuery
# ---------------------------------------------------------------------------


@dataclass
class RAGQuery:
    """A query submitted to the RAG subsystem."""

    query_id: str
    challenge_id: str
    query_text: str
    context_hint: str
    created_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 14. RAGResult
# ---------------------------------------------------------------------------


@dataclass
class RAGResult:
    """Results returned from the RAG subsystem for a given query."""

    result_id: str
    query_id: str
    challenge_id: str
    retrieved_chunks: list[dict[str, Any]]
    score: float
    created_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 15. MemoryEntry
# ---------------------------------------------------------------------------


@dataclass
class MemoryEntry:
    """A persisted memory entry from a previous session or challenge."""

    memory_id: str
    challenge_id: str
    content: str
    memory_type: str            # "episodic", "semantic", "procedural"
    importance: float           # 0.0 – 1.0
    created_at: datetime
    expires_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 16. Task
# ---------------------------------------------------------------------------


@dataclass
class Task:
    """A unit of async work tracked by the task orchestration system.

    A retry creates a new task_id but reuses the same logical retry_key.
    A new submission uses a new task_group_id.
    """

    task_id: str
    challenge_id: str
    task_group_id: str
    task_type: str
    status: TaskStatus
    retry_key: str
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    error_message: str = ""
    result_ref: str = ""        # opaque reference to the task result
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 17. TaskDependency
# ---------------------------------------------------------------------------


@dataclass
class TaskDependency:
    """Records a dependency relationship between two tasks."""

    dependency_id: str
    task_id: str
    depends_on_task_id: str
    dependency_type: DependencyType
    created_at: datetime


# ---------------------------------------------------------------------------
# 18. Event
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """Audit event. Every Blackboard mutation must produce a corresponding Event.

    Task lifecycle events may exist independently.
    Events are immutable after creation.
    """

    event_id: str
    challenge_id: str
    event_type: str         # e.g. "blackboard_updated", "task_started", "hypothesis_promoted"
    actor: str              # "system", "user", "skill:<name>", "reasoning_engine"
    payload: dict[str, Any]
    occurred_at: datetime
    blackboard_version_after: Optional[int] = None   # set when event is Blackboard mutation
    task_id: Optional[str] = None                    # set for task lifecycle events
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 19. SkillResult
# ---------------------------------------------------------------------------


@dataclass
class SkillResult:
    """The output of a Skill execution."""

    skill_result_id: str
    challenge_id: str
    skill_name: str
    success: bool
    output: str
    evidence_ids: list[str]
    created_at: datetime
    error_message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 20. ApprovalRequest
# ---------------------------------------------------------------------------


@dataclass
class ApprovalRequest:
    """Represents a pending request for human approval.

    Human approval is mandatory for:
    - environment actions
    - L6 walkthrough
    - connector evidence trust
    """

    approval_id: str
    challenge_id: str
    approval_type: ApprovalType
    requested_by: str
    requested_action_ref: str       # opaque reference to the action awaiting approval
    status: ApprovalStatus
    requested_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    decision_reason: str = ""
    related_request_id: Optional[str] = None
    related_event_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 21. ApprovalRecord  (canonical persisted approval history)
# ---------------------------------------------------------------------------


@dataclass
class ApprovalRecord:
    """Immutable record of an approval decision.

    Fields as locked by the architecture:
      approval_id, challenge_id, approval_type, requested_by,
      requested_action_ref, status, requested_at, resolved_at,
      resolved_by, decision_reason, related_request_id, related_event_id
    """

    approval_id: str
    challenge_id: str
    approval_type: ApprovalType
    requested_by: str
    requested_action_ref: str
    status: ApprovalStatus
    requested_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    decision_reason: str
    related_request_id: Optional[str]
    related_event_id: Optional[str]


# ---------------------------------------------------------------------------
# 22. ConflictRecord
# ---------------------------------------------------------------------------


@dataclass
class ConflictRecord:
    """Records a conflict between two evidence items.

    Conflicts must be reconciled and preserved per the evidence priority model.
    """

    conflict_id: str
    challenge_id: str
    evidence_id_a: str
    evidence_id_b: str
    conflict_description: str
    resolution: str             # "a_wins", "b_wins", "merged", "pending"
    resolved: bool
    created_at: datetime
    resolved_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 23. AuthorizedScope
# ---------------------------------------------------------------------------


@dataclass
class AuthorizedScope:
    """Deterministic structured scope for a challenge.

    Every challenge MUST have an AuthorizedScope.
    Scope is deterministic and structured; not natural-language-only.
    The system must fail closed when scope cannot be established.
    The AI must never silently widen scope.
    """

    scope_id: str
    challenge_id: str
    scheme: str                         # "http", "https", "tcp", etc.
    hostname: str
    port: int
    allowed_path_patterns: list[str]    # e.g. ["/api/*", "/flag"]
    allowed_methods: list[str]          # e.g. ["GET", "POST"]
    exclusions: list[str]               # paths / hosts explicitly forbidden
    query_restrictions: dict[str, Any]  # parameter name → allowed values or patterns
    environment_id: str                 # identifies the lab/CTF environment
    challenge_relationship: str         # e.g. "primary_target", "auxiliary"
    created_at: datetime
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.hostname:
            raise ValueError("AuthorizedScope.hostname must not be empty (fail-closed)")
        if self.port < 0 or self.port > 65535:
            raise ValueError(f"AuthorizedScope.port out of range: {self.port}")


# ---------------------------------------------------------------------------
# Phase 5D Intelligence Models
# ---------------------------------------------------------------------------


@dataclass
class ChallengeClassification:
    """Represents a deterministic classification result for a CTF challenge."""

    classification_id: str
    challenge_id: str
    category: str
    confidence: float
    signals: list[str]
    ruleset_version: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


@dataclass
class ReasoningState:
    """Read-only on-demand projection of current intelligence state.

    NOT persisted to database. Built dynamically via build_reasoning_state handler.
    """

    challenge_id: str
    blackboard_version: int
    generated_at: datetime
    classification: Optional[ChallengeClassification]
    active_hypotheses: list[Hypothesis]
    watchlist_hypotheses: list[Hypothesis]
    recent_evidence: list[Evidence]
    findings: list[Finding]
    attempts: list[Attempt]
    failed_attempts: list[FailedAttempt]
    session_notes: str


# ---------------------------------------------------------------------------
# Phase 6 Controlled Investigation Models
# ---------------------------------------------------------------------------


class ActionProposalType(str, Enum):
    """Closed vocabulary of authorized action types for Phase 6."""

    OBSERVE_RESPONSE = "observe_response"
    INSPECT_HEADER = "inspect_header"
    COMPARE_PARAMETER_VALUES = "compare_parameter_values"
    TEST_INPUT_BOUNDARY = "test_input_boundary"
    INSPECT_API_BEHAVIOR = "inspect_api_behavior"


class ActionProposalState(str, Enum):
    """Closed lifecycle states for Phase 6 ActionProposals."""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RESULT_SUBMITTED = "result_submitted"
    CONFIRMING = "confirming"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class ActionProposalTarget:
    """Structured, non-executable target description for an action proposal."""

    scheme: str
    hostname: str
    port: int
    path: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.hostname:
            raise ValueError("Target hostname must not be empty.")
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"Target port out of range: {self.port}")
        if self.method.upper() not in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"}:
            raise ValueError(f"Disallowed target HTTP method: {self.method}")


@dataclass
class ActionProposal:
    """Represents a human-guided candidate investigation action."""

    proposal_id: str
    challenge_id: str
    action_type: ActionProposalType
    target: ActionProposalTarget
    rationale: str
    request_id: Optional[str] = None
    hypothesis_id: Optional[str] = None
    scope_id: Optional[str] = None
    scope_version: str = "1.0"
    status: ActionProposalState = ActionProposalState.DRAFT
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionResult:
    """Append-only record of a user-submitted investigation result."""

    result_id: str
    proposal_id: str
    challenge_id: str
    raw_output: str
    outcome: str = "success"
    submitted_at: Optional[datetime] = None
    submitted_by: str = "user"
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Shared contracts (re-exported for backward compatibility)
# ---------------------------------------------------------------------------
from ctf_mentor.contracts import (  # noqa: E402
    EntityWrite,
    ScopedDiff,
    StaleApprovalError,
    StaleVersionError,
)

__all__ = [
    # Enums
    "HintLevel",
    "HypothesisStatus",
    "EvidencePriority",
    "TaskStatus",
    "ApprovalStatus",
    "ApprovalType",
    "DependencyType",
    "ActionProposalType",
    "ActionProposalState",
    # Domain models 1-23
    "Challenge",
    "Evidence",
    "Finding",
    "Hypothesis",
    "Attempt",
    "FailedAttempt",
    "BlackboardState",
    "HintRequest",
    "HintCandidate",
    "HintDecision",
    "UserActionRequest",
    "UserActionResult",
    "RAGQuery",
    "RAGResult",
    "MemoryEntry",
    "Task",
    "TaskDependency",
    "Event",
    "SkillResult",
    "ApprovalRequest",
    "ApprovalRecord",
    "ConflictRecord",
    "AuthorizedScope",
    # Phase 5D Intelligence models
    "ChallengeClassification",
    "ReasoningState",
    # Phase 6 Investigation models
    "ActionProposalTarget",
    "ActionProposal",
    "ActionResult",
    # Shared contracts (re-exported)
    "StaleVersionError",
    "StaleApprovalError",
    "ScopedDiff",
    "EntityWrite",
]

