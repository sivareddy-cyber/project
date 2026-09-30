"""
Contracts and abstractions for Phase 10A Passive Tool Adapters.
Phase 10B.2: Adds WorkspaceCapabilitySpec to ToolAdapter Protocol contract.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, Type, Union, runtime_checkable

if TYPE_CHECKING:
    from ctf_mentor.workspace.capabilities import WorkspaceCapabilitySpec, IssuedCapabilitySet


class ExecutionClass(str, Enum):
    """Execution classification for tool adapters.

    Phase 10A supports only PASSIVE classes. ACTIVE classes are reserved and forbidden in 10A.
    """

    PASSIVE_LOCAL = "PASSIVE_LOCAL"
    PASSIVE_NETWORK = "PASSIVE_NETWORK"
    ACTIVE_NETWORK = "ACTIVE_NETWORK"
    ACTIVE_EXPLOIT = "ACTIVE_EXPLOIT"
    CREDENTIALED = "CREDENTIALED"


@dataclass
class RateLimitPolicy:
    """Central rate limiting and execution boundary configuration."""

    max_requests_per_window: int = 10
    window_seconds: float = 60.0
    max_concurrent: int = 2
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1048576  # 1MB

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")


class ToolInputSchema:
    """Base class for closed typed tool input validation.

    Do NOT use open/arbitrary dictionaries as primary input contracts.
    Subclasses must define explicit fields and validate inputs strictly.
    """

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> ToolInputSchema:
        raise NotImplementedError("Subclasses must implement validate()")

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement to_dict()")


@dataclass
class EvidenceCandidate:
    """Normalized observation produced by a tool adapter.

    LOCKED ARCHITECTURAL REQUIREMENT:
    Every Phase 10A adapter result MUST be explicitly marked trust = "UNTRUSTED".
    Never promote external tool output directly to verified evidence.
    """

    source: str
    observation: str
    provenance: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime.datetime] = None
    authorized_target_relationship: str = ""
    trust: str = "UNTRUSTED"

    def __post_init__(self) -> None:
        if self.trust != "UNTRUSTED":
            raise ValueError("Phase 10A evidence candidates MUST be marked UNTRUSTED")
        if not self.source:
            raise ValueError("EvidenceCandidate source cannot be empty")
        if not self.observation:
            raise ValueError("EvidenceCandidate observation cannot be empty")


@dataclass
class ToolResult:
    """Structured result returned by a ToolAdapter execution."""

    tool_id: str
    tool_version: str
    request_id: str
    timestamp: datetime.datetime
    authorized_target: Any
    query_fingerprint: str
    raw_result_ref: Optional[str] = None
    raw_data: Optional[Any] = None
    normalized_observations: List[EvidenceCandidate] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    error_status: Optional[str] = None
    served_from_cache: bool = False

    def __post_init__(self) -> None:
        if not self.tool_id:
            raise ValueError("ToolResult tool_id cannot be empty")
        if not self.query_fingerprint:
            raise ValueError("ToolResult query_fingerprint cannot be empty")


@runtime_checkable
class ToolAdapter(Protocol):
    """Abstract protocol for all Phase 10A/10B.2 Tool Adapters.

    Phase 10B.2 Contract Change:
    Adapters declare a class-level `workspace_capability_spec` attribute of type
    WorkspaceCapabilitySpec. This static, trusted metadata determines what
    workspace capabilities the adapter requires. The TrustedWorkspaceExecutionBoundary
    reads this spec to issue the minimum required capabilities.

    CRITICAL: Adapters MUST declare workspace_capability_spec as a class-level
    constant, not as a computed property or based on any runtime/user input.
    """

    @property
    def tool_id(self) -> str:
        ...

    @property
    def tool_version(self) -> str:
        ...

    @property
    def domain_ids(self) -> List[str]:
        ...

    @property
    def execution_class(self) -> ExecutionClass:
        ...

    @property
    def allowed_target_types(self) -> List[str]:
        ...

    @property
    def input_schema(self) -> Type[ToolInputSchema]:
        ...

    @property
    def requires_credentials(self) -> bool:
        ...

    @property
    def credential_ref(self) -> Optional[str]:
        ...

    @property
    def rate_limit_policy(self) -> RateLimitPolicy:
        ...

    @property
    def network_destinations(self) -> List[str]:
        ...

    @property
    def workspace_capability_spec(self) -> "WorkspaceCapabilitySpec":
        """Static, class-level declaration of required workspace capabilities.

        This MUST be a class-level constant of type WorkspaceCapabilitySpec.
        The TrustedWorkspaceExecutionBoundary reads this to issue least-privilege
        capability tokens. Must never be influenced by user/LLM input.

        Adapters that require no workspace access should declare:
            workspace_capability_spec = NULL_CAPABILITY_SPEC
        """
        ...

    def validate_input(self, raw_args: Dict[str, Any]) -> ToolInputSchema:
        ...

    def validate_scope(self, target: Any, scope: Any) -> bool:
        ...

    def execute(
        self,
        validated_input: ToolInputSchema,
        scope: Any,
        credential_provider: Optional[Any] = None,
    ) -> ToolResult:
        ...

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        ...
