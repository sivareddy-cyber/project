"""
Domain models and contracts for Phase 6A Common Investigation Framework.

LOCKED ARCHITECTURE INVARIANTS:
1. Common, domain-agnostic investigation lifecycle foundation.
2. Closed tagged target vocabulary (HTTP_TARGET, FILE_TARGET, PCAP_TARGET, BINARY_TARGET, MEMORY_TARGET, CLOUD_TARGET, TEXT_TARGET).
3. Fail-closed validation for unknown target types, malformed targets, and invalid lifecycle transitions.
4. Non-executing boundary: represents, validates, scope-checks, requests approval, and records results without external execution capabilities.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class InvestigationSessionStatus(str, Enum):
    """Lifecycle states for an InvestigationSession."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    TERMINATED = "terminated"


class InvestigationStepStatus(str, Enum):
    """Lifecycle states for an InvestigationStep."""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RESULT_SUBMITTED = "result_submitted"
    CONFIRMING = "confirming"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class TargetType(str, Enum):
    """Closed vocabulary of supported target types for Phase 6A."""

    HTTP_TARGET = "HTTP_TARGET"
    FILE_TARGET = "FILE_TARGET"
    PCAP_TARGET = "PCAP_TARGET"
    BINARY_TARGET = "BINARY_TARGET"
    MEMORY_TARGET = "MEMORY_TARGET"
    CLOUD_TARGET = "CLOUD_TARGET"
    TEXT_TARGET = "TEXT_TARGET"


@dataclass
class InvestigationTarget:
    """Closed tagged target model for Phase 6A InvestigationStep.

    Validates required structure per target_type; fails closed on missing required keys.
    """

    target_type: TargetType
    details: Dict[str, Any]

    def __post_init__(self) -> None:
        if isinstance(self.target_type, str):
            try:
                self.target_type = TargetType(self.target_type)
            except ValueError:
                raise ValueError(f"Unknown target_type: {self.target_type!r}")

        if not isinstance(self.details, dict):
            raise ValueError(f"target_json details must be a dict, got {type(self.details).__name__}")

        self.validate()

    def validate(self) -> None:
        """Enforce required schema rules per TargetType."""
        if self.target_type == TargetType.HTTP_TARGET:
            req_keys = {"hostname", "port"}
            if not req_keys.issubset(self.details.keys()):
                missing = req_keys - set(self.details.keys())
                raise ValueError(f"HTTP_TARGET missing required fields: {sorted(missing)}")
            if not isinstance(self.details["port"], int) or not (0 <= self.details["port"] <= 65535):
                raise ValueError(f"HTTP_TARGET invalid port: {self.details.get('port')!r}")

        elif self.target_type == TargetType.FILE_TARGET:
            if "path" not in self.details or not str(self.details["path"]).strip():
                raise ValueError("FILE_TARGET missing required non-empty 'path'")

        elif self.target_type == TargetType.PCAP_TARGET:
            if "pcap_path" not in self.details or not str(self.details["pcap_path"]).strip():
                raise ValueError("PCAP_TARGET missing required non-empty 'pcap_path'")

        elif self.target_type == TargetType.BINARY_TARGET:
            if "binary_name" not in self.details or not str(self.details["binary_name"]).strip():
                raise ValueError("BINARY_TARGET missing required non-empty 'binary_name'")

        elif self.target_type == TargetType.MEMORY_TARGET:
            if "dump_id" not in self.details and "address_space" not in self.details:
                raise ValueError("MEMORY_TARGET requires 'dump_id' or 'address_space'")

        elif self.target_type == TargetType.CLOUD_TARGET:
            if "resource_id" not in self.details or not str(self.details["resource_id"]).strip():
                raise ValueError("CLOUD_TARGET missing required non-empty 'resource_id'")

        elif self.target_type == TargetType.TEXT_TARGET:
            if "query_or_text" not in self.details or not str(self.details["query_or_text"]).strip():
                raise ValueError("TEXT_TARGET missing required non-empty 'query_or_text'")

    def to_json(self) -> str:
        """Serialize target details to JSON string."""
        return json.dumps(self.details, sort_keys=True)

    @classmethod
    def from_json(cls, target_type: str, json_str: str) -> InvestigationTarget:
        """Deserialize target from target_type string and JSON string."""
        try:
            details = json.loads(json_str)
        except Exception as ex:
            raise ValueError(f"Invalid target_json string: {ex}")
        return cls(target_type=TargetType(target_type), details=details)


@dataclass
class InvestigationSession:
    """Represents an investigation attempt/session within a Challenge."""

    session_id: str
    challenge_id: str
    status: InvestigationSessionStatus
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationStep:
    """Represents a concrete, approval-gated, non-executing investigation action.

    Note on proposal_ref:
        proposal_ref is an advisory, optional opaque reference string that is intentionally
        not DB-verifiable because 5E InvestigationProposal has no dedicated database table
        (it is serialized inside reasoning_runs.canonical_result).
    """

    step_id: str
    session_id: str
    challenge_id: str
    step_type: str
    target: InvestigationTarget
    rationale: str
    status: InvestigationStepStatus
    created_at: datetime
    updated_at: datetime
    proposal_ref: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class InvestigationResult(Protocol):
    """Structural protocol contract for an InvestigationResult (externally supplied result).

    Any class providing result_id, challenge_id, outcome, and raw_output structural attributes
    satisfies this Protocol.
    """

    result_id: str
    challenge_id: str
    outcome: str
    raw_output: str


@dataclass
class ConcreteInvestigationResult:
    """Concrete implementation of the structural InvestigationResult protocol."""

    result_id: str
    step_id: str
    session_id: str
    challenge_id: str
    raw_output: str
    outcome: str = "success"
    result_type: str = "GENERIC"
    data_json: str = "{}"
    provenance_hash: str = ""
    submitted_by: str = "user"
    submitted_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

