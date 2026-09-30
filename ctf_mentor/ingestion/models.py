"""
Domain models and dataclasses for Phase 9 Challenge Ingestion Adapter.

LOCKED INVARIANTS:
1. Ingestion observations are UNTRUSTED by default and retained with full provenance.
2. Ingestion observations NEVER automatically trigger approvals, Solve Mode switches, or evidence confirmation.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class SourceType(str, Enum):
    """Supported ingestion source types."""

    CHALLENGE_URL = "CHALLENGE_URL"
    CHALLENGE_TEXT = "CHALLENGE_TEXT"
    ARTIFACT_FILE = "ARTIFACT_FILE"


class TrustLevel(str, Enum):
    """Trust/verification status for ingested content."""

    UNTRUSTED = "UNTRUSTED"
    PROVENANCE_STAGED = "PROVENANCE_STAGED"


@dataclass
class IngestionObservation:
    """Provenance-aware, staged observation derived from ingested challenge inputs.
    
    CRITICAL: Untrusted content is NEVER automatically promoted to verified evidence,
    control-plane commands, or human approvals.
    """

    observation_id: str
    challenge_id: str
    copilot_session_id: Optional[str]
    source_type: SourceType
    source_reference: str
    content_summary: str
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    provenance: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize observation to dict."""
        return {
            "observation_id": self.observation_id,
            "challenge_id": self.challenge_id,
            "copilot_session_id": self.copilot_session_id,
            "source_type": self.source_type.value,
            "source_reference": self.source_reference,
            "content_summary": self.content_summary,
            "trust_level": self.trust_level.value,
            "provenance": self.provenance,
            "created_at": self.created_at.isoformat(),
        }
