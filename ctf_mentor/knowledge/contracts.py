"""
Domain contracts for Phase 5F Knowledge Ingestion & Retrieval Pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import HintLevel


@dataclass(frozen=True)
class KnowledgeSource:
    """Represents an offline, curated educational knowledge source."""

    source_id: str
    name: str
    source_version: str
    category: str
    trust_tier: str  # e.g. "curated_official", "vetted_community"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KnowledgeChunk:
    """An immutable chunk of cybersecurity educational knowledge."""

    chunk_id: str
    source_id: str
    source_version: str
    content: str
    content_hash: str
    category: str
    technique: str
    trust_tier: str
    hint_level_floor: HintLevel  # Lowest hint level authorized to retrieve this chunk
    allowed_use: str  # e.g. "education_only", "technique_guidance"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievalRequest:
    """Structured, challenge-aware retrieval query."""

    challenge_id: str
    category: str
    requested_hint_level: HintLevel
    hypothesis_id: Optional[str] = None
    technique: Optional[str] = None
    information_gaps: List[str] = field(default_factory=list)
    top_k: int = 5


@dataclass
class RetrievalResult:
    """Traceable retrieval result containing gated chunks and provenance."""

    challenge_id: str
    requested_hint_level: HintLevel
    chunks: List[KnowledgeChunk]
    scores: List[float]
    provenance_records: List[Dict[str, Any]]
