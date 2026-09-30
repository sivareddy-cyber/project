"""
Contracts, Enums, and Data Models for Phase 5E Deterministic Reasoning Foundation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class TaskOrigin(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"


class EvidenceTier(str, Enum):
    T1_USER_CONFIRMED = "T1_USER_CONFIRMED"
    T2_REASONING_INFERENCE = "T2_REASONING_INFERENCE"
    T3_SKILL_INFERENCE = "T3_SKILL_INFERENCE"


class EvidenceRelationType(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    NEUTRAL = "NEUTRAL"
    RETRACTED = "RETRACTED"


class InvestigationLinkType(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    TESTS = "tests"
    WEAKENS = "weakens"


class HypothesisRelationType(str, Enum):
    COMPETES = "competes"
    COMPATIBLE = "compatible"


class HypothesisPosture(str, Enum):
    UNTESTED = "untested"
    EMERGING = "emerging"
    SUPPORTED_CANDIDATE = "supported_candidate"
    CONTESTED = "contested"
    WEAKENED_CANDIDATE = "weakened_candidate"
    REFUTED_CANDIDATE = "refuted_candidate"


class GapType(str, Enum):
    NO_USER_CONFIRMED_SUPPORT = "NO_USER_CONFIRMED_SUPPORT"
    UNTESTED_PREDICTION = "UNTESTED_PREDICTION"
    HYPOTHESIS_WITHOUT_PREDICTIONS = "HYPOTHESIS_WITHOUT_PREDICTIONS"
    ORPHAN_EVIDENCE = "ORPHAN_EVIDENCE"
    UNRESOLVED_CONTRADICTION = "UNRESOLVED_CONTRADICTION"
    ATTEMPT_WITHOUT_EVIDENCE = "ATTEMPT_WITHOUT_EVIDENCE"
    ATTEMPT_UNLINKED = "ATTEMPT_UNLINKED"
    NO_OR_LOW_CLASSIFICATION = "NO_OR_LOW_CLASSIFICATION"
    NON_DIAGNOSTIC_ONLY = "NON_DIAGNOSTIC_ONLY"


class PredictionStatus(str, Enum):
    UNTESTED = "untested"
    VERIFIED = "verified"
    REFUTED = "refuted"
    SUPERSEDED = "superseded"


class LinkStatus(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class ReasoningRunStatus(str, Enum):
    COMPLETED = "completed"
    SUPERSEDED = "superseded"
    FAILED = "failed"


@dataclass
class HypothesisPrediction:
    prediction_id: str
    challenge_id: str
    hypothesis_id: str
    description: str
    expected_observation: str
    status: PredictionStatus
    created_at: datetime
    superseded_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationLink:
    link_id: str
    challenge_id: str
    source_id: str
    source_type: str  # "evidence", "attempt", "failed_attempt"
    target_id: str
    target_type: str  # "hypothesis", "prediction"
    relation_type: InvestigationLinkType
    independence_group: str = ""
    weight: int = 1000  # permille
    status: LinkStatus = LinkStatus.ACTIVE
    created_at: Optional[datetime] = None
    superseded_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HypothesisRelation:
    relation_id: str
    challenge_id: str
    source_hypothesis_id: str
    target_hypothesis_id: str
    relation_type: HypothesisRelationType
    discriminating_criteria: str = ""
    status: LinkStatus = LinkStatus.ACTIVE
    created_at: Optional[datetime] = None
    superseded_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReasoningAssessment:
    assessment_id: str
    run_id: str
    challenge_id: str
    hypothesis_id: str
    posture: HypothesisPosture
    support_strength: int  # permille 0-1000
    contradiction_strength: int  # permille 0-1000
    evidence_quality: int  # permille 0-1000
    evidence_coverage: int  # permille 0-1000
    is_confirmation_eligible: bool
    created_at: Optional[datetime] = None
    assessment_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationProposal:
    proposal_id: str
    challenge_id: str
    title: str
    description: str
    gap_type: GapType
    target_hypothesis_ids: List[str]
    discriminates_hypotheses: List[str]
    rationale: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReasoningResult:
    run_id: str
    challenge_id: str
    run_sequence: int
    input_fingerprint: str
    ruleset_version: str
    assessments: List[ReasoningAssessment]
    proposals: List[InvestigationProposal]
    detected_gaps: List[Dict[str, Any]]
    canonical_dict: Dict[str, Any]
    result_hash: str
    created_at: datetime


@dataclass
class ReasoningRun:
    run_id: str
    challenge_id: str
    run_sequence: int
    input_fingerprint: str
    ruleset_version: str
    canonical_result: str
    result_hash: str
    status: ReasoningRunStatus
    created_at: datetime
