"""
Deterministic Information Gap Detector.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from ctf_mentor.domain.models import Attempt, ChallengeClassification, Evidence, Hypothesis
from ctf_mentor.reasoning.contracts import GapType, HypothesisPrediction, InvestigationLink, PredictionStatus, ReasoningAssessment


def detect_information_gaps(
    classification: Optional[ChallengeClassification],
    hypotheses: List[Hypothesis],
    evidence_list: List[Evidence],
    attempts: List[Attempt],
    predictions: List[HypothesisPrediction],
    links: List[InvestigationLink],
    assessments: List[ReasoningAssessment],
    competing_pairs: Set[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """Detect all 9 typed information gap categories deterministically."""
    gaps: List[Dict[str, Any]] = []

    # 1. NO_OR_LOW_CLASSIFICATION
    if not classification or classification.confidence < 0.5:
        gaps.append(
            {
                "gap_type": GapType.NO_OR_LOW_CLASSIFICATION.value,
                "description": "Challenge classification is missing or has confidence below 0.5.",
                "target_ids": [],
            }
        )

    # 2. NO_USER_CONFIRMED_SUPPORT
    asmt_map = {a.hypothesis_id: a for a in assessments}
    for h in hypotheses:
        asmt = asmt_map.get(h.hypothesis_id)
        if h.status.value in ("active", "watchlist") and asmt and not asmt.is_confirmation_eligible:
            gaps.append(
                {
                    "gap_type": GapType.NO_USER_CONFIRMED_SUPPORT.value,
                    "description": f"Hypothesis {h.hypothesis_id!r} ('{h.title}') has no user-confirmed evidence.",
                    "target_ids": [h.hypothesis_id],
                }
            )

    # 3. HYPOTHESIS_WITHOUT_PREDICTIONS & UNTESTED_PREDICTION
    preds_by_hyp: Dict[str, List[HypothesisPrediction]] = {h.hypothesis_id: [] for h in hypotheses}
    for p in predictions:
        if p.hypothesis_id in preds_by_hyp:
            preds_by_hyp[p.hypothesis_id].append(p)
            if p.status == PredictionStatus.UNTESTED:
                gaps.append(
                    {
                        "gap_type": GapType.UNTESTED_PREDICTION.value,
                        "description": f"Prediction {p.prediction_id!r} for hypothesis {p.hypothesis_id!r} is untested.",
                        "target_ids": [p.hypothesis_id, p.prediction_id],
                    }
                )

    for h in hypotheses:
        if not preds_by_hyp.get(h.hypothesis_id):
            gaps.append(
                {
                    "gap_type": GapType.HYPOTHESIS_WITHOUT_PREDICTIONS.value,
                    "description": f"Hypothesis {h.hypothesis_id!r} has no registered testable predictions.",
                    "target_ids": [h.hypothesis_id],
                }
            )

    # 4. ORPHAN_EVIDENCE
    for e in evidence_list:
        if not e.hypothesis_id and not any(l.source_id == e.evidence_id for l in links):
            gaps.append(
                {
                    "gap_type": GapType.ORPHAN_EVIDENCE.value,
                    "description": f"Evidence {e.evidence_id!r} is not linked to any hypothesis.",
                    "target_ids": [e.evidence_id],
                }
            )

    # 5. UNRESOLVED_CONTRADICTION
    for asmt in assessments:
        if asmt.contradiction_strength >= 300:
            gaps.append(
                {
                    "gap_type": GapType.UNRESOLVED_CONTRADICTION.value,
                    "description": f"Hypothesis {asmt.hypothesis_id!r} has unresolved contradiction strength {asmt.contradiction_strength}.",
                    "target_ids": [asmt.hypothesis_id],
                }
            )

    # 6. ATTEMPT_WITHOUT_EVIDENCE & ATTEMPT_UNLINKED
    for att in attempts:
        if not att.hypothesis_id:
            gaps.append(
                {
                    "gap_type": GapType.ATTEMPT_UNLINKED.value,
                    "description": f"Attempt {att.attempt_id!r} is not linked to any hypothesis.",
                    "target_ids": [att.attempt_id],
                }
            )
        if not any(l.source_id == att.attempt_id for l in links):
            gaps.append(
                {
                    "gap_type": GapType.ATTEMPT_WITHOUT_EVIDENCE.value,
                    "description": f"Attempt {att.attempt_id!r} produced no associated evidence record.",
                    "target_ids": [att.attempt_id],
                }
            )

    # 7. NON_DIAGNOSTIC_ONLY
    for h in hypotheses:
        if competing_pairs and any(h.hypothesis_id in pair for pair in competing_pairs):
            asmt = asmt_map.get(h.hypothesis_id)
            if asmt and 0 < asmt.support_strength < 300:
                gaps.append(
                    {
                        "gap_type": GapType.NON_DIAGNOSTIC_ONLY.value,
                        "description": f"Hypothesis {h.hypothesis_id!r} has only weak/non-diagnostic support in competing context.",
                        "target_ids": [h.hypothesis_id],
                    }
                )

    return gaps
