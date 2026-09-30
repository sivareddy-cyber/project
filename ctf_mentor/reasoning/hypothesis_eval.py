"""
Deterministic Hypothesis Evaluator for advisory reasoning postures and confirmation eligibility.
"""

from __future__ import annotations

import uuid
from typing import Dict, List

from ctf_mentor.domain.models import Hypothesis
from ctf_mentor.reasoning.contracts import HypothesisPosture, ReasoningAssessment
from ctf_mentor.reasoning.ruleset import (
    CONTESTED_THRESHOLD_PERMILLE,
    EMERGING_THRESHOLD_PERMILLE,
    REFUTED_THRESHOLD_PERMILLE,
    SUPPORTED_THRESHOLD_PERMILLE,
    WEAKENED_THRESHOLD_PERMILLE,
)


def evaluate_hypotheses(
    run_id: str,
    challenge_id: str,
    hypotheses: List[Hypothesis],
    evidence_metrics: Dict[str, Dict[str, int]],
) -> List[ReasoningAssessment]:
    """Evaluate each hypothesis deterministically and derive advisory posture and confirmation eligibility.

    CRITICAL SAFETY GUARANTEE:
    This function derives ADVISORY assessments ONLY.
    It does NOT mutate Phase 5D hypothesis status or DB rows.
    """
    assessments: List[ReasoningAssessment] = []

    for h in sorted(hypotheses, key=lambda x: x.hypothesis_id):
        hid = h.hypothesis_id
        metrics = evidence_metrics.get(
            hid,
            {
                "support_strength": 0,
                "contradiction_strength": 0,
                "evidence_quality": 0,
                "evidence_coverage": 0,
                "user_confirmed_count": 0,
            },
        )

        sup = metrics["support_strength"]
        con = metrics["contradiction_strength"]
        uc_count = metrics["user_confirmed_count"]

        # Derive advisory posture deterministically
        if con >= REFUTED_THRESHOLD_PERMILLE and sup < EMERGING_THRESHOLD_PERMILLE:
            posture = HypothesisPosture.REFUTED_CANDIDATE
        elif sup >= SUPPORTED_THRESHOLD_PERMILLE and con >= CONTESTED_THRESHOLD_PERMILLE:
            posture = HypothesisPosture.CONTESTED
        elif con >= WEAKENED_THRESHOLD_PERMILLE and sup < SUPPORTED_THRESHOLD_PERMILLE:
            posture = HypothesisPosture.WEAKENED_CANDIDATE
        elif sup >= SUPPORTED_THRESHOLD_PERMILLE:
            posture = HypothesisPosture.SUPPORTED_CANDIDATE
        elif sup >= EMERGING_THRESHOLD_PERMILLE:
            posture = HypothesisPosture.EMERGING
        else:
            posture = HypothesisPosture.UNTESTED

        # Preserves Phase 5D User-Confirmed Evidence Gate for confirmation eligibility
        is_confirmation_eligible = uc_count > 0

        assessments.append(
            ReasoningAssessment(
                assessment_id=f"asmt_{uuid.uuid4().hex[:12]}",
                run_id=run_id,
                challenge_id=challenge_id,
                hypothesis_id=hid,
                posture=posture,
                support_strength=sup,
                contradiction_strength=con,
                evidence_quality=metrics["evidence_quality"],
                evidence_coverage=metrics["evidence_coverage"],
                is_confirmation_eligible=is_confirmation_eligible,
                assessment_data={
                    "user_confirmed_count": uc_count,
                    "phase5d_status": h.status.value,
                },
            )
        )

    return assessments
