"""
Pure Deterministic ReasoningEngine Pipeline.

INVARIANTS:
1. Pure deterministic function of input ReasoningView.
2. Zero randomness, zero time calculation in reasoning logic.
3. Zero network, database, subprocess, or external service calls.
4. Identical ReasoningView input ALWAYS produces identical ReasoningResult and SHA-256 result_hash.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from ctf_mentor.reasoning.canonical import canonicalize_json, compute_result_hash
from ctf_mentor.reasoning.competition import analyze_hypothesis_relationships
from ctf_mentor.reasoning.contracts import ReasoningResult
from ctf_mentor.reasoning.evidence_analysis import analyze_evidence_for_hypotheses
from ctf_mentor.reasoning.gaps import detect_information_gaps
from ctf_mentor.reasoning.hypothesis_eval import evaluate_hypotheses
from ctf_mentor.reasoning.proposals import generate_investigation_proposals
from ctf_mentor.reasoning.ruleset import RULESET_VERSION
from ctf_mentor.reasoning.view import ReasoningView


class ReasoningEngine:
    """Pure deterministic reasoning engine."""

    def analyze(self, view: ReasoningView, run_sequence: int = 1) -> ReasoningResult:
        """Execute deterministic reasoning pipeline on the immutable ReasoningView."""
        challenge_id = view.challenge_id

        # 1. Analyze hypothesis relationships (competing / compatible)
        competing_pairs, discriminating_criteria = analyze_hypothesis_relationships(
            hypotheses=view.hypotheses,
            relations=view.hypothesis_relations,
        )

        # 2. Analyze evidence deterministically
        evidence_metrics = analyze_evidence_for_hypotheses(
            hypotheses=view.hypotheses,
            evidence_list=view.evidence,
            investigation_links=view.investigation_links,
            competing_hypothesis_pairs=competing_pairs,
        )

        # 3. Evaluate hypothesis assessments & postures
        # Use deterministic run_id derived from input_fingerprint and run_sequence
        run_id = f"run_{view.input_fingerprint[:12]}_{run_sequence}"
        assessments = evaluate_hypotheses(
            run_id=run_id,
            challenge_id=challenge_id,
            hypotheses=view.hypotheses,
            evidence_metrics=evidence_metrics,
        )

        # 4. Detect information gaps
        gaps = detect_information_gaps(
            classification=view.classification,
            hypotheses=view.hypotheses,
            evidence_list=view.evidence,
            attempts=view.attempts,
            predictions=view.predictions,
            links=view.investigation_links,
            assessments=assessments,
            competing_pairs=competing_pairs,
        )

        # 5. Generate advisory investigation proposals
        proposals = generate_investigation_proposals(
            challenge_id=challenge_id,
            gaps=gaps,
            hypotheses=view.hypotheses,
            competing_pairs=competing_pairs,
            discriminating_criteria=discriminating_criteria,
        )

        # 6. Canonicalize result for deterministic hashing
        canonical_dict = {
            "challenge_id": challenge_id,
            "run_sequence": run_sequence,
            "input_fingerprint": view.input_fingerprint,
            "ruleset_version": RULESET_VERSION,
            "assessments": [
                {
                    "hypothesis_id": a.hypothesis_id,
                    "posture": a.posture.value,
                    "support_strength": a.support_strength,
                    "contradiction_strength": a.contradiction_strength,
                    "evidence_quality": a.evidence_quality,
                    "evidence_coverage": a.evidence_coverage,
                    "is_confirmation_eligible": a.is_confirmation_eligible,
                }
                for a in sorted(assessments, key=lambda x: x.hypothesis_id)
            ],
            "gaps": sorted(gaps, key=lambda x: (x["gap_type"], str(x.get("target_ids")))),
            "proposals": [
                {
                    "title": p.title,
                    "gap_type": p.gap_type.value,
                    "target_hypothesis_ids": sorted(p.target_hypothesis_ids),
                    "discriminates_hypotheses": sorted(p.discriminates_hypotheses),
                    "rationale": p.rationale,
                }
                for p in sorted(proposals, key=lambda x: x.title)
            ],
        }

        result_hash = compute_result_hash(canonical_dict)
        now_utc = datetime.now(timezone.utc)

        return ReasoningResult(
            run_id=run_id,
            challenge_id=challenge_id,
            run_sequence=run_sequence,
            input_fingerprint=view.input_fingerprint,
            ruleset_version=RULESET_VERSION,
            assessments=assessments,
            proposals=proposals,
            detected_gaps=gaps,
            canonical_dict=canonical_dict,
            result_hash=result_hash,
            created_at=now_utc,
        )
