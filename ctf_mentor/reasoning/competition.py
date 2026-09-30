"""
Competing and compatible hypothesis relationship analysis.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from ctf_mentor.domain.models import Hypothesis
from ctf_mentor.reasoning.contracts import HypothesisRelation, HypothesisRelationType, LinkStatus


def analyze_hypothesis_relationships(
    hypotheses: List[Hypothesis],
    relations: List[HypothesisRelation],
) -> Tuple[Set[Tuple[str, str]], List[Dict[str, str]]]:
    """Analyze hypothesis relationships deterministically.

    Returns:
    - competing_pairs: Set of (hyp_id_1, hyp_id_2) tuples
    - discriminating_observations: List of dicts describing discrimination criteria
    """
    competing_pairs: Set[Tuple[str, str]] = set()
    discriminating_observations: List[Dict[str, str]] = []

    active_rels = [r for r in relations if r.status == LinkStatus.ACTIVE]

    # Explicit relations
    for rel in active_rels:
        if rel.relation_type == HypothesisRelationType.COMPETES:
            competing_pairs.add((rel.source_hypothesis_id, rel.target_hypothesis_id))
            competing_pairs.add((rel.target_hypothesis_id, rel.source_hypothesis_id))
            if rel.discriminating_criteria:
                discriminating_observations.append(
                    {
                        "source_hypothesis_id": rel.source_hypothesis_id,
                        "target_hypothesis_id": rel.target_hypothesis_id,
                        "criteria": rel.discriminating_criteria,
                    }
                )

    # Heuristic competition: hypotheses with the same category/tag or multiple active hypotheses
    active_hyps = [h for h in hypotheses if h.status.value == "active"]
    if len(active_hyps) > 1:
        for i in range(len(active_hyps)):
            for j in range(i + 1, len(active_hyps)):
                h1, h2 = active_hyps[i], active_hyps[j]
                competing_pairs.add((h1.hypothesis_id, h2.hypothesis_id))
                competing_pairs.add((h2.hypothesis_id, h1.hypothesis_id))

    return competing_pairs, discriminating_observations
