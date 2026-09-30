"""
Deterministic Evidence Analyzer with Tier scoring, independence grouping, and diagnosticity discount.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from ctf_mentor.domain.models import Evidence, Hypothesis
from ctf_mentor.reasoning.contracts import InvestigationLink, InvestigationLinkType, LinkStatus
from ctf_mentor.reasoning.ruleset import (
    CONTRADICTION_WEIGHT_PERMILLE,
    DIAGNOSTICITY_DISCOUNT_PERMILLE,
    DEFAULT_EVIDENCE_WEIGHT_PERMILLE,
    TIER_WEIGHTS_PERMILLE,
)


def analyze_evidence_for_hypotheses(
    hypotheses: List[Hypothesis],
    evidence_list: List[Evidence],
    investigation_links: List[InvestigationLink],
    competing_hypothesis_pairs: Set[Tuple[str, str]],
) -> Dict[str, Dict[str, int]]:
    """Analyze evidence deterministically for each hypothesis.

    Returns dict mapping hypothesis_id to metrics dict:
    {
        "support_strength": int (0-1000),
        "contradiction_strength": int (0-1000),
        "evidence_quality": int (0-1000),
        "evidence_coverage": int (0-1000),
        "user_confirmed_count": int,
    }
    """
    evidence_by_id = {e.evidence_id: e for e in evidence_list}
    active_links = [l for l in investigation_links if l.status == LinkStatus.ACTIVE]

    # Map hypothesis_id -> linked evidence & links
    hyp_support_evidence: Dict[str, List[Evidence]] = {h.hypothesis_id: [] for h in hypotheses}
    hyp_contradict_evidence: Dict[str, List[Evidence]] = {h.hypothesis_id: [] for h in hypotheses}

    # First, collect evidence linked via Phase 5D hypothesis_id property on Evidence object
    for e in evidence_list:
        if e.hypothesis_id and e.hypothesis_id in hyp_support_evidence:
            hyp_support_evidence[e.hypothesis_id].append(e)

    # Second, incorporate explicit investigation_links
    for link in active_links:
        if link.target_type == "hypothesis" and link.target_id in hyp_support_evidence:
            if link.source_type == "evidence" and link.source_id in evidence_by_id:
                ev = evidence_by_id[link.source_id]
                if link.relation_type == InvestigationLinkType.SUPPORTS:
                    if ev not in hyp_support_evidence[link.target_id]:
                        hyp_support_evidence[link.target_id].append(ev)
                elif link.relation_type == InvestigationLinkType.CONTRADICTS:
                    if ev not in hyp_contradict_evidence[link.target_id]:
                        hyp_contradict_evidence[link.target_id].append(ev)

    results = {}
    for h in hypotheses:
        hid = h.hypothesis_id
        sup_evs = hyp_support_evidence[hid]
        con_evs = hyp_contradict_evidence[hid]

        # 1. Calculate support strength with independence grouping & diagnosticity discount
        raw_support = _calculate_grouped_score(sup_evs, hid, competing_hypothesis_pairs)
        # 2. Calculate contradiction strength
        raw_contradiction = _calculate_grouped_score(con_evs, hid, competing_hypothesis_pairs, is_contradiction=True)

        # Count user confirmed evidence
        user_confirmed_count = sum(1 for e in sup_evs if e.source == "user_confirmed" and not e.is_fabricated)

        # Clamp strengths to [0, 1000]
        support_strength = min(1000, raw_support)
        contradiction_strength = min(1000, raw_contradiction)

        # Quality: average tier score of supporting evidence
        if sup_evs:
            quality = int(sum(TIER_WEIGHTS_PERMILLE.get(e.source, DEFAULT_EVIDENCE_WEIGHT_PERMILLE) for e in sup_evs) / len(sup_evs))
        else:
            quality = 0

        # Coverage: based on total evidence items linked
        total_linked = len(set(e.evidence_id for e in (sup_evs + con_evs)))
        coverage = min(1000, total_linked * 250)

        results[hid] = {
            "support_strength": support_strength,
            "contradiction_strength": contradiction_strength,
            "evidence_quality": quality,
            "evidence_coverage": coverage,
            "user_confirmed_count": user_confirmed_count,
        }

    return results


def _calculate_grouped_score(
    evidence_items: List[Evidence],
    hypothesis_id: str,
    competing_pairs: Set[Tuple[str, str]],
    is_contradiction: bool = False,
) -> int:
    if not evidence_items:
        return 0

    # Group evidence items by independence_group metadata (or evidence_id if non-grouped)
    groups: Dict[str, List[Evidence]] = {}
    for ev in evidence_items:
        group_key = ev.metadata.get("independence_group") or f"single_{ev.evidence_id}"
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(ev)

    total_permille = 0
    for group_key, items in sorted(groups.items(), key=lambda x: x[0]):
        # Max score within the independence group to prevent artificial multiplication
        max_tier_score = max(TIER_WEIGHTS_PERMILLE.get(e.source, DEFAULT_EVIDENCE_WEIGHT_PERMILLE) for e in items)

        # Check if evidence applies in a competing hypothesis context
        applies_to_competing = any(hypothesis_id in pair for pair in competing_pairs)

        score = max_tier_score
        if applies_to_competing:
            score = int(score * DIAGNOSTICITY_DISCOUNT_PERMILLE / 1000)

        if is_contradiction:
            score = int(score * CONTRADICTION_WEIGHT_PERMILLE / 1000)

        total_permille += score

    return total_permille
