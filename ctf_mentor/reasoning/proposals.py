"""
Advisory Investigation Proposal Generator.

CRITICAL ARCHITECTURE INVARIANT:
Proposals describe INFORMATION missing or discriminating criteria ONLY.
They MUST NOT contain executable commands, attack payloads, exploit instructions, or automated actions.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Set, Tuple

from ctf_mentor.domain.models import Hypothesis
from ctf_mentor.reasoning.contracts import GapType, InvestigationProposal


def generate_investigation_proposals(
    challenge_id: str,
    gaps: List[Dict[str, Any]],
    hypotheses: List[Hypothesis],
    competing_pairs: Set[Tuple[str, str]],
    discriminating_criteria: List[Dict[str, str]],
) -> List[InvestigationProposal]:
    """Generate advisory investigation proposals based on detected information gaps."""
    proposals: List[InvestigationProposal] = []
    hyp_map = {h.hypothesis_id: h for h in hypotheses}

    # 1. Proposals for competing hypotheses discrimination
    seen_pairs = set()
    for pair in competing_pairs:
        h1_id, h2_id = pair
        pair_key = tuple(sorted([h1_id, h2_id]))
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        h1 = hyp_map.get(h1_id)
        h2 = hyp_map.get(h2_id)
        if not h1 or not h2:
            continue

        # Find any custom criteria or default informational observation rationale
        criteria_text = next(
            (c["criteria"] for c in discriminating_criteria if (c["source_hypothesis_id"] == h1_id and c["target_hypothesis_id"] == h2_id) or (c["source_hypothesis_id"] == h2_id and c["target_hypothesis_id"] == h1_id)),
            "An observation comparing response behavior under different authorization/parameter contexts",
        )

        proposals.append(
            InvestigationProposal(
                proposal_id=f"prop_{uuid.uuid4().hex[:12]}",
                challenge_id=challenge_id,
                title=f"Discriminate Competing Hypotheses: '{h1.title}' vs '{h2.title}'",
                description=f"Gather comparative information to distinguish hypothesis {h1_id!r} from {h2_id!r}.",
                gap_type=GapType.NON_DIAGNOSTIC_ONLY,
                target_hypothesis_ids=[h1_id, h2_id],
                discriminates_hypotheses=[h1_id, h2_id],
                rationale=f"{criteria_text} would distinguish between {h1.title!r} and {h2.title!r}.",
                metadata={"type": "discrimination"},
            )
        )

    # 2. Proposals for missing user-confirmed evidence
    for gap in gaps:
        if gap["gap_type"] == GapType.NO_USER_CONFIRMED_SUPPORT.value:
            for hid in gap.get("target_ids", []):
                h = hyp_map.get(hid)
                if h:
                    proposals.append(
                        InvestigationProposal(
                            proposal_id=f"prop_{uuid.uuid4().hex[:12]}",
                            challenge_id=challenge_id,
                            title=f"Confirm Evidence for '{h.title}'",
                            description=f"Validate hypothesis {hid!r} with user-confirmed observational evidence.",
                            gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
                            target_hypothesis_ids=[hid],
                            discriminates_hypotheses=[hid],
                            rationale="User-confirmed evidence is required before any hypothesis can reach confirmed state.",
                            metadata={"type": "user_confirmation"},
                        )
                    )

    return proposals
