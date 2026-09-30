"""
Normalization helper and validation for Phase 10A tool adapter outputs.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ctf_mentor.tools.contracts import EvidenceCandidate, ToolResult


def normalize_tool_result(result: ToolResult) -> List[EvidenceCandidate]:
    """Validate and enforce normalization standards on all observations in a ToolResult.

    LOCKED INVARIANT:
    All Phase 10A evidence candidates MUST be explicitly marked trust = "UNTRUSTED".
    """
    if not isinstance(result, ToolResult):
        raise TypeError(f"Expected ToolResult, got {type(result).__name__}")

    normalized: List[EvidenceCandidate] = []
    for cand in result.normalized_observations:
        if not isinstance(cand, EvidenceCandidate):
            raise TypeError(f"Observation in result is not EvidenceCandidate: {type(cand).__name__}")

        if cand.trust != "UNTRUSTED":
            raise ValueError("All Phase 10A evidence candidates must have trust='UNTRUSTED'")

        # Verify no raw credentials exist in observation
        obs_str = str(cand.observation)
        if "shodan_api_key" in obs_str or "virustotal_api_key" in obs_str or "github_token" in obs_str:
            raise ValueError("Credential reference string found in EvidenceCandidate observation!")

        normalized.append(cand)

    return normalized
