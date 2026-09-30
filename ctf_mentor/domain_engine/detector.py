"""
Deterministic DomainDetector for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Pure deterministic function of ChallengeClassification.
2. Zero LLM dependency, zero network access, zero database calls.
3. Support ONLY Web/API vertical slice for Phase 7 initial release.
"""

from __future__ import annotations

from typing import Optional

from ctf_mentor.domain.models import ChallengeClassification

WEB_API_CATEGORIES = {
    "WEB",
    "API",
    "AUTHENTICATION",
    "SESSION",
    "IDOR",
    "INJECTION",
    "SSRF",
    "CLIENT_SIDE",
    "BUSINESS_LOGIC",
    "INFORMATION_DISCLOSURE",
    "GRAPHQL",
    "FILE_HANDLING",
}


OSINT_CATEGORIES = {
    "OSINT",
    "RECON",
    "GEOLOCATION",
    "METADATA",
    "SOCIAL",
    "DNS",
    "WHOIS",
    "PII",
}


class DomainDetector:
    """Detects investigation domain ID from Phase 5D ChallengeClassification."""

    @staticmethod
    def detect_domain(classification: Optional[ChallengeClassification]) -> Optional[str]:
        """Map classification category to domain ID (e.g. 'web_api', 'osint').
        
        Returns None if classification is missing, low confidence (< 0.2), or unsupported.
        """
        if not classification:
            return None

        if classification.confidence < 0.2:
            return None

        cat = (classification.category or "").strip().upper()

        if cat in WEB_API_CATEGORIES:
            return "web_api"

        if cat in OSINT_CATEGORIES:
            return "osint"

        # Check signals for multi-label category matches if primary category wasn't explicit
        if classification.signals:
            for signal in classification.signals:
                if signal.startswith("matched_category:"):
                    signal_cat = signal.split(":", 1)[1].strip().upper()
                    if signal_cat in WEB_API_CATEGORIES:
                        return "web_api"
                    if signal_cat in OSINT_CATEGORIES:
                        return "osint"

        return None
