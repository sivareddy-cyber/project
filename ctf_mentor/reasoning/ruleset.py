"""
Deterministic Ruleset configuration and permille scoring constants for Phase 5E Reasoning Engine.
"""

from __future__ import annotations

RULESET_VERSION: str = "1.0.0"

# Evidence Tier weights in permille (0 to 1000)
TIER_WEIGHTS_PERMILLE: dict[str, int] = {
    "user_confirmed": 1000,
    "reasoning_inference": 700,
    "skill_inference": 400,
    "T1_USER_CONFIRMED": 1000,
    "T2_REASONING_INFERENCE": 700,
    "T3_SKILL_INFERENCE": 400,
}

# Default evidence weight when unspecified
DEFAULT_EVIDENCE_WEIGHT_PERMILLE: int = 500

# Contradiction multiplier weight in permille
CONTRADICTION_WEIGHT_PERMILLE: int = 1200

# Diagnosticity discount when evidence applies to multiple competing hypotheses (80%)
DIAGNOSTICITY_DISCOUNT_PERMILLE: int = 800

# Posture derivation permille thresholds
SUPPORTED_THRESHOLD_PERMILLE: int = 600
EMERGING_THRESHOLD_PERMILLE: int = 250
CONTESTED_THRESHOLD_PERMILLE: int = 400
WEAKENED_THRESHOLD_PERMILLE: int = 500
REFUTED_THRESHOLD_PERMILLE: int = 700
