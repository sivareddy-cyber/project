"""
Canonical JSON serialization and SHA-256 hashing for deterministic reasoning verification.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _normalize_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _normalize_obj(v) for k, v in sorted(obj.items(), key=lambda x: str(x[0]))}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_obj(item) for item in obj]
    elif isinstance(obj, float):
        # Format floats deterministically up to 6 decimal places to prevent FP rounding drift
        return round(obj, 6)
    elif hasattr(obj, "value") and isinstance(obj.value, (str, int)):
        # Enum handling
        return obj.value
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


def canonicalize_json(data: Any) -> str:
    """Return a deterministic, canonical JSON string representation of data."""
    normalized = _normalize_obj(data)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_result_hash(data: Any) -> str:
    """Compute SHA-256 hex digest of the canonical JSON representation of data."""
    canonical_str = canonicalize_json(data)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
