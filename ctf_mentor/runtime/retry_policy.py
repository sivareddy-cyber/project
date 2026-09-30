"""
Retry policy configuration for Phase 5C Runtime Orchestration.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RetryPolicy:
    """Configures retry behavior for logical task work."""

    max_retries: int = 3
    retry_on_stale_version: bool = True
    retry_on_failure: bool = True
    retry_on_timeout: bool = True
    backoff_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
