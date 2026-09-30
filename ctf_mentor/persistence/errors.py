"""
Persistence-layer errors and value contracts for CTF Mentor/Copilot.

Re-exports contracts from ctf_mentor.contracts for backwards compatibility.
"""

from __future__ import annotations

from ctf_mentor.contracts import (
    ScopedDiff,
    StaleApprovalError,
    StaleVersionError,
)

__all__ = [
    "ScopedDiff",
    "StaleVersionError",
    "StaleApprovalError",
]
