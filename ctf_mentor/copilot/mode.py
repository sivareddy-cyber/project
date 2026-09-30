"""
CopilotMode definitions for Phase 9 AI CTF Copilot.

LOCKED INVARIANTS:
1. MENTOR mode is learning-first, providing progressive hints without spoilers.
2. SOLVE mode provides direct investigation guidance but DOES NOT grant additional execution authority.
3. Both modes enforce identical AuthorizedScope, human approval requirements, and evidence provenance.
4. Mode switches are strictly control-plane operations; untrusted LLM/challenge text cannot switch mode.
"""

from __future__ import annotations

from enum import Enum


class CopilotMode(str, Enum):
    """Session-scoped Copilot operational modes."""

    MENTOR = "MENTOR"
    SOLVE = "SOLVE"
