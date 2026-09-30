"""
DomainSkill Protocol and DomainSkillRegistry for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Stateless Protocol interface for domain skills.
2. Skills propose draft investigation steps only; ZERO external execution.
3. Skills DO NOT access database directly or bypass scope/approval validation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from ctf_mentor.domain.investigation_models import (
    ConcreteInvestigationResult,
    InvestigationSession,
    InvestigationStep,
)
from ctf_mentor.domain.models import AuthorizedScope
from ctf_mentor.reasoning.contracts import InvestigationProposal

logger = logging.getLogger(__name__)


@runtime_checkable
class DomainSkill(Protocol):
    """Protocol interface for domain investigation skills."""

    @property
    def domain_id(self) -> str:
        ...

    def propose_step(
        self,
        proposal: InvestigationProposal,
        scopes: list[AuthorizedScope],
        session: InvestigationSession,
    ) -> Optional[InvestigationStep]:
        """Translate abstract advisory 5E proposal + target scope into a draft InvestigationStep.
        
        Returns None if target info is missing or proposal cannot be mapped.
        """
        ...


class DomainSkillRegistry:
    """In-memory static registry mapping domain_id to DomainSkill implementations."""

    def __init__(self) -> None:
        self._skills: Dict[str, DomainSkill] = {}

    def register(self, skill: DomainSkill) -> None:
        """Register a DomainSkill instance."""
        if not skill or not hasattr(skill, "domain_id") or not skill.domain_id:
            raise ValueError("DomainSkill must have a non-empty domain_id")
        self._skills[skill.domain_id] = skill
        logger.info(f"Registered DomainSkill for domain_id: '{skill.domain_id}'")

    def get(self, domain_id: str) -> DomainSkill:
        """Fetch DomainSkill for domain_id. Raises KeyError if missing."""
        if domain_id not in self._skills:
            raise KeyError(f"No DomainSkill registered for domain_id: '{domain_id}'")
        return self._skills[domain_id]

    def has_skill(self, domain_id: str) -> bool:
        """Check if domain_id has a registered skill."""
        return domain_id in self._skills
