"""
InvestigationPlanner for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Orchestrates proposal translation, scope validation, and atomic step creation.
2. Runs DeterministicScopeValidator.validate() BEFORE calling create_step_atomic().
3. Fail-closed: missing scopes or scope mismatch aborts step creation.
4. Created steps are ALWAYS in PENDING_APPROVAL status.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.investigation_models import InvestigationSession, InvestigationStep
from ctf_mentor.domain.models import AuthorizedScope
from ctf_mentor.domain_engine.protocol import DomainSkill, DomainSkillRegistry
from ctf_mentor.domain_engine.skills.web_api import WebApiDomainSkill
from ctf_mentor.domain_engine.target_translator import investigation_target_to_action_proposal_target
from ctf_mentor.investigation.scope_validator import DeterministicScopeValidator
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.reasoning.contracts import InvestigationProposal

logger = logging.getLogger(__name__)


@dataclass
class PlannerResult:
    """Result of an InvestigationPlanner planning operation."""

    success: bool
    step_id: Optional[str] = None
    approval_id: Optional[str] = None
    status: Optional[str] = None
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class InvestigationPlanner:
    """Orchestrates Phase 7 Domain Engine investigation step planning."""

    def __init__(
        self,
        investigation_repo: InvestigationRepository,
        blackboard_repo: BlackboardRepository,
        registry: Optional[DomainSkillRegistry] = None,
    ) -> None:
        self.investigation_repo = investigation_repo
        self.blackboard_repo = blackboard_repo
        self.registry = registry or DomainSkillRegistry()

        # Register default WebApiDomainSkill if not present
        if not self.registry.has_skill("web_api"):
            self.registry.register(WebApiDomainSkill())

    def plan_investigation_step(
        self,
        proposal: InvestigationProposal,
        session: InvestigationSession,
        domain_id: str = "web_api",
        ttl_seconds: int = 3600,
    ) -> PlannerResult:
        """Plan, validate scope, and atomically persist a Phase 6A InvestigationStep."""
        if not proposal or not session:
            return PlannerResult(
                success=False,
                error_message="Proposal and session must not be None.",
            )

        if session.challenge_id != proposal.challenge_id:
            return PlannerResult(
                success=False,
                error_message=f"Cross-challenge proposal rejected: proposal challenge '{proposal.challenge_id}' != session challenge '{session.challenge_id}'.",
            )

        # 1. Fetch DomainSkill
        if not self.registry.has_skill(domain_id):
            return PlannerResult(
                success=False,
                error_message=f"No DomainSkill registered for domain_id '{domain_id}'.",
            )
        skill = self.registry.get(domain_id)

        # 2. Retrieve AuthorizedScope records for challenge (Fail closed if missing)
        scope_dicts = self.blackboard_repo.read_authorized_scopes_for_challenge(session.challenge_id)
        if not scope_dicts:
            return PlannerResult(
                success=False,
                error_message=f"No active AuthorizedScope found for challenge '{session.challenge_id}' (fail-closed).",
            )

        def _parse_list(val: Any) -> list[str]:
            if isinstance(val, str):
                try:
                    import json
                    parsed = json.loads(val)
                    if isinstance(parsed, list):
                        return [str(x) for x in parsed]
                except Exception:
                    pass
                return [val]
            if isinstance(val, (list, tuple, set)):
                return [str(x) for x in val]
            return []

        # Parse scope objects for skill
        scopes: List[AuthorizedScope] = []
        for d in scope_dicts:
            try:
                # Build AuthorizedScope if dictionary
                if isinstance(d, dict):
                    scopes.append(
                        AuthorizedScope(
                            scope_id=str(d.get("scope_id", "scope_1")),
                            challenge_id=str(d.get("challenge_id", session.challenge_id)),
                            scheme=str(d.get("scheme", "http")),
                            hostname=str(d.get("hostname", "")),
                            port=int(d.get("port", 80)),
                            allowed_path_patterns=_parse_list(d.get("allowed_path_patterns", ["/*"])),
                            allowed_methods=_parse_list(d.get("allowed_methods", ["GET"])),
                            exclusions=_parse_list(d.get("exclusions", [])),
                            query_restrictions=d.get("query_restrictions", {}) if isinstance(d.get("query_restrictions"), dict) else {},
                            environment_id=str(d.get("environment_id", "default")),
                            challenge_relationship=str(d.get("challenge_relationship", "primary_target")),
                            created_at=session.created_at,
                            is_active=bool(d.get("is_active", True)),
                        )
                    )
                elif isinstance(d, AuthorizedScope):
                    scopes.append(d)
            except Exception as ex:
                logger.warning(f"Error parsing AuthorizedScope row: {ex}")

        if not scopes:
            return PlannerResult(
                success=False,
                error_message=f"Failed to parse active AuthorizedScopes for challenge '{session.challenge_id}'.",
            )

        # 3. Ask DomainSkill for draft step
        draft_step = skill.propose_step(proposal=proposal, scopes=scopes, session=session)
        if not draft_step:
            return PlannerResult(
                success=False,
                error_message=f"Skill '{domain_id}' failed to draft step from proposal '{proposal.proposal_id}'.",
            )

        # 4. Target Translation: InvestigationTarget -> ActionProposalTarget
        try:
            ap_target = investigation_target_to_action_proposal_target(draft_step.target)
        except Exception as ex:
            return PlannerResult(
                success=False,
                error_message=f"Target translation failed: {ex}",
            )

        # 5. Deterministic Scope Validation
        scope_result = DeterministicScopeValidator.validate(ap_target, scopes)
        if not scope_result.is_allowed:
            return PlannerResult(
                success=False,
                error_message=f"Proposed step target is out of authorized scope: {scope_result.reason}",
            )

        # 6. Atomically persist InvestigationStep in PENDING_APPROVAL status via 6A create_step_atomic()
        try:
            res_dict = self.investigation_repo.create_step_atomic(draft_step, ttl_seconds=ttl_seconds)
            return PlannerResult(
                success=True,
                step_id=res_dict["step_id"],
                approval_id=res_dict["approval_id"],
                status=res_dict["status"],
                details=res_dict,
            )
        except Exception as ex:
            return PlannerResult(
                success=False,
                error_message=f"Atomic step creation failed: {ex}",
            )
