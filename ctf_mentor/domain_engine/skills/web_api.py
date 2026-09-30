"""
WebApiDomainSkill implementation for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Translates abstract 5E InvestigationProposal + AuthorizedScope into HTTP_TARGET step.
2. Extracts hostname/port strictly from AuthorizedScope; NEVER invents targets.
3. Fails closed (returns None) if hostname or port is missing or ambiguous.
4. Stateless execution; ZERO direct database or execution calls.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional, Union

from ctf_mentor.domain.investigation_models import (
    InvestigationSession,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationTarget,
    TargetType,
)
from ctf_mentor.domain.models import AuthorizedScope
from ctf_mentor.reasoning.contracts import InvestigationProposal


class WebApiDomainSkill:
    """Concrete DomainSkill for Web/API investigation slice."""

    @property
    def domain_id(self) -> str:
        return "web_api"

    def propose_step(
        self,
        proposal: InvestigationProposal,
        scopes: List[Union[AuthorizedScope, dict]],
        session: InvestigationSession,
    ) -> Optional[InvestigationStep]:
        """Draft a concrete HTTP InvestigationStep from proposal and authorized scope."""
        if not proposal or not scopes or not session:
            return None

        # Filter active scope entries matching HTTP/HTTPS
        active_scope: Optional[Union[AuthorizedScope, dict]] = None
        for scope in scopes:
            is_active = True
            if isinstance(scope, dict):
                is_active = bool(scope.get("is_active", True))
                scheme = str(scope.get("scheme", "http")).lower()
            else:
                is_active = getattr(scope, "is_active", True)
                scheme = str(getattr(scope, "scheme", "http")).lower()

            if is_active and scheme in {"http", "https"}:
                active_scope = scope
                break

        if not active_scope:
            return None

        def _to_list(val: Any) -> List[str]:
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

        # Extract target parameters strictly from scope
        if isinstance(active_scope, dict):
            hostname = str(active_scope.get("hostname", "")).strip()
            port_val = active_scope.get("port")
            scheme = str(active_scope.get("scheme", "http")).strip().lower()
            path_patterns = _to_list(active_scope.get("allowed_path_patterns", ["/"]))
            methods = _to_list(active_scope.get("allowed_methods", ["GET"]))
        else:
            hostname = str(getattr(active_scope, "hostname", "")).strip()
            port_val = getattr(active_scope, "port", None)
            scheme = str(getattr(active_scope, "scheme", "http")).strip().lower()
            path_patterns = _to_list(getattr(active_scope, "allowed_path_patterns", ["/"]))
            methods = _to_list(getattr(active_scope, "allowed_methods", ["GET"]))

        if not hostname or port_val is None:
            return None

        try:
            port = int(port_val)
        except (ValueError, TypeError):
            return None

        if port < 1 or port > 65535:
            return None

        # Select deterministic default path & method from allowed patterns
        path = "/"
        if path_patterns:
            first_pat = str(path_patterns[0]).strip()
            if first_pat and first_pat != "/*":
                path = first_pat.rstrip("*")
                if not path.startswith("/"):
                    path = "/" + path

        method = "GET"
        if methods and isinstance(methods, list):
            first_m = str(methods[0]).strip().upper()
            if first_m in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"}:
                method = first_m

        step_type = f"HTTP_{method}"

        target = InvestigationTarget(
            target_type=TargetType.HTTP_TARGET,
            details={
                "hostname": hostname,
                "port": port,
                "path": path,
                "method": method,
                "scheme": scheme,
            },
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        step_id = f"step_{uuid.uuid4().hex[:12]}"

        return InvestigationStep(
            step_id=step_id,
            session_id=session.session_id,
            challenge_id=session.challenge_id,
            step_type=step_type,
            target=target,
            rationale=proposal.rationale or proposal.description or "Web/API investigation step",
            status=InvestigationStepStatus.PENDING_APPROVAL,
            created_at=now,
            updated_at=now,
            proposal_ref=proposal.proposal_id,
            metadata={"domain_id": self.domain_id, "gap_type": proposal.gap_type.value},
        )
