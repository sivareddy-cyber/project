"""
Target translation layer between Phase 6A InvestigationTarget and Phase 6 ActionProposalTarget.

LOCKED INVARIANTS:
1. 100% Deterministic field translation and validation.
2. Fail-closed: missing hostname/port or invalid values raise ValueError.
3. Does NOT modify either locked target model.
"""

from __future__ import annotations

from typing import Any, Dict

from ctf_mentor.domain.investigation_models import InvestigationTarget, TargetType
from ctf_mentor.domain.models import ActionProposalTarget


def investigation_target_to_action_proposal_target(
    target: InvestigationTarget,
) -> ActionProposalTarget:
    """Translate a Phase 6A InvestigationTarget into an ActionProposalTarget for scope validation."""
    if not target:
        raise ValueError("InvestigationTarget must not be None")

    if target.target_type != TargetType.HTTP_TARGET:
        raise ValueError(
            f"Scope validation requires HTTP_TARGET, got '{target.target_type.value}'"
        )

    details: Dict[str, Any] = target.details or {}

    hostname = str(details.get("hostname", "")).strip()
    if not hostname:
        raise ValueError("Target hostname must not be empty")

    port_raw = details.get("port")
    if port_raw is None:
        raise ValueError("Target port must not be missing")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid target port: {port_raw!r}")

    if port < 1 or port > 65535:
        raise ValueError(f"Target port out of range: {port}")

    scheme = str(details.get("scheme", "http")).strip().lower()
    if not scheme:
        scheme = "http"

    path = str(details.get("path", "/")).strip()
    if not path:
        path = "/"
    elif not path.startswith("/"):
        path = "/" + path

    method = str(details.get("method", "GET")).strip().upper()
    if not method:
        method = "GET"

    headers = details.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}

    query_params = details.get("query_params", {})
    if not isinstance(query_params, dict):
        query_params = {}

    return ActionProposalTarget(
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        method=method,
        headers=headers,
        query_params=query_params,
    )
