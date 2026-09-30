"""
Phase 10B.3 — LocalToolOrchestrationHandler.

Routes PASSIVE_LOCAL InvestigationStep executions through LocalToolAdapter.execute_local().

DESIGN:
- The Phase 8 locked orchestration_handlers.py handles PASSIVE_NETWORK tools
  via ToolAdapter.execute(). DO NOT MODIFY IT.
- This handler is new and handles PASSIVE_LOCAL tools only.
- It issues workspace capabilities via TrustedWorkspaceExecutionBoundary,
  builds LocalExecutionContext, and dispatches to execute_local().
- Capabilities are revoked in execute_local()'s finally block (adapter
  responsibility), but this handler also calls revoke_all() in its own
  finally block as a defense-in-depth double-revocation.
- No second human approval mechanism. Existing approval in the Phase 8
  dispatch path remains authoritative.

This module must NOT be imported by orchestration_handlers.py.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from ctf_mentor.tools.contracts import ExecutionClass, ToolResult
from ctf_mentor.tools.local.adapter import LocalExecutionContext
from ctf_mentor.tools.local.policy import ToolUnavailableError, LocalPolicyViolation

if TYPE_CHECKING:
    from ctf_mentor.tools.local.adapter import LocalToolAdapter
    from ctf_mentor.workspace.capabilities import TrustedWorkspaceExecutionBoundary

logger = logging.getLogger(__name__)


class LocalToolOrchestrationHandler:
    """
    Orchestration handler for PASSIVE_LOCAL tool adapters (Phase 10B.3).

    Usage:
        handler = LocalToolOrchestrationHandler()
        result = handler.execute(adapter, raw_args, scope, boundary)

    Security:
    - Only dispatches adapters with execution_class == PASSIVE_LOCAL.
    - Builds LocalExecutionContext with minimum capabilities.
    - Capabilities are revoked via double-revocation: once inside execute_local()
      (mandatory adapter contract) and once in this handler's finally block.
    - Returns a ToolResult even on failure — never raises to caller except on
      programming errors (wrong execution_class, wrong adapter type).
    """

    def execute(
        self,
        adapter: "LocalToolAdapter",
        raw_args: Dict[str, Any],
        scope: Any,
        boundary: "TrustedWorkspaceExecutionBoundary",
    ) -> ToolResult:
        """
        Execute a PASSIVE_LOCAL adapter through the full local execution lifecycle.

        Args:
            adapter:   A LocalToolAdapter instance. Must have execution_class = PASSIVE_LOCAL.
            raw_args:  Raw (unvalidated) input arguments from the investigation step.
            scope:     Authorized execution scope (challenge/session target).
            boundary:  TrustedWorkspaceExecutionBoundary for issuing capabilities.

        Returns:
            ToolResult (always — failures are encoded as error_status, not exceptions).

        Raises:
            TypeError:  If adapter does not have execution_class == PASSIVE_LOCAL.
            TypeError:  If adapter is not a LocalToolAdapter instance.
        """
        from ctf_mentor.tools.local.adapter import LocalToolAdapter

        if not isinstance(adapter, LocalToolAdapter):
            raise TypeError(
                f"LocalToolOrchestrationHandler requires a LocalToolAdapter instance, "
                f"got {type(adapter).__name__!r}"
            )

        if getattr(adapter, "execution_class", None) != ExecutionClass.PASSIVE_LOCAL:
            raise TypeError(
                f"LocalToolOrchestrationHandler only handles PASSIVE_LOCAL adapters. "
                f"Adapter {type(adapter).__name__!r} has execution_class="
                f"{getattr(adapter, 'execution_class', 'MISSING')!r}"
            )

        # Validate input before capability issuance (fail fast)
        try:
            validated_input = adapter.validate_input(raw_args)
        except Exception as exc:
            return _make_error_result(
                adapter=adapter,
                scope=scope,
                error_status=f"input_validation_error: {type(exc).__name__}",
                details={"message": str(exc)},
            )

        # Issue minimum capabilities
        caps = boundary.issue(adapter.workspace_capability_spec)

        ctx = LocalExecutionContext.create(
            caps=caps,
            policy=adapter.execution_policy,
            challenge_id=boundary.challenge_id,
            session_id=boundary.session_id,
            workspace_id=boundary.workspace_id,
        )

        result: Optional[ToolResult] = None
        try:
            result = adapter.execute_local(validated_input, scope, ctx)
        except ToolUnavailableError as exc:
            result = _make_error_result(
                adapter=adapter,
                scope=scope,
                error_status="tool_unavailable",
                details={"message": str(exc)},
                invocation_id=ctx.invocation_id,
            )
        except LocalPolicyViolation as exc:
            result = _make_error_result(
                adapter=adapter,
                scope=scope,
                error_status=f"policy_violation: {type(exc).__name__}",
                details={"message": str(exc)},
                invocation_id=ctx.invocation_id,
            )
        except Exception as exc:
            logger.exception(
                "Unexpected error in %s.execute_local() [invocation_id=%s]",
                type(adapter).__name__,
                ctx.invocation_id,
            )
            result = _make_error_result(
                adapter=adapter,
                scope=scope,
                error_status=f"unexpected_error: {type(exc).__name__}",
                details={"message": str(exc)},
                invocation_id=ctx.invocation_id,
            )
        finally:
            # Revoke invocation authorization record and capabilities
            try:
                from ctf_mentor.tools.local.adapter import TRUSTED_INVOCATION_AUTHORITY
                TRUSTED_INVOCATION_AUTHORITY.revoke(ctx.invocation_id)
            except Exception:
                pass
            # Defense-in-depth double-revocation.
            # execute_local() must also revoke in its own finally block.
            try:
                caps.revoke_all()
            except Exception:
                pass

        return result  # type: ignore[return-value]


def _make_error_result(
    adapter: "LocalToolAdapter",
    scope: Any,
    error_status: str,
    details: Dict[str, Any],
    invocation_id: str = "",
) -> ToolResult:
    """Build an error ToolResult. Never raises."""
    import hashlib
    fingerprint = hashlib.sha256(
        f"{adapter.tool_id}:{error_status}:{invocation_id}".encode()
    ).hexdigest()[:16]
    return ToolResult(
        tool_id=adapter.tool_id,
        tool_version=adapter.tool_version,
        request_id=invocation_id or "error-no-invocation-id",
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        authorized_target=scope,
        query_fingerprint=fingerprint,
        normalized_observations=[],
        error_status=error_status,
        provenance={"error_details": details, "invocation_id": invocation_id},
        source=adapter.tool_id,
    )

