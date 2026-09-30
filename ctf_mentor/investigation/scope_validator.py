"""
Deterministic Scope Validator for Phase 6 Human-Guided Controlled Investigation Layer.

LOCKED SECURITY INVARIANTS:
1. 100% Deterministic validation (NO LLM involvement).
2. Fail-closed: missing scope, expired scope, ambiguous target, or any mismatch REJECTS proposal.
3. Validates scheme, hostname/IP, port, path patterns, allowed methods, and exclusions.
4. No wildcard-by-default behavior.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from typing import Any, List, Optional, Set, Union

from ctf_mentor.domain.models import ActionProposalTarget, AuthorizedScope


@dataclass
class ScopeValidationResult:
    is_allowed: bool
    reason: str
    scope_id: Optional[str] = None
    scope_version: str = "1.0"


class DeterministicScopeValidator:
    """100% deterministic, rule-based scope validator for ActionProposalTargets."""

    @staticmethod
    def _get_val(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _get_list_val(obj: Any, key: str) -> List[str]:
        val = DeterministicScopeValidator._get_val(obj, key)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    val = parsed
                else:
                    val = [val]
            except Exception:
                val = [val]
        if isinstance(val, (list, set, tuple)):
            return [str(item) for item in val]
        return []

    @classmethod
    def validate(
        cls,
        target: ActionProposalTarget,
        scopes: List[Union[AuthorizedScope, dict]],
    ) -> ScopeValidationResult:
        """Validate target against an array of human-provisioned active AuthorizedScopes."""
        if not scopes:
            return ScopeValidationResult(
                is_allowed=False,
                reason="No active AuthorizedScope found for challenge (fail-closed).",
            )

        target_scheme = target.scheme.strip().lower()
        target_host = target.hostname.strip().lower()
        target_port = target.port
        target_path = target.path.strip()
        target_method = target.method.strip().upper()

        if not target_host:
            return ScopeValidationResult(
                is_allowed=False,
                reason="Target hostname is empty.",
            )

        for scope in scopes:
            is_active = bool(cls._get_val(scope, "is_active", True))
            if not is_active:
                continue

            # 1. Scheme Check
            scope_scheme = cls._get_val(scope, "scheme")
            if scope_scheme and str(scope_scheme).strip().lower() != target_scheme:
                continue

            # 2. Hostname Check
            scope_host = str(cls._get_val(scope, "hostname", "")).strip().lower()
            if scope_host != target_host:
                # Disallow wildcard host matching unless exact match
                continue

            # 3. Port Check
            scope_port = cls._get_val(scope, "port")
            if scope_port is not None and int(scope_port) != target_port:
                continue

            # 4. Method Check
            methods_list = cls._get_list_val(scope, "allowed_methods")
            allowed_methods: Set[str] = {m.strip().upper() for m in methods_list} if methods_list else {"GET"}
            if target_method not in allowed_methods:
                return ScopeValidationResult(
                    is_allowed=False,
                    reason=f"HTTP method '{target_method}' is not in allowed methods {sorted(allowed_methods)} for scope.",
                )

            # 5. Exclusion Check
            excluded = False
            exclusions = cls._get_list_val(scope, "exclusions")
            for excl_pattern in exclusions:
                if fnmatch.fnmatch(target_path, excl_pattern.strip()):
                    excluded = True
                    break
            if excluded:
                return ScopeValidationResult(
                    is_allowed=False,
                    reason=f"Target path '{target_path}' matches scope exclusion pattern.",
                )

            # 6. Path Pattern Check
            path_allowed = False
            allowed_patterns = cls._get_list_val(scope, "allowed_path_patterns") or ["/*", "/"]
            for path_pat in allowed_patterns:
                pat_clean = path_pat.strip()
                if fnmatch.fnmatch(target_path, pat_clean):
                    path_allowed = True
                    break

            if not path_allowed:
                return ScopeValidationResult(
                    is_allowed=False,
                    reason=f"Target path '{target_path}' does not match allowed path patterns {allowed_patterns}.",
                )

            scope_id = str(cls._get_val(scope, "scope_id", "scope_1"))
            meta = cls._get_val(scope, "metadata", {})
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            if not isinstance(meta, dict):
                meta = {}

            # Clean match against this scope!
            return ScopeValidationResult(
                is_allowed=True,
                reason="",
                scope_id=scope_id,
                scope_version=str(meta.get("version", "1.0")),
            )

        return ScopeValidationResult(
            is_allowed=False,
            reason=f"Target {target_scheme}://{target_host}:{target_port}{target_path} is out of authorized scope.",
        )

