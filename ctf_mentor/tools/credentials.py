"""
CredentialProvider and SecretStr abstractions for Phase 10A.

Requirements:
- Never store raw secrets in tool definitions.
- Never leak secrets in ToolResult, EvidenceCandidate, logs, repr, or exception strings.
- Missing credentials fail closed.
- Prefer environment / secret-manager backed lookup.
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Protocol, runtime_checkable


class SecretStr:
    """Secure wrapper for sensitive credential strings.

    Prevents accidental leakage via str(), repr(), logging, or serialization.
    """

    def __init__(self, secret_value: str) -> None:
        if not isinstance(secret_value, str):
            raise TypeError("SecretStr value must be a string")
        if not secret_value:
            raise ValueError("SecretStr value cannot be empty")
        self._secret_value = secret_value

    def get_secret_value(self) -> str:
        """Explicit getter to retrieve the unmasked secret value."""
        return self._secret_value

    def __str__(self) -> str:
        return "***REDACTED***"

    def __repr__(self) -> str:
        return "SecretStr('***REDACTED***')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._secret_value == other._secret_value
        return False

    def __hash__(self) -> int:
        return hash(self._secret_value)


class CredentialNotFoundError(Exception):
    """Raised when a requested credential_ref cannot be resolved.

    Fails closed without exposing ambient environment secrets in the message.
    """

    def __init__(self, credential_ref: str) -> None:
        safe_ref = str(credential_ref).replace("\n", "").replace("\r", "")
        super().__init__(f"Credential not found for reference: {safe_ref!r}")
        self.credential_ref = safe_ref


@runtime_checkable
class CredentialProvider(Protocol):
    """Protocol for secure credential resolution."""

    def get(self, credential_ref: str) -> SecretStr:
        ...


class EnvCredentialProvider:
    """Environment / dictionary backed CredentialProvider implementation."""

    DEFAULT_ENV_MAP = {
        "shodan_api_key": "SHODAN_API_KEY",
        "virustotal_api_key": "VIRUSTOTAL_API_KEY",
        "github_token": "GITHUB_TOKEN",
    }

    def __init__(self, overrides: Optional[Dict[str, str]] = None, env_map: Optional[Dict[str, str]] = None) -> None:
        self._overrides = dict(overrides) if overrides else {}
        self._env_map = dict(self.DEFAULT_ENV_MAP)
        if env_map:
            self._env_map.update(env_map)

    def get(self, credential_ref: str) -> SecretStr:
        if not credential_ref or not isinstance(credential_ref, str):
            raise CredentialNotFoundError(str(credential_ref))

        # Check explicit overrides first
        if credential_ref in self._overrides:
            val = self._overrides[credential_ref]
            if val:
                return SecretStr(val)

        # Check env map mapping
        env_var = self._env_map.get(credential_ref, credential_ref.upper())
        val = os.environ.get(env_var, "")
        if val:
            return SecretStr(val)

        raise CredentialNotFoundError(credential_ref)
