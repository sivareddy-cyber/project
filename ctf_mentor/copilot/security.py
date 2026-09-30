"""
Control-Plane Security Boundary for Phase 9 AI CTF Copilot.

LOCKED SECURITY INVARIANTS:
1. Control-plane operations (approving steps, switching modes) REQUIRE a VerifiedControlPlaneIdentity.
2. VerifiedControlPlaneIdentity MUST originate from an explicit ExternalHostAuthenticator initialized with an external secret.
3. Self-attested or forged identity objects, manual AUTHENTICATED_USER enums, and prompt injections are REJECTED.
4. Top-level self-issuance with hardcoded module secrets is FORBIDDEN.
5. LLM output, Challenge text, RAG content, and Ingested artifacts are UNTRUSTED DATA.
6. Fail closed on missing, unverified, or placeholder identity parameters.
"""

from __future__ import annotations

import hmac
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

FORBIDDEN_CONTROL_PLANE_ACTORS: Set[str] = {
    "user",
    "system",
    "none",
    "null",
    "unknown",
    "admin",
    "default",
    "placeholder",
    "anonymous",
    "llm",
    "assistant",
    "copilot",
    "rag",
    "challenge",
    "attacker",
    "unauthenticated",
}


class ControlPlaneSource(str, Enum):
    """Origin source of a control-plane request."""

    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    LLM_OUTPUT = "LLM_OUTPUT"
    CHALLENGE_CONTENT = "CHALLENGE_CONTENT"
    RAG_CONTENT = "RAG_CONTENT"
    UNTRUSTED_INGESTION = "UNTRUSTED_INGESTION"


class ControlPlaneActionType(str, Enum):
    """Allowed control-plane action types."""

    DECIDE_STEP_APPROVAL = "DECIDE_STEP_APPROVAL"
    SWITCH_COPILOT_MODE = "SWITCH_COPILOT_MODE"


class ControlPlaneSecurityViolation(Exception):
    """Raised when an untrusted, unverified, or forged control-plane action is attempted."""

    pass


@dataclass(frozen=True)
class VerifiedControlPlaneIdentity:
    """Immutable, cryptographically verified control-plane user identity context.
    
    Instances can ONLY be issued by a registered ExternalHostAuthenticator instance.
    Directly instantiated or forged objects will fail verification.
    """

    user_id: str
    auth_token: str
    issued_at: float
    session_id: Optional[str] = None
    signature: Optional[str] = None
    issuer_id: Optional[str] = None


class ExternalHostAuthenticator:
    """External, host-controlled authentication authority for control-plane operations.
    
    Control-plane identity tokens can ONLY be issued and verified by an instance of this
    class initialized with a host secret key. Unauthenticated application code cannot mint tokens
    without the external host secret key.
    """

    def __init__(self, secret_key: bytes, issuer_id: str = "external_auth_host") -> None:
        if not secret_key or not isinstance(secret_key, bytes) or len(secret_key) < 16:
            raise ValueError("ExternalHostAuthenticator requires a secure bytes secret key (>= 16 bytes).")
        self._secret_key = secret_key
        self.issuer_id = issuer_id

    def issue_identity(
        self,
        user_id: str,
        session_id: Optional[str] = None,
    ) -> VerifiedControlPlaneIdentity:
        """Issue a verified ControlPlaneIdentity signed with the host secret key."""
        cleaned_user = str(user_id or "").strip()
        if not cleaned_user or cleaned_user.lower() in FORBIDDEN_CONTROL_PLANE_ACTORS:
            raise ControlPlaneSecurityViolation(f"Cannot issue verified identity for forbidden user_id: {user_id!r}")

        issued_at = time.time()
        auth_token = f"tok_{hmac.new(self._secret_key, f'{cleaned_user}:{issued_at}'.encode(), 'sha256').hexdigest()[:16]}"
        
        msg = f"{self.issuer_id}:{cleaned_user}:{auth_token}:{issued_at}:{session_id or ''}"
        sig = hmac.new(self._secret_key, msg.encode(), "sha256").hexdigest()

        return VerifiedControlPlaneIdentity(
            user_id=cleaned_user,
            auth_token=auth_token,
            issued_at=issued_at,
            session_id=session_id,
            signature=sig,
            issuer_id=self.issuer_id,
        )

    def verify_identity(self, identity: Any) -> bool:
        """Verify that identity is a genuine VerifiedControlPlaneIdentity signed by this host authenticator."""
        if not isinstance(identity, VerifiedControlPlaneIdentity):
            return False

        if not identity.user_id or not identity.signature or not identity.auth_token:
            return False

        msg = f"{identity.issuer_id or self.issuer_id}:{identity.user_id}:{identity.auth_token}:{identity.issued_at}:{identity.session_id or ''}"
        expected_sig = hmac.new(self._secret_key, msg.encode(), "sha256").hexdigest()

        return hmac.compare_digest(identity.signature, expected_sig)


class ControlPlaneSecurity:
    """Security boundary enforcing control-plane isolation from untrusted data and forged identities."""

    @classmethod
    def validate_control_plane_action(
        cls,
        action_type: ControlPlaneActionType,
        identity: Optional[VerifiedControlPlaneIdentity],
        source: Optional[ControlPlaneSource] = None,
        authenticator: Optional[ExternalHostAuthenticator] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Validate whether a control-plane action is authorized to proceed.
        
        CRITICAL: Rejects missing identities, unverified/forged identities,
        missing host authenticators, placeholder actor IDs, and non-AUTHENTICATED_USER sources. Fails closed.
        """
        # 1. Require explicit authenticated source
        if source is None or source != ControlPlaneSource.AUTHENTICATED_USER:
            err_msg = (
                f"Control-Plane Violation! Action '{action_type.value}' requested by untrusted source '{source}'. "
                "Control-plane state changes CANNOT originate from LLM text, challenge content, or RAG output."
            )
            logger.warning(err_msg)
            raise ControlPlaneSecurityViolation(err_msg)

        # 2. Require valid VerifiedControlPlaneIdentity
        if identity is None:
            err_msg = f"Control-Plane Violation! Action '{action_type.value}' requires a VerifiedControlPlaneIdentity."
            logger.warning(err_msg)
            raise ControlPlaneSecurityViolation(err_msg)

        # 3. Require registered ExternalHostAuthenticator
        if authenticator is None:
            err_msg = (
                f"Control-Plane Violation! Action '{action_type.value}' requires a registered ExternalHostAuthenticator. "
                "Control-plane trust MUST originate from an external host/API authentication boundary."
            )
            logger.warning(err_msg)
            raise ControlPlaneSecurityViolation(err_msg)

        # 4. Cryptographic signature check against host authenticator
        if not authenticator.verify_identity(identity):
            err_msg = (
                f"Control-Plane Violation! Action '{action_type.value}' provided an unverified or forged identity object. "
                "Self-attested or manually constructed AUTHENTICATED_USER parameters are rejected."
            )
            logger.warning(err_msg)
            raise ControlPlaneSecurityViolation(err_msg)

        # 5. Check actor ID against forbidden placeholders
        actor = identity.user_id.strip().lower()
        if actor in FORBIDDEN_CONTROL_PLANE_ACTORS:
            err_msg = (
                f"Control-Plane Violation! Actor ID {identity.user_id!r} is a forbidden default/placeholder value. "
                "Explicit authenticated human actor ID is required."
            )
            logger.warning(err_msg)
            raise ControlPlaneSecurityViolation(err_msg)

        return True
