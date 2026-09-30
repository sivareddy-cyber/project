"""
OsintDomainSkill implementation for Phase 9 AI CTF Copilot.

LOCKED INVARIANTS:
1. Closed OSINT Target Union: IMAGE_TARGET, USERNAME_TARGET, DOMAIN_TARGET, EMAIL_TARGET, TEXT_TARGET, METADATA_TARGET.
2. Deterministic target schema validation; invalid or unknown OSINT target types FAIL CLOSED.
3. Translates abstract 5E InvestigationProposal + AuthorizedScope into concrete draft InvestigationStep.
4. Fails closed on cross-challenge scope mismatch or inactive scope.
5. Stateless execution; ZERO direct database calls, ZERO autonomous reconnaissance.
"""

from __future__ import annotations

import datetime
import logging
import re
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

from ctf_mentor.domain.investigation_models import (
    InvestigationSession,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationTarget,
    TargetType,
)
from ctf_mentor.domain.models import AuthorizedScope
from ctf_mentor.reasoning.contracts import InvestigationProposal


class OsintTargetType(str, Enum):
    """Closed tagged union of supported OSINT target types."""

    IMAGE_TARGET = "IMAGE_TARGET"
    USERNAME_TARGET = "USERNAME_TARGET"
    DOMAIN_TARGET = "DOMAIN_TARGET"
    EMAIL_TARGET = "EMAIL_TARGET"
    TEXT_TARGET = "TEXT_TARGET"
    METADATA_TARGET = "METADATA_TARGET"


def validate_osint_target_details(osint_type: OsintTargetType, details: Dict[str, Any]) -> bool:
    """Deterministically validate required fields for each OSINT target type. Fails closed."""
    if not isinstance(details, dict):
        return False

    if osint_type == OsintTargetType.IMAGE_TARGET:
        image_ref = str(details.get("image_path") or details.get("image_url") or "").strip()
        return bool(image_ref)

    if osint_type == OsintTargetType.USERNAME_TARGET:
        username = str(details.get("username") or "").strip()
        if not username:
            return False
        # Alphanumeric + common separators
        return bool(re.match(r"^[a-zA-Z0-9_\-\.]{1,100}$", username))

    if osint_type == OsintTargetType.DOMAIN_TARGET:
        domain = str(details.get("domain_name") or details.get("hostname") or "").strip()
        if not domain:
            return False
        return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain))

    if osint_type == OsintTargetType.EMAIL_TARGET:
        email = str(details.get("email_address") or "").strip()
        if not email:
            return False
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

    if osint_type == OsintTargetType.TEXT_TARGET:
        query = str(details.get("query_or_text") or details.get("text") or "").strip()
        return bool(query)

    if osint_type == OsintTargetType.METADATA_TARGET:
        artifact = str(details.get("artifact_ref") or details.get("metadata_type") or "").strip()
        return bool(artifact)

    return False


class OsintDomainSkill:
    """Concrete DomainSkill for OSINT domain slice."""

    @property
    def domain_id(self) -> str:
        return "osint"

    def propose_step(
        self,
        proposal: InvestigationProposal,
        scopes: List[Union[AuthorizedScope, dict]],
        session: InvestigationSession,
    ) -> Optional[InvestigationStep]:
        """Draft a concrete OSINT InvestigationStep from proposal and authorized scope."""
        if not proposal or not scopes or not session:
            return None

        # Cross-challenge security validation
        if proposal.challenge_id != session.challenge_id:
            return None

        # Filter active scope matching challenge_id
        active_scope: Optional[Union[AuthorizedScope, dict]] = None
        for scope in scopes:
            scope_chal = (
                scope.get("challenge_id") if isinstance(scope, dict) else getattr(scope, "challenge_id", None)
            )
            is_active = (
                scope.get("is_active", True) if isinstance(scope, dict) else getattr(scope, "is_active", True)
            )
            if is_active and scope_chal == session.challenge_id:
                active_scope = scope
                break

        if not active_scope:
            return None

        # Extract proposal OSINT metadata or details
        meta = proposal.metadata or {}
        raw_osint_type = meta.get("osint_target_type") or meta.get("osint_type") or "TEXT_TARGET"

        try:
            osint_type = OsintTargetType(str(raw_osint_type).strip().upper())
        except ValueError:
            return None

        details = meta.get("target_details")
        if not isinstance(details, dict):
            # Try to build fallback details from proposal
            details = {
                "query_or_text": proposal.description or proposal.title or "OSINT investigation",
                "username": meta.get("username"),
                "domain_name": meta.get("domain_name"),
                "email_address": meta.get("email_address"),
                "image_path": meta.get("image_path"),
                "artifact_ref": meta.get("artifact_ref"),
            }

        # Validate target details against closed OSINT target schema
        if not validate_osint_target_details(osint_type, details):
            return None

        # Extract scope details
        if isinstance(active_scope, dict):
            scope_hostname = str(active_scope.get("hostname", "")).strip().lower()
            port = int(active_scope.get("port", 443))
            scheme = str(active_scope.get("scheme", "https")).strip().lower()
            exclusions = active_scope.get("exclusions", [])
            metadata = active_scope.get("metadata", {})
            query_restrictions = active_scope.get("query_restrictions", {})
        else:
            scope_hostname = str(getattr(active_scope, "hostname", "")).strip().lower()
            port = int(getattr(active_scope, "port", 443))
            scheme = str(getattr(active_scope, "scheme", "https")).strip().lower()
            exclusions = getattr(active_scope, "exclusions", [])
            metadata = getattr(active_scope, "metadata", {})
            query_restrictions = getattr(active_scope, "query_restrictions", {})

        if not scope_hostname:
            return None

        # --- ACTUAL TARGET VALUE SCOPE VALIDATION FOR ALL SIX OSINT TARGET TYPES ---
        actual_target_hostname = scope_hostname

        allowed_osint_domains = set()
        if isinstance(metadata, dict) and "allowed_osint_domains" in metadata:
            allowed_osint_domains.update([str(d).lower() for d in metadata["allowed_osint_domains"]])
        if isinstance(query_restrictions, dict) and "allowed_domains" in query_restrictions:
            allowed_osint_domains.update([str(d).lower() for d in query_restrictions["allowed_domains"]])
        allowed_osint_domains.add(scope_hostname)

        def _is_domain_in_scope(domain: str) -> bool:
            clean_dom = domain.strip().lower()
            if not clean_dom:
                return False
            if clean_dom in allowed_osint_domains:
                return True
            for allowed in allowed_osint_domains:
                if clean_dom.endswith("." + allowed):
                    return True
            return False

        # Collect explicit allowed usernames
        allowed_usernames = set()
        if isinstance(metadata, dict):
            if "allowed_usernames" in metadata:
                allowed_usernames.update([str(u).lower() for u in metadata["allowed_usernames"]])
            if "allowed_users" in metadata:
                allowed_usernames.update([str(u).lower() for u in metadata["allowed_users"]])
        if isinstance(query_restrictions, dict):
            if "allowed_usernames" in query_restrictions:
                allowed_usernames.update([str(u).lower() for u in query_restrictions["allowed_usernames"]])
            if "allowed_users" in query_restrictions:
                allowed_usernames.update([str(u).lower() for u in query_restrictions["allowed_users"]])
        if scope_hostname:
            allowed_usernames.add(scope_hostname.split(".")[0])

        # Collect allowed artifacts and subjects
        allowed_artifacts = set()
        if isinstance(metadata, dict) and "allowed_artifacts" in metadata:
            allowed_artifacts.update([str(a).lower() for a in metadata["allowed_artifacts"]])
        if isinstance(query_restrictions, dict) and "allowed_artifacts" in query_restrictions:
            allowed_artifacts.update([str(a).lower() for a in query_restrictions["allowed_artifacts"]])

        allowed_subjects = set(allowed_osint_domains)
        allowed_subjects.update(allowed_usernames)
        allowed_subjects.update(allowed_artifacts)
        if isinstance(metadata, dict) and "allowed_subjects" in metadata:
            allowed_subjects.update([str(s).lower() for s in metadata["allowed_subjects"]])

        if osint_type == OsintTargetType.DOMAIN_TARGET:
            actual_dom = str(details.get("domain_name") or details.get("hostname") or "").strip().lower()
            if not actual_dom or not _is_domain_in_scope(actual_dom):
                logger.warning(f"OSINT DOMAIN_TARGET '{actual_dom}' is out of scope (authorized: {scope_hostname}). REJECTED.")
                return None
            actual_target_hostname = actual_dom

        elif osint_type == OsintTargetType.EMAIL_TARGET:
            email = str(details.get("email_address") or "").strip().lower()
            if "@" not in email:
                return None
            email_domain = email.split("@")[-1]
            if not _is_domain_in_scope(email_domain):
                logger.warning(f"OSINT EMAIL_TARGET '{email}' domain '{email_domain}' is out of scope. REJECTED.")
                return None
            actual_target_hostname = email_domain

        elif osint_type == OsintTargetType.USERNAME_TARGET:
            username = str(details.get("username") or "").strip().lower()
            if not username or username not in allowed_usernames:
                logger.warning(f"OSINT USERNAME_TARGET '{username}' is not in authorized username allowlist {allowed_usernames}. REJECTED.")
                return None

        elif osint_type == OsintTargetType.TEXT_TARGET:
            text_query = str(details.get("query_or_text") or details.get("text") or proposal.description or "").strip()
            subject_token = str(details.get("subject") or details.get("domain_name") or "").strip().lower()
            if any(ex in text_query.lower() for ex in exclusions):
                return None
            if not subject_token:
                logger.warning("OSINT TEXT_TARGET missing required structured subject/domain_name field. REJECTED.")
                return None
            if not (_is_domain_in_scope(subject_token) or subject_token in allowed_subjects or subject_token in allowed_usernames):
                logger.warning(f"OSINT TEXT_TARGET structured subject '{subject_token}' is not in authorized scope. REJECTED.")
                return None
            actual_target_hostname = scope_hostname

        elif osint_type == OsintTargetType.IMAGE_TARGET:
            img_ref = str(details.get("image_url") or details.get("image_path") or "").strip()
            if not img_ref:
                return None
            if any(ex in img_ref.lower() for ex in exclusions):
                logger.warning(f"OSINT IMAGE_TARGET '{img_ref}' is in scope exclusions. REJECTED.")
                return None

            if "://" in img_ref or img_ref.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(img_ref)
                    host = parsed_url.hostname
                    if not host:
                        logger.warning(f"OSINT IMAGE_TARGET URL '{img_ref}' has no valid hostname. REJECTED.")
                        return None
                    host_clean = host.lower()
                    if not _is_domain_in_scope(host_clean):
                        logger.warning(f"OSINT IMAGE_TARGET actual URL hostname '{host_clean}' is NOT in authorized scope. REJECTED.")
                        return None
                    actual_target_hostname = host_clean
                except Exception:
                    return None
            else:
                # Non-URL image reference requires a valid structured subject in scope
                subject_token = str(details.get("subject") or details.get("domain_name") or "").strip().lower()
                if not subject_token or not (_is_domain_in_scope(subject_token) or subject_token in allowed_subjects):
                    logger.warning(f"OSINT IMAGE_TARGET non-URL reference missing valid in-scope subject. REJECTED.")
                    return None

        elif osint_type == OsintTargetType.METADATA_TARGET:
            artifact_ref = str(details.get("artifact_ref") or details.get("subject") or "").strip().lower()
            if not artifact_ref:
                logger.warning("OSINT METADATA_TARGET missing structured artifact_ref/subject. REJECTED.")
                return None
            if any(ex in artifact_ref for ex in exclusions):
                return None
            in_artifacts = artifact_ref in allowed_artifacts
            in_domains = _is_domain_in_scope(artifact_ref)
            in_subjects = artifact_ref in allowed_subjects
            if not (in_artifacts or in_domains or in_subjects):
                logger.warning(f"OSINT METADATA_TARGET '{artifact_ref}' is not in authorized scope. REJECTED.")
                return None

        step_type = f"OSINT_{osint_type.value}"
        target = InvestigationTarget(
            target_type=TargetType.HTTP_TARGET,
            details={
                "hostname": actual_target_hostname,
                "port": port,
                "path": "/",
                "method": "GET",
                "scheme": scheme,
                "osint_target_type": osint_type.value,
                "osint_details": details,
            },
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        step_id = f"step_osint_{uuid.uuid4().hex[:12]}"

        return InvestigationStep(
            step_id=step_id,
            session_id=session.session_id,
            challenge_id=session.challenge_id,
            step_type=step_type,
            target=target,
            rationale=proposal.rationale or proposal.description or "OSINT investigation step",
            status=InvestigationStepStatus.PENDING_APPROVAL,
            created_at=now,
            updated_at=now,
            proposal_ref=proposal.proposal_id,
            metadata={
                "domain_id": self.domain_id,
                "gap_type": proposal.gap_type.value,
                "osint_type": osint_type.value,
            },
        )
