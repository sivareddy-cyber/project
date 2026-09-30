"""
Scope enforcement utilities for Phase 10A tool adapters.

Reuses existing Phase 9 scope concepts and rules.
Fails closed on lookalikes, substring matches, and scope bypass attempts.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set


def extract_allowed_domains(scope: Any) -> Set[str]:
    """Extract set of clean allowed domain names from AuthorizedScope object or dictionary."""
    allowed: Set[str] = set()

    if scope is None:
        return allowed

    if isinstance(scope, dict):
        hostname = str(scope.get("hostname", "")).strip().lower().rstrip(".")
        metadata = scope.get("metadata", {})
        query_restrictions = scope.get("query_restrictions", {})
    else:
        hostname = str(getattr(scope, "hostname", "")).strip().lower().rstrip(".")
        metadata = getattr(scope, "metadata", {})
        query_restrictions = getattr(scope, "query_restrictions", {})

    if hostname:
        allowed.add(hostname)

    if isinstance(metadata, dict):
        for k in ("allowed_domains", "allowed_osint_domains", "domains"):
            if k in metadata and isinstance(metadata[k], (list, tuple, set)):
                for d in metadata[k]:
                    clean_d = str(d).strip().lower().rstrip(".")
                    if clean_d:
                        allowed.add(clean_d)

    if isinstance(query_restrictions, dict):
        for k in ("allowed_domains", "domains"):
            if k in query_restrictions and isinstance(query_restrictions[k], (list, tuple, set)):
                for d in query_restrictions[k]:
                    clean_d = str(d).strip().lower().rstrip(".")
                    if clean_d:
                        allowed.add(clean_d)

    return allowed


def is_domain_in_scope(target_domain: str, scope: Any) -> bool:
    """Strictly validate if target_domain is authorized under scope.

    Fails closed on:
    - empty / non-string domain
    - substring matches (e.g. 'not-target.com' vs 'target.com')
    - domain suffix lookalikes (e.g. 'target.com.evil.com')
    """
    if not target_domain or not isinstance(target_domain, str):
        return False

    clean_target = target_domain.strip().lower().rstrip(".")
    if not clean_target:
        return False

    allowed_domains = extract_allowed_domains(scope)
    if not allowed_domains:
        return False

    for allowed in allowed_domains:
        clean_allowed = allowed.strip().lower().rstrip(".")
        if clean_target == clean_allowed:
            return True
        if clean_target.endswith("." + clean_allowed):
            return True

    return False


def extract_allowed_subjects(scope: Any) -> Set[str]:
    """Extract allowed text subjects/usernames/artifacts from AuthorizedScope."""
    allowed: Set[str] = set()
    if scope is None:
        return allowed

    # Include domain names as allowed text search subjects
    allowed.update(extract_allowed_domains(scope))

    if isinstance(scope, dict):
        metadata = scope.get("metadata", {})
        query_restrictions = scope.get("query_restrictions", {})
    else:
        metadata = getattr(scope, "metadata", {})
        query_restrictions = getattr(scope, "query_restrictions", {})

    if isinstance(metadata, dict):
        for k in ("allowed_subjects", "allowed_artifacts", "allowed_usernames", "allowed_users"):
            if k in metadata and isinstance(metadata[k], (list, tuple, set)):
                for s in metadata[k]:
                    clean_s = str(s).strip().lower()
                    if clean_s:
                        allowed.add(clean_s)

    if isinstance(query_restrictions, dict):
        for k in ("allowed_subjects", "allowed_artifacts", "allowed_usernames", "allowed_users"):
            if k in query_restrictions and isinstance(query_restrictions[k], (list, tuple, set)):
                for s in query_restrictions[k]:
                    clean_s = str(s).strip().lower()
                    if clean_s:
                        allowed.add(clean_s)

    return allowed


def is_text_subject_in_scope(text_subject: str, scope: Any) -> bool:
    """Validate if a search subject or text query is authorized under scope.

    Fails closed on:
    - empty / non-string subject
    - substring matches (e.g. 'evil-target.com', 'nottarget.com', 'attacker-target.com')
    - domain suffix lookalikes (e.g. 'target.com.evil.com')
    - arbitrary substring inclusions
    """
    if not text_subject or not isinstance(text_subject, str):
        return False

    clean_subject = text_subject.strip().lower().rstrip(".")
    if not clean_subject:
        return False

    # If input is URL-like, parse and extract hostname for canonical scope evaluation
    if clean_subject.startswith("https://") or clean_subject.startswith("http://"):
        try:
            parsed = urllib.parse.urlparse(clean_subject)
            host = (parsed.hostname or "").strip().lower().rstrip(".")
            if not host:
                return False
            clean_subject = host
        except Exception:
            return False

    allowed_subjects = extract_allowed_subjects(scope)
    if not allowed_subjects:
        return False

    for allowed in allowed_subjects:
        clean_allowed = allowed.strip().lower().rstrip(".")
        if clean_subject == clean_allowed:
            return True
        # Allow legitimate subdomains if the allowed subject is a domain
        if clean_subject.endswith("." + clean_allowed):
            return True

    return False
