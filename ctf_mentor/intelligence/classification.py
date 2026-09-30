"""
Deterministic Challenge Classification for CTF Mentor/Copilot Phase 5D.

Zero LLM dependency.
Uses a versioned, extensible, deterministic ruleset.
Same input + same ruleset version = same classification output.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from ctf_mentor.contracts import EntityWrite
from ctf_mentor.domain.models import ChallengeClassification
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

RULESET_VERSION = "1.0"

TAXONOMY_CATEGORIES = [
    "WEB",
    "API",
    "AUTHENTICATION",
    "SESSION",
    "IDOR",
    "INJECTION",
    "SSRF",
    "CLIENT_SIDE",
    "BUSINESS_LOGIC",
    "INFORMATION_DISCLOSURE",
    "GRAPHQL",
    "FILE_HANDLING",
]

# Deterministic keyword rules: (category, keyword, weight)
RULE_PATTERNS = [
    ("INJECTION", "sqli", 0.4),
    ("INJECTION", "sql injection", 0.5),
    ("INJECTION", "command injection", 0.5),
    ("INJECTION", "rce", 0.4),
    ("SSRF", "ssrf", 0.5),
    ("SSRF", "server side request forgery", 0.5),
    ("IDOR", "idor", 0.5),
    ("IDOR", "insecure direct object", 0.5),
    ("GRAPHQL", "graphql", 0.5),
    ("GRAPHQL", "query", 0.2),
    ("AUTHENTICATION", "auth", 0.3),
    ("AUTHENTICATION", "login", 0.3),
    ("AUTHENTICATION", "jwt", 0.4),
    ("SESSION", "cookie", 0.3),
    ("SESSION", "session", 0.3),
    ("FILE_HANDLING", "upload", 0.4),
    ("FILE_HANDLING", "lfi", 0.4),
    ("FILE_HANDLING", "rfi", 0.4),
    ("CLIENT_SIDE", "xss", 0.4),
    ("CLIENT_SIDE", "csrf", 0.4),
    ("INFORMATION_DISCLOSURE", "git", 0.3),
    ("INFORMATION_DISCLOSURE", "leak", 0.3),
    ("API", "api", 0.3),
    ("API", "rest", 0.3),
    ("WEB", "http", 0.2),
    ("WEB", "web", 0.2),
]


def classify_challenge_deterministic(
    challenge_id: str,
    name: str = "",
    description: str = "",
    tags: List[Any] = None,
    parameters: Dict[str, Any] = None,
) -> ChallengeClassification:
    """Classify a challenge using the deterministic ruleset v1.0 with multi-label support and word boundary matching."""
    safe_tags = []
    if tags:
        for t in tags:
            if isinstance(t, str):
                safe_tags.append(t)
            elif t is not None and isinstance(t, (int, float, bool)):
                safe_tags.append(str(t))

    parameters = parameters or {}
    safe_name = str(name) if name is not None else ""
    safe_desc = str(description) if description is not None else ""

    text_to_scan = f"{safe_name} {safe_desc} {' '.join(safe_tags)} {str(parameters)}".lower()

    signals: List[str] = []
    category_scores: Dict[str, float] = {cat: 0.0 for cat in TAXONOMY_CATEGORIES}

    # Match rules using regex word boundaries to prevent substring false positives (e.g. 'rce' in 'resource')
    for cat, keyword, weight in RULE_PATTERNS:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if re.search(pattern, text_to_scan, re.IGNORECASE):
            category_scores[cat] += weight
            signals.append(f"matched_rule:{cat}:{keyword}")

    # Collect matched categories (> 0.0 score) sorted by score desc, then name asc
    matched_cats = [cat for cat, score in category_scores.items() if score > 0.0]
    matched_cats.sort(key=lambda c: (-category_scores[c], c))

    if not matched_cats:
        matched_cats = ["WEB"]

    for cat in matched_cats:
        signals.append(f"matched_category:{cat}")

    category_str = matched_cats[0]
    max_score = category_scores[matched_cats[0]]

    # Base confidence calculation
    confidence = min(1.0, max(0.2, 0.3 + max_score))

    now = datetime.now(timezone.utc)
    classification_id = str(uuid.uuid4())

    return ChallengeClassification(
        classification_id=classification_id,
        challenge_id=challenge_id,
        category=category_str,
        confidence=confidence,
        signals=signals if signals else ["default_fallback_rule"],
        ruleset_version=RULESET_VERSION,
        created_at=now,
    )



class ClassifyChallengeHandler(TaskHandler):
    """Handler for classifying a CTF challenge."""

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        name = params.get("name", "")
        description = params.get("description", "")
        tags = params.get("tags", [])

        classification = classify_challenge_deterministic(
            challenge_id=context.challenge_id,
            name=name,
            description=description,
            tags=tags,
            parameters=params,
        )

        ew = EntityWrite(
            entity_type="classification",
            operation="insert",
            entity_id=classification.classification_id,
            fields={
                "classification_id": classification.classification_id,
                "challenge_id": classification.challenge_id,
                "category": classification.category,
                "confidence": classification.confidence,
                "signals": classification.signals,
                "ruleset_version": classification.ruleset_version,
                "created_at": classification.created_at,
            },
        )

        return HandlerResult(
            success=True,
            output=classification,
            proposed_entity_writes=[ew],
        )
