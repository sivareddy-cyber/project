"""
Action Proposal Drafter & Strict Structural Parser for Phase 6.

LOCKED SECURITY INVARIANTS:
1. Action Proposal Drafter drafts ONE candidate action only (NO multi-step campaigns).
2. Raw LLM output is strictly validated against closed enum schemas.
3. Plain text, arrays, nulls, extra keys, wrong types, unknown action_types, and malicious executable prose are REJECTED (fail-closed).
4. Arbitrary shell commands, code execution strings, or unvalidated URLs are forbidden.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from ctf_mentor.domain.models import (
    ActionProposal,
    ActionProposalState,
    ActionProposalTarget,
    ActionProposalType,
    HintLevel,
)
from ctf_mentor.llm.gateway import LLMGateway
from ctf_mentor.mentor.contracts import PromptContext


REQUIRED_PROPOSAL_FIELDS: Set[str] = {
    "action_type",
    "target",
    "rationale",
}

REQUIRED_TARGET_FIELDS: Set[str] = {
    "scheme",
    "hostname",
    "port",
    "path",
}

FORBIDDEN_SHELL_PATTERNS = [
    r";\s*",
    r"\|\s*",
    r"&\s*",
    r"`",
    r"\$\(",
    r"\${",
    r">\s*",
    r"<\s*",
    r"\b(curl|nc|bash|sh|python|eval|exec|system|cmd|powershell)\b",
]


@dataclass
class ProposalParsingResult:
    is_valid: bool
    proposal: Optional[ActionProposal]
    error_message: str
    rejection_reason: str


def parse_and_validate_action_proposal(
    raw_text: str, challenge_id: str, request_id: Optional[str] = None
) -> ProposalParsingResult:
    """Parse and strictly validate raw LLM JSON text into a safe ActionProposal."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Raw proposal input must be a non-empty string.",
            rejection_reason="Proposal input was empty or non-string.",
        )

    stripped = raw_text.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Proposal must be a valid JSON object string.",
            rejection_reason="Proposal raw text was plain text prose instead of a JSON object.",
        )

    try:
        data = json.loads(stripped)
    except Exception as ex:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"JSON parsing failed for proposal: {ex}",
            rejection_reason=f"JSON parse error: {ex}",
        )

    if not isinstance(data, dict):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Proposal JSON must be an object/dict.",
            rejection_reason=f"Proposal JSON root was {type(data).__name__} instead of dict.",
        )

    # Required & Extra Fields Check
    keys_set = set(data.keys())
    # Optional fields allowed: hypothesis_id, metadata
    allowed_keys = REQUIRED_PROPOSAL_FIELDS | {"hypothesis_id", "metadata"}
    missing = REQUIRED_PROPOSAL_FIELDS - keys_set
    if missing:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Missing required proposal fields: {sorted(missing)}",
            rejection_reason=f"Missing required fields {sorted(missing)}",
        )

    extra = keys_set - allowed_keys
    if extra:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Forbidden extra proposal fields: {sorted(extra)}",
            rejection_reason=f"Contained forbidden extra fields {sorted(extra)}",
        )

    # 1. Action Type Validation
    action_type_str = data.get("action_type")
    if not isinstance(action_type_str, str):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="action_type must be a string.",
            rejection_reason="action_type was not a string.",
        )

    try:
        action_type = ActionProposalType(action_type_str.strip())
    except ValueError:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Invalid action_type {action_type_str!r}. Must be one of {[e.value for e in ActionProposalType]}",
            rejection_reason=f"Unknown action_type enum value {action_type_str!r}",
        )

    # 2. Target Validation
    target_data = data.get("target")
    if not isinstance(target_data, dict):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="target must be a JSON object.",
            rejection_reason="target was not a dict.",
        )

    target_keys = set(target_data.keys())
    allowed_target_keys = REQUIRED_TARGET_FIELDS | {"method", "headers", "query_params"}
    missing_target = REQUIRED_TARGET_FIELDS - target_keys
    if missing_target:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Missing required target fields: {sorted(missing_target)}",
            rejection_reason=f"Missing required target fields {sorted(missing_target)}",
        )

    extra_target = target_keys - allowed_target_keys
    if extra_target:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Forbidden extra target fields: {sorted(extra_target)}",
            rejection_reason=f"Contained forbidden extra target fields {sorted(extra_target)}",
        )

    scheme = str(target_data.get("scheme", "http")).strip().lower()
    hostname = str(target_data.get("hostname", "")).strip().lower()
    port = target_data.get("port")
    path = str(target_data.get("path", "/")).strip()
    method = str(target_data.get("method", "GET")).strip().upper()

    if scheme not in {"http", "https"}:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Invalid target scheme {scheme!r}. Must be http or https.",
            rejection_reason=f"Invalid target scheme {scheme!r}",
        )

    if not hostname or re.search(r"\s", hostname):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Target hostname must be non-empty and contain no spaces.",
            rejection_reason="Target hostname invalid",
        )

    if not isinstance(port, int) or port < 1 or port > 65535:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Target port must be an integer in 1-65535, got {port!r}.",
            rejection_reason=f"Target port invalid: {port!r}",
        )

    if not path.startswith("/"):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Target path must start with '/', got {path!r}.",
            rejection_reason="Target path must start with '/'",
        )

    # Percent-encoding unquoting path traversal check
    unquoted_path = path
    for _ in range(5):
        nxt = urllib.parse.unquote(unquoted_path)
        if nxt == unquoted_path:
            break
        unquoted_path = nxt

    unquoted_lower = unquoted_path.lower()
    if ".." in unquoted_path or "%2e" in unquoted_lower or "%2f" in unquoted_lower or "%5c" in unquoted_lower:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Path traversal ('..') is strictly forbidden in target path.",
            rejection_reason="Path traversal detected in target path",
        )

    # Shell pattern inspection across all string fields
    raw_blob = f"{hostname} {path} {data.get('rationale', '')}"
    for pat in FORBIDDEN_SHELL_PATTERNS:
        if re.search(pat, raw_blob, re.IGNORECASE):
            return ProposalParsingResult(
                is_valid=False,
                proposal=None,
                error_message=f"Forbidden shell execution pattern detected: {pat}",
                rejection_reason=f"Forbidden shell execution pattern detected: {pat}",
            )

    headers = target_data.get("headers", {})
    query_params = target_data.get("query_params", {})
    if not isinstance(headers, dict) or not isinstance(query_params, dict):
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="headers and query_params must be dicts.",
            rejection_reason="headers or query_params was not a dict.",
        )

    try:
        target_obj = ActionProposalTarget(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            method=method,
            headers={str(k): str(v) for k, v in headers.items()},
            query_params={str(k): str(v) for k, v in query_params.items()},
        )
    except Exception as ex:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message=f"Target construction failed: {ex}",
            rejection_reason=f"Target construction error: {ex}",
        )

    # 3. Rationale Validation
    rationale = str(data.get("rationale", "")).strip()
    if not rationale:
        return ProposalParsingResult(
            is_valid=False,
            proposal=None,
            error_message="Rationale must not be empty.",
            rejection_reason="Rationale was empty",
        )

    hypothesis_id = data.get("hypothesis_id")
    if hypothesis_id is not None:
        hypothesis_id = str(hypothesis_id).strip()

    proposal_id = f"prop_{uuid.uuid4().hex[:12]}"
    now_utc = datetime.now(timezone.utc)

    proposal = ActionProposal(
        proposal_id=proposal_id,
        challenge_id=challenge_id,
        request_id=request_id,
        action_type=action_type,
        target=target_obj,
        rationale=rationale,
        hypothesis_id=hypothesis_id,
        scope_version="1.0",
        status=ActionProposalState.DRAFT,
        created_at=now_utc,
    )

    return ProposalParsingResult(
        is_valid=True,
        proposal=proposal,
        error_message="",
        rejection_reason="",
    )


class ActionProposalDrafter:
    """Drafter component generating ONE structured candidate proposal using LLMGateway."""

    def __init__(self, llm_gateway: Optional[LLMGateway] = None) -> None:
        self.llm_gateway = llm_gateway or LLMGateway()

    async def draft_proposal(
        self,
        challenge_id: str,
        prompt_ctx: PromptContext,
        request_id: Optional[str] = None,
    ) -> ProposalParsingResult:
        """Draft a candidate action proposal using text-only LLMGateway."""
        req_id = request_id or f"req_{uuid.uuid4().hex[:12]}"
        candidate = await self.llm_gateway.generate_hint_candidate(
            request_id=req_id,
            challenge_id=challenge_id,
            requested_level=HintLevel.L2,
            prompt_ctx=prompt_ctx,
        )

        return parse_and_validate_action_proposal(candidate.raw_content, challenge_id, request_id=req_id)
