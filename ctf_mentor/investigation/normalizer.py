"""
Evidence Normalizer for Phase 6 Human-Guided Controlled Investigation Layer.

LOCKED SECURITY INVARIANTS:
1. Untrusted user-submitted ActionResult output is normalized deterministically.
2. System NEVER fabricates observations.
3. Normalized evidence requires EXPLICIT HUMAN CONFIRMATION before canonical Phase 5D persistence.
4. Preserves provenance tag: source_provenance = "action_result_derived".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ctf_mentor.domain.models import EvidencePriority
from ctf_mentor.intelligence.evidence_handlers import SubmitEvidenceHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


@dataclass
class NormalizedEvidenceDraft:
    """Draft normalized evidence awaiting human confirmation."""

    challenge_id: str
    proposal_id: str
    result_id: str
    summary_content: str
    raw_snippet: str
    hypothesis_id: Optional[str] = None
    extracted_status_code: Optional[int] = None
    extracted_headers: Dict[str, str] = field(default_factory=dict)
    is_confirmed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceNormalizer:
    """Normalizes untrusted ActionResult raw output into structured evidence drafts."""

    @staticmethod
    def normalize_action_result(
        raw_output: str,
        challenge_id: str,
        proposal_id: str,
        result_id: str,
        hypothesis_id: Optional[str] = None,
    ) -> NormalizedEvidenceDraft:
        """Deterministically extract status codes and key header observations from raw output."""
        clean_output = raw_output.strip()

        # Extract HTTP status code if present (e.g., "HTTP/1.1 200 OK" or "Status: 404")
        status_match = re.search(r"HTTP/\d\.\d\s+(\d{3})", clean_output, re.IGNORECASE)
        status_code = int(status_match.group(1)) if status_match else None

        snippet = clean_output[:500]
        if status_code:
            summary = f"Observed HTTP status code {status_code} in action result output."
        else:
            summary = f"Observed action result output snippet: {snippet[:150]}..."

        meta = {
            "source_provenance": "action_result_derived",
            "proposal_id": proposal_id,
            "result_id": result_id,
        }

        return NormalizedEvidenceDraft(
            challenge_id=challenge_id,
            proposal_id=proposal_id,
            result_id=result_id,
            summary_content=summary,
            raw_snippet=snippet,
            hypothesis_id=hypothesis_id,
            extracted_status_code=status_code,
            is_confirmed=False,
            metadata=meta,
        )

    @staticmethod
    async def confirm_and_submit_to_phase5d(
        draft: NormalizedEvidenceDraft,
        context: TaskContext,
        submit_handler: Optional[SubmitEvidenceHandler] = None,
        proposal_repo: Optional[Any] = None,
    ) -> HandlerResult:
        """Confirm draft normalized evidence and submit to canonical Phase 5D via SubmitEvidenceHandler."""
        if not draft.is_confirmed:
            return HandlerResult(
                success=False,
                error_message="Human confirmation is required before normalized evidence can be written to canonical Phase 5D state.",
            )

        handler = submit_handler or SubmitEvidenceHandler()

        meta = dict(draft.metadata)
        meta["source_provenance"] = "action_result_derived"
        meta["raw_snippet"] = draft.raw_snippet
        meta["proposal_id"] = draft.proposal_id
        meta["result_id"] = draft.result_id
        meta["idempotency_key"] = f"confirm_{draft.proposal_id}_{draft.result_id}"
        if draft.extracted_status_code:
            meta["status_code"] = draft.extracted_status_code

        # Build Phase 5D parameters from an explicit server-controlled allowlist.
        # Caller MUST NOT control relation, evidence_provenance, evidence_type, hypothesis_id, created_by, or content.
        ctx_params = {
            "content": draft.summary_content,
            "source": EvidencePriority.USER_CONFIRMED.value,
            "evidence_type": "action_result_derived",
            "relation": "supports",
            "hypothesis_id": draft.hypothesis_id,
            "created_by": "user_action_result",
            "is_fabricated": False,
            "metadata": meta,
        }

        confirmed_ctx = TaskContext(
            task_id=context.task_id,
            challenge_id=context.challenge_id,
            task_group_id=context.task_group_id,
            task_type="submit_evidence",
            parameters=ctx_params,
            blackboard_snapshot=context.blackboard_snapshot,
        )

        res = await handler.execute(confirmed_ctx)
        if res.success and proposal_repo and draft.proposal_id:
            proposal_repo.mark_proposal_consumed_atomic(draft.proposal_id, draft.challenge_id)

        return res

