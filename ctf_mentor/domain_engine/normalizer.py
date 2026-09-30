"""
Web/API ResultNormalizer for Phase 7 Domain Investigation Engine.

LOCKED INVARIANTS:
1. Untrusted raw output is normalized deterministically.
2. System NEVER fabricates content (is_fabricated = False).
3. Preserves provenance tag: source_provenance = "action_result_derived".
4. Requires EXPLICIT human confirmation before canonical Phase 5D write.
5. Uses existing ALLOWED_ENTITY_TYPES ("evidence").
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ctf_mentor.domain.investigation_models import ConcreteInvestigationResult, InvestigationStep
from ctf_mentor.intelligence.evidence_handlers import SubmitEvidenceHandler
from ctf_mentor.investigation.normalizer import EvidenceNormalizer, NormalizedEvidenceDraft
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

logger = logging.getLogger(__name__)


class WebApiResultNormalizer:
    """Normalizes Web/API InvestigationResult instances into structured evidence drafts."""

    @staticmethod
    def normalize_result(
        result: ConcreteInvestigationResult,
        step: InvestigationStep,
    ) -> NormalizedEvidenceDraft:
        """Deterministically extract status codes and header observations from raw output."""
        if not result or not step:
            raise ValueError("Result and step must not be None")

        if result.challenge_id != step.challenge_id:
            raise ValueError(
                f"Cross-challenge result normalization rejected: result '{result.challenge_id}' != step '{step.challenge_id}'"
            )

        proposal_id = step.proposal_ref or f"prop_{step.step_id}"

        # Delegate deterministic status code and snippet parsing to EvidenceNormalizer
        draft = EvidenceNormalizer.normalize_action_result(
            raw_output=result.raw_output,
            challenge_id=result.challenge_id,
            proposal_id=proposal_id,
            result_id=result.result_id,
            hypothesis_id=None,
        )

        # Attach domain engine metadata provenance
        draft.metadata.update(
            {
                "domain_id": "web_api",
                "step_id": step.step_id,
                "step_type": step.step_type,
                "source_provenance": "action_result_derived",
                "is_fabricated": False,
            }
        )

        return draft

    @staticmethod
    async def confirm_and_submit_to_canonical_5d(
        draft: NormalizedEvidenceDraft,
        context: TaskContext,
        submit_handler: Optional[SubmitEvidenceHandler] = None,
    ) -> HandlerResult:
        """Confirm evidence draft (is_confirmed=True) and submit to canonical Phase 5D via SubmitEvidenceHandler."""
        if not draft.is_confirmed:
            return HandlerResult(
                success=False,
                error_message="Human confirmation is required before normalized evidence can be written to canonical Phase 5D state.",
            )

        return await EvidenceNormalizer.confirm_and_submit_to_phase5d(
            draft=draft,
            context=context,
            submit_handler=submit_handler,
        )
