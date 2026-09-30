"""
LLMGateway for Phase 5F Controlled LLM Mentor.

LOCKED ARCHITECTURE INVARIANTS:
1. TEXT INPUT -> TEXT OUTPUT ONLY.
2. Absolutely NO function calling, tool calling, shell, filesystem, browser, Burp, scanning, or target interaction.
3. Network access is completely isolated inside LLMGateway.
4. Returns HintCandidate (ALWAYS untrusted text).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.mentor.contracts import HintCandidate, PromptContext


class LLMGateway:
    """Isolated gateway for text generation from LLMs."""

    def __init__(
        self,
        model_id: str = "ctf-mentor-v1",
        custom_provider: Optional[Callable[[str], str]] = None,
    ) -> None:
        self.model_id = model_id
        self._custom_provider = custom_provider

    async def generate_hint_candidate(
        self,
        request_id: str,
        challenge_id: str,
        requested_level: HintLevel,
        prompt_ctx: PromptContext,
    ) -> HintCandidate:
        """Generate an untrusted HintCandidate text from LLM prompt context."""
        full_prompt = prompt_ctx.format_full_prompt()

        if self._custom_provider:
            raw_text = self._custom_provider(full_prompt)
        else:
            # Default deterministic mock provider for isolated runtime execution
            raw_text = self._default_mock_generator(requested_level, prompt_ctx)

        candidate_id = f"cand_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc)

        return HintCandidate(
            candidate_id=candidate_id,
            request_id=request_id,
            challenge_id=challenge_id,
            requested_level=requested_level,
            effective_level=requested_level,
            raw_content=raw_text,
            rationale=f"Generated via model {self.model_id}",
            model_id=self.model_id,
            prompt_hash=prompt_ctx.context_hash,
            created_at=now_utc,
        )

    def _default_mock_generator(self, level: HintLevel, prompt_ctx: PromptContext) -> str:
        """Generate safe deterministic default mentor text based on hint level."""
        import json

        level_val = level.value
        if level_val == 0:
            return "Reflect on what user input parameter is passed to the application request."
        elif level_val == 1:
            return "Consider the concept of input sanitization and how special characters might alter control flow."
        elif level_val == 2:
            return "Observe the target HTTP response headers and status codes when sending single quote parameters."
        elif level_val == 3:
            return json.dumps({
                "concept_id": "concept.input_sanitization",
                "observation_type": "obs.parameter_handling",
                "evidence_type": "ev.http_request",
                "question_type": "q.sanitization_check",
            })
        elif level_val == 4:
            return json.dumps({
                "technique_id": "tech.input_validation",
                "observation_target": "target.query_param",
                "evidence_type": "ev.http_response",
                "discriminator_type": "disc.status_code_comparison",
                "next_check_type": "check.observe_status",
            })
        elif level_val == 5:
            return json.dumps({
                "vulnerability_class": "vuln.input_injection",
                "mechanism_type": "mech.unhandled_special_char",
                "evidence_interpretation_type": "interp.unparsed_input",
                "discriminator_type": "disc.status_code_comparison",
                "safe_next_check_type": "check.code_pattern_audit",
                "risk_explanation_type": "risk.control_flow_alteration",
            })
        elif level_val == 6:
            return "Full walkthrough: Submit SQL injection payload to extract flag table column content."
        return "Observe the application behavior carefully."
