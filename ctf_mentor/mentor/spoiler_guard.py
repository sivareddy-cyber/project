"""
SpoilerGuard deterministic rule-based safety inspector.

LOCKED ARCHITECTURE INVARIANTS:
1. Two-layer protection: Retrieval-time (Layer 1) & Generation-time (Layer 2).
2. Deterministic rule-based inspection (NO second LLM as spoiler guard).
3. If candidate fails: rejected candidate text is NEVER displayed to user.
4. Returns safe generic mentor response on rejection and audits the violation.
"""

from __future__ import annotations

import re
from typing import List, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.mentor.contracts import HintCandidate, SpoilerGuardResult
from ctf_mentor.mentor.structured_output import parse_and_validate_structured_hint


class SpoilerGuard:
    """Deterministic rule-based Spoiler Guard for inspecting HintCandidates."""

    def __init__(self, custom_secret_patterns: Optional[List[str]] = None) -> None:
        self.flag_regexes = [
            re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
            re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
            re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
            re.compile(r"secret\{[^}]+\}", re.IGNORECASE),
        ]
        self.credential_patterns = [
            "password=",
            "admin:admin",
            "root:root",
            "admin:pass",
        ]
        self.forbidden_payload_patterns = [
            "curl ",
            "nc -e",
            "/bin/sh",
            "python -c",
            "rm -rf",
            "UNION SELECT",
            "OR 1=1",
            "DROP TABLE",
        ]
        self.custom_secret_patterns = custom_secret_patterns or []

    def inspect_candidate(self, candidate: HintCandidate) -> SpoilerGuardResult:
        """Inspect HintCandidate text for spoilers, flags, credentials, or forbidden payloads."""
        content = candidate.raw_content
        detected_patterns: List[str] = []

        # 0. Deterministic Schema Validation for L3-L5 (Defense-In-Depth Boundary)
        level = candidate.requested_level.value
        rendered_safe_text: Optional[str] = None

        if 3 <= level <= 5:
            schema_res = parse_and_validate_structured_hint(content, candidate.requested_level)
            if not schema_res.is_valid:
                detected_patterns.append("structured_schema_invalid")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="structured_schema_invalid",
                    safe_content="Focus your investigation on observing system inputs and collecting evidence.",
                    rejection_reason=f"Structured schema validation failed for L{level}: {schema_res.error_message}",
                    detected_patterns=detected_patterns,
                )
            rendered_safe_text = schema_res.rendered_text

        # 1. Check flag patterns
        for regex in self.flag_regexes:
            if regex.search(content):
                detected_patterns.append("flag_pattern")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="flag_pattern",
                    safe_content="Focus on investigating the input parameter handling and application response codes.",
                    rejection_reason="Candidate text contained a flag pattern.",
                    detected_patterns=detected_patterns,
                )

        # 2. Check custom secret patterns
        for secret in self.custom_secret_patterns:
            if secret and secret.lower() in content.lower():
                detected_patterns.append("custom_secret_match")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="custom_secret_match",
                    safe_content="Observe the application behavior carefully and analyze parameter inputs.",
                    rejection_reason="Candidate text contained a secret challenge solution pattern.",
                    detected_patterns=detected_patterns,
                )

        # 3. Check credentials
        for cred in self.credential_patterns:
            if cred.lower() in content.lower():
                detected_patterns.append("credential_pattern")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="credential_pattern",
                    safe_content="Analyze authentication mechanisms and HTTP response headers.",
                    rejection_reason="Candidate text contained credential disclosure.",
                    detected_patterns=detected_patterns,
                )

        # 4. Check forbidden payload/command patterns (applicable below L6)
        if level < 6:
            for pat in self.forbidden_payload_patterns:
                if pat.lower() in content.lower():
                    detected_patterns.append("forbidden_payload_command")
                    return SpoilerGuardResult(
                        is_spoiler=True,
                        violation_type="forbidden_payload_command",
                        safe_content="Consider how parameter values are sanitized by the server.",
                        rejection_reason=f"Candidate text contained forbidden command/payload pattern {pat!r}.",
                        detected_patterns=detected_patterns,
                    )

        # 5. Deterministic Structural & Paraphrased Checks by Level
        if level < 6:
            if self._has_flag_extraction_instructions(content):
                detected_patterns.append("flag_extraction_instructions")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="flag_extraction_forbidden_below_l6",
                    safe_content="Investigate the vulnerability mechanics rather than looking for flag extraction steps.",
                    rejection_reason=f"Level L{level} hint contained flag extraction instructions which are forbidden below L6.",
                    detected_patterns=detected_patterns,
                )

            if self._has_complete_walkthrough(content):
                detected_patterns.append("complete_walkthrough")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="walkthrough_forbidden_below_l6",
                    safe_content="Focus on applying general testing methodology for this vulnerability class.",
                    rejection_reason=f"Level L{level} hint contained complete walkthrough content which is only permitted at L6.",
                    detected_patterns=detected_patterns,
                )

            if self._has_paraphrased_exploit_instructions(content):
                detected_patterns.append("paraphrased_exploit_detected")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="paraphrased_exploit_detected",
                    safe_content="Analyze system behavior and collect evidence regarding input processing.",
                    rejection_reason=f"Level L{level} hint contained paraphrased exploit/solution instructions.",
                    detected_patterns=detected_patterns,
                )

        if level <= 2:
            if "payload" in content.lower() or "exploit" in content.lower() or self._has_command_or_script_patterns(content):
                detected_patterns.append("level_detail_exceeded")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="level_detail_exceeded",
                    safe_content="Reflect on the parameter structure and HTTP status codes.",
                    rejection_reason=f"Level L{level} hint contained excessive exploit detail.",
                    detected_patterns=detected_patterns,
                )

        elif level == 3:
            # L3: Allow conceptual technique guidance.
            # Reject actionable exploit instructions, exact payloads, commands, scripts, credentials, or complete attack sequences.
            if (
                self._has_command_or_script_patterns(content)
                or self._has_actionable_payload_or_exploit_instructions(content)
                or self._has_actionable_exploit_instructions(content)
                or self._has_step_by_step_attack_instructions(content)
            ):
                detected_patterns.append("level_3_actionable_exploit_or_command")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="level_detail_exceeded",
                    safe_content="Identify the general vulnerability class relevant to this behavior.",
                    rejection_reason="Level L3 hint contained actionable exploit instructions, command sequences, or attack steps.",
                    detected_patterns=detected_patterns,
                )

        elif level == 4:
            # L4: Allow a narrowed investigation strategy.
            # Reject copy-paste payloads, exact exploit requests, command sequences, and step-by-step attack instructions.
            if (
                self._has_command_or_script_patterns(content)
                or self._has_actionable_payload_or_exploit_instructions(content)
                or self._has_step_by_step_attack_instructions(content)
            ):
                detected_patterns.append("level_4_payload_or_attack_sequence")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="level_detail_exceeded",
                    safe_content="Focus your investigation on analyzing component behavior.",
                    rejection_reason="Level L4 hint contained copy-paste payloads, command sequences, or step-by-step attack instructions.",
                    detected_patterns=detected_patterns,
                )

        elif level == 5:
            # L5: Allow detailed vulnerability mechanics and what evidence to inspect.
            # Reject a complete reproducible exploit/solution walkthrough or step-by-step attack sequence.
            if self._has_step_by_step_attack_instructions(content) or self._has_complete_walkthrough(content):
                detected_patterns.append("level_5_complete_walkthrough_or_step_sequence")
                return SpoilerGuardResult(
                    is_spoiler=True,
                    violation_type="level_detail_exceeded",
                    safe_content="Follow detailed testing methodology for the target component.",
                    rejection_reason="Level L5 hint contained a complete reproducible walkthrough or step-by-step attack sequence.",
                    detected_patterns=detected_patterns,
                )

        # Clean PASS
        final_content = rendered_safe_text if rendered_safe_text is not None else candidate.raw_content
        return SpoilerGuardResult(
            is_spoiler=False,
            violation_type=None,
            safe_content=final_content,
            rejection_reason="",
            detected_patterns=[],
        )

    def _has_flag_extraction_instructions(self, content: str) -> bool:
        """Detect instructions for extracting/obtaining the flag."""
        patterns = [
            r"\b(extract|obtain|print|read|cat|select|grab|retrieve|get|steal|fetch|dump|output)\b.{0,50}\b(flag|ctf|secret)\b",
            r"\bto\s+(get|obtain|extract|read|print|retrieve|find|dump)\s+(the\s+)?(flag|ctf|secret)\b",
            r"\b(flag\.txt|/flag|get_flag|flag_field)\b",
        ]
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _has_command_or_script_patterns(self, content: str) -> bool:
        """Detect executable shell commands, scripts, code blocks, or piping."""
        if re.search(r"```[\s\S]*?```", content):
            return True
        if re.search(r"`[^`]*(curl|nc|python|bash|sh|cat|ls|chmod|sqlmap|nmap|gdb|eval|exec|system|import)[^`]*`", content, re.IGNORECASE):
            return True
        if re.search(r"^\s*(\$|#|>)\s+\S+", content, re.MULTILINE):
            return True
        if re.search(r"\b(curl|nc|nmap|sqlmap|wget|cat|grep|chmod|chown)\b", content, re.IGNORECASE):
            return True
        if re.search(r"\b(python|bash|sh|perl|powershell)\s+(-c|--script|\S+\.py|\S+\.sh|\S+)\b", content, re.IGNORECASE):
            return True
        return False

    def _has_actionable_payload_or_exploit_instructions(self, content: str) -> bool:
        """Detect copy-paste payloads, injection strings, or payload submission commands."""
        if re.search(r"['\"`]\s*(OR|AND)\s+['\"`]?\d+['\"`]?\s*=\s*['\"`]?\d+['\"`]", content, re.IGNORECASE):
            return True
        if re.search(r"['\"`]\s*;\s*(DROP|SELECT|INSERT|UPDATE|DELETE|UNION|EXEC)\b", content, re.IGNORECASE):
            return True
        if re.search(r"['\"`]\s*(UNION\s+ALL\s+SELECT|UNION\s+SELECT)\b", content, re.IGNORECASE):
            return True
        if re.search(r"<script.*?>.*?</script>", content, re.IGNORECASE):
            return True
        if re.search(r"['\"`]?(\.\./|\.\.\\){2,}", content):
            return True
        if re.search(r"\b(inject|submit|send|type|use|enter)\b.{0,30}\b(payload|exploit string|malicious input|attack vector)\b", content, re.IGNORECASE):
            return True
        if re.search(r"\b(exact|solution)\s+payload\b", content, re.IGNORECASE):
            return True
        return False

    def _has_actionable_exploit_instructions(self, content: str) -> bool:
        """Detect actionable exploit instructions directing specific attack steps."""
        if re.search(r"\b(send|submit|post|craft|issue|transmit)\b.{0,40}\b(request|header|cookie|parameter|body|payload)\b.{0,40}\b(to|with)\b.{0,40}\b(bypass|exploit|crash|trigger|gain|access|escalate|dump)\b", content, re.IGNORECASE | re.DOTALL):
            return True
        if re.search(r"\b(bypass|exploit|overwrite|hijack|escalate)\b.{0,40}\b(by|using|via)\b.{0,40}\b(sending|submitting|crafting|modifying|injecting)\b", content, re.IGNORECASE | re.DOTALL):
            return True
        return False

    def _has_step_by_step_attack_instructions(self, content: str) -> bool:
        """Detect step-by-step numbered/bulleted attack instructions."""
        step_matches = re.findall(
            r"(?:^|\.|\s)\s*(\d+[\.\)]|step\s*\d+|first,?|second,?|third,?|finally,?)\s+.*?\b(inject|send|submit|enter|run|execute|extract|read|bypass|exploit|navigate|fetch|cat|curl|python)\b",
            content,
            re.IGNORECASE,
        )
        if len(step_matches) >= 2:
            return True
        if re.search(r"\b(follow these steps|step-by-step (attack|exploit|procedure|sequence))\b", content, re.IGNORECASE):
            return True
        return False

    def _has_complete_walkthrough(self, content: str) -> bool:
        """Detect complete solution walkthrough content."""
        if re.search(r"\b(complete|full|total|entire|end-to-end)\s+(walkthrough|solution|exploit|guide|attack sequence|procedure)\b", content, re.IGNORECASE):
            return True
        if re.search(r"\b(here is|below is|following is)\s+the\s+(complete|full|exact|step-by-step)\s+(solution|exploit|walkthrough)\b", content, re.IGNORECASE):
            return True
        return False

    def _has_paraphrased_exploit_instructions(self, content: str) -> bool:
        """Detect paraphrased exploit instructions for IDOR, SQLi, Auth Bypass, XSS, Command Execution, SSRF."""
        content_lower = content.lower()

        # 1. Paraphrased IDOR
        if re.search(r"\b(change|modify|increment|decrement|alter|replace|iterate|swap|adjust)\b.{0,80}\b(numeric|id|user_id|account_id|identifier|cookie|parameter|number|digit)\b", content_lower) and \
           re.search(r"\b(view|access|see|read|other|another|victim|admin|private|account|profile)\b", content_lower):
            return True

        # 2. Paraphrased SQLi
        if re.search(r"\b(append|concat|insert|add|join|combine|include)\b.{0,80}\b(single quote|quote|boolean|always true|or condition|union|clause|expression)\b", content_lower) and \
           re.search(r"\b(bypass|force|all records|dump|extract|filter|login)\b", content_lower):
            return True

        # 3. Paraphrased Auth Bypass
        if re.search(r"\b(modify|change|alter|override|replace|swap|set)\b.{0,80}\b(jwt|token|role|admin|claim|header|cookie|flag|privilege)\b", content_lower) and \
           re.search(r"\b(gain|get|grant|admin|unauthorized|access|privilege)\b", content_lower):
            return True

        # 4. Paraphrased XSS
        if re.search(r"\b(embed|insert|inject|append|add)\b.{0,80}\b(html|script|onload|onerror|element|tag|handler|svg)\b", content_lower) and \
           re.search(r"\b(execute|run|victim|browser|session|javascript|code)\b", content_lower):
            return True

        # 5. Paraphrased Command Execution
        if re.search(r"\b(append|pipe|add|use|chain|execute)\b.{0,80}\b(pipe|semicolon|backtick|subshell|system command|shell command|binary)\b", content_lower) and \
           re.search(r"\b(execute|run|host|server|system|os|code)\b", content_lower):
            return True

        # 6. Paraphrased SSRF
        if re.search(r"\b(direct|point|send|fetch|request)\b.{0,80}\b(parameter|url|address|uri|host)\b", content_lower) and \
           re.search(r"\b(localhost|127\.0\.0\.1|internal|metadata|cloud metadata|169\.254)\b", content_lower):
            return True

        return False
