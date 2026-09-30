"""
Structured Mentor Output Contract, Strict Schema Validation, and Deterministic Safe Rendering for Phase 5F.

LOCKED ARCHITECTURE INVARIANTS:
1. L3-L5 outputs MUST be JSON objects whose values are approved restricted enum/token constants.
2. Unrestricted LLM solution prose is IMPOSSIBLE at L3-L5.
3. parse_and_validate_structured_hint accepts ONLY valid JSON dicts matching required keys and approved enum values.
4. Plain text, arrays, null, extra keys, wrong types, and unknown enum values are REJECTED (FAIL CLOSED).
5. User-visible text for L3-L5 is deterministically rendered from safe approved templates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional, Set

from ctf_mentor.domain.models import HintLevel

# ---------------------------------------------------------------------------
# Approved Enum Constrained Token Sets for L3, L4, L5
# ---------------------------------------------------------------------------

L3_CONCEPT_ENUMS: Set[str] = {
    "concept.input_sanitization",
    "concept.control_flow",
    "concept.access_control",
    "concept.parameter_handling",
    "concept.authentication",
    "concept.data_encoding",
    "concept.request_routing",
    "concept.session_management",
}

L3_OBSERVATION_ENUMS: Set[str] = {
    "obs.parameter_handling",
    "obs.status_codes",
    "obs.response_headers",
    "obs.error_messages",
    "obs.input_reflection",
    "obs.cookie_values",
}

L3_EVIDENCE_ENUMS: Set[str] = {
    "ev.http_request",
    "ev.http_response",
    "ev.user_input_flow",
    "ev.network_capture",
    "ev.status_code",
}

L3_QUESTION_ENUMS: Set[str] = {
    "q.sanitization_check",
    "q.boundary_analysis",
    "q.encoding_verification",
    "q.access_scope",
    "q.header_inspection",
}

L4_TECHNIQUE_ENUMS: Set[str] = {
    "tech.input_validation",
    "tech.parameter_parsing",
    "tech.cookie_handling",
    "tech.header_analysis",
    "tech.token_validation",
    "tech.path_traversal",
}

L4_TARGET_ENUMS: Set[str] = {
    "target.query_param",
    "target.body_field",
    "target.auth_header",
    "target.cookie_value",
    "target.uri_path",
}

L4_DISCRIMINATOR_ENUMS: Set[str] = {
    "disc.status_code_comparison",
    "disc.error_message_presence",
    "disc.reflection_syntax",
    "disc.header_presence",
}

L4_NEXT_CHECK_ENUMS: Set[str] = {
    "check.observe_status",
    "check.inspect_headers",
    "check.compare_types",
    "check.verify_boundary",
}

L5_VULN_CLASS_ENUMS: Set[str] = {
    "vuln.input_injection",
    "vuln.broken_access_control",
    "vuln.insecure_deserialization",
    "vuln.ssrf",
    "vuln.improper_authentication",
    "vuln.path_traversal",
}

L5_MECHANISM_ENUMS: Set[str] = {
    "mech.unhandled_special_char",
    "mech.unverified_type",
    "mech.unvalidated_redirect",
    "mech.missing_authorization",
    "mech.unsafe_deserialization",
}

L5_INTERPRETATION_ENUMS: Set[str] = {
    "interp.unparsed_input",
    "interp.type_mismatch",
    "interp.missing_check",
    "interp.unexpected_status",
}

L5_NEXT_CHECK_ENUMS: Set[str] = {
    "check.code_pattern_audit",
    "check.ast_parsing_review",
    "check.evidence_cross_reference",
    "check.boundary_testing",
}

L5_RISK_ENUMS: Set[str] = {
    "risk.control_flow_alteration",
    "risk.unauthorized_read",
    "risk.state_mutation",
    "risk.privilege_escalation",
}

L3_REQUIRED_FIELDS: Set[str] = {
    "concept_id",
    "observation_type",
    "evidence_type",
    "question_type",
}

L4_REQUIRED_FIELDS: Set[str] = {
    "technique_id",
    "observation_target",
    "evidence_type",
    "discriminator_type",
    "next_check_type",
}

L5_REQUIRED_FIELDS: Set[str] = {
    "vulnerability_class",
    "mechanism_type",
    "evidence_interpretation_type",
    "discriminator_type",
    "safe_next_check_type",
    "risk_explanation_type",
}


@dataclass
class StructuredValidationResult:
    is_valid: bool
    hint_level: HintLevel
    parsed_data: Optional[Dict[str, str]]
    rendered_text: str
    error_message: str
    rejection_reason: str


# ---------------------------------------------------------------------------
# Approved Safe Template Descriptions for Deterministic Rendering
# ---------------------------------------------------------------------------

ENUM_DESCRIPTIONS: Dict[str, str] = {
    # L3 Concepts
    "concept.input_sanitization": "Input sanitization and parameter escaping mechanisms in web applications",
    "concept.control_flow": "Application control flow and request routing behavior",
    "concept.access_control": "Access control boundaries and authorization checks",
    "concept.parameter_handling": "Parameter parsing and HTTP request processing",
    "concept.authentication": "Identity verification and session token handling",
    "concept.data_encoding": "Data encoding, decoding, and representation formats",
    "concept.request_routing": "URL routing and request parameter dispatching",
    "concept.session_management": "Session state persistence and cookie validation",
    # Observations
    "obs.parameter_handling": "Inspect how parameter values are accepted and parsed by the server",
    "obs.status_codes": "Observe HTTP status code responses across varied inputs",
    "obs.response_headers": "Analyze HTTP response header disclosures",
    "obs.error_messages": "Inspect detailed application error messages or stack traces",
    "obs.input_reflection": "Observe whether user input is reflected in response bodies",
    "obs.cookie_values": "Examine session cookie structures and parameters",
    # Evidence Types
    "ev.http_request": "HTTP request structures and parameter payloads",
    "ev.http_response": "HTTP response status, headers, and body content",
    "ev.user_input_flow": "User input data flow through system boundaries",
    "ev.network_capture": "Recorded network traffic logs",
    "ev.status_code": "Returned HTTP status code values",
    # Questions
    "q.sanitization_check": "How does the backend validate or sanitize input before processing?",
    "q.boundary_analysis": "What input boundary checks exist on parameter lengths and types?",
    "q.encoding_verification": "Is user input decoded or transformed prior to internal handling?",
    "q.access_scope": "Does the request execute within the authorized user session scope?",
    "q.header_inspection": "Are security headers present to restrict browser execution?",
    # L4 Techniques
    "tech.input_validation": "Analyze input validation routines for parameter processing",
    "tech.parameter_parsing": "Investigate HTTP parameter parsing and boundary checks",
    "tech.cookie_handling": "Examine cookie parsing and session token handling",
    "tech.header_analysis": "Inspect HTTP request headers and authorization metadata",
    "tech.token_validation": "Analyze token signature verification and claim parsing",
    "tech.path_traversal": "Investigate file path parameter processing and normalization",
    # L4 Targets
    "target.query_param": "URL query parameters in the request URI",
    "target.body_field": "POST body parameters or JSON request payload fields",
    "target.auth_header": "Authorization headers (e.g. Bearer token or custom headers)",
    "target.cookie_value": "HTTP Cookie header values and session identifiers",
    "target.uri_path": "URI path segments and routing parameters",
    # Discriminators
    "disc.status_code_comparison": "Compare HTTP status codes returned for valid vs invalid inputs",
    "disc.error_message_presence": "Check whether detailed error responses appear",
    "disc.reflection_syntax": "Check if special characters appear unmodified in output",
    "disc.header_presence": "Compare response headers returned across different request types",
    # Next Checks
    "check.observe_status": "Perform safe request checks to observe HTTP status code changes",
    "check.inspect_headers": "Inspect HTTP response headers for structural disclosures",
    "check.compare_types": "Compare application behavior when supplying different parameter data types",
    "check.verify_boundary": "Test input boundaries with standard alphanumeric parameter values",
    # L5 Vuln Classes
    "vuln.input_injection": "Input injection vulnerability class in parameter processing",
    "vuln.broken_access_control": "Broken access control flaw in authorization checks",
    "vuln.insecure_deserialization": "Insecure object deserialization in session processing",
    "vuln.ssrf": "Server-side request forgery flaw in URL parameter handling",
    "vuln.improper_authentication": "Improper authentication flaw in token validation",
    "vuln.path_traversal": "Path traversal flaw in file handling",
    # Mechanisms
    "mech.unhandled_special_char": "Unsanitized special characters altering query context",
    "mech.unverified_type": "Unverified input data type passed to internal interpreter",
    "mech.unvalidated_redirect": "Unvalidated URL destination parameter in HTTP request",
    "mech.missing_authorization": "Missing access control check on requested resource ID",
    "mech.unsafe_deserialization": "Object deserialization executed without class filtering",
    # Interpretations
    "interp.unparsed_input": "Evidence indicates parameter input is processed directly without filtering",
    "interp.type_mismatch": "Evidence shows parameter data type mismatch produces internal exceptions",
    "interp.missing_check": "Evidence indicates authorization checks are omitted for user-supplied IDs",
    "interp.unexpected_status": "Evidence shows unexpected status codes indicate unhandled execution paths",
    # L5 Next Checks
    "check.code_pattern_audit": "Audit source code for parameter processing function calls",
    "check.ast_parsing_review": "Review AST parsing rules and boundary sanitization functions",
    "check.evidence_cross_reference": "Cross-reference collected evidence items against known vulnerability indicators",
    "check.boundary_testing": "Review data flow from request entry points to internal functions",
    # Risks
    "risk.control_flow_alteration": "Unintended control flow alteration in backend logic",
    "risk.unauthorized_read": "Unauthorized disclosure of internal application data",
    "risk.state_mutation": "Unauthorized state mutation or parameter manipulation",
    "risk.privilege_escalation": "Potential privilege escalation across access control boundaries",
}


class DeterministicSafeRenderer:
    """Deterministically renders validated structured schema enums into safe educational text."""

    @staticmethod
    def render(level: HintLevel, parsed_data: Dict[str, str]) -> str:
        level_val = level.value

        if level_val == 3:
            concept_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("concept_id", ""), "Cybersecurity Concept")
            obs_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("observation_type", ""), "Observe System Behavior")
            ev_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("evidence_type", ""), "HTTP Traffic Evidence")
            q_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("question_type", ""), "How is input sanitized?")
            return (
                f"Core Concept: {concept_desc}.\n"
                f"Observation Target: {obs_desc}.\n"
                f"Evidence to Collect: {ev_desc}.\n"
                f"Guiding Question: {q_desc}"
            )

        elif level_val == 4:
            tech_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("technique_id", ""), "Investigation Technique")
            target_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("observation_target", ""), "Target Endpoint Parameter")
            ev_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("evidence_type", ""), "HTTP Response Data")
            disc_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("discriminator_type", ""), "Compare Status Codes")
            check_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("next_check_type", ""), "Observe HTTP Status")
            return (
                f"Technique Direction: {tech_desc}.\n"
                f"Observation Target: {target_desc}.\n"
                f"Evidence to Collect: {ev_desc}.\n"
                f"Hypothesis Discriminator: {disc_desc}.\n"
                f"Safe Next Check: {check_desc}"
            )

        elif level_val == 5:
            vuln_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("vulnerability_class", ""), "Vulnerability Class")
            mech_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("mechanism_type", ""), "Parameter Processing Mechanism")
            interp_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("evidence_interpretation_type", ""), "Evidence Processing")
            disc_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("discriminator_type", ""), "Compare Status Codes")
            check_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("safe_next_check_type", ""), "Audit Code Patterns")
            risk_desc = ENUM_DESCRIPTIONS.get(parsed_data.get("risk_explanation_type", ""), "Risk Assessment")
            return (
                f"Vulnerability Mechanics: {vuln_desc} ({mech_desc}).\n"
                f"Evidence Interpretation: {interp_desc}.\n"
                f"Hypothesis Discriminator: {disc_desc}.\n"
                f"Safe Next Check: {check_desc}.\n"
                f"Risk Explanation: {risk_desc}"
            )

        return parsed_data.get("content", "")


def parse_and_validate_structured_hint(
    raw_text: str, level: HintLevel
) -> StructuredValidationResult:
    """Parse and strictly validate raw LLM text against restricted enum schema contracts for L3-L5."""
    level_val = level.value

    # L0-L2 and L6 use standard string format contracts; schema check passes
    if level_val < 3 or level_val == 6:
        return StructuredValidationResult(
            is_valid=True,
            hint_level=level,
            parsed_data={"content": raw_text},
            rendered_text=raw_text,
            error_message="",
            rejection_reason="",
        )

    # STRICT SCHEMAS FOR L3-L5: MUST BE A VALID JSON OBJECT!
    if not isinstance(raw_text, str) or not raw_text.strip():
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=None,
            rendered_text="",
            error_message="Raw input must be a non-empty JSON string",
            rejection_reason=f"Level L{level_val} input was empty or non-string",
        )

    text_stripped = raw_text.strip()

    # Reject plain text strings that are not JSON objects
    if not text_stripped.startswith("{") or not text_stripped.endswith("}"):
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=None,
            rendered_text="",
            error_message="L3-L5 structured hints MUST be a valid JSON object string",
            rejection_reason=f"Level L{level_val} raw text was plain text prose instead of a JSON object",
        )

    # Parse JSON
    try:
        data = json.loads(text_stripped)
    except Exception as ex:
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=None,
            rendered_text="",
            error_message=f"JSON parsing failed for L{level_val} structured output: {ex}",
            rejection_reason=f"Level L{level_val} output must be valid JSON",
        )

    # Must be a JSON dict (reject JSON arrays, integers, booleans, nulls)
    if not isinstance(data, dict):
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=None,
            rendered_text="",
            error_message="Level L3-L5 structured output MUST be a JSON object (dict)",
            rejection_reason=f"Level L{level_val} output was a {type(data).__name__} instead of JSON object",
        )

    # Check required fields & unexpected extra keys
    if level_val == 3:
        required = L3_REQUIRED_FIELDS
        enum_map = {
            "concept_id": L3_CONCEPT_ENUMS,
            "observation_type": L3_OBSERVATION_ENUMS,
            "evidence_type": L3_EVIDENCE_ENUMS,
            "question_type": L3_QUESTION_ENUMS,
        }
    elif level_val == 4:
        required = L4_REQUIRED_FIELDS
        enum_map = {
            "technique_id": L4_TECHNIQUE_ENUMS,
            "observation_target": L4_TARGET_ENUMS,
            "evidence_type": L3_EVIDENCE_ENUMS,
            "discriminator_type": L4_DISCRIMINATOR_ENUMS,
            "next_check_type": L4_NEXT_CHECK_ENUMS,
        }
    elif level_val == 5:
        required = L5_REQUIRED_FIELDS
        enum_map = {
            "vulnerability_class": L5_VULN_CLASS_ENUMS,
            "mechanism_type": L5_MECHANISM_ENUMS,
            "evidence_interpretation_type": L5_INTERPRETATION_ENUMS,
            "discriminator_type": L4_DISCRIMINATOR_ENUMS,
            "safe_next_check_type": L5_NEXT_CHECK_ENUMS,
            "risk_explanation_type": L5_RISK_ENUMS,
        }
    else:
        required = set()
        enum_map = {}

    keys_set = set(data.keys())
    missing = required - keys_set
    if missing:
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=data,
            rendered_text="",
            error_message=f"Missing required fields for L{level_val}: {sorted(missing)}",
            rejection_reason=f"Level L{level_val} structured hint missing required fields {sorted(missing)}",
        )

    extra = keys_set - required
    if extra:
        return StructuredValidationResult(
            is_valid=False,
            hint_level=level,
            parsed_data=data,
            rendered_text="",
            error_message=f"Unexpected extra fields for L{level_val}: {sorted(extra)}",
            rejection_reason=f"Level L{level_val} structured hint contained forbidden extra fields {sorted(extra)}",
        )

    # Validate value types & enum constraints
    for field_name, allowed_enums in enum_map.items():
        val = data.get(field_name)

        if not isinstance(val, str):
            return StructuredValidationResult(
                is_valid=False,
                hint_level=level,
                parsed_data=data,
                rendered_text="",
                error_message=f"Field '{field_name}' must be a string, got {type(val).__name__}",
                rejection_reason=f"Field '{field_name}' in L{level_val} hint was not a string",
            )

        val_str = val.strip()
        if val_str not in allowed_enums:
            return StructuredValidationResult(
                is_valid=False,
                hint_level=level,
                parsed_data=data,
                rendered_text="",
                error_message=f"Field '{field_name}' value {val_str!r} is not an allowed enum in {sorted(allowed_enums)}",
                rejection_reason=f"Field '{field_name}' in L{level_val} hint contained unknown enum value {val_str!r}",
            )

    parsed_clean = {k: str(data[k]).strip() for k in required}
    rendered = DeterministicSafeRenderer.render(level, parsed_clean)

    return StructuredValidationResult(
        is_valid=True,
        hint_level=level,
        parsed_data=parsed_clean,
        rendered_text=rendered,
        error_message="",
        rejection_reason="",
    )
