"""
CrtShAdapter for Certificate Transparency lookup.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Type

from ctf_mentor.tools.adapters.scope_utils import is_domain_in_scope
from ctf_mentor.tools.contracts import (
    EvidenceCandidate,
    ExecutionClass,
    RateLimitPolicy,
    ToolAdapter,
    ToolInputSchema,
    ToolResult,
)
from ctf_mentor.tools.network import SecureNetworkWrapper
from ctf_mentor.workspace.capabilities import NULL_CAPABILITY_SPEC, WorkspaceCapabilitySpec


class CrtShInput(ToolInputSchema):
    """Closed typed input schema for crt.sh query."""

    def __init__(self, domain: str) -> None:
        self.domain = str(domain).strip().lower().rstrip(".")
        if not self.domain:
            raise ValueError("domain parameter cannot be empty")
        if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", self.domain):
            raise ValueError(f"Invalid domain format: {domain!r}")

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> CrtShInput:
        if not isinstance(raw_args, dict):
            raise ValueError("Input arguments must be a dictionary")
        allowed_keys = {"domain", "domain_name", "hostname"}
        extra_keys = set(raw_args.keys()) - allowed_keys
        if extra_keys:
            raise ValueError(f"Unexpected argument keys for crt.sh input: {sorted(extra_keys)}")

        domain = raw_args.get("domain") or raw_args.get("domain_name") or raw_args.get("hostname")
        if not domain:
            raise ValueError("Missing required domain argument")

        return cls(domain=str(domain))

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain}


class CrtShAdapter:
    """crt.sh Certificate Transparency adapter."""

    tool_id = "crt_sh"
    tool_version = "1.0.0"
    domain_ids = ["osint"]
    execution_class = ExecutionClass.PASSIVE_NETWORK
    allowed_target_types = ["DOMAIN_TARGET"]
    input_schema: Type[ToolInputSchema] = CrtShInput
    requires_credentials = False
    credential_ref = None
    rate_limit_policy = RateLimitPolicy(
        max_requests_per_window=10,
        window_seconds=60.0,
        timeout_seconds=5.0,
        max_response_bytes=1048576,
    )
    network_destinations = ["crt.sh"]
    # Phase 10B.2: Passive network adapter — no workspace access required.
    workspace_capability_spec: WorkspaceCapabilitySpec = NULL_CAPABILITY_SPEC

    def validate_input(self, raw_args: Dict[str, Any]) -> CrtShInput:
        return CrtShInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        domain = ""
        if isinstance(target, str):
            domain = target
        elif isinstance(target, dict):
            domain = str(target.get("domain") or target.get("domain_name") or target.get("hostname") or "")
        return is_domain_in_scope(domain, scope)

    def execute(
        self,
        validated_input: ToolInputSchema,
        scope: Any,
        credential_provider: Optional[Any] = None,
    ) -> ToolResult:
        if not isinstance(validated_input, CrtShInput):
            validated_input = self.validate_input(validated_input.to_dict() if hasattr(validated_input, "to_dict") else {})

        domain = validated_input.domain
        if not self.validate_scope(domain, scope):
            raise ValueError(f"Target domain {domain!r} is out of authorized scope")

        request_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = hashlib.sha256(f"crt_sh:{domain}".encode("utf-8")).hexdigest()

        target_url = f"https://crt.sh/?q={domain}&output=json"
        wrapper = SecureNetworkWrapper(
            allowed_destinations=self.network_destinations,
            rate_limit_policy=self.rate_limit_policy,
        )

        try:
            status, headers, resp_bytes = wrapper.request(target_url, context_key=self.tool_id)
            if status != 200:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_version=self.tool_version,
                    request_id=request_id,
                    timestamp=timestamp,
                    authorized_target=domain,
                    query_fingerprint=fingerprint,
                    error_status=f"HTTP {status}",
                    source="crt.sh",
                )

            raw_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
        except Exception as ex:
            return ToolResult(
                tool_id=self.tool_id,
                tool_version=self.tool_version,
                request_id=request_id,
                timestamp=timestamp,
                authorized_target=domain,
                query_fingerprint=fingerprint,
                error_status=f"Execution error: {ex}",
                source="crt.sh",
            )

        context = {
            "domain": domain,
            "timestamp": timestamp,
            "request_id": request_id,
        }
        observations = self.normalize(raw_json, context)

        return ToolResult(
            tool_id=self.tool_id,
            tool_version=self.tool_version,
            request_id=request_id,
            timestamp=timestamp,
            authorized_target=domain,
            query_fingerprint=fingerprint,
            raw_data=raw_json,
            normalized_observations=observations,
            provenance={"domain": domain, "source_url": target_url},
            source="crt.sh",
        )

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        candidates: List[EvidenceCandidate] = []
        domain = context.get("domain", "")
        ts = context.get("timestamp")

        if not isinstance(raw_data, list):
            return candidates

        seen_names = set()
        for item in raw_data:
            if not isinstance(item, dict):
                continue
            name_val = item.get("name_value") or item.get("common_name")
            if not name_val:
                continue

            for name in str(name_val).split("\n"):
                clean_name = name.strip().lower()
                if clean_name and clean_name not in seen_names:
                    seen_names.add(clean_name)
                    candidates.append(
                        EvidenceCandidate(
                            source=self.tool_id,
                            observation=f"Discovered certificate identity SAN: {clean_name}",
                            provenance={
                                "tool_id": self.tool_id,
                                "certificate_id": item.get("id"),
                                "issuer_name": item.get("issuer_name"),
                                "name_value": clean_name,
                            },
                            timestamp=ts,
                            authorized_target_relationship=f"Discovered Certificate SAN for authorized target {domain}",
                            trust="UNTRUSTED",  # Explicitly UNTRUSTED
                        )
                    )

        return candidates
