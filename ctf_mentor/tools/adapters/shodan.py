"""
ShodanAdapter for passive indexed host/banner information.
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
from ctf_mentor.tools.credentials import CredentialProvider
from ctf_mentor.tools.network import SecureNetworkWrapper
from ctf_mentor.workspace.capabilities import NULL_CAPABILITY_SPEC, WorkspaceCapabilitySpec


class ShodanInput(ToolInputSchema):
    """Closed typed input schema for Shodan domain query."""

    def __init__(self, domain: str) -> None:
        self.domain = str(domain).strip().lower().rstrip(".")
        if not self.domain:
            raise ValueError("domain parameter cannot be empty")
        if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", self.domain):
            raise ValueError(f"Invalid domain format: {domain!r}")

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> ShodanInput:
        if not isinstance(raw_args, dict):
            raise ValueError("Input arguments must be a dictionary")
        allowed_keys = {"domain", "domain_name", "hostname"}
        extra_keys = set(raw_args.keys()) - allowed_keys
        if extra_keys:
            raise ValueError(f"Unexpected argument keys for Shodan input: {sorted(extra_keys)}")

        domain = raw_args.get("domain") or raw_args.get("domain_name") or raw_args.get("hostname")
        if not domain:
            raise ValueError("Missing required domain argument")

        return cls(domain=str(domain))

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain}


class ShodanAdapter:
    """Shodan passive indexed intelligence adapter."""

    tool_id = "shodan"
    tool_version = "1.0.0"
    domain_ids = ["osint"]
    execution_class = ExecutionClass.PASSIVE_NETWORK
    allowed_target_types = ["DOMAIN_TARGET"]
    input_schema: Type[ToolInputSchema] = ShodanInput
    requires_credentials = True
    credential_ref = "shodan_api_key"
    rate_limit_policy = RateLimitPolicy(
        max_requests_per_window=10,
        window_seconds=60.0,
        timeout_seconds=5.0,
        max_response_bytes=1048576,
    )
    network_destinations = ["api.shodan.io"]
    # Phase 10B.2: Passive network adapter — no workspace access required.
    workspace_capability_spec: WorkspaceCapabilitySpec = NULL_CAPABILITY_SPEC

    def validate_input(self, raw_args: Dict[str, Any]) -> ShodanInput:
        return ShodanInput.validate(raw_args)

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
        credential_provider: Optional[CredentialProvider] = None,
    ) -> ToolResult:
        if not isinstance(validated_input, ShodanInput):
            validated_input = self.validate_input(validated_input.to_dict() if hasattr(validated_input, "to_dict") else {})

        domain = validated_input.domain
        if not self.validate_scope(domain, scope):
            raise ValueError(f"Target domain {domain!r} is out of authorized scope")

        if not credential_provider:
            raise ValueError("CredentialProvider is required for Shodan execution")

        # Resolve secret key without exposing in exceptions
        api_key = credential_provider.get(self.credential_ref)
        raw_key = api_key.get_secret_value()

        request_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = hashlib.sha256(f"shodan:{domain}".encode("utf-8")).hexdigest()

        target_url = f"https://api.shodan.io/dns/domain/{domain}"
        headers = {"key": raw_key}

        wrapper = SecureNetworkWrapper(
            allowed_destinations=self.network_destinations,
            rate_limit_policy=self.rate_limit_policy,
        )

        try:
            status, resp_headers, resp_bytes = wrapper.request(target_url, headers=headers, context_key=self.tool_id)
            if status != 200:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_version=self.tool_version,
                    request_id=request_id,
                    timestamp=timestamp,
                    authorized_target=domain,
                    query_fingerprint=fingerprint,
                    error_status=f"HTTP {status}",
                    source="Shodan",
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
                source="Shodan",
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
            source="Shodan",
        )

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        candidates: List[EvidenceCandidate] = []
        domain = context.get("domain", "")
        ts = context.get("timestamp")

        if not isinstance(raw_data, dict):
            return candidates

        subdomains = raw_data.get("subdomains", [])
        data_records = raw_data.get("data", [])

        if isinstance(subdomains, list):
            for sub in subdomains:
                sub_str = str(sub).strip()
                if sub_str:
                    fqdn = f"{sub_str}.{domain}" if sub_str != "@" else domain
                    candidates.append(
                        EvidenceCandidate(
                            source=self.tool_id,
                            observation=f"Shodan indexed subdomain: {fqdn}",
                            provenance={
                                "tool_id": self.tool_id,
                                "domain": domain,
                                "subdomain": fqdn,
                                "indexed_data": True,
                                "as_of": str(ts),
                            },
                            timestamp=ts,
                            authorized_target_relationship=f"Shodan indexed subdomain record for authorized domain {domain}",
                            trust="UNTRUSTED",  # Explicitly UNTRUSTED
                        )
                    )

        if isinstance(data_records, list):
            for rec in data_records:
                if isinstance(rec, dict):
                    sub = rec.get("subdomain")
                    value = rec.get("value")
                    type_str = rec.get("type", "A")
                    if value:
                        fqdn = f"{sub}.{domain}" if sub else domain
                        candidates.append(
                            EvidenceCandidate(
                                source=self.tool_id,
                                observation=f"Shodan indexed DNS record: {fqdn} -> {value} ({type_str})",
                                provenance={
                                    "tool_id": self.tool_id,
                                    "record_type": type_str,
                                    "value": str(value),
                                    "indexed_data": True,
                                    "as_of": str(ts),
                                },
                                timestamp=ts,
                                authorized_target_relationship=f"Shodan indexed DNS record for authorized domain {domain}",
                                trust="UNTRUSTED",  # Explicitly UNTRUSTED
                            )
                        )

        return candidates
