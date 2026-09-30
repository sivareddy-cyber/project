"""
VirusTotalAdapter for passive reputation/intelligence lookup.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Type

from ctf_mentor.tools.adapters.scope_utils import is_domain_in_scope, is_text_subject_in_scope
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


class VirusTotalInput(ToolInputSchema):
    """Closed typed input schema for VirusTotal passive lookup."""

    def __init__(self, target_value: str, target_type: str = "DOMAIN_TARGET") -> None:
        self.target_value = str(target_value).strip()
        if not self.target_value:
            raise ValueError("target_value parameter cannot be empty")

        self.target_type = str(target_type).strip().upper()
        if self.target_type not in ("DOMAIN_TARGET", "METADATA_TARGET"):
            raise ValueError(f"VirusTotal target_type must be DOMAIN_TARGET or METADATA_TARGET, got {target_type!r}")

        # Strict input validation preventing traversal, injection, or URL strings
        if "/" in self.target_value or "\\" in self.target_value or ".." in self.target_value:
            raise ValueError(f"Path traversal or slashes not permitted in target_value: {target_value!r}")

        if "%" in self.target_value or "?" in self.target_value or "#" in self.target_value:
            raise ValueError(f"Query fragments or encoded characters not permitted in target_value: {target_value!r}")

        if self.target_value.lower().startswith("http://") or self.target_value.lower().startswith("https://"):
            raise ValueError(f"URL strings not permitted in target_value: {target_value!r}")

        if self.target_type == "DOMAIN_TARGET":
            clean_dom = self.target_value.rstrip(".")
            if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", clean_dom):
                raise ValueError(f"Invalid domain format for DOMAIN_TARGET: {target_value!r}")
            self.target_value = clean_dom
        elif self.target_type == "METADATA_TARGET":
            if not re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", self.target_value):
                raise ValueError(f"Invalid identifier format for METADATA_TARGET: {target_value!r}")

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> VirusTotalInput:
        if not isinstance(raw_args, dict):
            raise ValueError("Input arguments must be a dictionary")
        allowed_keys = {"target_value", "target_type", "domain", "hash", "artifact_ref"}
        extra_keys = set(raw_args.keys()) - allowed_keys
        if extra_keys:
            raise ValueError(f"Unexpected argument keys for VirusTotal input: {sorted(extra_keys)}")

        target_value = raw_args.get("target_value") or raw_args.get("domain") or raw_args.get("hash") or raw_args.get("artifact_ref")
        if not target_value:
            raise ValueError("Missing required target_value argument")

        target_type = raw_args.get("target_type", "DOMAIN_TARGET")
        return cls(target_value=str(target_value), target_type=str(target_type))

    def to_dict(self) -> Dict[str, Any]:
        return {"target_value": self.target_value, "target_type": self.target_type}


class VirusTotalAdapter:
    """VirusTotal passive reputation and intelligence adapter."""

    tool_id = "virustotal"
    tool_version = "1.0.0"
    domain_ids = ["osint"]
    execution_class = ExecutionClass.PASSIVE_NETWORK
    allowed_target_types = ["DOMAIN_TARGET", "METADATA_TARGET"]
    input_schema: Type[ToolInputSchema] = VirusTotalInput
    requires_credentials = True
    credential_ref = "virustotal_api_key"
    rate_limit_policy = RateLimitPolicy(
        max_requests_per_window=10,
        window_seconds=60.0,
        timeout_seconds=5.0,
        max_response_bytes=1048576,
    )
    network_destinations = ["www.virustotal.com", "api.virustotal.com"]
    # Phase 10B.2: Passive network adapter — no workspace access required.
    workspace_capability_spec: WorkspaceCapabilitySpec = NULL_CAPABILITY_SPEC

    def validate_input(self, raw_args: Dict[str, Any]) -> VirusTotalInput:
        return VirusTotalInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        target_val = ""
        if isinstance(target, str):
            target_val = target
        elif isinstance(target, dict):
            target_val = str(target.get("target_value") or target.get("domain") or target.get("hash") or "")

        if not target_val:
            return False

        if "." in target_val and not len(target_val) in (32, 40, 64):
            return is_domain_in_scope(target_val, scope)
        return is_text_subject_in_scope(target_val, scope)

    def execute(
        self,
        validated_input: ToolInputSchema,
        scope: Any,
        credential_provider: Optional[CredentialProvider] = None,
    ) -> ToolResult:
        if not isinstance(validated_input, VirusTotalInput):
            validated_input = self.validate_input(validated_input.to_dict() if hasattr(validated_input, "to_dict") else {})

        target_val = validated_input.target_value
        target_type = validated_input.target_type
        if not self.validate_scope(target_val, scope):
            raise ValueError(f"Target {target_val!r} is out of authorized scope")

        if not credential_provider:
            raise ValueError("CredentialProvider is required for VirusTotal execution")

        api_key = credential_provider.get(self.credential_ref)
        raw_key = api_key.get_secret_value()

        request_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = hashlib.sha256(f"virustotal:{target_type}:{target_val}".encode("utf-8")).hexdigest()

        safe_encoded = urllib.parse.quote(target_val, safe="")
        if target_type == "DOMAIN_TARGET":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{safe_encoded}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/files/{safe_encoded}"

        wrapper = SecureNetworkWrapper(
            allowed_destinations=self.network_destinations,
            rate_limit_policy=self.rate_limit_policy,
        )

        headers = {
            "x-apikey": raw_key,
            "Accept": "application/json",
        }

        try:
            status, resp_headers, resp_bytes = wrapper.request(endpoint, headers=headers, context_key=self.tool_id)
            if status != 200:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_version=self.tool_version,
                    request_id=request_id,
                    timestamp=timestamp,
                    authorized_target=target_val,
                    query_fingerprint=fingerprint,
                    error_status=f"HTTP {status}",
                    source="VirusTotal",
                )

            raw_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
        except Exception as ex:
            return ToolResult(
                tool_id=self.tool_id,
                tool_version=self.tool_version,
                request_id=request_id,
                timestamp=timestamp,
                authorized_target=target_val,
                query_fingerprint=fingerprint,
                error_status=f"Execution error: {ex}",
                source="VirusTotal",
            )

        context = {
            "target_value": target_val,
            "target_type": target_type,
            "timestamp": timestamp,
            "request_id": request_id,
        }
        observations = self.normalize(raw_json, context)

        return ToolResult(
            tool_id=self.tool_id,
            tool_version=self.tool_version,
            request_id=request_id,
            timestamp=timestamp,
            authorized_target=target_val,
            query_fingerprint=fingerprint,
            raw_data=raw_json,
            normalized_observations=observations,
            provenance={"target": target_val, "target_type": target_type, "endpoint": endpoint},
            source="VirusTotal",
        )

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        candidates: List[EvidenceCandidate] = []
        target_val = context.get("target_value", "")
        ts = context.get("timestamp")

        if not isinstance(raw_data, dict):
            return candidates

        data_obj = raw_data.get("data", {})
        if not isinstance(data_obj, dict):
            return candidates

        attributes = data_obj.get("attributes", {})
        if isinstance(attributes, dict):
            stats = attributes.get("last_analysis_stats", {})
            if isinstance(stats, dict):
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                candidates.append(
                    EvidenceCandidate(
                        source=self.tool_id,
                        observation=f"VirusTotal report for {target_val}: {malicious} malicious, {suspicious} suspicious, {harmless} harmless (total engines: {total})",
                        provenance={
                            "tool_id": self.tool_id,
                            "target": target_val,
                            "malicious_count": malicious,
                            "total_engines": total,
                            "reputation": attributes.get("reputation"),
                        },
                        timestamp=ts,
                        authorized_target_relationship=f"VirusTotal reputation report for authorized target {target_val}",
                        trust="UNTRUSTED",  # Explicitly UNTRUSTED
                    )
                )

        return candidates
