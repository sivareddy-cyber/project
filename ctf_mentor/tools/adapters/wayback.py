"""
WaybackAdapter for historical URL/snapshot lookup.
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


class WaybackInput(ToolInputSchema):
    """Closed typed input schema for Wayback Machine CDX lookup."""

    def __init__(self, domain: str, limit: int = 10) -> None:
        self.domain = str(domain).strip().lower().rstrip(".")
        if not self.domain:
            raise ValueError("domain parameter cannot be empty")
        if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", self.domain):
            raise ValueError(f"Invalid domain format: {domain!r}")
        if not isinstance(limit, int) or not (1 <= limit <= 500):
            raise ValueError(f"limit must be an integer between 1 and 500, got {limit!r}")
        self.limit = limit

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> WaybackInput:
        if not isinstance(raw_args, dict):
            raise ValueError("Input arguments must be a dictionary")
        allowed_keys = {"domain", "domain_name", "hostname", "limit"}
        extra_keys = set(raw_args.keys()) - allowed_keys
        if extra_keys:
            raise ValueError(f"Unexpected argument keys for wayback input: {sorted(extra_keys)}")

        domain = raw_args.get("domain") or raw_args.get("domain_name") or raw_args.get("hostname")
        if not domain:
            raise ValueError("Missing required domain argument")

        limit = raw_args.get("limit", 10)
        return cls(domain=str(domain), limit=int(limit))

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "limit": self.limit}


class WaybackAdapter:
    """Wayback Machine historical snapshot adapter."""

    tool_id = "wayback"
    tool_version = "1.0.0"
    domain_ids = ["osint"]
    execution_class = ExecutionClass.PASSIVE_NETWORK
    allowed_target_types = ["DOMAIN_TARGET"]
    input_schema: Type[ToolInputSchema] = WaybackInput
    requires_credentials = False
    credential_ref = None
    rate_limit_policy = RateLimitPolicy(
        max_requests_per_window=10,
        window_seconds=60.0,
        timeout_seconds=5.0,
        max_response_bytes=1048576,
    )
    network_destinations = ["web.archive.org"]
    # Phase 10B.2: Passive network adapter — no workspace access required.
    workspace_capability_spec: WorkspaceCapabilitySpec = NULL_CAPABILITY_SPEC

    def validate_input(self, raw_args: Dict[str, Any]) -> WaybackInput:
        return WaybackInput.validate(raw_args)

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
        if not isinstance(validated_input, WaybackInput):
            validated_input = self.validate_input(validated_input.to_dict() if hasattr(validated_input, "to_dict") else {})

        domain = validated_input.domain
        limit = validated_input.limit
        if not self.validate_scope(domain, scope):
            raise ValueError(f"Target domain {domain!r} is out of authorized scope")

        request_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = hashlib.sha256(f"wayback:{domain}:{limit}".encode("utf-8")).hexdigest()

        target_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit={limit}"
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
                    source="Wayback Machine",
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
                source="Wayback Machine",
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
            source="Wayback Machine",
        )

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        candidates: List[EvidenceCandidate] = []
        domain = context.get("domain", "")
        ts = context.get("timestamp")

        if not isinstance(raw_data, list) or len(raw_data) < 2:
            return candidates

        # First row in CDX json format is header: ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"]
        header = [str(h).lower() for h in raw_data[0]]
        url_idx = header.index("original") if "original" in header else 2
        ts_idx = header.index("timestamp") if "timestamp" in header else 1

        for row in raw_data[1:]:
            if not isinstance(row, list) or len(row) <= max(url_idx, ts_idx):
                continue
            orig_url = str(row[url_idx])
            snap_ts = str(row[ts_idx])

            candidates.append(
                EvidenceCandidate(
                    source=self.tool_id,
                    observation=f"Historical Wayback snapshot URL: {orig_url} (timestamp: {snap_ts})",
                    provenance={
                        "tool_id": self.tool_id,
                        "snapshot_timestamp": snap_ts,
                        "original_url": orig_url,
                    },
                    timestamp=ts,
                    authorized_target_relationship=f"Historical Wayback snapshot for authorized domain {domain}",
                    trust="UNTRUSTED",  # Explicitly UNTRUSTED
                )
            )

        return candidates
