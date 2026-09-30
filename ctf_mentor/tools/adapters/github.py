"""
GitHubCodeSearchAdapter for authorized code/text search.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Type

from ctf_mentor.tools.adapters.scope_utils import is_text_subject_in_scope
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


class GitHubSearchInput(ToolInputSchema):
    """Closed typed input schema for GitHub Code Search."""

    def __init__(self, query: str, target_subject: Optional[str] = None) -> None:
        self.query = str(query).strip()
        if not self.query:
            raise ValueError("query parameter cannot be empty")

        clean_query = self.query.lower().rstrip(".")
        if target_subject is not None:
            clean_subject = str(target_subject).strip().lower().rstrip(".")
            if clean_subject and clean_subject != clean_query:
                raise ValueError(
                    f"Execution query {self.query!r} does not strictly match target_subject {target_subject!r}"
                )

        self.target_subject = self.query

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> GitHubSearchInput:
        if not isinstance(raw_args, dict):
            raise ValueError("Input arguments must be a dictionary")
        allowed_keys = {"query", "target_subject", "text", "subject", "query_or_text"}
        extra_keys = set(raw_args.keys()) - allowed_keys
        if extra_keys:
            raise ValueError(f"Unexpected argument keys for GitHub Code Search input: {sorted(extra_keys)}")

        query = raw_args.get("query") or raw_args.get("text") or raw_args.get("query_or_text")
        if not query:
            raise ValueError("Missing required query argument")

        target_subject = raw_args.get("target_subject") or raw_args.get("subject") or query
        return cls(query=str(query), target_subject=str(target_subject))

    def to_dict(self) -> Dict[str, Any]:
        return {"query": self.query, "target_subject": self.target_subject}


class GitHubCodeSearchAdapter:
    """GitHub Code Search OSINT adapter."""

    tool_id = "github_code_search"
    tool_version = "1.0.0"
    domain_ids = ["osint"]
    execution_class = ExecutionClass.PASSIVE_NETWORK
    allowed_target_types = ["TEXT_TARGET"]
    input_schema: Type[ToolInputSchema] = GitHubSearchInput
    requires_credentials = False
    credential_ref = "github_token"
    rate_limit_policy = RateLimitPolicy(
        max_requests_per_window=10,
        window_seconds=60.0,
        timeout_seconds=5.0,
        max_response_bytes=1048576,
    )
    network_destinations = ["api.github.com"]
    # Phase 10B.2: Passive network adapter — no workspace access required.
    workspace_capability_spec: WorkspaceCapabilitySpec = NULL_CAPABILITY_SPEC

    def validate_input(self, raw_args: Dict[str, Any]) -> GitHubSearchInput:
        return GitHubSearchInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        query = ""
        if isinstance(target, str):
            query = target
        elif isinstance(target, dict):
            query = str(target.get("query") or target.get("target_subject") or target.get("text") or "")
        elif hasattr(target, "query"):
            query = getattr(target, "query", "")

        return is_text_subject_in_scope(query, scope)

    def execute(
        self,
        validated_input: ToolInputSchema,
        scope: Any,
        credential_provider: Optional[CredentialProvider] = None,
    ) -> ToolResult:
        if not isinstance(validated_input, GitHubSearchInput):
            validated_input = self.validate_input(validated_input.to_dict() if hasattr(validated_input, "to_dict") else {})

        query = validated_input.query

        # Strict scope check directly on the executed query
        if not self.validate_scope(query, scope):
            raise ValueError(f"Executed query {query!r} is out of authorized scope")

        target_subject = query

        request_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        fingerprint = hashlib.sha256(f"github:{query}:{target_subject}".encode("utf-8")).hexdigest()

        encoded_query = urllib.parse.quote(query)
        endpoint = f"https://api.github.com/search/code?q={encoded_query}"

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CTFMentor-Phase10A",
        }

        # Optional credentials handling
        if credential_provider and self.credential_ref:
            try:
                token = credential_provider.get(self.credential_ref)
                headers["Authorization"] = f"Bearer {token.get_secret_value()}"
            except Exception:
                pass  # Optional credential, proceed without if unconfigured

        wrapper = SecureNetworkWrapper(
            allowed_destinations=self.network_destinations,
            rate_limit_policy=self.rate_limit_policy,
        )

        try:
            status, resp_headers, resp_bytes = wrapper.request(endpoint, headers=headers, context_key=self.tool_id)
            if status != 200:
                return ToolResult(
                    tool_id=self.tool_id,
                    tool_version=self.tool_version,
                    request_id=request_id,
                    timestamp=timestamp,
                    authorized_target=target_subject,
                    query_fingerprint=fingerprint,
                    error_status=f"HTTP {status}",
                    source="GitHub Code Search",
                )

            raw_json = json.loads(resp_bytes.decode("utf-8", errors="replace"))
        except Exception as ex:
            return ToolResult(
                tool_id=self.tool_id,
                tool_version=self.tool_version,
                request_id=request_id,
                timestamp=timestamp,
                authorized_target=target_subject,
                query_fingerprint=fingerprint,
                error_status=f"Execution error: {ex}",
                source="GitHub Code Search",
            )

        context = {
            "query": query,
            "target_subject": target_subject,
            "timestamp": timestamp,
            "request_id": request_id,
        }
        observations = self.normalize(raw_json, context)

        return ToolResult(
            tool_id=self.tool_id,
            tool_version=self.tool_version,
            request_id=request_id,
            timestamp=timestamp,
            authorized_target=target_subject,
            query_fingerprint=fingerprint,
            raw_data=raw_json,
            normalized_observations=observations,
            provenance={"query": query, "target_subject": target_subject, "endpoint": endpoint},
            source="GitHub Code Search",
        )

    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[EvidenceCandidate]:
        candidates: List[EvidenceCandidate] = []
        target_sub = context.get("target_subject", "")
        ts = context.get("timestamp")

        if not isinstance(raw_data, dict):
            return candidates

        items = raw_data.get("items", [])
        if not isinstance(items, list):
            return candidates

        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            path = item.get("path")
            html_url = item.get("html_url")
            repo = item.get("repository", {})
            repo_name = repo.get("full_name") if isinstance(repo, dict) else ""

            candidates.append(
                EvidenceCandidate(
                    source=self.tool_id,
                    observation=f"GitHub code match in repository {repo_name!r}: {path} ({html_url})",
                    provenance={
                        "tool_id": self.tool_id,
                        "repository": repo_name,
                        "file_name": name,
                        "file_path": path,
                        "html_url": html_url,
                    },
                    timestamp=ts,
                    authorized_target_relationship=f"GitHub code match for authorized target subject {target_sub}",
                    trust="UNTRUSTED",  # Explicitly UNTRUSTED
                )
            )

        return candidates
