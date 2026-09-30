"""
Tool cache for Phase 10A passive tool execution results.

Isolated by:
hash(tool_id, query_fingerprint, challenge_id, authorized_scope_id)
"""

from __future__ import annotations

import copy
import hashlib
import time
from typing import Dict, Optional, Tuple

from ctf_mentor.tools.contracts import ToolResult


class ToolCache:
    """In-memory result cache for tool adapter executions."""

    def __init__(self, default_ttl_seconds: float = 300.0) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._entries: Dict[str, Tuple[ToolResult, float, float]] = {}

    def _build_key(
        self,
        tool_id: str,
        query_fingerprint: str,
        challenge_id: str,
        authorized_scope_id: str,
    ) -> str:
        raw = f"{tool_id}:{query_fingerprint}:{challenge_id}:{authorized_scope_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(
        self,
        tool_id: str,
        query_fingerprint: str,
        challenge_id: str,
        authorized_scope_id: str,
    ) -> Optional[ToolResult]:
        key = self._build_key(tool_id, query_fingerprint, challenge_id, authorized_scope_id)
        if key not in self._entries:
            return None

        result, timestamp, ttl = self._entries[key]
        now = time.time()
        if now - timestamp > ttl:
            # Expired
            del self._entries[key]
            return None

        # Return a copy marked as served_from_cache
        cached_result = copy.deepcopy(result)
        cached_result.served_from_cache = True
        return cached_result

    def put(
        self,
        tool_id: str,
        query_fingerprint: str,
        challenge_id: str,
        authorized_scope_id: str,
        result: ToolResult,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        # Do not cache error results
        if result.error_status:
            return

        key = self._build_key(tool_id, query_fingerprint, challenge_id, authorized_scope_id)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        self._entries[key] = (copy.deepcopy(result), time.time(), ttl)

    def clear(self) -> None:
        self._entries.clear()
