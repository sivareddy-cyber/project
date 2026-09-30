"""
Static Tool Registry for Phase 10A tool adapters.

Requirements:
- Static registration in code.
- No runtime dynamic imports or config-controlled tool loading.
- Unique tool_id required.
- Unknown tool_id fails closed.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ctf_mentor.tools.adapters import (
    CrtShAdapter,
    GitHubCodeSearchAdapter,
    ShodanAdapter,
    VirusTotalAdapter,
    WaybackAdapter,
)
from ctf_mentor.tools.contracts import ToolAdapter


class UnknownToolError(Exception):
    """Raised when an unknown tool_id is requested."""

    def __init__(self, tool_id: str) -> None:
        safe_id = str(tool_id).replace("\n", "").replace("\r", "")
        super().__init__(f"Unknown or unauthorized tool_id: {safe_id!r}")
        self.tool_id = safe_id


class StaticToolRegistry:
    """Static registry of authorized tool adapters."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolAdapter] = {}
        self._register_default_adapters()

    def _register_default_adapters(self) -> None:
        """Statically register the 5 authorized Phase 10A passive OSINT adapters."""
        adapters: List[ToolAdapter] = [
            CrtShAdapter(),
            WaybackAdapter(),
            ShodanAdapter(),
            VirusTotalAdapter(),
            GitHubCodeSearchAdapter(),
        ]
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ToolAdapter) -> None:
        """Statically register a tool adapter instance. Raises ValueError on duplicate tool_id."""
        if not hasattr(adapter, "tool_id") or not adapter.tool_id:
            raise ValueError("Tool adapter must have a non-empty tool_id")
        tool_id = str(adapter.tool_id).strip().lower()

        if tool_id in self._tools:
            raise ValueError(f"Duplicate tool_id registration attempted: {tool_id!r}")

        self._tools[tool_id] = adapter

    def get(self, tool_id: str) -> Optional[ToolAdapter]:
        """Look up tool adapter by tool_id. Returns None if unknown."""
        if not tool_id or not isinstance(tool_id, str):
            return None
        return self._tools.get(tool_id.strip().lower())

    def get_or_raise(self, tool_id: str) -> ToolAdapter:
        """Look up tool adapter by tool_id or raise UnknownToolError."""
        adapter = self.get(tool_id)
        if adapter is None:
            raise UnknownToolError(tool_id)
        return adapter

    def list_tools(self) -> List[str]:
        """List all registered tool_ids."""
        return sorted(list(self._tools.keys()))
