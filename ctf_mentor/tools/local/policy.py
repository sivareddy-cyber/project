"""
Phase 10B.3 — Local Execution Policy and Executable Allowlist.

SECURITY DESIGN:
- All executable paths are resolved at module import time from a hardcoded
  set of known absolute paths. shutil.which() is NOT used for primary
  resolution because it consults user-controlled PATH.
- Resolved paths are stored as absolute Path objects. This value is passed
  directly to subprocess.Popen() — never via shell expansion.
- LocalExecutionPolicy instances are frozen dataclasses: immutable after
  creation. No field may be populated from user/LLM input.
- A tool whose binary is absent → executable_path = None.
  Any attempt to execute raises ToolUnavailableError (fail-closed).
- Platform-specific limits (RLIMIT_*) are applied where the 'resource'
  module is available (POSIX). On Windows they are not available;
  timeout enforcement remains. This is documented explicitly.

IMPORTANT: Do NOT weaken any limit because the host platform lacks a
specific primitive. Fail to the next available control (timeout) and
document the gap.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class LocalPolicyViolation(Exception):
    """Base class for all local execution policy violations."""


class ToolUnavailableError(LocalPolicyViolation):
    """Raised when the required executable is absent or not in the allowlist."""


class LocalSubprocessPolicyViolation(LocalPolicyViolation):
    """Raised when a caller attempts to violate subprocess security policy
    (e.g., shell=True, executable not in allowlist, forbidden argv component)."""


class InputSizeLimitExceeded(LocalPolicyViolation):
    """Raised when an input artifact exceeds the policy maximum."""


class OutputSizeLimitExceeded(LocalPolicyViolation):
    """Raised when subprocess output exceeds the policy maximum."""


class WorkspaceConfinementError(LocalSubprocessPolicyViolation):
    """Raised when a path would escape the workspace confinement boundary."""


class ProcessCleanupError(LocalPolicyViolation):
    """Raised when process-tree cleanup fails or cannot be guaranteed."""


# ---------------------------------------------------------------------------
# LocalExecutionPolicy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LocalExecutionPolicy:
    """
    Immutable per-tool execution security policy.

    All fields are set at module-load time from hardcoded constants.
    NO field may be populated from user/LLM input at any time.

    Attributes:
        tool_id:              Unique identifier matching the tool adapter.
        executable_path:      Absolute resolved Path to the binary, or None if absent.
        timeout_seconds:      Hard wall-clock timeout for the subprocess.
        max_stdout_bytes:     Maximum bytes read from stdout before process kill.
        max_stderr_bytes:     Maximum bytes read from stderr before process kill.
        max_input_bytes:      Maximum artifact input size before execution is refused.
        max_output_bytes:     Maximum output bytes written to workspace.
        posix_cpu_limit_s:    RLIMIT_CPU in seconds (POSIX only; None = not applied).
        posix_mem_limit_bytes:RLIMIT_AS in bytes (POSIX only; None = not applied).
        posix_fsize_limit_bytes: RLIMIT_FSIZE in bytes (POSIX only; None = not applied).
        network_allowed:      Always False for all Phase 10B.3 tools.
        allowed_exit_codes:   Frozenset of exit codes treated as success.
        start_new_session:    If True, subprocess starts in a new session (for killpg).
    """
    tool_id: str
    executable_path: Optional[Path]
    timeout_seconds: float
    max_stdout_bytes: int
    max_stderr_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    posix_cpu_limit_s: Optional[int]
    posix_mem_limit_bytes: Optional[int]
    posix_fsize_limit_bytes: Optional[int]
    network_allowed: bool = False
    allowed_exit_codes: FrozenSet[int] = field(default_factory=lambda: frozenset({0}))
    start_new_session: bool = True

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_stdout_bytes <= 0:
            raise ValueError("max_stdout_bytes must be positive")
        if self.max_stderr_bytes <= 0:
            raise ValueError("max_stderr_bytes must be positive")
        if self.max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.network_allowed:
            raise ValueError(
                "network_allowed must be False for all Phase 10B.3 local tools"
            )

    @property
    def is_available(self) -> bool:
        """True if the executable is present and verified at probe time."""
        return self.executable_path is not None


# ---------------------------------------------------------------------------
# Executable Allowlist
# ---------------------------------------------------------------------------

_IS_WINDOWS = sys.platform == "win32"

# Hardcoded trusted candidate paths per tool.
# These are the ONLY paths that will be considered.
# Do NOT add user-supplied or PATH-derived entries here.
_KNOWN_PATHS: dict[str, list[str]] = {
    "tshark": [
        "/usr/bin/tshark",
        "/usr/sbin/tshark",
        "/usr/local/bin/tshark",
        "/opt/wireshark/bin/tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ],
    "steghide": [
        "/usr/bin/steghide",
        "/usr/local/bin/steghide",
        "/usr/sbin/steghide",
        r"C:\Program Files\steghide\steghide.exe",
    ],
}

# Trusted directory prefixes. A resolved binary path must be within one of
# these prefixes; otherwise it is rejected (PATH hijacking guard).
_TRUSTED_PREFIXES_POSIX: list[Path] = [
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/local/bin"),
    Path("/opt/wireshark/bin"),
    Path("/opt/wireshark"),
]

_TRUSTED_PREFIXES_WINDOWS: list[Path] = [
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
    Path(r"C:\Program Files\steghide"),
    Path(r"C:\Program Files (x86)\steghide"),
]

_TRUSTED_PREFIXES: list[str] = [
    str(p) for p in (_TRUSTED_PREFIXES_WINDOWS if _IS_WINDOWS else _TRUSTED_PREFIXES_POSIX)
]


def _is_path_trusted(resolved_path: Path) -> bool:
    """Check if resolved_path is strictly inside an allowlisted trusted system prefix."""
    if _IS_WINDOWS:
        norm_resolved = Path(str(resolved_path).lower())
        for prefix in _TRUSTED_PREFIXES_WINDOWS:
            norm_prefix = Path(str(prefix).lower())
            try:
                if norm_resolved.is_relative_to(norm_prefix):
                    return True
            except AttributeError:
                # Fallback for older Path implementations
                if str(norm_resolved).startswith(str(norm_prefix)):
                    return True
        return False
    else:
        for prefix in _TRUSTED_PREFIXES_POSIX:
            try:
                if resolved_path.is_relative_to(prefix):
                    return True
            except Exception:
                if str(resolved_path).startswith(str(prefix)):
                    return True
        return False


def _probe_executable(name: str) -> Optional[Path]:
    """
    Probe for a tool binary using the hardcoded path list.

    Returns the resolved absolute Path if found and trusted, else None.

    Security properties:
    - Only checks hardcoded paths; does NOT consult PATH or shutil.which().
    - Calls Path.resolve() to follow symlinks to the final target.
    - Verifies the resolved target starts with a trusted directory prefix.
    - Never raises; returns None on any error (fail-safe, not fail-open).
    """
    candidates = _KNOWN_PATHS.get(name, [])
    for candidate_str in candidates:
        try:
            candidate = Path(candidate_str)
            if not candidate.exists() or not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if not _is_path_trusted(resolved):
                # Binary exists at candidate path but resolves outside trusted
                # directory — possible symlink attack or installation anomaly.
                # Refuse it.
                continue
            return resolved
        except Exception:
            continue
    return None



class ExecutableAllowlist:
    """
    Module-level singleton that probes for known tool binaries at import time.

    The allowlist maps tool_id → resolved absolute Path (or None if absent).
    This is the authoritative source for executable paths. No other code
    may select or derive an executable path.
    """

    def __init__(self) -> None:
        self._paths: dict[str, Optional[Path]] = {}
        for name in _KNOWN_PATHS:
            self._paths[name] = _probe_executable(name)

    def get_path(self, tool_id: str) -> Optional[Path]:
        """Return the resolved Path for tool_id, or None if absent."""
        return self._paths.get(tool_id)

    def require_path(self, tool_id: str) -> Path:
        """
        Return the resolved Path for tool_id.

        Raises:
            ToolUnavailableError: If the tool is absent or not in the allowlist.
        """
        p = self._paths.get(tool_id)
        if p is None:
            raise ToolUnavailableError(
                f"Tool {tool_id!r} is not available: executable not found at any "
                f"trusted path. Install the tool and restart the application."
            )
        return p

    def is_available(self, tool_id: str) -> bool:
        """Return True if the tool binary is present and verified."""
        return self._paths.get(tool_id) is not None

    def __repr__(self) -> str:
        entries = {k: str(v) if v else "ABSENT" for k, v in self._paths.items()}
        return f"<ExecutableAllowlist {entries}>"


# Module-level singleton — probed once at import time.
EXECUTABLE_ALLOWLIST = ExecutableAllowlist()


# ---------------------------------------------------------------------------
# Per-tool Policy Constants
# ---------------------------------------------------------------------------

TSHARK_POLICY = LocalExecutionPolicy(
    tool_id="tshark",
    executable_path=EXECUTABLE_ALLOWLIST.get_path("tshark"),
    timeout_seconds=30.0,
    max_stdout_bytes=10 * 1024 * 1024,      # 10 MB
    max_stderr_bytes=1 * 1024 * 1024,       # 1 MB
    max_input_bytes=50 * 1024 * 1024,       # 50 MB
    max_output_bytes=10 * 1024 * 1024,      # 10 MB
    posix_cpu_limit_s=30,
    posix_mem_limit_bytes=512 * 1024 * 1024,  # 512 MB
    posix_fsize_limit_bytes=10 * 1024 * 1024, # 10 MB
    network_allowed=False,
    allowed_exit_codes=frozenset({0}),
    start_new_session=True,
)

STEGHIDE_POLICY = LocalExecutionPolicy(
    tool_id="steghide",
    executable_path=EXECUTABLE_ALLOWLIST.get_path("steghide"),
    timeout_seconds=30.0,
    max_stdout_bytes=1 * 1024 * 1024,       # 1 MB
    max_stderr_bytes=512 * 1024,            # 512 KB
    max_input_bytes=10 * 1024 * 1024,       # 10 MB
    max_output_bytes=5 * 1024 * 1024,       # 5 MB
    posix_cpu_limit_s=30,
    posix_mem_limit_bytes=256 * 1024 * 1024,  # 256 MB
    posix_fsize_limit_bytes=5 * 1024 * 1024,  # 5 MB
    network_allowed=False,
    allowed_exit_codes=frozenset({0}),
    start_new_session=True,
)

# Registry of all tool policies (used by orchestration for dispatch).
ALL_LOCAL_TOOL_POLICIES: dict[str, LocalExecutionPolicy] = {
    "tshark": TSHARK_POLICY,
    "steghide": STEGHIDE_POLICY,
}
