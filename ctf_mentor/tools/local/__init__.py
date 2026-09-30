"""
Phase 10B.3 — Local Tool Execution Infrastructure.

Exports the public surface of the local execution subsystem.
"""

from ctf_mentor.tools.local.policy import (
    LocalExecutionPolicy,
    ExecutableAllowlist,
    ToolUnavailableError,
    LocalSubprocessPolicyViolation,
    InputSizeLimitExceeded,
    OutputSizeLimitExceeded,
    WorkspaceConfinementError,
    LocalPolicyViolation,
)
from ctf_mentor.tools.local.network import (
    LocalSubprocessRunner,
    SubprocessResult,
    AuditEntry,
)
from ctf_mentor.tools.local.adapter import (
    LocalToolAdapter,
    LocalExecutionContext,
)
from ctf_mentor.tools.local.orchestration import LocalToolOrchestrationHandler
from ctf_mentor.tools.local.sandbox import (
    IsolationLevel,
    SandboxUnavailableError,
    SandboxPolicyViolation,
    SandboxProfile,
    PreparedExecution,
    SandboxBackend,
    LinuxNamespaceSandboxBackend,
    WindowsJobObjectSandboxBackend,
    PureInMemorySandboxBackend,
    SandboxExecutionBoundary,
    TSHARK_SANDBOX_PROFILE,
    STEGHIDE_SANDBOX_PROFILE,
    CRYPTO_SANDBOX_PROFILE,
)

__all__ = [
    # Policy
    "LocalExecutionPolicy",
    "ExecutableAllowlist",
    "ToolUnavailableError",
    "LocalSubprocessPolicyViolation",
    "InputSizeLimitExceeded",
    "OutputSizeLimitExceeded",
    "WorkspaceConfinementError",
    "LocalPolicyViolation",
    # Runner
    "LocalSubprocessRunner",
    "SubprocessResult",
    "AuditEntry",
    # Adapter base
    "LocalToolAdapter",
    "LocalExecutionContext",
    # Orchestration
    "LocalToolOrchestrationHandler",
    # Sandbox
    "IsolationLevel",
    "SandboxUnavailableError",
    "SandboxPolicyViolation",
    "SandboxProfile",
    "PreparedExecution",
    "SandboxBackend",
    "LinuxNamespaceSandboxBackend",
    "WindowsJobObjectSandboxBackend",
    "PureInMemorySandboxBackend",
    "SandboxExecutionBoundary",
    "TSHARK_SANDBOX_PROFILE",
    "STEGHIDE_SANDBOX_PROFILE",
    "CRYPTO_SANDBOX_PROFILE",
]
