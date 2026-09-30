"""
Phase 10A: Passive Tool Adapter Foundation + OSINT Adapters.
Phase 10B.3: Local Tool Execution (tshark, steghide, LocalCryptoOps).
"""

from ctf_mentor.tools.contracts import (
    ExecutionClass,
    RateLimitPolicy,
    ToolInputSchema,
    EvidenceCandidate,
    ToolResult,
    ToolAdapter,
)
from ctf_mentor.tools.credentials import (
    SecretStr,
    CredentialProvider,
    EnvCredentialProvider,
    CredentialNotFoundError,
)
from ctf_mentor.tools.network import (
    SecureNetworkWrapper,
    SSRFProtectionError,
    RedirectSecurityError,
    ResponseSizeExceededError,
    RateLimitExceededError,
    ConcurrencyLimitExceededError,
)
from ctf_mentor.tools.registry import StaticToolRegistry, UnknownToolError
from ctf_mentor.tools.cache import ToolCache
from ctf_mentor.tools.normalization import normalize_tool_result

from ctf_mentor.tools.adapters import (
    CrtShAdapter,
    CrtShInput,
    WaybackAdapter,
    WaybackInput,
    ShodanAdapter,
    ShodanInput,
    VirusTotalAdapter,
    VirusTotalInput,
    GitHubCodeSearchAdapter,
    GitHubSearchInput,
    # Phase 10B.3
    TsharkAdapter,
    TsharkInput,
    TsharkOperation,
    SteghideAdapter,
    SteghideInput,
    SteghideOperation,
    LocalCryptoOpsAdapter,
    LocalCryptoInput,
    CryptoOperation,
)

# Phase 10B.3 — Local Execution Infrastructure
from ctf_mentor.tools.local import (
    LocalToolAdapter,
    LocalExecutionContext,
    LocalExecutionPolicy,
    ExecutableAllowlist,
    ToolUnavailableError,
    LocalSubprocessPolicyViolation,
    InputSizeLimitExceeded,
    OutputSizeLimitExceeded,
    WorkspaceConfinementError,
    LocalPolicyViolation,
    LocalSubprocessRunner,
    SubprocessResult,
    AuditEntry,
    LocalToolOrchestrationHandler,
)

__all__ = [
    "ExecutionClass",
    "RateLimitPolicy",
    "ToolInputSchema",
    "EvidenceCandidate",
    "ToolResult",
    "ToolAdapter",
    "SecretStr",
    "CredentialProvider",
    "EnvCredentialProvider",
    "CredentialNotFoundError",
    "SecureNetworkWrapper",
    "SSRFProtectionError",
    "RedirectSecurityError",
    "ResponseSizeExceededError",
    "RateLimitExceededError",
    "ConcurrencyLimitExceededError",
    "StaticToolRegistry",
    "UnknownToolError",
    "ToolCache",
    "normalize_tool_result",
    # Phase 10A adapters
    "CrtShAdapter",
    "CrtShInput",
    "WaybackAdapter",
    "WaybackInput",
    "ShodanAdapter",
    "ShodanInput",
    "VirusTotalAdapter",
    "VirusTotalInput",
    "GitHubCodeSearchAdapter",
    "GitHubSearchInput",
    # Phase 10B.3 adapters
    "TsharkAdapter",
    "TsharkInput",
    "TsharkOperation",
    "SteghideAdapter",
    "SteghideInput",
    "SteghideOperation",
    "LocalCryptoOpsAdapter",
    "LocalCryptoInput",
    "CryptoOperation",
    # Phase 10B.3 infrastructure
    "LocalToolAdapter",
    "LocalExecutionContext",
    "LocalExecutionPolicy",
    "ExecutableAllowlist",
    "ToolUnavailableError",
    "LocalSubprocessPolicyViolation",
    "InputSizeLimitExceeded",
    "OutputSizeLimitExceeded",
    "WorkspaceConfinementError",
    "LocalPolicyViolation",
    "LocalSubprocessRunner",
    "SubprocessResult",
    "AuditEntry",
    "LocalToolOrchestrationHandler",
]
