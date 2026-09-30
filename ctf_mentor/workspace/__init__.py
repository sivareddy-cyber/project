"""
Phase 10B.1 Workspace Isolation Package.
Phase 10B.2 Capability System.

Provides isolated local filesystem workspaces bound to (challenge_id, session_id),
and a trusted workspace execution boundary with least-privilege capability issuance
for tool adapters.
"""

from ctf_mentor.workspace.manager import WorkspaceManager
from ctf_mentor.workspace.models import (
    ArtifactIntegrityError,
    ArtifactSecurityError,
    PathConfinementError,
    QuotaExceededError,
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceLockError,
    WorkspacePath,
    WorkspaceRecord,
    WorkspaceStatus,
    WorkspaceStatusError,
    WorkspaceValidationError,
)
from ctf_mentor.workspace.repository import WorkspaceRepository, ensure_workspace_table
from ctf_mentor.workspace.capabilities import (
    CapabilityPermission,
    CapabilityPermissionError,
    CapabilityRevokedError,
    InputCapability,
    IssuedCapabilitySet,
    NULL_CAPABILITY_SPEC,
    OutputCapability,
    TrustedWorkspaceExecutionBoundary,
    WorkCapability,
    WorkspaceCapability,
    WorkspaceCapabilitySpec,
)

__all__ = [
    # Phase 10B.1
    "WorkspaceManager",
    "WorkspaceHandle",
    "WorkspacePath",
    "WorkspaceRecord",
    "WorkspaceStatus",
    "WorkspaceRepository",
    "ensure_workspace_table",
    "WorkspaceError",
    "WorkspaceValidationError",
    "WorkspaceStatusError",
    "PathConfinementError",
    "QuotaExceededError",
    "ArtifactIntegrityError",
    "ArtifactSecurityError",
    "WorkspaceLockError",
    # Phase 10B.2 Capability System
    "WorkspaceCapabilitySpec",
    "NULL_CAPABILITY_SPEC",
    "CapabilityPermission",
    "WorkspaceCapability",
    "InputCapability",
    "WorkCapability",
    "OutputCapability",
    "IssuedCapabilitySet",
    "TrustedWorkspaceExecutionBoundary",
    "CapabilityRevokedError",
    "CapabilityPermissionError",
]

