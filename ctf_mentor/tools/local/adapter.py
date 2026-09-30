"""
Phase 10B.3 — LocalToolAdapter ABC and LocalExecutionContext.

LocalToolAdapter is the abstract base class for all local subprocess-based
tool adapters introduced in Phase 10B.3 and later.

SECURITY RULES:
- execute() on a LocalToolAdapter raises RuntimeError. The Phase 8 locked
  orchestration dispatcher dispatches PASSIVE_NETWORK tools via execute().
  Local adapters MUST be dispatched via execute_local() by the new
  LocalToolOrchestrationHandler. If the Phase 8 dispatcher erroneously
  calls execute() on a local adapter, the explicit RuntimeError is the
  fail-closed response.
- execute_local() receives a LocalExecutionContext which bundles the issued
  IssuedCapabilitySet, LocalExecutionPolicy, and per-invocation audit state.
- Capabilities MUST be revoked in the finally block of execute_local().
- Sandboxing & Confinement: On Linux, OS-level namespace/filesystem sandboxing is
  enforced via Bubblewrap (Phase 10B.4). On Windows, process limits and lifecycle
  containment are enforced via Job Objects (Windows Job Objects provide process/resource
  containment but no kernel-level filesystem or network namespace isolation).
"""

from __future__ import annotations

import abc
import datetime
import hashlib
import json
import secrets
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ctf_mentor.tools.local.policy import LocalExecutionPolicy, WorkspaceConfinementError
from ctf_mentor.tools.local.network import AuditEntry

if TYPE_CHECKING:
    from ctf_mentor.workspace.capabilities import IssuedCapabilitySet


@dataclass(frozen=True)
class AuthorizedInvocationRecord:
    """
    Immutable authorization record binding a workspace execution invocation
    to its trusted execution directory and cryptographic token.
    """
    invocation_id: str
    challenge_id: str
    session_id: str
    workspace_id: str
    cwd: Path
    token: str
    active: bool = True


class _TrustedInvocationAuthority:
    """
    Trusted in-memory authority and verifier for authorized local subprocess execution directories.

    Establishes cryptographic and structural binding between:
        challenge/session workspace + invocation_id + subprocess cwd.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: Dict[str, AuthorizedInvocationRecord] = {}

    def register(
        self,
        invocation_id: str,
        challenge_id: str,
        session_id: str,
        workspace_id: str,
        cwd: Path,
        workspace_root: Path,
        token: Optional[str] = None,
    ) -> AuthorizedInvocationRecord:
        """Register an authorized invocation bound to workspace and write its authorization marker."""
        if workspace_root is None:
            raise WorkspaceConfinementError("Registration requires an authorized workspace_root")

        if not isinstance(cwd, Path):
            cwd = Path(cwd)
        if not isinstance(workspace_root, Path):
            workspace_root = Path(workspace_root)

        if not cwd.is_absolute():
            raise WorkspaceConfinementError(f"Authorized cwd must be absolute: {cwd!r}")
        if not workspace_root.is_absolute():
            raise WorkspaceConfinementError(f"Authorized workspace_root must be absolute: {workspace_root!r}")

        if cwd.is_symlink() and cwd != workspace_root:
            raise WorkspaceConfinementError(f"Authorized cwd must not be a symlink: {cwd!r}")
        if workspace_root.is_symlink() and cwd != workspace_root:
            raise WorkspaceConfinementError(
                f"Authorized workspace_root must not be a symlink: {workspace_root!r}"
            )

        resolved_ws = workspace_root.resolve()
        if resolved_ws.is_symlink() or not resolved_ws.exists() or not resolved_ws.is_dir():
            raise WorkspaceConfinementError(
                f"Workspace root directory is invalid, missing, or a symlink: {workspace_root!r}"
            )

        resolved_cwd = cwd.resolve()

        # Reject banned system directories
        _BANNED_SYSTEM_PREFIXES = (
            "/etc", "/sys", "/proc", "/dev", "/boot", "/bin", "/sbin", "/usr",
            r"C:\Windows", r"C:\WINDOWS", r"C:\Program Files", r"C:\Program Files (x86)",
        )
        for bp in _BANNED_SYSTEM_PREFIXES:
            try:
                bp_resolved = Path(bp).resolve()
                if sys.platform == "win32":
                    str_cwd = str(resolved_cwd).lower()
                    str_ws = str(resolved_ws).lower()
                    str_bp = str(bp_resolved).lower()
                    if (
                        str_cwd == str_bp or str_cwd.startswith(str_bp + "\\") or str_cwd.startswith(str_bp + "/")
                        or str_ws == str_bp or str_ws.startswith(str_bp + "\\") or str_ws.startswith(str_bp + "/")
                    ):
                        raise WorkspaceConfinementError(f"Authorized cwd or workspace inside forbidden system directory: {cwd!r}")
                else:
                    if (
                        resolved_cwd == bp_resolved or bp_resolved in resolved_cwd.parents
                        or resolved_ws == bp_resolved or bp_resolved in resolved_ws.parents
                    ):
                        raise WorkspaceConfinementError(f"Authorized cwd or workspace inside forbidden system directory: {cwd!r}")
            except WorkspaceConfinementError:
                raise
            except Exception:
                pass

        # Enforce strict confinement within workspace
        if not resolved_cwd.is_relative_to(resolved_ws):
            raise WorkspaceConfinementError(
                f"Authorized execution cwd {resolved_cwd!r} is not confined within workspace {resolved_ws!r}"
            )

        if token is None:
            token = secrets.token_hex(32)

        resolved_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Write cryptographic authorization marker
        marker_file = resolved_cwd / ".invocation_auth"
        current_data: Dict[str, Any] = {}
        if marker_file.exists():
            try:
                current_data = json.loads(marker_file.read_text(encoding="utf-8"))
            except Exception:
                current_data = {}

        marker_data = {
            "invocation_id": invocation_id,
            "challenge_id": challenge_id,
            "session_id": session_id,
            "workspace_id": workspace_id,
            "token": token,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        if "invocations" in current_data and isinstance(current_data["invocations"], dict):
            current_data["invocations"][invocation_id] = marker_data
        elif current_data and current_data.get("invocation_id") != invocation_id:
            old_id = str(current_data.get("invocation_id", "default"))
            current_data = {"invocations": {old_id: current_data, invocation_id: marker_data}}
        else:
            current_data = marker_data

        marker_file.write_text(json.dumps(current_data), encoding="utf-8")

        record = AuthorizedInvocationRecord(
            invocation_id=invocation_id,
            challenge_id=challenge_id,
            session_id=session_id,
            workspace_id=workspace_id,
            cwd=cwd,
            token=token,
            active=True,
        )
        with self._lock:
            self._records[invocation_id] = record
        return record

    def get_record(self, invocation_id: str) -> Optional[AuthorizedInvocationRecord]:
        """Return active authorized invocation record or None."""
        with self._lock:
            rec = self._records.get(invocation_id)
            if rec is not None and rec.active:
                return rec
            return None

    def revoke(self, invocation_id: str) -> None:
        """Mark invocation authorization record as revoked/inactive."""
        with self._lock:
            rec = self._records.get(invocation_id)
            if rec is not None:
                self._records[invocation_id] = AuthorizedInvocationRecord(
                    invocation_id=rec.invocation_id,
                    challenge_id=rec.challenge_id,
                    session_id=rec.session_id,
                    workspace_id=rec.workspace_id,
                    cwd=rec.cwd,
                    token=rec.token,
                    active=False,
                )

    def clear(self) -> None:
        """Clear all records (primarily for test teardown)."""
        with self._lock:
            self._records.clear()


TRUSTED_INVOCATION_AUTHORITY = _TrustedInvocationAuthority()


@dataclass(frozen=True)
class LocalExecutionContext:
    """
    Per-invocation execution context for a local tool adapter.

    Immutable/frozen per Phase 10B.3 security requirements.
    Adapters receive NO raw filesystem paths (execution_cwd, workspace root, etc.).
    All workspace I/O is capability-mediated; subprocess cwd is resolved
    internally by TrustedInvocationAuthority.

    Fields:
        caps:           Issued workspace capabilities for this invocation.
        policy:         Frozen execution policy for this tool.
        invocation_id:  UUID4 for audit/provenance correlation.
        challenge_id:   Challenge this invocation belongs to.
        session_id:     Session this invocation belongs to.
        workspace_id:   Workspace this invocation belongs to.
        started_at:     UTC timestamp of context creation.
        audit_log:      Append-only list of AuditEntry records.
    """
    caps: "IssuedCapabilitySet"
    policy: LocalExecutionPolicy
    invocation_id: str
    challenge_id: str
    session_id: str
    workspace_id: str
    started_at: datetime.datetime
    audit_log: List[AuditEntry] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        caps: "IssuedCapabilitySet",
        policy: LocalExecutionPolicy,
        challenge_id: str,
        session_id: str,
        workspace_id: str,
    ) -> "LocalExecutionContext":
        """
        Factory that assigns a fresh UUID4 and UTC timestamp, securely deriving and
        registering the authorized execution CWD from capability state.
        """
        from ctf_mentor.tools.local.policy import WorkspaceConfinementError

        invocation_id = str(uuid.uuid4())

        # If work capability is present, derive and validate execution_cwd from workspace boundary
        if caps is not None and getattr(caps, "work_cap", None) is not None:
            work_cap = caps.work_cap

            # Validate capability identity against context
            if (
                str(work_cap.challenge_id) != str(challenge_id)
                or str(work_cap.session_id) != str(session_id)
                or str(work_cap.workspace_id) != str(workspace_id)
            ):
                raise WorkspaceConfinementError(
                    "Cross-session or cross-challenge capability mismatch in workspace binding"
                )

            # Extract workspace handle from capability bound function closure
            write_fn = (
                getattr(work_cap, "_WorkCapability__write_bytes_fn", None)
                or getattr(work_cap, "_write_bytes_fn", None)
            )
            handle = None
            if write_fn is not None and hasattr(write_fn, "__closure__") and write_fn.__closure__:
                for cell in write_fn.__closure__:
                    contents = cell.cell_contents
                    if hasattr(contents, "_root"):
                        handle = contents
                        break

            if handle is not None:
                if (
                    (hasattr(handle, "challenge_id") and str(handle.challenge_id) != str(challenge_id))
                    or (hasattr(handle, "session_id") and str(handle.session_id) != str(session_id))
                    or (hasattr(handle, "workspace_id") and str(handle.workspace_id) != str(workspace_id))
                ):
                    raise WorkspaceConfinementError(
                        "Cross-session or cross-challenge handle mismatch in capability closure"
                    )

                raw_root = Path(handle._root)
                if raw_root.is_symlink():
                    raise WorkspaceConfinementError("Workspace root directory is a symlink")
                root_path = raw_root.resolve()
                if root_path.is_symlink() or not root_path.exists():
                    raise WorkspaceConfinementError("Workspace root directory is invalid or a symlink")

                raw_work = root_path / "work"
                if raw_work.is_symlink():
                    raise WorkspaceConfinementError("Workspace work directory is a symlink")
                work_dir = raw_work.resolve()
                if work_dir.is_symlink() or not work_dir.exists():
                    raise WorkspaceConfinementError("Workspace work directory is invalid or a symlink")

                execution_cwd = (work_dir / invocation_id).resolve()
                if not execution_cwd.is_relative_to(work_dir):
                    raise WorkspaceConfinementError("Execution cwd escapes workspace work boundary")

                execution_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)
                TRUSTED_INVOCATION_AUTHORITY.register(
                    invocation_id=invocation_id,
                    challenge_id=challenge_id,
                    session_id=session_id,
                    workspace_id=workspace_id,
                    cwd=execution_cwd,
                    workspace_root=root_path,
                )

        return cls(
            caps=caps,
            policy=policy,
            invocation_id=invocation_id,
            challenge_id=challenge_id,
            session_id=session_id,
            workspace_id=workspace_id,
            started_at=datetime.datetime.now(datetime.timezone.utc),
            audit_log=[],
        )



class LocalToolAdapter(abc.ABC):
    """
    Abstract base class for all Phase 10B.3 local subprocess tool adapters.

    Subclasses must declare:
        tool_id:                  str constant
        tool_version:             str constant
        execution_class:          ExecutionClass.PASSIVE_LOCAL (static)
        workspace_capability_spec: WorkspaceCapabilitySpec (static, frozen)
        _ARGV_TEMPLATE_NAME:      str constant — name of the argv template used
        sandbox_profile:          SandboxProfile (static, frozen)

    Subclasses must implement:
        validate_input()
        validate_scope()
        execute_local()
        normalize()

    execute() raises RuntimeError to prevent accidental dispatch through the
    Phase 8 orchestration path.
    """

    # --- Subclass must declare these as class-level constants ---
    tool_id: str
    tool_version: str
    _ARGV_TEMPLATE_NAME: str  # name of argv construction template, for provenance
    sandbox_profile: Any = None

    @abc.abstractmethod
    def validate_input(self, raw_args: Dict[str, Any]) -> Any:
        """Validate and return a typed ToolInputSchema instance."""

    @abc.abstractmethod
    def validate_scope(self, target: Any, scope: Any) -> bool:
        """Return True if target is within the authorized scope."""

    @abc.abstractmethod
    def execute_local(
        self,
        validated_input: Any,
        scope: Any,
        ctx: LocalExecutionContext,
    ) -> Any:
        """
        Execute the tool with workspace capabilities.

        MUST revoke ctx.caps in a finally block before returning.
        MUST NOT let ctx.caps escape the scope of this method.
        """

    @abc.abstractmethod
    def normalize(self, raw_data: Any, context: Dict[str, Any]) -> List[Any]:
        """Normalize tool output to a list of EvidenceCandidate objects."""

    def execute(self, *args, **kwargs) -> None:
        """
        Intentionally disabled.

        LocalToolAdapters must be dispatched through execute_local() by the
        LocalToolOrchestrationHandler, not through the Phase 8 execute() path.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError(
            f"{type(self).__name__} is a local tool adapter and must be "
            f"dispatched via execute_local() through the "
            f"LocalToolOrchestrationHandler. Calling execute() directly is "
            f"forbidden. This error is the fail-closed response to an "
            f"incorrect dispatch path."
        )

    def _build_provenance(
        self,
        ctx: LocalExecutionContext,
        result: Any,
        input_filename: str,
        input_size_bytes: int,
    ) -> Dict[str, Any]:
        """
        Build a ToolResult provenance dict.

        Security:
        - Passphrase/secret must NEVER appear here.
        - Full filesystem paths are excluded (basename only).
        - argv template name (not raw argv) is recorded.
        """
        binary_hash = ""
        if ctx.policy.executable_path is not None:
            try:
                raw = ctx.policy.executable_path.read_bytes()
                binary_hash = hashlib.sha256(raw).hexdigest()
            except Exception:
                binary_hash = "unavailable"

        provenance: Dict[str, Any] = {
            "invocation_id": ctx.invocation_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "argv_template": self._ARGV_TEMPLATE_NAME,
            "binary_path": (
                str(ctx.policy.executable_path)
                if ctx.policy.executable_path else "N/A"
            ),
            "binary_sha256": binary_hash,
            "workspace_id": ctx.workspace_id,
            "challenge_id": ctx.challenge_id,
            "session_id": ctx.session_id,
            "timestamp_start": ctx.started_at.isoformat(),
            "timestamp_end": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "input_filename": input_filename,

            "input_size_bytes": input_size_bytes,
        }

        # Merge subprocess result fields if available
        if hasattr(result, "exit_code"):
            provenance.update({
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "killed": result.killed,
                "stdout_truncated": result.stdout_truncated,
                "stderr_truncated": result.stderr_truncated,
                "duration_ms": result.duration_ms,
            })

        return provenance

    @staticmethod
    def _scrub_secrets(provenance: Dict[str, Any], *secrets: str) -> None:
        """
        In-place scrub of any secret string from all string values in
        a provenance dict. Secrets are replaced with '<redacted>'.

        This is a defense-in-depth measure. Secrets should never be
        in provenance in the first place.
        """
        for secret in secrets:
            if not secret:
                continue
            for key, val in list(provenance.items()):
                if isinstance(val, str) and secret in val:
                    provenance[key] = val.replace(secret, "<redacted>")
