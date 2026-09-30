"""
Phase 10B.2 Trusted Workspace Execution Boundary and Capability System.

Defines:
- WorkspaceCapabilitySpec: static, per-adapter declaration of required capabilities.
- WorkspaceCapability: abstract base (ABC) for all capability objects.
- InputCapability: read-only capability for the input/ subdirectory.
- WorkCapability: read/write/delete capability for the work/ subdirectory.
- OutputCapability: read/write capability for the output/ subdirectory (no delete).
- IssuedCapabilitySet: revocable group of capabilities for a single invocation.
- TrustedWorkspaceExecutionBoundary: issues capabilities from trusted state.

ARCHITECTURE RULES ENFORCED HERE:
- Adapter never receives WorkspaceHandle.
- Adapter never receives WorkspacePath.
- Adapter never receives raw workspace paths, directory FDs, or workspace root.
- Adapter never chooses capability permissions.
- User/LLM input never chooses capability permissions.
- Static trusted adapter metadata determines required capabilities.
- WorkspaceCapability is abstract -- cannot be directly instantiated.
- InputCapability exposes NO write or delete API whatsoever.
- OutputCapability exposes NO delete_file API.
- Capabilities hold bound IO functions, NOT a WorkspaceHandle reference.
- No list_files(), no glob()-based workspace traversal.
- Capability methods return inert values only (bytes, str, int, bool).
- Capabilities are revocable.

ACKNOWLEDGED LIMITATION (same-process trust domain):
- Capabilities capture the WorkspaceHandle in function closures.
- Python introspection (gc, ctypes, __closure__) can recover the handle.
- Process-level isolation belongs to a later sandbox phase.
"""

from __future__ import annotations

import abc
import sqlite3
import threading
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, FrozenSet, Optional

if TYPE_CHECKING:
    from ctf_mentor.workspace.manager import WorkspaceManager


class CapabilityRevokedError(Exception):
    """Raised when an operation is attempted on a revoked capability."""
    pass


class CapabilityPermissionError(Exception):
    """Raised when an operation is not allowed by the capability's permissions."""
    pass


class CapabilityPermission(str, Enum):
    """Enumeration of capability permissions for workspace subdirectories."""
    READ_INPUT = "READ_INPUT"
    READ_WORK = "READ_WORK"
    WRITE_WORK = "WRITE_WORK"
    READ_OUTPUT = "READ_OUTPUT"
    WRITE_OUTPUT = "WRITE_OUTPUT"


@dataclass(frozen=True)
class WorkspaceCapabilitySpec:
    """
    Static, immutable declaration of what workspace capabilities a ToolAdapter requires.

    This is declared on the adapter as class-level metadata (trusted, static).
    The TrustedWorkspaceExecutionBoundary reads this spec to issue the minimum
    required capabilities. Neither the user/LLM nor the adapter can expand the
    granted permissions beyond what is specified here.

    Attributes:
        needs_input: Adapter reads from input/ directory (read-only).
        needs_work_read: Adapter reads from work/ directory.
        needs_work_write: Adapter writes to work/ directory.
        needs_output_write: Adapter writes to output/ directory.
        needs_output_read: Adapter reads from output/ directory.
    """
    needs_input: bool = False
    needs_work_read: bool = False
    needs_work_write: bool = False
    needs_output_write: bool = False
    needs_output_read: bool = False

    def required_permissions(self) -> FrozenSet[CapabilityPermission]:
        """Derive the minimal set of required permissions from this spec."""
        perms = set()
        if self.needs_input:
            perms.add(CapabilityPermission.READ_INPUT)
        if self.needs_work_read:
            perms.add(CapabilityPermission.READ_WORK)
        if self.needs_work_write:
            perms.add(CapabilityPermission.WRITE_WORK)
        if self.needs_output_write:
            perms.add(CapabilityPermission.WRITE_OUTPUT)
        if self.needs_output_read:
            perms.add(CapabilityPermission.READ_OUTPUT)
        return frozenset(perms)


# The null spec: adapter does not require any workspace access.
NULL_CAPABILITY_SPEC = WorkspaceCapabilitySpec()


class WorkspaceCapability(abc.ABC):
    """
    Abstract base class for all workspace capability objects.

    Cannot be directly instantiated. Only concrete subclasses
    (InputCapability, WorkCapability, OutputCapability) can be instantiated,
    and only by TrustedWorkspaceExecutionBoundary.

    Adapter-facing objects NEVER hold a WorkspaceHandle reference or WorkspacePath.
    IO operations are delegated through bound functions captured at issuance time.
    The WorkspaceHandle is captured ONLY in closures inside TrustedWorkspaceExecutionBoundary.
    """

    def __init__(
        self,
        workspace_id: str,
        challenge_id: str,
        session_id: str,
        subdir: str,
    ) -> None:
        # Inert identity strings only. No handle, no path, no FD.
        self.__workspace_id = workspace_id
        self.__challenge_id = challenge_id
        self.__session_id = session_id
        self.__subdir = subdir
        self.__revoked = False
        self.__lock = threading.Lock()

    @property
    def workspace_id(self) -> str:
        """Inert workspace identifier string."""
        return self.__workspace_id

    @property
    def challenge_id(self) -> str:
        """Inert challenge identifier string."""
        return self.__challenge_id

    @property
    def session_id(self) -> str:
        """Inert session identifier string."""
        return self.__session_id

    def revoke(self) -> None:
        """Revoke this capability. After revocation all operations raise CapabilityRevokedError."""
        with self.__lock:
            self.__revoked = True

    @property
    def is_revoked(self) -> bool:
        """True if this capability has been revoked."""
        with self.__lock:
            return self.__revoked

    def _check_live(self) -> None:
        """Raise CapabilityRevokedError if this capability has been revoked."""
        with self.__lock:
            if self.__revoked:
                raise CapabilityRevokedError(
                    f"{type(self).__name__} for workspace {self.__workspace_id!r} "
                    f"subdir {self.__subdir!r} has been revoked."
                )

    def __repr__(self) -> str:
        status = "revoked" if self.is_revoked else "live"
        return (
            f"<{type(self).__name__} workspace_id={self.__workspace_id!r} "
            f"subdir={self.__subdir!r} {status}>"
        )

    # Abstract read interface shared by all concrete subclasses.
    # write_bytes, write_text, delete_file are NOT on the abstract base.
    # They are defined only on the subclasses that grant those permissions.

    @abc.abstractmethod
    def read_bytes(self, relative_path: str) -> bytes:
        """Read bytes from relative_path in this capability's subdirectory."""

    @abc.abstractmethod
    def read_text(self, relative_path: str, encoding: str = "utf-8") -> str:
        """Read text from relative_path in this capability's subdirectory."""

    @abc.abstractmethod
    def file_exists(self, relative_path: str) -> bool:
        """Return True if relative_path exists in this capability's subdirectory."""


class InputCapability(WorkspaceCapability):
    """
    Read-only capability for the input/ subdirectory.

    Exposes: read_bytes, read_text, file_exists.
    Does NOT expose: write_bytes, write_text, delete_file.
    These methods do not exist on this class.
    """

    def __init__(
        self,
        workspace_id: str,
        challenge_id: str,
        session_id: str,
        *,
        _read_bytes_fn: Callable[[str], bytes],
        _read_text_fn: Callable[[str, str], str],
        _file_exists_fn: Callable[[str], bool],
    ) -> None:
        super().__init__(workspace_id, challenge_id, session_id, "input")
        # Bound IO functions only. No handle, no path, no FD.
        self.__read_bytes_fn = _read_bytes_fn
        self.__read_text_fn = _read_text_fn
        self.__file_exists_fn = _file_exists_fn

    def read_bytes(self, relative_path: str) -> bytes:
        """Read bytes from input/relative_path. Returns inert bytes only."""
        self._check_live()
        return self.__read_bytes_fn(relative_path)

    def read_text(self, relative_path: str, encoding: str = "utf-8") -> str:
        """Read text from input/relative_path. Returns inert str only."""
        self._check_live()
        return self.__read_text_fn(relative_path, encoding)

    def file_exists(self, relative_path: str) -> bool:
        """Return True if input/relative_path exists. Returns inert bool only."""
        self._check_live()
        return self.__file_exists_fn(relative_path)


class WorkCapability(WorkspaceCapability):
    """
    Read/write/delete capability for the work/ subdirectory.

    Exposes: read_bytes, read_text, file_exists, write_bytes, write_text, delete_file.
    Scoped strictly to work/.
    """

    def __init__(
        self,
        workspace_id: str,
        challenge_id: str,
        session_id: str,
        *,
        _read_bytes_fn: Callable[[str], bytes],
        _read_text_fn: Callable[[str, str], str],
        _file_exists_fn: Callable[[str], bool],
        _write_bytes_fn: Callable[[str, bytes], int],
        _write_text_fn: Callable[[str, str, str], int],
        _delete_file_fn: Callable[[str, bool], None],
    ) -> None:
        super().__init__(workspace_id, challenge_id, session_id, "work")
        self.__read_bytes_fn = _read_bytes_fn
        self.__read_text_fn = _read_text_fn
        self.__file_exists_fn = _file_exists_fn
        self.__write_bytes_fn = _write_bytes_fn
        self.__write_text_fn = _write_text_fn
        self.__delete_file_fn = _delete_file_fn

    def read_bytes(self, relative_path: str) -> bytes:
        """Read bytes from work/relative_path. Returns inert bytes only."""
        self._check_live()
        return self.__read_bytes_fn(relative_path)

    def read_text(self, relative_path: str, encoding: str = "utf-8") -> str:
        """Read text from work/relative_path. Returns inert str only."""
        self._check_live()
        return self.__read_text_fn(relative_path, encoding)

    def file_exists(self, relative_path: str) -> bool:
        """Return True if work/relative_path exists. Returns inert bool only."""
        self._check_live()
        return self.__file_exists_fn(relative_path)

    def write_bytes(self, relative_path: str, data: bytes) -> int:
        """Write bytes to work/relative_path. Returns inert int (bytes written)."""
        self._check_live()
        return self.__write_bytes_fn(relative_path, data)

    def write_text(self, relative_path: str, data: str, encoding: str = "utf-8") -> int:
        """Write text to work/relative_path. Returns inert int (chars written)."""
        self._check_live()
        return self.__write_text_fn(relative_path, data, encoding)

    def delete_file(self, relative_path: str, missing_ok: bool = False) -> None:
        """Delete work/relative_path."""
        self._check_live()
        self.__delete_file_fn(relative_path, missing_ok)


class OutputCapability(WorkspaceCapability):
    """
    Read/write capability for the output/ subdirectory.

    Exposes: read_bytes, read_text, file_exists, write_bytes, write_text.
    Does NOT expose: delete_file. Output is append-only by policy.
    Scoped strictly to output/.
    """

    def __init__(
        self,
        workspace_id: str,
        challenge_id: str,
        session_id: str,
        *,
        _read_bytes_fn: Callable[[str], bytes],
        _read_text_fn: Callable[[str, str], str],
        _file_exists_fn: Callable[[str], bool],
        _write_bytes_fn: Callable[[str, bytes], int],
        _write_text_fn: Callable[[str, str, str], int],
    ) -> None:
        super().__init__(workspace_id, challenge_id, session_id, "output")
        self.__read_bytes_fn = _read_bytes_fn
        self.__read_text_fn = _read_text_fn
        self.__file_exists_fn = _file_exists_fn
        self.__write_bytes_fn = _write_bytes_fn
        self.__write_text_fn = _write_text_fn

    def read_bytes(self, relative_path: str) -> bytes:
        """Read bytes from output/relative_path. Returns inert bytes only."""
        self._check_live()
        return self.__read_bytes_fn(relative_path)

    def read_text(self, relative_path: str, encoding: str = "utf-8") -> str:
        """Read text from output/relative_path. Returns inert str only."""
        self._check_live()
        return self.__read_text_fn(relative_path, encoding)

    def file_exists(self, relative_path: str) -> bool:
        """Return True if output/relative_path exists. Returns inert bool only."""
        self._check_live()
        return self.__file_exists_fn(relative_path)

    def write_bytes(self, relative_path: str, data: bytes) -> int:
        """Write bytes to output/relative_path. Returns inert int (bytes written)."""
        self._check_live()
        return self.__write_bytes_fn(relative_path, data)

    def write_text(self, relative_path: str, data: str, encoding: str = "utf-8") -> int:
        """Write text to output/relative_path. Returns inert int (chars written)."""
        self._check_live()
        return self.__write_text_fn(relative_path, data, encoding)

    # delete_file is intentionally NOT defined on OutputCapability.


@dataclass
class IssuedCapabilitySet:
    """
    The result of capability issuance for a single tool invocation.

    Only capabilities that were actually requested (per WorkspaceCapabilitySpec)
    are set. Unrequested capabilities are None -- never granted.
    """
    input_cap: Optional[InputCapability] = None
    work_cap: Optional[WorkCapability] = None
    output_cap: Optional[OutputCapability] = None

    def revoke_all(self) -> None:
        """Revoke all capabilities in this set simultaneously."""
        for cap in (self.input_cap, self.work_cap, self.output_cap):
            if cap is not None:
                cap.revoke()

    @property
    def all_revoked(self) -> bool:
        """True if every issued capability has been revoked (or none were issued)."""
        caps = [c for c in (self.input_cap, self.work_cap, self.output_cap) if c is not None]
        if not caps:
            return True
        return all(c.is_revoked for c in caps)


def _make_subdir_io(handle: object, subdir: str) -> dict:
    """
    Build a dict of bound IO functions for the given handle + subdir.

    The handle is captured in closures here. It is NOT stored on any
    adapter-visible capability object. This is the acknowledged same-process
    trust domain limitation documented in the module docstring.
    """

    def _read_bytes(rel_path: str) -> bytes:
        return handle.read_bytes(subdir, rel_path)  # type: ignore[attr-defined]

    def _read_text(rel_path: str, encoding: str = "utf-8") -> str:
        return handle.read_text(subdir, rel_path, encoding=encoding)  # type: ignore[attr-defined]

    def _file_exists(rel_path: str) -> bool:
        try:
            wp = handle.resolve(subdir, rel_path)  # type: ignore[attr-defined]
            return wp.is_file()
        except Exception:
            return False

    def _write_bytes(rel_path: str, data: bytes) -> int:
        return handle.write_bytes(subdir, rel_path, data)  # type: ignore[attr-defined]

    def _write_text(rel_path: str, data: str, encoding: str = "utf-8") -> int:
        return handle.write_text(subdir, rel_path, data, encoding=encoding)  # type: ignore[attr-defined]

    def _delete_file(rel_path: str, missing_ok: bool = False) -> None:
        handle.delete_file(subdir, rel_path, missing_ok=missing_ok)  # type: ignore[attr-defined]

    return {
        "read_bytes": _read_bytes,
        "read_text": _read_text,
        "file_exists": _file_exists,
        "write_bytes": _write_bytes,
        "write_text": _write_text,
        "delete_file": _delete_file,
    }


class TrustedWorkspaceExecutionBoundary:
    """
    Trusted issuer of workspace capabilities.

    Resolves the canonical WorkspaceHandle from trusted WorkspaceManager state.
    Callers do NOT supply a WorkspaceHandle -- the boundary is the authority
    that obtains it from trusted infrastructure.

    The handle is retained only in this boundary and in IO closures.
    It is NEVER exposed to adapter code.

    Usage:
        boundary = TrustedWorkspaceExecutionBoundary(
            manager, conn, challenge_id, session_id
        )
        caps = boundary.issue(adapter.workspace_capability_spec)
        try:
            result = adapter.execute_with_workspace(...)
        finally:
            caps.revoke_all()
    """

    def __init__(
        self,
        manager: "WorkspaceManager",
        conn: sqlite3.Connection,
        challenge_id: str,
        session_id: str,
    ) -> None:
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError(
                f"conn must be a sqlite3.Connection, got {type(conn).__name__!r}"
            )
        # Resolve canonical handle from trusted infrastructure.
        # Handle is NOT exposed publicly; only identity strings are extracted.
        handle = manager.get_or_create(conn, challenge_id, session_id)
        self.__workspace_id: str = handle.workspace_id
        self.__challenge_id: str = handle.challenge_id
        self.__session_id: str = handle.session_id
        # Build IO function tables. Handle captured in closures only.
        self.__input_io = _make_subdir_io(handle, "input")
        self.__work_io = _make_subdir_io(handle, "work")
        self.__output_io = _make_subdir_io(handle, "output")

    def issue(self, spec: WorkspaceCapabilitySpec) -> IssuedCapabilitySet:
        """
        Issue the minimum required capabilities declared by the given spec.

        Args:
            spec: Static WorkspaceCapabilitySpec from ToolAdapter class-level metadata.

        Returns:
            IssuedCapabilitySet with exactly the capabilities declared in spec.

        Raises:
            TypeError: If spec is not a WorkspaceCapabilitySpec instance.
        """
        if not isinstance(spec, WorkspaceCapabilitySpec):
            raise TypeError(
                f"spec must be a WorkspaceCapabilitySpec, got {type(spec).__name__!r}"
            )

        input_cap: Optional[InputCapability] = None
        work_cap: Optional[WorkCapability] = None
        output_cap: Optional[OutputCapability] = None

        if spec.needs_input:
            io = self.__input_io
            input_cap = InputCapability(
                self.__workspace_id, self.__challenge_id, self.__session_id,
                _read_bytes_fn=io["read_bytes"],
                _read_text_fn=io["read_text"],
                _file_exists_fn=io["file_exists"],
            )

        if spec.needs_work_read or spec.needs_work_write:
            io = self.__work_io
            work_cap = WorkCapability(
                self.__workspace_id, self.__challenge_id, self.__session_id,
                _read_bytes_fn=io["read_bytes"],
                _read_text_fn=io["read_text"],
                _file_exists_fn=io["file_exists"],
                _write_bytes_fn=io["write_bytes"],
                _write_text_fn=io["write_text"],
                _delete_file_fn=io["delete_file"],
            )

        if spec.needs_output_write or spec.needs_output_read:
            io = self.__output_io
            output_cap = OutputCapability(
                self.__workspace_id, self.__challenge_id, self.__session_id,
                _read_bytes_fn=io["read_bytes"],
                _read_text_fn=io["read_text"],
                _file_exists_fn=io["file_exists"],
                _write_bytes_fn=io["write_bytes"],
                _write_text_fn=io["write_text"],
            )

        return IssuedCapabilitySet(
            input_cap=input_cap,
            work_cap=work_cap,
            output_cap=output_cap,
        )

    @property
    def workspace_id(self) -> str:
        """Inert workspace identifier string."""
        return self.__workspace_id

    @property
    def challenge_id(self) -> str:
        """Inert challenge identifier string."""
        return self.__challenge_id

    @property
    def session_id(self) -> str:
        """Inert session identifier string."""
        return self.__session_id

    def __repr__(self) -> str:
        return (
            f"<TrustedWorkspaceExecutionBoundary "
            f"workspace_id={self.__workspace_id!r}>"
        )
