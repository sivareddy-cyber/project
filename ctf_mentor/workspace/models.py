"""
Models and dataclasses for Phase 10B.1 Workspace Isolation.

Defines WorkspaceStatus enum, WorkspaceHandle capability object, and workspace exceptions.
"""

from __future__ import annotations

import os
import stat as stat_module
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Union, Optional


class WorkspaceStatus(str, Enum):
    """Lifecycle status of a local workspace."""
    CREATING = "CREATING"
    READY = "READY"
    EXPIRED = "EXPIRED"
    QUARANTINED = "QUARANTINED"


class WorkspaceError(Exception):
    """Base exception for workspace isolation operations."""
    pass


class WorkspaceValidationError(WorkspaceError):
    """Raised when workspace validation or challenge/session binding fails."""
    pass


class WorkspaceStatusError(WorkspaceError):
    """Raised when attempting to operate on an invalid, expired, or quarantined workspace."""
    pass


class PathConfinementError(WorkspaceError):
    """Raised when path resolution violates workspace boundary or traversal rules."""
    pass


class QuotaExceededError(WorkspaceError):
    """Raised when a workspace operation exceeds maximum file size or total disk quota."""
    pass


class ArtifactIntegrityError(WorkspaceError):
    """Raised when artifact SHA-256 integrity verification fails."""
    pass


class ArtifactSecurityError(WorkspaceError):
    """Raised when an artifact violates hard-link or symlink security invariants."""
    pass


class WorkspaceLockError(WorkspaceError):
    """Raised when cross-process workspace lock acquisition fails."""
    pass



_ALLOWED_SUBDIRS = ("input", "work", "output")

# Windows reserved device names
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def calculate_workspace_root_size(root: Path) -> int:
    """Calculate total size of all regular files in the workspace directory."""
    total_size = 0
    try:
        resolved_root = root.resolve()
        for dirpath, _, filenames in os.walk(resolved_root):
            for f in filenames:
                if f == ".workspace.lock":
                    continue
                fp = Path(dirpath) / f
                try:
                    if not fp.is_symlink():
                        total_size += fp.stat().st_size
                except (OSError, ValueError):
                    pass
    except (OSError, ValueError):
        pass
    return total_size


@dataclass
class WorkspaceRecord:
    """Database record representation for local_workspaces table."""
    workspace_id: str
    challenge_id: str
    session_id: str
    relative_root: str
    status: str
    created_at: str
    updated_at: str
    expires_at: Union[str, None] = None


@dataclass(frozen=True)
class WorkspaceHandle:
    """Capability-style handle representing an isolated workspace for a (challenge_id, session_id).

    Exposes input_dir(), work_dir(), output_dir(), and resolve(subdir, relative_path).
    Does NOT expose raw unrestricted filesystem access.
    Retains immutable reference and device/inode stat identity to global workspace root of trust to prevent post-issuance symlink escapes.
    """

    workspace_id: str
    challenge_id: str
    session_id: str
    status: str
    _root: Path
    _global_root: Optional[Path] = None
    _global_root_dev_ino: Optional[tuple[int, int]] = None
    _root_dev_ino: Optional[tuple[int, int]] = None
    max_file_bytes: int = 50 * 1024 * 1024
    default_quota_bytes: int = 100 * 1024 * 1024

    def __post_init__(self) -> None:
        """Capture immutable global root path and device/inode stat identities at handle creation time."""
        g_root = self._global_root
        if g_root is None:
            try:
                g_root = self._root.parent.parent.resolve()
            except Exception:
                g_root = self._root.parent.parent
            object.__setattr__(self, "_global_root", g_root)

        if self._global_root_dev_ino is None and g_root is not None:
            try:
                st = g_root.resolve().stat()
                object.__setattr__(self, "_global_root_dev_ino", (st.st_dev, st.st_ino))
            except Exception:
                pass

        if self._root_dev_ino is None and self._root is not None:
            try:
                st = self._root.resolve().stat()
                object.__setattr__(self, "_root_dev_ino", (st.st_dev, st.st_ino))
            except Exception:
                pass

    def _get_global_root(self) -> Path:
        """Internal helper returning original authorized global workspace root path."""
        if self._global_root is not None:
            return self._global_root
        return self._root.parent.parent

    def _validate_handle_root_confinement(self) -> tuple[Path, Path]:
        """Validate that _root and all path components between global workspace root and _root remain inside global workspace root.

        Enforces immutable device and inode stat identity matching for global root and workspace root.
        Fails closed by raising PathConfinementError if global root or workspace root has been replaced, symlinked, or moved.
        Returns tuple of (global_root_resolved, root_resolved).
        """
        global_root = self._get_global_root()

        # 1. Global root existence check
        if not global_root.exists():
            raise PathConfinementError(f"Global workspace root '{global_root}' does not exist.")

        # 2. Check if global root or any parent component is a symlink
        curr_g = global_root
        while curr_g != curr_g.parent:
            if curr_g.is_symlink():
                raise PathConfinementError(
                    f"Global workspace root path component '{curr_g}' is a symlink and violates confinement boundary."
                )
            curr_g = curr_g.parent

        # 3. Canonical resolution of global root must match original authorized path
        try:
            global_root_resolved = global_root.resolve()
            if global_root_resolved != global_root:
                raise PathConfinementError(
                    f"Global workspace root '{global_root}' resolved to '{global_root_resolved}', "
                    f"violating namespace immutability."
                )
        except OSError as e:
            raise PathConfinementError(f"Global workspace root resolution error: {e}")

        # 4. Immutable Device & Inode identity verification for global workspace root
        if self._global_root_dev_ino is not None:
            try:
                g_st = global_root_resolved.stat()
                if (g_st.st_dev, g_st.st_ino) != self._global_root_dev_ino:
                    raise PathConfinementError(
                        f"Global workspace root '{self._global_root}' has been replaced or modified on disk."
                    )
            except OSError as e:
                raise PathConfinementError(f"Global workspace root access error: {e}")

        # 5. Check workspace root existence
        if not self._root.exists():
            raise PathConfinementError(f"Workspace root '{self._root}' does not exist.")

        # 6. Check if workspace root or any intermediate component is a symlink
        rel_parts = [p for p in f"{self.challenge_id}/{self.session_id}".replace("\\", "/").split("/") if p and p != "."]
        curr = global_root_resolved
        for part in rel_parts:
            curr = curr / part
            if curr.is_symlink():
                raise PathConfinementError(
                    f"Workspace path component '{part}' is a symlink and violates confinement boundary."
                )
            if curr.exists():
                curr_resolved = curr.resolve()
                try:
                    curr_resolved.relative_to(global_root_resolved)
                except ValueError:
                    raise PathConfinementError(
                        f"Workspace path component '{part}' resolved to '{curr_resolved}', "
                        f"which escapes global workspace root '{global_root_resolved}'."
                    )

        # 7. Canonical resolution of workspace root
        root_resolved = self._root.resolve()

        # 8. Immutable Device & Inode identity verification for workspace handle root
        if self._root_dev_ino is not None:
            try:
                r_st = root_resolved.stat()
                if (r_st.st_dev, r_st.st_ino) != self._root_dev_ino:
                    raise PathConfinementError(
                        f"Workspace handle root '{self._root}' has been replaced or modified on disk."
                    )
            except OSError as e:
                raise PathConfinementError(f"Workspace root access error: {e}")

        # 9. Target must be relative to global workspace root
        try:
            root_resolved.relative_to(global_root_resolved)
        except ValueError:
            raise PathConfinementError(
                f"Workspace handle root '{root_resolved}' escapes global workspace root '{global_root_resolved}'."
            )

        return global_root_resolved, root_resolved

    def _get_validated_subdir(self, subdir: str) -> Path:
        """Centralized safe subdirectory resolution and confinement validation.

        Ensures that input, work, output subdirectories:
        1. Are strictly in ("input", "work", "output")
        2. Workspace handle root and parents pass _validate_handle_root_confinement against global workspace root
        3. Subdirectory itself is not a symlink
        4. Subdirectory exists and is an actual directory
        5. Subdirectory resolves strictly inside both root_resolved AND global_root_resolved
        """
        if subdir not in _ALLOWED_SUBDIRS:
            raise PathConfinementError(
                f"Invalid workspace subdirectory {subdir!r}. Allowed: {_ALLOWED_SUBDIRS}"
            )

        global_root_resolved, root_resolved = self._validate_handle_root_confinement()
        raw_subdir = self._root / subdir

        # Reject symlinked subdirectories
        if raw_subdir.is_symlink():
            raise PathConfinementError(
                f"Workspace subdirectory {subdir!r} is a symlink and violates confinement boundary."
            )

        if not raw_subdir.exists() or not raw_subdir.is_dir():
            raise PathConfinementError(
                f"Workspace subdirectory {subdir!r} does not exist or is not a directory."
            )

        resolved_subdir = raw_subdir.resolve()

        try:
            rel = resolved_subdir.relative_to(root_resolved)
            if rel == Path("."):
                raise PathConfinementError(
                    f"Workspace subdirectory {subdir!r} cannot be workspace root itself."
                )
        except ValueError:
            raise PathConfinementError(
                f"Subdirectory confinement violation: subdirectory {subdir!r} resolved to '{resolved_subdir}', "
                f"which escapes workspace root '{root_resolved}'."
            )

        try:
            resolved_subdir.relative_to(global_root_resolved)
        except ValueError:
            raise PathConfinementError(
                f"Subdirectory confinement violation: subdirectory {subdir!r} resolved to '{resolved_subdir}', "
                f"which escapes global workspace root '{global_root_resolved}'."
            )

        return resolved_subdir

    def _resolve_raw(self, subdir: str, relative_path: Union[str, Path]) -> Path:
        """Private internal helper resolving a raw Path inside workspace for internal manager capability descriptors."""
        if subdir not in _ALLOWED_SUBDIRS:
            raise PathConfinementError(
                f"Invalid workspace subdirectory {subdir!r}. Allowed: {_ALLOWED_SUBDIRS}"
            )

        subdir_root = self._get_validated_subdir(subdir)
        global_root_resolved, root_resolved = self._validate_handle_root_confinement()

        rel_str = str(relative_path).strip()

        # 1. NUL byte check
        if "\x00" in rel_str:
            raise PathConfinementError("Path contains forbidden NUL byte.")

        # 2. Check empty or current dir
        if not rel_str or rel_str in (".", "./", ".\\"):
            return subdir_root

        # 3. Check for absolute path on POSIX or Windows
        p_obj = Path(rel_str)
        if p_obj.is_absolute() or os.path.isabs(rel_str):
            raise PathConfinementError(f"Absolute paths forbidden: {rel_str!r}")

        if rel_str.startswith(("/", "\\")) or (len(rel_str) >= 2 and rel_str[1] == ":"):
            raise PathConfinementError(f"Absolute or drive path forbidden: {rel_str!r}")

        if rel_str.startswith(("\\\\", "//")):
            raise PathConfinementError(f"UNC network path forbidden: {rel_str!r}")

        # 4. Check for explicit path traversal tokens
        norm_str = rel_str.replace("\\", "/")
        parts = [p for p in norm_str.split("/") if p and p != "."]
        if ".." in parts:
            raise PathConfinementError(f"Path traversal ('..') forbidden: {rel_str!r}")

        # Check for Windows reserved filenames
        for part in parts:
            stem = part.split(".")[0].upper()
            if stem in _WINDOWS_RESERVED_NAMES:
                raise PathConfinementError(f"Windows reserved filename forbidden: {part!r}")

        # 5. Construct raw target path
        try:
            raw_target = subdir_root.joinpath(*parts)
        except Exception as e:
            raise PathConfinementError(f"Invalid path specification: {e}")

        # 6. Canonical resolution to check symlink escapes
        if raw_target.exists():
            resolved_target = raw_target.resolve()
            try:
                resolved_target.relative_to(subdir_root)
                resolved_target.relative_to(root_resolved)
                resolved_target.relative_to(global_root_resolved)
            except ValueError:
                raise PathConfinementError(
                    f"Path confinement violation: target '{rel_str}' resolved to '{resolved_target}', "
                    f"which escapes workspace root."
                )
            return resolved_target
        else:
            parent_resolved = raw_target.parent.resolve()
            try:
                parent_resolved.relative_to(subdir_root)
                parent_resolved.relative_to(root_resolved)
                parent_resolved.relative_to(global_root_resolved)
            except ValueError:
                raise PathConfinementError(
                    f"Path confinement violation: target parent resolved to '{parent_resolved}', "
                    f"which escapes workspace root."
                )
            return raw_target

    def input_dir(self) -> WorkspacePath:
        """Returns confined WorkspacePath capability for input directory."""
        self._get_validated_subdir("input")
        return WorkspacePath(self, "input")

    def work_dir(self) -> WorkspacePath:
        """Returns confined WorkspacePath capability for work directory."""
        self._get_validated_subdir("work")
        return WorkspacePath(self, "work")

    def output_dir(self) -> WorkspacePath:
        """Returns confined WorkspacePath capability for output directory."""
        self._get_validated_subdir("output")
        return WorkspacePath(self, "output")

    def resolve(self, subdir: str, relative_path: Union[str, Path] = "") -> WorkspacePath:
        """Safely resolve a WorkspacePath capability within a specific workspace subdirectory."""
        wp = WorkspacePath(self, subdir, relative_path)
        wp._resolve_and_validate()
        return wp

    def read_bytes(self, subdir: str, relative_path: Union[str, Path]) -> bytes:
        return self.resolve(subdir, relative_path).read_bytes()

    def read_text(self, subdir: str, relative_path: Union[str, Path], encoding: str = "utf-8") -> str:
        return self.resolve(subdir, relative_path).read_text(encoding=encoding)

    def write_bytes(self, subdir: str, relative_path: Union[str, Path], data: bytes) -> int:
        return self.resolve(subdir, relative_path).write_bytes(data)

    def write_text(self, subdir: str, relative_path: Union[str, Path], data: str, encoding: str = "utf-8") -> int:
        return self.resolve(subdir, relative_path).write_text(data, encoding=encoding)

    def delete_file(self, subdir: str, relative_path: Union[str, Path], missing_ok: bool = False) -> None:
        self.resolve(subdir, relative_path).unlink(missing_ok=missing_ok)


class WorkspacePath:
    """Capability-style object representing a confined path bound to a WorkspaceHandle.

    All filesystem operations (read, write, unlink, open, stat) are strictly anchored
    to descriptor-relative _DirCapability directory capabilities to prevent check/use TOCTOU races.
    """

    def __init__(
        self,
        handle: WorkspaceHandle,
        subdir: str,
        relative_path: Union[str, Path, WorkspacePath] = "",
    ) -> None:
        self._handle = handle
        self._subdir = str(subdir).strip("/\\")
        if isinstance(relative_path, WorkspacePath):
            self._rel_path = relative_path._rel_path
        else:
            self._rel_path = Path(relative_path) if relative_path else Path(".")

    @property
    def handle(self) -> WorkspaceHandle:
        return self._handle

    @property
    def subdir(self) -> str:
        return self._subdir

    @property
    def relative_path(self) -> Path:
        return self._rel_path

    def _get_safe_relative_str(self) -> str:
        rel_str = str(self._rel_path).strip()
        if "\x00" in rel_str:
            raise PathConfinementError("Path contains forbidden NUL byte.")
        if not rel_str or rel_str in (".", "./", ".\\"):
            raise PathConfinementError("Capability operation requires a relative filename.")

        p_obj = Path(rel_str)
        if p_obj.is_absolute() or os.path.isabs(rel_str) or rel_str.startswith(("/", "\\")) or (len(rel_str) >= 2 and rel_str[1] == ":") or rel_str.startswith(("\\\\", "//")):
            raise PathConfinementError(f"Absolute paths forbidden: {rel_str!r}")

        norm_str = rel_str.replace("\\", "/")
        parts = [p for p in norm_str.split("/") if p and p != "."]
        if ".." in parts:
            raise PathConfinementError(f"Path traversal ('..') forbidden: {rel_str!r}")

        for part in parts:
            stem = part.split(".")[0].upper()
            if stem in _WINDOWS_RESERVED_NAMES:
                raise PathConfinementError(f"Windows reserved filename forbidden: {part!r}")

        return "/".join(parts)

    def _resolve_and_validate(self) -> tuple[Path, Path, Path]:
        """Re-validate workspace handle confinement & subdirectory boundary on EVERY access."""
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_resolved = self._handle._get_validated_subdir(self._subdir)

        rel_str = str(self._rel_path).strip()
        if not rel_str or rel_str in (".", "./", ".\\"):
            return subdir_resolved, subdir_resolved, global_root_resolved

        target_resolved = self._handle._resolve_raw(self._subdir, rel_str)
        return target_resolved, subdir_resolved, global_root_resolved

    def __truediv__(self, other: Union[str, Path, WorkspacePath]) -> WorkspacePath:
        if isinstance(other, WorkspacePath):
            other_path = other._rel_path
        else:
            other_path = Path(other)
        if str(self._rel_path) in (".", ""):
            new_rel = other_path
        else:
            new_rel = self._rel_path / other_path
        return WorkspacePath(self._handle, self._subdir, new_rel)

    def write_bytes(self, data: bytes) -> int:
        """Race-safe descriptor-anchored file write via _DirCapability under cross-process lock and quota limits."""
        from ctf_mentor.workspace.manager import _CrossProcessWorkspaceLock, _DirCapability, is_dir_fd_supported
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = self._get_safe_relative_str()

        eff_max_file = getattr(self._handle, "max_file_bytes", 50 * 1024 * 1024)
        eff_quota = getattr(self._handle, "default_quota_bytes", 100 * 1024 * 1024)

        data_len = len(data)
        if data_len > eff_max_file:
            raise QuotaExceededError(f"File write size ({data_len} bytes) exceeds maximum file limit ({eff_max_file} bytes).")

        lock_path = root_resolved / ".workspace.lock"
        with _CrossProcessWorkspaceLock(lock_path, handle=self._handle):
            current_size = calculate_workspace_root_size(root_resolved)
            if current_size + data_len > eff_quota:
                raise QuotaExceededError(
                    f"Workspace disk quota exceeded ({current_size + data_len} / {eff_quota} bytes used)."
                )

            with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
                parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_str)
                try:
                    temp_name = f".staging_tmp_{uuid.uuid4().hex}"
                    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
                    try:
                        st_fd = os.fstat(fd)
                        if getattr(st_fd, "st_nlink", 1) > 1:
                            raise ArtifactSecurityError("Suspicious multi-link file detected during write.")
                        with open(fd, "wb", closefd=True) as f_out:
                            f_out.write(data)
                            f_out.flush()
                            if hasattr(os, "fsync"):
                                try:
                                    os.fsync(f_out.fileno())
                                except OSError:
                                    pass
                        os.rename(temp_name, final_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                        return data_len
                    except Exception:
                        try:
                            os.unlink(temp_name, dir_fd=parent_fd)
                        except Exception:
                            pass
                        raise
                finally:
                    cap.close_fds(opened_fds)

    def write_text(self, data: str, encoding: str = "utf-8", errors: Optional[str] = None) -> int:
        """Race-safe descriptor-anchored text write via _DirCapability."""
        encoded = data.encode(encoding, errors=errors or "strict")
        self.write_bytes(encoded)
        return len(data)

    def read_bytes(self) -> bytes:
        """Race-safe descriptor-anchored file read via _DirCapability."""
        from ctf_mentor.workspace.manager import _DirCapability
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = self._get_safe_relative_str()

        with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
            parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_str)
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(final_name, flags, dir_fd=parent_fd)
                try:
                    st_fd = os.fstat(fd)
                    if getattr(st_fd, "st_nlink", 1) > 1:
                        raise ArtifactSecurityError(f"Suspicious multi-link file detected during read (st_nlink={st_fd.st_nlink} > 1).")
                    with open(fd, "rb", closefd=True) as f_in:
                        return f_in.read()
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
            finally:
                cap.close_fds(opened_fds)

    def read_text(self, encoding: str = "utf-8", errors: Optional[str] = None) -> str:
        """Race-safe descriptor-anchored text read via _DirCapability."""
        b_data = self.read_bytes()
        return b_data.decode(encoding, errors=errors or "strict")

    def unlink(self, missing_ok: bool = False) -> None:
        """Race-safe descriptor-anchored file unlink via _DirCapability under cross-process lock."""
        from ctf_mentor.workspace.manager import _CrossProcessWorkspaceLock, _DirCapability, is_dir_fd_supported
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = self._get_safe_relative_str()

        lock_path = root_resolved / ".workspace.lock"
        with _CrossProcessWorkspaceLock(lock_path, handle=self._handle):
            with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
                parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_str)
                try:
                    if not hasattr(os, "supports_dir_fd") or os.unlink not in os.supports_dir_fd:
                        raise PathConfinementError("Race-safe unlink requires dir_fd support.")
                    os.unlink(final_name, dir_fd=parent_fd)
                except PathConfinementError:
                    raise
                except OSError as e:
                    if missing_ok and getattr(e, "errno", None) == getattr(os, "ENOENT", 2):
                        return
                    raise
                finally:
                    cap.close_fds(opened_fds)

    def rmdir(self) -> None:
        """Remove empty directory capability target under descriptor-anchored dir_fd."""
        from ctf_mentor.workspace.manager import _CrossProcessWorkspaceLock, _DirCapability, is_dir_fd_supported
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = self._get_safe_relative_str()

        lock_path = root_resolved / ".workspace.lock"
        with _CrossProcessWorkspaceLock(lock_path, handle=self._handle):
            with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
                parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_str)
                try:
                    if hasattr(os, "rmdir") and os.rmdir in os.supports_dir_fd:
                        os.rmdir(final_name, dir_fd=parent_fd)
                    else:
                        raise PathConfinementError("Descriptor-relative rmdir is unsupported on this platform.")
                except PathConfinementError:
                    raise
                except OSError as e:
                    raise
                finally:
                    cap.close_fds(opened_fds)

    def open(
        self,
        mode: str = "r",
        buffering: int = -1,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ):
        """Race-safe descriptor-anchored file open via _DirCapability."""
        if any(w in mode for w in ("w", "a", "+", "x")):
            raise PathConfinementError(
                "Direct write-mode open on WorkspacePath capability is forbidden to enforce atomic publication and quota accounting. "
                "Use write_bytes() or stage_upload() for atomic quota-enforced writes."
            )

        from ctf_mentor.workspace.manager import _DirCapability
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = self._get_safe_relative_str()

        with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
            parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_str)
            try:
                posix_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

                fd = os.open(final_name, posix_flags, dir_fd=parent_fd)
                try:
                    st_fd = os.fstat(fd)
                    if getattr(st_fd, "st_nlink", 1) > 1:
                        os.close(fd)
                        raise ArtifactSecurityError("Suspicious multi-link file detected during open.")
                    b_mode = mode if ("b" in mode or "t" in mode) else (mode + "t")
                    return open(fd, mode=b_mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline, closefd=True)
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
            finally:
                cap.close_fds(opened_fds)

    def stat(self) -> os.stat_result:
        """Race-safe descriptor-anchored stat via _DirCapability."""
        from ctf_mentor.workspace.manager import _DirCapability, is_dir_fd_supported
        global_root_resolved, root_resolved = self._handle._validate_handle_root_confinement()
        subdir_path = self._handle._get_validated_subdir(self._subdir)
        rel_str = str(self._rel_path).strip()
        if not rel_str or rel_str in (".", "./", ".\\"):
            with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
                if cap.dir_fd is None or not is_dir_fd_supported():
                    raise PathConfinementError("Race-safe stat is unsupported on Windows / non-POSIX platforms.")
                return os.fstat(cap.dir_fd)

        rel_safe = self._get_safe_relative_str()
        with _DirCapability(self._handle, subdir_path, global_root_resolved) as cap:
            parent_fd, final_name, opened_fds = cap.traverse_to_parent(rel_safe)
            try:
                if hasattr(os, "stat") and os.stat in os.supports_dir_fd:
                    return os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(final_name, flags, dir_fd=parent_fd)
                try:
                    return os.fstat(fd)
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            finally:
                cap.close_fds(opened_fds)

    def exists(self) -> bool:
        try:
            self.stat()
            return True
        except OSError:
            return False

    def is_file(self) -> bool:
        try:
            st = self.stat()
            return stat_module.S_ISREG(st.st_mode)
        except OSError:
            return False

    def is_dir(self) -> bool:
        try:
            st = self.stat()
            return stat_module.S_ISDIR(st.st_mode)
        except OSError:
            return False

    def is_symlink(self) -> bool:
        try:
            st = self.stat()
            return stat_module.S_ISLNK(st.st_mode)
        except OSError:
            return False

    def glob(self, pattern: str) -> list[WorkspacePath]:
        raise PathConfinementError(
            "Path-based glob traversal is disabled on WorkspacePath capabilities to prevent unanchored TOCTOU escapes."
        )

    def rglob(self, pattern: str) -> list[WorkspacePath]:
        raise PathConfinementError(
            "Path-based rglob traversal is disabled on WorkspacePath capabilities to prevent unanchored TOCTOU escapes."
        )

    @property
    def parent(self) -> WorkspacePath:
        return WorkspacePath(self._handle, self._subdir, self._rel_path.parent)

    @property
    def name(self) -> str:
        if str(self._rel_path) in (".", ""):
            return self._subdir
        return self._rel_path.name

    @property
    def stem(self) -> str:
        if str(self._rel_path) in (".", ""):
            return self._subdir
        return self._rel_path.stem

    @property
    def suffix(self) -> str:
        return self._rel_path.suffix

    @property
    def suffixes(self) -> list[str]:
        return self._rel_path.suffixes

    def resolve(self) -> WorkspacePath:
        self._resolve_and_validate()
        return self

    def relative_to(self, other: Union[str, Path, WorkspacePath]) -> Path:
        target, _, _ = self._resolve_and_validate()
        if isinstance(other, WorkspacePath):
            other_target, _, _ = other._resolve_and_validate()
            return target.relative_to(other_target)
        return target.relative_to(Path(other))

    def __fspath__(self) -> str:
        raise TypeError(
            "WorkspacePath capability cannot be converted to a raw filesystem path string. "
            "Use capability methods (read_bytes, write_bytes, open, unlink) directly."
        )

    def __str__(self) -> str:
        rel = str(self._rel_path) if str(self._rel_path) not in (".", "") else "."
        return f"<WorkspacePath {self._subdir}/{rel}>"

    def __repr__(self) -> str:
        rel = str(self._rel_path) if str(self._rel_path) not in (".", "") else "."
        return f"<WorkspacePath {self._subdir}/{rel}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, WorkspacePath):
            return (
                self._handle.workspace_id == other._handle.workspace_id
                and self._subdir == other._subdir
                and str(self._rel_path) == str(other._rel_path)
            )
        elif isinstance(other, (str, Path)):
            try:
                target, _, _ = self._resolve_and_validate()
                return target == Path(other)
            except Exception:
                return False
        return False

    def __hash__(self) -> int:
        return hash((self._handle.workspace_id, self._subdir, str(self._rel_path)))

