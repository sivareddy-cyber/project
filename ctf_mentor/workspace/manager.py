"""
Workspace Manager for Phase 10B.1 Workspace Isolation.

Implements WorkspaceManager capability object handling:
- get_or_create(conn, challenge_id, session_id) with strict workspace root symlink confinement
- path confinement and safe resolution
- atomic artifact staging with streaming quota enforcement
- cross-instance/process workspace locking for atomic quota accounting
- fstat-on-open hard-link security checks
- single-pass import_verified_artifact bridge (eliminating TOCTOU integrity vulnerability)
- stale-aware cleanup of temporary staging files
- lifecycle management (CREATING, READY, EXPIRED, QUARANTINED)
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Optional, Union

from ctf_mentor.workspace.models import (
    _WINDOWS_RESERVED_NAMES,
    ArtifactIntegrityError,
    ArtifactSecurityError,
    PathConfinementError,
    QuotaExceededError,
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceLockError,
    WorkspaceRecord,
    WorkspaceStatus,
    WorkspaceStatusError,
    WorkspaceValidationError,
)
from ctf_mentor.workspace.repository import WorkspaceRepository
import stat as stat_module


def is_dir_fd_supported() -> bool:
    """Check if descriptor-relative dir_fd operations are supported on the current platform."""
    return hasattr(os, "supports_dir_fd") and bool(os.supports_dir_fd)



class _CrossProcessWorkspaceLock:
    """Cross-process file lock using fcntl (POSIX) / msvcrt (Windows) for workspace lock files.

    Fails closed by raising WorkspaceLockError or PathConfinementError if OS-level lock acquisition or confinement validation fails.
    If handle is provided, validates workspace root confinement BEFORE creating/opening lock file, and uses descriptor-relative opening if supported.
    """

    def __init__(self, lock_file_path: Path, handle: Optional[WorkspaceHandle] = None):
        self.lock_file_path = lock_file_path
        self.handle = handle
        self._file: Optional[BinaryIO] = None
        self._fd: Optional[int] = None

    def __enter__(self):
        try:
            target_lock_path = self.lock_file_path
            if self.handle is not None:
                # 1. Confinement check BEFORE lock file creation/opening
                global_root_resolved, root_resolved = self.handle._validate_handle_root_confinement()
                target_lock_path = root_resolved / ".workspace.lock"

                if is_dir_fd_supported():
                    # Open workspace root directory descriptor safely
                    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                    ws_dir_fd = os.open(str(root_resolved), flags_dir)
                    try:
                        st_dir = os.fstat(ws_dir_fd)
                        if self.handle._root_dev_ino is not None and (st_dir.st_dev, st_dir.st_ino) != self.handle._root_dev_ino:
                            raise PathConfinementError("Workspace root directory descriptor inode mismatch.")

                        flags_lock = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                        self._fd = os.open(".workspace.lock", flags_lock, 0o600, dir_fd=ws_dir_fd)
                        if sys.platform == "win32":
                            import msvcrt
                            msvcrt.locking(self._fd, msvcrt.LK_LOCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(self._fd, fcntl.LOCK_EX)
                        return self
                    finally:
                        try:
                            os.close(ws_dir_fd)
                        except OSError:
                            pass

            target_lock_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(target_lock_path, "a+b")
            if sys.platform == "win32":
                import msvcrt
                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        except Exception as e:
            self._close_internal()
            if isinstance(e, WorkspaceError):
                raise
            raise WorkspaceLockError(
                f"Failed to acquire cross-process workspace lock on '{self.lock_file_path}': {e}"
            ) from e
        return self

    def _close_internal(self):
        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None

        if self._file is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self._file.seek(0)
                    msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close_internal()


class _DirCapability:
    """Directory Capability descriptor object anchored to a validated workspace directory.

    POSIX Platform Behavior:
    - Captures expected pre-open directory identity (st_dev, st_ino).
    - Validates confinement of directory path.
    - Opens directory file descriptor (dir_fd).
    - Compares os.fstat(dir_fd) identity against CAPTURED pre-open identity.
    - Uses descriptor-relative operations (os.open, os.rename, os.unlink with dir_fd).
    - Prevents directory opening races and post-validation namespace swaps.

    Windows Platform Behavior (Option B Fail-Closed):
    - Windows C runtime does not support dir_fd (os.supports_dir_fd is empty).
    - Security-sensitive workspace mutation operations (stage_upload, import_verified_artifact,
      and staging cleanup) refuse to run and fail closed with PathConfinementError on Windows,
      preventing un-anchored path-based mutation operations.
    """

    def __init__(
        self,
        handle: WorkspaceHandle,
        dir_path: Path,
        global_root_resolved: Path,
    ) -> None:
        self.handle = handle
        self.path = dir_path
        self.global_root_resolved = global_root_resolved
        self.dir_fd: Optional[int] = None

        # 1. Capture expected directory identity BEFORE opening & confinement validation
        try:
            expected_st = dir_path.resolve().stat()
            self.expected_dev_ino: tuple[int, int] = (expected_st.st_dev, expected_st.st_ino)
        except (OSError, ValueError) as e:
            raise PathConfinementError(f"Target directory '{dir_path}' does not exist or is inaccessible: {e}")

        # 2. Confinement validation
        self._validate_confinement()

        # 3. Open dir_fd if supported on POSIX
        if is_dir_fd_supported():
            try:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                self.dir_fd = os.open(str(self.path), flags)
                # Verify open descriptor identity against CAPTURED pre-open identity
                st_fd = os.fstat(self.dir_fd)
                if (st_fd.st_dev, st_fd.st_ino) != self.expected_dev_ino:
                    self.close()
                    raise PathConfinementError(
                        f"Directory capability descriptor inode mismatch for '{self.path}': "
                        f"opened (dev={st_fd.st_dev}, ino={st_fd.st_ino}) != expected {self.expected_dev_ino}."
                    )
            except Exception as e:
                self.close()
                if isinstance(e, PathConfinementError):
                    raise
                raise PathConfinementError(
                    f"Failed to open directory capability descriptor for '{self.path}': {e}"
                ) from e
        else:
            # Option B: Fail closed on platforms lacking dir_fd support (Windows)
            raise PathConfinementError(
                f"Race-safe descriptor-anchored workspace operations are unsupported on Windows / non-POSIX platforms "
                f"(os.supports_dir_fd is empty)."
            )

    def _validate_confinement(self) -> None:
        self.handle._validate_handle_root_confinement()
        if self.path.is_symlink():
            raise PathConfinementError(f"Directory capability target '{self.path}' is a symlink.")
        if not self.path.exists() or not self.path.is_dir():
            raise PathConfinementError(f"Directory capability target '{self.path}' is not a directory.")
        resolved = self.path.resolve()
        resolved.relative_to(self.global_root_resolved)

    def traverse_to_parent(self, rel_str: str) -> tuple[int, str, list[int]]:
        """Traverse intermediate path components relative to dir_fd using O_NOFOLLOW / O_DIRECTORY.

        Returns (parent_dir_fd, final_component_name, list_of_intermediate_fds_to_close).
        Every intermediate component is opened relative to its parent descriptor with O_NOFOLLOW | O_DIRECTORY.
        If any intermediate component is a symlink or non-directory, raises PathConfinementError.
        """
        if self.dir_fd is None or not is_dir_fd_supported():
            raise PathConfinementError(
                "Race-safe descriptor-anchored workspace operations are unsupported on Windows / non-POSIX platforms."
            )

        parts = [p for p in rel_str.replace("\\", "/").split("/") if p and p != "."]
        if not parts:
            raise PathConfinementError("Empty relative path for traversal.")

        if len(parts) == 1:
            return self.dir_fd, parts[0], []

        intermediate_parts = parts[:-1]
        final_name = parts[-1]

        current_fd = self.dir_fd
        opened_fds: list[int] = []

        comp_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)

        try:
            for comp in intermediate_parts:
                next_fd = os.open(comp, comp_flags, dir_fd=current_fd)
                opened_fds.append(next_fd)
                st = os.fstat(next_fd)
                if not stat_module.S_ISDIR(st.st_mode):
                    raise PathConfinementError(f"Intermediate path component '{comp}' in '{rel_str}' is not a directory.")
                current_fd = next_fd
            return current_fd, final_name, opened_fds
        except Exception as e:
            self.close_fds(opened_fds)
            if isinstance(e, PathConfinementError):
                raise
            raise PathConfinementError(
                f"Failed safe descriptor-relative traversal for '{rel_str}': {e}"
            ) from e

    @staticmethod
    def close_fds(fds: list[int]) -> None:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass

    def create_temp_file(self, prefix: str = ".staging_tmp_") -> tuple[int, Path, str]:
        """Create temp file inside the validated directory capability."""
        if self.dir_fd is None or not is_dir_fd_supported():
            raise PathConfinementError(
                "Race-safe temp file creation requires descriptor-relative dir_fd support."
            )
        temp_name = f"{prefix}{uuid.uuid4().hex}"
        temp_path = self.path / temp_name
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(temp_name, flags, 0o600, dir_fd=self.dir_fd)
        return fd, temp_path, temp_name

    def publish_temp_file(
        self,
        temp_name: str,
        final_filename: str,
        temp_path: Path,
        final_path: Path,
    ) -> Path:
        """Publish temp file to final_filename relative to directory capability."""
        self._validate_confinement()
        if self.dir_fd is None or not is_dir_fd_supported():
            raise PathConfinementError(
                "Race-safe atomic publication requires descriptor-relative dir_fd support."
            )

        os.rename(temp_name, final_filename, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
        published = self.path / final_filename
        return published

    def unlink_file(self, tmp_name: str, tmp_path: Path) -> None:
        """Unlink file relative to directory capability."""
        self._validate_confinement()
        if self.dir_fd is None or not is_dir_fd_supported():
            raise PathConfinementError(
                "Race-safe unlink requires descriptor-relative dir_fd support."
            )
        os.unlink(tmp_name, dir_fd=self.dir_fd)

    def close(self) -> None:
        if self.dir_fd is not None:
            try:
                os.close(self.dir_fd)
            except OSError:
                pass
            self.dir_fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()




class WorkspaceManager:
    """Manages isolated local filesystem workspaces bound to (challenge_id, session_id).

    Synchronization Invariants:
    - Thread-level isolation within a WorkspaceManager instance is enforced via per-workspace
      threading.Lock for each (challenge_id, session_id) pair.
    - Process-level and cross-instance isolation relies on OS-level cross-process file locks (_CrossProcessWorkspaceLock)
      for workspace write & quota operations, SQLite transaction isolation for database records,
      and atomic filesystem operations (os.replace) for artifact publication.
    """

    def __init__(
        self,
        workspace_root: Union[str, Path, None] = None,
        default_quota_bytes: int = 100 * 1024 * 1024,  # 100 MB default per workspace
        max_file_bytes: int = 50 * 1024 * 1024,        # 50 MB default max single file
    ) -> None:
        if workspace_root is None:
            workspace_root = Path.cwd() / "workspaces"
        self.workspace_root = Path(workspace_root).resolve()
        self.default_quota_bytes = default_quota_bytes
        self.max_file_bytes = max_file_bytes

        # Per-workspace locks to protect concurrent writes and quota accounting in-process
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._global_lock = threading.Lock()

        # Ensure base workspace root exists
        self._ensure_workspace_root_exists()

        # 1. Secret Root Anchor File (Cross-platform protection against directory replacement & inode reuse)
        self._root_anchor_file = self.workspace_root / ".workspace_root.id"
        if self._root_anchor_file.exists() and not self._root_anchor_file.is_symlink():
            try:
                self._root_id = self._root_anchor_file.read_text(encoding="utf-8").strip()
            except Exception:
                self._root_id = uuid.uuid4().hex
                self._write_root_anchor_id()
        else:
            self._root_id = uuid.uuid4().hex
            self._write_root_anchor_id()

        # 2. POSIX Open Directory Descriptor Capability Anchor
        self._root_dir_fd: Optional[int] = None
        if is_dir_fd_supported():
            try:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                self._root_dir_fd = os.open(str(self.workspace_root), flags)
            except Exception:
                self._root_dir_fd = None

        # 3. Capture stat dev/ino
        try:
            st = self.workspace_root.stat()
            self._workspace_root_dev_ino: Optional[tuple[int, int]] = (st.st_dev, st.st_ino)
        except Exception:
            self._workspace_root_dev_ino = None

    def _ensure_workspace_root_exists(self) -> None:
        """Create global workspace root if it does not exist."""
        try:
            self.workspace_root.mkdir(parents=True, exist_ok=True)
            if hasattr(os, "chmod"):
                try:
                    os.chmod(self.workspace_root, 0o700)
                except OSError:
                    pass
        except Exception as e:
            raise WorkspaceError(f"Failed to initialize global workspace root '{self.workspace_root}': {e}")

    def _write_root_anchor_id(self) -> None:
        """Write secret root anchor ID file."""
        try:
            self._root_anchor_file.write_text(self._root_id, encoding="utf-8")
            if hasattr(os, "chmod"):
                try:
                    os.chmod(self._root_anchor_file, 0o600)
                except OSError:
                    pass
        except Exception as e:
            raise WorkspaceError(f"Failed to initialize workspace root anchor file: {e}")

    def _validate_manager_root_confinement(self) -> Path:
        """Validate that the manager's global workspace root remains un-tampered and anchored.

        Enforces descriptor anchoring, root ID file validation, symlink rejection, canonical resolution,
        and stat device & inode identity verification.
        Fails closed by raising PathConfinementError if global root has been replaced, symlinked, moved, or deleted.
        Returns the validated canonical global root Path.
        """
        # 1. Existence check
        if not self.workspace_root.exists():
            raise PathConfinementError(f"Workspace manager root '{self.workspace_root}' does not exist.")

        # 2. Check if workspace_root or any parent component is a symlink
        curr = self.workspace_root
        while curr != curr.parent:
            if curr.is_symlink():
                raise PathConfinementError(
                    f"Workspace manager root path component '{curr}' is a symlink and violates global root confinement."
                )
            curr = curr.parent

        # 3. Canonical resolution of workspace root must match original authorized path
        try:
            resolved_root = self.workspace_root.resolve()
            if resolved_root != self.workspace_root:
                raise PathConfinementError(
                    f"Workspace manager root '{self.workspace_root}' resolved to '{resolved_root}', "
                    f"violating namespace immutability."
                )
        except OSError as e:
            raise PathConfinementError(f"Workspace manager root resolution error: {e}")

        # 4. Descriptor Anchoring & Unlink Verification (POSIX)
        if self._root_dir_fd is not None and is_dir_fd_supported():
            try:
                st_fd = os.fstat(self._root_dir_fd)
                if getattr(st_fd, "st_nlink", 2) < 2:
                    raise PathConfinementError(
                        f"Workspace manager root descriptor detected unlinked directory (st_nlink={st_fd.st_nlink})."
                    )

                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                curr_fd = os.open(str(self.workspace_root), flags)
                try:
                    st_curr = os.fstat(curr_fd)
                    if (st_curr.st_dev, st_curr.st_ino) != (st_fd.st_dev, st_fd.st_ino):
                        raise PathConfinementError(
                            f"Workspace manager root directory descriptor inode mismatch for '{self.workspace_root}': "
                            f"opened (dev={st_curr.st_dev}, ino={st_curr.st_ino}) != anchored (dev={st_fd.st_dev}, ino={st_fd.st_ino})."
                        )
                finally:
                    os.close(curr_fd)
            except Exception as e:
                if isinstance(e, PathConfinementError):
                    raise
                raise PathConfinementError(f"Workspace manager descriptor validation error: {e}") from e

        # 5. Root Anchor ID File Verification (Cross-platform protection against directory replacement & inode reuse)
        anchor_file = resolved_root / ".workspace_root.id"
        if not anchor_file.exists() or anchor_file.is_symlink():
            raise PathConfinementError(
                f"Workspace manager root anchor file '{anchor_file}' is missing or a symlink."
            )
        try:
            current_id = anchor_file.read_text(encoding="utf-8").strip()
            if current_id != self._root_id:
                raise PathConfinementError(
                    f"Workspace manager root anchor ID mismatch: '{current_id}' != expected '{self._root_id}'."
                )
        except Exception as e:
            if isinstance(e, PathConfinementError):
                raise
            raise PathConfinementError(f"Failed to verify workspace manager root anchor ID: {e}") from e

        # 6. Immutable Device & Inode identity verification
        if self._workspace_root_dev_ino is not None:
            try:
                st = resolved_root.stat()
                if (st.st_dev, st.st_ino) != self._workspace_root_dev_ino:
                    raise PathConfinementError(
                        f"Workspace manager root '{self.workspace_root}' has been replaced or modified on disk."
                    )
            except OSError as e:
                raise PathConfinementError(f"Workspace manager root access error: {e}")

        return resolved_root

    def _get_workspace_lock(self, challenge_id: str, session_id: str) -> threading.Lock:
        """Thread-safe acquisition of a per-workspace lock."""
        key = (challenge_id, session_id)
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def _get_cross_process_lock(self, handle: WorkspaceHandle) -> _CrossProcessWorkspaceLock:
        """Return cross-process file lock for workspace."""
        self._validate_manager_root_confinement()
        return _CrossProcessWorkspaceLock(handle._root / ".workspace.lock", handle=handle)

    def _validate_workspace_root_confinement(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        relative_root: str,
    ) -> Path:
        """Validate that relative_root and all intermediate path components resolve strictly within global workspace_root.

        Fails closed by updating workspace status to QUARANTINED in DB and raising PathConfinementError if any
        symlink escape or boundary violation is detected.
        """
        try:
            global_root_resolved = self._validate_manager_root_confinement()
        except PathConfinementError:
            WorkspaceRepository.update_status(conn, workspace_id, WorkspaceStatus.QUARANTINED)
            raise

        abs_root_resolved = (global_root_resolved / relative_root).resolve()

        # 1. Verify target containment
        try:
            abs_root_resolved.relative_to(global_root_resolved)
        except ValueError:
            WorkspaceRepository.update_status(conn, workspace_id, WorkspaceStatus.QUARANTINED)
            raise PathConfinementError(
                f"Workspace root '{abs_root_resolved}' escapes global workspace root '{global_root_resolved}'."
            )

        # 2. Check intermediate components for symlink escapes
        curr = global_root_resolved
        parts = [p for p in relative_root.replace("\\", "/").split("/") if p and p != "."]
        for part in parts:
            curr = curr / part
            if curr.is_symlink() or curr.exists():
                curr_resolved = curr.resolve()
                try:
                    curr_resolved.relative_to(global_root_resolved)
                except ValueError:
                    WorkspaceRepository.update_status(conn, workspace_id, WorkspaceStatus.QUARANTINED)
                    raise PathConfinementError(
                        f"Workspace path component '{part}' is a symlink resolving to '{curr_resolved}', "
                        f"which escapes global workspace root '{global_root_resolved}'."
                    )

        return abs_root_resolved

    def get_or_create(
        self,
        conn: sqlite3.Connection,
        challenge_id: str,
        session_id: str,
        expires_at: Optional[str] = None,
    ) -> WorkspaceHandle:
        """Get or create an isolated workspace for a verified (challenge_id, session_id) pair.

        Validates:
        1. challenge_id exists in challenges table.
        2. session_id exists in investigation_sessions table.
        3. session_id is bound to challenge_id.
        4. Rejects mismatched pairings and returns fail-closed WorkspaceValidationError.
        5. Handles workspace lifecycle status (CREATING, READY, EXPIRED, QUARANTINED).
        6. Enforces strict containment of workspace root and subdirectories on READY reuse.
        """
        # Step 0: Validate WorkspaceManager global root immutability
        self._validate_manager_root_confinement()

        # Step 1: Validate challenge/session pairing against DB
        WorkspaceRepository.validate_challenge_and_session(conn, challenge_id, session_id)

        lock = self._get_workspace_lock(challenge_id, session_id)
        with lock:
            # Step 2: Query DB for existing workspace record
            record = WorkspaceRepository.get_by_challenge_and_session(conn, challenge_id, session_id)
            now_iso = datetime.now(timezone.utc).isoformat()

            if record:
                # Lazy expiration check
                if record.expires_at and now_iso >= record.expires_at:
                    WorkspaceRepository.update_status(conn, record.workspace_id, WorkspaceStatus.EXPIRED)
                    raise WorkspaceStatusError(
                        f"Workspace '{record.workspace_id}' for challenge '{challenge_id}' / "
                        f"session '{session_id}' has EXPIRED."
                    )

                if record.status == WorkspaceStatus.EXPIRED.value:
                    raise WorkspaceStatusError(
                        f"Workspace '{record.workspace_id}' is EXPIRED and cannot be used."
                    )

                if record.status == WorkspaceStatus.QUARANTINED.value:
                    raise WorkspaceStatusError(
                        f"Workspace '{record.workspace_id}' is QUARANTINED and cannot be used."
                    )

                if record.status == WorkspaceStatus.CREATING.value:
                    # Incomplete/crashed creation detected -> quarantine workspace
                    WorkspaceRepository.update_status(conn, record.workspace_id, WorkspaceStatus.QUARANTINED)
                    raise WorkspaceStatusError(
                        f"Workspace '{record.workspace_id}' was left in incomplete CREATING status "
                        f"and has been QUARANTINED."
                    )

                if record.status == WorkspaceStatus.READY.value:
                    # Verify workspace root remains strictly contained within global workspace root
                    abs_root = self._validate_workspace_root_confinement(conn, record.workspace_id, record.relative_root)

                    temp_handle = WorkspaceHandle(
                        workspace_id=record.workspace_id,
                        challenge_id=record.challenge_id,
                        session_id=record.session_id,
                        status=record.status,
                        _root=abs_root,
                        _global_root=self.workspace_root.resolve(),
                        max_file_bytes=self.max_file_bytes,
                        default_quota_bytes=self.default_quota_bytes,
                    )

                    # Subdirectory symlink escape check on READY reuse
                    try:
                        for subdir in ("input", "work", "output"):
                            temp_handle._get_validated_subdir(subdir)
                    except PathConfinementError as e:
                        WorkspaceRepository.update_status(conn, record.workspace_id, WorkspaceStatus.QUARANTINED)
                        raise WorkspaceStatusError(
                            f"Workspace subdirectory confinement check failed for '{record.workspace_id}': {e}"
                        )

                    try:
                        self.clean_stale_staging_files_by_root(abs_root, stale_age_seconds=60.0)
                    except PathConfinementError:
                        pass
                    return temp_handle

            # Step 3: Create NEW workspace record
            workspace_id = f"ws_{uuid.uuid4().hex}"
            relative_root = f"{challenge_id}/{session_id}"

            new_record = WorkspaceRecord(
                workspace_id=workspace_id,
                challenge_id=challenge_id,
                session_id=session_id,
                relative_root=relative_root,
                status=WorkspaceStatus.CREATING.value,
                created_at=now_iso,
                updated_at=now_iso,
                expires_at=expires_at,
            )
            WorkspaceRepository.create(conn, new_record)

            try:
                abs_root = self._validate_workspace_root_confinement(conn, workspace_id, relative_root)

                for subdir in ("input", "work", "output"):
                    sub_path = abs_root / subdir
                    sub_path.mkdir(parents=True, exist_ok=True)
                    if hasattr(os, "chmod"):
                        try:
                            os.chmod(sub_path, 0o700)
                        except OSError:
                            pass

                if hasattr(os, "chmod"):
                    try:
                        os.chmod(abs_root, 0o700)
                    except OSError:
                        pass

                WorkspaceRepository.update_status(conn, workspace_id, WorkspaceStatus.READY)
                return WorkspaceHandle(
                    workspace_id=workspace_id,
                    challenge_id=challenge_id,
                    session_id=session_id,
                    status=WorkspaceStatus.READY.value,
                    _root=abs_root,
                    _global_root=self.workspace_root.resolve(),
                    max_file_bytes=self.max_file_bytes,
                    default_quota_bytes=self.default_quota_bytes,
                )
            except Exception as e:
                WorkspaceRepository.update_status(conn, workspace_id, WorkspaceStatus.QUARANTINED)
                if isinstance(e, WorkspaceError):
                    raise
                raise WorkspaceError(f"Failed to initialize filesystem workspace: {e}")

    def calculate_workspace_size(self, handle: WorkspaceHandle) -> int:
        """Recursively calculate total bytes used by files in the workspace."""
        self._validate_manager_root_confinement()
        root_resolved = handle._root.resolve()
        if not root_resolved.exists():
            return 0

        # Validate subdirectories before scanning
        for subdir in ("input", "work", "output"):
            handle._get_validated_subdir(subdir)

        total_bytes = 0
        for p in root_resolved.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
                    p_resolved = p.resolve()
                    p_resolved.relative_to(root_resolved)
                    total_bytes += p.stat().st_size
            except (OSError, ValueError, PathConfinementError):
                continue
        return total_bytes

    def _verify_open_file_confinement(
        self,
        handle: WorkspaceHandle,
        file_obj: Any,
        target_path: Path,
        expected_parent_dir: Path,
        global_root_resolved: Path,
    ) -> None:
        """Verify open file descriptor and path resolution strictly inside expected_parent_dir and global_root_resolved.

        Fails closed by raising PathConfinementError or ArtifactSecurityError.
        The caller's finally block handles closing file_obj prior to any cleanup unlinking.
        """
        # 1. Re-validate handle root confinement (fails if any parent component is a symlink or escapes)
        handle._validate_handle_root_confinement()

        # 2. Check fstat on descriptor
        fd = file_obj.fileno()
        st = os.fstat(fd)
        if getattr(st, "st_nlink", 1) > 1:
            raise ArtifactSecurityError(
                f"Suspicious hard-linked file descriptor detected (st_nlink={st.st_nlink} > 1)."
            )

        # 3. Check path resolution
        resolved_target = target_path.resolve()
        resolved_target.relative_to(expected_parent_dir.resolve())
        resolved_target.relative_to(global_root_resolved)

        # 4. Parent must exist and NOT be a symlink
        if target_path.parent.is_symlink():
            raise PathConfinementError(f"Parent directory of '{target_path}' is a symlink.")


    def stage_upload(
        self,
        handle: WorkspaceHandle,
        filename: str,
        byte_stream: Union[bytes, BinaryIO, Iterable[bytes]],
        max_file_size: Optional[int] = None,
        quota_bytes: Optional[int] = None,
    ) -> WorkspacePath:
        """Atomically stage an uploaded artifact file into the workspace input directory.

        Enforces:
        - READY workspace status
        - Pre-lock and in-lock handle root & subdirectory confinement validation
        - Path confinement (rejecting slashes, path traversal, Windows reserved names)
        - Directory capability descriptor anchoring (_DirCapability)
        - Streaming write to temporary staging file
        - Post-open descriptor & path resolution TOCTOU verification
        - Maximum file size and per-workspace total disk quota check during stream under cross-process locking
        - Hard-link security inspection (st_nlink)
        - Pre-replace confinement validation, fsync, and atomic publication anchored to directory capability
        """
        if handle.status != WorkspaceStatus.READY.value:
            raise WorkspaceStatusError(f"Cannot stage upload: workspace is in status {handle.status!r}.")

        self._validate_manager_root_confinement()

        # 1. Validate filename
        rel_str = str(filename).strip()
        if "\x00" in rel_str:
            raise PathConfinementError("Filename contains forbidden NUL byte.")

        if not rel_str or rel_str in (".", ".."):
            raise PathConfinementError(f"Invalid filename: {filename!r}")

        # Ensure simple filename (no directory path components)
        if "/" in rel_str or "\\" in rel_str or Path(rel_str).name != rel_str:
            raise PathConfinementError(f"Filename must be a simple name without path components: {filename!r}")

        stem = rel_str.split(".")[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise PathConfinementError(f"Windows reserved filename forbidden: {filename!r}")

        # Validate handle confinement BEFORE acquiring cross-process lock to prevent external .workspace.lock creation
        global_root_resolved, root_resolved = handle._validate_handle_root_confinement()
        input_dir = handle._get_validated_subdir("input")

        lock = self._get_workspace_lock(handle.challenge_id, handle.session_id)
        cp_lock = self._get_cross_process_lock(handle)

        with lock, cp_lock:
            # Re-validate handle confinement inside lock
            global_root_resolved, root_resolved = handle._validate_handle_root_confinement()
            input_dir = handle._get_validated_subdir("input")
            final_path = (input_dir / rel_str).resolve()

            try:
                final_path.relative_to(input_dir)
                final_path.relative_to(global_root_resolved)
            except ValueError:
                raise PathConfinementError(f"Staged filename '{filename}' escapes input directory.")

            eff_max_file = max_file_size if max_file_size is not None else handle.max_file_bytes
            eff_quota = quota_bytes if quota_bytes is not None else handle.default_quota_bytes

            current_size = self.calculate_workspace_size(handle)

            # Check if quota is already exceeded
            if current_size >= eff_quota:
                raise QuotaExceededError(
                    f"Workspace disk quota exceeded ({current_size} / {eff_quota} bytes used)."
                )

            with _DirCapability(handle, input_dir, global_root_resolved) as cap:
                fd, temp_path, temp_name = cap.create_temp_file(prefix=".staging_tmp_")
                bytes_written = 0

                try:
                    f = open(fd, "wb", closefd=True)
                    try:
                        self._verify_open_file_confinement(
                            handle=handle,
                            file_obj=f,
                            target_path=temp_path,
                            expected_parent_dir=input_dir,
                            global_root_resolved=global_root_resolved,
                        )

                        if isinstance(byte_stream, bytes):
                            chunks = [byte_stream[i : i + 65536] for i in range(0, len(byte_stream), 65536)]
                        elif hasattr(byte_stream, "read"):
                            def _read_chunks():
                                while True:
                                    chunk = byte_stream.read(65536)
                                    if not chunk:
                                        break
                                    yield chunk
                            chunks = _read_chunks()
                        else:
                            chunks = byte_stream

                        for chunk in chunks:
                            chunk_len = len(chunk)
                            if bytes_written + chunk_len > eff_max_file:
                                raise QuotaExceededError(
                                    f"File upload size ({bytes_written + chunk_len} bytes) "
                                    f"exceeds maximum allowed file size ({eff_max_file} bytes)."
                                )
                            if current_size + bytes_written + chunk_len > eff_quota:
                                raise QuotaExceededError(
                                    f"File upload size causes total workspace usage ({current_size + bytes_written + chunk_len} bytes) "
                                    f"to exceed workspace disk quota ({eff_quota} bytes)."
                                )
                            f.write(chunk)
                            bytes_written += chunk_len

                        f.flush()
                        os.fsync(f.fileno())
                    finally:
                        f.close()

                    # Hard link security check on temporary file
                    st = temp_path.stat()
                    if getattr(st, "st_nlink", 1) > 1:
                        raise ArtifactSecurityError(
                            f"Suspicious hard-linked file detected during staging (st_nlink={st.st_nlink} > 1)."
                        )

                    cap.publish_temp_file(temp_name, rel_str, temp_path, final_path)
                    return handle.resolve("input", rel_str)
                except Exception:
                    try:
                        cap.unlink_file(temp_name, temp_path)
                    except Exception:
                        pass
                    raise

    def import_verified_artifact(
        self,
        handle: WorkspaceHandle,
        observation: Any,
    ) -> WorkspacePath:
        """Bridge operation: import an IngestionObservation artifact into workspace after single-pass SHA-256 verification.

        Reads bytes ONCE directly into a workspace temporary staging file, calculating SHA-256 during the stream.
        Eliminates stat-then-open TOCTOU on source_path by calling os.fstat on the open file descriptor.
        Enforces post-open & pre-replace TOCTOU confinement verification on destination workspace paths using _DirCapability.
        Returns WorkspacePath capability.
        """
        if handle.status != WorkspaceStatus.READY.value:
            raise WorkspaceStatusError(f"Cannot import artifact: workspace is in status {handle.status!r}.")

        self._validate_manager_root_confinement()

        raw_path = getattr(observation, "artifact_path", None)
        expected_sha256 = getattr(observation, "sha256", None)

        if not raw_path:
            raise ArtifactIntegrityError("IngestionObservation missing 'artifact_path'.")
        if not expected_sha256:
            raise ArtifactIntegrityError("IngestionObservation missing 'sha256'.")

        source_path = Path(raw_path).resolve()
        if not source_path.exists() or not source_path.is_file():
            raise ArtifactIntegrityError(f"Source artifact file does not exist at '{source_path}'.")

        filename = source_path.name
        rel_str = str(filename).strip()
        if "\x00" in rel_str or not rel_str or rel_str in (".", "..") or "/" in rel_str or "\\" in rel_str:
            raise PathConfinementError(f"Invalid artifact filename: {filename!r}")

        # Validate handle confinement BEFORE acquiring cross-process lock to prevent external .workspace.lock creation
        global_root_resolved, root_resolved = handle._validate_handle_root_confinement()
        input_dir = handle._get_validated_subdir("input")

        lock = self._get_workspace_lock(handle.challenge_id, handle.session_id)
        cp_lock = self._get_cross_process_lock(handle)

        with lock, cp_lock:
            global_root_resolved, root_resolved = handle._validate_handle_root_confinement()
            input_dir = handle._get_validated_subdir("input")
            final_path = (input_dir / rel_str).resolve()
            try:
                final_path.relative_to(input_dir)
                final_path.relative_to(global_root_resolved)
            except ValueError:
                raise PathConfinementError(f"Imported artifact filename '{filename}' escapes input directory.")

            eff_max_file = handle.max_file_bytes
            eff_quota = handle.default_quota_bytes
            current_size = self.calculate_workspace_size(handle)
            if current_size >= eff_quota:
                raise QuotaExceededError(
                    f"Workspace disk quota exceeded ({current_size} / {eff_quota} bytes used)."
                )

            # Open source file FIRST and inspect fstat before creating temp file
            with open(source_path, "rb") as f_in:
                fd_in = f_in.fileno()
                st_src = os.fstat(fd_in)
                if getattr(st_src, "st_nlink", 1) > 1:
                    raise ArtifactSecurityError(
                        f"Suspicious multi-link source artifact detected (st_nlink={st_src.st_nlink} > 1)."
                    )

                with _DirCapability(handle, input_dir, global_root_resolved) as cap:
                    fd, temp_path, temp_name = cap.create_temp_file(prefix=".staging_tmp_")
                    hasher = hashlib.sha256()
                    bytes_written = 0

                    try:
                        f_out = open(fd, "wb", closefd=True)
                        try:
                            self._verify_open_file_confinement(
                                handle=handle,
                                file_obj=f_out,
                                target_path=temp_path,
                                expected_parent_dir=input_dir,
                                global_root_resolved=global_root_resolved,
                            )

                            while True:
                                chunk = f_in.read(65536)
                                if not chunk:
                                    break
                                chunk_len = len(chunk)
                                if bytes_written + chunk_len > eff_max_file:
                                    raise QuotaExceededError(
                                        f"Imported file size ({bytes_written + chunk_len} bytes) "
                                        f"exceeds maximum allowed file size ({eff_max_file} bytes)."
                                    )
                                if current_size + bytes_written + chunk_len > eff_quota:
                                    raise QuotaExceededError(
                                        f"Imported file size causes total workspace usage to exceed disk quota."
                                    )
                                f_out.write(chunk)
                                hasher.update(chunk)
                                bytes_written += chunk_len

                            f_out.flush()
                            os.fsync(f_out.fileno())
                        finally:
                            f_out.close()

                        calculated_sha256 = hasher.hexdigest()
                        if calculated_sha256.lower() != str(expected_sha256).lower():
                            raise ArtifactIntegrityError(
                                f"Artifact SHA-256 mismatch during import of '{filename}': "
                                f"expected '{expected_sha256}', calculated '{calculated_sha256}'."
                            )

                        st_tmp = temp_path.stat()
                        if getattr(st_tmp, "st_nlink", 1) > 1:
                            raise ArtifactSecurityError("Suspicious multi-link file detected during staging.")

                        cap.publish_temp_file(temp_name, rel_str, temp_path, final_path)
                        return handle.resolve("input", rel_str)
                    except Exception:
                        try:
                            cap.unlink_file(temp_name, temp_path)
                        except Exception:
                            pass
                        raise

    def clean_stale_staging_files(self, handle: WorkspaceHandle, stale_age_seconds: float = 60.0) -> int:
        """Clean up orphaned .staging_tmp_* files in workspace directories older than stale_age_seconds.

        Fails closed by raising PathConfinementError if workspace root or any intermediate component
        violates global workspace root confinement or is a symlink.
        Acquires workspace locks during scan to ensure TOCTOU protection.
        Anchors deletions to _DirCapability directory capability descriptors.
        """
        self._validate_manager_root_confinement()
        if not (hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd):
            raise PathConfinementError(
                "Race-safe descriptor-anchored workspace cleanup is unsupported on Windows / non-POSIX platforms "
                "(os.supports_dir_fd is empty)."
            )
        global_root_resolved, root_resolved = handle._validate_handle_root_confinement()

        lock = self._get_workspace_lock(handle.challenge_id, handle.session_id)
        cp_lock = self._get_cross_process_lock(handle)

        with lock, cp_lock:
            handle._validate_handle_root_confinement()

            cleaned = 0
            now = datetime.now(timezone.utc).timestamp()

            for subdir in ("input", "work", "output"):
                try:
                    resolved_sub = handle._get_validated_subdir(subdir)
                except PathConfinementError:
                    continue

                try:
                    with _DirCapability(handle, resolved_sub, global_root_resolved) as cap:
                        for tmp_file in resolved_sub.glob(".staging_tmp_*"):
                            try:
                                handle._validate_handle_root_confinement()
                                if tmp_file.is_symlink() or tmp_file.parent.is_symlink():
                                    continue
                                if not tmp_file.is_file():
                                    continue

                                tmp_resolved = tmp_file.resolve()
                                tmp_resolved.relative_to(resolved_sub)
                                tmp_resolved.relative_to(global_root_resolved)

                                file_mtime = tmp_file.stat().st_mtime
                                age = now - file_mtime
                                if stale_age_seconds <= 0 or age >= stale_age_seconds:
                                    cap.unlink_file(tmp_file.name, tmp_file)
                                    cleaned += 1
                            except (OSError, ValueError, PathConfinementError):
                                pass
                except PathConfinementError:
                    continue

            return cleaned


    def clean_stale_staging_files_by_root(self, root: Path, stale_age_seconds: float = 60.0) -> int:
        """Clean up orphaned .staging_tmp_* files in a workspace root older than stale_age_seconds.

        Enforces strict global workspace root confinement:
        - Root must be relative to global workspace_root.
        - Root and all intermediate path components must exist and contain NO symlinks.
        - Fails closed by raising PathConfinementError if confinement is violated.
        - Anchors deletions to _DirCapability directory capability descriptors.
        """
        if not (hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd):
            raise PathConfinementError(
                "Race-safe descriptor-anchored workspace cleanup is unsupported on Windows / non-POSIX platforms "
                "(os.supports_dir_fd is empty)."
            )
        global_root_resolved = self._validate_manager_root_confinement()
        abs_root = root if root.is_absolute() else (global_root_resolved / root)

        # 1. Validate relative path to workspace_root
        try:
            rel_path = abs_root.resolve().relative_to(global_root_resolved)
            if rel_path == Path("."):
                raise PathConfinementError("Cleanup root cannot be global workspace root itself.")
        except ValueError:
            raise PathConfinementError(
                f"Cleanup root '{root}' escapes global workspace root '{global_root_resolved}'."
            )

        # 2. Check intermediate components for symlink escapes
        try:
            rel_to_ws = abs_root.relative_to(self.workspace_root)
        except ValueError:
            try:
                rel_to_ws = abs_root.resolve().relative_to(global_root_resolved)
            except ValueError:
                raise PathConfinementError(f"Cleanup root '{root}' is not inside global workspace root.")

        curr = self.workspace_root
        for part in rel_to_ws.parts:
            curr = curr / part
            if curr.is_symlink():
                raise PathConfinementError(
                    f"Cleanup path component '{part}' is a symlink and violates confinement boundary."
                )
            if curr.exists():
                curr_resolved = curr.resolve()
                try:
                    curr_resolved.relative_to(global_root_resolved)
                except ValueError:
                    raise PathConfinementError(
                        f"Cleanup path component '{part}' resolved to '{curr_resolved}', "
                        f"which escapes global workspace root '{global_root_resolved}'."
                    )

        root_resolved = abs_root.resolve()
        cleaned = 0
        now = datetime.now(timezone.utc).timestamp()

        rel_parts = rel_to_ws.parts
        ch_id = rel_parts[0] if len(rel_parts) > 0 else "unknown"
        sess_id = rel_parts[1] if len(rel_parts) > 1 else "unknown"
        dummy_handle = WorkspaceHandle(
            workspace_id="cleanup_root",
            challenge_id=ch_id,
            session_id=sess_id,
            status=WorkspaceStatus.READY.value,
            _root=root_resolved,
            _global_root=global_root_resolved,
        )

        for subdir in ("input", "work", "output"):
            sub_dir = root_resolved / subdir
            if sub_dir.is_symlink() or not sub_dir.exists() or not sub_dir.is_dir():
                continue

            resolved_sub = sub_dir.resolve()
            try:
                rel = resolved_sub.relative_to(root_resolved)
                if rel == Path("."):
                    continue
                resolved_sub.relative_to(global_root_resolved)
            except ValueError:
                continue

            try:
                with _DirCapability(dummy_handle, resolved_sub, global_root_resolved) as cap:
                    for tmp_file in resolved_sub.glob(".staging_tmp_*"):
                        try:
                            if tmp_file.is_file() and not tmp_file.is_symlink():
                                tmp_resolved = tmp_file.resolve()
                                tmp_resolved.relative_to(resolved_sub)
                                tmp_resolved.relative_to(global_root_resolved)

                                file_mtime = tmp_file.stat().st_mtime
                                age = now - file_mtime
                                if stale_age_seconds <= 0 or age >= stale_age_seconds:
                                    cap.unlink_file(tmp_file.name, tmp_file)
                                    cleaned += 1
                        except (OSError, ValueError, PathConfinementError):
                            pass
            except PathConfinementError:
                continue

        return cleaned


    def sweep_expired(self, conn: sqlite3.Connection) -> int:
        """Sweep expired workspaces in DB."""
        return WorkspaceRepository.sweep_expired(conn)
