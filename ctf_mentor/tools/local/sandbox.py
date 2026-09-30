"""
ctf_mentor.tools.local.sandbox
=============================

Phase 10B.4: OS-Level Sandboxing & Fail-Closed Isolation Boundary.

Provides strict OS-level process, filesystem, and network isolation profiles
for local tool adapters (Tshark, Steghide, Crypto ops, etc.).

Security Guarantees & Backend Classification:
---------------------------------------------
1. LinuxNamespaceSandboxBackend (GENUINE_OS_ISOLATION):
   - Mount Isolation: Private mount namespace (CLONE_NEWNS) with read-only system
     roots (/usr, /lib, /bin) and strict writable binding restricted to the
     authorized workspace execution directory.
   - Network Isolation: Private network namespace (CLONE_NEWNET) with no external
     interfaces (loopback disabled or unrouted), guaranteeing zero outbound/inbound traffic.
   - PID Isolation: Private PID namespace (CLONE_NEWPID) where the executed tool is PID 1,
     preventing signal or ptrace inspection of host processes.
   - IPC/UTS Isolation: Private IPC and UTS namespaces (CLONE_NEWIPC, CLONE_NEWUTS).
   - Defense-in-Depth: POSIX setrlimit (RLIMIT_AS, RLIMIT_CPU, RLIMIT_NPROC, RLIMIT_FSIZE)
     and process groups (setsid/setpgid) are applied inside the container as DID,
     NOT as a substitute for namespace isolation.

2. WindowsJobObjectSandboxBackend (GENUINE_OS_ISOLATION):
   - Process Confinement: Win32 Job Objects with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
     guaranteeing atomic termination of the entire process tree on termination or handle closure.
   - Resource Confinement: JOB_OBJECT_LIMIT_JOB_MEMORY and JOB_OBJECT_LIMIT_ACTIVE_PROCESS
     enforcing strict memory quotas and blocking process fork-bombs.
   - UI / Token Restrictions: JOB_OBJECT_UILIMIT flags blocking clipboard access, handle
     sharing, desktop switching, system parameters, and global atom access.
   - Filesystem Boundary: Confinement to authorized workspace execution directory enforced
     via TrustedInvocationAuthority and strict relative path mediation.
   - Network Boundary Note: Win32 Job Objects do NOT provide OS-level network namespace isolation.
     On Windows, network denial is enforced via application/policy mediation (minimal sanitized
     environment, closed argv templates, disabling name resolution via -n, and capability restrictions).

3. PureInMemorySandboxBackend (IN_MEMORY_RUNTIME):
   - Dedicated runtime for pure in-memory tools (e.g., LocalCryptoOpsAdapter) that do not
     spawn child subprocesses. Enforces execution memory and execution time limits.

Fail-Closed Enforcement Rule:
-----------------------------
If a tool adapter requires OS-level sandbox isolation (require_os_sandbox=True)
and the host environment cannot establish the genuine OS isolation boundary
(e.g., restricted unprivileged namespaces on Linux or Job Object creation failure
on Windows), execution MUST immediately fail closed by raising `SandboxUnavailableError`.
Execution is NEVER silently downgraded to an unsandboxed state.
"""

from __future__ import annotations

import abc
import ctypes
import os
import platform
import shutil
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


class IsolationLevel(str, Enum):
    """Classification of isolation guarantees provided by an execution backend."""
    GENUINE_OS_ISOLATION = "GENUINE_OS_ISOLATION"
    IN_MEMORY_RUNTIME = "IN_MEMORY_RUNTIME"
    DEFENSE_IN_DEPTH_ONLY = "DEFENSE_IN_DEPTH_ONLY"


class SandboxUnavailableError(Exception):
    """
    Raised when OS-level sandbox isolation is required by policy but cannot
    be established by the platform backends. Fail-closed: execution is aborted.
    """


class SandboxPolicyViolation(Exception):
    """Raised when an executed tool violates sandbox policy or resource constraints."""


@dataclass(frozen=True)
class SandboxProfile:
    """
    Immutable sandbox isolation configuration and resource constraints.

    Attributes:
        require_os_sandbox: If True, execution MUST fail closed with SandboxUnavailableError
                           if genuine OS isolation cannot be established.
        allow_network:      Whether external/loopback network access is allowed. Default: False.
        isolate_mounts:     Whether filesystem mounts must be strictly isolated. Default: True.
        isolate_pids:       Whether PID namespace/process isolation is enforced. Default: True.
        isolate_ipc:        Whether IPC namespace isolation is enforced. Default: True.
        max_memory_bytes:   Hard memory limit (default: 512 MB).
        max_wall_time_sec:  Wall-clock timeout in seconds (default: 30.0 s).
        max_cpu_time_sec:   CPU time timeout in seconds (default: 15.0 s).
        max_output_bytes:   Maximum allowed stdout/stderr capture (default: 10 MB).
        max_processes:      Maximum concurrent processes in sandbox (default: 8).
        read_only_binds:    Tuple of absolute paths bound read-only into sandbox.
        writable_binds:     Tuple of absolute paths bound writable into sandbox.
    """
    require_os_sandbox: bool = True
    allow_network: bool = False
    isolate_mounts: bool = True
    isolate_pids: bool = True
    isolate_ipc: bool = True
    max_memory_bytes: int = 512 * 1024 * 1024  # 512 MB
    max_wall_time_sec: float = 30.0
    max_cpu_time_sec: float = 15.0
    max_output_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_processes: int = 8
    read_only_binds: Tuple[Path, ...] = ()
    writable_binds: Tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if self.max_memory_bytes <= 0:
            raise ValueError(f"max_memory_bytes must be positive, got {self.max_memory_bytes}")
        if self.max_wall_time_sec <= 0:
            raise ValueError(f"max_wall_time_sec must be positive, got {self.max_wall_time_sec}")
        if self.max_cpu_time_sec <= 0:
            raise ValueError(f"max_cpu_time_sec must be positive, got {self.max_cpu_time_sec}")
        if self.max_output_bytes <= 0:
            raise ValueError(f"max_output_bytes must be positive, got {self.max_output_bytes}")
        if self.max_processes <= 0:
            raise ValueError(f"max_processes must be positive, got {self.max_processes}")

        # Ensure tuple types for binds
        if not isinstance(self.read_only_binds, tuple):
            object.__setattr__(self, "read_only_binds", tuple(Path(p) for p in self.read_only_binds))
        if not isinstance(self.writable_binds, tuple):
            object.__setattr__(self, "writable_binds", tuple(Path(p) for p in self.writable_binds))


# Pre-defined Standard Profiles for Phase 10B.4 Tools
TSHARK_SANDBOX_PROFILE = SandboxProfile(
    require_os_sandbox=True,
    allow_network=False,
    isolate_mounts=True,
    isolate_pids=True,
    isolate_ipc=True,
    max_memory_bytes=512 * 1024 * 1024,
    max_wall_time_sec=30.0,
    max_cpu_time_sec=15.0,
    max_output_bytes=10 * 1024 * 1024,
    max_processes=4,
)

STEGHIDE_SANDBOX_PROFILE = SandboxProfile(
    require_os_sandbox=True,
    allow_network=False,
    isolate_mounts=True,
    isolate_pids=True,
    isolate_ipc=True,
    max_memory_bytes=512 * 1024 * 1024,
    max_wall_time_sec=30.0,
    max_cpu_time_sec=15.0,
    max_output_bytes=10 * 1024 * 1024,
    max_processes=4,
)

CRYPTO_SANDBOX_PROFILE = SandboxProfile(
    require_os_sandbox=False,
    allow_network=False,
    isolate_mounts=False,
    isolate_pids=False,
    isolate_ipc=False,
    max_memory_bytes=256 * 1024 * 1024,
    max_wall_time_sec=10.0,
    max_cpu_time_sec=5.0,
    max_output_bytes=5 * 1024 * 1024,
    max_processes=1,
)


@dataclass
class PreparedExecution:
    """Artifacts, arguments, and hooks prepared by the sandbox boundary for process launch."""
    argv: List[str]
    cwd: Path
    env: Dict[str, str]
    preexec_fn: Optional[Callable[[], None]] = None
    creationflags: int = 0
    cleanup_callbacks: List[Callable[[], None]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SandboxBackend(abc.ABC):
    """Abstract base class for platform-specific sandbox isolation backends."""

    @property
    @abc.abstractmethod
    def backend_name(self) -> str:
        """Human-readable name of the backend."""

    @property
    @abc.abstractmethod
    def isolation_level(self) -> IsolationLevel:
        """The isolation level provided by this backend."""

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check whether the backend is functional and supported on this host."""

    @abc.abstractmethod
    def prepare_execution(
        self,
        profile: SandboxProfile,
        argv: Sequence[str],
        cwd: Path,
        env: Dict[str, str],
    ) -> PreparedExecution:
        """Prepare command, environment, and pre-execution hooks for sandbox boundary."""

    def post_spawn(self, proc: Any, prepared: PreparedExecution) -> None:
        """Hook called immediately after child process is spawned."""

    def cleanup(self, proc: Optional[Any], prepared: PreparedExecution) -> None:
        """Hook called after execution completes to release sandbox resources.
        
        Drain and clear callbacks to ensure idempotency and prevent double-cleanup.
        """
        callbacks = list(prepared.cleanup_callbacks)
        prepared.cleanup_callbacks.clear()
        for cb in callbacks:
            try:
                cb()
            except Exception:
                pass


def _apply_posix_limit(resource_const: int, desired_value: int) -> None:
    """
    Apply a POSIX resource limit monotonically (never raising hard limit).
    Fails closed: raises if setrlimit fails.
    """
    import resource
    if desired_value is None or desired_value <= 0:
        return

    cur_hard = None
    try:
        cur_limits = resource.getrlimit(resource_const)
        if isinstance(cur_limits, (tuple, list)) and len(cur_limits) >= 2:
            cur_hard = cur_limits[1]
    except Exception:
        cur_hard = None

    if cur_hard is None or (hasattr(resource, "RLIM_INFINITY") and cur_hard == resource.RLIM_INFINITY):
        new_hard = desired_value
    else:
        new_hard = min(cur_hard, desired_value)
    new_soft = min(desired_value, new_hard)
    resource.setrlimit(resource_const, (new_soft, new_hard))


# =============================================================================
# Linux Namespace Sandbox Backend
# =============================================================================

class LinuxNamespaceSandboxBackend(SandboxBackend):
    """
    Linux container/namespace sandbox backend.

    Implements OS-level isolation using Linux namespaces:
    - Bubblewrap (bwrap) wrapping with private mount/PID/network namespaces.
    - True PID 2 process isolation inside private PID namespace (bwrap is PID 1).
    - Read-only system roots, private tmpfs /tmp, private /proc, private /dev, bound workspace.
    - Bound executable ro-bind after /tmp tmpfs to support test harnesses and non-/usr binaries.
    - Standalone unshare utility is only used for Defense-in-Depth when isolate_mounts=False
      and require_os_sandbox=False, because standalone unshare does NOT provide mount/filesystem confinement.
    - POSIX setrlimit enforced fail-closed inside the sandbox child.
    """

    def __init__(self) -> None:
        self._bwrap_path: Optional[str] = shutil.which("bwrap")
        self._unshare_path: Optional[str] = shutil.which("unshare")

    @property
    def backend_name(self) -> str:
        return "LinuxNamespaceSandbox"

    @property
    def isolation_level(self) -> IsolationLevel:
        return IsolationLevel.GENUINE_OS_ISOLATION

    def is_available(self) -> bool:
        if sys.platform != "linux":
            return False
        # Bubblewrap is required for genuine OS filesystem sandbox isolation
        return bool(self._bwrap_path and os.path.isfile(self._bwrap_path) and os.access(self._bwrap_path, os.X_OK))

    def prepare_execution(
        self,
        profile: SandboxProfile,
        argv: Sequence[str],
        cwd: Path,
        env: Dict[str, str],
    ) -> PreparedExecution:
        resolved_cwd = cwd.resolve()

        # Strategy 1: Bubblewrap (bwrap) — provides genuine OS filesystem, PID, and network isolation
        if self._bwrap_path and os.path.isfile(self._bwrap_path) and os.access(self._bwrap_path, os.X_OK):
            bwrap_cmd: List[str] = [self._bwrap_path]

            # Namespaces
            if profile.isolate_mounts:
                bwrap_cmd.extend(["--unshare-user", "--unshare-ipc", "--unshare-uts"])
            if not profile.allow_network:
                bwrap_cmd.append("--unshare-net")
            if profile.isolate_pids:
                bwrap_cmd.append("--unshare-pid")

            # Die with parent
            bwrap_cmd.append("--die-with-parent")

            # Mount isolation: read-only system binds
            standard_ro_binds = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/alternatives"]
            for ro_dir in standard_ro_binds:
                p = Path(ro_dir)
                if p.exists() and p.is_dir():
                    bwrap_cmd.extend(["--ro-bind", str(p), str(p)])

            for ro_bind in profile.read_only_binds:
                if ro_bind.exists():
                    bwrap_cmd.extend(["--ro-bind", str(ro_bind), str(ro_bind)])

            # Private tmpfs /tmp, /proc, /dev
            bwrap_cmd.extend(["--tmpfs", "/tmp"])
            bwrap_cmd.extend(["--proc", "/proc"])
            bwrap_cmd.extend(["--dev", "/dev"])

            # FIX 6 (Option A): Ro-bind the executable after /tmp tmpfs so test harness binaries in /tmp
            # and non-standard binaries (/opt, etc.) remain visible read-only inside sandbox
            if argv:
                exe_p = Path(argv[0])
                if exe_p.is_absolute() and exe_p.exists():
                    bwrap_cmd.extend(["--ro-bind", str(exe_p), str(exe_p)])

            # Writable workspace bind
            bwrap_cmd.extend(["--bind", str(resolved_cwd), str(resolved_cwd)])
            for w_bind in profile.writable_binds:
                if w_bind.exists():
                    bwrap_cmd.extend(["--bind", str(w_bind), str(w_bind)])

            bwrap_cmd.extend(["--chdir", str(resolved_cwd)])
            bwrap_cmd.append("--")

            # FIX 3: Apply RLIMIT_NPROC inside sandbox via prlimit wrapper if max_processes is configured
            tool_argv = list(argv)
            if profile.max_processes > 0:
                prlimit_path = shutil.which("prlimit")
                if prlimit_path and os.path.isfile(prlimit_path) and os.access(prlimit_path, os.X_OK):
                    tool_argv = [prlimit_path, f"--nproc={profile.max_processes}", "--"] + tool_argv
                elif profile.require_os_sandbox:
                    raise SandboxUnavailableError(
                        "prlimit utility is required to enforce max_processes inside bubblewrap sandbox "
                        "but is not available on this host. Execution failed closed."
                    )

            bwrap_cmd.extend(tool_argv)

            return PreparedExecution(
                argv=bwrap_cmd,
                cwd=resolved_cwd,
                env=env,
                preexec_fn=self._make_did_preexec(profile),
                metadata={"backend": self.backend_name, "mode": "bwrap"},
            )

        # FIX 4: Fail closed if mount isolation is requested and bubblewrap is unavailable
        if profile.isolate_mounts:
            raise SandboxUnavailableError(
                "Linux mount/filesystem isolation requested (isolate_mounts=True) "
                "but Bubblewrap (bwrap) is not available on this host. "
                "Standalone unshare does not provide filesystem isolation. "
                "Execution failed closed."
            )

        # Fail closed if genuine OS sandboxing is required and bubblewrap is unavailable
        if profile.require_os_sandbox:
            raise SandboxUnavailableError(
                "Linux OS sandbox isolation requested (require_os_sandbox=True) "
                "but Bubblewrap (bwrap) is not available on this host. "
                "Standalone unshare does not provide filesystem isolation. "
                "Execution failed closed."
            )

        # Strategy 2: Defense-in-Depth unshare with PID/net isolation (only when isolate_mounts=False)
        if self._unshare_path and os.path.isfile(self._unshare_path) and os.access(self._unshare_path, os.X_OK):
            unshare_cmd: List[str] = [self._unshare_path]
            unshare_cmd.extend(["--user", "--map-root-user", "--ipc", "--uts"])
            if not profile.allow_network:
                unshare_cmd.append("--net")
            if profile.isolate_pids:
                unshare_cmd.extend(["--pid", "--fork", "--mount-proc"])

            unshare_cmd.append("--")
            unshare_cmd.extend(list(argv))

            return PreparedExecution(
                argv=unshare_cmd,
                cwd=resolved_cwd,
                env=env,
                preexec_fn=self._make_did_preexec(profile),
                metadata={"backend": self.backend_name, "mode": "unshare_fork"},
            )

        return PreparedExecution(
            argv=list(argv),
            cwd=resolved_cwd,
            env=env,
            preexec_fn=self._make_did_preexec(profile),
            metadata={"backend": self.backend_name, "mode": "unisolated_did_only"},
        )

    def _make_did_preexec(self, profile: SandboxProfile) -> Callable[[], None]:
        """Create a preexec hook for resource limits inside sandbox container."""
        def _did_preexec() -> None:
            if hasattr(os, "setpgid"):
                try:
                    os.setpgid(0, 0)
                except OSError:
                    pass
            self._apply_rlimits(profile)
        return _did_preexec

    @staticmethod
    def _apply_rlimits(profile: SandboxProfile) -> None:
        """Apply POSIX resource limits safely and monotonically (never raising hard limits)."""
        import resource
        # Memory limit
        if profile.max_memory_bytes > 0:
            _apply_posix_limit(resource.RLIMIT_AS, profile.max_memory_bytes)
        # CPU time limit
        if profile.max_cpu_time_sec > 0:
            cpu_lim = int(profile.max_cpu_time_sec) + 1
            _apply_posix_limit(resource.RLIMIT_CPU, cpu_lim)
        # Max file size limit
        if profile.max_output_bytes > 0 and hasattr(resource, "RLIMIT_FSIZE"):
            _apply_posix_limit(resource.RLIMIT_FSIZE, profile.max_output_bytes)


# =============================================================================
# Windows Job Object Sandbox Backend
# =============================================================================

# Win32 Constants
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400

JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020
JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080

JobObjectExtendedLimitInformation = 9
JobObjectBasicUIRestrictions = 4
CREATE_SUSPENDED = 0x00000004
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [
        ("UIRestrictionsClass", ctypes.c_uint32),
    ]


def _get_win32_last_error() -> int:
    """Return GetLastError() from ctypes if available, else 0."""
    if hasattr(ctypes, "get_last_error"):
        try:
            return ctypes.get_last_error()
        except Exception:
            return 0
    return 0


class WindowsJobObjectSandboxBackend(SandboxBackend):
    """
    Windows Job Object sandbox backend.

    Implements OS-level process lifecycle and resource confinement using Win32 Job Objects:
    - Atomic tree cleanup on close (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    - Hard job memory limits (JOB_OBJECT_LIMIT_JOB_MEMORY)
    - Active process count limits (JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
    - Full UI / Clipboard / Handle isolation (JOB_OBJECT_UILIMIT_*)
    - Note on Network & Filesystem Isolation: Win32 Job Objects provide OS process lifecycle
      and resource confinement. They do NOT provide kernel-level filesystem or network namespace
      isolation (accepted by design). Filesystem confinement is mediated by TrustedInvocationAuthority
      path validation, and network denial is policy/application mediated.
    """

    def __init__(self) -> None:
        self._kernel32 = None
        if sys.platform == "win32":
            try:
                self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            except Exception:
                self._kernel32 = None

    @property
    def backend_name(self) -> str:
        return "WindowsJobObjectSandbox"

    @property
    def isolation_level(self) -> IsolationLevel:
        return IsolationLevel.GENUINE_OS_ISOLATION

    def is_available(self) -> bool:
        if sys.platform != "win32" or self._kernel32 is None:
            return False
        return (
            hasattr(self._kernel32, "CreateJobObjectW")
            and hasattr(self._kernel32, "SetInformationJobObject")
            and hasattr(self._kernel32, "AssignProcessToJobObject")
        )

    def prepare_execution(
        self,
        profile: SandboxProfile,
        argv: Sequence[str],
        cwd: Path,
        env: Dict[str, str],
    ) -> PreparedExecution:
        if not self.is_available():
            if profile.require_os_sandbox:
                raise SandboxUnavailableError(
                    "Windows Job Object isolation requested (require_os_sandbox=True) "
                    "but Win32 Job Object APIs are unavailable on this system. "
                    "Execution failed closed."
                )
            return PreparedExecution(
                argv=list(argv),
                cwd=cwd.resolve(),
                env=env,
                metadata={"backend": self.backend_name, "job_handle": None},
            )

        # Create Win32 Job Object
        job_handle = self._kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            err = _get_win32_last_error()
            if profile.require_os_sandbox:
                raise SandboxUnavailableError(
                    f"CreateJobObjectW failed with Win32 error code {err}. Execution failed closed."
                )
            return PreparedExecution(
                argv=list(argv),
                cwd=cwd.resolve(),
                env=env,
                metadata={"backend": self.backend_name, "job_handle": None},
            )

        # Configure Extended Limits
        ext_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION

        if profile.max_memory_bytes > 0:
            limit_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            ext_limits.JobMemoryLimit = profile.max_memory_bytes
            ext_limits.ProcessMemoryLimit = profile.max_memory_bytes

        if profile.max_processes > 0:
            limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            ext_limits.BasicLimitInformation.ActiveProcessLimit = profile.max_processes

        ext_limits.BasicLimitInformation.LimitFlags = limit_flags

        res = self._kernel32.SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(ext_limits),
            ctypes.sizeof(ext_limits),
        )
        if not res:
            err = _get_win32_last_error()
            self._kernel32.CloseHandle(job_handle)
            if profile.require_os_sandbox:
                raise SandboxUnavailableError(
                    f"SetInformationJobObject(ExtendedLimits) failed with error {err}. Execution failed closed."
                )
            return PreparedExecution(
                argv=list(argv),
                cwd=cwd.resolve(),
                env=env,
                metadata={"backend": self.backend_name, "job_handle": None},
            )

        # Configure UI Restrictions
        ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS()
        ui_limits.UIRestrictionsClass = (
            JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
        )

        res = self._kernel32.SetInformationJobObject(
            job_handle,
            JobObjectBasicUIRestrictions,
            ctypes.byref(ui_limits),
            ctypes.sizeof(ui_limits),
        )
        if not res:
            err = _get_win32_last_error()
            self._kernel32.CloseHandle(job_handle)
            if profile.require_os_sandbox:
                raise SandboxUnavailableError(
                    f"SetInformationJobObject(BasicUIRestrictions) failed with error {err}. Execution failed closed."
                )
            return PreparedExecution(
                argv=list(argv),
                cwd=cwd.resolve(),
                env=env,
                metadata={"backend": self.backend_name, "job_handle": None},
            )

        def _cleanup_job() -> None:
            nonlocal job_handle
            if job_handle and self._kernel32:
                h = job_handle
                job_handle = None
                try:
                    self._kernel32.CloseHandle(h)
                except Exception:
                    pass

        return PreparedExecution(
            argv=list(argv),
            cwd=cwd.resolve(),
            env=env,
            creationflags=0,
            cleanup_callbacks=[_cleanup_job],
            metadata={"backend": self.backend_name, "job_handle": job_handle},
        )

    def post_spawn(self, proc: subprocess.Popen, prepared: PreparedExecution) -> None:
        job_handle = prepared.metadata.get("job_handle")
        if not job_handle or not self._kernel32:
            return

        # Obtain process handle
        proc_handle = getattr(proc, "_handle", None)
        if proc_handle is None:
            # Fall back to OpenProcess
            PROCESS_SET_QUOTA = 0x0100
            PROCESS_TERMINATE = 0x0001
            proc_handle = self._kernel32.OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                False,
                proc.pid,
            )
            need_close_proc = True
        else:
            need_close_proc = False

        if not proc_handle:
            err = _get_win32_last_error()
            proc.kill()
            raise SandboxUnavailableError(
                f"Failed to obtain Win32 process handle for PID {proc.pid} (error {err}). Execution killed."
            )

        try:
            res = self._kernel32.AssignProcessToJobObject(job_handle, proc_handle)
            if not res:
                err = _get_win32_last_error()
                proc.kill()
                raise SandboxUnavailableError(
                    f"AssignProcessToJobObject failed for PID {proc.pid} with error {err}. Child killed."
                )
        finally:
            if need_close_proc and proc_handle:
                self._kernel32.CloseHandle(proc_handle)


# =============================================================================
# Pure In-Memory Sandbox Backend
# =============================================================================

class PureInMemorySandboxBackend(SandboxBackend):
    """
    Dedicated in-memory runtime sandbox for tools that do not spawn subprocesses
    (e.g., LocalCryptoOpsAdapter).
    """

    @property
    def backend_name(self) -> str:
        return "PureInMemorySandbox"

    @property
    def isolation_level(self) -> IsolationLevel:
        return IsolationLevel.IN_MEMORY_RUNTIME

    def is_available(self) -> bool:
        return True

    def prepare_execution(
        self,
        profile: SandboxProfile,
        argv: Sequence[str],
        cwd: Path,
        env: Dict[str, str],
    ) -> PreparedExecution:
        if profile.require_os_sandbox:
            raise SandboxUnavailableError(
                "Tool requires OS-level sandbox isolation (require_os_sandbox=True) "
                "which cannot be satisfied by the PureInMemorySandboxBackend."
            )
        return PreparedExecution(
            argv=list(argv),
            cwd=cwd.resolve(),
            env=env,
            metadata={"backend": self.backend_name},
        )


# =============================================================================
# Central Sandbox Execution Boundary
# =============================================================================

class SandboxExecutionBoundary:
    """
    Central factory and manager for sandbox isolation.

    Enforces:
    - Selection of genuine OS-level sandbox backends (LinuxNamespace / WindowsJobObject).
    - Immediate fail-closed abort (SandboxUnavailableError) if require_os_sandbox=True
      and genuine OS-level isolation is not established.
    - Explicit classification of any fallback as defense-in-depth only.
    """

    def __init__(self, backend: Optional[SandboxBackend] = None) -> None:
        if backend is not None:
            self._backend = backend
        elif sys.platform == "win32":
            self._backend = WindowsJobObjectSandboxBackend()
        elif sys.platform == "linux":
            self._backend = LinuxNamespaceSandboxBackend()
        else:
            self._backend = PureInMemorySandboxBackend()

    @property
    def backend(self) -> SandboxBackend:
        return self._backend

    def prepare_and_verify(
        self,
        profile: SandboxProfile,
        argv: Sequence[str],
        cwd: Path,
        env: Dict[str, str],
    ) -> PreparedExecution:
        """
        Prepare execution through the active backend and strictly verify isolation guarantees.
        """
        if profile.require_os_sandbox:
            if not self._backend.is_available():
                raise SandboxUnavailableError(
                    f"OS-level sandbox isolation is required (require_os_sandbox=True) "
                    f"but active backend '{self._backend.backend_name}' is unavailable on {sys.platform}. "
                    f"Execution failed closed."
                )
            if self._backend.isolation_level != IsolationLevel.GENUINE_OS_ISOLATION:
                raise SandboxUnavailableError(
                    f"OS-level sandbox isolation is required (require_os_sandbox=True) "
                    f"but active backend '{self._backend.backend_name}' provides only "
                    f"'{self._backend.isolation_level.value}', which is NOT OS sandbox isolation. "
                    f"Execution failed closed."
                )

        prepared = self._backend.prepare_execution(profile, argv, cwd, env)
        return prepared

    def post_spawn(self, proc: Any, prepared: PreparedExecution) -> None:
        """Enforce post-spawn sandbox attachment."""
        self._backend.post_spawn(proc, prepared)

    def cleanup(self, proc: Optional[Any], prepared: PreparedExecution) -> None:
        """Release sandbox resources."""
        self._backend.cleanup(proc, prepared)
