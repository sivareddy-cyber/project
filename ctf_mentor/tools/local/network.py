"""
Phase 10B.3 — Local Execution Network (Subprocess Boundary).

This module is the PASSIVE_LOCAL analogue of ctf_mentor/tools/network.py
(which handles PASSIVE_NETWORK tool execution). It provides the sole
controlled subprocess boundary for local tool execution.

SECURITY INVARIANTS enforced by this module:
1. shell=False on every Popen call. Raising LocalSubprocessPolicyViolation
   if shell=True is requested.
2. Executable path comes from the caller (must originate from allowlist).
3. argv is a List[str]. Never a shell string.
4. Environment is the sanitized dict passed in — os.environ is never consulted.
5. stdout and stderr are read in streaming fashion with hard byte limits.
   The process is killed immediately when a limit is exceeded.
6. Timeout is enforced via Popen.wait(timeout=...) with process-tree kill.
7. On POSIX: process group kill via os.killpg / os.kill after new session.
8. On Windows: process tree kill via taskkill /F /T.
9. On POSIX: RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE applied via preexec_fn.
10. Platform limits unavailable on Windows — timeout is the only hard control.
    This is documented explicitly and does NOT cause a security exception.

This module does NOT know about workspace capabilities. It operates purely
at the OS process boundary.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ctf_mentor.tools.local.policy import (
    LocalExecutionPolicy,
    LocalSubprocessPolicyViolation,
    OutputSizeLimitExceeded,
    ProcessCleanupError,
    WorkspaceConfinementError,
)

_IS_WINDOWS = sys.platform == "win32"
_IS_POSIX = not _IS_WINDOWS


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """
    A single append-only audit event for a local tool invocation.

    Security: details must NOT contain secrets, raw user input strings,
    full filesystem paths (basename only), or arbitrary stdout/stderr content.
    """
    timestamp_utc: str        # ISO-8601 UTC
    event: str                # e.g. "SUBPROCESS_START", "SUBPROCESS_TIMEOUT"
    invocation_id: str
    tool_id: str
    details: Dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SubprocessResult
# ---------------------------------------------------------------------------

@dataclass
class SubprocessResult:
    """
    The result of a bounded subprocess execution.

    All fields are inert value types. No references to live processes.
    """
    exit_code: int
    stdout_bytes: bytes
    stderr_bytes: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    killed: bool
    duration_ms: float


# ---------------------------------------------------------------------------
# Environment Sanitization
# ---------------------------------------------------------------------------

_POSIX_MINIMAL_ENV: Dict[str, str] = {
    "PATH": "/usr/bin:/usr/sbin:/bin:/usr/local/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "TERM": "dumb",
}

_WINDOWS_MINIMAL_ENV_KEYS = (
    "SystemRoot",
    "SystemDrive",
    "TEMP",
    "TMP",
    "COMSPEC",
    "windir",
)


_BANNED_ENV_KEYS = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH", "PYTHONHOME", "LD_AUDIT", "GCONV_PATH",
    "LD_DEBUG", "LD_BIND_NOW", "LD_TRACE_LOADED_OBJECTS",
    "DYLD_LIBRARY_PATH", "DYLD_PRINT_LIBRARIES",
    "BASH_ENV", "ENV", "CDPATH", "IFS",
})


def _build_minimal_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Build a minimal, sanitized environment dictionary.

    Does NOT inherit os.environ. Extra keys are merged ONLY from the
    caller-supplied dict (which must originate from trusted code, not
    user/LLM input).

    Explicitly ensures the following are ABSENT:
    LD_PRELOAD, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, PYTHONPATH,
    PYTHONHOME, LD_AUDIT, GCONV_PATH, LD_DEBUG, LD_BIND_NOW.
    """
    if _IS_WINDOWS:
        env: Dict[str, str] = {}
        for key in _WINDOWS_MINIMAL_ENV_KEYS:
            val = os.environ.get(key)
            if val is not None:
                env[key] = val
    else:
        env = dict(_POSIX_MINIMAL_ENV)

    if extra:
        # Only merge keys explicitly provided by trusted adapter code.
        # Banned keys are rejected even if the adapter tries to add them.
        for k, v in extra.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise LocalSubprocessPolicyViolation(f"Environment keys and values must be str, got {k!r}={v!r}")
            if "\x00" in k or "\x00" in v:
                raise LocalSubprocessPolicyViolation("Null byte in environment variable")
            k_upper = k.upper()
            if k_upper in _BANNED_ENV_KEYS:
                raise LocalSubprocessPolicyViolation(
                    f"Attempt to inject banned environment variable: {k!r}"
                )
            if k_upper == "PATH":
                for p_entry in v.split(os.pathsep):
                    if p_entry == "" or p_entry == "." or not Path(p_entry).is_absolute():
                        raise LocalSubprocessPolicyViolation(
                            f"PATH environment variable contains unsafe relative entry: {p_entry!r}"
                        )
                # Remove any existing PATH variations to avoid duplicate case keys
                for existing_k in list(env.keys()):
                    if existing_k.upper() == "PATH":
                        del env[existing_k]
                env["PATH"] = v
            else:
                env[k] = v

    return env


# ---------------------------------------------------------------------------
# Process-Tree Kill
# ---------------------------------------------------------------------------

def _get_trusted_taskkill_path() -> Optional[Path]:
    """
    Resolve the absolute path to taskkill.exe from trusted Windows system directory.
    Prevents redirection through manipulated environment variables, UNC paths, or PATH.
    """
    if not _IS_WINDOWS:
        return None

    candidate_paths: list[Path] = []

    # 1. Query Win32 GetSystemDirectoryW if available (independent of os.environ)
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        res = ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
        if res > 0:
            sys_dir = Path(buf.value).resolve()
            candidate_paths.append(sys_dir / "taskkill.exe")
    except Exception:
        pass

    # 2. Canonical local system path
    candidate_paths.append(Path(r"C:\Windows\System32\taskkill.exe"))

    for cand in candidate_paths:
        try:
            cand_resolved = cand.resolve()
            cand_str = str(cand_resolved)
            # Must be local drive (e.g. C:\), reject UNC (\\server\share) or POSIX-like //
            if cand_str.startswith("\\\\") or cand_str.startswith("//"):
                continue
            if len(cand_str) < 3 or cand_str[1:3] != ":\\":
                continue
            parts = [p.lower() for p in cand_resolved.parts]
            if len(parts) >= 4 and parts[1] in ("windows", "winnt") and parts[2] == "system32" and parts[3] == "taskkill.exe":
                if cand_resolved.is_file() and not cand_resolved.is_symlink():
                    return cand_resolved
        except Exception:
            continue

    return None


def _kill_process_tree(proc: subprocess.Popen, require_tree: bool = False) -> bool:
    """
    Kill the process and its entire process tree.

    POSIX: sends SIGKILL to the process group (requires start_new_session=True
    on Popen so the child has a distinct process group).
    Windows: uses trusted taskkill.exe /F /T to terminate the tree.
    Does NOT silently downgrade to parent-only termination when tree kill is required.
    Emergency parent termination is performed as best-effort containment on failure.

    Returns:
        True if process tree kill succeeded, False otherwise.

    Raises:
        ProcessCleanupError: If require_tree is True and trusted taskkill is unavailable
            or fails on Windows, or process group kill fails on POSIX.
    """
    if _IS_POSIX:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            # Process / group already exited cleanly
            return True
        except (OSError, PermissionError, Exception) as exc:
            try:
                proc.kill()
            except Exception:
                pass
            if require_tree:
                raise ProcessCleanupError(f"POSIX process tree kill failed: {exc}") from exc
            return False
    else:
        taskkill = _get_trusted_taskkill_path()
        if taskkill is None:
            # Emergency best-effort parent kill
            try:
                proc.kill()
            except Exception:
                pass
            if require_tree:
                raise ProcessCleanupError(
                    "Trusted taskkill.exe unavailable for required Windows process-tree cleanup"
                )
            return False

        try:
            res = subprocess.run(
                [str(taskkill), "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
                shell=False,  # INVARIANT: shell=False
            )
            if res.returncode != 0:
                stderr_text = res.stderr.decode(errors="replace")
                stdout_text = res.stdout.decode(errors="replace")
                combined = (stderr_text + " " + stdout_text).lower()
                if "not found" not in combined or proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    if require_tree:
                        raise ProcessCleanupError(
                            f"Windows taskkill process-tree cleanup failed with exit code {res.returncode}: "
                            f"{stderr_text.strip()}"
                        )
                    return False
            return True
        except ProcessCleanupError:
            raise
        except Exception as exc:
            try:
                proc.kill()
            except Exception:
                pass
            if require_tree:
                raise ProcessCleanupError(f"Windows taskkill execution failed: {exc}") from exc
            return False


# ---------------------------------------------------------------------------
# Streaming Bounded Read
# ---------------------------------------------------------------------------

def _read_bounded(
    pipe,
    limit: int,
    result_queue: queue.Queue,
    label: str,
) -> None:
    """
    Thread target: read from pipe up to limit bytes.

    Puts (data: bytes, truncated: bool) into result_queue when done or limit reached.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                # Only keep data up to the limit
                excess = total - limit
                keep = chunk[:len(chunk) - excess]
                if keep:
                    chunks.append(keep)
                truncated = True
                break
            chunks.append(chunk)
    except Exception:
        pass
    result_queue.put((b"".join(chunks), truncated))


# ---------------------------------------------------------------------------
# POSIX Resource Limits
# ---------------------------------------------------------------------------

def _apply_posix_limit(
    resource_const: int,
    desired_soft: int,
    desired_hard: Optional[int] = None,
) -> None:
    """
    Apply a POSIX resource limit monotonically (never raising hard limit).
    Fails closed: raises if setrlimit fails.
    """
    import resource
    if desired_soft is None or desired_soft <= 0:
        return
    if desired_hard is None:
        desired_hard = desired_soft

    cur_hard = None
    try:
        cur_limits = resource.getrlimit(resource_const)
        if isinstance(cur_limits, (tuple, list)) and len(cur_limits) >= 2:
            cur_hard = cur_limits[1]
    except Exception:
        cur_hard = None

    if cur_hard is None or (hasattr(resource, "RLIM_INFINITY") and cur_hard == resource.RLIM_INFINITY):
        new_hard = desired_hard
    else:
        new_hard = min(cur_hard, desired_hard)
    new_soft = min(desired_soft, new_hard)
    resource.setrlimit(resource_const, (new_soft, new_hard))


def _make_posix_preexec_fn(policy: LocalExecutionPolicy):
    """
    Return a preexec_fn that applies POSIX resource limits.

    Called in the child process after fork, before exec.
    Fails closed: if any mandatory limit cannot be set, an exception is raised
    which aborts execution before exec.
    Monotonically clamps limits so it never raises a hard limit.
    This function is POSIX-only.
    """
    cpu_s = policy.posix_cpu_limit_s
    mem_b = policy.posix_mem_limit_bytes
    fsize_b = policy.posix_fsize_limit_bytes

    def _preexec():
        import resource
        if cpu_s is not None:
            _apply_posix_limit(resource.RLIMIT_CPU, cpu_s, cpu_s + 1)
        if mem_b is not None:
            _apply_posix_limit(resource.RLIMIT_AS, mem_b, mem_b)
        if fsize_b is not None:
            _apply_posix_limit(resource.RLIMIT_FSIZE, fsize_b, fsize_b)

    return _preexec



# ---------------------------------------------------------------------------
# LocalSubprocessRunner
# ---------------------------------------------------------------------------

class LocalSubprocessRunner:
    """
    Trusted subprocess executor for Phase 10B.3 local tool adapters.

    SECURITY CONTRACT:
    - Only call run() with argv from a validated, allowlisted source.
    - The executable MUST be the first element of argv and must be an
      absolute Path string originating from ExecutableAllowlist.
    - env must be produced by build_env().
    - shell=True is unconditionally refused.
    - Caller is responsible for ensuring cwd is within the workspace.
    """

    def build_env(
        self,
        extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Build a sanitized environment. See _build_minimal_env()."""
        return _build_minimal_env(extra)

    def run(
        self,
        argv: List[str],
        policy: LocalExecutionPolicy,
        invocation_id: str,
        env: Optional[Dict[str, str]] = None,
        audit_log: Optional[List[AuditEntry]] = None,
        cwd: Optional[Any] = None,
        sandbox_profile: Optional[Any] = None,
    ) -> SubprocessResult:
        """
        Execute the subprocess with all security controls applied.

        Args:
            argv:            List[str] argv. argv[0] must be the absolute executable path.
            policy:          The LocalExecutionPolicy for this tool.
            invocation_id:   UUID for audit correlation and trusted workspace resolution.
            env:             Pre-sanitized environment dict from build_env().
            audit_log:       Append-only audit list.
            cwd:             Forbidden (must be None). Runner resolves cwd from TrustedInvocationAuthority.
            sandbox_profile: Optional SandboxProfile enforcing OS-level isolation boundary.

        Returns:
            SubprocessResult with all outputs bounded.

        Raises:
            LocalSubprocessPolicyViolation: If shell=True is attempted, caller-supplied cwd is given,
                or other policy invariants are violated before exec.
            WorkspaceConfinementError: If authorized invocation record is missing/invalid or cwd escapes.
            SandboxUnavailableError: If OS sandbox is required but unavailable on the host.
            ToolUnavailableError: If executable_path is None.
        """
        if cwd is not None:
            raise LocalSubprocessPolicyViolation(
                "Caller-supplied cwd is forbidden; runner obtains cwd exclusively from TrustedInvocationAuthority"
            )

        if audit_log is None:
            audit_log = []
        if env is None:
            env = self.build_env()

        # Ensure env is validated and normalized independently in the runner (F5)
        normalized_env: Dict[str, str] = {}
        for k, v in env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise LocalSubprocessPolicyViolation(f"Environment keys and values must be str, got {k!r}={v!r}")
            if "\x00" in k or "\x00" in v:
                raise LocalSubprocessPolicyViolation("Null byte in environment variable")
            k_upper = k.upper()
            if k_upper in _BANNED_ENV_KEYS:
                raise LocalSubprocessPolicyViolation(
                    f"Attempt to pass banned environment variable to runner: {k!r}"
                )
            if k_upper == "PATH":
                for p_entry in v.split(os.pathsep):
                    if p_entry == "" or p_entry == "." or not Path(p_entry).is_absolute():
                        raise LocalSubprocessPolicyViolation(
                            f"PATH environment variable contains unsafe relative entry: {p_entry!r}"
                        )
                for existing_k in list(normalized_env.keys()):
                    if existing_k.upper() == "PATH":
                        del normalized_env[existing_k]
                normalized_env["PATH"] = v
            else:
                if _IS_WINDOWS:
                    for existing_k in list(normalized_env.keys()):
                        if existing_k.upper() == k_upper:
                            del normalized_env[existing_k]
                normalized_env[k] = v
        env = normalized_env

        # --- Pre-execution security checks ---
        if not argv:
            raise LocalSubprocessPolicyViolation("argv must not be empty")

        # Validate that argv[0] matches the policy executable path exactly.
        if policy.executable_path is None:
            from ctf_mentor.tools.local.policy import ToolUnavailableError
            raise ToolUnavailableError(
                f"Policy has no executable_path for tool {policy.tool_id!r}"
            )

        if str(argv[0]) != str(policy.executable_path):
            raise LocalSubprocessPolicyViolation(
                f"argv[0] {argv[0]!r} does not match policy executable "
                f"{policy.executable_path!r} for tool {policy.tool_id!r}"
            )

        # Verify and resolve cwd exclusively from TrustedInvocationAuthority
        from ctf_mentor.tools.local.adapter import TRUSTED_INVOCATION_AUTHORITY
        record = TRUSTED_INVOCATION_AUTHORITY.get_record(invocation_id)
        if record is None or not record.active:
            raise WorkspaceConfinementError(
                f"No active authorized workspace invocation record found for invocation {invocation_id!r}"
            )

        cwd_path = record.cwd
        if not isinstance(cwd_path, Path):
            cwd_path = Path(cwd_path)
        cwd = cwd_path

        if not cwd_path.is_absolute():
            raise WorkspaceConfinementError(
                f"Authorized cwd must be an absolute path, got: {cwd_path!r}"
            )
        if not cwd_path.exists() or not cwd_path.is_dir():
            raise WorkspaceConfinementError(
                f"Authorized cwd must exist and be a directory: {cwd_path!r}"
            )
        if cwd_path.is_symlink():
            raise WorkspaceConfinementError(
                f"Authorized cwd must not be a symlink: {cwd_path!r}"
            )

        cwd_resolved = cwd_path.resolve()
        if cwd_resolved.is_symlink():
            raise WorkspaceConfinementError(
                f"Resolved authorized cwd must not be a symlink: {cwd_resolved!r}"
            )

        # Reject attempts to use system root or forbidden directories as cwd
        _BANNED_CWD_PREFIXES = (
            "/etc", "/sys", "/proc", "/dev", "/boot", "/bin", "/sbin", "/usr",
            r"C:\Windows", r"C:\WINDOWS", r"C:\Program Files", r"C:\Program Files (x86)",
        )
        for bp in _BANNED_CWD_PREFIXES:
            try:
                bp_resolved = Path(bp).resolve()
                if _IS_WINDOWS:
                    if Path(str(cwd_resolved).lower()).is_relative_to(Path(str(bp_resolved).lower())):
                        raise WorkspaceConfinementError(
                            f"cwd is inside forbidden system directory: {cwd_path!r}"
                        )
                else:
                    if cwd_resolved.is_relative_to(bp_resolved):
                        raise WorkspaceConfinementError(
                            f"cwd is inside forbidden system directory: {cwd_path!r}"
                        )
            except WorkspaceConfinementError:
                raise
            except Exception:
                pass

        # Verify on-disk invocation authorization marker
        marker_path = cwd_resolved / ".invocation_auth"
        if not marker_path.exists() or not marker_path.is_file() or marker_path.is_symlink():
            raise WorkspaceConfinementError(
                f"Invocation authorization marker missing or invalid in cwd: {cwd_path!r}"
            )
        try:
            marker_data = json.loads(marker_path.read_text(encoding="utf-8"))
            if "invocations" in marker_data and isinstance(marker_data["invocations"], dict):
                marker_data = marker_data["invocations"].get(record.invocation_id, {})
            if (
                marker_data.get("token") != record.token
                or marker_data.get("invocation_id") != record.invocation_id
                or marker_data.get("challenge_id") != record.challenge_id
                or marker_data.get("session_id") != record.session_id
                or marker_data.get("workspace_id") != record.workspace_id
            ):
                raise WorkspaceConfinementError(
                    "Invocation authorization marker contents do not match authorized invocation record"
                )
        except WorkspaceConfinementError:
            raise
        except Exception as exc:
            raise WorkspaceConfinementError(
                f"Failed to read or verify invocation authorization marker: {exc}"
            ) from exc

        # Automatic tool-specific configuration directory isolation
        if policy.tool_id == "tshark":
            wscfg = cwd_resolved / ".wscfg"
            wscfg.mkdir(parents=True, exist_ok=True, mode=0o700)
            env = dict(env)
            env["WIRESHARK_CONFIG_DIR"] = str(wscfg)

        # Identify indices of secret-bearing arguments (F4)
        _SECRET_FLAGS = frozenset({"-p", "-P", "-passphrase", "--passphrase", "-password", "--password", "-k", "--key"})
        secret_indices = set()
        for i, arg in enumerate(argv):
            if i > 0 and argv[i - 1] in _SECRET_FLAGS:
                secret_indices.add(i)

        # Validate individual argv components for null bytes and path traversal.
        for i, arg in enumerate(argv):
            if not isinstance(arg, str):
                raise LocalSubprocessPolicyViolation(
                    f"argv[{i}] is not a str: {type(arg).__name__!r}"
                )
            if "\x00" in arg:
                raise LocalSubprocessPolicyViolation(
                    f"argv[{i}] contains null byte — possible injection attempt"
                )

            # Secret-bearing arguments must NOT be interpreted as filesystem paths (F4)
            if i in secret_indices:
                continue

            # Check for path traversal outside cwd in non-flag arguments
            if i > 0 and not arg.startswith("-"):
                norm_arg = arg.replace("\\", "/")
                if ".." in norm_arg.split("/"):
                    raise WorkspaceConfinementError(
                        f"argv[{i}] contains directory traversal"
                    )
                if Path(arg).is_absolute():
                    try:
                        if not Path(arg).resolve().is_relative_to(cwd_resolved):
                            raise WorkspaceConfinementError(
                                f"Absolute path in argv[{i}] escapes cwd boundary"
                            )
                    except Exception:
                        raise WorkspaceConfinementError(
                            f"Path in argv[{i}] escapes cwd boundary"
                        )

        # Phase 10B.4 Sandbox Boundary Preparation & Verification
        from ctf_mentor.tools.local.sandbox import (
            SandboxExecutionBoundary,
            SandboxProfile,
            TSHARK_SANDBOX_PROFILE,
            STEGHIDE_SANDBOX_PROFILE,
        )

        if sandbox_profile is None:
            if policy.tool_id == "tshark":
                sandbox_profile = TSHARK_SANDBOX_PROFILE
            elif policy.tool_id == "steghide":
                sandbox_profile = STEGHIDE_SANDBOX_PROFILE
            else:
                sandbox_profile = SandboxProfile(require_os_sandbox=True)

        sandbox_boundary = SandboxExecutionBoundary()
        prepared = sandbox_boundary.prepare_and_verify(
            profile=sandbox_profile,
            argv=argv,
            cwd=cwd_resolved,
            env=env,
        )

        # --- Platform-specific Popen kwargs ---
        popen_kwargs: dict = {
            "args": prepared.argv,
            "cwd": str(prepared.cwd),
            "env": prepared.env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,          # INVARIANT: shell=False — never negotiate
        }

        if _IS_POSIX:
            popen_kwargs["start_new_session"] = True
            policy_preexec = _make_posix_preexec_fn(policy)
            sandbox_preexec = prepared.preexec_fn

            def _combined_posix_preexec() -> None:
                # 1. Apply mandatory Phase 10B.3 policy POSIX resource controls (fail-closed)
                if policy_preexec is not None:
                    policy_preexec()
                # 2. Apply Phase 10B.4 sandbox preexec controls (fail-closed)
                if sandbox_preexec is not None:
                    sandbox_preexec()

            popen_kwargs["preexec_fn"] = _combined_posix_preexec
        else:
            # Windows: CREATE_NEW_PROCESS_GROUP for taskkill /T + sandbox creationflags
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | prepared.creationflags

        # --- Audit start ---
        import datetime
        start_time = time.monotonic()
        start_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_log.append(AuditEntry(
            timestamp_utc=start_ts,
            event="SUBPROCESS_START",
            invocation_id=invocation_id,
            tool_id=policy.tool_id,
            details={
                "argv_length": len(argv),
                "cwd_basename": cwd.name,
                "sandbox_backend": sandbox_boundary.backend.backend_name,
            },
        ))

        # --- Launch subprocess ---
        timed_out = False
        killed = False
        proc: Optional[subprocess.Popen] = None
        stdout_data = b""
        stderr_data = b""
        stdout_truncated = False
        stderr_truncated = False
        exit_code = -1

        stdout_queue: queue.Queue = queue.Queue()
        stderr_queue: queue.Queue = queue.Queue()

        try:
            try:
                proc = subprocess.Popen(**popen_kwargs)
                sandbox_boundary.post_spawn(proc, prepared)
            except Exception as exc:
                # Fail-closed on Popen launch / preexec failure / sandbox attachment failure
                sandbox_boundary.cleanup(proc, prepared)
                raise LocalSubprocessPolicyViolation(
                    f"Subprocess invocation failed: {exc}"
                ) from exc

            # Start bounded-read threads
            t_stdout = threading.Thread(
                target=_read_bounded,
                args=(proc.stdout, policy.max_stdout_bytes, stdout_queue, "stdout"),
                daemon=True,
            )
            t_stderr = threading.Thread(
                target=_read_bounded,
                args=(proc.stderr, policy.max_stderr_bytes, stderr_queue, "stderr"),
                daemon=True,
            )
            t_stdout.start()
            t_stderr.start()

            # Wait with timeout
            try:
                proc.wait(timeout=policy.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                killed = True
                _kill_process_tree(proc, require_tree=True)
                audit_log.append(AuditEntry(
                    timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    event="SUBPROCESS_TIMEOUT",
                    invocation_id=invocation_id,
                    tool_id=policy.tool_id,
                    details={"timeout_s": policy.timeout_seconds},
                ))

            # Collect bounded output (wait for read threads with generous timeout)
            t_stdout.join(timeout=5.0)
            t_stderr.join(timeout=5.0)

            if not stdout_queue.empty():
                stdout_data, stdout_truncated = stdout_queue.get_nowait()
            if not stderr_queue.empty():
                stderr_data, stderr_truncated = stderr_queue.get_nowait()

            if stdout_truncated:
                audit_log.append(AuditEntry(
                    timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    event="STDOUT_TRUNCATED",
                    invocation_id=invocation_id,
                    tool_id=policy.tool_id,
                    details={"limit_bytes": policy.max_stdout_bytes},
                ))
                # Kill process after truncation (it may still be running)
                if proc.poll() is None:
                    killed = True
                    _kill_process_tree(proc, require_tree=True)

            if stderr_truncated:
                audit_log.append(AuditEntry(
                    timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    event="STDERR_TRUNCATED",
                    invocation_id=invocation_id,
                    tool_id=policy.tool_id,
                    details={"limit_bytes": policy.max_stderr_bytes},
                ))
                if proc.poll() is None:
                    killed = True
                    _kill_process_tree(proc, require_tree=True)

            exit_code = proc.returncode if proc.returncode is not None else -1

        finally:
            sandbox_boundary.cleanup(proc, prepared)
            # Unconditional cleanup
            if proc is not None:
                try:
                    if proc.poll() is None:
                        killed = True
                        _kill_process_tree(proc, require_tree=True)
                finally:
                    try:
                        if proc.stdout and not proc.stdout.closed:
                            proc.stdout.close()
                    except Exception:
                        pass
                    try:
                        if proc.stderr and not proc.stderr.closed:
                            proc.stderr.close()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass

        duration_ms = (time.monotonic() - start_time) * 1000.0

        audit_log.append(AuditEntry(
            timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            event="SUBPROCESS_COMPLETE",
            invocation_id=invocation_id,
            tool_id=policy.tool_id,
            details={
                "exit_code": exit_code,
                "timed_out": timed_out,
                "killed": killed,
                "duration_ms": round(duration_ms, 1),
                "stdout_bytes": len(stdout_data),
                "stderr_bytes": len(stderr_data),
            },
        ))

        return SubprocessResult(
            exit_code=exit_code,
            stdout_bytes=stdout_data,
            stderr_bytes=stderr_data,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            timed_out=timed_out,
            killed=killed,
            duration_ms=duration_ms,
        )
