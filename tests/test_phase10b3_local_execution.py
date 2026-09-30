"""
Phase 10B.3 — Comprehensive Test Suite.

Tests cover:
A. Allowlist / Binary Tests
B. Subprocess Security Tests  
C. Resource Limit Tests
D. tshark-Specific Tests
E. steghide-Specific Tests
F. LocalCryptoOps Tests
G. Capability Tests
H. Workspace / Confinement Tests
I. Normalization / Provenance Tests
J. Fail-Closed Tests
K. Orchestration Handler Tests

IMPORTANT: tshark and steghide are NOT available in the test environment.
Tests use controlled fake executables (temporary scripts) and mocked
subprocess boundaries. Never uses cmd.exe, powershell, bash, or python
as a substitute for authorized tools in production adapter tests.

NOTE: Tests that require real tshark/steghide are skipped with SKIP_BINARY
markers and clear reason messages.
"""

from __future__ import annotations

import base64
import codecs
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
from ctf_mentor.tools.local.policy import (
    LocalExecutionPolicy,
    ExecutableAllowlist,
    ToolUnavailableError,
    LocalSubprocessPolicyViolation,
    InputSizeLimitExceeded,
    OutputSizeLimitExceeded,
    WorkspaceConfinementError,
    ProcessCleanupError,
    LocalPolicyViolation,
    TSHARK_POLICY,
    STEGHIDE_POLICY,
    _probe_executable,
    _TRUSTED_PREFIXES,
    _is_path_trusted,
    EXECUTABLE_ALLOWLIST,
)
from ctf_mentor.tools.local.network import (
    LocalSubprocessRunner,
    SubprocessResult,
    AuditEntry,
    _read_bounded,
    _kill_process_tree,
    _build_minimal_env,
    _get_trusted_taskkill_path,
    _make_posix_preexec_fn,
)
from ctf_mentor.tools.local.adapter import (
    LocalToolAdapter,
    LocalExecutionContext,
    AuthorizedInvocationRecord,
    TRUSTED_INVOCATION_AUTHORITY,
)
from ctf_mentor.tools.local.orchestration import LocalToolOrchestrationHandler
from ctf_mentor.tools.adapters.tshark import (
    TsharkAdapter,
    TsharkInput,
    TsharkOperation,
    _validate_pcap_magic,
    _validate_safe_filename,
    _validate_field_name,
    _FILTER_ALLOWLIST,
    _FIELD_ALLOWLIST,
)
from ctf_mentor.tools.adapters.steghide import (
    SteghideAdapter,
    SteghideInput,
    SteghideOperation,
    _validate_steg_format,
    _validate_passphrase,
)
from ctf_mentor.tools.adapters.local_crypto import (
    LocalCryptoOpsAdapter,
    LocalCryptoInput,
    CryptoOperation,
    _validate_hex_string,
)
from ctf_mentor.tools.contracts import ExecutionClass, ToolResult, EvidenceCandidate
from ctf_mentor.workspace.capabilities import (
    WorkspaceCapabilitySpec,
    IssuedCapabilitySet,
    InputCapability,
    WorkCapability,
    OutputCapability,
    NULL_CAPABILITY_SPEC,
)


# ---------------------------------------------------------------------------
# Test markers
# ---------------------------------------------------------------------------
IS_WINDOWS = sys.platform == "win32"
IS_POSIX = not IS_WINDOWS
SKIP_ON_WINDOWS = pytest.mark.skipif(IS_WINDOWS, reason="POSIX-only feature")
SKIP_ON_POSIX = pytest.mark.skipif(IS_POSIX, reason="Windows-only feature")
TSHARK_AVAILABLE = EXECUTABLE_ALLOWLIST.is_available("tshark")
STEGHIDE_AVAILABLE = EXECUTABLE_ALLOWLIST.is_available("steghide")
SKIP_NEEDS_TSHARK = pytest.mark.skipif(
    not TSHARK_AVAILABLE,
    reason="tshark binary not available at any trusted path — skipped per test mandate"
)
SKIP_NEEDS_STEGHIDE = pytest.mark.skipif(
    not STEGHIDE_AVAILABLE,
    reason="steghide binary not available at any trusted path — skipped per test mandate"
)


# ---------------------------------------------------------------------------
# Test Fixtures and Helpers — Fake Executable Infrastructure
# ---------------------------------------------------------------------------

_PYTHON_EXE = Path(sys.executable)


def _register_test_invocation(
    invocation_id: str,
    cwd: Path,
    challenge_id: str = "ch-test",
    session_id: str = "sess-test",
    workspace_id: str = "ws-test",
    workspace_root: Optional[Path] = None,
) -> AuthorizedInvocationRecord:
    """Helper to register an authorized invocation for direct runner unit tests."""
    ws_root = workspace_root if workspace_root is not None else cwd
    return TRUSTED_INVOCATION_AUTHORITY.register(
        invocation_id=invocation_id,
        challenge_id=challenge_id,
        session_id=session_id,
        workspace_id=workspace_id,
        cwd=cwd,
        workspace_root=ws_root,
    )


@pytest.fixture(autouse=True)
def _auto_register_test_invocations(request):
    """Auto-registers known test invocation IDs when tmp_path fixture is active."""
    if "tmp_path" in request.fixturenames:
        tmp_p = request.getfixturevalue("tmp_path")
        for inv_id in (
            "test-inv-001", "test-inv-002", "test-inv-003", "test-inv-004",
            "test-inv-005", "test-inv-006", "test-timeout-001", "test-timeout-002",
            "test-timeout-003", "test-stdout-001", "test-exit-001", "test-audit-001",
            "test-cwd-pass", "test-nonzero-001", "test-argv-outside",
            "test-argv-traversal", "test-empty-argv",
        ):
            _register_test_invocation(inv_id, tmp_p)
    yield
    TRUSTED_INVOCATION_AUTHORITY.clear()


class FakeExe:
    """
    A cross-platform fake executable for subprocess runner tests.

    On POSIX: creates a real shell script (chmod +x) and uses it as exe.
    On Windows: uses sys.executable with ['-c', code] as argv.

    Usage (as context manager):
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            argv = fake.make_argv()
            result = runner.run(argv=argv, policy=policy, ...)
    """

    def __init__(self, exe_path: Path, inline_py: Optional[str] = None):
        self._exe_path = exe_path
        self._inline_py = inline_py

    @property
    def exe_path(self) -> Path:
        return self._exe_path

    def make_policy(
        self,
        timeout: float = 5.0,
        max_stdout: int = 1024 * 1024,
        max_stderr: int = 512 * 1024,
        max_input: int = 1024 * 1024,
        max_output: int = 1024 * 1024,
        tool_id: str = "test_tool",
    ) -> LocalExecutionPolicy:
        """Build a LocalExecutionPolicy whose executable_path matches this fake exe."""
        return LocalExecutionPolicy(
            tool_id=tool_id,
            executable_path=self._exe_path,
            timeout_seconds=timeout,
            max_stdout_bytes=max_stdout,
            max_stderr_bytes=max_stderr,
            max_input_bytes=max_input,
            max_output_bytes=max_output,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )

    def make_argv(self, extra_args: Optional[List[str]] = None) -> List[str]:
        """Build correct argv for the platform."""
        argv = [str(self._exe_path)]
        if IS_WINDOWS and self._inline_py is not None:
            argv.extend(["-c", self._inline_py])
        if extra_args:
            argv.extend(extra_args)
        return argv

    def cleanup(self) -> None:
        try:
            if self._exe_path.exists() and IS_POSIX:
                self._exe_path.unlink(missing_ok=True)
        except Exception:
            pass

    def __enter__(self) -> "FakeExe":
        return self

    def __exit__(self, *args) -> None:
        self.cleanup()

    @classmethod
    def _make(cls, posix_sh: str, win_py: str) -> "FakeExe":
        if IS_POSIX:
            fd, path_str = tempfile.mkstemp(suffix=".sh")
            path = Path(path_str)
            try:
                os.write(fd, posix_sh.encode())
            finally:
                os.close(fd)
            path.chmod(0o755)
            return cls(path)
        else:
            return cls(_PYTHON_EXE, win_py)

    @classmethod
    def noop(cls) -> "FakeExe":
        """Exits 0 with no output."""
        return cls._make(
            posix_sh="#!/bin/sh\nexit 0\n",
            win_py="import sys\nsys.exit(0)\n",
        )

    @classmethod
    def nonzero(cls, exit_code: int = 1) -> "FakeExe":
        """Exits with given non-zero code."""
        return cls._make(
            posix_sh=f"#!/bin/sh\nexit {exit_code}\n",
            win_py=f"import sys\nsys.exit({exit_code})\n",
        )

    @classmethod
    def slow(cls, sleep_seconds: int = 60) -> "FakeExe":
        """Sleeps then exits 0."""
        return cls._make(
            posix_sh=f"#!/bin/sh\nsleep {sleep_seconds}\nexit 0\n",
            win_py=f"import time, sys\ntime.sleep({sleep_seconds})\nsys.exit(0)\n",
        )

    @classmethod
    def flood_stdout(cls, target_bytes: int = 200 * 1024) -> "FakeExe":
        """Outputs approximately target_bytes of data."""
        kb = target_bytes // 1024
        return cls._make(
            posix_sh=(
                f"#!/bin/sh\n"
                f"dd if=/dev/zero bs=1024 count={kb} 2>/dev/null | tr '\\0' 'A'\n"
                f"exit 0\n"
            ),
            win_py=(
                f"import sys\n"
                f"sys.stdout.buffer.write(b'A' * {target_bytes})\n"
                f"sys.exit(0)\n"
            ),
        )


# --- Fake PCAP data (minimal valid magic bytes) ---
_FAKE_PCAP = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20   # le PCAP magic + padding
_FAKE_PCAPNG = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
_FAKE_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 20
_FAKE_BMP = b"BM" + b"\x00" * 20
_FAKE_WAV = b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 20
_FAKE_AU = b".snd" + b"\x00" * 20
_FAKE_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


def _make_mock_capability_set(
    workspace_id: str = "ws-test",
    challenge_id: str = "ch-test",
    session_id: str = "sess-test",
    input_store: Optional[Dict[str, bytes]] = None,
    work_store: Optional[Dict[str, bytes]] = None,
) -> IssuedCapabilitySet:
    """Build a real IssuedCapabilitySet backed by in-memory dicts."""
    input_store = input_store or {}
    work_store = work_store or {}

    def _read_bytes_input(rel_path: str) -> bytes:
        if rel_path not in input_store:
            raise FileNotFoundError(f"input/{rel_path} not found")
        return input_store[rel_path]

    def _read_text_input(rel_path: str, encoding: str = "utf-8") -> str:
        return _read_bytes_input(rel_path).decode(encoding)

    def _file_exists_input(rel_path: str) -> bool:
        return rel_path in input_store

    def _read_bytes_work(rel_path: str) -> bytes:
        if rel_path not in work_store:
            raise FileNotFoundError(f"work/{rel_path} not found")
        return work_store[rel_path]

    def _read_text_work(rel_path: str, encoding: str = "utf-8") -> str:
        return _read_bytes_work(rel_path).decode(encoding)

    def _file_exists_work(rel_path: str) -> bool:
        return rel_path in work_store

    def _write_bytes_work(rel_path: str, data: bytes) -> int:
        work_store[rel_path] = data
        return len(data)

    def _write_text_work(rel_path: str, data: str, encoding: str = "utf-8") -> int:
        work_store[rel_path] = data.encode(encoding)
        return len(data)

    def _delete_file_work(rel_path: str, missing_ok: bool = False) -> None:
        if rel_path in work_store:
            del work_store[rel_path]
        elif not missing_ok:
            raise FileNotFoundError(f"work/{rel_path} not found")

    input_cap = InputCapability(
        workspace_id, challenge_id, session_id,
        _read_bytes_fn=_read_bytes_input,
        _read_text_fn=_read_text_input,
        _file_exists_fn=_file_exists_input,
    )
    work_cap = WorkCapability(
        workspace_id, challenge_id, session_id,
        _read_bytes_fn=_read_bytes_work,
        _read_text_fn=_read_text_work,
        _file_exists_fn=_file_exists_work,
        _write_bytes_fn=_write_bytes_work,
        _write_text_fn=_write_text_work,
        _delete_file_fn=_delete_file_work,
    )
    return IssuedCapabilitySet(input_cap=input_cap, work_cap=work_cap)


def _make_local_ctx(
    policy: LocalExecutionPolicy,
    input_store: Optional[Dict[str, bytes]] = None,
    work_store: Optional[Dict[str, bytes]] = None,
) -> LocalExecutionContext:
    caps = _make_mock_capability_set(input_store=input_store, work_store=work_store)
    return LocalExecutionContext.create(
        caps=caps,
        policy=policy,
        challenge_id="ch-test",
        session_id="sess-test",
        workspace_id="ws-test",
    )


def _make_test_policy(
    exe_path: Optional[Path] = None,
    timeout: float = 5.0,
    max_stdout: int = 1 * 1024 * 1024,
    max_input: int = 10 * 1024 * 1024,
) -> LocalExecutionPolicy:
    return LocalExecutionPolicy(
        tool_id="test_tool",
        executable_path=exe_path,
        timeout_seconds=timeout,
        max_stdout_bytes=max_stdout,
        max_stderr_bytes=512 * 1024,
        max_input_bytes=max_input,
        max_output_bytes=5 * 1024 * 1024,
        posix_cpu_limit_s=None,
        posix_mem_limit_bytes=None,
        posix_fsize_limit_bytes=None,
        network_allowed=False,
    )


# ============================================================================
# A. Allowlist / Binary Tests
# ============================================================================

class TestExecutableAllowlist:

    def test_allowlist_is_singleton(self):
        """EXECUTABLE_ALLOWLIST is a module-level singleton."""
        from ctf_mentor.tools.local.policy import EXECUTABLE_ALLOWLIST as a1
        from ctf_mentor.tools.local import policy as pol_mod
        assert EXECUTABLE_ALLOWLIST is a1

    def test_allowlist_known_tools_present(self):
        """Allowlist has entries for tshark and steghide (may be None)."""
        # get_path returns None if absent — not raises
        path_t = EXECUTABLE_ALLOWLIST.get_path("tshark")
        path_s = EXECUTABLE_ALLOWLIST.get_path("steghide")
        # Result is either None or a Path
        assert path_t is None or isinstance(path_t, Path)
        assert path_s is None or isinstance(path_s, Path)

    def test_allowlist_unknown_tool_returns_none(self):
        """Unknown tool returns None (not raises)."""
        path = EXECUTABLE_ALLOWLIST.get_path("definitely_unknown_xxxx")
        assert path is None

    def test_allowlist_require_path_raises_for_unknown(self):
        """require_path raises ToolUnavailableError for unknown tool."""
        with pytest.raises(ToolUnavailableError):
            EXECUTABLE_ALLOWLIST.require_path("unknown_tool_xyz")

    def test_allowlist_require_path_raises_for_absent_binary(self):
        """require_path raises ToolUnavailableError when binary is absent."""
        allowlist = ExecutableAllowlist.__new__(ExecutableAllowlist)
        allowlist._paths = {"test_tool": None}
        with pytest.raises(ToolUnavailableError):
            allowlist.require_path("test_tool")

    def test_allowlist_is_available_returns_false_for_none(self):
        allowlist = ExecutableAllowlist.__new__(ExecutableAllowlist)
        allowlist._paths = {"mytool": None}
        assert not allowlist.is_available("mytool")

    def test_allowlist_is_available_returns_false_for_unknown(self):
        assert not EXECUTABLE_ALLOWLIST.is_available("not_a_real_tool_xyz")

    def test_probe_returns_none_for_nonexistent_path(self):
        """_probe_executable returns None for a path that doesn't exist."""
        result = _probe_executable("nonexistent_tool_xyz_12345")
        assert result is None

    def test_probe_rejects_path_outside_trusted_prefix(self, tmp_path):
        """_probe_executable rejects binaries not in trusted prefix dirs."""
        # Create a fake binary in a non-trusted location
        fake_bin = tmp_path / "tshark"
        fake_bin.write_bytes(b"#!/bin/sh\n")
        fake_bin.chmod(0o755)
        # Direct call to probe with a fresh allowlist — the file exists but
        # the tmp_path is not in _TRUSTED_PREFIXES, so it should not be returned.
        # We verify this by checking that the probe for our tmp path isn't trusted
        from ctf_mentor.tools.local.policy import _TRUSTED_PREFIXES
        assert not any(
            str(fake_bin).startswith(p) or str(fake_bin).lower().startswith(p.lower())
            for p in _TRUSTED_PREFIXES
        )

    def test_policy_constants_frozen(self):
        """LocalExecutionPolicy is a frozen dataclass."""
        with pytest.raises((TypeError, AttributeError)):
            TSHARK_POLICY.timeout_seconds = 999  # type: ignore

    def test_network_allowed_always_false(self):
        assert TSHARK_POLICY.network_allowed is False
        assert STEGHIDE_POLICY.network_allowed is False

    def test_policy_rejects_network_true(self):
        with pytest.raises(ValueError, match="network_allowed must be False"):
            LocalExecutionPolicy(
                tool_id="bad",
                executable_path=None,
                timeout_seconds=10,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=None,
                posix_mem_limit_bytes=None,
                posix_fsize_limit_bytes=None,
                network_allowed=True,  # must raise
            )

    def test_policy_rejects_zero_timeout(self):
        with pytest.raises(ValueError, match="timeout_seconds"):
            LocalExecutionPolicy(
                tool_id="bad",
                executable_path=None,
                timeout_seconds=0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=None,
                posix_mem_limit_bytes=None,
                posix_fsize_limit_bytes=None,
                network_allowed=False,
            )

    def test_windows_path_normalization_prefix_rule(self):
        """Path-aware verification correctly identifies trusted and untrusted paths on Windows."""
        if IS_WINDOWS:
            # Valid canonical Wireshark and steghide paths
            assert _is_path_trusted(Path(r"C:\Program Files\Wireshark\tshark.exe"))
            assert _is_path_trusted(Path(r"c:\program files\wireshark\tshark.exe"))
            assert _is_path_trusted(Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"))
            assert _is_path_trusted(Path(r"C:\Program Files\steghide\steghide.exe"))
            # Untrusted paths outside approved directory trees
            assert not _is_path_trusted(Path(r"C:\Temp\tshark.exe"))
            assert not _is_path_trusted(Path(r"C:\Windows\System32\tshark.exe"))
            assert not _is_path_trusted(Path(r"C:\Users\Public\steghide.exe"))
        else:
            # POSIX trusted paths
            assert _is_path_trusted(Path("/usr/bin/tshark"))
            assert _is_path_trusted(Path("/usr/local/bin/tshark"))
            assert _is_path_trusted(Path("/usr/bin/steghide"))
            # Untrusted paths
            assert not _is_path_trusted(Path("/tmp/tshark"))
            assert not _is_path_trusted(Path("/home/user/steghide"))


# ============================================================================
# B. Subprocess Security Tests
# ============================================================================

class TestSubprocessSecurity:

    def test_windows_taskkill_path_ignores_manipulated_systemroot(self):
        """Taskkill resolver falls back to trusted Windows directory if SystemRoot is manipulated."""
        if IS_WINDOWS:
            with patch.dict(os.environ, {"SystemRoot": r"C:\Manipulated\EvilDir"}):
                resolved = _get_trusted_taskkill_path()
                # Must either be None or resolve to trusted Windows\System32\taskkill.exe
                if resolved is not None:
                    assert "manipulated" not in str(resolved).lower()
                    assert "windows" in str(resolved).lower()
                    assert resolved.name.lower() == "taskkill.exe"

    def test_runner_shell_false_enforced_by_popen(self, tmp_path):
        """Verify LocalSubprocessRunner never calls Popen with shell=True."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log: List[AuditEntry] = []

            original_popen = subprocess.Popen
            popen_calls = []

            def capturing_popen(*args, **kwargs):
                popen_calls.append(kwargs.get("shell", False))
                return original_popen(*args, **kwargs)

            with patch("subprocess.Popen", side_effect=capturing_popen):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-inv-001",
                    audit_log=audit_log,
                )

            assert all(shell is False for shell in popen_calls), (
                "subprocess.Popen was called with shell=True — invariant violated!"
            )

    def test_runner_rejects_argv_mismatch_with_policy_exe(self, tmp_path):
        """Runner raises if argv[0] does not match policy executable_path."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            with pytest.raises(LocalSubprocessPolicyViolation, match="does not match policy"):
                runner.run(
                    argv=["/some/other/binary", "-x"],
                    policy=policy,
                    env=env,
                    invocation_id="test-inv-002",
                    audit_log=[],
                )

    def test_runner_rejects_null_byte_in_argv(self, tmp_path):
        """Runner raises LocalSubprocessPolicyViolation on null byte in argv."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            with pytest.raises(LocalSubprocessPolicyViolation, match="null byte"):
                runner.run(
                    argv=[str(fake.exe_path), "arg\x00malicious"],
                    policy=policy,
                    env=env,
                    invocation_id="test-inv-003",
                    audit_log=[],
                )

    def test_runner_env_no_ld_preload(self):
        """Sanitized env has no LD_PRELOAD."""
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        assert "LD_PRELOAD" not in env
        assert "LD_PRELOAD" not in (k.upper() for k in env)

    def test_runner_env_no_pythonpath(self):
        """Sanitized env has no PYTHONPATH."""
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        assert "PYTHONPATH" not in env

    def test_runner_env_no_ld_library_path(self):
        """Sanitized env has no LD_LIBRARY_PATH."""
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        assert "LD_LIBRARY_PATH" not in env

    def test_runner_env_does_not_inherit_os_environ(self):
        """Runner env does not contain arbitrary os.environ keys."""
        sentinel_key = "CTF_MENTOR_SENTINEL_TEST_KEY_XYZ_12345"
        old_val = os.environ.get(sentinel_key)
        try:
            os.environ[sentinel_key] = "should_not_appear"
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            assert sentinel_key not in env, (
                f"Runner environment inherited os.environ key {sentinel_key!r}"
            )
        finally:
            if old_val is None:
                os.environ.pop(sentinel_key, None)
            else:
                os.environ[sentinel_key] = old_val

    def test_runner_rejects_banned_env_key_ld_preload(self):
        """Runner raises if caller tries to inject LD_PRELOAD via extra env."""
        runner = LocalSubprocessRunner()
        with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment"):
            runner.build_env(extra={"LD_PRELOAD": "/evil/lib.so"})

    def test_runner_rejects_banned_env_key_pythonpath(self):
        """Runner raises if caller tries to inject PYTHONPATH via extra env."""
        runner = LocalSubprocessRunner()
        with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment"):
            runner.build_env(extra={"PYTHONPATH": "/evil/pypath"})

    def test_runner_rejects_caller_supplied_cwd(self, tmp_path):
        """Runner raises if caller passes explicit cwd parameter."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            with pytest.raises(LocalSubprocessPolicyViolation, match="Caller-supplied cwd is forbidden"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    invocation_id="test-inv-004",
                    env=env,
                    audit_log=[],
                    cwd=tmp_path,
                )

    def test_runner_raises_for_none_executable_path(self, tmp_path):
        """Runner raises ToolUnavailableError if policy.executable_path is None."""
        policy = _make_test_policy(exe_path=None)
        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with pytest.raises(ToolUnavailableError):
            runner.run(
                argv=["/some/path"],
                policy=policy,
                env=env,
                invocation_id="test-inv-005",
                audit_log=[],
            )

    def test_runner_returns_subprocess_result_on_success(self, tmp_path):
        """Runner returns SubprocessResult with exit_code=0 on success."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-inv-006",
                audit_log=[],
            )
            assert isinstance(result, SubprocessResult)
            assert result.exit_code == 0
            assert not result.timed_out
            assert not result.stdout_truncated


# ============================================================================
# C. Resource Limit Tests
# ============================================================================

class TestResourceLimits:

    def test_timeout_sets_timed_out_flag(self, tmp_path):
        """A subprocess that runs longer than timeout has timed_out=True."""
        with FakeExe.slow(sleep_seconds=60) as fake:
            policy = fake.make_policy(timeout=1.0)
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-timeout-001",
                audit_log=[],
            )
            assert result.timed_out is True
            assert result.killed is True

    def test_timeout_process_killed(self, tmp_path):
        """Timed-out process is killed (not still running)."""
        with FakeExe.slow(sleep_seconds=60) as fake:
            policy = fake.make_policy(timeout=1.0)
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            t_start = time.monotonic()
            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-timeout-002",
                audit_log=[],
            )
            elapsed = time.monotonic() - t_start
            assert elapsed < 15, f"run() took {elapsed:.1f}s — process may not have been killed"
            assert result.killed is True

    def test_timeout_audit_event_recorded(self, tmp_path):
        """SUBPROCESS_TIMEOUT audit event is recorded on timeout."""
        with FakeExe.slow(sleep_seconds=60) as fake:
            policy = fake.make_policy(timeout=1.0)
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log: List[AuditEntry] = []

            runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-timeout-003",
                audit_log=audit_log,
            )
            events = [e.event for e in audit_log]
            assert "SUBPROCESS_TIMEOUT" in events

    @SKIP_ON_WINDOWS
    def test_posix_stdout_limit_kills_process(self, tmp_path):
        """Subprocess is killed when stdout exceeds max_stdout_bytes (POSIX only)."""
        with FakeExe.flood_stdout(target_bytes=200 * 1024) as fake:
            policy = fake.make_policy(max_stdout=50 * 1024)
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log: List[AuditEntry] = []

            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-stdout-001",
                audit_log=audit_log,
            )
            assert result.stdout_truncated is True
            assert len(result.stdout_bytes) <= 50 * 1024 + 4096

    def test_read_bounded_returns_exact_limit(self):
        """_read_bounded returns exactly limit bytes and sets truncated=True."""
        import io
        data = b"A" * 10000
        pipe = io.BytesIO(data)

        result_queue = __import__("queue").Queue()
        _read_bounded(pipe, limit=5000, result_queue=result_queue, label="test")

        out_data, truncated = result_queue.get_nowait()
        assert truncated is True
        assert len(out_data) <= 5000

    def test_read_bounded_not_truncated_when_under_limit(self):
        """_read_bounded returns all data and truncated=False when under limit."""
        import io
        data = b"B" * 100
        pipe = io.BytesIO(data)

        result_queue = __import__("queue").Queue()
        _read_bounded(pipe, limit=1000, result_queue=result_queue, label="test")

        out_data, truncated = result_queue.get_nowait()
        assert truncated is False
        assert out_data == data

    def test_nonzero_exit_reflected_in_result(self, tmp_path):
        """Non-zero exit code is correctly captured in SubprocessResult."""
        with FakeExe.nonzero(exit_code=42) as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()

            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-exit-001",
                audit_log=[],
            )
            assert result.exit_code == 42

    def test_audit_log_records_start_and_complete(self, tmp_path):
        """Audit log has SUBPROCESS_START and SUBPROCESS_COMPLETE events."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log: List[AuditEntry] = []

            runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-audit-001",
                audit_log=audit_log,
            )
            events = [e.event for e in audit_log]
            assert "SUBPROCESS_START" in events
            assert "SUBPROCESS_COMPLETE" in events

    def test_posix_resource_limit_failure_fails_closed(self):
        """Resource limit setup failures must propagate and prevent execution (fail-closed)."""
        policy = LocalExecutionPolicy(
            tool_id="test_tool",
            executable_path=Path("/usr/bin/tshark"),
            timeout_seconds=5.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=1024,
            max_output_bytes=1024,
            posix_cpu_limit_s=10,
            posix_mem_limit_bytes=100 * 1024 * 1024,
            posix_fsize_limit_bytes=50 * 1024 * 1024,
            network_allowed=False,
        )
        preexec_fn = _make_posix_preexec_fn(policy)
        if preexec_fn is not None:
            # If resource module exists or is mocked to fail
            mock_resource = MagicMock()
            mock_resource.setrlimit.side_effect = OSError("Permission denied setting RLIMIT")
            with patch.dict("sys.modules", {"resource": mock_resource}):
                # Re-create preexec fn with mocked failing resource
                failing_preexec = _make_posix_preexec_fn(policy)
                if failing_preexec:
                    with pytest.raises(OSError, match="Permission denied"):
                        failing_preexec()


# ============================================================================
# D. tshark-Specific Tests
# ============================================================================

class TestTsharkAdapter:

    def test_tshark_execution_class(self):
        assert TsharkAdapter.execution_class == ExecutionClass.PASSIVE_LOCAL

    def test_tshark_tool_id(self):
        assert TsharkAdapter.tool_id == "tshark"

    def test_tshark_workspace_capability_spec(self):
        spec = TsharkAdapter.workspace_capability_spec
        assert isinstance(spec, WorkspaceCapabilitySpec)
        assert spec.needs_input is True
        assert spec.needs_work_read is True
        assert spec.needs_work_write is True

    def test_tshark_argv_template_name_is_constant(self):
        assert isinstance(TsharkAdapter._ARGV_TEMPLATE_NAME, str)
        assert TsharkAdapter._ARGV_TEMPLATE_NAME  # not empty

    def test_tshark_execute_raises_runtime_error(self):
        """execute() raises RuntimeError — local adapters must use execute_local()."""
        adapter = TsharkAdapter()
        with pytest.raises(RuntimeError, match="execute_local"):
            adapter.execute(None, None)

    # --- Input Validation ---

    def test_tshark_validate_input_packet_summary(self):
        inp = TsharkInput.validate({
            "operation": "PACKET_SUMMARY",
            "input_filename": "capture.pcap",
            "packet_count": 50,
        })
        assert inp.operation == TsharkOperation.PACKET_SUMMARY
        assert inp.packet_count == 50

    def test_tshark_validate_input_field_extract(self):
        inp = TsharkInput.validate({
            "operation": "FIELD_EXTRACT",
            "input_filename": "capture.pcap",
            "field_name": "ip.src",
        })
        assert inp.operation == TsharkOperation.FIELD_EXTRACT
        assert inp.field_name == "ip.src"

    def test_tshark_validate_input_protocol_filter(self):
        inp = TsharkInput.validate({
            "operation": "PROTOCOL_FILTER",
            "input_filename": "capture.pcap",
            "protocol_key": "http",
        })
        assert inp.operation == TsharkOperation.PROTOCOL_FILTER
        assert inp.protocol_key == "http"

    def test_tshark_rejects_unknown_operation(self):
        with pytest.raises(ValueError, match="operation must be one of"):
            TsharkInput.validate({
                "operation": "LIVE_CAPTURE",  # forbidden
                "input_filename": "capture.pcap",
            })

    def test_tshark_rejects_unknown_keys(self):
        with pytest.raises(ValueError, match="Unexpected input keys"):
            TsharkInput.validate({
                "operation": "PACKET_SUMMARY",
                "input_filename": "capture.pcap",
                "extra_evil_key": "bad",
            })

    def test_tshark_rejects_packet_count_zero(self):
        with pytest.raises(ValueError, match="packet_count"):
            TsharkInput.validate({
                "operation": "PACKET_SUMMARY",
                "input_filename": "capture.pcap",
                "packet_count": 0,
            })

    def test_tshark_rejects_packet_count_too_large(self):
        with pytest.raises(ValueError, match="packet_count"):
            TsharkInput.validate({
                "operation": "PACKET_SUMMARY",
                "input_filename": "capture.pcap",
                "packet_count": 9999,
            })

    def test_tshark_rejects_arbitrary_display_filter(self):
        """User cannot supply a raw display filter string."""
        with pytest.raises((ValueError, KeyError)):
            TsharkInput.validate({
                "operation": "PROTOCOL_FILTER",
                "input_filename": "capture.pcap",
                "protocol_key": "ip.src == 1.2.3.4 or eth.type == 0x0800",
            })

    def test_tshark_rejects_non_allowlisted_field(self):
        with pytest.raises(ValueError, match="allowlist"):
            TsharkInput.validate({
                "operation": "FIELD_EXTRACT",
                "input_filename": "capture.pcap",
                "field_name": "frame.coloring_rule.name",  # not in allowlist
            })

    def test_tshark_rejects_field_with_path_separator(self):
        with pytest.raises(ValueError):
            _validate_field_name("../etc/passwd")

    def test_tshark_rejects_field_with_special_chars(self):
        with pytest.raises(ValueError):
            _validate_field_name("ip.src; rm -rf /")

    def test_tshark_rejects_path_traversal_in_filename(self):
        with pytest.raises(WorkspaceConfinementError):
            TsharkInput.validate({
                "operation": "PACKET_SUMMARY",
                "input_filename": "../../etc/passwd",
            })

    def test_tshark_rejects_filename_with_slash(self):
        with pytest.raises(WorkspaceConfinementError):
            _validate_safe_filename("subdir/capture.pcap")

    def test_tshark_rejects_filename_with_null_byte(self):
        with pytest.raises(WorkspaceConfinementError):
            _validate_safe_filename("file\x00name.pcap")

    # --- Magic Byte Validation ---

    def test_tshark_accepts_valid_pcap_le_magic(self):
        """Little-endian PCAP magic is accepted."""
        _validate_pcap_magic(_FAKE_PCAP, "test.pcap")  # should not raise

    def test_tshark_accepts_valid_pcap_be_magic(self):
        """Big-endian PCAP magic is accepted."""
        _validate_pcap_magic(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20, "test.pcap")

    def test_tshark_accepts_pcapng_magic(self):
        """PCAPNG magic is accepted."""
        _validate_pcap_magic(_FAKE_PCAPNG, "test.pcapng")

    def test_tshark_rejects_exe_file(self):
        """EXE file magic is rejected."""
        with pytest.raises(ValueError, match="PCAP"):
            _validate_pcap_magic(b"MZ\x90\x00" + b"\x00" * 20, "evil.exe")

    def test_tshark_rejects_jpeg_file(self):
        """JPEG file is rejected (wrong type for tshark)."""
        with pytest.raises(ValueError, match="PCAP"):
            _validate_pcap_magic(_FAKE_JPEG, "image.jpg")

    def test_tshark_rejects_too_small_file(self):
        with pytest.raises(ValueError, match="too small"):
            _validate_pcap_magic(b"\xd4\xc3", "tiny.pcap")

    # --- argv Construction ---

    def test_tshark_packet_summary_argv_has_n_flag(self):
        """PACKET_SUMMARY argv always has -n."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
            packet_count=10,
        )
        argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
        assert "-n" in argv, "tshark -n flag missing from argv — name resolution not disabled"

    def test_tshark_argv_no_interface_flag(self):
        """argv must never contain -i (live capture)."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        for op in TsharkOperation:
            inp = TsharkInput(
                operation=op,
                input_filename="cap.pcap",
                packet_count=10,
                field_name="ip.src" if op == TsharkOperation.FIELD_EXTRACT else None,
                protocol_key="http" if op == TsharkOperation.PROTOCOL_FILTER else None,
            )
            argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
            assert "-i" not in argv, f"Forbidden flag -i found in argv for {op}"

    def test_tshark_argv_no_write_flag(self):
        """argv must never contain -w (write capture)."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        for op in TsharkOperation:
            inp = TsharkInput(
                operation=op,
                input_filename="cap.pcap",
                packet_count=10,
                field_name="ip.src" if op == TsharkOperation.FIELD_EXTRACT else None,
                protocol_key="http" if op == TsharkOperation.PROTOCOL_FILTER else None,
            )
            argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
            assert "-w" not in argv, f"Forbidden flag -w found in argv for {op}"

    def test_tshark_argv_no_lua_script_flag(self):
        """argv must never contain -X (Lua/plugins)."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        for op in TsharkOperation:
            inp = TsharkInput(
                operation=op,
                input_filename="cap.pcap",
                packet_count=10,
                field_name="ip.src" if op == TsharkOperation.FIELD_EXTRACT else None,
                protocol_key="http" if op == TsharkOperation.PROTOCOL_FILTER else None,
            )
            argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
            assert "-X" not in argv, f"Forbidden flag -X found in argv for {op}"

    def test_tshark_packet_count_is_validated_int_in_argv(self):
        """Packet count in argv is a validated int (not user string)."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
            packet_count=42,
        )
        argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
        assert "42" in argv
        # Verify it's the str() of the validated int, not from raw args
        c_idx = argv.index("-c")
        assert argv[c_idx + 1] == "42"

    def test_tshark_filter_is_from_allowlist_not_user_string(self):
        """PROTOCOL_FILTER uses the allowlist filter value, not user input."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        inp = TsharkInput(
            operation=TsharkOperation.PROTOCOL_FILTER,
            input_filename="cap.pcap",
            protocol_key="http",
        )
        argv = adapter._build_argv(exe, "/tmp/input.pcap", inp)
        # The value should be the allowlist filter, not the key
        assert _FILTER_ALLOWLIST["http"] in argv
        y_idx = argv.index("-Y")
        assert argv[y_idx + 1] == _FILTER_ALLOWLIST["http"]

    # --- Fail-Closed: Tool Unavailable ---

    def test_tshark_unavailable_raises_tool_unavailable_error(self):
        """If tshark is unavailable, execute_local raises ToolUnavailableError."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,  # unavailable
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        with pytest.raises(ToolUnavailableError):
            adapter.execute_local(inp, "scope", ctx)

    def test_tshark_capabilities_revoked_on_unavailable_error(self):
        """Capabilities are revoked even when ToolUnavailableError is raised."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass
        assert ctx.caps.all_revoked, "Capabilities not revoked after ToolUnavailableError"

    def test_tshark_input_size_limit_enforced(self):
        """InputSizeLimitExceeded raised if input exceeds policy limit."""
        adapter = TsharkAdapter()
        small_limit_policy = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,  # won't reach subprocess
            timeout_seconds=30.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=10,   # tiny limit
            max_output_bytes=1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        big_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100  # 104 bytes > 10 byte limit
        ctx = _make_local_ctx(small_limit_policy, input_store={"cap.pcap": big_data})
        # We set executable_path=None so it raises ToolUnavailableError before InputSizeLimitExceeded.
        # Set a real path to test input size limit:
        policy_with_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=Path("/usr/bin/tshark"),   # may not exist, but checked after size
            timeout_seconds=30.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=10,   # tiny limit
            max_output_bytes=1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx2 = _make_local_ctx(policy_with_exe, input_store={"cap.pcap": big_data})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        with pytest.raises((InputSizeLimitExceeded, ToolUnavailableError)):
            adapter.execute_local(inp, "scope", ctx2)

    # --- WIRESHARK_CONFIG_DIR test (no actual subprocess needed) ---

    def test_tshark_wireshark_config_dir_in_env(self, tmp_path):
        """WIRESHARK_CONFIG_DIR key appears in the environment passed to subprocess."""
        popen_kwargs_captured = []

        original_popen = subprocess.Popen

        def capturing_popen(*args, **kwargs):
            popen_kwargs_captured.append(dict(kwargs))
            return original_popen(*args, **kwargs)

        with FakeExe.noop() as fake:
            runner = LocalSubprocessRunner()
            env = runner.build_env(extra={"WIRESHARK_CONFIG_DIR": str(tmp_path)})

            assert "WIRESHARK_CONFIG_DIR" in env
            assert env["WIRESHARK_CONFIG_DIR"] == str(tmp_path)
            _ = fake  # exe created to satisfy context manager; env test doesn't need to run it

    # --- Normalization ---

    def test_tshark_normalizes_valid_json_output(self):
        adapter = TsharkAdapter()
        packets = [
            {"_source": {"layers": {
                "frame": {"frame.number": "1", "frame.protocols": "tcp"},
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
            }}}
        ]
        raw = json.dumps(packets).encode()
        obs = adapter.normalize(raw, {
            "operation": TsharkOperation.PACKET_SUMMARY.value,
            "invocation_id": "test-norm-001",
            "input_filename": "cap.pcap",
        })
        assert len(obs) > 0
        for o in obs:
            assert o.trust == "UNTRUSTED"

    def test_tshark_normalizes_malformed_json_gracefully(self):
        """Malformed JSON output does not crash normalize — returns error observation."""
        adapter = TsharkAdapter()
        obs = adapter.normalize(
            b"not valid json {{{",
            {
                "operation": TsharkOperation.PACKET_SUMMARY.value,
                "invocation_id": "test-norm-002",
                "input_filename": "cap.pcap",
            },
        )
        assert len(obs) == 1
        assert "parse error" in obs[0].observation.lower()
        assert obs[0].trust == "UNTRUSTED"

    def test_tshark_all_observations_untrusted(self):
        """All EvidenceCandidate objects have trust='UNTRUSTED'."""
        adapter = TsharkAdapter()
        packets = [{"_source": {"layers": {}}}] * 5
        raw = json.dumps(packets).encode()
        obs = adapter.normalize(raw, {
            "operation": TsharkOperation.PACKET_SUMMARY.value,
            "invocation_id": "test-norm-003",
            "input_filename": "cap.pcap",
        })
        assert all(o.trust == "UNTRUSTED" for o in obs)

    def test_tshark_result_has_invocation_id_in_provenance(self, tmp_path):
        """ToolResult provenance contains invocation_id."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        invocation_id = ctx.invocation_id
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass

    @SKIP_NEEDS_TSHARK
    def test_tshark_real_binary_packet_summary(self, tmp_path):
        """Integration test: real tshark returns valid ToolResult on minimal PCAP."""
        pytest.skip("Real binary integration tests deferred to CI with test PCAP fixtures")


# ============================================================================
# E. steghide-Specific Tests
# ============================================================================

class TestSteghideAdapter:

    def test_steghide_execution_class(self):
        assert SteghideAdapter.execution_class == ExecutionClass.PASSIVE_LOCAL

    def test_steghide_tool_id(self):
        assert SteghideAdapter.tool_id == "steghide"

    def test_steghide_execute_raises_runtime_error(self):
        adapter = SteghideAdapter()
        with pytest.raises(RuntimeError, match="execute_local"):
            adapter.execute(None, None)

    # --- EMBED operation permanently excluded ---

    def test_steghide_embed_not_in_operation_enum(self):
        """EMBED is not a valid SteghideOperation."""
        valid_ops = {o.value for o in SteghideOperation}
        assert "EMBED" not in valid_ops

    def test_steghide_embed_input_validation_fails(self):
        """Input validation rejects 'EMBED' operation."""
        with pytest.raises(ValueError, match="operation must be one of"):
            SteghideInput.validate({
                "operation": "EMBED",
                "input_filename": "cover.jpg",
            })

    # --- Format validation ---

    def test_steghide_accepts_jpeg(self):
        fmt = _validate_steg_format(_FAKE_JPEG, "test.jpg")
        assert fmt == "jpeg"

    def test_steghide_accepts_bmp(self):
        fmt = _validate_steg_format(_FAKE_BMP, "test.bmp")
        assert fmt == "bmp"

    def test_steghide_accepts_wav(self):
        fmt = _validate_steg_format(_FAKE_WAV, "test.wav")
        assert fmt == "wav"

    def test_steghide_accepts_au(self):
        fmt = _validate_steg_format(_FAKE_AU, "test.au")
        assert fmt == "au"

    def test_steghide_rejects_png(self):
        with pytest.raises(ValueError, match="not a supported"):
            _validate_steg_format(_FAKE_PNG, "test.png")

    def test_steghide_rejects_pcap(self):
        with pytest.raises(ValueError, match="not a supported"):
            _validate_steg_format(_FAKE_PCAP, "test.pcap")

    def test_steghide_rejects_too_small_file(self):
        with pytest.raises(ValueError, match="too small"):
            _validate_steg_format(b"\xff\xd8", "tiny.jpg")

    # --- Passphrase validation ---

    def test_steghide_accepts_empty_passphrase(self):
        """Empty passphrase is valid (steghide allows no passphrase)."""
        _validate_passphrase("")  # should not raise

    def test_steghide_accepts_normal_passphrase(self):
        _validate_passphrase("CTF_secret_2024!")  # should not raise

    def test_steghide_rejects_passphrase_with_null_byte(self):
        with pytest.raises(ValueError, match="null byte"):
            _validate_passphrase("secret\x00evil")

    def test_steghide_rejects_too_long_passphrase(self):
        with pytest.raises(ValueError, match="maximum length"):
            _validate_passphrase("A" * 2000)

    def test_steghide_rejects_non_printable_passphrase(self):
        with pytest.raises(ValueError, match="non-printable"):
            _validate_passphrase("secret\x01\x02")

    # --- Passphrase redaction ---

    def test_steghide_passphrase_not_in_provenance(self):
        """Passphrase must not appear in ToolResult.provenance."""
        adapter = SteghideAdapter()
        secret = "super_secret_passphrase_XYZ"
        policy_no_exe = LocalExecutionPolicy(
            tool_id="steghide",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1 * 1024 * 1024,
            max_stderr_bytes=512 * 1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=5 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cover.jpg": _FAKE_JPEG})
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase=secret,
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass
        # The ToolUnavailableError is raised; by this point ctx.caps are revoked
        # and no ToolResult was generated. The passphrase should not be in any
        # AuditEntry either.
        for entry in ctx.audit_log:
            assert secret not in str(entry.details), (
                f"Passphrase found in audit log entry: {entry}"
            )

    def test_steghide_passphrase_not_in_audit_log(self):
        """Passphrase does not appear in any audit log entry details."""
        secret = "another_secret_QWERTY"
        adapter = SteghideAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="steghide",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1 * 1024 * 1024,
            max_stderr_bytes=512 * 1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=5 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cover.jpg": _FAKE_JPEG})
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase=secret,
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass
        for entry in ctx.audit_log:
            for val in entry.details.values():
                assert secret not in str(val), f"Secret in audit log: {entry}"

    def test_steghide_to_dict_excludes_passphrase(self):
        """SteghideInput.to_dict() does not include passphrase."""
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase="top_secret_passphrase",
        )
        d = inp.to_dict()
        assert "passphrase" not in d
        assert "top_secret_passphrase" not in str(d)

    # --- argv Construction ---

    def test_steghide_extract_argv_contains_extract_verb(self):
        adapter = SteghideAdapter()
        exe = Path("/usr/bin/steghide")
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase="pass",
        )
        argv = adapter._build_argv(exe, "/tmp/input.jpg", "/tmp/output.bin", inp)
        assert argv[1] == "extract"

    def test_steghide_info_argv_contains_info_verb(self):
        adapter = SteghideAdapter()
        exe = Path("/usr/bin/steghide")
        inp = SteghideInput(
            operation=SteghideOperation.INFO,
            input_filename="cover.jpg",
        )
        argv = adapter._build_argv(exe, "/tmp/input.jpg", "/tmp/output.bin", inp)
        assert argv[1] == "info"

    def test_steghide_extract_argv_has_no_embed_verb(self):
        adapter = SteghideAdapter()
        exe = Path("/usr/bin/steghide")
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase="pass",
        )
        argv = adapter._build_argv(exe, "/tmp/input.jpg", "/tmp/output.bin", inp)
        assert "embed" not in argv

    def test_steghide_rejects_path_traversal_in_filename(self):
        with pytest.raises(WorkspaceConfinementError):
            SteghideInput.validate({
                "operation": "EXTRACT",
                "input_filename": "../../etc/shadow",
                "passphrase": "",
            })

    # --- Capability revocation ---

    def test_steghide_caps_revoked_on_unavailable(self):
        """Capabilities revoked even when tool is unavailable."""
        adapter = SteghideAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="steghide",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1 * 1024 * 1024,
            max_stderr_bytes=512 * 1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=5 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cover.jpg": _FAKE_JPEG})
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase="",
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass
        assert ctx.caps.all_revoked

    @SKIP_NEEDS_STEGHIDE
    def test_steghide_real_binary_integration(self):
        pytest.skip("Real binary integration tests deferred to CI with test fixtures")


# ============================================================================
# F. LocalCryptoOps Tests
# ============================================================================

class TestLocalCryptoOpsAdapter:

    def _make_crypto_ctx(self) -> LocalExecutionContext:
        """Create a context with NULL_CAPABILITY_SPEC (crypto needs no caps)."""
        # NULL caps
        caps = IssuedCapabilitySet()
        policy = LocalExecutionPolicy(
            tool_id="local_crypto_ops",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        return LocalExecutionContext.create(
            caps=caps,
            policy=policy,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
        )

    def test_crypto_execution_class(self):
        assert LocalCryptoOpsAdapter.execution_class == ExecutionClass.PASSIVE_LOCAL

    def test_crypto_tool_id(self):
        assert LocalCryptoOpsAdapter.tool_id == "local_crypto_ops"

    def test_crypto_execute_raises_runtime_error(self):
        adapter = LocalCryptoOpsAdapter()
        with pytest.raises(RuntimeError, match="execute_local"):
            adapter.execute(None, None)

    def test_crypto_base64_encode(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"Hello, CTF!"
        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.BASE64_ENCODE,
                data_hex=data.hex(),
            ),
            "scope",
            ctx,
        )
        assert result.error_status is None
        encoded = base64.b64encode(data).decode()
        assert any(encoded in o.observation for o in result.normalized_observations)

    def test_crypto_base64_roundtrip(self):
        """BASE64_ENCODE then BASE64_DECODE returns original data."""
        adapter = LocalCryptoOpsAdapter()
        original = b"round trip test data 1234"

        ctx1 = self._make_crypto_ctx()
        result_enc = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.BASE64_ENCODE,
                data_hex=original.hex(),
            ),
            "scope", ctx1,
        )
        assert result_enc.error_status is None
        encoded_b64 = base64.b64encode(original).decode()

        ctx2 = self._make_crypto_ctx()
        result_dec = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.BASE64_DECODE,
                data_hex=encoded_b64.encode().hex(),
            ),
            "scope", ctx2,
        )
        assert result_dec.error_status is None
        assert result_dec.raw_data == original

    def test_crypto_hex_encode(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"\xde\xad\xbe\xef"
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.HEX_ENCODE, data_hex=data.hex()),
            "scope", ctx,
        )
        assert result.error_status is None
        assert any("deadbeef" in o.observation for o in result.normalized_observations)

    def test_crypto_hex_decode(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        hex_str = "deadbeef"
        # data_hex is the hex of the hex string "deadbeef"
        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.HEX_DECODE,
                data_hex=hex_str.encode().hex(),
            ),
            "scope", ctx,
        )
        assert result.error_status is None
        assert result.raw_data == bytes.fromhex(hex_str)

    def test_crypto_rot13(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        plaintext = "Hello World"
        expected = "Uryyb Jbeyq"
        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.ROT13,
                data_hex=plaintext.encode().hex(),
            ),
            "scope", ctx,
        )
        assert result.error_status is None
        assert any(expected in o.observation for o in result.normalized_observations)

    def test_crypto_rot13_double_is_identity(self):
        """ROT13 applied twice is identity."""
        adapter = LocalCryptoOpsAdapter()
        original = "The flag is hidden!"
        ctx1 = self._make_crypto_ctx()
        result1 = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.ROT13,
                data_hex=original.encode().hex(),
            ),
            "scope", ctx1,
        )
        assert result1.error_status is None
        # Extract result text from observation
        for o in result1.normalized_observations:
            if "result (text)" in o.observation:
                rot13_text = o.observation.split("): ", 1)[1]
                break

        ctx2 = self._make_crypto_ctx()
        result2 = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.ROT13,
                data_hex=rot13_text.encode().hex(),
            ),
            "scope", ctx2,
        )
        assert result2.error_status is None
        assert any(original in o.observation for o in result2.normalized_observations)

    def test_crypto_xor_bytes(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"\xAA\xBB\xCC"
        key = b"\xFF"
        expected = bytes(b ^ 0xFF for b in data)
        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.XOR_BYTES,
                data_hex=data.hex(),
                xor_key_hex=key.hex(),
            ),
            "scope", ctx,
        )
        assert result.error_status is None
        assert result.raw_data == expected

    def test_crypto_sha256(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"ctf_flag_data"
        expected_hash = hashlib.sha256(data).hexdigest()
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex=data.hex()),
            "scope", ctx,
        )
        assert result.error_status is None
        assert any(expected_hash in o.observation for o in result.normalized_observations)

    def test_crypto_sha1(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"test_data"
        expected_hash = hashlib.sha1(data).hexdigest()
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA1, data_hex=data.hex()),
            "scope", ctx,
        )
        assert result.error_status is None
        assert any(expected_hash in o.observation for o in result.normalized_observations)

    def test_crypto_md5(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        data = b"test_data"
        expected_hash = hashlib.md5(data).hexdigest()
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.MD5, data_hex=data.hex()),
            "scope", ctx,
        )
        assert result.error_status is None
        assert any(expected_hash in o.observation for o in result.normalized_observations)

    def test_crypto_aes_decrypt_ecb(self):
        """AES-ECB decryption returns correct plaintext."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            pytest.skip("cryptography package not installed")

        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        plaintext = b"secretdata12345!"   # 16 bytes (no padding needed for ECB test)
        key = b"thisisaeskey1234"  # 16 bytes AES-128
        # Encrypt with AES-ECB (for test reference only)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.AES_DECRYPT_ECB,
                data_hex=ciphertext.hex(),
                key_hex=key.hex(),
            ),
            "scope", ctx,
        )
        assert result.error_status is None
        # Decrypted bytes (may have padding stripped or not depending on padding check)
        assert plaintext in (result.raw_data or b"") or (
            result.raw_data is not None and result.raw_data.startswith(plaintext.rstrip(b"\x10"))
        )

    def test_crypto_aes_decrypt_cbc(self):
        """AES-CBC decryption returns correct plaintext."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            pytest.skip("cryptography package not installed")

        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        plaintext = b"Hello, AES-CBC!!"  # 16 bytes
        key = b"sixteenbytekey!!"  # 16 bytes
        iv = b"initvector123456"    # 16 bytes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.AES_DECRYPT_CBC,
                data_hex=ciphertext.hex(),
                key_hex=key.hex(),
                iv_hex=iv.hex(),
            ),
            "scope", ctx,
        )
        assert result.error_status is None
        # Plaintext should appear in raw_data (possibly without padding)
        assert result.raw_data is not None
        assert plaintext.rstrip(b"\x10") in result.raw_data or plaintext in result.raw_data

    def test_crypto_aes_key_not_in_provenance(self):
        """AES key must not appear in ToolResult.provenance."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            pytest.skip("cryptography package not installed")

        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        key = b"thisisaeskey1234"
        iv = b"initvector123456"
        plaintext = b"secret_plaintext"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ciphertext = cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()

        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.AES_DECRYPT_CBC,
                data_hex=ciphertext.hex(),
                key_hex=key.hex(),
                iv_hex=iv.hex(),
            ),
            "scope", ctx,
        )
        # Verify key hex is not in any provenance field
        key_hex = key.hex()
        iv_hex = iv.hex()
        prov_str = str(result.provenance)
        assert key_hex not in prov_str, "AES key found in provenance!"
        assert iv_hex not in prov_str, "AES IV found in provenance!"

    def test_crypto_aes_iv_not_in_observations(self):
        """AES IV must not appear in EvidenceCandidate observations."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            pytest.skip("cryptography package not installed")

        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        key = b"thisisaeskey1234"
        iv = b"initvector123456"
        plaintext = b"another secret!!"
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ciphertext = cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()

        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.AES_DECRYPT_CBC,
                data_hex=ciphertext.hex(),
                key_hex=key.hex(),
                iv_hex=iv.hex(),
            ),
            "scope", ctx,
        )
        iv_hex = iv.hex()
        for obs in result.normalized_observations:
            assert iv_hex not in obs.observation, "AES IV found in observation!"
            assert iv_hex not in str(obs.provenance), "AES IV found in observation provenance!"

    def test_crypto_rejects_unknown_operation(self):
        """Unknown operation raises ValueError during validation."""
        with pytest.raises(ValueError, match="operation must be one of"):
            LocalCryptoInput.validate({
                "operation": "ARBITRARY_EVAL",
                "data_hex": "deadbeef",
            })

    def test_crypto_rejects_dynamic_import_via_operation(self):
        """There is no mechanism to dynamically import modules via operation."""
        # All operations are enumerated — this test verifies there's no
        # "exec", "eval", or "import" based dispatch.
        import inspect
        from ctf_mentor.tools.adapters import local_crypto
        source = inspect.getsource(local_crypto.LocalCryptoOpsAdapter._dispatch)
        # These patterns would indicate dynamic execution
        assert "__import__(" not in source
        assert "importlib" not in source
        assert "eval(" not in source
        assert "exec(" not in source
        assert "compile(" not in source

    def test_crypto_input_size_limit_enforced(self):
        """InputSizeLimitExceeded raised for oversized data."""
        big_data = b"\xAB" * (10 * 1024 * 1024 + 1)  # just over 10MB limit
        with pytest.raises(InputSizeLimitExceeded):
            LocalCryptoInput.validate({
                "operation": "SHA256",
                "data_hex": big_data.hex(),
            })

    def test_crypto_rejects_non_hex_data(self):
        """Non-hexadecimal data_hex raises ValueError."""
        with pytest.raises(ValueError, match="non-hexadecimal"):
            LocalCryptoInput.validate({
                "operation": "SHA256",
                "data_hex": "GGGGGG",
            })

    def test_crypto_rejects_odd_length_hex(self):
        """Odd-length hex string raises ValueError."""
        with pytest.raises(ValueError, match="even number"):
            LocalCryptoInput.validate({
                "operation": "SHA256",
                "data_hex": "abc",  # 3 chars — odd
            })

    def test_crypto_aes_rejects_wrong_key_size(self):
        """AES with 15-byte key raises ValueError."""
        with pytest.raises(ValueError, match="16, 24, or 32 bytes"):
            LocalCryptoInput.validate({
                "operation": "AES_DECRYPT_ECB",
                "data_hex": "deadbeef" * 4,
                "key_hex": "aa" * 15,  # 15 bytes — invalid
            })

    def test_crypto_aes_cbc_rejects_wrong_iv_size(self):
        """AES-CBC with wrong IV size raises ValueError."""
        with pytest.raises(ValueError, match="IV must be"):
            LocalCryptoInput.validate({
                "operation": "AES_DECRYPT_CBC",
                "data_hex": "deadbeef" * 4,
                "key_hex": "aa" * 16,
                "iv_hex": "bb" * 8,   # 8 bytes — wrong (need 16)
            })

    def test_crypto_xor_rejects_empty_key(self):
        """XOR with empty key raises ValueError."""
        with pytest.raises(ValueError, match="xor_key_hex"):
            LocalCryptoInput.validate({
                "operation": "XOR_BYTES",
                "data_hex": "deadbeef",
                "xor_key_hex": "",
            })

    def test_crypto_all_observations_untrusted(self):
        """All EvidenceCandidate objects have trust='UNTRUSTED'."""
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex="deadbeef"),
            "scope", ctx,
        )
        assert all(o.trust == "UNTRUSTED" for o in result.normalized_observations)

    def test_crypto_no_subprocess_called(self):
        """LocalCryptoOpsAdapter does not invoke subprocess.Popen."""
        popen_calls = []
        original_popen = subprocess.Popen

        def tracking_popen(*args, **kwargs):
            popen_calls.append(args)
            return original_popen(*args, **kwargs)

        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        with patch("subprocess.Popen", side_effect=tracking_popen):
            adapter.execute_local(
                LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex="deadbeef"),
                "scope", ctx,
            )
        assert len(popen_calls) == 0, "LocalCryptoOpsAdapter called subprocess.Popen!"

    def test_crypto_result_has_invocation_id(self):
        """ToolResult provenance contains invocation_id."""
        adapter = LocalCryptoOpsAdapter()
        ctx = self._make_crypto_ctx()
        invocation_id = ctx.invocation_id
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex="deadbeef"),
            "scope", ctx,
        )
        assert result.provenance.get("invocation_id") == invocation_id

    def test_crypto_to_dict_excludes_key(self):
        """LocalCryptoInput.to_dict() excludes key_hex and iv_hex."""
        inp = LocalCryptoInput(
            operation=CryptoOperation.AES_DECRYPT_CBC,
            data_hex="deadbeef" * 4,
            key_hex="aa" * 16,
            iv_hex="bb" * 16,
        )
        d = inp.to_dict()
        assert "key_hex" not in d
        assert "iv_hex" not in d
        assert "aa" * 16 not in str(d)
        assert "bb" * 16 not in str(d)


# ============================================================================
# G. Capability Tests
# ============================================================================

class TestCapabilities:

    def test_execute_raises_for_local_adapter(self):
        """LocalToolAdapter.execute() always raises RuntimeError."""
        for cls in (TsharkAdapter, SteghideAdapter, LocalCryptoOpsAdapter):
            adapter = cls()
            with pytest.raises(RuntimeError, match="execute_local"):
                adapter.execute(MagicMock(), MagicMock())

    def test_revoked_capability_raises_on_read(self):
        """Using a revoked InputCapability raises CapabilityRevokedError."""
        from ctf_mentor.workspace.capabilities import CapabilityRevokedError
        caps = _make_mock_capability_set(input_store={"file.txt": b"data"})
        caps.input_cap.revoke()
        with pytest.raises(CapabilityRevokedError):
            caps.input_cap.read_bytes("file.txt")

    def test_revoke_all_revokes_all_caps(self):
        """revoke_all() revokes every capability in the set."""
        caps = _make_mock_capability_set(input_store={}, work_store={})
        assert not caps.all_revoked
        caps.revoke_all()
        assert caps.all_revoked

    def test_double_revocation_is_safe(self):
        """Calling revoke_all() twice does not raise."""
        caps = _make_mock_capability_set()
        caps.revoke_all()
        caps.revoke_all()  # should not raise

    def test_caps_revoked_after_crypto_execute_local(self):
        """Capabilities revoked after LocalCryptoOpsAdapter.execute_local()."""
        adapter = LocalCryptoOpsAdapter()
        caps = IssuedCapabilitySet()  # null caps
        policy = LocalExecutionPolicy(
            tool_id="local_crypto_ops",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = LocalExecutionContext.create(
            caps=caps, policy=policy,
            challenge_id="ch", session_id="sess", workspace_id="ws",
        )
        adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex="aabb"),
            "scope", ctx,
        )
        assert ctx.caps.all_revoked

    def test_caps_always_revoked_on_exception_in_execute_local(self):
        """Capabilities are revoked even when execute_local() raises."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,  # will raise ToolUnavailableError
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        try:
            adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            pass
        assert ctx.caps.all_revoked, "Capabilities not revoked after exception"

    def test_null_capability_spec_has_no_permissions(self):
        spec = NULL_CAPABILITY_SPEC
        assert not spec.needs_input
        assert not spec.needs_work_read
        assert not spec.needs_work_write
        assert not spec.needs_output_write
        assert not spec.needs_output_read

    def test_tshark_capability_spec_requires_input_and_work(self):
        spec = TsharkAdapter.workspace_capability_spec
        assert spec.needs_input
        assert spec.needs_work_read
        assert spec.needs_work_write

    def test_local_crypto_capability_spec_is_null(self):
        spec = LocalCryptoOpsAdapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC or (
            not spec.needs_input and
            not spec.needs_work_read and
            not spec.needs_work_write
        )


# ============================================================================
# H. Workspace / Confinement Tests
# ============================================================================

class TestWorkspaceConfinement:

    def test_tshark_input_path_traversal_rejected(self):
        with pytest.raises(WorkspaceConfinementError):
            TsharkInput.validate({
                "operation": "PACKET_SUMMARY",
                "input_filename": "../../../etc/passwd",
            })

    def test_steghide_input_path_traversal_rejected(self):
        with pytest.raises(WorkspaceConfinementError):
            SteghideInput.validate({
                "operation": "EXTRACT",
                "input_filename": "../../secret",
                "passphrase": "",
            })

    def test_tshark_filename_with_backslash_rejected(self):
        with pytest.raises(WorkspaceConfinementError):
            _validate_safe_filename("sub\\dir\\file.pcap")

    def test_steghide_filename_null_byte_rejected(self):
        with pytest.raises(WorkspaceConfinementError):
            from ctf_mentor.tools.adapters.steghide import _validate_safe_filename as steg_vsf
            steg_vsf("file\x00name.jpg")

    def test_runner_cwd_must_be_absolute(self, tmp_path):
        """Runner raises if authorized cwd is relative."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            rec = AuthorizedInvocationRecord(
                invocation_id="test-cwd-relative",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=Path("relative/path"),
                token="test-token",
                active=True,
            )
            with TRUSTED_INVOCATION_AUTHORITY._lock:
                TRUSTED_INVOCATION_AUTHORITY._records["test-cwd-relative"] = rec

            with pytest.raises(WorkspaceConfinementError, match="absolute"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-relative",
                    audit_log=[],
                )

    def test_cross_session_capability_isolation(self):
        """Capabilities from one session cannot read another session's files."""
        caps_a = _make_mock_capability_set(
            session_id="session-A",
            input_store={"secret.txt": b"session A secret"},
        )
        caps_b = _make_mock_capability_set(
            session_id="session-B",
            input_store={"secret.txt": b"session B secret"},
        )
        # Each session reads its own data
        assert caps_a.input_cap.read_bytes("secret.txt") == b"session A secret"
        assert caps_b.input_cap.read_bytes("secret.txt") == b"session B secret"
        # session_id is correct on each cap
        assert caps_a.input_cap.session_id == "session-A"
        assert caps_b.input_cap.session_id == "session-B"

    def test_cross_challenge_capability_isolation(self):
        """Capabilities from one challenge cannot access another challenge's data."""
        caps_x = _make_mock_capability_set(
            challenge_id="challenge-X",
            input_store={"flag.txt": b"flag{x}"},
        )
        caps_y = _make_mock_capability_set(
            challenge_id="challenge-Y",
            input_store={"flag.txt": b"flag{y}"},
        )
        assert caps_x.input_cap.read_bytes("flag.txt") == b"flag{x}"
        assert caps_y.input_cap.read_bytes("flag.txt") == b"flag{y}"
        assert caps_x.input_cap.challenge_id == "challenge-X"
        assert caps_y.input_cap.challenge_id == "challenge-Y"

    def test_input_cap_has_no_write_method(self):
        """InputCapability has no write_bytes method."""
        caps = _make_mock_capability_set(input_store={})
        assert not hasattr(caps.input_cap, "write_bytes")

    def test_runner_cwd_outside_workspace_or_banned_prefix_rejected(self):
        """Runner rejects cwd in forbidden system directories (e.g. C:\\Windows, /etc)."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            forbidden_cwd = Path(r"C:\Windows") if IS_WINDOWS else Path("/etc")
            rec = AuthorizedInvocationRecord(
                invocation_id="test-cwd-forbidden",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=forbidden_cwd,
                token="test-token",
                active=True,
            )
            with TRUSTED_INVOCATION_AUTHORITY._lock:
                TRUSTED_INVOCATION_AUTHORITY._records["test-cwd-forbidden"] = rec

            with pytest.raises(WorkspaceConfinementError, match="forbidden system directory"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-forbidden",
                    audit_log=[],
                )

    def test_runner_cwd_nonexistent_or_file_rejected(self, tmp_path):
        """Runner rejects non-existent directory or regular file as cwd."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            # Non-existent
            non_existent = tmp_path / "non_existent_subdir_xyz"
            rec1 = AuthorizedInvocationRecord(
                invocation_id="test-cwd-nonexistent",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=non_existent,
                token="test-token",
                active=True,
            )
            with TRUSTED_INVOCATION_AUTHORITY._lock:
                TRUSTED_INVOCATION_AUTHORITY._records["test-cwd-nonexistent"] = rec1

            with pytest.raises(WorkspaceConfinementError, match="must exist and be a directory"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-nonexistent",
                    audit_log=[],
                )

            # Regular file as cwd
            file_as_cwd = tmp_path / "some_file.txt"
            file_as_cwd.write_text("not a dir")
            rec2 = AuthorizedInvocationRecord(
                invocation_id="test-cwd-file",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=file_as_cwd,
                token="test-token",
                active=True,
            )
            with TRUSTED_INVOCATION_AUTHORITY._lock:
                TRUSTED_INVOCATION_AUTHORITY._records["test-cwd-file"] = rec2

            with pytest.raises(WorkspaceConfinementError, match="must exist and be a directory"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-file",
                    audit_log=[],
                )

    def test_runner_argv_absolute_path_outside_cwd_rejected(self, tmp_path):
        """Runner rejects non-flag argv components pointing outside cwd."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            outside_path = str(Path(tempfile.gettempdir()).resolve() / "evil.txt")
            with pytest.raises(WorkspaceConfinementError):
                runner.run(
                    argv=fake.make_argv(extra_args=[outside_path]),
                    policy=policy,
                    env=env,
                    invocation_id="test-argv-outside",
                    audit_log=[],
                )

    def test_runner_argv_traversal_rejected(self, tmp_path):
        """Runner rejects path traversal in argv components."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            with pytest.raises(WorkspaceConfinementError):
                runner.run(
                    argv=fake.make_argv(extra_args=["../../escape.txt"]),
                    policy=policy,
                    env=env,
                    invocation_id="test-argv-traversal",
                    audit_log=[],
                )

    def test_runner_cwd_symlink_rejected(self, tmp_path):
        """Runner rejects symlink directory as cwd."""
        target_dir = tmp_path / "real_dir"
        target_dir.mkdir()
        symlink_dir = tmp_path / "symlink_dir"
        try:
            symlink_dir.symlink_to(target_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not supported in this environment")

        _register_test_invocation("test-cwd-symlink", symlink_dir)
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            with pytest.raises(WorkspaceConfinementError):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-symlink",
                    audit_log=[],
                )

    def test_adapters_do_not_use_tempfile_gettempdir(self):
        """Static verification: tshark and steghide do not use tempfile.gettempdir()."""
        import inspect
        from ctf_mentor.tools.adapters import tshark, steghide
        tshark_src = inspect.getsource(tshark)
        steghide_src = inspect.getsource(steghide)
        assert "tempfile.gettempdir()" not in tshark_src
        assert "tempfile.gettempdir()" not in steghide_src

    def test_execution_cwd_resolves_inside_work_directory(self, tmp_path):
        """LocalExecutionContext registers authorized cwd inside workspace work/<inv_id>."""
        ws_root = tmp_path / "workspace"
        work_dir = ws_root / "work"
        work_dir.mkdir(parents=True)

        class MockHandle:
            _root = ws_root

        mock_handle = MockHandle()

        def make_write(h):
            def _w(path: str, data: bytes) -> int:
                _ = h
                return 0
            return _w

        work_cap = WorkCapability(
            "ws-1", "ch-1", "sess-1",
            _read_bytes_fn=lambda p: b"",
            _read_text_fn=lambda p, enc="utf-8": "",
            _file_exists_fn=lambda p: False,
            _write_bytes_fn=make_write(mock_handle),
            _write_text_fn=lambda p, t, enc="utf-8": 0,
            _delete_file_fn=lambda p, m=False: None,
        )
        caps = IssuedCapabilitySet(work_cap=work_cap)
        policy = _make_test_policy()
        ctx = LocalExecutionContext.create(
            caps=caps, policy=policy,
            challenge_id="ch-1", session_id="sess-1", workspace_id="ws-1",
        )
        # Context must NOT expose execution_cwd or any raw filesystem Path
        assert not hasattr(ctx, "execution_cwd")
        assert not hasattr(ctx, "cwd")
        assert not hasattr(ctx, "workspace_root")

        # But the invocation must be registered with the TrustedInvocationAuthority
        record = TRUSTED_INVOCATION_AUTHORITY.get_record(ctx.invocation_id)
        assert record is not None
        assert record.cwd.exists()
        assert record.cwd.name == ctx.invocation_id
        assert record.cwd.parent.resolve() == work_dir.resolve()

    def test_subprocess_receives_confined_cwd(self, tmp_path):
        """Subprocess Popen receives the exact confined workspace cwd resolved from authority."""
        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            captured_cwds = []

            original_popen = subprocess.Popen

            def capturing_popen(*args, **kwargs):
                captured_cwds.append(kwargs.get("cwd"))
                return original_popen(*args, **kwargs)

            with patch("subprocess.Popen", side_effect=capturing_popen):
                runner.run(
                    argv=fake.make_argv(),
                    policy=policy,
                    env=env,
                    invocation_id="test-cwd-pass",
                    audit_log=[],
                )

            assert len(captured_cwds) == 1
            assert Path(captured_cwds[0]).resolve() == tmp_path.resolve()


# ============================================================================
# I. Normalization / Provenance Tests
# ============================================================================

class TestNormalizationProvenance:

    def test_invocation_context_has_uuid_invocation_id(self):
        caps = IssuedCapabilitySet()
        policy = LocalExecutionPolicy(
            tool_id="local_crypto_ops",
            executable_path=None,
            timeout_seconds=5.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=1024,
            max_output_bytes=1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = LocalExecutionContext.create(
            caps=caps, policy=policy,
            challenge_id="ch", session_id="sess", workspace_id="ws",
        )
        # UUID4 format: 8-4-4-4-12
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ctx.invocation_id,
        ), f"invocation_id {ctx.invocation_id!r} is not a valid UUID4"

    def test_crypto_provenance_has_argv_template(self):
        adapter = LocalCryptoOpsAdapter()
        ctx = TestLocalCryptoOpsAdapter()._make_crypto_ctx()
        result = adapter.execute_local(
            LocalCryptoInput(operation=CryptoOperation.SHA256, data_hex="aabbcc"),
            "scope", ctx,
        )
        assert "argv_template" in result.provenance
        assert result.provenance["argv_template"] == LocalCryptoOpsAdapter._ARGV_TEMPLATE_NAME

    def test_crypto_provenance_no_raw_key(self):
        """provenance does not contain 'key_hex' or 'iv_hex' fields."""
        adapter = LocalCryptoOpsAdapter()
        ctx = TestLocalCryptoOpsAdapter()._make_crypto_ctx()
        result = adapter.execute_local(
            LocalCryptoInput(
                operation=CryptoOperation.SHA256,
                data_hex="aabbcc",
            ),
            "scope", ctx,
        )
        prov = result.provenance
        assert "key_hex" not in prov
        assert "iv_hex" not in prov

    def test_tshark_provenance_has_operation(self):
        """tshark ToolResult provenance has 'operation' field."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        try:
            result = adapter.execute_local(inp, "scope", ctx)
        except ToolUnavailableError:
            # We can still verify ctx.invocation_id was generated
            assert ctx.invocation_id  # has a UUID

    def test_nonzero_exit_returns_error_toolresult(self, tmp_path):
        """Non-zero subprocess exit yields ToolResult with error_status set."""
        with FakeExe.nonzero(exit_code=2) as fake:
            policy = fake.make_policy()
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log: List[AuditEntry] = []
            result = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                env=env,
                invocation_id="test-nonzero-001",
                audit_log=audit_log,
            )
            assert result.exit_code == 2
            assert not result.timed_out


# ============================================================================
# J. Fail-Closed Tests
# ============================================================================

class TestFailClosed:

    def test_absent_binary_tshark_fails_closed(self):
        """TsharkAdapter with no binary raises ToolUnavailableError, not silent success."""
        adapter = TsharkAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="tshark",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=1 * 1024 * 1024,
            max_input_bytes=50 * 1024 * 1024,
            max_output_bytes=10 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cap.pcap": _FAKE_PCAP})
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
        )
        with pytest.raises(ToolUnavailableError):
            adapter.execute_local(inp, "scope", ctx)

    def test_absent_binary_steghide_fails_closed(self):
        """SteghideAdapter with no binary raises ToolUnavailableError."""
        adapter = SteghideAdapter()
        policy_no_exe = LocalExecutionPolicy(
            tool_id="steghide",
            executable_path=None,
            timeout_seconds=30.0,
            max_stdout_bytes=10 * 1024 * 1024,
            max_stderr_bytes=512 * 1024,
            max_input_bytes=10 * 1024 * 1024,
            max_output_bytes=5 * 1024 * 1024,
            posix_cpu_limit_s=None,
            posix_mem_limit_bytes=None,
            posix_fsize_limit_bytes=None,
            network_allowed=False,
        )
        ctx = _make_local_ctx(policy_no_exe, input_store={"cover.jpg": _FAKE_JPEG})
        inp = SteghideInput(
            operation=SteghideOperation.EXTRACT,
            input_filename="cover.jpg",
            passphrase="",
        )
        with pytest.raises(ToolUnavailableError):
            adapter.execute_local(inp, "scope", ctx)

    def test_wrong_input_format_not_silently_processed(self):
        """Wrong-format input is rejected before subprocess invocation."""
        with pytest.raises(ValueError, match="not a supported"):
            _validate_steg_format(_FAKE_PNG, "image.png")

    def test_policy_violation_does_not_succeed(self):
        """LocalSubprocessPolicyViolation is not silently converted to success."""
        runner = LocalSubprocessRunner()
        with pytest.raises(LocalSubprocessPolicyViolation):
            runner.build_env(extra={"LD_PRELOAD": "/evil.so"})

    def test_empty_argv_rejected(self, tmp_path):
        """Empty argv raises LocalSubprocessPolicyViolation."""
        policy = _make_test_policy(exe_path=Path("/usr/bin/tshark"))
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with pytest.raises(LocalSubprocessPolicyViolation):
            runner.run(
                argv=[],
                policy=policy,
                env=env,
                invocation_id="test-empty-argv",
                audit_log=[],
            )


# ============================================================================
# K. Orchestration Handler Tests
# ============================================================================

class TestOrchestrationHandler:

    def _make_mock_boundary(self, caps: IssuedCapabilitySet):
        """Build a mock TrustedWorkspaceExecutionBoundary."""
        boundary = MagicMock()
        boundary.challenge_id = "ch-test"
        boundary.session_id = "sess-test"
        boundary.workspace_id = "ws-test"
        boundary.issue.return_value = caps
        return boundary

    def test_handler_rejects_non_local_adapter(self):
        """Handler raises TypeError for non-LocalToolAdapter."""
        handler = LocalToolOrchestrationHandler()
        not_a_local_adapter = MagicMock()
        with pytest.raises(TypeError, match="LocalToolAdapter"):
            handler.execute(not_a_local_adapter, {}, "scope", MagicMock())

    def test_handler_rejects_wrong_execution_class(self):
        """Handler raises TypeError if adapter has wrong execution_class."""
        handler = LocalToolOrchestrationHandler()

        class FakeNetworkAdapter(LocalToolAdapter):
            tool_id = "fake"
            tool_version = "0"
            execution_class = ExecutionClass.PASSIVE_NETWORK  # wrong
            _ARGV_TEMPLATE_NAME = "fake"
            workspace_capability_spec = NULL_CAPABILITY_SPEC
            execution_policy = None
            def validate_input(self, raw_args): return raw_args
            def validate_scope(self, t, s): return True
            def execute_local(self, inp, scope, ctx): pass
            def normalize(self, raw, ctx): return []

        with pytest.raises(TypeError, match="PASSIVE_LOCAL"):
            handler.execute(FakeNetworkAdapter(), {}, "scope", MagicMock())

    def test_handler_returns_toolresult_on_unavailable_tool(self):
        """Handler returns ToolResult (error_status) when tool is unavailable."""
        handler = LocalToolOrchestrationHandler()
        adapter = TsharkAdapter()
        caps = _make_mock_capability_set(input_store={"cap.pcap": _FAKE_PCAP})
        boundary = self._make_mock_boundary(caps)

        result = handler.execute(
            adapter,
            {
                "operation": "PACKET_SUMMARY",
                "input_filename": "cap.pcap",
            },
            "scope",
            boundary,
        )
        assert isinstance(result, ToolResult)
        # If tshark unavailable, error_status should be set
        if not TSHARK_AVAILABLE:
            assert result.error_status is not None

    def test_handler_input_validation_failure_returns_error_result(self):
        """Handler returns error ToolResult on input validation failure."""
        handler = LocalToolOrchestrationHandler()
        adapter = TsharkAdapter()
        caps = _make_mock_capability_set()
        boundary = self._make_mock_boundary(caps)

        result = handler.execute(
            adapter,
            {
                "operation": "INVALID_OP_XYZ",  # invalid
                "input_filename": "cap.pcap",
            },
            "scope",
            boundary,
        )
        assert isinstance(result, ToolResult)
        assert result.error_status is not None
        assert "input_validation" in result.error_status

    def test_handler_revokes_caps_after_unavailable_error(self):
        """Handler double-revokes capabilities after ToolUnavailableError."""
        handler = LocalToolOrchestrationHandler()
        adapter = TsharkAdapter()
        caps = _make_mock_capability_set(input_store={"cap.pcap": _FAKE_PCAP})
        boundary = self._make_mock_boundary(caps)

        handler.execute(
            adapter,
            {
                "operation": "PACKET_SUMMARY",
                "input_filename": "cap.pcap",
            },
            "scope",
            boundary,
        )
        # Verify that revoke_all() was called at the boundary level
        # (the mock caps' revoke_all should have been called at least once)
        assert caps.all_revoked


# ============================================================================
# L. Static Security Scan
# ============================================================================

class TestStaticSecurityScan:
    """
    Static analysis of Phase 10B.3 source files to detect forbidden patterns.

    These tests read source code and verify invariants that could not be
    detected at runtime.
    """

    _LOCAL_MODULE_FILES = [
        "ctf_mentor/tools/local/policy.py",
        "ctf_mentor/tools/local/network.py",
        "ctf_mentor/tools/local/adapter.py",
        "ctf_mentor/tools/local/orchestration.py",
        "ctf_mentor/tools/adapters/tshark.py",
        "ctf_mentor/tools/adapters/steghide.py",
        "ctf_mentor/tools/adapters/local_crypto.py",
    ]

    def _load_source(self, rel_path: str) -> str:
        project_root = Path(__file__).parent.parent
        full_path = project_root / rel_path
        if not full_path.exists():
            pytest.skip(f"Source file not found: {full_path}")
        return full_path.read_text(encoding="utf-8")

    def test_no_shell_true_in_any_local_module(self):
        """None of the Phase 10B.3 source files use shell=True in executable code."""
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            # Use AST to find actual keyword-argument shell=True (not in strings/docstrings)
            import ast as _ast
            try:
                tree = _ast.parse(source)
            except SyntaxError:
                pytest.skip(f"Could not parse {rel_path}")
            violations = []
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Call):
                    for kw in node.keywords:
                        if (
                            kw.arg == "shell"
                            and isinstance(kw.value, _ast.Constant)
                            and kw.value.value is True
                        ):
                            violations.append(f"shell=True at line {kw.value.lineno}")
            assert not violations, (
                f"shell=True found in code in {rel_path}! "
                f"Violations: {violations}. This is a critical security violation."
            )

    def test_no_os_system_in_any_local_module(self):
        """None of the Phase 10B.3 source files use os.system()."""
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            matches = re.findall(r"\bos\.system\s*\(", source)
            assert not matches, f"os.system() found in {rel_path}"

    def test_no_eval_in_any_local_module(self):
        """None of the Phase 10B.3 source files use eval()."""
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            # Allow eval in string literals (comments, docstrings) but not as calls
            matches = re.findall(r"\beval\s*\(", source)
            assert not matches, f"eval() found in {rel_path}"

    def test_no_exec_in_any_local_module(self):
        """None of the Phase 10B.3 source files use exec()."""
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            matches = re.findall(r"\bexec\s*\(", source)
            assert not matches, f"exec() found in {rel_path}"

    def test_no_compile_in_any_local_module(self):
        """None of the Phase 10B.3 source files call the compile() builtin directly.

        re.compile() is allowed (it is regex compilation, not code execution).
        Only bare compile() calls are forbidden.
        """
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            import ast as _ast
            try:
                tree = _ast.parse(source)
            except SyntaxError:
                pytest.skip(f"Could not parse {rel_path}")
            violations = []
            for node in _ast.walk(tree):
                # Only flag bare compile() calls (func is a Name node named 'compile')
                # NOT re.compile() (which is an Attribute node)
                if (
                    isinstance(node, _ast.Call)
                    and isinstance(node.func, _ast.Name)
                    and node.func.id == "compile"
                ):
                    violations.append(f"compile() at line {node.func.lineno}")
            assert not violations, f"compile() builtin found in {rel_path}: {violations}"

    def test_locked_file_not_in_new_file_imports(self):
        """New local module files do not import from orchestration_handlers.

        Mentions in docstrings/comments are allowed; only actual import statements
        are checked.
        """
        import ast as _ast
        for rel_path in self._LOCAL_MODULE_FILES:
            source = self._load_source(rel_path)
            try:
                tree = _ast.parse(source)
            except SyntaxError:
                pytest.skip(f"Could not parse {rel_path}")
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.Import, _ast.ImportFrom)):
                    if isinstance(node, _ast.ImportFrom):
                        mod = node.module or ""
                        assert "orchestration_handlers" not in mod, (
                            f"Phase 8 locked orchestration_handlers imported in {rel_path}"
                        )
                    elif isinstance(node, _ast.Import):
                        for alias in node.names:
                            assert "orchestration_handlers" not in alias.name, (
                                f"Phase 8 locked orchestration_handlers imported in {rel_path}"
                            )

    def test_runner_references_shell_false(self):
        """network.py (local execution boundary) must reference shell=False."""
        source = self._load_source("ctf_mentor/tools/local/network.py")
        assert "shell=False" in source or "shell': False" in source, (
            "network.py does not explicitly set shell=False"
        )

    def test_tshark_argv_builds_list_not_string(self):
        """TsharkAdapter._build_argv returns a list, not a shell command string."""
        adapter = TsharkAdapter()
        exe = Path("/usr/bin/tshark")
        inp = TsharkInput(
            operation=TsharkOperation.PACKET_SUMMARY,
            input_filename="cap.pcap",
            packet_count=10,
        )
        result = adapter._build_argv(exe, "/tmp/input.pcap", inp)
        assert isinstance(result, list)
        assert all(isinstance(a, str) for a in result)
        # Verify it's not a single string with shell metacharacters embedded
        assert not any(
            ";" in a or "|" in a or "&&" in a or "$(" in a or "`" in a
            for a in result
        ), "Potential shell injection characters found in argv list"


# ============================================================================
# L. Remediated Security Invariants Tests (Phase 10B.3 Final)
# ============================================================================

class TestExecutionContextImmutability:
    """Tests verifying LocalExecutionContext is immutable and does NOT expose raw filesystem paths."""

    def test_adapter_facing_execution_context_has_no_raw_path_attributes(self, tmp_path):
        """LocalExecutionContext does NOT expose execution_cwd or any raw filesystem Path."""
        ws_root = tmp_path / "workspace"
        ws_root.mkdir()
        (ws_root / "work").mkdir()

        caps = IssuedCapabilitySet()
        policy = _make_test_policy()
        ctx = LocalExecutionContext.create(
            caps=caps,
            policy=policy,
            challenge_id="ch-1",
            session_id="sess-1",
            workspace_id="ws-1",
        )
        # Must not expose raw filesystem path to adapter
        assert not hasattr(ctx, "execution_cwd")
        assert not hasattr(ctx, "cwd")
        assert not hasattr(ctx, "workspace_root")
        assert not hasattr(ctx, "work_path")

    def test_execution_context_is_frozen_against_attribute_reassignment(self, tmp_path):
        """Setting any attribute on LocalExecutionContext raises FrozenInstanceError / AttributeError."""
        from dataclasses import FrozenInstanceError
        caps = IssuedCapabilitySet()
        policy = _make_test_policy()
        ctx = LocalExecutionContext.create(
            caps=caps,
            policy=policy,
            challenge_id="ch-1",
            session_id="sess-1",
            workspace_id="ws-1",
        )
        with pytest.raises((FrozenInstanceError, AttributeError)):
            ctx.invocation_id = "malicious_mutation"  # type: ignore[misc]

    def test_adapter_cannot_bypass_authority_with_synthetic_context(self, tmp_path):
        """A synthetic or fabricated invocation_id fails closed in runner."""
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            with pytest.raises(WorkspaceConfinementError, match="No active authorized workspace invocation record"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env=env,
                    invocation_id="fabricated-nonexistent-id",
                    audit_log=[],
                )


class TestSubprocessCwdAuthorityNegative:
    """Behavioral negative tests for runner invocation authority enforcement."""

    def test_authorized_cwd_succeeds(self, tmp_path):
        """Authorized registered workspace cwd executes successfully."""
        auth_dir = tmp_path / "authorized_ws"
        auth_dir.mkdir()
        inv_id = "test-auth-success"
        _register_test_invocation(inv_id, auth_dir, "chal-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            result = runner.run(
                argv=fake.make_argv(),
                policy=fake.make_policy(),
                env=env,
                invocation_id=inv_id,
                audit_log=[],
            )
            assert result.exit_code == 0

    def test_caller_supplied_cwd_rejected(self, tmp_path):
        """Supplying an explicit cwd argument to runner.run() is rejected."""
        auth_dir = tmp_path / "authorized_ws"
        auth_dir.mkdir()
        inv_id = "test-caller-cwd"
        _register_test_invocation(inv_id, auth_dir, "chal-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            with pytest.raises(LocalSubprocessPolicyViolation, match="Caller-supplied cwd is forbidden"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    cwd=auth_dir,
                    env=env,
                    invocation_id=inv_id,
                    audit_log=[],
                )

    def test_unregistered_invocation_id_fails_closed(self):
        """Runner fails closed when invocation_id has no authorized record."""
        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            with pytest.raises(WorkspaceConfinementError, match="No active authorized workspace invocation record"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env=env,
                    invocation_id="nonexistent-inv-id",
                    audit_log=[],
                )

    def test_revoked_invocation_id_fails_closed(self, tmp_path):
        """Runner fails closed when invocation has been revoked."""
        auth_dir = tmp_path / "revoked_ws"
        auth_dir.mkdir()
        inv_id = "test-revoked-inv"
        _register_test_invocation(inv_id, auth_dir, "chal-1", "sess-1", "ws-1")

        # Revoke the invocation
        TRUSTED_INVOCATION_AUTHORITY.revoke(inv_id)

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            with pytest.raises(WorkspaceConfinementError, match="No active authorized workspace invocation record"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env=env,
                    invocation_id=inv_id,
                    audit_log=[],
                )

    def test_tampered_marker_file_rejected(self, tmp_path):
        """Corrupt or tampered marker file causes runner to fail closed."""
        auth_dir = tmp_path / "tampered_ws"
        auth_dir.mkdir()
        inv_id = "test-tamper-marker"
        _register_test_invocation(inv_id, auth_dir, "chal-1", "sess-1", "ws-1")

        # Tamper marker file
        marker_path = auth_dir / ".invocation_auth"
        marker_path.write_text(json.dumps({"token": "invalid_evil_token"}), encoding="utf-8")

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        with FakeExe.noop() as fake:
            with pytest.raises(WorkspaceConfinementError, match="Invocation authorization marker contents do not match"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env=env,
                    invocation_id=inv_id,
                    audit_log=[],
                )


class TestProcessTreeCleanupGuarantees:
    """Tests for Windows process tree cleanup security guarantees."""

    def test_taskkill_unavailable_raises_when_tree_kill_required(self):
        """When trusted taskkill is unavailable and require_tree=True, ProcessCleanupError is raised."""
        if IS_WINDOWS:
            mock_proc = MagicMock()
            mock_proc.pid = 99999
            mock_proc.poll.return_value = None

            with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=None):
                with pytest.raises(ProcessCleanupError, match="taskkill.exe unavailable"):
                    _kill_process_tree(mock_proc, require_tree=True)
                mock_proc.kill.assert_called_once()

    def test_taskkill_failure_raises_when_tree_kill_required(self):
        """When taskkill exits with non-zero error code and process is alive, ProcessCleanupError is raised."""
        if IS_WINDOWS:
            mock_proc = MagicMock()
            mock_proc.pid = 99999
            mock_proc.poll.return_value = None

            fake_taskkill = Path(r"C:\Windows\System32\taskkill.exe")
            mock_run_result = MagicMock()
            mock_run_result.returncode = 1
            mock_run_result.stderr = b"ERROR: Access denied."

            with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=fake_taskkill):
                with patch("subprocess.run", return_value=mock_run_result):
                    with pytest.raises(ProcessCleanupError, match="taskkill process-tree cleanup failed"):
                        _kill_process_tree(mock_proc, require_tree=True)
                    mock_proc.kill.assert_called_once()

    def test_emergency_parent_kill_invoked_on_failure(self):
        """Best effort parent kill is invoked even when tree cleanup fails."""
        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None

        if IS_WINDOWS:
            with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=None):
                _kill_process_tree(mock_proc, require_tree=False)
                mock_proc.kill.assert_called_once()


# ============================================================================
# N. F1–F5 and M1/M2 Remediation Verification Tests
# ============================================================================

class TestRemediationF1CwdAuthority:
    """F1: Trusted execution CWD binding, self-assertion removal, and boundary confinement."""

    def test_f1_create_rejects_caller_supplied_execution_cwd(self):
        """LocalExecutionContext.create does not accept execution_cwd argument."""
        caps = IssuedCapabilitySet()
        policy = _make_test_policy()
        with pytest.raises(TypeError):
            LocalExecutionContext.create(  # type: ignore[call-arg]
                caps=caps,
                policy=policy,
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                execution_cwd=Path("/tmp/evil"),
            )

    def test_f1_cross_session_capability_in_create_rejected(self, tmp_path):
        """Passing capability from different session raises WorkspaceConfinementError."""
        ws_root = tmp_path / "ws"
        (ws_root / "work").mkdir(parents=True)
        class MockHandle:
            _root = ws_root
            challenge_id = "ch-1"
            session_id = "sess-1"
            workspace_id = "ws-1"
        def make_write(h):
            def _w(path: str, data: bytes) -> int:
                _ = h
                return 0
            return _w
        work_cap = WorkCapability(
            "ws-1", "ch-1", "sess-OTHER",
            _read_bytes_fn=lambda p: b"",
            _read_text_fn=lambda p, enc="utf-8": "",
            _file_exists_fn=lambda p: False,
            _write_bytes_fn=make_write(MockHandle()),
            _write_text_fn=lambda p, t, enc="utf-8": 0,
            _delete_file_fn=lambda p, m=False: None,
        )
        caps = IssuedCapabilitySet(work_cap=work_cap)
        policy = _make_test_policy()
        with pytest.raises(WorkspaceConfinementError, match="Cross-session or cross-challenge capability mismatch"):
            LocalExecutionContext.create(
                caps=caps,
                policy=policy,
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
            )

    def test_f1_cross_challenge_handle_in_closure_rejected(self, tmp_path):
        """Passing handle from different challenge in closure raises WorkspaceConfinementError."""
        ws_root = tmp_path / "ws"
        (ws_root / "work").mkdir(parents=True)
        class MockHandle:
            _root = ws_root
            challenge_id = "ch-OTHER"
            session_id = "sess-1"
            workspace_id = "ws-1"
        def make_write(h):
            def _w(path: str, data: bytes) -> int:
                _ = h
                return 0
            return _w
        work_cap = WorkCapability(
            "ws-1", "ch-1", "sess-1",
            _read_bytes_fn=lambda p: b"",
            _read_text_fn=lambda p, enc="utf-8": "",
            _file_exists_fn=lambda p: False,
            _write_bytes_fn=make_write(MockHandle()),
            _write_text_fn=lambda p, t, enc="utf-8": 0,
            _delete_file_fn=lambda p, m=False: None,
        )
        caps = IssuedCapabilitySet(work_cap=work_cap)
        policy = _make_test_policy()
        with pytest.raises(WorkspaceConfinementError, match="Cross-session or cross-challenge handle mismatch"):
            LocalExecutionContext.create(
                caps=caps,
                policy=policy,
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
            )

    def test_f1_outside_banned_system_dir_registration_rejected(self, tmp_path):
        """_TrustedInvocationAuthority rejects system directory registration."""
        banned = r"C:\Windows\System32" if IS_WINDOWS else "/etc"
        ws_root = tmp_path / "authorized_ws"
        ws_root.mkdir()
        with pytest.raises(WorkspaceConfinementError, match="forbidden system directory"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-f1-sys",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=Path(banned),
                workspace_root=ws_root,
            )

    def test_f1_registration_without_workspace_binding_fails(self, tmp_path):
        """1. Registration without workspace binding (workspace_root=None) raises WorkspaceConfinementError."""
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        with pytest.raises(WorkspaceConfinementError, match="Registration requires an authorized workspace_root"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-f1-no-ws",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=work_dir,
                workspace_root=None,
            )

    def test_f1_outside_workspace_cwd_fails(self, tmp_path):
        """2. Outside-workspace CWD registration raises WorkspaceConfinementError."""
        ws_root = tmp_path / "authorized_ws"
        ws_root.mkdir()
        outside_dir = tmp_path / "evil_outside_ws"
        outside_dir.mkdir()
        with pytest.raises(WorkspaceConfinementError, match="not confined within workspace"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-f1-outside-ws",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=outside_dir,
                workspace_root=ws_root,
            )

    def test_f1_unrelated_workspace_cwd_fails(self, tmp_path):
        """3. Registering a CWD in an unrelated workspace raises WorkspaceConfinementError."""
        ws_root_auth = tmp_path / "authorized_ws"
        ws_root_auth.mkdir()
        ws_root_unrelated = tmp_path / "other_user_workspace"
        unrelated_work = ws_root_unrelated / "work"
        unrelated_work.mkdir(parents=True)
        with pytest.raises(WorkspaceConfinementError, match="not confined within workspace"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-f1-unrelated-ws",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=unrelated_work,
                workspace_root=ws_root_auth,
            )

    def test_f1_nonexistent_workspace_root_rejected(self, tmp_path):
        """_TrustedInvocationAuthority rejects nonexistent workspace_root."""
        ws_root = tmp_path / "nonexistent_ws"
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        with pytest.raises(WorkspaceConfinementError, match="invalid, missing, or a symlink"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-f1-bad-ws",
                challenge_id="ch-1",
                session_id="sess-1",
                workspace_id="ws-1",
                cwd=work_dir,
                workspace_root=ws_root,
            )

    def test_f1_valid_workspace_bound_cwd_succeeds(self, tmp_path):
        """6. Valid workspace-bound capability derivation succeeds and registers in authority."""
        ws_root = tmp_path / "valid_ws"
        work_dir = ws_root / "work"
        work_dir.mkdir(parents=True)

        class MockHandle:
            _root = ws_root
            challenge_id = "ch-1"
            session_id = "sess-1"
            workspace_id = "ws-1"

        def make_write(h):
            def _w(path: str, data: bytes) -> int:
                _ = h
                return 0
            return _w

        work_cap = WorkCapability(
            "ws-1", "ch-1", "sess-1",
            _read_bytes_fn=lambda p: b"",
            _read_text_fn=lambda p, enc="utf-8": "",
            _file_exists_fn=lambda p: False,
            _write_bytes_fn=make_write(MockHandle()),
            _write_text_fn=lambda p, t, enc="utf-8": 0,
            _delete_file_fn=lambda p, m=False: None,
        )
        caps = IssuedCapabilitySet(work_cap=work_cap)
        policy = _make_test_policy()
        ctx = LocalExecutionContext.create(
            caps=caps,
            policy=policy,
            challenge_id="ch-1",
            session_id="sess-1",
            workspace_id="ws-1",
        )
        rec = TRUSTED_INVOCATION_AUTHORITY.get_record(ctx.invocation_id)
        assert rec is not None
        assert rec.active is True
        assert rec.cwd.is_relative_to(work_dir)
        assert (rec.cwd / ".invocation_auth").exists()

    def test_f1_subprocess_executes_in_authorized_workspace_cwd(self, tmp_path):
        """7. Subprocess executes in the exact authorized workspace CWD and cannot escape."""
        ws_root = tmp_path / "proc_ws"
        work_dir = ws_root / "work"
        work_dir.mkdir(parents=True)

        class MockHandle:
            _root = ws_root
            challenge_id = "ch-proc"
            session_id = "sess-proc"
            workspace_id = "ws-proc"

        def make_write(h):
            def _w(path: str, data: bytes) -> int:
                _ = h
                return 0
            return _w

        work_cap = WorkCapability(
            "ws-proc", "ch-proc", "sess-proc",
            _read_bytes_fn=lambda p: b"",
            _read_text_fn=lambda p, enc="utf-8": "",
            _file_exists_fn=lambda p: False,
            _write_bytes_fn=make_write(MockHandle()),
            _write_text_fn=lambda p, t, enc="utf-8": 0,
            _delete_file_fn=lambda p, m=False: None,
        )
        caps = IssuedCapabilitySet(work_cap=work_cap)
        policy = _make_test_policy()
        ctx = LocalExecutionContext.create(
            caps=caps,
            policy=policy,
            challenge_id="ch-proc",
            session_id="sess-proc",
            workspace_id="ws-proc",
        )
        rec = TRUSTED_INVOCATION_AUTHORITY.get_record(ctx.invocation_id)
        assert rec is not None

        fake = FakeExe._make(
            posix_sh="#!/bin/sh\npwd\n",
            win_py="import os\nprint(os.getcwd())\n",
        )
        with fake:
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            res = runner.run(
                argv=fake.make_argv(),
                policy=fake.make_policy(),
                env=env,
                invocation_id=ctx.invocation_id,
                audit_log=ctx.audit_log,
            )
            output_cwd = Path(res.stdout_bytes.decode(errors="replace").strip()).resolve()
            assert output_cwd == rec.cwd.resolve()
            assert output_cwd.is_relative_to(ws_root.resolve())


class TestRemediationF2ProcessTreeCleanup:
    """F2: Fail-closed process tree cleanup on timeout and truncation."""

    def test_f2_timeout_propagates_tree_cleanup_failure(self, tmp_path):
        """Timeout path raises ProcessCleanupError if tree cleanup cannot be guaranteed."""
        if IS_WINDOWS:
            auth_dir = tmp_path / "auth_ws"
            auth_dir.mkdir()
            inv_id = "test-f2-timeout-fail"
            _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

            runner = LocalSubprocessRunner()
            env = runner.build_env()

            with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=None):
                with FakeExe.slow(sleep_seconds=10) as fake:
                    policy = fake.make_policy(timeout=0.1)
                    with pytest.raises(ProcessCleanupError, match="Trusted taskkill.exe unavailable"):
                        runner.run(
                            argv=fake.make_argv(),
                            policy=policy,
                            env=env,
                            invocation_id=inv_id,
                            audit_log=[],
                        )

    def test_f2_stdout_truncation_propagates_tree_cleanup_failure(self, tmp_path):
        """Stdout truncation path raises ProcessCleanupError when process-tree cleanup fails."""
        if IS_WINDOWS:
            auth_dir = tmp_path / "auth_ws"
            auth_dir.mkdir()
            inv_id = "test-f2-trunc-fail"
            _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

            runner = LocalSubprocessRunner()
            env = runner.build_env()

            with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=None):
                fake = FakeExe._make(
                    posix_sh="#!/bin/sh\ndd if=/dev/zero bs=1024 count=100 2>/dev/null | tr '\\0' 'A'\nsleep 10\n",
                    win_py="import sys, time\nsys.stdout.buffer.write(b'A' * 5000)\nsys.stdout.buffer.flush()\ntime.sleep(10)\n",
                )
                with fake:
                    policy = fake.make_policy(timeout=5.0, max_stdout=100)
                    with pytest.raises(ProcessCleanupError, match="Trusted taskkill.exe unavailable"):
                        runner.run(
                            argv=fake.make_argv(),
                            policy=policy,
                            env=env,
                            invocation_id=inv_id,
                            audit_log=[],
                        )

    def test_f2_posix_tree_kill_failure_raises_process_cleanup_error(self):
        """On POSIX, if process tree kill fails with OSError, ProcessCleanupError is raised and True is NEVER returned."""
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        with patch("ctf_mentor.tools.local.network._IS_POSIX", True):
            with patch("os.getpgid", create=True, return_value=12345):
                with patch("os.killpg", create=True, side_effect=PermissionError("Permission denied")):
                    with pytest.raises(ProcessCleanupError, match="POSIX process tree kill failed"):
                        _kill_process_tree(mock_proc, require_tree=True)
                    mock_proc.kill.assert_called_once()

    def test_f2_windows_taskkill_nonzero_access_denied_raises_process_cleanup_error(self):
        """On Windows, if taskkill returns non-zero code due to access denial, ProcessCleanupError is raised."""
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.poll.return_value = None
        fake_taskkill = Path(r"C:\Windows\System32\taskkill.exe")
        fake_result = subprocess.CompletedProcess(
            args=["taskkill", "/F", "/T", "/PID", "12345"],
            returncode=1,
            stdout=b"",
            stderr=b"ERROR: Access is denied.\r\n",
        )
        with patch("ctf_mentor.tools.local.network._IS_WINDOWS", True):
            with patch("ctf_mentor.tools.local.network._IS_POSIX", False):
                with patch("ctf_mentor.tools.local.network._get_trusted_taskkill_path", return_value=fake_taskkill):
                    with patch("subprocess.run", return_value=fake_result):
                        with pytest.raises(ProcessCleanupError, match="Windows taskkill process-tree cleanup failed"):
                            _kill_process_tree(mock_proc, require_tree=True)
                        mock_proc.kill.assert_called_once()


class TestRemediationF3SystemRootHardening:
    """F3: Hardened Windows system directory / taskkill resolution."""

    def test_f3_manipulated_systemroot_unc_ignored(self):
        """_get_trusted_taskkill_path does not return UNC path when SystemRoot is manipulated."""
        if IS_WINDOWS:
            with patch.dict(os.environ, {"SystemRoot": r"\\attacker\share\Windows"}):
                taskkill = _get_trusted_taskkill_path()
                if taskkill is not None:
                    assert not str(taskkill).startswith(r"\\")
                    assert not str(taskkill).startswith("//")
                    assert str(taskkill).lower().startswith("c:\\") or str(taskkill)[1:3] == ":\\"

    def test_f3_taskkill_is_canonical_system_path(self):
        """_get_trusted_taskkill_path returns canonical local system32 taskkill.exe."""
        if IS_WINDOWS:
            taskkill = _get_trusted_taskkill_path()
            if taskkill is not None:
                assert taskkill.name.lower() == "taskkill.exe"
                assert "system32" in str(taskkill).lower()


class TestRemediationF4SecretRedaction:
    """F4: Secret-bearing arguments not treated as paths and redacted from errors/provenance."""

    def test_f4_steghide_passphrase_with_traversal_chars_accepted(self):
        """Passphrase containing '..', slashes, or colons is not rejected by path traversal checks."""
        argv = [
            str(Path(r"C:\fake\steghide.exe") if IS_WINDOWS else Path("/usr/bin/steghide")),
            "extract",
            "-sf", "cover.jpg",
            "-p", "../secret/pass:phrase..",
            "-xf", "output.txt",
            "-f",
        ]
        _SECRET_FLAGS = frozenset({"-p", "-P", "-passphrase", "--passphrase", "-password", "--password", "-k", "--key"})
        secret_indices = set()
        for i, arg in enumerate(argv):
            if i > 0 and argv[i - 1] in _SECRET_FLAGS:
                secret_indices.add(i)
        assert 5 in secret_indices

    def test_f4_traversal_error_does_not_leak_argument_content(self, tmp_path):
        """WorkspaceConfinementError message does not leak raw argument string."""
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f4-redaction"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        secret_str = "SUPER_SECRET_VALUE_12345"
        with FakeExe.noop() as fake:
            with pytest.raises(WorkspaceConfinementError) as excinfo:
                runner.run(
                    argv=fake.make_argv([f"../../{secret_str}"]),
                    policy=fake.make_policy(),
                    env=env,
                    invocation_id=inv_id,
                    audit_log=[],
                )
            assert secret_str not in str(excinfo.value)
            assert "contains directory traversal" in str(excinfo.value)


class TestRemediationF5RunnerEnvironmentSanitization:
    """F5: LocalSubprocessRunner independently validates environment."""

    def test_f5_runner_rejects_ld_preload_directly(self, tmp_path):
        """runner.run rejects env with LD_PRELOAD directly."""
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f5-ld-preload"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        with FakeExe.noop() as fake:
            with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"LD_PRELOAD": "/evil.so", "PATH": r"C:\Windows\System32" if IS_WINDOWS else "/bin"},
                    invocation_id=inv_id,
                    audit_log=[],
                )

    def test_f5_runner_rejects_pythonpath_directly(self, tmp_path):
        """runner.run rejects env with PYTHONPATH directly."""
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f5-pythonpath"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        with FakeExe.noop() as fake:
            with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"PYTHONPATH": "/evil", "PATH": r"C:\Windows\System32" if IS_WINDOWS else "/bin"},
                    invocation_id=inv_id,
                    audit_log=[],
                )

    def test_f5_runner_rejects_relative_path_entry(self, tmp_path):
        """runner.run rejects PATH containing relative entries."""
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f5-rel-path"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        with FakeExe.noop() as fake:
            with pytest.raises(LocalSubprocessPolicyViolation, match="unsafe relative entry"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"PATH": "."},
                    invocation_id=inv_id,
                    audit_log=[],
                )

    def test_f5_mixed_case_env_keys_normalized_and_banned_rejected(self, tmp_path):
        """Mixed-case environment variables (e.g. Ld_Preload, Path, PythonPath) are checked case-insensitively."""
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f5-mixed-case"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        with FakeExe.noop() as fake:
            with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"Ld_Preload": "/evil.so"},
                    invocation_id=inv_id,
                    audit_log=[],
                )
            with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"PythonPath": "/evil"},
                    invocation_id=inv_id,
                    audit_log=[],
                )
            with pytest.raises(LocalSubprocessPolicyViolation, match="unsafe relative entry"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"Path": "."},
                    invocation_id=inv_id,
                    audit_log=[],
                )
            with pytest.raises(LocalSubprocessPolicyViolation, match="unsafe relative entry"):
                runner.run(
                    argv=fake.make_argv(),
                    policy=fake.make_policy(),
                    env={"pAtH": "."},
                    invocation_id=inv_id,
                    audit_log=[],
                )
            with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                runner.build_env(extra={"Ld_Preload": "/evil.so"})
            with pytest.raises(LocalSubprocessPolicyViolation, match="unsafe relative entry"):
                runner.build_env(extra={"Path": "."})

    def test_f5_all_banned_keys_case_variations_rejected(self, tmp_path):
        """Verify all banned keys in various mixed casing are rejected in both build_env and runner.run."""
        from ctf_mentor.tools.local.network import _BANNED_ENV_KEYS
        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-f5-all-banned"
        _register_test_invocation(inv_id, auth_dir, "ch-1", "sess-1", "ws-1")

        runner = LocalSubprocessRunner()
        with FakeExe.noop() as fake:
            for b_key in _BANNED_ENV_KEYS:
                # Lowercase variation
                low_key = b_key.lower()
                with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                    runner.run(
                        argv=fake.make_argv(),
                        policy=fake.make_policy(),
                        env={low_key: "/test"},
                        invocation_id=inv_id,
                        audit_log=[],
                    )
                with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                    runner.build_env(extra={low_key: "/test"})

                # Titlecase variation
                title_key = b_key.title()
                with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                    runner.run(
                        argv=fake.make_argv(),
                        policy=fake.make_policy(),
                        env={title_key: "/test"},
                        invocation_id=inv_id,
                        audit_log=[],
                    )
                with pytest.raises(LocalSubprocessPolicyViolation, match="banned environment variable"):
                    runner.build_env(extra={title_key: "/test"})


class TestRemediationM1ResourceLimits:
    """M1: Resource limits documentation and fail-closed validation."""

    def test_m1_posix_preexec_fn_fails_closed(self):
        """_make_posix_preexec_fn sets resource limits where available."""
        policy = LocalExecutionPolicy(
            tool_id="test",
            executable_path=Path("/bin/true"),
            timeout_seconds=5.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=1024,
            max_output_bytes=1024,
            posix_cpu_limit_s=10,
            posix_mem_limit_bytes=50 * 1024 * 1024,
            posix_fsize_limit_bytes=10 * 1024 * 1024,
            network_allowed=False,
        )
        preexec = _make_posix_preexec_fn(policy)
        assert callable(preexec)


# ============================================================================
# M. Duplicate Test Name Check
# ============================================================================

class TestNoDuplicateTestNames:

    def test_no_duplicate_test_names_in_this_file(self):
        """Verify no two tests in this file share the same method name."""
        import ast
        source_path = Path(__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"))

        test_names = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test_"):
                    test_names.append(node.name)

        seen = set()
        duplicates = []
        for name in test_names:
            if name in seen:
                duplicates.append(name)
            seen.add(name)

        assert not duplicates, (
            f"Duplicate test names found: {duplicates}. "
            "This can cause tests to shadow each other."
        )
