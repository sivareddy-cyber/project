"""
tests.test_phase10b4_sandbox
============================

Phase 10B.4: Comprehensive test suite for OS-Level Sandboxing & Fail-Closed Isolation Boundary.

Tests:
1. SandboxProfile immutability and parameter validation.
2. Fail-closed semantics when OS sandbox is unavailable (SandboxUnavailableError).
3. Defense-in-depth classification (RLIMITs/process groups != OS isolation).
4. Linux namespace backend (Bubblewrap argv builder, unshare --pid --fork command builder, rlimits).
5. Windows Job Object backend (JobObject limits, UI restrictions, process assignment, fail-closed on UI limits, kill-on-fail).
6. Pure in-memory sandbox backend behavior.
7. Adapter sandbox profile bindings (Tshark, Steghide, LocalCryptoOps).
8. End-to-end LocalSubprocessRunner sandbox integration.
9. Real adversarial / isolation boundary verification (PID isolation, filesystem boundary, network denial, job cleanup).
"""

import ctypes
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from ctf_mentor.tools.contracts import ExecutionClass
from ctf_mentor.tools.local.adapter import (
    AuthorizedInvocationRecord,
    LocalExecutionContext,
    LocalToolAdapter,
    TRUSTED_INVOCATION_AUTHORITY,
)
from ctf_mentor.tools.local.network import AuditEntry, LocalSubprocessRunner, SubprocessResult
from ctf_mentor.tools.local.policy import (
    LocalExecutionPolicy,
    LocalSubprocessPolicyViolation,
    WorkspaceConfinementError,
)
from ctf_mentor.tools.local.sandbox import (
    CRYPTO_SANDBOX_PROFILE,
    STEGHIDE_SANDBOX_PROFILE,
    TSHARK_SANDBOX_PROFILE,
    IsolationLevel,
    LinuxNamespaceSandboxBackend,
    PreparedExecution,
    PureInMemorySandboxBackend,
    SandboxBackend,
    SandboxExecutionBoundary,
    SandboxPolicyViolation,
    SandboxProfile,
    SandboxUnavailableError,
    WindowsJobObjectSandboxBackend,
)
from ctf_mentor.tools.adapters.tshark import TsharkAdapter
from ctf_mentor.tools.adapters.steghide import SteghideAdapter
from ctf_mentor.tools.adapters.local_crypto import LocalCryptoOpsAdapter
from ctf_mentor.workspace.capabilities import IssuedCapabilitySet, WorkspaceCapabilitySpec


IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform == "linux"


# =============================================================================
# 1. SandboxProfile Tests
# =============================================================================

class TestSandboxProfile:
    """Test suite for SandboxProfile configuration and immutability."""

    def test_profile_defaults(self):
        """Default profile enforces OS sandbox and denies network."""
        p = SandboxProfile()
        assert p.require_os_sandbox is True
        assert p.allow_network is False
        assert p.isolate_mounts is True
        assert p.isolate_pids is True
        assert p.isolate_ipc is True
        assert p.max_memory_bytes == 512 * 1024 * 1024
        assert p.max_wall_time_sec == 30.0
        assert p.max_cpu_time_sec == 15.0
        assert p.max_output_bytes == 10 * 1024 * 1024
        assert p.max_processes == 8
        assert p.read_only_binds == ()
        assert p.writable_binds == ()

    def test_profile_immutability(self):
        """SandboxProfile is frozen; attributes cannot be modified."""
        p = SandboxProfile()
        with pytest.raises(FrozenInstanceError):
            p.allow_network = True  # type: ignore

    def test_profile_invalid_memory_rejected(self):
        """Non-positive memory quota raises ValueError."""
        with pytest.raises(ValueError, match="max_memory_bytes must be positive"):
            SandboxProfile(max_memory_bytes=0)
        with pytest.raises(ValueError, match="max_memory_bytes must be positive"):
            SandboxProfile(max_memory_bytes=-1024)

    def test_profile_invalid_wall_time_rejected(self):
        """Non-positive wall-clock time raises ValueError."""
        with pytest.raises(ValueError, match="max_wall_time_sec must be positive"):
            SandboxProfile(max_wall_time_sec=0.0)

    def test_profile_invalid_cpu_time_rejected(self):
        """Non-positive CPU time raises ValueError."""
        with pytest.raises(ValueError, match="max_cpu_time_sec must be positive"):
            SandboxProfile(max_cpu_time_sec=-1.0)

    def test_profile_invalid_output_bytes_rejected(self):
        """Non-positive max_output_bytes raises ValueError."""
        with pytest.raises(ValueError, match="max_output_bytes must be positive"):
            SandboxProfile(max_output_bytes=0)

    def test_profile_invalid_max_processes_rejected(self):
        """Non-positive max_processes raises ValueError."""
        with pytest.raises(ValueError, match="max_processes must be positive"):
            SandboxProfile(max_processes=0)

    def test_profile_binds_converted_to_tuples_of_paths(self):
        """Lists passed to read_only_binds or writable_binds are normalized to tuple[Path]."""
        p = SandboxProfile(
            read_only_binds=[Path("/usr/bin"), "/lib"],  # type: ignore
            writable_binds=[Path("/tmp/work")],  # type: ignore
        )
        assert isinstance(p.read_only_binds, tuple)
        assert all(isinstance(x, Path) for x in p.read_only_binds)
        assert isinstance(p.writable_binds, tuple)
        assert all(isinstance(x, Path) for x in p.writable_binds)

    def test_standard_profiles(self):
        """Pre-defined standard profiles have expected security posture."""
        assert TSHARK_SANDBOX_PROFILE.require_os_sandbox is True
        assert TSHARK_SANDBOX_PROFILE.allow_network is False
        assert TSHARK_SANDBOX_PROFILE.isolate_mounts is True

        assert STEGHIDE_SANDBOX_PROFILE.require_os_sandbox is True
        assert STEGHIDE_SANDBOX_PROFILE.allow_network is False
        assert STEGHIDE_SANDBOX_PROFILE.isolate_mounts is True

        assert CRYPTO_SANDBOX_PROFILE.require_os_sandbox is False
        assert CRYPTO_SANDBOX_PROFILE.allow_network is False


# =============================================================================
# 2. Fail-Closed Sandbox Boundary Tests
# =============================================================================

class MockUnavailableBackend(SandboxBackend):
    @property
    def backend_name(self) -> str:
        return "MockUnavailableBackend"

    @property
    def isolation_level(self) -> IsolationLevel:
        return IsolationLevel.GENUINE_OS_ISOLATION

    def is_available(self) -> bool:
        return False

    def prepare_execution(self, profile, argv, cwd, env):
        raise SandboxUnavailableError("Unavailable")


class MockWeakBackend(SandboxBackend):
    @property
    def backend_name(self) -> str:
        return "MockWeakBackend"

    @property
    def isolation_level(self) -> IsolationLevel:
        return IsolationLevel.DEFENSE_IN_DEPTH_ONLY

    def is_available(self) -> bool:
        return True

    def prepare_execution(self, profile, argv, cwd, env):
        return PreparedExecution(argv=list(argv), cwd=cwd, env=env)


class TestFailClosedSandboxBoundary:
    """Test fail-closed behavior of SandboxExecutionBoundary."""

    def test_unavailable_backend_fails_closed_when_sandbox_required(self, tmp_path):
        """When require_os_sandbox=True and backend is unavailable, SandboxUnavailableError is raised."""
        boundary = SandboxExecutionBoundary(backend=MockUnavailableBackend())
        profile = SandboxProfile(require_os_sandbox=True)
        with pytest.raises(SandboxUnavailableError, match="is unavailable"):
            boundary.prepare_and_verify(
                profile=profile,
                argv=["/bin/echo", "test"],
                cwd=tmp_path,
                env={},
            )

    def test_weak_defense_in_depth_fails_closed_when_os_sandbox_required(self, tmp_path):
        """Weak backend (DEFENSE_IN_DEPTH_ONLY) cannot satisfy require_os_sandbox=True."""
        boundary = SandboxExecutionBoundary(backend=MockWeakBackend())
        profile = SandboxProfile(require_os_sandbox=True)
        with pytest.raises(SandboxUnavailableError, match="NOT OS sandbox isolation"):
            boundary.prepare_and_verify(
                profile=profile,
                argv=["/bin/echo", "test"],
                cwd=tmp_path,
                env={},
            )

    def test_weak_backend_allowed_when_os_sandbox_not_required(self, tmp_path):
        """Weak backend is permitted if require_os_sandbox=False."""
        boundary = SandboxExecutionBoundary(backend=MockWeakBackend())
        profile = SandboxProfile(require_os_sandbox=False)
        prep = boundary.prepare_and_verify(
            profile=profile,
            argv=["/bin/echo", "test"],
            cwd=tmp_path,
            env={"A": "1"},
        )
        assert prep.argv == ["/bin/echo", "test"]


# =============================================================================
# 3. Linux Namespace Backend Tests
# =============================================================================

class TestLinuxNamespaceSandboxBackend:
    """Test suite for LinuxNamespaceSandboxBackend."""

    def test_linux_backend_properties(self):
        """Backend classification is GENUINE_OS_ISOLATION."""
        backend = LinuxNamespaceSandboxBackend()
        assert backend.backend_name == "LinuxNamespaceSandbox"
        assert backend.isolation_level == IsolationLevel.GENUINE_OS_ISOLATION

    def test_bubblewrap_command_construction(self, tmp_path):
        """When bubblewrap is available, correct sandbox isolation flags, PID isolation, executable ro-bind, and prlimit wrapper are built."""
        backend = LinuxNamespaceSandboxBackend()
        backend._bwrap_path = "/usr/bin/bwrap"

        dummy_exe = tmp_path / "tshark"
        dummy_exe.write_text("#!/bin/sh\necho ok\n")

        with patch.object(backend, "is_available", return_value=True):
            with patch("os.path.isfile", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("shutil.which", side_effect=lambda name: "/usr/bin/prlimit" if name == "prlimit" else "/usr/bin/bwrap"):
                        profile = SandboxProfile(
                            require_os_sandbox=True,
                            allow_network=False,
                            isolate_mounts=True,
                            isolate_pids=True,
                            max_processes=4,
                            read_only_binds=(tmp_path / "ro",),
                            writable_binds=(tmp_path / "rw",),
                        )
                        (tmp_path / "ro").mkdir(exist_ok=True)
                        (tmp_path / "rw").mkdir(exist_ok=True)

                        prep = backend.prepare_execution(
                            profile=profile,
                            argv=[str(dummy_exe), "-r", "test.pcap"],
                            cwd=tmp_path,
                            env={"LANG": "C"},
                        )

                        assert prep.argv[0] == "/usr/bin/bwrap"
                        assert "--unshare-net" in prep.argv
                        assert "--unshare-pid" in prep.argv
                        assert "--unshare-user" in prep.argv
                        assert "--tmpfs" in prep.argv
                        assert "--proc" in prep.argv
                        assert "--die-with-parent" in prep.argv
                        assert str(tmp_path.resolve()) in prep.argv

                        # FIX 6: Executable is ro-bound after /tmp tmpfs
                        tmpfs_idx = prep.argv.index("/tmp")
                        exe_str = str(dummy_exe)
                        assert exe_str in prep.argv
                        exe_idx = prep.argv.index(exe_str)
                        assert exe_idx > tmpfs_idx

                        # FIX 3: Inner command is wrapped with prlimit --nproc=4
                        dash_idx = prep.argv.index("--")
                        assert prep.argv[dash_idx + 1] == "/usr/bin/prlimit"
                        assert prep.argv[dash_idx + 2] == "--nproc=4"
                        assert prep.metadata["mode"] == "bwrap"

    def test_unshare_cannot_satisfy_required_os_sandbox_fails_closed(self, tmp_path):
        """When bubblewrap is unavailable, require_os_sandbox=True fails closed with SandboxUnavailableError."""
        backend = LinuxNamespaceSandboxBackend()
        backend._bwrap_path = None
        backend._unshare_path = "/usr/bin/unshare"

        profile = SandboxProfile(
            require_os_sandbox=True,
            allow_network=False,
            isolate_mounts=True,
            isolate_pids=True,
        )
        with pytest.raises(SandboxUnavailableError, match="Bubblewrap \\(bwrap\\) is not available"):
            backend.prepare_execution(
                profile=profile,
                argv=["/usr/bin/tshark", "-r", "test.pcap"],
                cwd=tmp_path,
                env={"LANG": "C"},
            )

    def test_unshare_rejected_when_isolate_mounts_true_even_if_require_os_sandbox_false(self, tmp_path):
        """FIX 4: When isolate_mounts=True, unshare must raise SandboxUnavailableError regardless of require_os_sandbox."""
        backend = LinuxNamespaceSandboxBackend()
        backend._bwrap_path = None
        backend._unshare_path = "/usr/bin/unshare"

        profile = SandboxProfile(
            require_os_sandbox=False,
            allow_network=False,
            isolate_mounts=True,
            isolate_pids=True,
        )
        with pytest.raises(SandboxUnavailableError, match="Linux mount/filesystem isolation requested"):
            backend.prepare_execution(
                profile=profile,
                argv=["/usr/bin/tshark", "-r", "test.pcap"],
                cwd=tmp_path,
                env={"LANG": "C"},
            )

    def test_unshare_command_construction_for_defense_in_depth(self, tmp_path):
        """When require_os_sandbox=False and isolate_mounts=False, unshare is permitted for DID PID/network isolation."""
        backend = LinuxNamespaceSandboxBackend()
        backend._bwrap_path = None
        backend._unshare_path = "/usr/bin/unshare"

        with patch("os.path.isfile", return_value=True):
            with patch("os.access", return_value=True):
                profile = SandboxProfile(
                    require_os_sandbox=False,
                    allow_network=False,
                    isolate_mounts=False,
                    isolate_pids=True,
                )
                prep = backend.prepare_execution(
                    profile=profile,
                    argv=["/usr/bin/tshark", "-r", "test.pcap"],
                    cwd=tmp_path,
                    env={"LANG": "C"},
                )

                assert prep.argv[0] == "/usr/bin/unshare"
                assert "--user" in prep.argv
                assert "--map-root-user" in prep.argv
                assert "--net" in prep.argv
                assert "--pid" in prep.argv
                assert "--fork" in prep.argv  # Guarantees child becomes PID 1 in new namespace
                assert "--mount-proc" in prep.argv
                assert prep.metadata["mode"] == "unshare_fork"

    def test_unavailable_namespaces_fails_closed(self, tmp_path):
        """If Linux namespaces and bwrap are unavailable, raises SandboxUnavailableError."""
        backend = LinuxNamespaceSandboxBackend()
        backend._bwrap_path = None
        backend._unshare_path = None

        # Case 1: default isolate_mounts=True
        profile_mount = SandboxProfile(require_os_sandbox=True, isolate_mounts=True)
        with pytest.raises(SandboxUnavailableError, match="Linux mount/filesystem isolation requested"):
            backend.prepare_execution(
                profile=profile_mount,
                argv=["/usr/bin/tshark"],
                cwd=tmp_path,
                env={},
            )

        # Case 2: isolate_mounts=False but require_os_sandbox=True
        profile_os = SandboxProfile(require_os_sandbox=True, isolate_mounts=False)
        with pytest.raises(SandboxUnavailableError, match="Linux OS sandbox isolation requested"):
            backend.prepare_execution(
                profile=profile_os,
                argv=["/usr/bin/tshark"],
                cwd=tmp_path,
                env={},
            )


# =============================================================================
# 4. Windows Job Object Backend Tests
# =============================================================================

class TestWindowsJobObjectSandboxBackend:
    """Test suite for WindowsJobObjectSandboxBackend."""

    def test_windows_backend_properties(self):
        """Backend classification is GENUINE_OS_ISOLATION."""
        backend = WindowsJobObjectSandboxBackend()
        assert backend.backend_name == "WindowsJobObjectSandbox"
        assert backend.isolation_level == IsolationLevel.GENUINE_OS_ISOLATION

    def test_job_object_creation_failure_fails_closed(self, tmp_path):
        """If CreateJobObjectW returns NULL, execution fails closed."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.CreateJobObjectW.return_value = 0
        backend._kernel32 = fake_kernel32

        with patch("sys.platform", "win32"):
            with patch.object(backend, "is_available", return_value=True):
                profile = SandboxProfile(require_os_sandbox=True)
                with patch("ctf_mentor.tools.local.sandbox._get_win32_last_error", return_value=5):
                    with pytest.raises(SandboxUnavailableError, match="CreateJobObjectW failed"):
                        backend.prepare_execution(
                            profile=profile,
                            argv=["C:\\tool.exe"],
                            cwd=tmp_path,
                            env={},
                        )

    def test_job_object_extended_limits_configuration_failure_fails_closed(self, tmp_path):
        """If SetInformationJobObject(ExtendedLimits) fails, job handle is closed and execution fails closed."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.CreateJobObjectW.return_value = 1001
        fake_kernel32.SetInformationJobObject.return_value = 0  # Fail
        backend._kernel32 = fake_kernel32

        with patch("sys.platform", "win32"):
            with patch.object(backend, "is_available", return_value=True):
                profile = SandboxProfile(require_os_sandbox=True)
                with patch("ctf_mentor.tools.local.sandbox._get_win32_last_error", return_value=87):
                    with pytest.raises(SandboxUnavailableError, match="SetInformationJobObject\\(ExtendedLimits\\)"):
                        backend.prepare_execution(
                            profile=profile,
                            argv=["C:\\tool.exe"],
                            cwd=tmp_path,
                            env={},
                        )
                    fake_kernel32.CloseHandle.assert_called_once_with(1001)

    def test_job_object_ui_restrictions_configuration_failure_fails_closed(self, tmp_path):
        """If SetInformationJobObject(BasicUIRestrictions) fails, job handle is closed and execution fails closed."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.CreateJobObjectW.return_value = 1001
        # Succeed on extended limits (call 1), fail on UI limits (call 2)
        fake_kernel32.SetInformationJobObject.side_effect = [1, 0]
        backend._kernel32 = fake_kernel32

        with patch("sys.platform", "win32"):
            with patch.object(backend, "is_available", return_value=True):
                profile = SandboxProfile(require_os_sandbox=True)
                with patch("ctf_mentor.tools.local.sandbox._get_win32_last_error", return_value=5):
                    with pytest.raises(SandboxUnavailableError, match="SetInformationJobObject\\(BasicUIRestrictions\\)"):
                        backend.prepare_execution(
                            profile=profile,
                            argv=["C:\\tool.exe"],
                            cwd=tmp_path,
                            env={},
                        )
                    fake_kernel32.CloseHandle.assert_called_once_with(1001)

    def test_job_object_limits_failure_when_not_required_clears_handle(self, tmp_path):
        """If SetInformationJobObject fails when require_os_sandbox=False, job_handle is None (not closed handle)."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.CreateJobObjectW.return_value = 1001
        fake_kernel32.SetInformationJobObject.return_value = 0  # Fail
        backend._kernel32 = fake_kernel32

        with patch("sys.platform", "win32"):
            with patch.object(backend, "is_available", return_value=True):
                profile = SandboxProfile(require_os_sandbox=False)
                with patch("ctf_mentor.tools.local.sandbox._get_win32_last_error", return_value=87):
                    prep = backend.prepare_execution(
                        profile=profile,
                        argv=["C:\\tool.exe"],
                        cwd=tmp_path,
                        env={},
                    )
                    assert prep.metadata.get("job_handle") is None
                    fake_kernel32.CloseHandle.assert_called_once_with(1001)

    def test_post_spawn_assigns_process_to_job_object(self):
        """post_spawn assigns child process handle to Job Object."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.AssignProcessToJobObject.return_value = 1
        backend._kernel32 = fake_kernel32

        mock_proc = MagicMock()
        mock_proc._handle = 2002
        mock_proc.pid = 4321

        prepared = PreparedExecution(
            argv=["tool.exe"],
            cwd=Path("."),
            env={},
            metadata={"job_handle": 1001},
        )

        backend.post_spawn(mock_proc, prepared)
        fake_kernel32.AssignProcessToJobObject.assert_called_once_with(1001, 2002)

    def test_post_spawn_assignment_failure_kills_process_and_raises(self):
        """If AssignProcessToJobObject fails, child process is killed and SandboxUnavailableError is raised."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.AssignProcessToJobObject.return_value = 0  # Fail
        backend._kernel32 = fake_kernel32

        mock_proc = MagicMock()
        mock_proc._handle = 2002
        mock_proc.pid = 4321

        prepared = PreparedExecution(
            argv=["tool.exe"],
            cwd=Path("."),
            env={},
            metadata={"job_handle": 1001},
        )

        with patch("ctf_mentor.tools.local.sandbox._get_win32_last_error", return_value=5):
            with pytest.raises(SandboxUnavailableError, match="AssignProcessToJobObject failed"):
                backend.post_spawn(mock_proc, prepared)
            mock_proc.kill.assert_called_once()

    def test_job_object_cleanup_idempotency_prevents_double_close(self, tmp_path):
        """Sandbox cleanup is strictly idempotent; second cleanup does not call CloseHandle again."""
        backend = WindowsJobObjectSandboxBackend()
        fake_kernel32 = MagicMock()
        fake_kernel32.CreateJobObjectW.return_value = 1001
        fake_kernel32.SetInformationJobObject.return_value = 1
        backend._kernel32 = fake_kernel32

        with patch("sys.platform", "win32"):
            with patch.object(backend, "is_available", return_value=True):
                profile = SandboxProfile(require_os_sandbox=True)
                prep = backend.prepare_execution(
                    profile=profile,
                    argv=["C:\\tool.exe"],
                    cwd=tmp_path,
                    env={},
                )
                assert len(prep.cleanup_callbacks) == 1
                assert prep.metadata.get("job_handle") == 1001

                # First cleanup invocation
                backend.cleanup(None, prep)
                fake_kernel32.CloseHandle.assert_called_once_with(1001)
                assert len(prep.cleanup_callbacks) == 0

                # Second cleanup invocation (e.g. from outer finally block)
                backend.cleanup(None, prep)
                # Must still be called exactly once
                assert fake_kernel32.CloseHandle.call_count == 1

    @pytest.mark.skipif(not IS_WINDOWS, reason="Live Windows Job Object tests require Windows host")
    def test_live_windows_job_object_lifecycle(self, tmp_path):
        """Real Windows execution tests Job Object creation, process assignment, and cleanup."""
        backend = WindowsJobObjectSandboxBackend()
        assert backend.is_available() is True

        profile = SandboxProfile(
            require_os_sandbox=True,
            max_memory_bytes=256 * 1024 * 1024,
            max_processes=4,
        )

        prep = backend.prepare_execution(
            profile=profile,
            argv=[sys.executable, "-c", "import sys; sys.exit(0)"],
            cwd=tmp_path,
            env=dict(os.environ),
        )
        assert prep.metadata.get("job_handle") is not None

        proc = subprocess.Popen(
            prep.argv,
            cwd=str(prep.cwd),
            env=prep.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            backend.post_spawn(proc, prep)
            proc.wait(timeout=5)
            assert proc.returncode == 0
        finally:
            backend.cleanup(proc, prep)


# =============================================================================
# 5. Pure In-Memory Backend Tests
# =============================================================================

class TestPureInMemorySandboxBackend:
    """Test suite for PureInMemorySandboxBackend."""

    def test_in_memory_backend_properties(self):
        """Backend classification is IN_MEMORY_RUNTIME."""
        backend = PureInMemorySandboxBackend()
        assert backend.backend_name == "PureInMemorySandbox"
        assert backend.isolation_level == IsolationLevel.IN_MEMORY_RUNTIME
        assert backend.is_available() is True

    def test_in_memory_fails_closed_if_os_sandbox_demanded(self, tmp_path):
        """PureInMemorySandboxBackend cannot satisfy require_os_sandbox=True."""
        backend = PureInMemorySandboxBackend()
        profile = SandboxProfile(require_os_sandbox=True)
        with pytest.raises(SandboxUnavailableError, match="cannot be satisfied by the PureInMemorySandboxBackend"):
            backend.prepare_execution(profile, ["test"], tmp_path, {})

    def test_in_memory_succeeds_when_os_sandbox_not_demanded(self, tmp_path):
        """PureInMemorySandboxBackend prepares execution successfully when require_os_sandbox=False."""
        backend = PureInMemorySandboxBackend()
        profile = SandboxProfile(require_os_sandbox=False)
        prep = backend.prepare_execution(profile, ["test"], tmp_path, {"K": "V"})
        assert prep.argv == ["test"]
        assert prep.env == {"K": "V"}


# =============================================================================
# 6. Adapter Sandbox Profile Binding Tests
# =============================================================================

class TestAdapterSandboxBindings:
    """Verify that all Phase 10B.4 local tool adapters declare appropriate sandbox profiles."""

    def test_tshark_adapter_profile_binding(self):
        """TsharkAdapter declares TSHARK_SANDBOX_PROFILE."""
        assert hasattr(TsharkAdapter, "sandbox_profile")
        assert TsharkAdapter.sandbox_profile == TSHARK_SANDBOX_PROFILE
        assert TsharkAdapter.sandbox_profile.require_os_sandbox is True
        assert TsharkAdapter.sandbox_profile.allow_network is False

    def test_steghide_adapter_profile_binding(self):
        """SteghideAdapter declares STEGHIDE_SANDBOX_PROFILE."""
        assert hasattr(SteghideAdapter, "sandbox_profile")
        assert SteghideAdapter.sandbox_profile == STEGHIDE_SANDBOX_PROFILE
        assert SteghideAdapter.sandbox_profile.require_os_sandbox is True
        assert SteghideAdapter.sandbox_profile.allow_network is False

    def test_local_crypto_adapter_profile_binding(self):
        """LocalCryptoOpsAdapter declares CRYPTO_SANDBOX_PROFILE."""
        assert hasattr(LocalCryptoOpsAdapter, "sandbox_profile")
        assert LocalCryptoOpsAdapter.sandbox_profile == CRYPTO_SANDBOX_PROFILE
        assert LocalCryptoOpsAdapter.sandbox_profile.require_os_sandbox is False

    def test_local_tool_adapter_base_profile(self):
        """LocalToolAdapter base class declares sandbox_profile attribute."""
        assert hasattr(LocalToolAdapter, "sandbox_profile")


# =============================================================================
# 7. Runner Sandbox Integration Tests
# =============================================================================

class TestRunnerSandboxIntegration:
    """Verify LocalSubprocessRunner integration with SandboxExecutionBoundary."""

    def test_runner_audit_log_records_sandbox_backend(self, tmp_path):
        """Runner records sandbox backend name in SUBPROCESS_START audit log."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-sandbox-audit-1"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()
        audit_log: List[AuditEntry] = []

        with FakeExe.noop() as fake:
            policy = fake.make_policy()
            profile = SandboxProfile(require_os_sandbox=True)
            res = runner.run(
                argv=fake.make_argv(),
                policy=policy,
                invocation_id=inv_id,
                env=env,
                audit_log=audit_log,
                sandbox_profile=profile,
            )

            start_events = [e for e in audit_log if e.event == "SUBPROCESS_START"]
            assert len(start_events) == 1
            assert "sandbox_backend" in start_events[0].details

    def test_runner_fails_closed_when_sandbox_boundary_raises(self, tmp_path):
        """Runner aborts before launch if sandbox boundary raises SandboxUnavailableError."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-sandbox-failclosed-1"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            policy = fake.make_policy()

            with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.prepare_and_verify", side_effect=SandboxUnavailableError("Sandbox failed")):
                with pytest.raises(SandboxUnavailableError, match="Sandbox failed"):
                    runner.run(
                        argv=fake.make_argv(),
                        policy=policy,
                        invocation_id=inv_id,
                        env=env,
                        audit_log=[],
                        sandbox_profile=SandboxProfile(require_os_sandbox=True),
                    )

    def test_runner_failure_path_cleans_up_without_double_close(self, tmp_path):
        """Runner failure path (e.g. post_spawn failure) invokes cleanup idempotently without double-cleanup."""
        from tests.test_phase10b3_local_execution import FakeExe
        from ctf_mentor.tools.local.network import LocalSubprocessPolicyViolation

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-sandbox-cleanup-idempotency"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            policy = fake.make_policy()

            mock_cleanup_cb = MagicMock()
            prepared = PreparedExecution(
                argv=fake.make_argv(),
                cwd=auth_dir,
                env=env,
                cleanup_callbacks=[mock_cleanup_cb],
                metadata={"backend": "MockBackend"},
            )

            with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.prepare_and_verify", return_value=prepared):
                with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.post_spawn", side_effect=RuntimeError("Spawn attachment failed")):
                    with pytest.raises(LocalSubprocessPolicyViolation, match="Spawn attachment failed"):
                        runner.run(
                            argv=fake.make_argv(),
                            policy=policy,
                            invocation_id=inv_id,
                            env=env,
                            audit_log=[],
                            sandbox_profile=SandboxProfile(require_os_sandbox=True),
                        )

            # Cleanup callback must have been executed exactly once across inner and outer cleanup
            mock_cleanup_cb.assert_called_once()

    def test_runner_combines_10b3_posix_rlimits_with_sandbox(self, tmp_path):
        """Runner popen preexec combines both 10B.3 policy POSIX rlimits and sandbox preexec."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-sandbox-rlimit-combo"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            policy = LocalExecutionPolicy(
                tool_id="test_tool",
                executable_path=fake.exe_path,
                timeout_seconds=5.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=5,
                posix_mem_limit_bytes=64 * 1024 * 1024,
                posix_fsize_limit_bytes=10 * 1024 * 1024,
            )

            with patch("ctf_mentor.tools.local.network._IS_POSIX", True):
                with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.post_spawn"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_proc = MagicMock()
                        mock_proc.poll.return_value = 0
                        mock_proc.returncode = 0
                        mock_proc.stdout.read.return_value = b""
                        mock_proc.stderr.read.return_value = b""
                        mock_popen.return_value = mock_proc

                        runner.run(
                            argv=fake.make_argv(),
                            policy=policy,
                            invocation_id=inv_id,
                            env=env,
                            audit_log=[],
                            sandbox_profile=SandboxProfile(require_os_sandbox=True),
                        )

                        call_kwargs = mock_popen.call_args.kwargs
                        assert "preexec_fn" in call_kwargs
                        combined_preexec = call_kwargs["preexec_fn"]
                        assert callable(combined_preexec)

    def test_preexec_rlimit_failure_fails_closed(self):
        """If resource.setrlimit fails during preexec, exception is raised fail-closed rather than swallowed."""
        profile = SandboxProfile(require_os_sandbox=True, max_memory_bytes=1024)
        backend = LinuxNamespaceSandboxBackend()
        preexec = backend._make_did_preexec(profile)

        fake_resource = MagicMock()
        fake_resource.RLIMIT_AS = 9
        fake_resource.getrlimit.return_value = (1024 * 1024, 1024 * 1024)
        fake_resource.setrlimit.side_effect = OSError("Permission denied setting resource limit")

        with patch.dict("sys.modules", {"resource": fake_resource}):
            with pytest.raises(OSError, match="Permission denied"):
                preexec()


class TestApplyPosixLimit:
    """Unit test suite for monotonic POSIX limit helper."""

    def test_apply_posix_limit_monotonic_never_raises_hard(self):
        """_apply_posix_limit never attempts to raise cur_hard."""
        fake_resource = MagicMock()
        fake_resource.RLIM_INFINITY = 999999999
        fake_resource.getrlimit.return_value = (256, 256)

        from ctf_mentor.tools.local.network import _apply_posix_limit

        with patch.dict("sys.modules", {"resource": fake_resource}):
            _apply_posix_limit(1, 512)
            # Desired 512 is higher than cur_hard 256; monotonic clamping sets min(256, 512) = 256
            fake_resource.setrlimit.assert_called_once_with(1, (256, 256))

    def test_apply_posix_limit_lowers_hard_when_smaller(self):
        """_apply_posix_limit lowers cur_hard when desired is smaller."""
        fake_resource = MagicMock()
        fake_resource.RLIM_INFINITY = 999999999
        fake_resource.getrlimit.return_value = (512, 512)

        from ctf_mentor.tools.local.network import _apply_posix_limit

        with patch.dict("sys.modules", {"resource": fake_resource}):
            _apply_posix_limit(1, 256)
            fake_resource.setrlimit.assert_called_once_with(1, (256, 256))


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX resource limits and fork testing only supported on POSIX")
class TestPosixMonotonicLimitsFork:
    """Real fork-and-inspect tests for POSIX resource limit composition (FIX 2)."""

    def _fork_and_get_limits(self, preexec_fn):
        """Fork child, run preexec_fn, serialize resource limits to pipe, return dict."""
        import json
        import resource
        r_fd, w_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r_fd)
            try:
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    import pwd
                    try:
                        nobody = pwd.getpwnam("nobody")
                        os.setgid(nobody.pw_gid)
                        os.setuid(nobody.pw_uid)
                    except Exception:
                        pass
                if preexec_fn:
                    preexec_fn()
                as_lim = resource.getrlimit(resource.RLIMIT_AS)
                fsize_lim = resource.getrlimit(resource.RLIMIT_FSIZE)
                cpu_lim = resource.getrlimit(resource.RLIMIT_CPU)
                data = json.dumps({
                    "as": as_lim,
                    "fsize": fsize_lim,
                    "cpu": cpu_lim,
                    "success": True,
                }).encode("utf-8")
                os.write(w_fd, data)
            except Exception as e:
                err_data = json.dumps({"success": False, "error": str(type(e).__name__), "msg": str(e)}).encode("utf-8")
                os.write(w_fd, err_data)
            finally:
                os.close(w_fd)
                os._exit(0)
        else:
            os.close(w_fd)
            r_file = os.fdopen(r_fd, "rb")
            data = r_file.read()
            r_file.close()
            _, status = os.waitpid(pid, 0)
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            return json.loads(data.decode("utf-8"))

    def test_fork_policy_looser_than_profile(self):
        """a) policy looser than profile -> child gets the profile (stricter) values."""
        from ctf_mentor.tools.local.network import _make_posix_preexec_fn
        from ctf_mentor.tools.local.sandbox import LinuxNamespaceSandboxBackend, SandboxProfile
        from ctf_mentor.tools.local.policy import LocalExecutionPolicy

        policy = LocalExecutionPolicy(
            tool_id="test",
            executable_path=Path("/bin/true"),
            timeout_seconds=5.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=1024,
            max_output_bytes=1024,
            posix_cpu_limit_s=20,
            posix_mem_limit_bytes=512 * 1024 * 1024,
            posix_fsize_limit_bytes=20 * 1024 * 1024,
        )
        profile = SandboxProfile(
            require_os_sandbox=False,
            max_memory_bytes=256 * 1024 * 1024,
            max_cpu_time_sec=10.0,
            max_output_bytes=5 * 1024 * 1024,
        )
        policy_preexec = _make_posix_preexec_fn(policy)
        backend = LinuxNamespaceSandboxBackend()
        sandbox_preexec = backend._make_did_preexec(profile)

        def combined():
            policy_preexec()
            sandbox_preexec()

        res = self._fork_and_get_limits(combined)
        assert res["success"] is True
        assert res["as"][0] == 256 * 1024 * 1024
        assert res["as"][1] == 256 * 1024 * 1024
        assert res["fsize"][0] == 5 * 1024 * 1024
        assert res["fsize"][1] == 5 * 1024 * 1024

    def test_fork_policy_tighter_than_profile_steghide(self):
        """b) policy tighter than profile (real STEGHIDE values) -> child gets policy values and does NOT fail."""
        from ctf_mentor.tools.local.network import _make_posix_preexec_fn
        from ctf_mentor.tools.local.sandbox import LinuxNamespaceSandboxBackend, STEGHIDE_SANDBOX_PROFILE
        from ctf_mentor.tools.local.policy import LocalExecutionPolicy

        policy = LocalExecutionPolicy(
            tool_id="steghide",
            executable_path=Path("/bin/true"),
            timeout_seconds=5.0,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_input_bytes=1024,
            max_output_bytes=1024,
            posix_cpu_limit_s=5,
            posix_mem_limit_bytes=256 * 1024 * 1024,
            posix_fsize_limit_bytes=5 * 1024 * 1024,
        )
        profile = STEGHIDE_SANDBOX_PROFILE
        policy_preexec = _make_posix_preexec_fn(policy)
        backend = LinuxNamespaceSandboxBackend()
        sandbox_preexec = backend._make_did_preexec(profile)

        def combined():
            policy_preexec()
            sandbox_preexec()

        res = self._fork_and_get_limits(combined)
        assert res["success"] is True
        assert res["as"][0] == 256 * 1024 * 1024
        assert res["as"][1] == 256 * 1024 * 1024
        assert res["fsize"][0] == 5 * 1024 * 1024
        assert res["fsize"][1] == 5 * 1024 * 1024

    def test_fork_impossible_limit_fails_closed(self):
        """c) an impossible limit -> exception, no exec (fail-closed)."""
        import resource
        from ctf_mentor.tools.local.network import _apply_posix_limit

        def bad_preexec():
            _apply_posix_limit(resource.RLIMIT_AS, 10 * 1024 * 1024)
            # Raising hard limit on unprivileged process fails with ValueError/EPERM
            resource.setrlimit(resource.RLIMIT_AS, (100 * 1024 * 1024, 100 * 1024 * 1024))

        res = self._fork_and_get_limits(bad_preexec)
        assert res["success"] is False


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX resource limits and fork testing only supported on POSIX")
class TestRunnerPosixForkIntegration:
    """Real fork tests exercising the actual LocalSubprocessRunner composition (B-1 a, b)."""

    def _fork_and_get_limits(self, preexec_fn):
        """Fork child, run preexec_fn, serialize resource limits to pipe, return dict."""
        import json
        import resource
        r_fd, w_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r_fd)
            try:
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    import pwd
                    try:
                        nobody = pwd.getpwnam("nobody")
                        os.setgid(nobody.pw_gid)
                        os.setuid(nobody.pw_uid)
                    except Exception:
                        pass
                if preexec_fn:
                    preexec_fn()
                as_lim = resource.getrlimit(resource.RLIMIT_AS)
                fsize_lim = resource.getrlimit(resource.RLIMIT_FSIZE)
                cpu_lim = resource.getrlimit(resource.RLIMIT_CPU)
                data = json.dumps({
                    "as": as_lim,
                    "fsize": fsize_lim,
                    "cpu": cpu_lim,
                    "success": True,
                }).encode("utf-8")
                os.write(w_fd, data)
            except Exception as e:
                err_data = json.dumps({"success": False, "error": str(type(e).__name__), "msg": str(e)}).encode("utf-8")
                os.write(w_fd, err_data)
            finally:
                os.close(w_fd)
                os._exit(0)
        else:
            os.close(w_fd)
            r_file = os.fdopen(r_fd, "rb")
            data = r_file.read()
            r_file.close()
            _, status = os.waitpid(pid, 0)
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            return json.loads(data.decode("utf-8"))

    def test_runner_captured_preexec_steghide_tight_policy(self, tmp_path):
        """a) Patch Popen to capture preexec_fn from runner.run() with STEGHIDE policy, execute in forked child."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-runner-fork-steghide"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            # Policy with real STEGHIDE limits (256MB memory, 5MB fsize, 5s cpu)
            policy = LocalExecutionPolicy(
                tool_id="steghide",
                executable_path=fake.exe_path,
                timeout_seconds=5.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=5,
                posix_mem_limit_bytes=256 * 1024 * 1024,
                posix_fsize_limit_bytes=5 * 1024 * 1024,
            )
            profile = STEGHIDE_SANDBOX_PROFILE

            captured_preexec = None

            def fake_popen(*args, **kwargs):
                nonlocal captured_preexec
                captured_preexec = kwargs.get("preexec_fn")
                mock_proc = MagicMock()
                mock_proc.poll.return_value = 0
                mock_proc.returncode = 0
                mock_proc.stdout.read.return_value = b""
                mock_proc.stderr.read.return_value = b""
                return mock_proc

            with patch("subprocess.Popen", side_effect=fake_popen):
                with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.post_spawn"):
                    with patch("shutil.which", return_value="/usr/bin/bwrap"):
                        with patch("os.path.isfile", return_value=True):
                            with patch("os.access", return_value=True):
                                runner.run(
                                    argv=fake.make_argv(),
                                    policy=policy,
                                    invocation_id=inv_id,
                                    env=env,
                                    audit_log=[],
                                    sandbox_profile=profile,
                                )

            assert captured_preexec is not None, "Runner did not pass preexec_fn to Popen"
            res = self._fork_and_get_limits(captured_preexec)
            assert res["success"] is True
            # Child gets policy values (256MB / 5MB) because policy is tighter than profile
            assert res["as"][0] == 256 * 1024 * 1024
            assert res["as"][1] == 256 * 1024 * 1024
            assert res["fsize"][0] == 5 * 1024 * 1024
            assert res["fsize"][1] == 5 * 1024 * 1024

    def test_runner_captured_preexec_detects_dropping_either_hook(self, tmp_path):
        """b) Test a policy/profile pair where dropping EITHER hook gives a different result."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-runner-fork-both-hooks"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            # Policy: AS=512MB, FSIZE=5MB
            policy = LocalExecutionPolicy(
                tool_id="test_tool",
                executable_path=fake.exe_path,
                timeout_seconds=5.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=20,
                posix_mem_limit_bytes=512 * 1024 * 1024,
                posix_fsize_limit_bytes=5 * 1024 * 1024,
            )
            # Profile: AS=256MB, FSIZE=10MB
            profile = SandboxProfile(
                require_os_sandbox=False,
                isolate_mounts=False,
                max_memory_bytes=256 * 1024 * 1024,
                max_cpu_time_sec=10.0,
                max_output_bytes=10 * 1024 * 1024,
            )

            captured_preexec = None

            def fake_popen(*args, **kwargs):
                nonlocal captured_preexec
                captured_preexec = kwargs.get("preexec_fn")
                mock_proc = MagicMock()
                mock_proc.poll.return_value = 0
                mock_proc.returncode = 0
                mock_proc.stdout.read.return_value = b""
                mock_proc.stderr.read.return_value = b""
                return mock_proc

            with patch("subprocess.Popen", side_effect=fake_popen):
                with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.post_spawn"):
                    runner.run(
                        argv=fake.make_argv(),
                        policy=policy,
                        invocation_id=inv_id,
                        env=env,
                        audit_log=[],
                        sandbox_profile=profile,
                    )

            assert captured_preexec is not None, "Runner did not pass preexec_fn to Popen"
            res = self._fork_and_get_limits(captured_preexec)
            assert res["success"] is True
            # If 10B.3 policy was dropped: AS would be 256MB, but FSIZE would be 10MB (differs!)
            # If 10B.4 sandbox profile was dropped: FSIZE would be 5MB, but AS would be 512MB (differs!)
            # Effective combined limit MUST be AS=256MB, FSIZE=5MB
            assert res["as"][0] == 256 * 1024 * 1024, f"Expected 256MB AS, got {res['as']}"
            assert res["as"][1] == 256 * 1024 * 1024
            assert res["fsize"][0] == 5 * 1024 * 1024, f"Expected 5MB FSIZE, got {res['fsize']}"
            assert res["fsize"][1] == 5 * 1024 * 1024


class TestRunnerPreexecCompositionCrossPlatform:
    """Unit test suite for runner preexec composition logic (B-1 b cross-platform)."""

    def test_runner_composition_applies_both_hooks(self, tmp_path):
        """Verify runner _combined_posix_preexec applies limits from both policy and sandbox hooks."""
        from tests.test_phase10b3_local_execution import FakeExe

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-runner-unit-both-hooks"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        runner = LocalSubprocessRunner()
        env = runner.build_env()

        with FakeExe.noop() as fake:
            # Policy: AS=512MB, FSIZE=5MB
            policy = LocalExecutionPolicy(
                tool_id="test_tool",
                executable_path=fake.exe_path,
                timeout_seconds=5.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=20,
                posix_mem_limit_bytes=512 * 1024 * 1024,
                posix_fsize_limit_bytes=5 * 1024 * 1024,
            )
            # Profile: AS=256MB, FSIZE=10MB
            profile = SandboxProfile(
                require_os_sandbox=False,
                isolate_mounts=False,
                max_memory_bytes=256 * 1024 * 1024,
                max_cpu_time_sec=10.0,
                max_output_bytes=10 * 1024 * 1024,
            )

            captured_preexec = None

            def fake_popen(*args, **kwargs):
                nonlocal captured_preexec
                captured_preexec = kwargs.get("preexec_fn")
                mock_proc = MagicMock()
                mock_proc.poll.return_value = 0
                mock_proc.returncode = 0
                mock_proc.stdout.read.return_value = b""
                mock_proc.stderr.read.return_value = b""
                return mock_proc

            with patch("ctf_mentor.tools.local.network._IS_POSIX", True):
                with patch("ctf_mentor.tools.local.sandbox.sys.platform", "linux"):
                    with patch("subprocess.Popen", side_effect=fake_popen):
                        with patch("ctf_mentor.tools.local.sandbox.SandboxExecutionBoundary.post_spawn"):
                            runner.run(
                                argv=fake.make_argv(),
                                policy=policy,
                                invocation_id=inv_id,
                                env=env,
                                audit_log=[],
                                sandbox_profile=profile,
                            )

            assert captured_preexec is not None, "Runner did not pass preexec_fn to Popen"

            # Execute captured preexec with mock tracking setrlimit calls
            limits_applied = {}
            fake_resource = MagicMock()
            fake_resource.RLIM_INFINITY = 999999999
            fake_resource.RLIMIT_AS = 1
            fake_resource.RLIMIT_CPU = 2
            fake_resource.RLIMIT_FSIZE = 3

            def mock_setrlimit(res_const, lim_tuple):
                limits_applied[res_const] = lim_tuple

            fake_resource.getrlimit.side_effect = lambda res_const: (
                limits_applied.get(res_const, (999999999, 999999999))
            )
            fake_resource.setrlimit.side_effect = mock_setrlimit

            with patch.dict("sys.modules", {"resource": fake_resource}):
                captured_preexec()

            # AS limit: policy requested 512MB, sandbox requested 256MB -> final is (256MB, 256MB)
            assert limits_applied[1] == (256 * 1024 * 1024, 256 * 1024 * 1024)
            # FSIZE limit: policy requested 5MB, sandbox requested 10MB -> final is (5MB, 5MB)
            assert limits_applied[3] == (5 * 1024 * 1024, 5 * 1024 * 1024)


def _probe_bwrap_functional() -> bool:
    """Probe whether bwrap and prlimit are functional and unprivileged user namespaces are permitted."""
    if not IS_LINUX:
        return False
    bwrap_path = shutil.which("bwrap")
    prlimit_path = shutil.which("prlimit")
    if not bwrap_path or not prlimit_path:
        return False
    try:
        res = subprocess.run(
            [bwrap_path, "--ro-bind", "/", "/", "--", "/bin/true"],
            capture_output=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(
    not _probe_bwrap_functional(),
    reason="Requires Linux host with functional bwrap (user namespaces enabled) and prlimit installed",
)
class TestLinuxLiveRunnerSandbox:
    """Real non-mocked execution tests on Linux with Bubblewrap and prlimit (B-1 c, T-1, T-2)."""

    def test_live_bwrap_executable_in_tmp_runs(self, tmp_path):
        """Guards executable ro-bind: binary in /tmp starts and executes inside bwrap."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tf:
            tf.write("#!/bin/sh\necho 'BWRAP_EXEC_OK'\n")
            tf_path = Path(tf.name)
        tf_path.chmod(0o755)

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-live-bwrap-tmp-exe"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        try:
            policy = LocalExecutionPolicy(
                tool_id="test_tool",
                executable_path=tf_path,
                timeout_seconds=10.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=30,
                posix_mem_limit_bytes=512 * 1024 * 1024,
                posix_fsize_limit_bytes=10 * 1024 * 1024,
            )
            profile = SandboxProfile(
                require_os_sandbox=True,
                allow_network=False,
                isolate_mounts=True,
                isolate_pids=True,
                max_processes=4,
            )
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log = []
            res = runner.run(
                argv=[str(tf_path)],
                policy=policy,
                invocation_id=inv_id,
                env=env,
                audit_log=audit_log,
                sandbox_profile=profile,
            )
            assert res.exit_code == 0
            assert b"BWRAP_EXEC_OK" in res.stdout_bytes
        finally:
            tf_path.unlink(missing_ok=True)

    def test_live_bwrap_max_processes_enforced(self, tmp_path):
        """Shows max_processes is enforced inside sandbox via prlimit --nproc."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            pytest.skip("RLIMIT_NPROC is not enforced for root user (euid == 0)")

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write("""#!/usr/bin/env python3
import os, sys, time

pids = []
for i in range(10):
    try:
        pid = os.fork()
        if pid == 0:
            time.sleep(1)
            os._exit(0)
        pids.append(pid)
    except BlockingIOError:
        print("FORK_BLOCKED")
        sys.exit(0)
    except OSError as e:
        print(f"FORK_FAILED_{e.errno}")
        sys.exit(0)

print(f"SPAWNED_{len(pids)}")
""")
            tf_path = Path(tf.name)
        tf_path.chmod(0o755)

        auth_dir = tmp_path / "auth_ws"
        auth_dir.mkdir()
        inv_id = "test-live-bwrap-nproc"

        TRUSTED_INVOCATION_AUTHORITY.register(
            invocation_id=inv_id,
            challenge_id="ch-test",
            session_id="sess-test",
            workspace_id="ws-test",
            cwd=auth_dir,
            workspace_root=tmp_path,
        )

        try:
            policy = LocalExecutionPolicy(
                tool_id="test_tool",
                executable_path=tf_path,
                timeout_seconds=10.0,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                max_input_bytes=1024,
                max_output_bytes=1024,
                posix_cpu_limit_s=30,
                posix_mem_limit_bytes=512 * 1024 * 1024,
                posix_fsize_limit_bytes=10 * 1024 * 1024,
            )
            profile = SandboxProfile(
                require_os_sandbox=True,
                allow_network=False,
                isolate_mounts=True,
                isolate_pids=True,
                max_processes=2,
            )
            runner = LocalSubprocessRunner()
            env = runner.build_env()
            audit_log = []
            res = runner.run(
                argv=[str(tf_path)],
                policy=policy,
                invocation_id=inv_id,
                env=env,
                audit_log=audit_log,
                sandbox_profile=profile,
            )
            out = res.stdout_bytes.decode(errors="replace")
            assert "FORK_BLOCKED" in out, f"NPROC not enforced inside sandbox: {out!r}"
        finally:
            tf_path.unlink(missing_ok=True)


# =============================================================================
# 8. Symlink Rejection Before Resolve Tests
# =============================================================================

class TestSymlinkRejectionBeforeResolution:
    """Verify that symlinks on cwd, workspace_root, and handle._root are rejected before resolve()."""

    def test_register_symlink_cwd_rejected_before_resolve(self, tmp_path):
        """Symlink cwd passed to register() is rejected even if target exists."""
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        symlink_dir = tmp_path / "symlink_cwd"
        try:
            os.symlink(str(real_dir), str(symlink_dir), target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not supported in this environment")

        with pytest.raises(WorkspaceConfinementError, match="must not be a symlink"):
            TRUSTED_INVOCATION_AUTHORITY.register(
                invocation_id="test-symlink-cwd",
                challenge_id="ch-1",
                session_id="s-1",
                workspace_id="w-1",
                cwd=symlink_dir,
                workspace_root=tmp_path,
            )

    def test_register_mocked_symlink_cwd_rejected_before_resolve(self, tmp_path):
        """Mocked symlink cwd passed to register() is rejected before resolve()."""
        cwd = tmp_path / "mocked_symlink_cwd"
        with patch.object(Path, "is_symlink", return_value=True):
            with pytest.raises(WorkspaceConfinementError, match="must not be a symlink"):
                TRUSTED_INVOCATION_AUTHORITY.register(
                    invocation_id="test-mock-symlink-cwd",
                    challenge_id="ch-1",
                    session_id="s-1",
                    workspace_id="w-1",
                    cwd=cwd,
                    workspace_root=tmp_path,
                )

    def test_register_mocked_symlink_ws_root_rejected_before_resolve(self, tmp_path):
        """Mocked symlink workspace_root passed to register() is rejected before resolve()."""
        ws_root = tmp_path / "mocked_symlink_ws"
        with patch.object(Path, "is_symlink", return_value=True):
            with pytest.raises(WorkspaceConfinementError, match="must not be a symlink"):
                TRUSTED_INVOCATION_AUTHORITY.register(
                    invocation_id="test-mock-symlink-ws",
                    challenge_id="ch-1",
                    session_id="s-1",
                    workspace_id="w-1",
                    cwd=tmp_path / "work",
                    workspace_root=ws_root,
                )
