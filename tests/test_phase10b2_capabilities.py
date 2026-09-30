"""
Phase 10B.2 Capability System Tests.

Tests:
- WorkspaceCapabilitySpec construction and required_permissions()
- NULL_CAPABILITY_SPEC correctness
- TrustedWorkspaceExecutionBoundary.issue() issuance policy
- InputCapability: read-only enforcement
- WorkCapability: read/write enforcement, confinement
- OutputCapability: read/write enforcement, confinement
- Capability revocation: single and revoke_all()
- IssuedCapabilitySet: all_revoked property
- CapabilityRevokedError on revoked capability operations
- CapabilityPermissionError on disallowed operations
- Security: adapters have static workspace_capability_spec
- Security: issue() rejects non-WorkspaceCapabilitySpec
- Security: WorkspaceCapability never exposes handle/path/fd
- Security: Input capability does not grant write
- Security: Work capability cannot access output or input
- Security: Output capability cannot access work or input
- Security: least-privilege - null spec yields no capabilities
- Security: spec-based issuance - only declared capabilities granted
- Adapter contract: all 5 Phase 10A adapters have workspace_capability_spec
- Adapter contract: all 5 adapters declare NULL_CAPABILITY_SPEC (passive network)
- Revocation: post-revoke reads raise CapabilityRevokedError
- Revocation: post-revoke writes raise CapabilityRevokedError
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pytest

from ctf_mentor.persistence import database
from ctf_mentor.workspace import (
    WorkspaceManager,
    WorkspaceHandle,
    WorkspacePath,
    PathConfinementError,
    WorkspaceCapabilitySpec,
    NULL_CAPABILITY_SPEC,
    CapabilityPermission,
    WorkspaceCapability,
    InputCapability,
    WorkCapability,
    OutputCapability,
    IssuedCapabilitySet,
    TrustedWorkspaceExecutionBoundary,
    CapabilityRevokedError,
    CapabilityPermissionError,
)
from ctf_mentor.tools.adapters import (
    CrtShAdapter,
    WaybackAdapter,
    ShodanAdapter,
    VirusTotalAdapter,
    GitHubCodeSearchAdapter,
)

HAS_DIR_FD = hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd and os.rename in os.supports_dir_fd


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _seed_challenge_session(conn: sqlite3.Connection, challenge_id: str, session_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO challenges (challenge_id, name, created_at, updated_at) VALUES (?, ?, ?, ?);",
        (challenge_id, f"Challenge {challenge_id}", now, now),
    )
    conn.execute(
        "INSERT OR IGNORE INTO investigation_sessions (session_id, challenge_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
        (session_id, challenge_id, "active", now, now),
    )
    conn.commit()


@pytest.fixture()
def temp_dir(tmp_path):
    return tmp_path.resolve()


@pytest.fixture()
def db_conn(temp_dir):
    db_path = temp_dir / "test_mentor.db"
    conn = database.get_connection(db_path)
    database.initialize_schema(conn)
    yield conn
    conn.close()


@pytest.fixture()
def ws_manager(temp_dir):
    ws_root = temp_dir / "workspaces"
    return WorkspaceManager(workspace_root=ws_root, default_quota_bytes=10 * 1024 * 1024)


@pytest.fixture()
def handle(db_conn, ws_manager):
    """Issue a READY WorkspaceHandle for testing capability operations.

    Used only for workspace setup/introspection (e.g. pre-seeding files,
    verifying workspace_id). Never passed into TrustedWorkspaceExecutionBoundary.
    """
    _seed_challenge_session(db_conn, "challenge_cap_test", "session_cap_001")
    return ws_manager.get_or_create(db_conn, "challenge_cap_test", "session_cap_001")


@pytest.fixture()
def boundary(db_conn, ws_manager):
    """Create TrustedWorkspaceExecutionBoundary via the trusted API.

    The boundary resolves the WorkspaceHandle internally from WorkspaceManager
    and DB connection. Callers do NOT supply a WorkspaceHandle.
    """
    _seed_challenge_session(db_conn, "challenge_cap_test", "session_cap_001")
    return TrustedWorkspaceExecutionBoundary(
        ws_manager,
        db_conn,
        "challenge_cap_test",
        "session_cap_001",
    )


# ---------------------------------------------------------------------------
# WorkspaceCapabilitySpec tests
# ---------------------------------------------------------------------------

class TestWorkspaceCapabilitySpec:
    def test_null_spec_has_no_permissions(self):
        spec = WorkspaceCapabilitySpec()
        assert spec.required_permissions() == frozenset()

    def test_null_capability_spec_is_null(self):
        assert NULL_CAPABILITY_SPEC.needs_input is False
        assert NULL_CAPABILITY_SPEC.needs_work_read is False
        assert NULL_CAPABILITY_SPEC.needs_work_write is False
        assert NULL_CAPABILITY_SPEC.needs_output_read is False
        assert NULL_CAPABILITY_SPEC.needs_output_write is False
        assert NULL_CAPABILITY_SPEC.required_permissions() == frozenset()

    def test_input_only_spec(self):
        spec = WorkspaceCapabilitySpec(needs_input=True)
        assert CapabilityPermission.READ_INPUT in spec.required_permissions()
        assert CapabilityPermission.READ_WORK not in spec.required_permissions()
        assert CapabilityPermission.WRITE_WORK not in spec.required_permissions()
        assert CapabilityPermission.READ_OUTPUT not in spec.required_permissions()
        assert CapabilityPermission.WRITE_OUTPUT not in spec.required_permissions()

    def test_work_write_spec(self):
        spec = WorkspaceCapabilitySpec(needs_work_write=True)
        assert CapabilityPermission.WRITE_WORK in spec.required_permissions()

    def test_work_read_spec(self):
        spec = WorkspaceCapabilitySpec(needs_work_read=True)
        assert CapabilityPermission.READ_WORK in spec.required_permissions()

    def test_output_write_spec(self):
        spec = WorkspaceCapabilitySpec(needs_output_write=True)
        assert CapabilityPermission.WRITE_OUTPUT in spec.required_permissions()

    def test_output_read_spec(self):
        spec = WorkspaceCapabilitySpec(needs_output_read=True)
        assert CapabilityPermission.READ_OUTPUT in spec.required_permissions()

    def test_full_spec(self):
        spec = WorkspaceCapabilitySpec(
            needs_input=True,
            needs_work_read=True,
            needs_work_write=True,
            needs_output_read=True,
            needs_output_write=True,
        )
        perms = spec.required_permissions()
        assert CapabilityPermission.READ_INPUT in perms
        assert CapabilityPermission.READ_WORK in perms
        assert CapabilityPermission.WRITE_WORK in perms
        assert CapabilityPermission.READ_OUTPUT in perms
        assert CapabilityPermission.WRITE_OUTPUT in perms

    def test_spec_is_frozen(self):
        """WorkspaceCapabilitySpec is a frozen dataclass and cannot be mutated."""
        spec = WorkspaceCapabilitySpec(needs_input=True)
        with pytest.raises((AttributeError, TypeError)):
            spec.needs_input = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustedWorkspaceExecutionBoundary issuance tests
# ---------------------------------------------------------------------------

class TestTrustedWorkspaceExecutionBoundary:
    def test_null_spec_issues_no_capabilities(self, boundary):
        caps = boundary.issue(NULL_CAPABILITY_SPEC)
        assert caps.input_cap is None
        assert caps.work_cap is None
        assert caps.output_cap is None

    def test_input_spec_issues_input_only(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_input=True)
        caps = boundary.issue(spec)
        assert caps.input_cap is not None
        assert isinstance(caps.input_cap, InputCapability)
        assert caps.work_cap is None
        assert caps.output_cap is None

    def test_work_write_spec_issues_work_only(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_work_write=True)
        caps = boundary.issue(spec)
        assert caps.work_cap is not None
        assert isinstance(caps.work_cap, WorkCapability)
        assert caps.input_cap is None
        assert caps.output_cap is None

    def test_work_read_spec_issues_work_only(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_work_read=True)
        caps = boundary.issue(spec)
        assert caps.work_cap is not None
        assert caps.input_cap is None
        assert caps.output_cap is None

    def test_output_spec_issues_output_only(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_output_write=True)
        caps = boundary.issue(spec)
        assert caps.output_cap is not None
        assert isinstance(caps.output_cap, OutputCapability)
        assert caps.input_cap is None
        assert caps.work_cap is None

    def test_full_spec_issues_all_capabilities(self, boundary):
        spec = WorkspaceCapabilitySpec(
            needs_input=True,
            needs_work_write=True,
            needs_output_write=True,
        )
        caps = boundary.issue(spec)
        assert caps.input_cap is not None
        assert caps.work_cap is not None
        assert caps.output_cap is not None

    def test_issue_rejects_non_spec(self, boundary):
        """issue() must only accept WorkspaceCapabilitySpec instances."""
        with pytest.raises(TypeError):
            boundary.issue({"needs_input": True})  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            boundary.issue(None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            boundary.issue("needs_input=True")  # type: ignore[arg-type]

    def test_boundary_exposes_only_inert_identifiers(self, boundary):
        """TrustedWorkspaceExecutionBoundary must only expose inert string IDs."""
        assert isinstance(boundary.workspace_id, str)
        assert isinstance(boundary.challenge_id, str)
        assert isinstance(boundary.session_id, str)
        # Must not expose WorkspaceHandle, WorkspacePath, or raw Path
        assert not hasattr(boundary, "handle")
        assert not isinstance(boundary.workspace_id, Path)
        assert not isinstance(boundary.challenge_id, Path)
        assert not isinstance(boundary.session_id, Path)

    def test_boundary_repr_is_safe(self, boundary):
        r = repr(boundary)
        assert "TrustedWorkspaceExecutionBoundary" in r
        # Must not contain OS filesystem paths
        assert "workspaces" not in r
        assert "challenge_cap_test" in r or boundary.workspace_id in r

    def test_boundary_does_not_expose_handle_publicly(self, boundary):
        """The trusted boundary must not expose the WorkspaceHandle on the public interface."""
        assert not hasattr(boundary, "handle")
        assert not hasattr(boundary, "_handle")
        # workspace_id, challenge_id, session_id are inert strings
        assert isinstance(boundary.workspace_id, str)

    def test_boundary_rejects_non_connection(self, ws_manager):
        """TrustedWorkspaceExecutionBoundary must reject non-sqlite3.Connection as conn."""
        with pytest.raises(TypeError):
            TrustedWorkspaceExecutionBoundary(ws_manager, "not_a_connection", "ch", "sess")


# ---------------------------------------------------------------------------
# InputCapability tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_DIR_FD, reason="dir_fd not supported on this platform")
class TestInputCapability:
    def test_input_cap_reads_existing_file(self, handle, boundary):
        """InputCapability.read_bytes and read_text must return file data."""
        # Stage a file in input/ via the handle (trusted path for setup only)
        handle.write_bytes("input", "test_file.txt", b"hello capability")
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        data = caps.input_cap.read_bytes("test_file.txt")
        assert data == b"hello capability"
        text = caps.input_cap.read_text("test_file.txt")
        assert text == "hello capability"
        caps.revoke_all()

    def test_input_cap_returns_inert_bytes(self, handle, boundary):
        """InputCapability.read_bytes must return plain bytes, not WorkspacePath."""
        handle.write_bytes("input", "data.bin", b"\x00\x01\x02")
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        result = caps.input_cap.read_bytes("data.bin")
        assert isinstance(result, bytes)
        assert not isinstance(result, WorkspacePath)
        assert not isinstance(result, Path)
        caps.revoke_all()

    def test_input_cap_file_exists(self, handle, boundary):
        handle.write_bytes("input", "exists.txt", b"yes")
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        assert caps.input_cap.file_exists("exists.txt") is True
        assert caps.input_cap.file_exists("nonexistent.txt") is False
        caps.revoke_all()

    def test_input_cap_structurally_lacks_write_bytes(self, boundary):
        """InputCapability must NOT expose write_bytes -- structural absence."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        assert not hasattr(cap, "write_bytes"), (
            "InputCapability must not expose write_bytes; the method must not exist on the class"
        )
        assert not hasattr(type(cap), "write_bytes"), (
            "InputCapability class must not define write_bytes"
        )
        caps.revoke_all()

    def test_input_cap_structurally_lacks_write_text(self, boundary):
        """InputCapability must NOT expose write_text -- structural absence."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        assert not hasattr(cap, "write_text"), (
            "InputCapability must not expose write_text; the method must not exist on the class"
        )
        assert not hasattr(type(cap), "write_text"), (
            "InputCapability class must not define write_text"
        )
        caps.revoke_all()

    def test_input_cap_structurally_lacks_delete_file(self, boundary):
        """InputCapability must NOT expose delete_file -- structural absence."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        assert not hasattr(cap, "delete_file"), (
            "InputCapability must not expose delete_file; the method must not exist on the class"
        )
        assert not hasattr(type(cap), "delete_file"), (
            "InputCapability class must not define delete_file"
        )
        caps.revoke_all()

    def test_input_cap_path_traversal_rejected(self, boundary):
        """InputCapability must reject path traversal attempts."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        with pytest.raises((PathConfinementError, Exception)):
            caps.input_cap.read_bytes("../work/secret.txt")
        caps.revoke_all()

    def test_input_cap_nested_traversal_rejected(self, boundary):
        """InputCapability must reject nested path traversal attempts."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        with pytest.raises((PathConfinementError, Exception)):
            caps.input_cap.read_bytes("a/../../etc/passwd")
        caps.revoke_all()

    def test_input_cap_revoked_read_raises(self, handle, boundary):
        """InputCapability operations must raise CapabilityRevokedError after revocation."""
        handle.write_bytes("input", "file.txt", b"data")
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        caps.revoke_all()
        with pytest.raises(CapabilityRevokedError):
            caps.input_cap.read_bytes("file.txt")
        with pytest.raises(CapabilityRevokedError):
            caps.input_cap.read_text("file.txt")
        with pytest.raises(CapabilityRevokedError):
            caps.input_cap.file_exists("file.txt")


# ---------------------------------------------------------------------------
# WorkCapability tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_DIR_FD, reason="dir_fd not supported on this platform")
class TestWorkCapability:
    def test_work_cap_write_and_read(self, boundary):
        """WorkCapability must support read/write cycle in work/."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True, needs_work_read=True))
        n = caps.work_cap.write_bytes("result.bin", b"work data")
        assert isinstance(n, int)
        assert n == len(b"work data")
        data = caps.work_cap.read_bytes("result.bin")
        assert data == b"work data"
        caps.revoke_all()

    def test_work_cap_write_text(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        n = caps.work_cap.write_text("notes.txt", "intermediate result")
        assert isinstance(n, int)
        caps.revoke_all()

    def test_work_cap_file_exists(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        caps.work_cap.write_bytes("present.txt", b"yes")
        assert caps.work_cap.file_exists("present.txt") is True
        assert caps.work_cap.file_exists("absent.txt") is False
        caps.revoke_all()

    def test_work_cap_delete_file(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        caps.work_cap.write_bytes("to_delete.txt", b"delete me")
        assert caps.work_cap.file_exists("to_delete.txt") is True
        caps.work_cap.delete_file("to_delete.txt")
        caps.revoke_all()

    def test_work_cap_cannot_access_input(self, handle, boundary):
        """WorkCapability must not be able to read from input/ via path traversal."""
        handle.write_bytes("input", "secret.txt", b"secret")
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        with pytest.raises(Exception):
            caps.work_cap.read_bytes("../input/secret.txt")
        caps.revoke_all()

    def test_work_cap_cannot_access_output(self, boundary):
        """WorkCapability must not be able to read from output/ via path traversal."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True, needs_output_write=True))
        caps.output_cap.write_bytes("output.txt", b"output data")
        with pytest.raises(Exception):
            caps.work_cap.read_bytes("../output/output.txt")
        caps.revoke_all()

    def test_work_cap_revoked_write_raises(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        caps.revoke_all()
        with pytest.raises(CapabilityRevokedError):
            caps.work_cap.write_bytes("file.txt", b"data")
        with pytest.raises(CapabilityRevokedError):
            caps.work_cap.write_text("file.txt", "data")
        with pytest.raises(CapabilityRevokedError):
            caps.work_cap.read_bytes("file.txt")
        with pytest.raises(CapabilityRevokedError):
            caps.work_cap.file_exists("file.txt")

    def test_work_cap_returns_inert_values_only(self, boundary):
        """WorkCapability methods must return only inert types (int, bytes, str, bool)."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        n = caps.work_cap.write_bytes("check.txt", b"test")
        assert isinstance(n, int)
        assert not isinstance(n, WorkspacePath)
        assert not isinstance(n, Path)
        b = caps.work_cap.file_exists("check.txt")
        assert isinstance(b, bool)
        caps.revoke_all()


# ---------------------------------------------------------------------------
# OutputCapability tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_DIR_FD, reason="dir_fd not supported on this platform")
class TestOutputCapability:
    def test_output_cap_write_and_read(self, boundary):
        """OutputCapability must support read/write cycle in output/."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True, needs_output_read=True))
        n = caps.output_cap.write_bytes("result.json", b'{"status":"ok"}')
        assert isinstance(n, int)
        data = caps.output_cap.read_bytes("result.json")
        assert data == b'{"status":"ok"}'
        caps.revoke_all()

    def test_output_cap_write_text(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        n = caps.output_cap.write_text("summary.txt", "Final output summary")
        assert isinstance(n, int)
        caps.revoke_all()

    def test_output_cap_file_exists(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        caps.output_cap.write_bytes("out.txt", b"data")
        assert caps.output_cap.file_exists("out.txt") is True
        assert caps.output_cap.file_exists("missing.txt") is False
        caps.revoke_all()

    def test_output_cap_structurally_lacks_delete_file(self, boundary):
        """OutputCapability must NOT expose delete_file -- structural absence."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        cap = caps.output_cap
        assert not hasattr(cap, "delete_file"), (
            "OutputCapability must not expose delete_file; the method must not exist on the class"
        )
        assert not hasattr(type(cap), "delete_file"), (
            "OutputCapability class must not define delete_file"
        )
        caps.revoke_all()

    def test_output_cap_cannot_access_work(self, boundary):
        """OutputCapability must not be able to access work/ via traversal."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True, needs_output_write=True))
        caps.work_cap.write_bytes("work_secret.txt", b"work secret")
        with pytest.raises(Exception):
            caps.output_cap.read_bytes("../work/work_secret.txt")
        caps.revoke_all()

    def test_output_cap_revoked_write_raises(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        caps.revoke_all()
        with pytest.raises(CapabilityRevokedError):
            caps.output_cap.write_bytes("file.txt", b"data")
        with pytest.raises(CapabilityRevokedError):
            caps.output_cap.write_text("file.txt", "data")

    def test_output_cap_returns_inert_values_only(self, boundary):
        """OutputCapability write_bytes must return inert int only."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        n = caps.output_cap.write_bytes("out.bin", b"bytes")
        assert isinstance(n, int)
        assert not isinstance(n, WorkspacePath)
        assert not isinstance(n, Path)
        caps.revoke_all()


# ---------------------------------------------------------------------------
# IssuedCapabilitySet tests
# ---------------------------------------------------------------------------

class TestIssuedCapabilitySet:
    def test_empty_set_all_revoked(self):
        """IssuedCapabilitySet with no capabilities reports all_revoked=True."""
        caps = IssuedCapabilitySet()
        assert caps.all_revoked is True

    def test_revoke_all_revokes_everything(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_input=True, needs_work_write=True, needs_output_write=True)
        caps = boundary.issue(spec)
        assert caps.input_cap is not None
        assert not caps.input_cap.is_revoked
        assert not caps.work_cap.is_revoked
        assert not caps.output_cap.is_revoked
        assert caps.all_revoked is False
        caps.revoke_all()
        assert caps.input_cap.is_revoked
        assert caps.work_cap.is_revoked
        assert caps.output_cap.is_revoked
        assert caps.all_revoked is True

    def test_revoke_all_on_null_caps_is_safe(self, boundary):
        """revoke_all() on a set with no capabilities must not raise."""
        caps = boundary.issue(NULL_CAPABILITY_SPEC)
        caps.revoke_all()  # must not raise
        assert caps.all_revoked is True

    def test_partial_revoke_not_all_revoked(self, boundary):
        spec = WorkspaceCapabilitySpec(needs_work_write=True, needs_output_write=True)
        caps = boundary.issue(spec)
        caps.work_cap.revoke()
        assert caps.work_cap.is_revoked
        assert not caps.output_cap.is_revoked
        assert caps.all_revoked is False
        caps.revoke_all()
        assert caps.all_revoked is True


# ---------------------------------------------------------------------------
# WorkspaceCapability base class tests
# ---------------------------------------------------------------------------

class TestWorkspaceCapabilityBase:
    def test_base_capability_is_abstract(self):
        """WorkspaceCapability is an abstract ABC; direct instantiation must raise TypeError."""
        import abc
        assert hasattr(WorkspaceCapability, "__abstractmethods__"), (
            "WorkspaceCapability must declare abstract methods"
        )
        with pytest.raises(TypeError):
            # Direct instantiation of an abstract class must fail
            WorkspaceCapability("wid", "ch", "sess", "input")  # type: ignore[abstract]

    def test_base_capability_repr(self, handle, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        r = repr(caps.input_cap)
        assert "InputCapability" in r
        assert handle.workspace_id in r
        assert "live" in r
        caps.revoke_all()
        r2 = repr(caps.input_cap)
        assert "revoked" in r2

    def test_capability_exposes_only_inert_identifiers(self, handle, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        # Must expose only safe string identifiers
        assert isinstance(cap.workspace_id, str)
        assert isinstance(cap.challenge_id, str)
        assert isinstance(cap.session_id, str)
        assert cap.workspace_id == handle.workspace_id
        assert cap.challenge_id == handle.challenge_id
        assert cap.session_id == handle.session_id
        # Must NOT expose WorkspaceHandle or WorkspacePath
        assert not isinstance(cap.workspace_id, WorkspaceHandle)
        assert not isinstance(cap.workspace_id, WorkspacePath)
        # Must NOT expose pathlib.Path
        assert not isinstance(cap.workspace_id, Path)
        caps.revoke_all()

    def test_capability_does_not_expose_handle_attribute(self, boundary):
        """Capabilities must not have a public 'handle' attribute."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        # Public interface must not expose handle
        assert not hasattr(type(cap), "handle")
        assert not hasattr(cap, "handle")
        # Also must not store _handle (new architecture uses closures)
        assert not hasattr(cap, "_handle")
        caps.revoke_all()

    def test_capability_does_not_expose_directory_fd(self, boundary):
        """Capabilities must not expose directory file descriptors."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        cap = caps.work_cap
        assert not hasattr(cap, "dir_fd")
        assert not hasattr(cap, "fd")
        assert not hasattr(cap, "_fd")
        assert not hasattr(cap, "_dir_fd")
        caps.revoke_all()

    def test_capability_does_not_expose_raw_path(self, boundary):
        """Capabilities must not expose raw filesystem paths."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        cap = caps.work_cap
        # Check no public Path attributes
        assert not hasattr(cap, "path")
        assert not hasattr(cap, "root")
        assert not hasattr(cap, "_root")
        assert not hasattr(cap, "_path")
        caps.revoke_all()

    def test_capability_does_not_expose_list_files(self, boundary):
        """Capabilities must not expose list_files or glob."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True, needs_input=True))
        for cap in (caps.input_cap, caps.work_cap):
            assert not hasattr(cap, "list_files")
            assert not hasattr(cap, "glob")
            assert not hasattr(cap, "rglob")
            assert not hasattr(cap, "iterdir")
        caps.revoke_all()


# ---------------------------------------------------------------------------
# Adapter contract tests
# ---------------------------------------------------------------------------

class TestAdapterCapabilityContract:
    """Verify all 5 Phase 10A adapters comply with Phase 10B.2 contract."""

    def test_crtsh_has_workspace_capability_spec(self):
        adapter = CrtShAdapter()
        assert hasattr(adapter, "workspace_capability_spec")
        assert isinstance(adapter.workspace_capability_spec, WorkspaceCapabilitySpec)

    def test_wayback_has_workspace_capability_spec(self):
        adapter = WaybackAdapter()
        assert hasattr(adapter, "workspace_capability_spec")
        assert isinstance(adapter.workspace_capability_spec, WorkspaceCapabilitySpec)

    def test_shodan_has_workspace_capability_spec(self):
        adapter = ShodanAdapter()
        assert hasattr(adapter, "workspace_capability_spec")
        assert isinstance(adapter.workspace_capability_spec, WorkspaceCapabilitySpec)

    def test_virustotal_has_workspace_capability_spec(self):
        adapter = VirusTotalAdapter()
        assert hasattr(adapter, "workspace_capability_spec")
        assert isinstance(adapter.workspace_capability_spec, WorkspaceCapabilitySpec)

    def test_github_has_workspace_capability_spec(self):
        adapter = GitHubCodeSearchAdapter()
        assert hasattr(adapter, "workspace_capability_spec")
        assert isinstance(adapter.workspace_capability_spec, WorkspaceCapabilitySpec)

    def test_crtsh_declares_null_spec(self):
        """CrtShAdapter is passive network — must declare NULL_CAPABILITY_SPEC."""
        adapter = CrtShAdapter()
        spec = adapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC
        assert spec.required_permissions() == frozenset()

    def test_wayback_declares_null_spec(self):
        adapter = WaybackAdapter()
        spec = adapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC

    def test_shodan_declares_null_spec(self):
        adapter = ShodanAdapter()
        spec = adapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC

    def test_virustotal_declares_null_spec(self):
        adapter = VirusTotalAdapter()
        spec = adapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC

    def test_github_declares_null_spec(self):
        adapter = GitHubCodeSearchAdapter()
        spec = adapter.workspace_capability_spec
        assert spec == NULL_CAPABILITY_SPEC

    def test_workspace_capability_spec_is_class_level_attribute(self):
        """workspace_capability_spec must be a class-level attribute (not instance-computed)."""
        # Verify it is on the class, not only on the instance
        assert hasattr(CrtShAdapter, "workspace_capability_spec")
        assert hasattr(WaybackAdapter, "workspace_capability_spec")
        assert hasattr(ShodanAdapter, "workspace_capability_spec")
        assert hasattr(VirusTotalAdapter, "workspace_capability_spec")
        assert hasattr(GitHubCodeSearchAdapter, "workspace_capability_spec")

    def test_workspace_capability_spec_is_not_runtime_mutable(self):
        """Two instances of the same adapter must return the same spec object."""
        a1 = CrtShAdapter()
        a2 = CrtShAdapter()
        assert a1.workspace_capability_spec is a2.workspace_capability_spec


# ---------------------------------------------------------------------------
# Security: capability isolation tests
# ---------------------------------------------------------------------------

class TestCapabilityIsolation:
    def test_null_spec_boundary_issue_returns_only_nones(self, boundary):
        """NULL_CAPABILITY_SPEC must yield all-None IssuedCapabilitySet."""
        caps = boundary.issue(NULL_CAPABILITY_SPEC)
        assert caps.input_cap is None
        assert caps.work_cap is None
        assert caps.output_cap is None

    def test_input_spec_only_no_work_output(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        assert caps.input_cap is not None
        assert caps.work_cap is None
        assert caps.output_cap is None
        caps.revoke_all()

    def test_work_spec_only_no_input_output(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_work_write=True))
        assert caps.input_cap is None
        assert caps.work_cap is not None
        assert caps.output_cap is None
        caps.revoke_all()

    def test_output_spec_only_no_input_work(self, boundary):
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        assert caps.input_cap is None
        assert caps.work_cap is None
        assert caps.output_cap is not None
        caps.revoke_all()

    def test_each_issuance_produces_fresh_capabilities(self, boundary):
        """Each call to issue() must produce distinct capability instances."""
        spec = WorkspaceCapabilitySpec(needs_input=True)
        caps1 = boundary.issue(spec)
        caps2 = boundary.issue(spec)
        assert caps1.input_cap is not caps2.input_cap
        caps1.revoke_all()
        caps2.revoke_all()

    def test_revocation_does_not_affect_other_issuance(self, boundary):
        """Revoking one IssuedCapabilitySet must not affect another issuance."""
        spec = WorkspaceCapabilitySpec(needs_input=True)
        caps1 = boundary.issue(spec)
        caps2 = boundary.issue(spec)
        caps1.revoke_all()
        assert caps1.input_cap.is_revoked
        assert not caps2.input_cap.is_revoked
        caps2.revoke_all()

    def test_base_capability_is_abstract_cannot_be_instantiated(self):
        """WorkspaceCapability is an ABC; direct construction raises TypeError."""
        with pytest.raises(TypeError):
            WorkspaceCapability("wid", "cid", "sid", "input")  # type: ignore[abstract]

    def test_input_cap_does_not_grant_work_or_output_access(self, boundary):
        """InputCapability must be confined to input/ and have no write surface."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_input=True))
        cap = caps.input_cap
        assert isinstance(cap, InputCapability)
        # Structural checks: must not expose write/delete
        assert not hasattr(cap, "write_bytes")
        assert not hasattr(cap, "write_text")
        assert not hasattr(cap, "delete_file")
        # Also must not have list/glob
        assert not hasattr(cap, "list_files")
        assert not hasattr(cap, "glob")
        caps.revoke_all()

    def test_output_cap_does_not_grant_delete(self, boundary):
        """OutputCapability must be structurally unable to delete."""
        caps = boundary.issue(WorkspaceCapabilitySpec(needs_output_write=True))
        cap = caps.output_cap
        assert isinstance(cap, OutputCapability)
        assert not hasattr(cap, "delete_file")
        assert not hasattr(type(cap), "delete_file")
        caps.revoke_all()

    def test_permissions_come_from_static_spec_only(self, boundary):
        """Capability permissions are determined by static spec, not runtime user input."""
        # Even if we construct a spec with all flags False, no capabilities are granted
        caps = boundary.issue(WorkspaceCapabilitySpec())
        assert caps.input_cap is None
        assert caps.work_cap is None
        assert caps.output_cap is None
        # Cannot expand capabilities by passing arbitrary kwargs at runtime
        spec = WorkspaceCapabilitySpec(needs_input=True)
        caps2 = boundary.issue(spec)
        # The boundary only issues what the spec declares
        assert caps2.input_cap is not None
        assert caps2.work_cap is None  # not declared
        assert caps2.output_cap is None  # not declared
        caps2.revoke_all()
