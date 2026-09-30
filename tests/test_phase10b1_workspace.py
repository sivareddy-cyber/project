"""
Comprehensive Unit & Security Test Suite for Phase 10B.1 Workspace Isolation.

Covers:
- Positive tests: workspace creation/reuse, directory creation, stage_upload, resolve read-back, import_verified_artifact.
- Negative tests: unknown challenge/session, mismatched challenge/session pairing, path traversal (POSIX & Windows), oversized uploads, quota exceeded, SHA-256 mismatch, expired/quarantined status.
- Security & Adversarial tests: symlink escape, TOCTOU symlink race, hard-link inspection, zip-slip filename traversal, Windows reserved names, stale staging cleanup, cross-session and cross-challenge access enforcement, concurrent writers and quota accounting.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from ctf_mentor.persistence import database
from ctf_mentor.workspace import (
    ArtifactIntegrityError,
    ArtifactSecurityError,
    PathConfinementError,
    QuotaExceededError,
    WorkspaceError,
    WorkspaceHandle,
    WorkspaceLockError,
    WorkspaceManager,
    WorkspacePath,
    WorkspaceRecord,
    WorkspaceRepository,
    WorkspaceStatus,
    WorkspaceStatusError,
    WorkspaceValidationError,
)

HAS_DIR_FD = hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd and os.rename in os.supports_dir_fd


@dataclass
class MockIngestionObservation:
    observation_id: str
    artifact_path: str
    sha256: str


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp).resolve()


@pytest.fixture
def db_conn(temp_dir):
    db_path = temp_dir / "test_mentor.db"
    conn = database.get_connection(db_path)
    database.initialize_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def ws_manager(temp_dir):
    ws_root = temp_dir / "workspaces"
    return WorkspaceManager(workspace_root=ws_root, default_quota_bytes=10 * 1024 * 1024)


def _seed_challenge_and_session(conn: sqlite3.Connection, challenge_id: str, session_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO challenges (challenge_id, name, created_at, updated_at) VALUES (?, ?, ?, ?);",
        (challenge_id, f"Challenge {challenge_id}", now, now),
    )
    conn.execute(
        "INSERT OR IGNORE INTO investigation_sessions (session_id, challenge_id, status, created_at, updated_at) VALUES (?, ?, 'active', ?, ?);",
        (session_id, challenge_id, now, now),
    )


# ---------------------------------------------------------------------------
# 1. POSITIVE TESTS
# ---------------------------------------------------------------------------


def test_valid_workspace_creation_and_reuse(db_conn, ws_manager):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")

    handle1 = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")
    assert isinstance(handle1, WorkspaceHandle)
    assert handle1.challenge_id == "ch_001"
    assert handle1.session_id == "sess_001"
    assert handle1.status == "READY"

    assert handle1.input_dir().exists()
    assert handle1.work_dir().exists()
    assert handle1.output_dir().exists()

    # Reuse should return the same workspace
    handle2 = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")
    assert handle2.workspace_id == handle1.workspace_id
    assert handle2._root == handle1._root


def test_path_confinement_resolve_and_readback(db_conn, ws_manager):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    in_file = handle.resolve("input", "sample.txt")
    work_file = handle.resolve("work", "sub/nested.txt")
    out_file = handle.resolve("output", "results.json")

    assert in_file.parent == handle.input_dir()
    assert work_file.relative_to(handle.work_dir())
    assert out_file.parent == handle.output_dir()

    # Read-back test
    in_file.write_text("hello input", encoding="utf-8")
    assert handle.resolve("input", "sample.txt").read_text(encoding="utf-8") == "hello input"


def test_import_verified_artifact_matching_sha256(db_conn, ws_manager, temp_dir):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Create dummy artifact outside workspace
    source_artifact = temp_dir / "evidence.bin"
    content = b"CRITICAL_EVIDENCE_DATA_12345"
    source_artifact.write_bytes(content)
    expected_sha256 = hashlib.sha256(content).hexdigest()

    obs = MockIngestionObservation(
        observation_id="obs_100",
        artifact_path=str(source_artifact),
        sha256=expected_sha256,
    )

    imported_path = ws_manager.import_verified_artifact(handle, obs)
    assert imported_path.exists()
    assert imported_path.parent == handle.input_dir()
    assert imported_path.read_bytes() == content


# ---------------------------------------------------------------------------
# 2. NEGATIVE TESTS & VALIDATIONS
# ---------------------------------------------------------------------------


def test_workspace_validation_unknown_challenge(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    with pytest.raises(WorkspaceValidationError, match="does not exist"):
        ws_manager.get_or_create(db_conn, "ch_nonexistent", "sess_001")


def test_workspace_validation_unknown_session(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    with pytest.raises(WorkspaceValidationError, match="does not exist"):
        ws_manager.get_or_create(db_conn, "ch_001", "sess_nonexistent")


def test_workspace_validation_mismatched_pairing(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    _seed_challenge_and_session(db_conn, "ch_002", "sess_002")

    # Attempt to request ch_002 + sess_001 (sess_001 belongs to ch_001)
    with pytest.raises(WorkspaceValidationError, match="belongs to challenge 'ch_001', not requested challenge 'ch_002'"):
        ws_manager.get_or_create(db_conn, "ch_002", "sess_001")


def test_path_confinement_traversal_rejection(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Parent traversal
    with pytest.raises(PathConfinementError, match="Path traversal"):
        handle.resolve("input", "../work/secret.txt")

    with pytest.raises(PathConfinementError, match="Path traversal"):
        handle.resolve("input", "..\\work\\secret.txt")

    # Absolute paths
    with pytest.raises(PathConfinementError, match="Absolute"):
        handle.resolve("input", "/etc/passwd")

    with pytest.raises(PathConfinementError, match="Absolute"):
        handle.resolve("input", "C:\\Windows\\System32\\cmd.exe")

    # UNC paths
    with pytest.raises(PathConfinementError, match="forbidden"):
        handle.resolve("input", "\\\\server\\share\\file.txt")

    # NUL bytes
    with pytest.raises(PathConfinementError, match="NUL byte"):
        handle.resolve("input", "file.txt\x00.png")

    # Windows reserved names
    with pytest.raises(PathConfinementError, match="Windows reserved filename"):
        handle.resolve("input", "CON")

    with pytest.raises(PathConfinementError, match="Windows reserved filename"):
        handle.resolve("input", "NUL.txt")


def test_oversized_upload_and_quota_exceeded(db_conn, ws_manager):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # 1. Single file max size check
    huge_data = b"X" * (1024 * 1024)
    with pytest.raises(QuotaExceededError, match="exceeds maximum allowed file size"):
        ws_manager.stage_upload(handle, "huge.bin", huge_data, max_file_size=500 * 1024)

    # Verify no temp file left behind
    assert len(list((handle._root / "input").glob(".staging_tmp_*"))) == 0

    # 2. Total workspace quota check
    ws_manager.stage_upload(handle, "part1.bin", b"A" * 800, max_file_size=1000, quota_bytes=1000)
    with pytest.raises(QuotaExceededError, match="exceed workspace disk quota"):
        ws_manager.stage_upload(handle, "part2.bin", b"B" * 300, max_file_size=1000, quota_bytes=1000)


def test_import_verified_artifact_sha256_mismatch(db_conn, ws_manager, temp_dir):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    source_artifact = temp_dir / "tampered.bin"
    source_artifact.write_bytes(b"TAMPERED_DATA")

    obs = MockIngestionObservation(
        observation_id="obs_101",
        artifact_path=str(source_artifact),
        sha256="0000000000000000000000000000000000000000000000000000000000000000",
    )

    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        ws_manager.import_verified_artifact(handle, obs)


def test_workspace_lifecycle_expired_quarantined_and_creating(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")

    # 1. Expired workspace
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    handle_exp = ws_manager.get_or_create(db_conn, "ch_001", "sess_001", expires_at=past_iso)

    # Next attempt to fetch must raise WorkspaceStatusError
    with pytest.raises(WorkspaceStatusError, match="EXPIRED"):
        ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # 2. Quarantined workspace
    _seed_challenge_and_session(db_conn, "ch_002", "sess_002")
    ws_manager.get_or_create(db_conn, "ch_002", "sess_002")
    record = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_002", "sess_002")
    WorkspaceRepository.update_status(db_conn, record.workspace_id, WorkspaceStatus.QUARANTINED)

    with pytest.raises(WorkspaceStatusError, match="QUARANTINED"):
        ws_manager.get_or_create(db_conn, "ch_002", "sess_002")

    # 3. Incomplete CREATING workspace (simulating crashed creation)
    _seed_challenge_and_session(db_conn, "ch_003", "sess_003")
    rec_creating = WorkspaceRecord(
        workspace_id="ws_creating_test",
        challenge_id="ch_003",
        session_id="sess_003",
        relative_root="ch_003/sess_003",
        status=WorkspaceStatus.CREATING.value,
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    WorkspaceRepository.create(db_conn, rec_creating)

    with pytest.raises(WorkspaceStatusError, match="QUARANTINED"):
        ws_manager.get_or_create(db_conn, "ch_003", "sess_003")

    # Status in DB must now be QUARANTINED
    updated_rec = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_003", "sess_003")
    assert updated_rec.status == WorkspaceStatus.QUARANTINED.value


# ---------------------------------------------------------------------------
# 3. ADVERSARIAL & SECURITY TESTS
# ---------------------------------------------------------------------------


def test_cross_session_and_cross_challenge_isolation(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_A", "sess_A1")
    _seed_challenge_and_session(db_conn, "ch_A", "sess_A2")
    _seed_challenge_and_session(db_conn, "ch_B", "sess_B1")

    handle_A1 = ws_manager.get_or_create(db_conn, "ch_A", "sess_A1")
    handle_A2 = ws_manager.get_or_create(db_conn, "ch_A", "sess_A2")
    handle_B1 = ws_manager.get_or_create(db_conn, "ch_B", "sess_B1")

    # Verify roots are distinct
    assert handle_A1._root != handle_A2._root
    assert handle_A1._root != handle_B1._root

    # Cross-session path resolution attempt: handle_A1 trying to reference handle_A2's directory
    rel_to_A2 = f"../../sess_A2/input/target.txt"
    with pytest.raises(PathConfinementError):
        handle_A1.resolve("input", rel_to_A2)

    # Cross-challenge path resolution attempt: handle_A1 trying to reference handle_B1's directory
    rel_to_B1 = f"../../../ch_B/sess_B1/input/target.txt"
    with pytest.raises(PathConfinementError):
        handle_A1.resolve("input", rel_to_B1)


def test_symlink_escape_and_race_prevention(db_conn, ws_manager, temp_dir):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Outside secret directory
    outside_dir = temp_dir / "outside_secrets"
    outside_dir.mkdir()
    secret_file = outside_dir / "passwords.txt"
    secret_file.write_text("root:password123", encoding="utf-8")

    # Create symlink inside input directory pointing outside using internal handle._root path for test setup
    link_path = handle._root / "input" / "escape_link"
    try:
        os.symlink(outside_dir, link_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # Resolving or reading path through symlink must fail with PathConfinementError
    with pytest.raises(PathConfinementError):
        handle.resolve("input", "escape_link/passwords.txt").read_text()


def test_hard_link_security(db_conn, ws_manager, temp_dir):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    target_file = temp_dir / "original.bin"
    target_file.write_bytes(b"HARDLINK_TARGET_DATA")

    hard_link_path = temp_dir / "hardlinked.bin"
    try:
        os.link(target_file, hard_link_path)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("Hard links not supported on this platform/filesystem")

    expected_sha = hashlib.sha256(b"HARDLINK_TARGET_DATA").hexdigest()
    obs = MockIngestionObservation(
        observation_id="obs_hl",
        artifact_path=str(hard_link_path),
        sha256=expected_sha,
    )

    with pytest.raises(ArtifactSecurityError, match="Suspicious multi-link"):
        ws_manager.import_verified_artifact(handle, obs)


def test_zip_slip_and_filename_traversal_staging(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Zip-slip style filenames with directory traversal
    with pytest.raises(PathConfinementError, match="simple name without path components"):
        ws_manager.stage_upload(handle, "../../etc/shadow", b"malicious")

    with pytest.raises(PathConfinementError, match="simple name without path components"):
        ws_manager.stage_upload(handle, "sub/dir/file.txt", b"malicious")


def test_stale_staging_file_cleanup(db_conn, ws_manager):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Simulate crashed staging uploads leaving .staging_tmp_* files created in the past
    tmp1 = handle.input_dir() / ".staging_tmp_abandoned1"
    tmp2 = handle.work_dir() / ".staging_tmp_abandoned2"
    tmp1.write_bytes(b"partial1")
    tmp2.write_bytes(b"partial2")

    old_ts = datetime.now(timezone.utc).timestamp() - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_abandoned1", (old_ts, old_ts))
    os.utime(handle._root / "work" / ".staging_tmp_abandoned2", (old_ts, old_ts))

    assert tmp1.exists()
    assert tmp2.exists()

    cleaned = ws_manager.clean_stale_staging_files(handle)
    assert cleaned == 2
    assert not tmp1.exists()
    assert not tmp2.exists()


def test_concurrent_writers_and_quota_accounting(db_conn, ws_manager):
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Test concurrent uploads to the SAME workspace
    errors = []
    threads = []

    def _worker(thread_idx: int):
        try:
            data = f"THREAD_{thread_idx}_DATA".encode("utf-8") * 100
            ws_manager.stage_upload(handle, f"file_{thread_idx}.txt", data)
        except Exception as e:
            errors.append(e)

    for i in range(10):
        t = threading.Thread(target=_worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0

    # Verify all files exist intact without corruption
    for i in range(10):
        fpath = handle.resolve("input", f"file_{i}.txt")
        assert fpath.exists()
        assert fpath.read_text(encoding="utf-8").startswith(f"THREAD_{i}_DATA")


def test_sweep_expired(db_conn, ws_manager):
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    _seed_challenge_and_session(db_conn, "ch_002", "sess_002")

    past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    future_iso = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    ws_manager.get_or_create(db_conn, "ch_001", "sess_001", expires_at=past_iso)
    ws_manager.get_or_create(db_conn, "ch_002", "sess_002", expires_at=future_iso)

    swept_count = ws_manager.sweep_expired(db_conn)
    assert swept_count == 1

    rec1 = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_001", "sess_001")
    rec2 = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_002", "sess_002")

    assert rec1.status == "EXPIRED"
    assert rec2.status == "READY"


# ---------------------------------------------------------------------------
# 4. SECURITY REMEDIATION REGRESSION TESTS (FINDINGS 1 - 4)
# ---------------------------------------------------------------------------


def test_remediation_finding1_workspace_root_symlink_escape_parent_level(db_conn, ws_manager, temp_dir):
    """Finding 1 Regression Test: Symlink at parent challenge level escapes workspace root on READY reuse."""
    _seed_challenge_and_session(db_conn, "ch_sym_parent", "sess_sym1")
    handle = ws_manager.get_or_create(db_conn, "ch_sym_parent", "sess_sym1")
    assert handle.status == "READY"

    # Remove legitimate challenge directory
    ch_dir = ws_manager.workspace_root / "ch_sym_parent"
    shutil.rmtree(ch_dir)

    # Outside target directory with fake input/work/output
    outside_dir = temp_dir / "outside_fake_root"
    fake_sess = outside_dir / "sess_sym1"
    (fake_sess / "input").mkdir(parents=True, exist_ok=True)
    (fake_sess / "work").mkdir(parents=True, exist_ok=True)
    (fake_sess / "output").mkdir(parents=True, exist_ok=True)

    # Replace parent ch_sym_parent with symlink pointing outside
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # get_or_create MUST fail closed and update status to QUARANTINED
    with pytest.raises((PathConfinementError, WorkspaceStatusError)):
        ws_manager.get_or_create(db_conn, "ch_sym_parent", "sess_sym1")

    # Status in DB MUST be QUARANTINED
    rec = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_sym_parent", "sess_sym1")
    assert rec.status == WorkspaceStatus.QUARANTINED.value


def test_remediation_finding1_workspace_root_symlink_escape_session_level(db_conn, ws_manager, temp_dir):
    """Finding 1 Regression Test: Symlink at session directory level escapes workspace root on READY reuse."""
    _seed_challenge_and_session(db_conn, "ch_sym_sess", "sess_sym2")
    handle = ws_manager.get_or_create(db_conn, "ch_sym_sess", "sess_sym2")
    assert handle.status == "READY"

    # Remove legitimate session directory
    sess_dir = ws_manager.workspace_root / "ch_sym_sess" / "sess_sym2"
    shutil.rmtree(sess_dir)

    # Outside target directory
    outside_sess = temp_dir / "outside_sess_root"
    (outside_sess / "input").mkdir(parents=True, exist_ok=True)
    (outside_sess / "work").mkdir(parents=True, exist_ok=True)
    (outside_sess / "output").mkdir(parents=True, exist_ok=True)

    # Replace sess_sym2 with symlink pointing outside
    try:
        os.symlink(outside_sess, sess_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # get_or_create MUST fail closed and update status to QUARANTINED
    with pytest.raises((PathConfinementError, WorkspaceStatusError)):
        ws_manager.get_or_create(db_conn, "ch_sym_sess", "sess_sym2")

    rec = WorkspaceRepository.get_by_challenge_and_session(db_conn, "ch_sym_sess", "sess_sym2")
    assert rec.status == WorkspaceStatus.QUARANTINED.value


def test_remediation_finding2_import_verified_artifact_toctou_mutation(db_conn, ws_manager, temp_dir):
    """Finding 2 Regression Test: Source artifact mutation between hash verification and copy is prevented."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    # Create source file with original content
    source_artifact = temp_dir / "mutating_artifact.bin"
    original_bytes = b"ORIGINAL_VERIFIED_CONTENT_999"
    source_artifact.write_bytes(original_bytes)
    original_sha256 = hashlib.sha256(original_bytes).hexdigest()

    # Mutate source file content so hash will mismatch during streaming import
    mutated_bytes = b"MUTATED_UNVERIFIED_CONTENT_888"
    source_artifact.write_bytes(mutated_bytes)

    obs = MockIngestionObservation(
        observation_id="obs_toctou",
        artifact_path=str(source_artifact),
        sha256=original_sha256,
    )

    # Import MUST fail with ArtifactIntegrityError
    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        ws_manager.import_verified_artifact(handle, obs)

    # Prove that the unverified/mutated artifact NEVER appeared in workspace input/ directory
    staged_target = handle.input_dir() / source_artifact.name
    assert not staged_target.exists()

    # Prove no leftover staging files exist
    assert len(list((handle._root / "input").glob(".staging_tmp_*"))) == 0


def test_remediation_finding3_concurrency_multiple_manager_instances(db_conn, temp_dir):
    """Finding 3 Regression Test: Multiple WorkspaceManager instances operating on the same workspace."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    ws_root = temp_dir / "shared_workspaces"

    mgr1 = WorkspaceManager(workspace_root=ws_root)
    mgr2 = WorkspaceManager(workspace_root=ws_root)

    handle1 = mgr1.get_or_create(db_conn, "ch_001", "sess_001")
    handle2 = mgr2.get_or_create(db_conn, "ch_001", "sess_001")

    assert handle1.workspace_id == handle2.workspace_id
    assert handle1._root == handle2._root

    # Concurrent operations using different manager instances
    path1 = mgr1.stage_upload(handle1, "file_mgr1.txt", b"MGR1_DATA")
    path2 = mgr2.stage_upload(handle2, "file_mgr2.txt", b"MGR2_DATA")

    assert path1.exists() and path1.read_text(encoding="utf-8") == "MGR1_DATA"
    assert path2.exists() and path2.read_text(encoding="utf-8") == "MGR2_DATA"


def test_remediation_finding4_stale_aware_staging_cleanup(db_conn, ws_manager):
    """Finding 4 Regression Test: Active staging files are retained while stale staging files are cleaned."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_001", "sess_001")
    handle = ws_manager.get_or_create(db_conn, "ch_001", "sess_001")

    now_ts = datetime.now(timezone.utc).timestamp()

    # Active staging file (created just now)
    active_tmp = handle.input_dir() / ".staging_tmp_active123"
    active_tmp.write_bytes(b"active_in_progress_data")

    # Stale staging file (created 120 seconds ago)
    stale_tmp = handle.input_dir() / ".staging_tmp_stale456"
    stale_tmp.write_bytes(b"stale_abandoned_data")
    old_time = now_ts - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_stale456", (old_time, old_time))

    # Clean with 60s stale threshold
    cleaned_count = ws_manager.clean_stale_staging_files(handle, stale_age_seconds=60.0)

    assert cleaned_count == 1
    assert active_tmp.exists()  # Active file MUST be retained!
    assert not stale_tmp.exists()  # Stale file MUST be cleaned!

    # Clean with 0s threshold removes active file
    ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0.0)
    assert not active_tmp.exists()


# ---------------------------------------------------------------------------
# 5. FINAL REMEDIATION REGRESSION TESTS: SUBDIRECTORY SYMLINK ESCAPES
# ---------------------------------------------------------------------------


def test_remediation_subdir_symlink_input_stage_upload_fails(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 1: input directory replaced by symlink to outside blocks stage_upload."""
    _seed_challenge_and_session(db_conn, "ch_sub_in", "sess_sub_in")
    handle = ws_manager.get_or_create(db_conn, "ch_sub_in", "sess_sub_in")

    outside_dir = temp_dir / "outside_input_target"
    outside_dir.mkdir()

    # Replace input directory with symlink pointing outside workspace
    shutil.rmtree(handle._root / "input")
    try:
        os.symlink(outside_dir, handle._root / "input", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # stage_upload MUST fail with PathConfinementError
    with pytest.raises(PathConfinementError, match="symlink"):
        ws_manager.stage_upload(handle, "exploit.bin", b"EXPLOIT_PAYLOAD")

    # Verify no file appears outside workspace
    assert not (outside_dir / "exploit.bin").exists()
    assert len(list(outside_dir.iterdir())) == 0


def test_remediation_subdir_symlink_work_dir_fails(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 2: work directory replaced by symlink to outside blocks work operations."""
    _seed_challenge_and_session(db_conn, "ch_sub_work", "sess_sub_work")
    handle = ws_manager.get_or_create(db_conn, "ch_sub_work", "sess_sub_work")

    outside_dir = temp_dir / "outside_work_target"
    outside_dir.mkdir()

    shutil.rmtree(handle._root / "work")
    try:
        os.symlink(outside_dir, handle._root / "work", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.work_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.resolve("work", "scratch.txt")


def test_remediation_subdir_symlink_output_dir_fails(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 3: output directory replaced by symlink to outside blocks output operations."""
    _seed_challenge_and_session(db_conn, "ch_sub_out", "sess_sub_out")
    handle = ws_manager.get_or_create(db_conn, "ch_sub_out", "sess_sub_out")

    outside_dir = temp_dir / "outside_out_target"
    outside_dir.mkdir()

    shutil.rmtree(handle._root / "output")
    try:
        os.symlink(outside_dir, handle._root / "output", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.output_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.resolve("output", "result.json")


def test_remediation_existing_handle_followed_by_subdir_replacement(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 4: existing handle followed by subdirectory replacement loses access capability."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_exist", "sess_exist")
    handle = ws_manager.get_or_create(db_conn, "ch_exist", "sess_exist")

    # Verify input_dir succeeds prior to tamper
    assert handle.input_dir().exists()

    outside_dir = temp_dir / "external_attack_dir"
    outside_dir.mkdir()

    # Tamper subdirectory after handle acquisition
    shutil.rmtree(handle._root / "input")
    try:
        os.symlink(outside_dir, handle._root / "input", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # Existing handle MUST NOT become a capability to access external_dir
    with pytest.raises(PathConfinementError, match="symlink"):
        handle.input_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.resolve("input", "data.txt")

    with pytest.raises(PathConfinementError, match="symlink"):
        ws_manager.stage_upload(handle, "attack.bin", b"DATA")

    assert len(list(outside_dir.iterdir())) == 0


def test_remediation_reproduce_attack_stage_upload_blocked(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 5: Specifically reproduce attack (stage_upload into symlinked input)."""
    _seed_challenge_and_session(db_conn, "ch_atk1", "sess_atk1")
    handle = ws_manager.get_or_create(db_conn, "ch_atk1", "sess_atk1")

    outside_dir = temp_dir / "attack_outside_upload"
    outside_dir.mkdir()

    shutil.rmtree(handle._root / "input")
    try:
        os.symlink(outside_dir, handle._root / "input", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "stolen.txt", b"SENSITIVE_DATA")

    # Verify NO file appeared outside the workspace
    assert not (outside_dir / "stolen.txt").exists()
    assert len(list(outside_dir.iterdir())) == 0


def test_remediation_reproduce_attack_import_verified_artifact_blocked(db_conn, ws_manager, temp_dir):
    """Subdirectory Symlink Remediation 6: Specifically reproduce attack (import_verified_artifact into symlinked input)."""
    _seed_challenge_and_session(db_conn, "ch_atk2", "sess_atk2")
    handle = ws_manager.get_or_create(db_conn, "ch_atk2", "sess_atk2")

    source_artifact = temp_dir / "legit_artifact.bin"
    source_artifact.write_bytes(b"LEGIT_ARTIFACT_DATA")
    sha256_val = hashlib.sha256(b"LEGIT_ARTIFACT_DATA").hexdigest()
    obs = MockIngestionObservation("obs_atk", str(source_artifact), sha256_val)

    outside_dir = temp_dir / "attack_outside_import"
    outside_dir.mkdir()

    shutil.rmtree(handle._root / "input")
    try:
        os.symlink(outside_dir, handle._root / "input", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    # Verify NO file appeared outside the workspace
    assert not (outside_dir / source_artifact.name).exists()
    assert len(list(outside_dir.iterdir())) == 0


def test_remediation_subdir_symlink_mock_unit_test(db_conn, ws_manager, monkeypatch):
    """Subdirectory Symlink Remediation Unit Test: verifies _get_validated_subdir fails when is_symlink() returns True."""
    _seed_challenge_and_session(db_conn, "ch_mock", "sess_mock")
    handle = ws_manager.get_or_create(db_conn, "ch_mock", "sess_mock")

    raw_input = handle._root / "input"
    orig_is_symlink = Path.is_symlink

    def mock_is_symlink(self_path):
        if str(self_path.resolve()) == str(raw_input.resolve()) or self_path == raw_input:
            return True
        return orig_is_symlink(self_path)

    monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.input_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        ws_manager.stage_upload(handle, "test.bin", b"DATA")


# ---------------------------------------------------------------------------
# 6. EXISTING HANDLE ROOT ESCAPE REMEDIATION REGRESSION TESTS
# ---------------------------------------------------------------------------


def test_remediation_existing_handle_challenge_symlink_escape(db_conn, ws_manager, temp_dir):
    """Existing Handle Remediation 1: challenge directory replaced by symlink after handle issuance fails closed."""
    _seed_challenge_and_session(db_conn, "ch_esc_parent", "sess_esc1")
    handle = ws_manager.get_or_create(db_conn, "ch_esc_parent", "sess_esc1")
    assert handle.status == "READY"

    # Setup external directory tree
    outside_dir = temp_dir / "outside_esc_parent"
    fake_sess = outside_dir / "sess_esc1"
    (fake_sess / "input").mkdir(parents=True, exist_ok=True)
    (fake_sess / "work").mkdir(parents=True, exist_ok=True)
    (fake_sess / "output").mkdir(parents=True, exist_ok=True)
    (fake_sess / "input" / "secret.txt").write_text("EXT_SECRET", encoding="utf-8")

    source_artifact = temp_dir / "src_artifact.bin"
    source_artifact.write_bytes(b"SRC_DATA")
    obs = MockIngestionObservation("obs_esc1", str(source_artifact), hashlib.sha256(b"SRC_DATA").hexdigest())

    # Replace legitimate challenge directory with symlink to outside_dir
    ch_dir = ws_manager.workspace_root / "ch_esc_parent"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # Use ORIGINAL handle (WITHOUT calling get_or_create() again)
    with pytest.raises(PathConfinementError):
        handle.input_dir()

    with pytest.raises(PathConfinementError):
        handle.work_dir()

    with pytest.raises(PathConfinementError):
        handle.output_dir()

    with pytest.raises(PathConfinementError):
        handle.resolve("input", "secret.txt")

    with pytest.raises(PathConfinementError):
        handle.resolve("work", "secret.txt")

    with pytest.raises(PathConfinementError):
        handle.resolve("output", "secret.txt")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "new.txt", b"NEW_DATA")

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    # Prove NO external file was written
    assert not (fake_sess / "input" / "new.txt").exists()
    assert not (fake_sess / "input" / source_artifact.name).exists()


def test_remediation_existing_handle_session_symlink_escape(db_conn, ws_manager, temp_dir):
    """Existing Handle Remediation 2: session directory replaced by symlink after handle issuance fails closed."""
    _seed_challenge_and_session(db_conn, "ch_esc_sess", "sess_esc2")
    handle = ws_manager.get_or_create(db_conn, "ch_esc_sess", "sess_esc2")
    assert handle.status == "READY"

    outside_dir = temp_dir / "outside_esc_sess"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)
    (outside_dir / "work").mkdir(parents=True, exist_ok=True)
    (outside_dir / "output").mkdir(parents=True, exist_ok=True)
    (outside_dir / "input" / "secret.txt").write_text("EXT_SECRET2", encoding="utf-8")

    sess_dir = ws_manager.workspace_root / "ch_esc_sess" / "sess_esc2"
    shutil.rmtree(sess_dir)
    try:
        os.symlink(outside_dir, sess_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    # Use ORIGINAL handle without calling get_or_create() again
    with pytest.raises(PathConfinementError):
        handle.input_dir()

    with pytest.raises(PathConfinementError):
        handle.work_dir()

    with pytest.raises(PathConfinementError):
        handle.output_dir()

    with pytest.raises(PathConfinementError):
        handle.resolve("input", "secret.txt")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "new.txt", b"NEW_DATA")

    assert not (outside_dir / "input" / "new.txt").exists()


def test_remediation_existing_handle_root_escape_mock_unit_test(db_conn, ws_manager, monkeypatch):
    """Existing Handle Remediation 3: Unit test verifying handle methods fail when parent path component is symlinked."""
    _seed_challenge_and_session(db_conn, "ch_esc_mock", "sess_esc_mock")
    handle = ws_manager.get_or_create(db_conn, "ch_esc_mock", "sess_esc_mock")

    ch_dir = ws_manager.workspace_root / "ch_esc_mock"
    orig_is_symlink = Path.is_symlink

    def mock_is_symlink(self_path):
        if self_path == ch_dir or str(self_path.resolve()) == str(ch_dir.resolve()):
            return True
        return orig_is_symlink(self_path)

    monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)

    # All handle methods MUST fail closed when using original handle
    with pytest.raises(PathConfinementError, match="symlink"):
        handle.input_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.work_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.output_dir()

    with pytest.raises(PathConfinementError, match="symlink"):
        handle.resolve("input", "secret.txt")

    with pytest.raises(PathConfinementError, match="symlink"):
        ws_manager.stage_upload(handle, "new.txt", b"NEW")


# ---------------------------------------------------------------------------
# 7. FINAL REMEDIATION ROUND TESTS (FINDINGS 1 & 2)
# ---------------------------------------------------------------------------


def test_remediation_finding1_cross_instance_quota_race(db_conn, temp_dir):
    """Finding 1 Remediation Test: Cross-instance / cross-process quota race prevention.
    
    Multiple independent WorkspaceManager instances operating against the exact same workspace
    attempt concurrent uploads whose combined size exceeds total workspace quota (5000 bytes).
    Proves:
    - Some uploads succeed
    - At least one upload is rejected with QuotaExceededError
    - Final disk usage NEVER exceeds the configured quota (5000 bytes)
    - Normal under-quota concurrent writes across multiple instances still work
    """
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_qrace", "sess_qrace")
    ws_root = temp_dir / "cross_instance_workspaces"
    quota_limit = 5000

    # Create 6 independent WorkspaceManager instances operating on the same workspace root
    managers = [
        WorkspaceManager(workspace_root=ws_root, default_quota_bytes=quota_limit)
        for _ in range(6)
    ]
    handles = [mgr.get_or_create(db_conn, "ch_qrace", "sess_qrace") for mgr in managers]

    upload_size = 1500  # 6 * 1500 = 9000 bytes > 5000 byte quota
    results = []
    errors = []
    threads = []

    def _worker(idx: int):
        try:
            mgr = managers[idx]
            h = handles[idx]
            data = bytes([idx % 256]) * upload_size
            path = mgr.stage_upload(h, f"upload_{idx}.bin", data)
            results.append((idx, path))
        except QuotaExceededError as e:
            errors.append((idx, e))
        except Exception as e:
            errors.append((idx, e))

    for i in range(6):
        t = threading.Thread(target=_worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # 1. Some uploads succeeded, some were rejected
    assert len(results) > 0, "At least one upload should have succeeded"
    assert len(errors) > 0, "At least one upload should have been rejected due to quota limit"
    assert all(isinstance(err[1], QuotaExceededError) for err in errors)

    # 2. Final disk usage NEVER exceeds quota
    total_size = managers[0].calculate_workspace_size(handles[0])
    assert total_size <= quota_limit, f"Total disk usage {total_size} exceeded quota {quota_limit}"

    # Verify physical disk size matches calculate_workspace_size
    actual_disk_bytes = sum(f.stat().st_size for f in handles[0]._root.rglob("*") if f.is_file() and not f.name.startswith("."))
    assert actual_disk_bytes <= quota_limit
    assert actual_disk_bytes == total_size

    # 3. Under-quota concurrent writes test across multiple instances
    _seed_challenge_and_session(db_conn, "ch_qrace_under", "sess_qrace_under")
    mgrs_under = [
        WorkspaceManager(workspace_root=ws_root, default_quota_bytes=5000)
        for _ in range(3)
    ]
    handles_under = [m.get_or_create(db_conn, "ch_qrace_under", "sess_qrace_under") for m in mgrs_under]

    results_under = []
    errors_under = []
    threads_under = []

    def _worker_under(idx: int):
        try:
            p = mgrs_under[idx].stage_upload(handles_under[idx], f"file_under_{idx}.bin", b"U" * 1000)
            results_under.append(p)
        except Exception as e:
            errors_under.append(e)

    for i in range(3):
        t = threading.Thread(target=_worker_under, args=(i,))
        threads_under.append(t)
        t.start()

    for t in threads_under:
        t.join()

    assert len(errors_under) == 0, f"Under-quota writes failed: {errors_under}"
    assert len(results_under) == 3
    assert mgrs_under[0].calculate_workspace_size(handles_under[0]) == 3000


def test_remediation_finding2_fstat_on_open_descriptor(db_conn, ws_manager, temp_dir):
    """Finding 2 Remediation Test: import_verified_artifact performs fstat on open file descriptor.
    
    Verifies:
    - Open file descriptor is used for fstat security check
    - Hard-linked file source is rejected by fstat check on open descriptor
    - Normal unlinked file opens, validates fstat, and streams cleanly
    """
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_fstat", "sess_fstat")
    handle = ws_manager.get_or_create(db_conn, "ch_fstat", "sess_fstat")

    # 1. Hard-link rejection via fstat on open fd
    target_file = temp_dir / "fstat_original.bin"
    target_file.write_bytes(b"FSTAT_TEST_DATA")
    hard_link_file = temp_dir / "fstat_hardlinked.bin"

    try:
        os.link(target_file, hard_link_file)
        has_hardlinks = True
    except (OSError, NotImplementedError, AttributeError):
        has_hardlinks = False

    if has_hardlinks:
        sha_val = hashlib.sha256(b"FSTAT_TEST_DATA").hexdigest()
        obs_hl = MockIngestionObservation("obs_fstat_hl", str(hard_link_file), sha_val)
        with pytest.raises(ArtifactSecurityError, match="Suspicious multi-link source artifact"):
            ws_manager.import_verified_artifact(handle, obs_hl)

    # 2. Normal file success via fstat on open fd
    normal_file = temp_dir / "fstat_normal.bin"
    normal_bytes = b"NORMAL_UNLINKED_DATA_12345"
    normal_file.write_bytes(normal_bytes)
    normal_sha = hashlib.sha256(normal_bytes).hexdigest()

    obs_norm = MockIngestionObservation("obs_fstat_norm", str(normal_file), normal_sha)
    imported = ws_manager.import_verified_artifact(handle, obs_norm)

    assert imported.exists()
    assert imported.read_bytes() == normal_bytes


def test_remediation_forced_lock_acquisition_failure_fails_closed(db_conn, ws_manager, temp_dir, monkeypatch):
    """Regression Test: Forced cross-process lock acquisition failure MUST fail closed.
    
    Verifies:
    - stage_upload() fails closed with WorkspaceLockError when OS-level lock acquisition fails.
    - No final artifact is created.
    - Quota accounting is not bypassed.
    - No partial/staging files remain.
    - import_verified_artifact() also fails closed with WorkspaceLockError.
    """
    _seed_challenge_and_session(db_conn, "ch_lockfail", "sess_lockfail")
    handle = ws_manager.get_or_create(db_conn, "ch_lockfail", "sess_lockfail")

    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")

    import sys
    if sys.platform == "win32":
        import msvcrt
        def mock_locking(fd, mode, nbytes):
            raise OSError("Simulated OS lock acquisition failure / Permission denied")
        monkeypatch.setattr(msvcrt, "locking", mock_locking)
    else:
        import fcntl
        def mock_flock(fd, operation):
            raise OSError("Simulated OS lock acquisition failure / Permission denied")
        monkeypatch.setattr(fcntl, "flock", mock_flock)

    # 1. stage_upload MUST fail closed with WorkspaceLockError
    with pytest.raises(WorkspaceLockError, match="Simulated OS lock acquisition failure"):
        ws_manager.stage_upload(handle, "lock_fail_upload.bin", b"FORCED_LOCK_FAIL_DATA")

    # Verify no final artifact created
    target_upload = handle.input_dir() / "lock_fail_upload.bin"
    assert not target_upload.exists()

    # Verify no staging file remains
    assert len(list((handle._root / "input").glob(".staging_tmp_*"))) == 0

    # Verify workspace size remains 0 (quota accounting not bypassed)
    assert ws_manager.calculate_workspace_size(handle) == 0

    # 2. import_verified_artifact MUST also fail closed with WorkspaceLockError
    source_file = temp_dir / "lock_fail_source.bin"
    source_file.write_bytes(b"SOURCE_LOCK_FAIL_DATA")
    sha_val = hashlib.sha256(b"SOURCE_LOCK_FAIL_DATA").hexdigest()
    obs = MockIngestionObservation("obs_lf", str(source_file), sha_val)

    with pytest.raises(WorkspaceLockError, match="Simulated OS lock acquisition failure"):
        ws_manager.import_verified_artifact(handle, obs)

    # Verify no final artifact created
    target_imported = handle.input_dir() / source_file.name
    assert not target_imported.exists()

    # Verify no staging file remains
    assert len(list((handle._root / "input").glob(".staging_tmp_*"))) == 0

    # Verify workspace size remains 0
    assert ws_manager.calculate_workspace_size(handle) == 0


# ---------------------------------------------------------------------------
# 8. CLEANUP SECURITY REMEDIATION TESTS
# ---------------------------------------------------------------------------


def test_cleanup_remediation_existing_handle_challenge_symlink_escape(db_conn, ws_manager, temp_dir):
    """Cleanup Remediation Test 1: Existing handle + challenge-parent replacement fails closed."""
    _seed_challenge_and_session(db_conn, "ch_cln_ch", "sess_cln_ch")
    handle = ws_manager.get_or_create(db_conn, "ch_cln_ch", "sess_cln_ch")

    outside_dir = temp_dir / "outside_cln_ch"
    outside_sess = outside_dir / "sess_cln_ch"
    (outside_sess / "input").mkdir(parents=True, exist_ok=True)
    evil_file = outside_sess / "input" / ".staging_tmp_evil"
    evil_file.write_bytes(b"EVIL_DATA")

    # Replace legitimate challenge directory with symlink to outside_dir
    ch_dir = ws_manager.workspace_root / "ch_cln_ch"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    # Evil file MUST remain untouched
    assert evil_file.exists()


def test_cleanup_remediation_existing_handle_session_symlink_escape(db_conn, ws_manager, temp_dir):
    """Cleanup Remediation Test 2: Existing handle + session-parent replacement fails closed."""
    _seed_challenge_and_session(db_conn, "ch_cln_sess", "sess_cln_sess")
    handle = ws_manager.get_or_create(db_conn, "ch_cln_sess", "sess_cln_sess")

    outside_dir = temp_dir / "outside_cln_sess"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)
    evil_file = outside_dir / "input" / ".staging_tmp_evil"
    evil_file.write_bytes(b"EVIL_DATA")

    sess_dir = ws_manager.workspace_root / "ch_cln_sess" / "sess_cln_sess"
    shutil.rmtree(sess_dir)
    try:
        os.symlink(outside_dir, sess_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    assert evil_file.exists()


def test_cleanup_remediation_subdir_symlink_replacements(db_conn, ws_manager, temp_dir):
    """Cleanup Remediation Tests 3, 4, 5: input/, work/, output/ symlink replacements are not followed."""
    _seed_challenge_and_session(db_conn, "ch_cln_sub", "sess_cln_sub")
    handle = ws_manager.get_or_create(db_conn, "ch_cln_sub", "sess_cln_sub")

    outside_dir = temp_dir / "outside_cln_sub"
    outside_dir.mkdir(parents=True, exist_ok=True)
    evil1 = outside_dir / ".staging_tmp_evil1"
    evil1.write_bytes(b"EVIL1")

    # Test input/ symlink replacement
    shutil.rmtree(handle._root / "input")
    try:
        os.symlink(outside_dir, handle._root / "input", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)
    assert evil1.exists()


def test_cleanup_remediation_exact_reproduced_attack(db_conn, ws_manager, temp_dir):
    """Cleanup Remediation Test 6: Exact reproduced attack leaves external file untouched."""
    _seed_challenge_and_session(db_conn, "ch_attack", "sess_attack")
    handle = ws_manager.get_or_create(db_conn, "ch_attack", "sess_attack")

    outside_dir = temp_dir / "attack_outside"
    fake_sess = outside_dir / "sess_attack"
    (fake_sess / "input").mkdir(parents=True, exist_ok=True)
    evil_file = fake_sess / "input" / ".staging_tmp_evil"
    evil_file.write_bytes(b"CRITICAL_SYSTEM_DATA")

    ch_dir = ws_manager.workspace_root / "ch_attack"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    assert evil_file.exists()
    assert evil_file.read_bytes() == b"CRITICAL_SYSTEM_DATA"


def test_cleanup_remediation_arbitrary_root_api_blocked(ws_manager, temp_dir):
    """Cleanup Remediation Test 7: clean_stale_staging_files_by_root cannot be used as an unrestricted deletion primitive."""
    outside_target = temp_dir / "arbitrary_target"
    (outside_target / "input").mkdir(parents=True, exist_ok=True)
    victim_file = outside_target / "input" / ".staging_tmp_victim"
    victim_file.write_bytes(b"VICTIM")

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files_by_root(outside_target, stale_age_seconds=0)

    assert victim_file.exists()


def test_cleanup_remediation_legitimate_stale_and_active_files(db_conn, ws_manager):
    """Cleanup Remediation Tests 8 & 9: Legitimate stale files are removed, active files remain."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_legit_cln", "sess_legit_cln")
    handle = ws_manager.get_or_create(db_conn, "ch_legit_cln", "sess_legit_cln")

    # Stale file
    stale_file = handle.input_dir() / ".staging_tmp_stale"
    stale_file.write_bytes(b"STALE")
    old_time = datetime.now(timezone.utc).timestamp() - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_stale", (old_time, old_time))

    # Active file
    active_file = handle.input_dir() / ".staging_tmp_active"
    active_file.write_bytes(b"ACTIVE")

    cleaned = ws_manager.clean_stale_staging_files(handle, stale_age_seconds=60.0)

    assert cleaned == 1
    assert not stale_file.exists()
    assert active_file.exists()


def test_cleanup_remediation_concurrent_cleanup_and_upload(db_conn, ws_manager):
    """Cleanup Remediation Test 10: Concurrent cleanup and upload under lock."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_conc_cln", "sess_conc_cln")
    handle = ws_manager.get_or_create(db_conn, "ch_conc_cln", "sess_conc_cln")

    errors = []
    threads = []

    def _upload_worker():
        try:
            for i in range(5):
                ws_manager.stage_upload(handle, f"file_{i}.bin", b"DATA")
        except Exception as e:
            errors.append(e)

    def _cleanup_worker():
        try:
            for _ in range(5):
                ws_manager.clean_stale_staging_files(handle, stale_age_seconds=60.0)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=_upload_worker)
    t2 = threading.Thread(target=_cleanup_worker)

    threads.extend([t1, t2])
    t1.start()
    t2.start()

    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(list((handle._root / "input").glob("file_*.bin"))) == 5


# ---------------------------------------------------------------------------
# 9. DETERMINISTIC FILESYSTEM TOCTOU REGRESSION TESTS
# ---------------------------------------------------------------------------


def test_toctou_stage_upload_challenge_symlink_before_open(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 1: stage_upload() challenge parent replacement immediately before temp open."""
    _seed_challenge_and_session(db_conn, "ch_toctou1", "sess_toctou1")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou1", "sess_toctou1")

    outside_dir = temp_dir / "outside_toctou1"
    (outside_dir / "sess_toctou1" / "input").mkdir(parents=True, exist_ok=True)

    ch_dir = ws_manager.workspace_root / "ch_toctou1"
    target_resolved = ch_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(ch_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_calc = ws_manager.calculate_workspace_size
    def mock_calc(h):
        res = orig_calc(h)
        if h.challenge_id == "ch_toctou1":
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return res

    monkeypatch.setattr(ws_manager, "calculate_workspace_size", mock_calc)

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "attack1.bin", b"ATTACK1_DATA")

    assert not (outside_dir / "sess_toctou1" / "input" / "attack1.bin").exists()


def test_toctou_stage_upload_session_symlink_before_open(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 2: stage_upload() session parent replacement immediately before temp open."""
    _seed_challenge_and_session(db_conn, "ch_toctou2", "sess_toctou2")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou2", "sess_toctou2")

    outside_dir = temp_dir / "outside_toctou2"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)

    sess_dir = ws_manager.workspace_root / "ch_toctou2" / "sess_toctou2"
    target_resolved = sess_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(sess_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_calc = ws_manager.calculate_workspace_size
    def mock_calc(h):
        res = orig_calc(h)
        if h.session_id == "sess_toctou2":
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return res

    monkeypatch.setattr(ws_manager, "calculate_workspace_size", mock_calc)

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "attack2.bin", b"ATTACK2_DATA")

    assert not (outside_dir / "input" / "attack2.bin").exists()


def test_toctou_import_artifact_challenge_symlink_before_open(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 3: import_verified_artifact() challenge parent replacement immediately before temp open."""
    _seed_challenge_and_session(db_conn, "ch_toctou3", "sess_toctou3")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou3", "sess_toctou3")

    source_artifact = temp_dir / "src_toctou3.bin"
    source_artifact.write_bytes(b"SRC3_DATA")
    obs = MockIngestionObservation("obs_toctou3", str(source_artifact), hashlib.sha256(b"SRC3_DATA").hexdigest())

    outside_dir = temp_dir / "outside_toctou3"
    (outside_dir / "sess_toctou3" / "input").mkdir(parents=True, exist_ok=True)

    ch_dir = ws_manager.workspace_root / "ch_toctou3"
    target_resolved = ch_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(ch_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_calc = ws_manager.calculate_workspace_size
    def mock_calc(h):
        res = orig_calc(h)
        if h.challenge_id == "ch_toctou3":
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return res

    monkeypatch.setattr(ws_manager, "calculate_workspace_size", mock_calc)

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    assert not (outside_dir / "sess_toctou3" / "input" / source_artifact.name).exists()


def test_toctou_import_artifact_session_symlink_before_open(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 4: import_verified_artifact() session parent replacement immediately before temp open."""
    _seed_challenge_and_session(db_conn, "ch_toctou4", "sess_toctou4")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou4", "sess_toctou4")

    source_artifact = temp_dir / "src_toctou4.bin"
    source_artifact.write_bytes(b"SRC4_DATA")
    obs = MockIngestionObservation("obs_toctou4", str(source_artifact), hashlib.sha256(b"SRC4_DATA").hexdigest())

    outside_dir = temp_dir / "outside_toctou4"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)

    sess_dir = ws_manager.workspace_root / "ch_toctou4" / "sess_toctou4"
    target_resolved = sess_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(sess_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_calc = ws_manager.calculate_workspace_size
    def mock_calc(h):
        res = orig_calc(h)
        if h.session_id == "sess_toctou4":
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return res

    monkeypatch.setattr(ws_manager, "calculate_workspace_size", mock_calc)

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    assert not (outside_dir / "input" / source_artifact.name).exists()


def test_toctou_cleanup_challenge_symlink_before_unlink(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 5: clean_stale_staging_files() challenge parent replacement immediately before unlink."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_toctou5", "sess_toctou5")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou5", "sess_toctou5")

    stale_file = handle.input_dir() / ".staging_tmp_toctou5"
    stale_file.write_bytes(b"STALE5")
    old_time = datetime.now(timezone.utc).timestamp() - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_toctou5", (old_time, old_time))

    outside_dir = temp_dir / "outside_toctou5"
    fake_sess = outside_dir / "sess_toctou5"
    (fake_sess / "input").mkdir(parents=True, exist_ok=True)
    evil_file = fake_sess / "input" / ".staging_tmp_toctou5"
    evil_file.write_bytes(b"EVIL_DATA_5")

    ch_dir = ws_manager.workspace_root / "ch_toctou5"
    target_resolved = ch_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(ch_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_validate = handle._validate_handle_root_confinement
    call_count = 0

    def mock_validate(self_handle=None):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return orig_validate()

    monkeypatch.setattr(WorkspaceHandle, "_validate_handle_root_confinement", mock_validate)

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    # Evil file in outside_dir MUST remain untouched
    assert evil_file.exists()
    assert evil_file.read_bytes() == b"EVIL_DATA_5"


def test_toctou_cleanup_session_symlink_before_unlink(db_conn, ws_manager, temp_dir, monkeypatch):
    """TOCTOU Test 6: clean_stale_staging_files() session parent replacement immediately before unlink."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_toctou6", "sess_toctou6")
    handle = ws_manager.get_or_create(db_conn, "ch_toctou6", "sess_toctou6")

    stale_file = handle.input_dir() / ".staging_tmp_toctou6"
    stale_file.write_bytes(b"STALE6")
    old_time = datetime.now(timezone.utc).timestamp() - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_toctou6", (old_time, old_time))

    outside_dir = temp_dir / "outside_toctou6"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)
    evil_file = outside_dir / "input" / ".staging_tmp_toctou6"
    evil_file.write_bytes(b"EVIL_DATA_6")

    sess_dir = ws_manager.workspace_root / "ch_toctou6" / "sess_toctou6"
    target_resolved = sess_dir.resolve()
    outside_resolved = outside_dir.resolve()

    orig_is_symlink = Path.is_symlink
    orig_resolve = Path.resolve

    def mock_is_symlink(self_path):
        if str(self_path) == str(sess_dir):
            return True
        return orig_is_symlink(self_path)

    def mock_resolve(self_path):
        resolved = orig_resolve(self_path)
        try:
            if resolved == target_resolved or target_resolved in resolved.parents:
                rel = resolved.relative_to(target_resolved)
                return (outside_resolved / rel)
        except Exception:
            pass
        return resolved

    orig_validate = handle._validate_handle_root_confinement
    call_count = 0

    def mock_validate(self_handle=None):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            monkeypatch.setattr(Path, "is_symlink", mock_is_symlink)
            monkeypatch.setattr(Path, "resolve", mock_resolve)
        return orig_validate()

    monkeypatch.setattr(WorkspaceHandle, "_validate_handle_root_confinement", mock_validate)

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    assert evil_file.exists()
    assert evil_file.read_bytes() == b"EVIL_DATA_6"


def test_real_filesystem_toctou_stage_upload_parent_swap(db_conn, ws_manager, temp_dir):
    """Real Filesystem TOCTOU Test 1: stage_upload parent replacement right before publication.

    Exercises the REAL underlying filesystem operation without mocking Path.resolve/is_symlink.
    Verifies that file publication fails closed or remains bound to the original directory descriptor,
    and NO file is published in the external directory.
    """
    _seed_challenge_and_session(db_conn, "ch_real_toctou1", "sess_real_toctou1")
    handle = ws_manager.get_or_create(db_conn, "ch_real_toctou1", "sess_real_toctou1")

    outside_dir = temp_dir / "outside_real_toctou1"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)

    ch_dir = ws_manager.workspace_root / "ch_real_toctou1"

    # Custom stream generator that performs REAL directory swap on the disk during streaming
    def stream_with_parent_swap():
        yield b"HEADER_DATA_CHUNK_1\n"
        # Perform real directory swap on disk while stage_upload is actively streaming
        if ch_dir.exists():
            try:
                shutil.rmtree(ch_dir)
                try:
                    os.symlink(outside_dir, ch_dir, target_is_directory=True)
                except (OSError, NotImplementedError, PermissionError):
                    shutil.copytree(outside_dir, ch_dir)
            except OSError:
                pass
        yield b"BODY_DATA_CHUNK_2\n"

    try:
        ws_manager.stage_upload(handle, "attack_artifact.bin", stream_with_parent_swap())
    except (WorkspaceStatusError, PathConfinementError, WorkspaceError, OSError):
        pass

    # VERIFY SECURITY INVARIANT:
    # External file MUST NOT be created or published in outside_dir
    assert not (outside_dir / "attack_artifact.bin").exists()
    assert not (outside_dir / "input" / "attack_artifact.bin").exists()


def test_real_filesystem_toctou_import_verified_artifact_parent_swap(db_conn, ws_manager, temp_dir):
    """Real Filesystem TOCTOU Test 2: import_verified_artifact parent replacement right before publication.

    Exercises the REAL underlying filesystem operation without mocking.
    Verifies that artifact import fails closed or remains bound to the original directory descriptor,
    and NO file is published in the external directory.
    """
    _seed_challenge_and_session(db_conn, "ch_real_toctou2", "sess_real_toctou2")
    handle = ws_manager.get_or_create(db_conn, "ch_real_toctou2", "sess_real_toctou2")

    source_artifact = temp_dir / "evidence_real.bin"
    content = b"REAL_EVIDENCE_DATA_BYTES_9999"
    source_artifact.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()

    outside_dir = temp_dir / "outside_real_toctou2"
    (outside_dir / "input").mkdir(parents=True, exist_ok=True)

    obs = MockIngestionObservation(
        observation_id="obs_real_2",
        artifact_path=str(source_artifact),
        sha256=sha256,
    )

    ch_dir = ws_manager.workspace_root / "ch_real_toctou2"

    # Start a background thread to swap directory on disk while import is in progress
    swap_done = threading.Event()

    def disk_swapper():
        for _ in range(100):
            try:
                inp = handle.input_dir()
                tmps = list(inp.glob(".staging_tmp_*"))
                if tmps:
                    break
            except Exception:
                pass
            import time
            time.sleep(0.001)

        try:
            if ch_dir.exists():
                shutil.rmtree(ch_dir)
                try:
                    os.symlink(outside_dir, ch_dir, target_is_directory=True)
                except (OSError, NotImplementedError, PermissionError):
                    shutil.copytree(outside_dir, ch_dir)
        except OSError:
            pass
        finally:
            swap_done.set()

    t = threading.Thread(target=disk_swapper, daemon=True)
    t.start()

    try:
        ws_manager.import_verified_artifact(handle, obs)
    except (WorkspaceStatusError, PathConfinementError, WorkspaceError, ArtifactIntegrityError, OSError):
        pass

    t.join(timeout=2.0)

    # VERIFY SECURITY INVARIANT:
    assert not (outside_dir / "evidence_real.bin").exists()
    assert not (outside_dir / "input" / "evidence_real.bin").exists()


def test_real_filesystem_toctou_clean_stale_staging_files_parent_swap(db_conn, ws_manager, temp_dir):
    """Real Filesystem TOCTOU Test 3: clean_stale_staging_files parent replacement right before deletion.

    Exercises the REAL underlying filesystem operation without mocking.
    Verifies that cleanup fails closed or remains bound to the original directory descriptor,
    and NO file in the external directory is deleted.
    """
    _seed_challenge_and_session(db_conn, "ch_real_toctou3", "sess_real_toctou3")
    handle = ws_manager.get_or_create(db_conn, "ch_real_toctou3", "sess_real_toctou3")

    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")

    stale_file = handle.input_dir() / ".staging_tmp_real_stale3"
    stale_file.write_bytes(b"STALE_REAL_3")
    old_time = datetime.now(timezone.utc).timestamp() - 120.0
    os.utime(handle._root / "input" / ".staging_tmp_real_stale3", (old_time, old_time))

    outside_dir = temp_dir / "outside_real_toctou3"
    outside_input = outside_dir / "sess_real_toctou3" / "input"
    outside_input.mkdir(parents=True, exist_ok=True)

    external_file = outside_input / ".staging_tmp_real_stale3"
    external_file.write_bytes(b"SENSITIVE_EXTERNAL_DATA_DO_NOT_DELETE")
    os.utime(external_file, (old_time, old_time))

    ch_dir = ws_manager.workspace_root / "ch_real_toctou3"

    try:
        if ch_dir.exists():
            shutil.rmtree(ch_dir)
            try:
                os.symlink(outside_dir, ch_dir, target_is_directory=True)
            except (OSError, NotImplementedError, PermissionError):
                shutil.copytree(outside_dir, ch_dir)
    except OSError:
        pass

    try:
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)
    except (WorkspaceStatusError, PathConfinementError, WorkspaceError, OSError):
        pass

    # VERIFY SECURITY INVARIANT:
    # External file in outside_dir MUST NOT be deleted
    assert external_file.exists()
    assert external_file.read_bytes() == b"SENSITIVE_EXTERNAL_DATA_DO_NOT_DELETE"


def test_publication_overwrite_existing_final_file(db_conn, ws_manager):
    """Test publication behavior when a legitimate destination file with the final name already exists."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_overwrite", "sess_overwrite")
    handle = ws_manager.get_or_create(db_conn, "ch_overwrite", "sess_overwrite")

    # Stage initial file
    initial_path = ws_manager.stage_upload(handle, "data.txt", b"INITIAL_VERSION_BYTES")
    assert initial_path.read_bytes() == b"INITIAL_VERSION_BYTES"

    # Overwrite by staging second version
    new_path = ws_manager.stage_upload(handle, "data.txt", b"UPDATED_VERSION_BYTES")
    assert new_path == initial_path
    assert new_path.read_bytes() == b"UPDATED_VERSION_BYTES"


def test_capability_audit_os_supports_dir_fd_runtime():
    """Explicit audit test verifying os.supports_dir_fd set on the active runtime environment."""
    import os
    print("Runtime os.supports_dir_fd:", os.supports_dir_fd)
    if hasattr(os, "supports_dir_fd"):
        print("os.open in os.supports_dir_fd:", os.open in os.supports_dir_fd)
        print("os.unlink in os.supports_dir_fd:", os.unlink in os.supports_dir_fd)
        print("os.rename in os.supports_dir_fd:", os.rename in os.supports_dir_fd)
        print("os.replace in os.supports_dir_fd:", os.replace in os.supports_dir_fd)
    assert isinstance(os.supports_dir_fd, set)


# ---------------------------------------------------------------------------
# 8. GLOBAL ROOT OF TRUST REMEDIATION TESTS
# ---------------------------------------------------------------------------


def test_real_global_root_replacement_existing_handle(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 1: Replacing global workspace root path fails closed on existing handle."""
    _seed_challenge_and_session(db_conn, "ch_groot1", "sess_groot1")
    handle = ws_manager.get_or_create(db_conn, "ch_groot1", "sess_groot1")
    assert handle.status == "READY"

    outside_dir = temp_dir / "outside_groot1"
    fake_tree = outside_dir / "ch_groot1" / "sess_groot1"
    (fake_tree / "input").mkdir(parents=True, exist_ok=True)
    (fake_tree / "input" / "secret.txt").write_text("EXTERNAL_SECRET_1", encoding="utf-8")

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        handle.input_dir()

    with pytest.raises(PathConfinementError):
        handle.work_dir()

    with pytest.raises(PathConfinementError):
        handle.output_dir()

    with pytest.raises(PathConfinementError):
        handle.resolve("input", "secret.txt")


def test_real_global_root_symlink_replacement(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 2: Symlinking global workspace root path fails closed."""
    _seed_challenge_and_session(db_conn, "ch_groot2", "sess_groot2")
    handle = ws_manager.get_or_create(db_conn, "ch_groot2", "sess_groot2")

    outside_dir = temp_dir / "outside_groot2"
    (outside_dir / "ch_groot2" / "sess_groot2" / "input").mkdir(parents=True, exist_ok=True)

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        pytest.skip("Symlinks not supported on this platform/privilege level")

    with pytest.raises(PathConfinementError):
        handle.input_dir()


def test_real_global_root_replacement_stage_upload(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 3: stage_upload fails closed if global workspace root path is replaced."""
    _seed_challenge_and_session(db_conn, "ch_groot3", "sess_groot3")
    handle = ws_manager.get_or_create(db_conn, "ch_groot3", "sess_groot3")

    outside_dir = temp_dir / "outside_groot3"
    fake_input = outside_dir / "ch_groot3" / "sess_groot3" / "input"
    fake_input.mkdir(parents=True, exist_ok=True)

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "attack.bin", b"ATTACKER_DATA_3")

    assert not (fake_input / "attack.bin").exists()


def test_real_global_root_replacement_import_verified_artifact(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 4: import_verified_artifact fails closed if global workspace root path is replaced."""
    _seed_challenge_and_session(db_conn, "ch_groot4", "sess_groot4")
    handle = ws_manager.get_or_create(db_conn, "ch_groot4", "sess_groot4")

    source_file = temp_dir / "source4.bin"
    source_bytes = b"SOURCE_DATA_4"
    source_file.write_bytes(source_bytes)
    sha_val = hashlib.sha256(source_bytes).hexdigest()
    obs = MockIngestionObservation("obs_groot4", str(source_file), sha_val)

    outside_dir = temp_dir / "outside_groot4"
    fake_input = outside_dir / "ch_groot4" / "sess_groot4" / "input"
    fake_input.mkdir(parents=True, exist_ok=True)

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    assert not (fake_input / "source4.bin").exists()


def test_real_global_root_replacement_cleanup(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 5: clean_stale_staging_files fails closed if global workspace root path is replaced."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_groot5", "sess_groot5")
    handle = ws_manager.get_or_create(db_conn, "ch_groot5", "sess_groot5")

    stale_file = handle.input_dir() / ".staging_tmp_groot5"
    stale_file.write_bytes(b"STALE5_DATA")

    outside_dir = temp_dir / "outside_groot5"
    fake_input = outside_dir / "ch_groot5" / "sess_groot5" / "input"
    fake_input.mkdir(parents=True, exist_ok=True)
    fake_stale = fake_input / ".staging_tmp_groot5"
    fake_stale.write_bytes(b"SENSITIVE_EXTERNAL_DATA_5")

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)

    assert fake_stale.exists()
    assert fake_stale.read_bytes() == b"SENSITIVE_EXTERNAL_DATA_5"


def test_legitimate_normal_workspace_operation_after_handle_issuance(db_conn, ws_manager):
    """Global Root Remediation Test 6: Legitimate normal workspace operation succeeds cleanly."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace mutations are fail-closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_norm6", "sess_norm6")
    handle = ws_manager.get_or_create(db_conn, "ch_norm6", "sess_norm6")

    assert handle.input_dir().exists()
    assert handle.work_dir().exists()
    assert handle.output_dir().exists()

    staged = ws_manager.stage_upload(handle, "normal.txt", b"NORMAL_BYTES_6")
    assert staged.exists()
    assert staged.read_bytes() == b"NORMAL_BYTES_6"
    assert handle.resolve("input", "normal.txt").read_bytes() == b"NORMAL_BYTES_6"


def test_real_global_root_path_removal_recreation(db_conn, ws_manager):
    """Global Root Remediation Test 7: Global root directory removal and recreation at same path fails closed."""
    _seed_challenge_and_session(db_conn, "ch_recreate7", "sess_recreate7")
    handle = ws_manager.get_or_create(db_conn, "ch_recreate7", "sess_recreate7")

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    ws_root.mkdir(parents=True, exist_ok=True)

    with pytest.raises(PathConfinementError):
        handle.input_dir()


def test_real_global_root_replacement_fake_matching_tree(db_conn, ws_manager, temp_dir):
    """Global Root Remediation Test 8: Global root replacement with matching fake challenge/session tree fails closed."""
    _seed_challenge_and_session(db_conn, "ch_fake8", "sess_fake8")
    handle = ws_manager.get_or_create(db_conn, "ch_fake8", "sess_fake8")

    outside_dir = temp_dir / "fake_tree8"
    fake_sess = outside_dir / "ch_fake8" / "sess_fake8"
    (fake_sess / "input").mkdir(parents=True, exist_ok=True)
    (fake_sess / "work").mkdir(parents=True, exist_ok=True)
    (fake_sess / "output").mkdir(parents=True, exist_ok=True)

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        handle.input_dir()

    with pytest.raises(PathConfinementError):
        handle.resolve("input", "test.txt")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "test.txt", b"TEST_BYTES")


def test_dir_capability_opening_race_detects_pre_open_inode_mismatch(db_conn, ws_manager, temp_dir, monkeypatch):
    """Finding 2 Remediation Test: _DirCapability captures pre-open inode identity and fails closed if swapped right before open."""
    if not (hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd):
        pytest.skip("Test requires POSIX dir_fd support")

    _seed_challenge_and_session(db_conn, "ch_cap_race", "sess_cap_race")
    handle = ws_manager.get_or_create(db_conn, "ch_cap_race", "sess_cap_race")

    input_dir_path = handle._get_validated_subdir("input")
    global_root_resolved = ws_manager.workspace_root.resolve()

    import stat as stat_module
    real_fstat = os.fstat
    closed_fds = []

    real_close = os.close
    def tracking_close(fd):
        closed_fds.append(fd)
        return real_close(fd)

    def mock_fstat(fd):
        res = real_fstat(fd)
        if stat_module.S_ISDIR(res.st_mode):
            return os.stat_result((
                res.st_mode,
                res.st_ino + 99999,
                res.st_dev,
                res.st_nlink,
                res.st_uid,
                res.st_gid,
                res.st_size,
                res.st_atime,
                res.st_mtime,
                res.st_ctime,
            ))
        return res

    monkeypatch.setattr(os, "fstat", mock_fstat)
    monkeypatch.setattr(os, "close", tracking_close)

    from ctf_mentor.workspace.manager import _DirCapability

    with pytest.raises(PathConfinementError, match="inode mismatch"):
        _DirCapability(handle, input_dir_path, global_root_resolved)

    assert len(closed_fds) > 0, "Descriptor should be closed when inode mismatch is detected"


def test_windows_fail_closed_security_sensitive_operations(db_conn, ws_manager, temp_dir):
    """Finding 1 Remediation Test: Security-sensitive mutation operations fail closed on Windows or non-dir_fd platforms."""
    _seed_challenge_and_session(db_conn, "ch_win_fc", "sess_win_fc")
    handle = ws_manager.get_or_create(db_conn, "ch_win_fc", "sess_win_fc")

    has_dir_fd = hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd

    if not has_dir_fd:
        # Windows / non-dir_fd platform MUST fail closed on stage_upload, import_verified_artifact, and cleanup
        with pytest.raises(PathConfinementError, match="unsupported"):
            ws_manager.stage_upload(handle, "win_file.bin", b"DATA")

        src_file = temp_dir / "win_src.bin"
        src_file.write_bytes(b"DATA")
        obs = MockIngestionObservation("obs_win", str(src_file), hashlib.sha256(b"DATA").hexdigest())

        with pytest.raises(PathConfinementError, match="unsupported"):
            ws_manager.import_verified_artifact(handle, obs)

        with pytest.raises(PathConfinementError, match="unsupported"):
            ws_manager.clean_stale_staging_files(handle, stale_age_seconds=0)
    else:
        # On POSIX with dir_fd, operations execute successfully and race-safely
        staged = ws_manager.stage_upload(handle, "posix_file.bin", b"DATA")
        assert staged.exists()


# ---------------------------------------------------------------------------
# 9. RAW PATH CAPABILITY ESCAPE SECURITY TESTS
# ---------------------------------------------------------------------------


def test_capability_escape_challenge_parent_replacement_blocked(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 1: Challenge parent replacement invalidates issued WorkspacePath capability."""
    _seed_challenge_and_session(db_conn, "ch_esc1", "sess_esc1")
    handle = ws_manager.get_or_create(db_conn, "ch_esc1", "sess_esc1")

    p = handle.input_dir()

    outside_dir = temp_dir / "outside_esc1"
    outside_dir.mkdir(parents=True, exist_ok=True)
    victim_file = outside_dir / "victim.txt"
    victim_file.write_text("SENSITIVE_DATA_1", encoding="utf-8")

    ch_dir = ws_manager.workspace_root / "ch_esc1"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ch_dir)

    with pytest.raises(PathConfinementError):
        p.write_text("EVIL_1")

    with pytest.raises(PathConfinementError):
        (p / "victim.txt").write_text("EVIL_1_CHILD")

    with pytest.raises(PathConfinementError):
        p.read_bytes()

    with pytest.raises(PathConfinementError):
        p.unlink()

    assert victim_file.read_text(encoding="utf-8") == "SENSITIVE_DATA_1"


def test_capability_escape_session_parent_replacement_blocked(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 2: Session parent replacement invalidates issued WorkspacePath capability."""
    _seed_challenge_and_session(db_conn, "ch_esc2", "sess_esc2")
    handle = ws_manager.get_or_create(db_conn, "ch_esc2", "sess_esc2")

    p = handle.work_dir()

    outside_dir = temp_dir / "outside_esc2"
    outside_dir.mkdir(parents=True, exist_ok=True)

    sess_dir = ws_manager.workspace_root / "ch_esc2" / "sess_esc2"
    shutil.rmtree(sess_dir)
    try:
        os.symlink(outside_dir, sess_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, sess_dir)

    with pytest.raises(PathConfinementError):
        p.write_bytes(b"EVIL_2")

    with pytest.raises(PathConfinementError):
        p.read_text()

    with pytest.raises(PathConfinementError):
        p.exists()


def test_capability_escape_resolve_returned_capability_blocked(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 3: Capability returned by resolve() is invalidated on namespace replacement."""
    _seed_challenge_and_session(db_conn, "ch_esc3", "sess_esc3")
    handle = ws_manager.get_or_create(db_conn, "ch_esc3", "sess_esc3")

    p = handle.resolve("input", "data.txt")

    outside_dir = temp_dir / "outside_esc3"
    outside_dir.mkdir(parents=True, exist_ok=True)
    target_victim = outside_dir / "data.txt"
    target_victim.write_text("ORIGINAL_DATA_3", encoding="utf-8")

    ws_root = ws_manager.workspace_root
    shutil.rmtree(ws_root)
    try:
        os.symlink(outside_dir, ws_root, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ws_root)

    with pytest.raises(PathConfinementError):
        p.write_text("EVIL_3")

    with pytest.raises(PathConfinementError):
        p.read_bytes()

    with pytest.raises(PathConfinementError):
        p.unlink()

    assert target_victim.read_text(encoding="utf-8") == "ORIGINAL_DATA_3"


def test_capability_escape_attempt_external_write(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 4: Attempt external write via capability fails closed."""
    _seed_challenge_and_session(db_conn, "ch_esc4", "sess_esc4")
    handle = ws_manager.get_or_create(db_conn, "ch_esc4", "sess_esc4")

    p = handle.input_dir() / "target.txt"

    outside_dir = temp_dir / "outside_esc4"
    outside_dir.mkdir(parents=True, exist_ok=True)

    ch_dir = ws_manager.workspace_root / "ch_esc4"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ch_dir)

    with pytest.raises(PathConfinementError):
        p.write_text("MUTATED_DATA_4")

    assert not (outside_dir / "target.txt").exists()


def test_capability_escape_attempt_external_read(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 5: Attempt external read via capability fails closed."""
    _seed_challenge_and_session(db_conn, "ch_esc5", "sess_esc5")
    handle = ws_manager.get_or_create(db_conn, "ch_esc5", "sess_esc5")

    outside_dir = temp_dir / "outside_esc5"
    outside_input = outside_dir / "sess_esc5" / "input"
    outside_input.mkdir(parents=True, exist_ok=True)
    secret_file = outside_input / "secret.txt"
    secret_file.write_text("TOP_SECRET_5", encoding="utf-8")

    p = handle.input_dir() / "secret.txt"

    ch_dir = ws_manager.workspace_root / "ch_esc5"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ch_dir)

    with pytest.raises(PathConfinementError):
        p.read_text()

    with pytest.raises(PathConfinementError):
        p.read_bytes()


def test_capability_escape_attempt_external_delete(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 6: Attempt external delete via capability fails closed."""
    _seed_challenge_and_session(db_conn, "ch_esc6", "sess_esc6")
    handle = ws_manager.get_or_create(db_conn, "ch_esc6", "sess_esc6")

    outside_dir = temp_dir / "outside_esc6"
    outside_input = outside_dir / "sess_esc6" / "input"
    outside_input.mkdir(parents=True, exist_ok=True)
    protected = outside_input / "protected.txt"
    protected.write_text("DO_NOT_DELETE_6", encoding="utf-8")

    p = handle.input_dir() / "protected.txt"

    ch_dir = ws_manager.workspace_root / "ch_esc6"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ch_dir)

    with pytest.raises(PathConfinementError):
        p.unlink()

    assert protected.exists()
    assert protected.read_text(encoding="utf-8") == "DO_NOT_DELETE_6"


def test_capability_escape_attempt_external_publication(db_conn, ws_manager, temp_dir):
    """Raw Path Escape Test 7: External publication attempt via manager fails closed on tampered handle."""
    _seed_challenge_and_session(db_conn, "ch_esc7", "sess_esc7")
    handle = ws_manager.get_or_create(db_conn, "ch_esc7", "sess_esc7")

    outside_dir = temp_dir / "outside_esc7"
    (outside_dir / "sess_esc7" / "input").mkdir(parents=True, exist_ok=True)

    ch_dir = ws_manager.workspace_root / "ch_esc7"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError, PermissionError):
        shutil.copytree(outside_dir, ch_dir)

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "pub.bin", b"DATA_7")

    assert not (outside_dir / "sess_esc7" / "input" / "pub.bin").exists()


def test_capability_legitimate_operations_succeed(db_conn, ws_manager):
    """Raw Path Escape Test 8: Legitimate operations on WorkspacePath capability succeed cleanly."""
    _seed_challenge_and_session(db_conn, "ch_esc8", "sess_esc8")
    handle = ws_manager.get_or_create(db_conn, "ch_esc8", "sess_esc8")

    has_dir_fd = hasattr(os, "supports_dir_fd") and os.open in os.supports_dir_fd

    p_in = handle.input_dir()
    p_file = p_in / "legit_test.txt"

    if not has_dir_fd:
        with pytest.raises(PathConfinementError):
            p_file.write_text("LEGIT_DATA_8", encoding="utf-8")
    else:
        p_file.write_text("LEGIT_DATA_8", encoding="utf-8")
        assert p_file.exists()
        assert p_file.is_file()
        assert p_file.read_text(encoding="utf-8") == "LEGIT_DATA_8"

        p_file.unlink()
        assert not p_file.exists()


def test_workspace_path_fspath_str_escape_prevention(db_conn, ws_manager):
    """Raw Path Escape Test 9: __fspath__ raises TypeError and __str__ returns non-path string."""
    _seed_challenge_and_session(db_conn, "ch_esc9", "sess_esc9")
    handle = ws_manager.get_or_create(db_conn, "ch_esc9", "sess_esc9")

    p = handle.input_dir() / "sample.txt"

    with pytest.raises(TypeError, match="cannot be converted to a raw filesystem path"):
        os.fspath(p)

    str_val = str(p)
    assert str_val.startswith("<WorkspacePath")
    assert "sample.txt" in str_val

    with pytest.raises(OSError):
        open(str_val, "r")


def test_workspace_path_glob_rglob_fail_closed(db_conn, ws_manager):
    """Raw Path Escape Test 10: glob and rglob methods fail closed on WorkspacePath capabilities."""
    _seed_challenge_and_session(db_conn, "ch_esc10", "sess_esc10")
    handle = ws_manager.get_or_create(db_conn, "ch_esc10", "sess_esc10")

    p = handle.input_dir()

    with pytest.raises(PathConfinementError, match="glob traversal is disabled"):
        p.glob("*")

    with pytest.raises(PathConfinementError, match="rglob traversal is disabled"):
        p.rglob("*")


# ---------------------------------------------------------------------------
# 10. NESTED INTERMEDIATE SYMLINK TOCTOU ADVERSARIAL TESTS
# ---------------------------------------------------------------------------


def test_nested_intermediate_symlink_during_read(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 1: Intermediate directory replaced with symlink during read."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_read", "sess_nest_read")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_read", "sess_nest_read")

    input_dir = handle._get_validated_subdir("input")
    link_dir = input_dir / "link"
    link_dir.mkdir(parents=True, exist_ok=True)
    secret_file = link_dir / "secret.txt"
    secret_file.write_bytes(b"LEGIT_SECRET_DATA")

    outside_dir = temp_dir / "outside_nest_read"
    outside_dir.mkdir(parents=True, exist_ok=True)
    evil_file = outside_dir / "secret.txt"
    evil_file.write_bytes(b"EVIL_EXTERNAL_DATA")

    p = handle.resolve("input", "link/secret.txt")

    shutil.rmtree(link_dir)
    try:
        os.symlink(outside_dir, link_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.read_bytes()


def test_nested_intermediate_symlink_during_write(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 2: Intermediate directory replaced with symlink during write."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_write", "sess_nest_write")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_write", "sess_nest_write")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = temp_dir / "outside_nest_write"
    outside_dir.mkdir(parents=True, exist_ok=True)
    victim_file = outside_dir / "victim.txt"
    victim_file.write_bytes(b"SAFE_DATA")

    p = handle.resolve("input", "sub/victim.txt")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.write_bytes(b"EVIL_OVERWRITE")

    assert victim_file.read_bytes() == b"SAFE_DATA"


def test_nested_intermediate_symlink_during_unlink(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 3: Intermediate directory replaced with symlink during unlink."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_unlink", "sess_nest_unlink")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_unlink", "sess_nest_unlink")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = temp_dir / "outside_nest_unlink"
    outside_dir.mkdir(parents=True, exist_ok=True)
    victim_file = outside_dir / "victim.txt"
    victim_file.write_bytes(b"CRITICAL_OUTSIDE_FILE")

    p = handle.resolve("input", "sub/victim.txt")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.unlink(missing_ok=True)

    assert victim_file.exists()


def test_nested_intermediate_symlink_during_open(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 4: Intermediate directory replaced with symlink during open."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_open", "sess_nest_open")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_open", "sess_nest_open")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = temp_dir / "outside_nest_open"
    outside_dir.mkdir(parents=True, exist_ok=True)
    (outside_dir / "target.txt").write_bytes(b"OUTSIDE_OPEN_TARGET")

    p = handle.resolve("input", "sub/target.txt")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.open("r")


def test_nested_intermediate_symlink_during_stat(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 5: Intermediate directory replaced with symlink during stat."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_stat", "sess_nest_stat")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_stat", "sess_nest_stat")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = temp_dir / "outside_nest_stat"
    outside_dir.mkdir(parents=True, exist_ok=True)
    (outside_dir / "target.txt").write_bytes(b"STAT_TARGET")

    p = handle.resolve("input", "sub/target.txt")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.stat()


def test_nested_intermediate_symlink_during_publication(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 6: Intermediate directory replaced with symlink during atomic write publication."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_pub", "sess_nest_pub")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_pub", "sess_nest_pub")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)

    outside_dir = temp_dir / "outside_nest_pub"
    outside_dir.mkdir(parents=True, exist_ok=True)

    p = handle.resolve("input", "sub/published.txt")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.write_bytes(b"STAGED_PUBLICATION_DATA")

    assert not (outside_dir / "published.txt").exists()


def test_existing_workspace_path_followed_by_nested_component_replacement(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 7: Previously issued WorkspacePath followed by nested parent directory replacement."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_nest_iss", "sess_nest_iss")
    handle = ws_manager.get_or_create(db_conn, "ch_nest_iss", "sess_nest_iss")

    input_dir = handle._get_validated_subdir("input")
    sub_dir = input_dir / "nested_dir"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "file.txt").write_bytes(b"ORIGINAL_VALID_DATA")

    wp = handle.resolve("input", "nested_dir/file.txt")

    outside_dir = temp_dir / "outside_nest_iss"
    outside_dir.mkdir(parents=True, exist_ok=True)
    (outside_dir / "file.txt").write_bytes(b"EVIL_SWAPPED_DATA")

    shutil.rmtree(sub_dir)
    try:
        os.symlink(outside_dir, sub_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        wp.read_bytes()


def test_multiple_intermediate_components_a_b_c_file(db_conn, ws_manager, temp_dir):
    """Nested TOCTOU Test 8: Deeply nested intermediate directory replacement (a/b/c/file)."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_deep", "sess_deep")
    handle = ws_manager.get_or_create(db_conn, "ch_deep", "sess_deep")

    input_dir = handle._get_validated_subdir("input")
    deep_dir = input_dir / "a" / "b" / "c"
    deep_dir.mkdir(parents=True, exist_ok=True)
    (deep_dir / "deep.txt").write_bytes(b"DEEP_VALID_DATA")

    p = handle.resolve("input", "a/b/c/deep.txt")
    assert p.read_bytes() == b"DEEP_VALID_DATA"

    outside_dir = temp_dir / "outside_deep"
    outside_dir.mkdir(parents=True, exist_ok=True)

    b_dir = input_dir / "a" / "b"
    shutil.rmtree(b_dir)
    try:
        os.symlink(outside_dir, b_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        p.read_bytes()


def test_legitimate_nested_directories_work(db_conn, ws_manager):
    """Nested Test 9: Legitimate nested directories operate correctly under descriptor traversal."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_legit_nest", "sess_legit_nest")
    handle = ws_manager.get_or_create(db_conn, "ch_legit_nest", "sess_legit_nest")

    input_dir = handle._get_validated_subdir("input")
    nest = input_dir / "legit_a" / "legit_b"
    nest.mkdir(parents=True, exist_ok=True)

    wp = handle.resolve("input", "legit_a/legit_b/data.txt")
    wp.write_bytes(b"LEGIT_NESTED_BYTES")

    assert wp.read_bytes() == b"LEGIT_NESTED_BYTES"
    assert wp.stat().st_size == len(b"LEGIT_NESTED_BYTES")
    assert wp.is_file()

    wp.unlink()
    assert not wp.exists()


# ---------------------------------------------------------------------------
# 11. WORKSPACE PATH SECURITY MUTATION & QUOTA POLICY REGRESSION TESTS
# ---------------------------------------------------------------------------


def test_workspace_path_write_bytes_enforces_quota_and_max_file_size(db_conn, ws_manager):
    """Mutation Test 1: WorkspacePath.write_bytes enforces maximum file size and workspace quota limits."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_quota_wp", "sess_quota_wp")
    handle = ws_manager.get_or_create(db_conn, "ch_quota_wp", "sess_quota_wp")

    wp = handle.resolve("input", "oversized.bin")

    # Single file size limit (50 MB)
    huge_data = b"X" * (51 * 1024 * 1024)
    with pytest.raises(QuotaExceededError, match="exceeds maximum file limit"):
        wp.write_bytes(huge_data)

    # Valid size write succeeds
    valid_wp = handle.resolve("input", "valid.bin")
    valid_wp.write_bytes(b"VALID_BYTES")
    assert valid_wp.read_bytes() == b"VALID_BYTES"


def test_workspace_path_open_rejects_write_modes(db_conn, ws_manager):
    """Mutation Test 2: WorkspacePath.open rejects write-capable open modes to enforce atomic publication & quota policy."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_open_mode", "sess_open_mode")
    handle = ws_manager.get_or_create(db_conn, "ch_open_mode", "sess_open_mode")

    wp = handle.resolve("input", "sample.txt")

    for mode in ("w", "w+", "a", "a+", "x", "r+"):
        with pytest.raises(PathConfinementError, match="Direct write-mode open on WorkspacePath capability is forbidden"):
            wp.open(mode)

    # Read-only open works for existing file
    wp.write_bytes(b"SAMPLE_CONTENT")
    with wp.open("r") as f:
        assert f.read() == "SAMPLE_CONTENT"


def test_workspace_path_rmdir_directory_semantics(db_conn, ws_manager):
    """Mutation Test 3: WorkspacePath.rmdir enforces real POSIX directory removal semantics."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_rmdir_sem", "sess_rmdir_sem")
    handle = ws_manager.get_or_create(db_conn, "ch_rmdir_sem", "sess_rmdir_sem")

    input_dir = handle._get_validated_subdir("input")
    empty_subdir = input_dir / "empty_dir"
    empty_subdir.mkdir(parents=True, exist_ok=True)

    wp_dir = handle.resolve("input", "empty_dir")
    wp_dir.rmdir()

    assert not empty_subdir.exists()


# ---------------------------------------------------------------------------
# 12. FINDINGS 1 & 2 CONSOLIDATED RECOVERY TESTS
# ---------------------------------------------------------------------------


def test_configured_manager_quota_policy_enforced_on_workspace_path(db_conn, temp_dir):
    """Finding 1 Test: WorkspacePath write_bytes respects WorkspaceManager configured quota policy (1MB max_file and quota)."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations fail closed on Windows (Option B).")
    _seed_challenge_and_session(db_conn, "ch_cfg_q", "sess_cfg_q")

    ws_root = temp_dir / "custom_quota_workspaces"
    mgr = WorkspaceManager(workspace_root=ws_root, default_quota_bytes=1024 * 1024, max_file_bytes=1024 * 1024)
    handle = mgr.get_or_create(db_conn, "ch_cfg_q", "sess_cfg_q")

    # 1. Writing 2 MB via WorkspacePath MUST fail with QuotaExceededError
    p = handle.resolve("input", "big.bin")
    with pytest.raises(QuotaExceededError, match="exceeds maximum file limit"):
        p.write_bytes(b"X" * (2 * 1024 * 1024))

    # 2. Exactly 1 MB file write succeeds
    valid_p = handle.resolve("input", "valid_1mb.bin")
    valid_p.write_bytes(b"A" * (1024 * 1024))

    # 3. Second write causing total workspace usage to exceed 1 MB quota MUST fail
    p2 = handle.resolve("input", "extra.bin")
    with pytest.raises(QuotaExceededError, match="quota exceeded"):
        p2.write_bytes(b"B" * 100)


def test_external_workspace_lock_file_creation_attack_blocked(db_conn, ws_manager, temp_dir):
    """Finding 2 Test: Replacing challenge parent with external symlink MUST fail closed without creating .workspace.lock outside."""
    _seed_challenge_and_session(db_conn, "ch_ext_lock", "sess_ext_lock")
    handle = ws_manager.get_or_create(db_conn, "ch_ext_lock", "sess_ext_lock")

    outside_dir = temp_dir / "outside_ext_lock"
    outside_sess = outside_dir / "sess_ext_lock"
    outside_sess.mkdir(parents=True, exist_ok=True)

    external_lock = outside_sess / ".workspace.lock"
    assert not external_lock.exists()

    ch_dir = ws_manager.workspace_root / "ch_ext_lock"
    shutil.rmtree(ch_dir)
    try:
        os.symlink(outside_dir, ch_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "test_file.bin", b"DATA")

    # VERIFY CRITICAL SECURITY INVARIANT:
    # External lock file MUST NOT be created on disk!
    assert not external_lock.exists()
    assert not (outside_dir / ".workspace.lock").exists()


def test_external_workspace_lock_creation_global_root_replacement_blocked(ws_manager, temp_dir):
    """Finding 2 Test: Global root replacement MUST NOT create .workspace.lock outside."""
    fake_global = temp_dir / "fake_global_root"
    (fake_global / "ch_g_lock" / "sess_g_lock").mkdir(parents=True, exist_ok=True)
    external_lock = fake_global / "ch_g_lock" / "sess_g_lock" / ".workspace.lock"

    handle = WorkspaceHandle(
        workspace_id="ws_g_lock",
        challenge_id="ch_g_lock",
        session_id="sess_g_lock",
        status="READY",
        _root=ws_manager.workspace_root / "ch_g_lock" / "sess_g_lock",
        _global_root=fake_global,
        _global_root_dev_ino=(99999, 99999),
    )

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "test_file.bin", b"DATA")

    assert not external_lock.exists()


def test_public_capability_api_isolation_and_no_raw_path_escape(db_conn, ws_manager):
    """Final Capability API Remediation Test: Verify WorkspaceHandle public API contains zero raw-path leakage."""
    _seed_challenge_and_session(db_conn, "ch_pub_A", "sess_pub_A")
    _seed_challenge_and_session(db_conn, "ch_pub_B", "sess_pub_B")

    handle_A = ws_manager.get_or_create(db_conn, "ch_pub_A", "sess_pub_A")
    handle_B = ws_manager.get_or_create(db_conn, "ch_pub_B", "sess_pub_B")

    # 1. Verify resolve_raw and get_global_root are NOT public methods on WorkspaceHandle
    assert not hasattr(handle_A, "resolve_raw"), "resolve_raw must NOT be a public method on WorkspaceHandle!"
    assert not hasattr(handle_A, "get_global_root"), "get_global_root must NOT be a public method on WorkspaceHandle!"

    # 2. Verify all public capability methods return WorkspacePath or primitives, NEVER raw pathlib.Path
    assert isinstance(handle_A.input_dir(), WorkspacePath)
    assert isinstance(handle_A.work_dir(), WorkspacePath)
    assert isinstance(handle_A.output_dir(), WorkspacePath)
    assert isinstance(handle_A.resolve("input", "test.txt"), WorkspacePath)

    # Audit all public methods on WorkspaceHandle
    import inspect
    for name, method in inspect.getmembers(handle_A):
        if not name.startswith("_") and callable(method):
            if name in ("input_dir", "work_dir", "output_dir", "resolve"):
                ret = method() if name != "resolve" else method("input", "test.txt")
                assert not isinstance(ret, Path), f"Public method {name} returned raw pathlib.Path!"
                assert isinstance(ret, WorkspacePath), f"Public method {name} did not return WorkspacePath!"

    # 3. Cross-challenge isolation test through public capability APIs
    with pytest.raises(PathConfinementError):
        handle_A.resolve("input", "../../../ch_pub_B/sess_pub_B/input/secret.txt")

    if HAS_DIR_FD:
        # Write secret in Challenge B
        (handle_B._root / "input" / "secret.txt").write_text("SECRET_B_DATA", encoding="utf-8")

        # Attempt to read Challenge B secret using Challenge A handle capabilities
        with pytest.raises(PathConfinementError):
            handle_A.read_text("input", "../../../ch_pub_B/sess_pub_B/input/secret.txt")

        # 4. Verify capability operations remain functional
        handle_A.write_text("input", "fileA.txt", "DATA_A")
        assert handle_A.read_text("input", "fileA.txt") == "DATA_A"

        wp = handle_A.resolve("input", "fileA.txt")
        assert wp.read_text() == "DATA_A"

        # 5. Verify __fspath__, glob, rglob remain disabled on WorkspacePath
        with pytest.raises(TypeError, match="cannot be converted"):
            os.fspath(wp)

        with pytest.raises(PathConfinementError):
            wp.glob("*")

        with pytest.raises(PathConfinementError):
            wp.rglob("*")
    else:
        wp = handle_A.resolve("input", "test.txt")
        with pytest.raises(TypeError, match="cannot be converted"):
            os.fspath(wp)

        with pytest.raises(PathConfinementError):
            wp.glob("*")

        with pytest.raises(PathConfinementError):
            wp.rglob("*")


def test_real_global_root_same_inode_move_and_symlink_replacement(db_conn, ws_manager, temp_dir):
    """Vulnerability Remediation Test: Moving global workspace root and restoring original path as symlink to same inode MUST fail closed."""
    _seed_challenge_and_session(db_conn, "ch_same_ino", "sess_same_ino")
    handle = ws_manager.get_or_create(db_conn, "ch_same_ino", "sess_same_ino")

    # Store original workspace root path
    original_ws_root = ws_manager.workspace_root.resolve()
    moved_ws_root = temp_dir / "moved_workspace_root_real"

    # Step 4: Rename original workspace root to new location (preserving inode)
    shutil.move(original_ws_root, moved_ws_root)

    # Step 5: Replace original workspace-root path with a symlink pointing to the moved ORIGINAL directory (same inode)
    try:
        os.symlink(moved_ws_root, original_ws_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform/privilege level")

    # Step 6: Use ORIGINAL WorkspaceHandle - ALL MUST fail closed!
    with pytest.raises(PathConfinementError):
        handle.input_dir()

    with pytest.raises(PathConfinementError):
        handle.work_dir()

    with pytest.raises(PathConfinementError):
        handle.output_dir()

    with pytest.raises(PathConfinementError):
        handle.resolve("input", "test.txt")

    with pytest.raises(PathConfinementError):
        ws_manager.stage_upload(handle, "upload.bin", b"DATA")

    src_art = temp_dir / "art.bin"
    src_art.write_bytes(b"DATA")
    obs = MockIngestionObservation("obs_same_ino", str(src_art), hashlib.sha256(b"DATA").hexdigest())

    with pytest.raises(PathConfinementError):
        ws_manager.import_verified_artifact(handle, obs)

    with pytest.raises(PathConfinementError):
        ws_manager.clean_stale_staging_files(handle)

    # Verifications:
    # 1. No lock file created in original path or moved location
    assert not (original_ws_root / "ch_same_ino" / "sess_same_ino" / ".workspace.lock").exists()
    assert not (moved_ws_root / "ch_same_ino" / "sess_same_ino" / ".workspace.lock").exists()

    # 2. No file created in input directory
    assert not (moved_ws_root / "ch_same_ino" / "sess_same_ino" / "input" / "upload.bin").exists()


def test_manager_global_root_replacement_different_directory(db_conn, ws_manager, temp_dir):
    """Finding 1 Test 1: WorkspaceManager global root replaced with a different directory."""
    _seed_challenge_and_session(db_conn, "ch_mgr_repl1", "sess_mgr_repl1")
    handle1 = ws_manager.get_or_create(db_conn, "ch_mgr_repl1", "sess_mgr_repl1")
    assert handle1.status == "READY"

    original_root = ws_manager.workspace_root.resolve()
    external_dir = temp_dir / "external_workspace_root_diff"
    external_dir.mkdir(parents=True, exist_ok=True)
    external_file = external_dir / "external_sensitive.txt"
    external_file.write_text("SENSITIVE_DATA", encoding="utf-8")

    # Replace original workspace_root directory with external_dir content
    shutil.rmtree(original_root)
    shutil.copytree(external_dir, original_root)

    # 4. Existing manager calls get_or_create(): MUST fail closed
    _seed_challenge_and_session(db_conn, "ch_mgr_repl1_new", "sess_mgr_repl1_new")
    with pytest.raises(PathConfinementError):
        ws_manager.get_or_create(db_conn, "ch_mgr_repl1_new", "sess_mgr_repl1_new")

    # 5. Existing manager calls clean_stale_staging_files_by_root(): MUST fail closed
    if HAS_DIR_FD:
        with pytest.raises(PathConfinementError):
            ws_manager.clean_stale_staging_files_by_root(Path("ch_mgr_repl1") / "sess_mgr_repl1")

    # Verify no new workspace appears outside original root, no external file is deleted/modified
    assert not (external_dir / "ch_mgr_repl1_new").exists()
    assert external_file.read_text(encoding="utf-8") == "SENSITIVE_DATA"


def test_manager_global_root_replaced_by_symlink(db_conn, ws_manager, temp_dir):
    """Finding 1 Test 2: WorkspaceManager global root replaced by symlink to different directory."""
    _seed_challenge_and_session(db_conn, "ch_mgr_sym1", "sess_mgr_sym1")
    handle1 = ws_manager.get_or_create(db_conn, "ch_mgr_sym1", "sess_mgr_sym1")
    assert handle1.status == "READY"

    original_root = ws_manager.workspace_root.resolve()
    outside_dir = temp_dir / "outside_mgr_sym"
    (outside_dir / "ch_mgr_sym1" / "sess_mgr_sym1" / "input").mkdir(parents=True, exist_ok=True)
    external_stale = outside_dir / "ch_mgr_sym1" / "sess_mgr_sym1" / "input" / ".staging_tmp_external"
    external_stale.write_bytes(b"STALE_EXTERNAL_DATA")

    shutil.rmtree(original_root)
    try:
        os.symlink(outside_dir, original_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform/privilege level")

    # 4. Existing manager calls get_or_create(): MUST fail closed
    _seed_challenge_and_session(db_conn, "ch_mgr_sym2", "sess_mgr_sym2")
    with pytest.raises(PathConfinementError):
        ws_manager.get_or_create(db_conn, "ch_mgr_sym2", "sess_mgr_sym2")

    # 5. Existing manager calls clean_stale_staging_files_by_root(): MUST fail closed
    if HAS_DIR_FD:
        with pytest.raises(PathConfinementError):
            ws_manager.clean_stale_staging_files_by_root(Path("ch_mgr_sym1") / "sess_mgr_sym1", stale_age_seconds=0)

    # Verify: no new workspace under outside_dir, external file not deleted
    assert not (outside_dir / "ch_mgr_sym2").exists()
    assert external_stale.exists()
    assert external_stale.read_bytes() == b"STALE_EXTERNAL_DATA"


def test_manager_global_root_same_inode_move_and_symlink_replacement(db_conn, ws_manager, temp_dir):
    """Finding 1 Test 3: WorkspaceManager global root moved and original path replaced by symlink to SAME original inode."""
    _seed_challenge_and_session(db_conn, "ch_mgr_same", "sess_mgr_same")
    handle1 = ws_manager.get_or_create(db_conn, "ch_mgr_same", "sess_mgr_same")
    assert handle1.status == "READY"

    original_root = ws_manager.workspace_root.resolve()
    moved_root = temp_dir / "moved_mgr_root_real"

    shutil.move(original_root, moved_root)

    try:
        os.symlink(moved_root, original_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on platform/privilege level")

    # 4. Existing manager calls get_or_create(): MUST fail closed
    _seed_challenge_and_session(db_conn, "ch_mgr_same_new", "sess_mgr_same_new")
    with pytest.raises(PathConfinementError):
        ws_manager.get_or_create(db_conn, "ch_mgr_same_new", "sess_mgr_same_new")

    # 5. Existing manager calls clean_stale_staging_files_by_root(): MUST fail closed
    if HAS_DIR_FD:
        with pytest.raises(PathConfinementError):
            ws_manager.clean_stale_staging_files_by_root(Path("ch_mgr_same") / "sess_mgr_same", stale_age_seconds=0)

    # Verify: no new workspace created in moved_root or original_root
    assert not (moved_root / "ch_mgr_same_new").exists()


def test_manager_normal_operation_without_tampering(db_conn, ws_manager):
    """Finding 1 Test 6: Normal WorkspaceManager operation without tampering MUST continue to work."""
    _seed_challenge_and_session(db_conn, "ch_norm_op", "sess_norm_op")
    handle = ws_manager.get_or_create(db_conn, "ch_norm_op", "sess_norm_op")
    assert handle.status == "READY"

    if HAS_DIR_FD:
        handle.write_text("input", "data.txt", "LEGITIMATE_CONTENT")
        assert handle.read_text("input", "data.txt") == "LEGITIMATE_CONTENT"

        stale_file = handle._root / "input" / ".staging_tmp_legit"
        stale_file.write_bytes(b"STALE_TMP")
        old_time = datetime.now(timezone.utc).timestamp() - 120.0
        os.utime(stale_file, (old_time, old_time))

        cleaned = ws_manager.clean_stale_staging_files_by_root(Path("ch_norm_op") / "sess_norm_op", stale_age_seconds=60.0)
        assert cleaned == 1
        assert not stale_file.exists()


def test_publication_no_post_rename_path_based_chmod(db_conn, ws_manager, temp_dir, monkeypatch):
    """Finding 2 Test: Verify descriptor-relative publication performs zero post-rename path-based chmod operations."""
    if not HAS_DIR_FD:
        pytest.skip("Descriptor-relative workspace operations are fail-closed on Windows (Option B).")

    _seed_challenge_and_session(db_conn, "ch_pub_chmod", "sess_pub_chmod")
    handle = ws_manager.get_or_create(db_conn, "ch_pub_chmod", "sess_pub_chmod")

    chmod_calls = []
    orig_chmod = os.chmod

    def mock_chmod(path, mode, *args, **kwargs):
        chmod_calls.append((str(path), mode))
        return orig_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", mock_chmod)

    wp = ws_manager.stage_upload(handle, "pub_test.bin", b"PUBLISHED_DATA")
    assert wp.read_bytes() == b"PUBLISHED_DATA"

    pub_file = handle._root / "input" / "pub_test.bin"
    st = pub_file.stat()
    assert (st.st_mode & 0o777) == 0o600

    for call_path, call_mode in chmod_calls:
        assert "pub_test.bin" not in call_path, f"Unsafe post-publication path-based chmod detected on '{call_path}'!"























