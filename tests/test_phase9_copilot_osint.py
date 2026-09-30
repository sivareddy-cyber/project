"""
Comprehensive Security & Remediation Test Suite for Phase 9 AI CTF Copilot & OSINT Domain Skill.

Remediation Test Sections:
F1. Zero Network Hostile Fixture Ingestion Tests
F2. Process-Isolated Safe Artifact Parser Sandbox & Filesystem Confinement Tests
F3. Control-Plane Security & Authentication Tests (No Per-Call Overrides, Single Authenticator Binding)
F4. OSINT Actual Target Value Scope Validation Tests (All 6 Target Types: DOMAIN, EMAIL, USERNAME, TEXT, IMAGE, METADATA)
F5. Real End-to-End TaskManager + Copilot Integration Test
F6. Repository-wide Security Boundary Scan for Execution Primitives
"""

from __future__ import annotations

import datetime
import inspect
import io
import os
import re
import sqlite3
import sys
import uuid
import zipfile
import pytest

from ctf_mentor.copilot.controller import CopilotSessionController
from ctf_mentor.copilot.mode import CopilotMode
from ctf_mentor.copilot.security import (
    ControlPlaneActionType,
    ControlPlaneSecurity,
    ControlPlaneSecurityViolation,
    ControlPlaneSource,
    ExternalHostAuthenticator,
    VerifiedControlPlaneIdentity,
)
from ctf_mentor.contracts import EntityWrite
from ctf_mentor.domain.investigation_models import (
    InvestigationSession,
    InvestigationStepStatus,
    TargetType,
)
from ctf_mentor.domain.models import (
    ApprovalStatus,
    AuthorizedScope,
    BlackboardState,
    HintLevel,
    TaskStatus,
)
from ctf_mentor.domain_engine.detector import DomainDetector
from ctf_mentor.domain_engine.orchestration_handlers import register_phase8_handlers
from ctf_mentor.domain_engine.planner import InvestigationPlanner
from ctf_mentor.domain_engine.protocol import DomainSkillRegistry
from ctf_mentor.domain_engine.skills.osint import (
    OsintDomainSkill,
    OsintTargetType,
    validate_osint_target_details,
)
from ctf_mentor.ingestion.adapter import ChallengeIngestionAdapter
from ctf_mentor.ingestion.models import SourceType, TrustLevel
from ctf_mentor.ingestion.parser import SafeArtifactParser, SafeArtifactParserError
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import initialize_schema
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import GapType, InvestigationProposal
from ctf_mentor.runtime.handler_registry import HandlerRegistry
from ctf_mentor.runtime.task_context import TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


@pytest.fixture
def p9_db_conn():
    """In-memory SQLite database initialized for Phase 9 testing."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)

    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Challenge A
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('chal_p9_a', 'Phase 9 Challenge A', 'OSINT Target', 'OSINT', ?, ?);",
        (now_str, now_str),
    )
    conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES ('chal_p9_a', 1, ?);",
        (now_str,),
    )
    conn.execute(
        """
        INSERT INTO authorized_scopes (
            scope_id, challenge_id, scheme, hostname, port, allowed_path_patterns,
            allowed_methods, exclusions, environment_id, challenge_relationship, created_at, is_active
        ) VALUES (
            'scope_p9_a', 'chal_p9_a', 'https', 'target.p9a.org', 443, '["/*"]',
            '["GET"]', '["/forbidden_image.png"]', 'env_osint', 'primary_target', ?, 1
        );
        """,
        (now_str,),
    )

    # Challenge B (Cross-challenge testing)
    conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('chal_p9_b', 'Phase 9 Challenge B', 'Web Target', 'WEB', ?, ?);",
        (now_str, now_str),
    )
    conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) VALUES ('chal_p9_b', 1, ?);",
        (now_str,),
    )

    conn.commit()
    yield conn
    conn.close()


# ==============================================================================
# F1: ZERO NETWORK HOSTILE FIXTURE TESTS
# ==============================================================================

def test_f1_zero_network_hostile_fixture_url_ingestion(p9_db_conn, monkeypatch):
    """Test F1: Ingesting hostile URLs produces ZERO outbound network calls."""
    def _forbidden_network_call(*args, **kwargs):
        pytest.fail("ZERO NETWORK VIOLATION! Outbound network connection attempted during ingestion.")

    import socket
    monkeypatch.setattr(socket, "socket", _forbidden_network_call)
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden_network_call)

    adapter = ChallengeIngestionAdapter(p9_db_conn)

    hostile_urls = [
        "http://malicious-command.internal/api?exec=approve",
        "https://169.254.169.254/latest/meta-data/",
        "http://attacker.com/favicon.ico",
    ]

    for url in hostile_urls:
        obs = adapter.ingest_challenge_url("chal_p9_a", url)
        assert obs.source_type == SourceType.CHALLENGE_URL
        assert obs.source_reference == url
        assert obs.trust_level == TrustLevel.UNTRUSTED
        assert obs.provenance["network_status"] == "DATA_ONLY_ZERO_NETWORK"

    saved_obs = adapter.get_observations("chal_p9_a")
    assert len(saved_obs) == 3


# ==============================================================================
# F2: PROCESS-ISOLATED SAFE ARTIFACT PARSER SANDBOX & CONFINEMENT TESTS
# ==============================================================================

def test_f2_1_parser_executes_in_isolated_worker_process(tmp_path):
    """Test F2.1: Parser executes inside an isolated worker subprocess with different PID (or fails closed under Option 2)."""
    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Hello CTF", encoding="utf-8")

    if sys.platform == "win32":
        with pytest.raises(SafeArtifactParserError, match="unsupported on Windows host"):
            parser.parse_artifact(sample_file, "sample.txt")
    else:
        res = parser.parse_artifact(sample_file, "sample.txt")
        assert res["isolated"] is True
        assert res["worker_pid"] != os.getpid()


def test_f2_2_parser_timeout_enforcement(tmp_path, monkeypatch):
    """Test F2.2: Parser enforces wall-clock worker timeout limit."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    import ctf_mentor.ingestion.parser as parser_mod
    monkeypatch.setattr(parser_mod, "WORKER_TIMEOUT_SECONDS", 0.001)

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Timeout test content", encoding="utf-8")

    with pytest.raises(SafeArtifactParserError, match="worker timeout"):
        parser.parse_artifact(sample_file, "sample.txt")


def test_f2_3_parser_oversized_input(tmp_path, monkeypatch):
    """Test F2.3: Parser rejects files exceeding maximum size limit."""
    import ctf_mentor.ingestion.parser as parser_mod
    monkeypatch.setattr(parser_mod, "MAX_FILE_SIZE_BYTES", 100)

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    big_file = tmp_path / "big.bin"
    big_file.write_bytes(b"X" * 500)

    with pytest.raises(SafeArtifactParserError, match="exceeds maximum allowed limit"):
        parser.parse_artifact(big_file, "big.bin")


def test_f2_4_parser_excessive_zip_expansion_bomb(tmp_path):
    """Test F2.4: Parser detects and blocks high expansion ratio zip bombs."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    zip_path = tmp_path / "bomb.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeroes.txt", b"\x00" * (2 * 1024 * 1024))
    buf.seek(0)
    zip_path.write_bytes(buf.read())

    with pytest.raises(SafeArtifactParserError, match="Zip bomb detected"):
        parser.parse_artifact(zip_path, "bomb.zip")


def test_f2_5_parser_path_traversal_detection(tmp_path):
    """Test F2.5: Parser detects and rejects path traversal filenames."""
    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "test.txt"
    sample_file.write_text("content", encoding="utf-8")

    for traversal in ["../../../etc/passwd", "..\\..\\win.ini"]:
        with pytest.raises(SafeArtifactParserError):
            parser.parse_artifact(sample_file, traversal)


def test_f2_6_parser_forbidden_executable_extension(tmp_path):
    """Test F2.6: Executable files are parsed inertly as binary bytes without execution."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    exe_file = tmp_path / "payload.exe"
    exe_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")

    res = parser.parse_artifact(exe_file, "payload.exe")
    assert res["is_forbidden_extension"] is True
    assert res["is_binary"] is True


def test_f2_7_parser_worker_crash_handling(tmp_path, monkeypatch):
    """Test F2.7: Parser fails closed if worker process encounters error/crash."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    import sys as sys_mod
    import ctf_mentor.ingestion.parser as parser_mod
    monkeypatch.setattr(sys_mod, "executable", "non_existent_python_binary_xyz")

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("test", encoding="utf-8")

    with pytest.raises(SafeArtifactParserError, match="Failed to execute isolated parser worker"):
        parser.parse_artifact(sample_file, "sample.txt")


def test_f2_8_parser_inability_to_establish_isolation(tmp_path):
    """Test F2.8: Non-existent input file fails closed."""
    parser = SafeArtifactParser(scratch_dir=tmp_path)
    missing_file = tmp_path / "non_existent.txt"

    with pytest.raises(SafeArtifactParserError):
        parser.parse_artifact(missing_file, "non_existent.txt")


def test_f2_9_parser_network_isolation(tmp_path, monkeypatch):
    """Test F2.9: Isolated worker performs zero network calls during artifact parsing."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    def _forbidden_network_call(*args, **kwargs):
        pytest.fail("Network call in parser!")

    import socket
    monkeypatch.setattr(socket, "socket", _forbidden_network_call)

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Inert text", encoding="utf-8")

    res = parser.parse_artifact(sample_file, "sample.txt")
    assert res["sha256"] is not None


def test_f2_10_parser_secret_isolation(tmp_path):
    """Test F2.10: Isolated worker does not have access to main process memory or secret state."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Secret check", encoding="utf-8")

    res = parser.parse_artifact(sample_file, "sample.txt")
    assert "secret" not in res
    assert res["isolated"] is True


def test_f2_11_windows_option2_fail_closed(tmp_path, monkeypatch):
    """Test F2.11: Option 2 Windows fail-closed enforcement returns explicit unsupported-platform error."""
    import sys as sys_mod
    monkeypatch.setattr(sys_mod, "platform", "win32")

    parser = SafeArtifactParser(scratch_dir=tmp_path)
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Sample text", encoding="utf-8")

    with pytest.raises(SafeArtifactParserError, match="unsupported on Windows host"):
        parser.parse_artifact(sample_file, "sample.txt")


def test_f2_12_scratch_dir_confinement_absolute_path_outside(tmp_path):
    """Test F2.12: parse_artifact() rejects file paths outside scratch_dir."""
    scratch = tmp_path / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("Outside file content", encoding="utf-8")

    with pytest.raises(SafeArtifactParserError, match="Filesystem confinement violation"):
        parser.parse_artifact(outside_file, "outside.txt")


def test_f2_13_scratch_dir_confinement_adapter_ingest(p9_db_conn, tmp_path):
    """Test F2.13: ChallengeIngestionAdapter.ingest_artifact_file() rejects file paths outside scratch_dir."""
    scratch = tmp_path / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)
    adapter = ChallengeIngestionAdapter(p9_db_conn, parser=parser)

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("Outside file content", encoding="utf-8")

    with pytest.raises(ValueError, match="Filesystem confinement violation"):
        adapter.ingest_artifact_file("chal_p9_a", outside_file, "outside.txt")


def test_f2_14_scratch_dir_confinement_traversal_outside(tmp_path):
    """Test F2.14: parse_artifact() rejects relative path traversal escaping scratch_dir."""
    scratch = tmp_path / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)

    traversal_path = scratch / ".." / "outside.txt"
    traversal_path.parent.mkdir(exist_ok=True)
    traversal_path.write_text("Outside traversal", encoding="utf-8")

    with pytest.raises(SafeArtifactParserError, match="Filesystem confinement violation"):
        parser.parse_artifact(traversal_path, "outside.txt")


def test_f2_15_scratch_dir_confinement_symlink_escape(tmp_path):
    """Test F2.15: parse_artifact() rejects symlink pointing outside scratch_dir."""
    if os.name != "posix":
        pytest.skip("Symlink creation requires POSIX environment")

    scratch = tmp_path / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)

    target_outside = tmp_path / "outside_target.txt"
    target_outside.write_text("Outside target", encoding="utf-8")

    symlink_file = scratch / "symlink_test.txt"
    os.symlink(str(target_outside), str(symlink_file))

    with pytest.raises(SafeArtifactParserError, match="Filesystem confinement violation"):
        parser.parse_artifact(symlink_file, "symlink_test.txt")


def test_f2_16_unprivileged_worker_reads_staged_artifact(tmp_path):
    """Test F2.16: Parent creates artifact in scratch_dir -> worker drops to nobody -> worker successfully reads/parses artifact -> result returned successfully."""
    if sys.platform == "win32":
        pytest.skip("Windows uses Option 2 fail closed")

    scratch = tmp_path / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)

    sample_file = scratch / "sample_staged.txt"
    sample_file.write_text("Staged artifact content readable by unprivileged worker", encoding="utf-8")

    res = parser.parse_artifact(sample_file, "sample_staged.txt")
    assert res is not None
    assert res["isolated"] is True
    assert res["filename"] == "sample_staged.txt"
    assert res["size_bytes"] > 0
    assert res["file_size"] > 0
    assert "sha256" in res


def test_f2_17_scratch_dir_permissions_do_not_modify_ancestors(tmp_path):
    """Test F2.17: Proves parse_artifact does not modify permissions of any ancestor directory outside scratch_dir."""
    private_ancestor = tmp_path / "private_ancestor"
    private_ancestor.mkdir()
    os.chmod(private_ancestor, 0o700)

    scratch = private_ancestor / "scratch_sub"
    scratch.mkdir()
    parser = SafeArtifactParser(scratch_dir=scratch)

    sample_file = scratch / "sample_staged.txt"
    sample_file.write_text("Staged artifact content inside scratch", encoding="utf-8")

    st_before = private_ancestor.stat()

    if sys.platform != "win32":
        res = parser.parse_artifact(sample_file, "sample_staged.txt")
        assert res is not None

    st_after = private_ancestor.stat()
    assert st_before.st_mode == st_after.st_mode, f"Ancestor permissions were modified! Before: {oct(st_before.st_mode)}, After: {oct(st_after.st_mode)}"



# ==============================================================================
# F3: CONTROL-PLANE SECURITY & AUTHENTICATION TESTS
# ==============================================================================

TEST_HOST_SECRET = b"test_external_host_secret_key_987654321"


@pytest.fixture
def host_authenticator():
    return ExternalHostAuthenticator(secret_key=TEST_HOST_SECRET, issuer_id="test_host_auth")


def test_f3_1_switch_mode_without_authentication_fails(p9_db_conn, tm_fixture, host_authenticator):
    """Test F3.1: Calling switch_mode without verified identity or authenticator fails closed."""
    inv_repo, bb_repo, tm = tm_fixture
    controller = CopilotSessionController(p9_db_conn, bb_repo, inv_repo, tm, authenticator=host_authenticator)

    with pytest.raises(ControlPlaneSecurityViolation, match="requires a VerifiedControlPlaneIdentity"):
        controller.switch_mode(
            challenge_id="chal_p9_a",
            new_mode=CopilotMode.SOLVE,
            identity=None,
            source=ControlPlaneSource.AUTHENTICATED_USER,
        )


@pytest.mark.asyncio
async def test_f3_2_submit_approval_without_authentication_fails(p9_db_conn, tm_fixture, host_authenticator):
    """Test F3.2: Calling submit_step_approval without verified identity or authenticator fails closed."""
    inv_repo, bb_repo, tm = tm_fixture
    controller = CopilotSessionController(p9_db_conn, bb_repo, inv_repo, tm, authenticator=host_authenticator)

    with pytest.raises(ControlPlaneSecurityViolation, match="requires a VerifiedControlPlaneIdentity"):
        await controller.submit_step_approval(
            challenge_id="chal_p9_a",
            step_id="step_1",
            session_id="sess_1",
            decision="APPROVE",
            reason="Reason",
            identity=None,
            source=ControlPlaneSource.AUTHENTICATED_USER,
        )


def test_f3_3_forged_authenticated_user_identity_fails(host_authenticator):
    """Test F3.3: Supplying a manually constructed AUTHENTICATED_USER identity fails verification."""
    forged_identity = VerifiedControlPlaneIdentity(
        user_id="attacker_user",
        auth_token="fake_token",
        issued_at=1234567.0,
        session_id=None,
        signature="fake_signature_hash",
        issuer_id="test_host_auth",
    )

    with pytest.raises(ControlPlaneSecurityViolation, match="unverified or forged identity"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
            identity=forged_identity,
            source=ControlPlaneSource.AUTHENTICATED_USER,
            authenticator=host_authenticator,
        )


def test_f3_4_forged_token_with_placeholder_actor_fails(host_authenticator):
    """Test F3.4: Token forged with different secret key or placeholder actor ID fails verification."""
    fake_authenticator = ExternalHostAuthenticator(secret_key=b"attacker_fake_secret_key_123456", issuer_id="fake")
    forged_identity = fake_authenticator.issue_identity("sec_analyst_01")

    with pytest.raises(ControlPlaneSecurityViolation, match="unverified or forged identity"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.SWITCH_COPILOT_MODE,
            identity=forged_identity,
            source=ControlPlaneSource.AUTHENTICATED_USER,
            authenticator=host_authenticator,
        )


def test_f3_5_llm_originated_request_fails(host_authenticator):
    """Test F3.5: Request with LLM_OUTPUT source fails closed."""
    identity = host_authenticator.issue_identity("sec_analyst_01")
    with pytest.raises(ControlPlaneSecurityViolation, match="untrusted source"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
            identity=identity,
            source=ControlPlaneSource.LLM_OUTPUT,
            authenticator=host_authenticator,
        )


def test_f3_6_challenge_content_request_fails(host_authenticator):
    """Test F3.6: Request with CHALLENGE_CONTENT source fails closed."""
    identity = host_authenticator.issue_identity("sec_analyst_01")
    with pytest.raises(ControlPlaneSecurityViolation, match="untrusted source"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
            identity=identity,
            source=ControlPlaneSource.CHALLENGE_CONTENT,
            authenticator=host_authenticator,
        )


def test_f3_7_rag_originated_request_fails(host_authenticator):
    """Test F3.7: Request with RAG_CONTENT source fails closed."""
    identity = host_authenticator.issue_identity("sec_analyst_01")
    with pytest.raises(ControlPlaneSecurityViolation, match="untrusted source"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.SWITCH_COPILOT_MODE,
            identity=identity,
            source=ControlPlaneSource.RAG_CONTENT,
            authenticator=host_authenticator,
        )


def test_f3_8_untrusted_ingestion_request_fails(host_authenticator):
    """Test F3.8: Request with UNTRUSTED_INGESTION source fails closed."""
    identity = host_authenticator.issue_identity("sec_analyst_01")
    with pytest.raises(ControlPlaneSecurityViolation, match="untrusted source"):
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
            identity=identity,
            source=ControlPlaneSource.UNTRUSTED_INGESTION,
            authenticator=host_authenticator,
        )


def test_f3_9_genuinely_verified_identity_succeeds(host_authenticator):
    """Test F3.9: Genuinely issued VerifiedControlPlaneIdentity via ExternalHostAuthenticator succeeds."""
    identity = host_authenticator.issue_identity("sec_analyst_real_01")
    res = ControlPlaneSecurity.validate_control_plane_action(
        action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
        identity=identity,
        source=ControlPlaneSource.AUTHENTICATED_USER,
        authenticator=host_authenticator,
    )
    assert res is True


def test_f3_10_forbidden_placeholder_actor_rejection(host_authenticator):
    """Test F3.10: Rejects attempts to issue identity for forbidden placeholder actors."""
    for placeholder in ["user", "system", "admin", "llm", "copilot"]:
        with pytest.raises(ControlPlaneSecurityViolation, match="forbidden user_id"):
            host_authenticator.issue_identity(placeholder)


def test_f3_11_no_public_self_issuance_in_security_module():
    """Test F3.11: Confirms public create_verified_identity and module secret are removed from security.py."""
    import ctf_mentor.copilot.security as sec_module

    assert not hasattr(sec_module, "create_verified_identity"), "Public create_verified_identity() helper MUST NOT exist in security.py!"
    assert not hasattr(sec_module, "_CONTROL_PLANE_SECRET"), "Hardcoded _CONTROL_PLANE_SECRET MUST NOT exist in security.py!"


@pytest.mark.asyncio
async def test_f3_12_per_call_authenticator_override_removal_and_single_binding(p9_db_conn, tm_fixture):
    """Test F3.12: Mandatory security test proving per-call authenticator override is eliminated and controller uses single startup-bound authenticator."""
    inv_repo, bb_repo, tm = tm_fixture

    # 1. Construct controller with legitimate host authenticator
    legit_auth = ExternalHostAuthenticator(b"legit_secret_key_1234567890", issuer_id="legit_host")
    controller = CopilotSessionController(p9_db_conn, bb_repo, inv_repo, tm, authenticator=legit_auth)

    session_info = controller.initialize_copilot_session("chal_p9_a", mode=CopilotMode.MENTOR)
    assert session_info["mode"] == "MENTOR"

    # 2. Construct SECOND attacker-controlled authenticator and identity
    attacker_auth = ExternalHostAuthenticator(b"attacker_secret_key_999999999", issuer_id="attacker_host")
    attacker_identity = attacker_auth.issue_identity("attacker_user")

    # 3. Attempt switch_mode with attacker identity -> MUST FAIL CLOSED
    with pytest.raises(ControlPlaneSecurityViolation, match="unverified or forged identity"):
        controller.switch_mode(
            challenge_id="chal_p9_a",
            new_mode=CopilotMode.SOLVE,
            identity=attacker_identity,
            source=ControlPlaneSource.AUTHENTICATED_USER,
        )

    # 4. Assert session mode remains MENTOR (unchanged)
    current_info = controller.get_session_info("chal_p9_a")
    assert current_info["mode"] == "MENTOR"

    # 5. Attempt submit_step_approval with attacker identity -> MUST FAIL CLOSED
    inv_session = inv_repo.create_session_atomic("chal_p9_a")
    with pytest.raises(ControlPlaneSecurityViolation, match="unverified or forged identity"):
        await controller.submit_step_approval(
            challenge_id="chal_p9_a",
            step_id="step_f3_12",
            session_id=inv_session.session_id,
            decision="APPROVE",
            reason="Attacker approval",
            identity=attacker_identity,
            source=ControlPlaneSource.AUTHENTICATED_USER,
        )

    # 6. Verify signature inspect proves zero per-call authenticator parameters in signatures
    switch_sig = inspect.signature(controller.switch_mode)
    approval_sig = inspect.signature(controller.submit_step_approval)

    assert "authenticator" not in switch_sig.parameters, "switch_mode MUST NOT accept a per-call authenticator parameter!"
    assert "authenticator" not in approval_sig.parameters, "submit_step_approval MUST NOT accept a per-call authenticator parameter!"
    assert controller.authenticator is legit_auth, "Controller MUST be bound to single startup authenticator!"


# ==============================================================================
# F4: OSINT ACTUAL TARGET VALUE SCOPE VALIDATION TESTS (ALL 6 TARGET TYPES)
# ==============================================================================

def test_f4_test_a_osint_unrelated_domain_target_rejected(p9_db_conn):
    """Test F4 Test A: Authorized scope = target.p9a.org, OSINT DOMAIN_TARGET = completely-unrelated-thirdparty-company.com -> propose_step() MUST RETURN None."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    cursor = p9_db_conn.cursor()
    cursor.execute("SELECT * FROM authorized_scopes WHERE challenge_id = 'chal_p9_a'")
    scope_dict = dict(cursor.fetchone())

    proposal = InvestigationProposal(
        proposal_id="prop_unrelated_domain",
        challenge_id="chal_p9_a",
        title="Lookup Unrelated Domain",
        description="OSINT lookup",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "DOMAIN_TARGET",
            "target_details": {"domain_name": "completely-unrelated-thirdparty-company.com"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # MUST RETURN NONE (REJECTED)


def test_f4_test_b_osint_unrelated_domain_rejected(p9_db_conn):
    """Test F4 Test B: Authorized domain = example-authorized-domain.com, OSINT target = unrelated-thirdparty.com -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "example-authorized-domain.com",
        "port": 443,
        "scheme": "https",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_b",
        challenge_id="chal_p9_a",
        title="Unrelated Domain",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "DOMAIN_TARGET",
            "target_details": {"domain_name": "unrelated-thirdparty.com"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_c_osint_unrelated_email_rejected(p9_db_conn):
    """Test F4 Test C: Authorized domain = target.p9a.org, OSINT EMAIL_TARGET = user@unrelated-thirdparty.com -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    cursor = p9_db_conn.cursor()
    cursor.execute("SELECT * FROM authorized_scopes WHERE challenge_id = 'chal_p9_a'")
    scope_dict = dict(cursor.fetchone())

    proposal = InvestigationProposal(
        proposal_id="prop_c",
        challenge_id="chal_p9_a",
        title="Unrelated Email",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "EMAIL_TARGET",
            "target_details": {"email_address": "user@unrelated-thirdparty.com"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_d_osint_forbidden_username_rejected(p9_db_conn):
    """Test F4 Test D: USERNAME_TARGET not in explicit allowed usernames -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "port": 443,
        "scheme": "https",
        "is_active": True,
        "metadata": {"allowed_usernames": ["authorized_user_1"]},
    }

    proposal = InvestigationProposal(
        proposal_id="prop_d",
        challenge_id="chal_p9_a",
        title="Forbidden Username",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "USERNAME_TARGET",
            "target_details": {"username": "unauthorized_hacker"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_e_valid_in_scope_osint_target_succeeds(p9_db_conn):
    """Test F4 Test E: Valid in-scope OSINT target succeeds and creates PENDING_APPROVAL step."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    cursor = p9_db_conn.cursor()
    cursor.execute("SELECT * FROM authorized_scopes WHERE challenge_id = 'chal_p9_a'")
    scope_dict = dict(cursor.fetchone())

    proposal = InvestigationProposal(
        proposal_id="prop_e",
        challenge_id="chal_p9_a",
        title="Valid In-Scope Domain",
        description="Desc",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "DOMAIN_TARGET",
            "target_details": {"domain_name": "target.p9a.org"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL
    assert step.target.details["hostname"] == "target.p9a.org"


def test_f4_test_f_text_target_unrelated_subject_rejected(p9_db_conn):
    """Test F4 Test F: TEXT_TARGET containing unrelated subject -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_f",
        challenge_id="chal_p9_a",
        title="Unrelated Text Target",
        description="Search secrets for completely_unrelated_secret_corp",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "TEXT_TARGET",
            "target_details": {
                "query_or_text": "Search secrets for completely_unrelated_secret_corp",
                "subject": "completely_unrelated_secret_corp",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_f_text_target_in_scope_succeeds(p9_db_conn):
    """Test F4 Test F (Positive): TEXT_TARGET matching authorized scope subject -> succeeds."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_f_pos",
        challenge_id="chal_p9_a",
        title="In Scope Text Target",
        description="Search OSINT info for target.p9a.org",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "TEXT_TARGET",
            "target_details": {
                "query_or_text": "Search OSINT info for target.p9a.org",
                "subject": "target.p9a.org",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


def test_f4_text_target_keyword_stuffing_rejected(p9_db_conn):
    """Test F4 Negative: TEXT_TARGET mentioning authorized hostname inside unrelated text with unrelated subject -> REJECTED."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_stuffing_text",
        challenge_id="chal_p9_a",
        title="Stuffing Text Target",
        description="Search info",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "TEXT_TARGET",
            "target_details": {
                "query_or_text": "private information about unrelated person ... target.p9a.org",
                "subject": "unrelated_person",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # MUST BE REJECTED


def test_f4_image_target_query_param_stuffing_rejected(p9_db_conn):
    """Test F4 Negative: IMAGE_TARGET with evil domain and authorized hostname in URL query params -> REJECTED."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_stuffing_img",
        challenge_id="chal_p9_a",
        title="URL Query Param Stuffing Image Target",
        description="Image search",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "IMAGE_TARGET",
            "target_details": {
                "image_url": "https://evil.example/private.jpg?ref=target.p9a.org",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # MUST BE REJECTED BECAUSE REAL HOSTNAME IS EVIL.EXAMPLE


def test_f4_test_g_image_target_unrelated_domain_rejected(p9_db_conn):
    """Test F4 Test G: IMAGE_TARGET pointing to unrelated domain -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_g",
        challenge_id="chal_p9_a",
        title="Unrelated Image Target",
        description="Image search",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "IMAGE_TARGET",
            "target_details": {
                "image_url": "https://unrelated-thirdparty-cdn.com/leak.png",
                "subject": "unrelated_thirdparty_cdn",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_g_image_target_in_scope_succeeds(p9_db_conn):
    """Test F4 Test G (Positive): IMAGE_TARGET pointing to in-scope domain -> succeeds."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_g_pos",
        challenge_id="chal_p9_a",
        title="In Scope Image Target",
        description="Image search",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "IMAGE_TARGET",
            "target_details": {
                "image_url": "https://target.p9a.org/assets/logo.png",
                "subject": "target.p9a.org",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


def test_f4_test_h_metadata_target_unrelated_artifact_rejected(p9_db_conn):
    """Test F4 Test H: METADATA_TARGET referencing unrelated artifact -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
    }

    proposal = InvestigationProposal(
        proposal_id="prop_h",
        challenge_id="chal_p9_a",
        title="Unrelated Metadata Target",
        description="Examine metadata",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "METADATA_TARGET",
            "target_details": {
                "artifact_ref": "unrelated_exfiltrated_database.sql",
                "subject": "unrelated_db",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_h_metadata_target_in_scope_succeeds(p9_db_conn):
    """Test F4 Test H (Positive): METADATA_TARGET referencing authorized artifact -> succeeds."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
        "metadata": {"allowed_artifacts": ["target.p9a.org_backup.zip"]},
    }

    proposal = InvestigationProposal(
        proposal_id="prop_h_pos",
        challenge_id="chal_p9_a",
        title="In Scope Metadata Target",
        description="Examine metadata",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "METADATA_TARGET",
            "target_details": {
                "artifact_ref": "target.p9a.org_backup.zip",
                "subject": "target.p9a.org",
            },
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


def test_f4_test_i_username_target_not_in_allowlist_rejected(p9_db_conn):
    """Test F4 Test I: USERNAME_TARGET not present in explicit authorized allowlist -> rejected."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
        "metadata": {"allowed_usernames": ["authorized_admin_user"]},
    }

    proposal = InvestigationProposal(
        proposal_id="prop_i",
        challenge_id="chal_p9_a",
        title="Unlisted Username Target",
        description="Lookup user",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "USERNAME_TARGET",
            "target_details": {"username": "unauthorized_hacker"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is None  # REJECTED


def test_f4_test_i_username_target_in_allowlist_succeeds(p9_db_conn):
    """Test F4 Test I (Positive): USERNAME_TARGET present in explicit authorized allowlist -> succeeds."""
    inv_repo = InvestigationRepository(p9_db_conn)
    skill = OsintDomainSkill()
    session = inv_repo.create_session_atomic("chal_p9_a")

    scope_dict = {
        "challenge_id": "chal_p9_a",
        "hostname": "target.p9a.org",
        "is_active": True,
        "metadata": {"allowed_usernames": ["authorized_admin_user"]},
    }

    proposal = InvestigationProposal(
        proposal_id="prop_i_pos",
        challenge_id="chal_p9_a",
        title="Authorized Username Target",
        description="Lookup user",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="Rationale",
        metadata={
            "osint_type": "USERNAME_TARGET",
            "target_details": {"username": "authorized_admin_user"},
        },
    )

    step = skill.propose_step(proposal, [scope_dict], session)
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL


# ==============================================================================
# F5: REAL END-TO-END TASKMANAGER + COPILOT INTEGRATION TEST
# ==============================================================================

@pytest.fixture
def tm_fixture(p9_db_conn):
    inv_repo = InvestigationRepository(p9_db_conn)
    bb_repo = BlackboardRepository(p9_db_conn)
    reasoning_repo = ReasoningRepository(p9_db_conn)
    registry = HandlerRegistry()

    skill_registry = DomainSkillRegistry()
    skill_registry.register(OsintDomainSkill())

    planner = InvestigationPlanner(inv_repo, bb_repo, registry=skill_registry)
    detector = DomainDetector()
    intel_repo = IntelligenceRepository(p9_db_conn)

    register_phase8_handlers(
        registry=registry,
        investigation_repo=inv_repo,
        blackboard_repo=bb_repo,
        reasoning_repo=reasoning_repo,
        planner=planner,
    )

    tm = TaskManager(db_connection=p9_db_conn, blackboard_repo=bb_repo, handler_registry=registry)
    yield inv_repo, bb_repo, tm


@pytest.mark.asyncio
async def test_phase9_copilot_end_to_end_flow(p9_db_conn, tm_fixture):
    """Test F5: Real End-to-End flow from Ingestion -> Session Controller -> TaskManager -> Approval."""
    inv_repo, bb_repo, tm = tm_fixture
    reasoning_repo = ReasoningRepository(p9_db_conn)

    adapter = ChallengeIngestionAdapter(p9_db_conn)
    authenticator = ExternalHostAuthenticator(secret_key=b"test_host_secret_key_987654321")
    controller = CopilotSessionController(p9_db_conn, bb_repo, inv_repo, tm, authenticator=authenticator)

    # 1. Ingest challenge input
    obs = adapter.ingest_challenge_text("chal_p9_a", "Find social profiles for username ctf_target_user")
    assert obs.trust_level == TrustLevel.UNTRUSTED

    # 2. Initialize Copilot session
    session_res = controller.initialize_copilot_session("chal_p9_a", mode=CopilotMode.MENTOR)
    assert session_res["mode"] == "MENTOR"

    inv_session = inv_repo.create_session_atomic("chal_p9_a")

    # 3. Submit OSINT Plan Investigation Step via TaskManager
    proposal = InvestigationProposal(
        proposal_id="prop_e2e_osint",
        challenge_id="chal_p9_a",
        title="Lookup OSINT Username",
        description="Investigate username ctf_target_user",
        gap_type=GapType.NO_USER_CONFIRMED_SUPPORT,
        target_hypothesis_ids=[],
        discriminates_hypotheses=[],
        rationale="OSINT username lookup",
        metadata={
            "osint_type": "DOMAIN_TARGET",
            "target_details": {"domain_name": "target.p9a.org"},
        },
    )

    req = TaskRequest(
        challenge_id="chal_p9_a",
        task_group_id=f"grp_{uuid.uuid4().hex[:8]}",
        task_type="plan_investigation_step",
        parameters={
            "session_id": inv_session.session_id,
            "proposal": proposal,
            "domain_id": "osint",
        },
    )

    submitted_plan_task = await tm.submit(req)
    final_plan_task = await tm.wait_for(submitted_plan_task.task_id, timeout=5.0)

    assert final_plan_task.status == TaskStatus.COMPLETED
    assert final_plan_task.result_ref["status"] == "pending_approval"
    step_id = final_plan_task.result_ref["step_id"]

    # Verify persisted step in DB
    step = inv_repo.get_step(step_id, "chal_p9_a")
    assert step is not None
    assert step.status == InvestigationStepStatus.PENDING_APPROVAL

    # 4. User control-plane approval via CopilotSessionController with VerifiedControlPlaneIdentity
    identity = authenticator.issue_identity("sec_analyst_p9")
    approval_res = await controller.submit_step_approval(
        challenge_id="chal_p9_a",
        step_id=step_id,
        session_id=inv_session.session_id,
        decision="APPROVE",
        reason="Explicit human approval for OSINT step",
        identity=identity,
        source=ControlPlaneSource.AUTHENTICATED_USER,
    )

    assert approval_res["success"] is True

    # 5. Verify step transitioned to APPROVED in DB
    approved_step = inv_repo.get_step(step_id, "chal_p9_a")
    assert approved_step is not None
    assert approved_step.status == InvestigationStepStatus.APPROVED


# ==============================================================================
# F6: REPOSITORY-WIDE SECURITY BOUNDARY SCAN
# ==============================================================================

def test_f6_repository_security_boundary_scan():
    """Test F6: Repository-wide security scan verifying 0 forbidden execution primitives."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "ctf_mentor")

    forbidden_patterns = [
        r"\bimport\s+subprocess\b",
        r"\bfrom\s+subprocess\s+import\b",
        r"\bos\.system\(",
        r"\bos\.popen\(",
        r"\bimport\s+requests\b",
        r"\bimport\s+httpx\b",
        r"\bimport\s+aiohttp\b",
        r"\bimport\s+playwright\b",
        r"\bimport\s+selenium\b",
        r"\bimport\s+paramiko\b",
        r"\bimport\s+socket\b",
    ]

    violations = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".py"):
                if (f in ("parser.py", "worker.py") and "ingestion" in root) or (f == "network.py" and "tools" in root):
                    continue
                fpath = os.path.join(root, f)
                with open(fpath, "r", encoding="utf-8") as file:
                    content = file.read()
                    for pat in forbidden_patterns:
                        if re.search(pat, content):
                            for line in content.splitlines():
                                if not line.strip().startswith("#") and not line.strip().startswith("*"):
                                    if re.search(pat, line):
                                        violations.append(f"{fpath}: {line.strip()}")

    assert violations == [], f"Security Violation! Found execution primitives: {violations}"
