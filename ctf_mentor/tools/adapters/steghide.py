"""
Phase 10B.3 — steghide Local Tool Adapter.

DESIGN: Closed set of operations (EXTRACT, INFO). EMBED is permanently
excluded from this adapter and must not be added without a dedicated
security review.

SECURITY:
- Passphrase is passed via -p argument (shell=False, no shell injection risk).
- KNOWN LIMITATION: On Linux, passphrase is visible in /proc/<pid>/cmdline
  during steghide execution (window ~100ms for typical CTF files). CTF
  passphrases are puzzle elements, not system credentials. This is documented
  and accepted at LOW severity per adversarial review ADV-002.
- Passphrase is NEVER written to: ToolResult.provenance, EvidenceCandidate,
  log messages, or any field of ToolResult.
- _scrub_secrets() is applied post-hoc to provenance as defense-in-depth.
- Supported input formats validated by magic bytes: JPEG, BMP, WAV, AU.
- EMBED operation is permanently excluded.
- All EvidenceCandidate trust='UNTRUSTED'.
- Sandboxing & Confinement: OS-level sandboxing is enforced via SandboxExecutionBoundary
  (Bubblewrap on Linux, Win32 Job Objects on Windows; Windows Job Objects provide process/resource
  containment but no kernel-level filesystem or network namespace isolation).
"""

from __future__ import annotations

import datetime
import hashlib
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ctf_mentor.tools.contracts import (
    EvidenceCandidate,
    ExecutionClass,
    ToolInputSchema,
    ToolResult,
)
from ctf_mentor.tools.local.adapter import LocalExecutionContext, LocalToolAdapter
from ctf_mentor.tools.local.policy import (
    InputSizeLimitExceeded,
    LocalSubprocessPolicyViolation,
    OutputSizeLimitExceeded,
    STEGHIDE_POLICY,
    ToolUnavailableError,
    WorkspaceConfinementError,
)
from ctf_mentor.tools.local.network import AuditEntry, LocalSubprocessRunner
from ctf_mentor.tools.local.sandbox import STEGHIDE_SANDBOX_PROFILE
from ctf_mentor.workspace.capabilities import WorkspaceCapabilitySpec


# ---------------------------------------------------------------------------
# Operation Enum — CLOSED set. EMBED is permanently absent.
# ---------------------------------------------------------------------------

class SteghideOperation(str, Enum):
    """Closed set of permitted steghide operations.

    EMBED is intentionally excluded and must never be added here without a
    dedicated security review. This adapter is read-only.
    """
    EXTRACT = "EXTRACT"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# Accepted Input Formats (validated by magic bytes)
# ---------------------------------------------------------------------------

_ACCEPTED_FORMATS: Dict[str, bytes] = {
    "jpeg": b"\xff\xd8\xff",
    "bmp":  b"BM",
    "au":   b".snd",
}

# WAV has a compound magic: starts with RIFF and has WAVE at offset 8
_WAV_MAGIC_START = b"RIFF"
_WAV_MAGIC_WAVE = b"WAVE"

# Passphrase validation: printable ASCII only, no null bytes, bounded length
_MAX_PASSPHRASE_LEN = 1024
_PASSPHRASE_RE = re.compile(r"^[\x20-\x7E]+$")  # printable ASCII


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------

@dataclass
class SteghideInput(ToolInputSchema):
    """
    Closed typed input for SteghideAdapter.

    Fields:
        operation:       SteghideOperation.EXTRACT or INFO.
        input_filename:  Basename of the artifact in input/.
        passphrase:      Steghide passphrase (EXTRACT only; may be empty string).
        output_filename: Optional output filename basename for extracted data.
    """
    operation: SteghideOperation
    input_filename: str
    passphrase: str = ""
    output_filename: str = ""

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> "SteghideInput":
        _check_no_unknown_keys(
            raw_args,
            {"operation", "input_filename", "passphrase", "output_filename"},
        )

        operation_raw = raw_args.get("operation")
        try:
            operation = SteghideOperation(operation_raw)
        except ValueError:
            raise ValueError(
                f"operation must be one of {[o.value for o in SteghideOperation]}, "
                f"got {operation_raw!r}"
            )

        input_filename = str(raw_args.get("input_filename", ""))
        if not input_filename:
            raise ValueError("input_filename is required")
        _validate_safe_filename(input_filename)

        passphrase = str(raw_args.get("passphrase", ""))
        if operation == SteghideOperation.EXTRACT:
            _validate_passphrase(passphrase)

        output_filename = str(raw_args.get("output_filename", ""))
        if output_filename:
            _validate_safe_filename(output_filename)

        return cls(
            operation=operation,
            input_filename=input_filename,
            passphrase=passphrase,
            output_filename=output_filename,
        )

    def to_dict(self) -> Dict[str, Any]:
        # SECURITY: passphrase is EXCLUDED from to_dict()
        return {
            "operation": self.operation.value,
            "input_filename": self.input_filename,
            "output_filename": self.output_filename,
            # passphrase intentionally omitted
        }


# ---------------------------------------------------------------------------
# SteghideAdapter
# ---------------------------------------------------------------------------

class SteghideAdapter(LocalToolAdapter):
    """
    Local adapter for steghide steganography extraction.

    OPERATIONS (closed set, EMBED is PERMANENTLY EXCLUDED):
        EXTRACT — extract hidden payload from image/audio file
        INFO    — display steganographic metadata (no passphrase needed)

    PASSPHRASE HANDLING:
        - Passed via -p argument with shell=False (no shell injection risk).
        - Visible in /proc/<pid>/cmdline during execution (~100ms window).
          This is documented as ADV-002 LOW risk (CTF context only).
        - Never appears in ToolResult, provenance, logs, or EvidenceCandidate.
        - _scrub_secrets() applied post-hoc to provenance.

    Sandboxing: Enforced via SandboxExecutionBoundary with STEGHIDE_SANDBOX_PROFILE
    (Bubblewrap on Linux, Win32 Job Objects on Windows).
    """

    tool_id = "steghide"
    tool_version = "10B.4.0"
    execution_class = ExecutionClass.PASSIVE_LOCAL
    _ARGV_TEMPLATE_NAME = "steghide_approved_argv_v1"
    sandbox_profile = STEGHIDE_SANDBOX_PROFILE

    workspace_capability_spec = WorkspaceCapabilitySpec(
        needs_input=True,
        needs_work_read=True,
        needs_work_write=True,
        needs_output_write=False,
        needs_output_read=False,
    )

    execution_policy = STEGHIDE_POLICY

    @property
    def domain_ids(self) -> List[str]:
        return ["steganography", "file_analysis"]

    @property
    def allowed_target_types(self) -> List[str]:
        return ["jpeg_file", "bmp_file", "wav_file", "au_file"]

    @property
    def input_schema(self):
        return SteghideInput

    @property
    def requires_credentials(self) -> bool:
        return False

    @property
    def credential_ref(self) -> Optional[str]:
        return None

    @property
    def rate_limit_policy(self):
        from ctf_mentor.tools.contracts import RateLimitPolicy
        return RateLimitPolicy(
            max_requests_per_window=20,
            window_seconds=60.0,
            max_concurrent=2,
            timeout_seconds=30.0,
        )

    @property
    def network_destinations(self) -> List[str]:
        return []

    def validate_input(self, raw_args: Dict[str, Any]) -> SteghideInput:
        return SteghideInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        return True

    def execute_local(
        self,
        validated_input: SteghideInput,
        scope: Any,
        ctx: LocalExecutionContext,
    ) -> ToolResult:
        """
        Execute steghide EXTRACT or INFO.

        Passphrase is NEVER stored in provenance or any ToolResult field.
        Capabilities are revoked unconditionally in finally block.
        """
        policy = ctx.policy
        if not policy.is_available:
            ctx.caps.revoke_all()
            raise ToolUnavailableError(
                "steghide is not available at any trusted path. "
                "Install steghide and restart."
            )

        runner = LocalSubprocessRunner()

        try:
            # --- Read input ---
            input_bytes = ctx.caps.input_cap.read_bytes(validated_input.input_filename)

            if len(input_bytes) > policy.max_input_bytes:
                raise InputSizeLimitExceeded(
                    f"Input {validated_input.input_filename!r} is {len(input_bytes)} bytes, "
                    f"exceeding the {policy.max_input_bytes} byte limit for steghide."
                )

            # --- Magic byte validation ---
            fmt = _validate_steg_format(input_bytes, validated_input.input_filename)

            # Determine file extension from format
            ext_map = {"jpeg": ".jpg", "bmp": ".bmp", "wav": ".wav", "au": ".au"}
            ext = ext_map.get(fmt, ".bin")
            work_input_filename = f"input{ext}"
            work_output_filename = "extracted_output.bin"
            work_input_name = f"{ctx.invocation_id}/{work_input_filename}"
            work_output_name = f"{ctx.invocation_id}/{work_output_filename}"

            # --- Stage input to workspace work/ (via capability) ---
            ctx.caps.work_cap.write_bytes(work_input_name, input_bytes)

            ctx.audit_log.append(AuditEntry(
                timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                event="INPUT_STAGED",
                invocation_id=ctx.invocation_id,
                tool_id=self.tool_id,
                details={
                    "filename_basename": validated_input.input_filename,
                    "size_bytes": len(input_bytes),
                    "format": fmt,
                },
            ))

            # --- Build argv with relative filenames ---
            argv = self._build_argv(
                policy.executable_path,
                work_input_filename,
                work_output_filename,
                validated_input,
            )

            # --- Build env (no passphrase in env) ---
            env = runner.build_env()

            # --- Execute within authorized workspace directory via TrustedInvocationAuthority ---
            sub_result = runner.run(
                argv=argv,
                policy=policy,
                invocation_id=ctx.invocation_id,
                env=env,
                audit_log=ctx.audit_log,
                sandbox_profile=self.sandbox_profile,
            )

            # --- Collect extracted output (EXTRACT only) ---
            extracted_bytes: Optional[bytes] = None
            if (
                validated_input.operation == SteghideOperation.EXTRACT
                and not sub_result.timed_out
                and sub_result.exit_code in policy.allowed_exit_codes
                and ctx.caps.work_cap.file_exists(work_output_name)
            ):
                extracted_bytes = ctx.caps.work_cap.read_bytes(work_output_name)
                raw_size = len(extracted_bytes)
                if raw_size > policy.max_output_bytes:
                    raise OutputSizeLimitExceeded(
                        f"steghide extracted {raw_size} bytes, exceeding "
                        f"the {policy.max_output_bytes} byte limit."
                    )

            # --- Determine result status ---
            if sub_result.timed_out:
                error_status = "subprocess_timeout"
                observations: List[EvidenceCandidate] = []
            elif sub_result.exit_code not in policy.allowed_exit_codes:
                error_status = f"subprocess_exit_{sub_result.exit_code}"
                observations = []
            else:
                error_status = None
                observations = self.normalize(
                    {
                        "stdout": sub_result.stdout_bytes,
                        "extracted": extracted_bytes,
                        "operation": validated_input.operation.value,
                    },
                    {
                        "invocation_id": ctx.invocation_id,
                        "input_filename": validated_input.input_filename,
                        "format": fmt,
                    },
                )

            # --- Provenance (no passphrase) ---
            provenance = self._build_provenance(
                ctx, sub_result,
                input_filename=validated_input.input_filename,
                input_size_bytes=len(input_bytes),
            )
            provenance["operation"] = validated_input.operation.value
            provenance["input_format"] = fmt
            if extracted_bytes is not None:
                provenance["extracted_size_bytes"] = len(extracted_bytes)

            # Defense-in-depth: scrub passphrase from provenance
            # (it should not be there, but we verify)
            if validated_input.passphrase:
                self._scrub_secrets(provenance, validated_input.passphrase)

            fingerprint = hashlib.sha256(
                f"{self.tool_id}:{validated_input.operation.value}:{ctx.invocation_id}".encode()
            ).hexdigest()[:24]

            return ToolResult(
                tool_id=self.tool_id,
                tool_version=self.tool_version,
                request_id=ctx.invocation_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                authorized_target=scope,
                query_fingerprint=fingerprint,
                normalized_observations=observations,
                error_status=error_status,
                provenance=provenance,
                raw_data=extracted_bytes,  # raw extracted bytes (untrusted binary)
                source=self.tool_id,
            )

        finally:
            # Unconditional cleanup
            try:
                if 'work_input_name' in dir():
                    ctx.caps.work_cap.delete_file(work_input_name, missing_ok=True)
                if 'work_output_name' in dir():
                    ctx.caps.work_cap.delete_file(work_output_name, missing_ok=True)
            except Exception:
                pass
            ctx.caps.revoke_all()
            ctx.audit_log.append(AuditEntry(
                timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                event="CAPABILITY_REVOKED",
                invocation_id=ctx.invocation_id,
                tool_id=self.tool_id,
                details={},
            ))


    def _build_argv(
        self,
        executable_path: Path,
        staged_input_path_str: str,
        staged_output_path_str: str,
        inp: SteghideInput,
    ) -> List[str]:
        """
        Build the exact argv list for the requested operation.

        Security:
        - No user string is injected into argv except passphrase via -p
          (which is validated and passed with shell=False).
        - Forbidden args: embed, -cf, -mf, -e, -z (only extract/info permitted).
        - Output path is workspace-controlled (staging_dir).
        """
        exe = str(executable_path)

        if inp.operation == SteghideOperation.EXTRACT:
            # argv: steghide extract -sf <input> -p <passphrase> -xf <output> -f
            # -f: force overwrite of output file (staging dir is per-invocation, safe)
            argv = [
                exe, "extract",
                "-sf", staged_input_path_str,
                "-p", inp.passphrase,   # passphrase from validated SteghideInput
                "-xf", staged_output_path_str,
                "-f",
            ]
            return argv

        elif inp.operation == SteghideOperation.INFO:
            # argv: steghide info -sf <input>
            return [
                exe, "info",
                "-sf", staged_input_path_str,
            ]

        else:
            raise LocalSubprocessPolicyViolation(
                f"Unknown SteghideOperation: {inp.operation!r}"
            )

    def normalize(
        self,
        raw_data: Any,
        context: Dict[str, Any],
    ) -> List[EvidenceCandidate]:
        """
        Normalize steghide output.

        SECURITY: extracted bytes are NOT included in observation text.
        Only metadata (size, apparent type) appears in EvidenceCandidate.
        All trust='UNTRUSTED'.
        """
        invocation_id = context.get("invocation_id", "")
        input_filename = context.get("input_filename", "")
        fmt = context.get("format", "")
        operation = raw_data.get("operation", "") if isinstance(raw_data, dict) else ""
        observations: List[EvidenceCandidate] = []

        if isinstance(raw_data, dict):
            stdout_bytes = raw_data.get("stdout", b"")
            extracted = raw_data.get("extracted")
        else:
            stdout_bytes = b""
            extracted = None

        # Parse stdout lines for informational observations
        stdout_text = (
            stdout_bytes.decode("utf-8", errors="replace")
            if isinstance(stdout_bytes, bytes) else str(stdout_bytes)
        )

        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Security: do NOT echo passphrase, even if steghide prints it back
            if "passphrase" in line.lower():
                continue
            observations.append(EvidenceCandidate(
                source=self.tool_id,
                observation=f"steghide output: {line[:200]}",
                provenance={
                    "invocation_id": invocation_id,
                    "input_filename": input_filename,
                    "format": fmt,
                    "operation": operation,
                },
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                trust="UNTRUSTED",
            ))

        # Record extracted payload metadata (not raw content)
        if extracted is not None:
            apparent_type = _detect_apparent_type(extracted)
            observations.append(EvidenceCandidate(
                source=self.tool_id,
                observation=(
                    f"Extracted hidden payload: {len(extracted)} bytes, "
                    f"apparent type: {apparent_type}"
                ),
                provenance={
                    "invocation_id": invocation_id,
                    "input_filename": input_filename,
                    "extracted_size_bytes": len(extracted),
                    "apparent_type": apparent_type,
                    "operation": operation,
                },
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                trust="UNTRUSTED",
            ))


        return observations


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _validate_steg_format(data: bytes, filename: str) -> str:
    """
    Validate that data matches a supported steghide input format.

    Returns format name string on success.
    Raises ValueError on unsupported format.
    """
    if len(data) < 4:
        raise ValueError(
            f"File {filename!r} is too small for steghide analysis ({len(data)} bytes)"
        )
    # JPEG
    if data[:3] == _ACCEPTED_FORMATS["jpeg"]:
        return "jpeg"
    # BMP
    if data[:2] == _ACCEPTED_FORMATS["bmp"]:
        return "bmp"
    # AU
    if data[:4] == _ACCEPTED_FORMATS["au"]:
        return "au"
    # WAV: RIFF....WAVE
    if len(data) >= 12 and data[:4] == _WAV_MAGIC_START and data[8:12] == _WAV_MAGIC_WAVE:
        return "wav"

    magic_hex = data[:8].hex()
    raise ValueError(
        f"File {filename!r} is not a supported steghide format "
        f"(magic bytes: {magic_hex!r}). "
        f"Supported formats: JPEG, BMP, WAV, AU."
    )


def _validate_passphrase(passphrase: str) -> None:
    """
    Validate passphrase for steghide.

    Accepts empty string (steghide allows no passphrase).
    Rejects: null bytes, non-printable ASCII, overly long strings.
    Note: with shell=False, shell metacharacters in the passphrase are
    not a security concern — they are passed literally to steghide.
    We validate for sanity and to prevent accidental misuse.
    """
    if "\x00" in passphrase:
        raise ValueError("passphrase contains null byte")
    if len(passphrase) > _MAX_PASSPHRASE_LEN:
        raise ValueError(
            f"passphrase exceeds maximum length of {_MAX_PASSPHRASE_LEN} characters"
        )
    if passphrase and not _PASSPHRASE_RE.match(passphrase):
        raise ValueError(
            "passphrase contains non-printable ASCII characters. "
            "Only printable ASCII (0x20–0x7E) is accepted."
        )


def _validate_safe_filename(filename: str) -> None:
    """Ensure filename is a safe basename."""
    if not filename:
        raise ValueError("filename cannot be empty")
    if "/" in filename or "\\" in filename:
        raise WorkspaceConfinementError(
            f"filename must be a basename only, got: {filename!r}"
        )
    if ".." in filename:
        raise WorkspaceConfinementError(
            f"filename contains path traversal: {filename!r}"
        )
    if "\x00" in filename:
        raise WorkspaceConfinementError(
            f"filename contains null byte: {filename!r}"
        )


def _check_no_unknown_keys(raw_args: Dict[str, Any], allowed: set) -> None:
    unknown = set(raw_args.keys()) - allowed
    if unknown:
        raise ValueError(
            f"Unexpected input keys: {sorted(unknown)}. "
            f"Allowed keys: {sorted(allowed)}"
        )


def _detect_apparent_type(data: bytes) -> str:
    """Detect apparent file type from magic bytes of extracted content."""
    if not data:
        return "empty"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:4] == b"\x89PNG":
        return "PNG"
    if data[:2] == b"PK":
        return "ZIP/archive"
    if data[:4] == b"\x7fELF":
        return "ELF binary"
    if data[:2] in (b"MZ", b"ZM"):
        return "PE/Windows executable"
    if data[:5] == b"%PDF-":
        return "PDF"
    # Try to detect text
    try:
        sample = data[:256].decode("utf-8", errors="strict")
        if sample.isprintable() or all(c in "\r\n\t " or c.isprintable() for c in sample):
            return "text/UTF-8"
    except UnicodeDecodeError:
        pass
    return "binary/unknown"
