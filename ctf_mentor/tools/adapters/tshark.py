"""
Phase 10B.3 — tshark Local Tool Adapter.

DESIGN NOTE: This is NOT a generic tshark command wrapper.
It supports a CLOSED set of operations. Every operation has a fixed
argv template. User/LLM input can only select from pre-enumerated
options; it can never inject raw flags, filters, or file paths into argv.

SECURITY:
- shell=False enforced by LocalSubprocessRunner (verified at runner level).
- argv assembled from typed components — no string concatenation with user input.
- Executable comes from ExecutableAllowlist.TSHARK_POLICY only.
- WIRESHARK_CONFIG_DIR overridden to an empty temp directory to prevent
  Lua script and plugin loading.
- Input validated by magic bytes before staging.
- -n flag always present to disable name resolution.
- No -i (live capture), -w (write), -D (list interfaces), -X (Lua/plugins).
- All EvidenceCandidate objects have trust='UNTRUSTED'.
- Sandboxing & Confinement: OS-level sandboxing is enforced via SandboxExecutionBoundary
  (Bubblewrap on Linux, Job Objects on Windows; Windows Job Objects provide process/resource
  containment but no kernel-level filesystem or network namespace isolation).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
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
    LocalPolicyViolation,
    LocalSubprocessPolicyViolation,
    TSHARK_POLICY,
    ToolUnavailableError,
    WorkspaceConfinementError,
)
from ctf_mentor.tools.local.network import AuditEntry, LocalSubprocessRunner
from ctf_mentor.tools.local.sandbox import TSHARK_SANDBOX_PROFILE
from ctf_mentor.workspace.capabilities import WorkspaceCapabilitySpec


# ---------------------------------------------------------------------------
# Operation Enum — CLOSED set
# ---------------------------------------------------------------------------

class TsharkOperation(str, Enum):
    """Closed set of permitted tshark operations.

    Adding new operations requires a security review.
    """
    PACKET_SUMMARY = "PACKET_SUMMARY"
    FIELD_EXTRACT = "FIELD_EXTRACT"
    PROTOCOL_FILTER = "PROTOCOL_FILTER"


# ---------------------------------------------------------------------------
# Protocol filter allowlist — user selects by key, never supplies raw BPF
# ---------------------------------------------------------------------------

_FILTER_ALLOWLIST: Dict[str, str] = {
    "http":  "http",
    "dns":   "dns",
    "tcp":   "tcp",
    "udp":   "udp",
    "icmp":  "icmp",
    "ftp":   "ftp",
    "smtp":  "smtp",
    "tls":   "tls",
    "arp":   "arp",
    "dhcp":  "dhcp",
}

# Field name allowlist — user cannot supply arbitrary field names
_FIELD_ALLOWLIST: frozenset[str] = frozenset({
    "ip.src", "ip.dst", "ip.proto",
    "tcp.port", "tcp.srcport", "tcp.dstport", "tcp.payload", "tcp.flags",
    "udp.port", "udp.srcport", "udp.dstport",
    "http.request.uri", "http.request.method", "http.host",
    "http.response.code", "http.file_data",
    "dns.qry.name", "dns.a", "dns.qry.type",
    "frame.len", "frame.time", "frame.number",
    "data.data",
    "eth.src", "eth.dst",
    "icmp.type", "icmp.code",
})

# Regex for field name format validation (defense-in-depth, allowlist is primary)
_FIELD_NAME_RE = re.compile(r"^[a-zA-Z0-9_.]+$")

# PCAP / PCAPNG magic bytes
_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",   # little-endian PCAP
    b"\xa1\xb2\xc3\xd4",   # big-endian PCAP
    b"\x0a\x0d\x0d\x0a",   # PCAPNG
    b"\x4d\x3c\xb2\xa1",   # modified PCAP LE
    b"\xa1\xb2\x3c\x4d",   # modified PCAP BE
)

# Max packets returned in PACKET_SUMMARY
_MAX_PACKET_COUNT = 500
_DEFAULT_PACKET_COUNT = 100


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------

@dataclass
class TsharkInput(ToolInputSchema):
    """
    Closed typed input for TsharkAdapter.

    Fields:
        operation:      One of TsharkOperation enum values.
        input_filename: Filename (basename only) of the artifact in input/.
        packet_count:   For PACKET_SUMMARY: number of packets to capture (1–500).
        field_name:     For FIELD_EXTRACT: one of the _FIELD_ALLOWLIST entries.
        protocol_key:   For PROTOCOL_FILTER: one of _FILTER_ALLOWLIST keys.
    """
    operation: TsharkOperation
    input_filename: str
    packet_count: int = _DEFAULT_PACKET_COUNT
    field_name: Optional[str] = None
    protocol_key: Optional[str] = None

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> "TsharkInput":
        """Validate and return a typed TsharkInput.

        Raises:
            ValueError: On any invalid field.
        """
        _check_no_unknown_keys(
            raw_args,
            {"operation", "input_filename", "packet_count",
             "field_name", "protocol_key"},
        )

        operation_raw = raw_args.get("operation")
        try:
            operation = TsharkOperation(operation_raw)
        except ValueError:
            raise ValueError(
                f"operation must be one of {[o.value for o in TsharkOperation]}, "
                f"got {operation_raw!r}"
            )

        input_filename = str(raw_args.get("input_filename", ""))
        if not input_filename:
            raise ValueError("input_filename is required")
        _validate_safe_filename(input_filename)

        packet_count = int(raw_args.get("packet_count", _DEFAULT_PACKET_COUNT))
        if not (1 <= packet_count <= _MAX_PACKET_COUNT):
            raise ValueError(
                f"packet_count must be between 1 and {_MAX_PACKET_COUNT}, "
                f"got {packet_count}"
            )

        field_name: Optional[str] = None
        if operation == TsharkOperation.FIELD_EXTRACT:
            field_name = raw_args.get("field_name")
            if not field_name:
                raise ValueError("field_name is required for FIELD_EXTRACT operation")
            _validate_field_name(field_name)

        protocol_key: Optional[str] = None
        if operation == TsharkOperation.PROTOCOL_FILTER:
            protocol_key = raw_args.get("protocol_key")
            if not protocol_key:
                raise ValueError("protocol_key is required for PROTOCOL_FILTER operation")
            if protocol_key not in _FILTER_ALLOWLIST:
                raise ValueError(
                    f"protocol_key must be one of {sorted(_FILTER_ALLOWLIST)}, "
                    f"got {protocol_key!r}"
                )

        return cls(
            operation=operation,
            input_filename=input_filename,
            packet_count=packet_count,
            field_name=field_name,
            protocol_key=protocol_key,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation.value,
            "input_filename": self.input_filename,
            "packet_count": self.packet_count,
            "field_name": self.field_name,
            "protocol_key": self.protocol_key,
        }


# ---------------------------------------------------------------------------
# TsharkAdapter
# ---------------------------------------------------------------------------

class TsharkAdapter(LocalToolAdapter):
    """
    Local adapter for tshark PCAP analysis.

    OPERATIONS (closed set):
        PACKET_SUMMARY   — structured JSON packet summary (-T json -c N)
        FIELD_EXTRACT    — extract specific allowlisted fields (-T fields -e FIELD)
        PROTOCOL_FILTER  — filter by allowlisted protocol (-T json -Y FILTER)

    NOT a generic tshark wrapper. No user-controlled flags, filters, or paths.

    Sandboxing: Enforced via SandboxExecutionBoundary with TSHARK_SANDBOX_PROFILE
    (Bubblewrap on Linux, Win32 Job Objects on Windows).
    """

    tool_id = "tshark"
    tool_version = "10B.4.0"
    execution_class = ExecutionClass.PASSIVE_LOCAL
    _ARGV_TEMPLATE_NAME = "tshark_approved_argv_v1"
    sandbox_profile = TSHARK_SANDBOX_PROFILE

    # Static class-level workspace capability spec
    workspace_capability_spec = WorkspaceCapabilitySpec(
        needs_input=True,
        needs_work_read=True,
        needs_work_write=True,
        needs_output_write=False,
        needs_output_read=False,
    )

    # Execution policy comes from the module-level constant (never user-supplied)
    execution_policy = TSHARK_POLICY

    # Required ToolAdapter protocol properties
    @property
    def domain_ids(self) -> List[str]:
        return ["network_forensics", "pcap_analysis"]

    @property
    def allowed_target_types(self) -> List[str]:
        return ["pcap_file", "pcapng_file"]

    @property
    def input_schema(self):
        return TsharkInput

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

    def validate_input(self, raw_args: Dict[str, Any]) -> TsharkInput:
        return TsharkInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        return True  # Scope validation is challenge-layer responsibility

    def execute_local(
        self,
        validated_input: TsharkInput,
        scope: Any,
        ctx: LocalExecutionContext,
    ) -> ToolResult:
        """
        Execute tshark with the approved argv for the requested operation.

        Revokes ctx.caps unconditionally in finally block.
        """
        policy = ctx.policy
        if not policy.is_available:
            ctx.caps.revoke_all()
            raise ToolUnavailableError(
                f"tshark is not available at any trusted path. "
                f"Install Wireshark/tshark and restart."
            )

        work_filename = "input.pcap"
        work_name = f"{ctx.invocation_id}/{work_filename}"
        wscfg_dir: Optional[Path] = None
        runner = LocalSubprocessRunner()

        try:
            # --- Read input artifact ---
            input_bytes = ctx.caps.input_cap.read_bytes(validated_input.input_filename)

            # --- Size limit ---
            if len(input_bytes) > policy.max_input_bytes:
                raise InputSizeLimitExceeded(
                    f"Input artifact {validated_input.input_filename!r} is "
                    f"{len(input_bytes)} bytes, exceeding the {policy.max_input_bytes} "
                    f"byte limit for tshark."
                )

            # --- Magic byte validation ---
            _validate_pcap_magic(input_bytes, validated_input.input_filename)

            # --- Stage to workspace work directory ---
            ctx.caps.work_cap.write_bytes(work_name, input_bytes)
            ctx.audit_log.append(AuditEntry(
                timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                event="INPUT_STAGED",
                invocation_id=ctx.invocation_id,
                tool_id=self.tool_id,
                details={
                    "filename_basename": validated_input.input_filename,
                    "size_bytes": len(input_bytes),
                    "work_name_basename": work_filename,
                },
            ))

            # --- Build argv with relative input filename ---
            argv = self._build_argv(
                policy.executable_path,
                work_filename,
                validated_input,
            )

            # --- Build sanitized env ---
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

            # --- Normalize output ---
            if sub_result.timed_out:
                error_status = "subprocess_timeout"
                observations: List[EvidenceCandidate] = []
            elif sub_result.exit_code not in policy.allowed_exit_codes:
                error_status = f"subprocess_exit_{sub_result.exit_code}"
                observations = []
            elif sub_result.stdout_truncated:
                error_status = "stdout_truncated"
                observations = []
            else:
                error_status = None
                observations = self.normalize(
                    sub_result.stdout_bytes,
                    {
                        "operation": validated_input.operation.value,
                        "invocation_id": ctx.invocation_id,
                        "input_filename": validated_input.input_filename,
                    },
                )

            provenance = self._build_provenance(
                ctx, sub_result,
                input_filename=validated_input.input_filename,
                input_size_bytes=len(input_bytes),
            )
            provenance["operation"] = validated_input.operation.value

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
                source=self.tool_id,
            )

        finally:
            # Unconditional cleanup inside workspace
            try:
                if wscfg_dir is not None and wscfg_dir.exists():
                    import shutil
                    shutil.rmtree(str(wscfg_dir), ignore_errors=True)
            except Exception:
                pass
            try:
                ctx.caps.work_cap.delete_file(work_name, missing_ok=True)
            except Exception:
                pass
            # Revoke capabilities — MANDATORY
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
        inp: TsharkInput,
    ) -> List[str]:
        """
        Build the exact, validated argv list for the requested operation.

        Security:
        - argv[0] is always the allowlist-resolved absolute tshark path.
        - -n is always present (disable name resolution).
        - -r is always the staged input path (workspace-controlled).
        - User input only selects operation, field (allowlisted), filter key (allowlisted).
        - No user string is ever concatenated directly into argv.
        - Forbidden flags: -i, -w, -D, -L, -X, -N (without -n override), -a, -b.
        """
        exe = str(executable_path)
        staged = staged_input_path_str

        if inp.operation == TsharkOperation.PACKET_SUMMARY:
            # argv template: tshark -n -r <file> -T json -c <count>
            return [
                exe, "-n", "-r", staged,
                "-T", "json",
                "-c", str(inp.packet_count),  # validated int, 1–500
            ]

        elif inp.operation == TsharkOperation.FIELD_EXTRACT:
            # argv template: tshark -n -r <file> -T fields -e <allowlisted_field>
            # field_name has been validated against _FIELD_ALLOWLIST
            return [
                exe, "-n", "-r", staged,
                "-T", "fields",
                "-e", inp.field_name,  # type: ignore[arg-type]  # validated
            ]

        elif inp.operation == TsharkOperation.PROTOCOL_FILTER:
            # argv template: tshark -n -r <file> -T json -Y <allowlisted_filter>
            # protocol_key has been validated against _FILTER_ALLOWLIST
            display_filter = _FILTER_ALLOWLIST[inp.protocol_key]  # type: ignore[index]
            return [
                exe, "-n", "-r", staged,
                "-T", "json",
                "-Y", display_filter,
            ]

        else:
            raise LocalSubprocessPolicyViolation(
                f"Unknown TsharkOperation: {inp.operation!r}"
            )

    def normalize(
        self,
        raw_data: Any,
        context: Dict[str, Any],
    ) -> List[EvidenceCandidate]:
        """
        Normalize tshark JSON/fields output to EvidenceCandidate list.

        All candidates have trust='UNTRUSTED'.
        Truncates to avoid overwhelming the evidence store.
        """
        operation = context.get("operation", "")
        invocation_id = context.get("invocation_id", "")
        input_filename = context.get("input_filename", "")
        observations: List[EvidenceCandidate] = []

        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode("utf-8", errors="replace")

        if not raw_data or not raw_data.strip():
            return observations

        if operation in (
            TsharkOperation.PACKET_SUMMARY.value,
            TsharkOperation.PROTOCOL_FILTER.value,
        ):
            try:
                packets = json.loads(raw_data)
                if not isinstance(packets, list):
                    packets = [packets]
                for i, pkt in enumerate(packets[:_MAX_PACKET_COUNT]):
                    summary = _summarize_packet(pkt)
                    observations.append(EvidenceCandidate(
                        source=self.tool_id,
                        observation=f"Packet {i + 1}: {summary}",
                        provenance={
                            "packet_index": i,
                            "invocation_id": invocation_id,
                            "input_filename": input_filename,
                            "operation": operation,
                        },
                        timestamp=datetime.datetime.now(datetime.timezone.utc),
                        trust="UNTRUSTED",
                    ))
            except (json.JSONDecodeError, Exception) as exc:
                # Malformed output is not a crash — record it as an observation
                observations.append(EvidenceCandidate(
                    source=self.tool_id,
                    observation=f"tshark output parse error: {type(exc).__name__}",
                    provenance={
                        "invocation_id": invocation_id,
                        "parse_error": str(exc)[:200],
                        "operation": operation,
                    },
                    timestamp=datetime.datetime.now(datetime.timezone.utc),
                    trust="UNTRUSTED",
                ))

        elif operation == TsharkOperation.FIELD_EXTRACT.value:
            lines = raw_data.splitlines()
            for i, line in enumerate(lines[:_MAX_PACKET_COUNT]):
                stripped = line.strip()
                if stripped:
                    observations.append(EvidenceCandidate(
                        source=self.tool_id,
                        observation=f"Field value [{i + 1}]: {stripped}",
                        provenance={
                            "line_index": i,
                            "invocation_id": invocation_id,
                            "input_filename": input_filename,
                            "operation": operation,
                        },
                        timestamp=datetime.datetime.now(datetime.timezone.utc),
                        trust="UNTRUSTED",
                    ))


        return observations


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _validate_pcap_magic(data: bytes, filename: str) -> None:
    """Validate PCAP magic bytes. Raises ValueError if not a recognized format."""
    if len(data) < 4:
        raise ValueError(
            f"File {filename!r} is too small to be a valid PCAP ({len(data)} bytes)"
        )
    for magic in _PCAP_MAGICS:
        if data[:4] == magic:
            return
    raise ValueError(
        f"File {filename!r} does not appear to be a PCAP/PCAPNG file "
        f"(unexpected magic bytes: {data[:4].hex()!r})"
    )


def _validate_safe_filename(filename: str) -> None:
    """Ensure filename is a safe basename with no path traversal."""
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


def _validate_field_name(field_name: str) -> None:
    """Validate tshark field name against allowlist and format regex."""
    if not _FIELD_NAME_RE.match(field_name):
        raise ValueError(
            f"field_name contains invalid characters: {field_name!r}. "
            f"Must match ^[a-zA-Z0-9_.]+$"
        )
    if field_name not in _FIELD_ALLOWLIST:
        raise ValueError(
            f"field_name {field_name!r} is not in the approved allowlist. "
            f"Allowed fields: {sorted(_FIELD_ALLOWLIST)}"
        )


def _check_no_unknown_keys(raw_args: Dict[str, Any], allowed: set) -> None:
    """Reject unexpected input keys (closed input schema enforcement)."""
    unknown = set(raw_args.keys()) - allowed
    if unknown:
        raise ValueError(
            f"Unexpected input keys: {sorted(unknown)}. "
            f"Allowed keys: {sorted(allowed)}"
        )


def _summarize_packet(pkt: Any) -> str:
    """Extract a brief human-readable summary from a tshark JSON packet."""
    if not isinstance(pkt, dict):
        return repr(pkt)[:120]
    layers = pkt.get("_source", {}).get("layers", {})
    parts = []
    frame = layers.get("frame", {})
    if frame:
        num = frame.get("frame.number", "?")
        proto = frame.get("frame.protocols", "")
        parts.append(f"#{num} [{proto}]")
    ip = layers.get("ip", {})
    if ip:
        src = ip.get("ip.src", "?")
        dst = ip.get("ip.dst", "?")
        parts.append(f"{src} → {dst}")
    tcp = layers.get("tcp", {})
    if tcp:
        sport = tcp.get("tcp.srcport", "?")
        dport = tcp.get("tcp.dstport", "?")
        parts.append(f"TCP {sport}→{dport}")
    udp = layers.get("udp", {})
    if udp:
        sport = udp.get("udp.srcport", "?")
        dport = udp.get("udp.dstport", "?")
        parts.append(f"UDP {sport}→{dport}")
    http = layers.get("http", {})
    if http:
        uri = http.get("http.request.uri", "")
        host = http.get("http.host", "")
        if uri:
            parts.append(f"HTTP {host}{uri}"[:80])
    dns = layers.get("dns", {})
    if dns:
        qname = dns.get("Queries", {})
        if isinstance(qname, dict):
            for v in qname.values():
                if isinstance(v, dict):
                    name = v.get("dns.qry.name", "")
                    if name:
                        parts.append(f"DNS {name}")
                        break
    return " | ".join(parts) if parts else repr(pkt)[:120]
