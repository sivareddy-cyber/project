"""
Phase 10B.3 — LocalCryptoOpsAdapter (Internal Pure-Python Crypto Utility).

IMPORTANT: This is NOT CyberChef. Do not rename it CyberChef.
This is an internal crypto utility using Python stdlib and the installed
'cryptography' package. It performs no subprocess calls, no network calls,
and no dynamic module imports based on user input.

AUTHORIZED OPERATIONS (exact set from approved architecture):
    BASE64_DECODE, BASE64_ENCODE
    HEX_DECODE, HEX_ENCODE
    ROT13
    XOR_BYTES
    SHA256, SHA1, MD5
    AES_DECRYPT_CBC, AES_DECRYPT_ECB

SECURITY:
- No subprocess.Popen. Verified by tests.
- No eval, exec, compile, __import__ with user-controlled module name.
- No dynamic imports based on user input.
- No os.environ access.
- No network calls.
- All EvidenceCandidate trust='UNTRUSTED'.
- Input size bounded before processing.
- Output size bounded after processing.
- Cryptographic errors handled safely (no key/IV leakage in errors).
- AES key and IV are NEVER written to EvidenceCandidate observation or provenance.
  They are recorded as '<redacted>' in provenance after use.
"""

from __future__ import annotations

import base64
import codecs
import datetime
import hashlib
import re
import sys
from dataclasses import dataclass
from enum import Enum
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
    OutputSizeLimitExceeded,
)
from ctf_mentor.tools.local.sandbox import CRYPTO_SANDBOX_PROFILE
from ctf_mentor.workspace.capabilities import WorkspaceCapabilitySpec, NULL_CAPABILITY_SPEC


# ---------------------------------------------------------------------------
# Operation Enum — CLOSED set
# ---------------------------------------------------------------------------

class CryptoOperation(str, Enum):
    """Authorized operations for LocalCryptoOpsAdapter.

    This set is exactly what was approved in the Phase 10B.3 architecture.
    Adding operations requires architecture review.
    """
    BASE64_DECODE = "BASE64_DECODE"
    BASE64_ENCODE = "BASE64_ENCODE"
    HEX_DECODE = "HEX_DECODE"
    HEX_ENCODE = "HEX_ENCODE"
    ROT13 = "ROT13"
    XOR_BYTES = "XOR_BYTES"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5"
    AES_DECRYPT_CBC = "AES_DECRYPT_CBC"
    AES_DECRYPT_ECB = "AES_DECRYPT_ECB"


_MAX_INPUT_BYTES = 10 * 1024 * 1024   # 10 MB
_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB

# AES key sizes (16 = AES-128, 24 = AES-192, 32 = AES-256)
_VALID_AES_KEY_SIZES = frozenset({16, 24, 32})
_AES_BLOCK_SIZE = 16   # bytes


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------

@dataclass
class LocalCryptoInput(ToolInputSchema):
    """
    Closed typed input for LocalCryptoOpsAdapter.

    Fields:
        operation:   One of CryptoOperation enum values.
        data_hex:    Input data as hex string (even number of hex chars).
        key_hex:     For AES ops: key as hex string. NEVER put in provenance.
        iv_hex:      For AES-CBC: IV as hex string. NEVER put in provenance.
        xor_key_hex: For XOR_BYTES: key as hex string (1–256 bytes).
    """
    operation: CryptoOperation
    data_hex: str
    key_hex: str = ""
    iv_hex: str = ""
    xor_key_hex: str = ""

    @classmethod
    def validate(cls, raw_args: Dict[str, Any]) -> "LocalCryptoInput":
        _check_no_unknown_keys(
            raw_args,
            {"operation", "data_hex", "key_hex", "iv_hex", "xor_key_hex"},
        )

        operation_raw = raw_args.get("operation")
        try:
            operation = CryptoOperation(operation_raw)
        except ValueError:
            raise ValueError(
                f"operation must be one of {[o.value for o in CryptoOperation]}, "
                f"got {operation_raw!r}"
            )

        data_hex = str(raw_args.get("data_hex", ""))
        _validate_hex_string(data_hex, "data_hex")
        data_bytes = bytes.fromhex(data_hex)
        if len(data_bytes) > _MAX_INPUT_BYTES:
            raise InputSizeLimitExceeded(
                f"Input data is {len(data_bytes)} bytes, exceeding the "
                f"{_MAX_INPUT_BYTES} byte limit."
            )

        key_hex = str(raw_args.get("key_hex", ""))
        iv_hex = str(raw_args.get("iv_hex", ""))
        xor_key_hex = str(raw_args.get("xor_key_hex", ""))

        if operation in (CryptoOperation.AES_DECRYPT_CBC, CryptoOperation.AES_DECRYPT_ECB):
            if not key_hex:
                raise ValueError("key_hex is required for AES operations")
            _validate_hex_string(key_hex, "key_hex")
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) not in _VALID_AES_KEY_SIZES:
                raise ValueError(
                    f"AES key must be 16, 24, or 32 bytes; got {len(key_bytes)}"
                )
            if operation == CryptoOperation.AES_DECRYPT_CBC:
                if not iv_hex:
                    raise ValueError("iv_hex is required for AES_DECRYPT_CBC")
                _validate_hex_string(iv_hex, "iv_hex")
                iv_bytes = bytes.fromhex(iv_hex)
                if len(iv_bytes) != _AES_BLOCK_SIZE:
                    raise ValueError(
                        f"AES IV must be {_AES_BLOCK_SIZE} bytes; got {len(iv_bytes)}"
                    )

        if operation == CryptoOperation.XOR_BYTES:
            if not xor_key_hex:
                raise ValueError("xor_key_hex is required for XOR_BYTES")
            _validate_hex_string(xor_key_hex, "xor_key_hex")
            xor_key_bytes = bytes.fromhex(xor_key_hex)
            if not (1 <= len(xor_key_bytes) <= 256):
                raise ValueError(
                    f"XOR key must be 1–256 bytes; got {len(xor_key_bytes)}"
                )

        return cls(
            operation=operation,
            data_hex=data_hex,
            key_hex=key_hex,
            iv_hex=iv_hex,
            xor_key_hex=xor_key_hex,
        )

    def to_dict(self) -> Dict[str, Any]:
        # SECURITY: key_hex and iv_hex are EXCLUDED from to_dict()
        return {
            "operation": self.operation.value,
            "data_hex": self.data_hex,
            # key_hex, iv_hex, xor_key_hex intentionally omitted
        }


# ---------------------------------------------------------------------------
# LocalCryptoOpsAdapter
# ---------------------------------------------------------------------------

class LocalCryptoOpsAdapter(LocalToolAdapter):
    """
    Internal pure-Python crypto utility adapter for Phase 10B.3.

    NOT CyberChef. This adapter performs no subprocess calls,
    no network calls, and no dynamic module loading from user input.

    Uses Python stdlib and the installed 'cryptography' package.

    All EvidenceCandidate trust='UNTRUSTED'.
    AES keys and IVs are NEVER written to provenance or observations.

    KNOWN LIMITATION: Not an OS-level sandbox, but this adapter has no
    subprocess boundary — it executes entirely within the Python process.
    """

    tool_id = "local_crypto_ops"
    tool_version = "10B.4.0"
    execution_class = ExecutionClass.PASSIVE_LOCAL
    _ARGV_TEMPLATE_NAME = "local_crypto_no_subprocess"
    sandbox_profile = CRYPTO_SANDBOX_PROFILE

    # LocalCryptoOpsAdapter requires no workspace capabilities —
    # it operates on data passed directly in the input schema.
    workspace_capability_spec = NULL_CAPABILITY_SPEC

    # No execution policy needed (no subprocess)
    execution_policy = None

    @property
    def domain_ids(self) -> List[str]:
        return ["cryptography", "encoding", "hashing"]

    @property
    def allowed_target_types(self) -> List[str]:
        return ["bytes", "text", "hash", "cipher"]

    @property
    def input_schema(self):
        return LocalCryptoInput

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
            max_requests_per_window=100,
            window_seconds=60.0,
            max_concurrent=4,
            timeout_seconds=30.0,
        )

    @property
    def network_destinations(self) -> List[str]:
        return []

    def validate_input(self, raw_args: Dict[str, Any]) -> LocalCryptoInput:
        return LocalCryptoInput.validate(raw_args)

    def validate_scope(self, target: Any, scope: Any) -> bool:
        return True

    def execute_local(
        self,
        validated_input: LocalCryptoInput,
        scope: Any,
        ctx: LocalExecutionContext,
    ) -> ToolResult:
        """
        Execute the crypto operation purely in Python.

        No subprocess is involved. Capabilities are revoked immediately —
        this adapter declares NULL_CAPABILITY_SPEC and does not use them.
        """
        try:
            # Revoke immediately — this adapter needs no capabilities
            ctx.caps.revoke_all()

            data_bytes = bytes.fromhex(validated_input.data_hex)
            result_bytes, result_text = self._dispatch(validated_input, data_bytes)

            # Output size limit
            if result_bytes is not None and len(result_bytes) > _MAX_OUTPUT_BYTES:
                raise OutputSizeLimitExceeded(
                    f"Output is {len(result_bytes)} bytes, exceeding "
                    f"the {_MAX_OUTPUT_BYTES} byte limit."
                )

            observations = self.normalize(
                {
                    "result_bytes": result_bytes,
                    "result_text": result_text,
                    "operation": validated_input.operation.value,
                },
                {
                    "invocation_id": ctx.invocation_id,
                    "operation": validated_input.operation.value,
                },
            )

            # Provenance — keys/IVs are EXCLUDED
            provenance = {
                "invocation_id": ctx.invocation_id,
                "tool_id": self.tool_id,
                "tool_version": self.tool_version,
                "argv_template": self._ARGV_TEMPLATE_NAME,
                "workspace_id": ctx.workspace_id,
                "challenge_id": ctx.challenge_id,
                "session_id": ctx.session_id,
                "operation": validated_input.operation.value,
                "input_size_bytes": len(data_bytes),
                "output_size_bytes": (
                    len(result_bytes) if result_bytes is not None
                    else len(result_text or "")
                ),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                # Keys and IVs are intentionally excluded from provenance
                "key_used": "<redacted>" if validated_input.key_hex else "none",
                "iv_used": "<redacted>" if validated_input.iv_hex else "none",
            }

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
                error_status=None,
                provenance=provenance,
                raw_data=result_bytes,
                source=self.tool_id,
            )

        except (InputSizeLimitExceeded, OutputSizeLimitExceeded, LocalPolicyViolation):
            raise
        except Exception as exc:
            # Cryptographic errors, encoding errors, etc.
            # SECURITY: do not include key material in the error message.
            safe_msg = _sanitize_crypto_error(str(exc))
            fingerprint = hashlib.sha256(
                f"{self.tool_id}:error:{ctx.invocation_id}".encode()
            ).hexdigest()[:24]
            return ToolResult(
                tool_id=self.tool_id,
                tool_version=self.tool_version,
                request_id=ctx.invocation_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                authorized_target=scope,
                query_fingerprint=fingerprint,
                normalized_observations=[],
                error_status=f"crypto_error: {type(exc).__name__}",
                provenance={
                    "invocation_id": ctx.invocation_id,
                    "operation": validated_input.operation.value,
                    "error": safe_msg,
                },
                source=self.tool_id,
            )
        finally:
            # Ensure caps are revoked even if exception path bypassed the early revoke
            try:
                ctx.caps.revoke_all()
            except Exception:
                pass

    def _dispatch(
        self,
        inp: LocalCryptoInput,
        data: bytes,
    ) -> tuple[Optional[bytes], Optional[str]]:
        """
        Dispatch to the correct crypto operation.

        Returns (result_bytes, result_text). One of them may be None.
        SECURITY: No eval, exec, compile, or dynamic import from user input.
        """
        op = inp.operation

        if op == CryptoOperation.BASE64_DECODE:
            result = base64.b64decode(data, validate=False)
            return result, None

        elif op == CryptoOperation.BASE64_ENCODE:
            result_text = base64.b64encode(data).decode("ascii")
            return None, result_text

        elif op == CryptoOperation.HEX_DECODE:
            text = data.decode("ascii", errors="replace").strip()
            result = bytes.fromhex(re.sub(r"\s+", "", text))
            return result, None

        elif op == CryptoOperation.HEX_ENCODE:
            return None, data.hex()

        elif op == CryptoOperation.ROT13:
            text = data.decode("utf-8", errors="replace")
            result_text = codecs.encode(text, "rot_13")
            return None, result_text

        elif op == CryptoOperation.XOR_BYTES:
            key = bytes.fromhex(inp.xor_key_hex)
            key_len = len(key)
            result = bytes(b ^ key[i % key_len] for i, b in enumerate(data))
            return result, None

        elif op == CryptoOperation.SHA256:
            digest = hashlib.sha256(data).hexdigest()
            return None, digest

        elif op == CryptoOperation.SHA1:
            digest = hashlib.sha1(data).hexdigest()
            return None, digest

        elif op == CryptoOperation.MD5:
            digest = hashlib.md5(data).hexdigest()
            return None, digest

        elif op == CryptoOperation.AES_DECRYPT_CBC:
            return self._aes_decrypt(data, inp.key_hex, inp.iv_hex, mode="CBC"), None

        elif op == CryptoOperation.AES_DECRYPT_ECB:
            return self._aes_decrypt(data, inp.key_hex, "", mode="ECB"), None

        else:
            raise ValueError(f"Unhandled operation: {op!r}")

    def _aes_decrypt(
        self,
        ciphertext: bytes,
        key_hex: str,
        iv_hex: str,
        mode: str,
    ) -> bytes:
        """
        AES decryption using the 'cryptography' package.

        SECURITY: key and IV are used directly but never logged.
        """
        # Import at call time (not module import) — avoids ImportError at module load
        # if 'cryptography' is absent. The adapter will still load; errors are
        # returned as ToolResult error_status.
        try:
            from cryptography.hazmat.primitives.ciphers import (
                Cipher,
                algorithms,
                modes,
            )
            from cryptography.hazmat.backends import default_backend
        except ImportError as exc:
            raise RuntimeError(
                "The 'cryptography' package is required for AES operations but "
                f"is not installed: {exc}"
            )

        key = bytes.fromhex(key_hex)

        if mode == "CBC":
            iv = bytes.fromhex(iv_hex)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend(),
            )
        elif mode == "ECB":
            cipher = Cipher(
                algorithms.AES(key),
                modes.ECB(),
                backend=default_backend(),
            )
        else:
            raise ValueError(f"Unsupported AES mode: {mode!r}")

        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # PKCS7 unpadding (best-effort; if padding is malformed, return raw)
        try:
            pad_len = padded[-1]
            if 1 <= pad_len <= 16 and padded[-pad_len:] == bytes([pad_len] * pad_len):
                return padded[:-pad_len]
        except (IndexError, ValueError):
            pass
        return padded

    def normalize(
        self,
        raw_data: Any,
        context: Dict[str, Any],
    ) -> List[EvidenceCandidate]:
        """Normalize crypto result to EvidenceCandidate. Trust='UNTRUSTED'."""
        invocation_id = context.get("invocation_id", "")
        operation = context.get("operation", "")
        observations: List[EvidenceCandidate] = []

        if isinstance(raw_data, dict):
            result_bytes = raw_data.get("result_bytes")
            result_text = raw_data.get("result_text")
        else:
            result_bytes = None
            result_text = None

        if result_text is not None:
            # Truncate display to avoid huge observations for hash/encode ops
            display = result_text if len(result_text) <= 2000 else result_text[:2000] + "…"
            observations.append(EvidenceCandidate(
                source=self.tool_id,
                observation=f"[{operation}] result (text): {display}",
                provenance={
                    "invocation_id": invocation_id,
                    "operation": operation,
                    "result_type": "text",
                    "result_length": len(result_text),
                },
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                trust="UNTRUSTED",
            ))

        if result_bytes is not None:
            # Show hex preview, not full raw bytes (may be binary)
            preview_hex = result_bytes[:32].hex()
            observations.append(EvidenceCandidate(
                source=self.tool_id,
                observation=(
                    f"[{operation}] result (bytes): {len(result_bytes)} bytes "
                    f"| hex preview: {preview_hex}{'…' if len(result_bytes) > 32 else ''}"
                ),
                provenance={
                    "invocation_id": invocation_id,
                    "operation": operation,
                    "result_type": "bytes",
                    "result_size_bytes": len(result_bytes),
                },
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                trust="UNTRUSTED",
            ))

        return observations


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _validate_hex_string(value: str, field_name: str) -> None:
    """Validate that value is a non-empty, well-formed hex string."""
    if not value:
        raise ValueError(f"{field_name} cannot be empty")
    if len(value) % 2 != 0:
        raise ValueError(
            f"{field_name} must have an even number of hex characters, got {len(value)}"
        )
    if not re.match(r"^[0-9a-fA-F]+$", value):
        raise ValueError(
            f"{field_name} contains non-hexadecimal characters"
        )


def _check_no_unknown_keys(raw_args: Dict[str, Any], allowed: set) -> None:
    unknown = set(raw_args.keys()) - allowed
    if unknown:
        raise ValueError(
            f"Unexpected input keys: {sorted(unknown)}. "
            f"Allowed keys: {sorted(allowed)}"
        )


def _sanitize_crypto_error(msg: str) -> str:
    """
    Sanitize crypto error message to ensure key material is not leaked.

    Truncates and removes anything that looks like a hex key.
    """
    # Remove long hex strings (possible key/IV material)
    sanitized = re.sub(r"[0-9a-fA-F]{32,}", "<hex_redacted>", msg)
    return sanitized[:300]
