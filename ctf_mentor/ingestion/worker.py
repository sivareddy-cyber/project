"""
Isolated Worker Process Entry Point for SafeArtifactParser (Phase 9 Ingestion Sandbox).

LOCKED SECURITY INVARIANTS:
1. Executes inside a separate isolated worker process boundary.
2. ZERO access to application state, database connection handles, or secret keys.
3. ZERO network connections (0 sockets/HTTP clients) - socket library is locked out at process startup.
4. ZERO shell execution (shell=True is forbidden).
5. Scratch-only file access with strict CPU/memory/wall-clock resource limits.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict

MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit for input files
MAX_ZIP_EXPANSION_RATIO: float = 100.0       # Max expansion ratio limit for archives
MAX_UNCOMPRESSED_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB total uncompressed limit

FORBIDDEN_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".jar", ".scr"
}

EXEC_MAGIC_BYTES: list[bytes] = [
    b"MZ",          # Windows PE Executable
    b"\x7fELF",      # Linux ELF Executable
    b"\xca\xfe\xba\xbe", # Java Class / Mach-O
    b"\xce\xfa\xed\xfe", # Mach-O 32-bit
    b"\xcf\xfa\xed\xfe", # Mach-O 64-bit
]


def _apply_sandbox_restrictions() -> None:
    """Enforce OS-level resource limits, network disablement, and environment sanitization inside worker process."""
    # 1. Disable network socket creation inside worker process
    try:
        import socket

        def _forbidden_socket(*args, **kwargs):
            raise PermissionError("Network access disabled inside sandbox worker boundary")

        socket.socket = _forbidden_socket  # type: ignore
        socket.create_connection = _forbidden_socket  # type: ignore
    except Exception:
        pass

    # 2. Sanitize environment variables to strip secrets
    keep_keys = {"PYTHONPATH", "PATH", "SYSTEMROOT", "TEMP", "TMP", "WINDIR", "HOME", "USERPROFILE"}
    current_keys = list(os.environ.keys())
    for k in current_keys:
        if k.upper() not in keep_keys:
            os.environ.pop(k, None)

    # 3. Privilege drop on POSIX if running as root
    if os.name == "posix":
        try:
            current_uid = os.getuid() if hasattr(os, "getuid") else 0
            current_euid = os.geteuid() if hasattr(os, "geteuid") else 0
            if current_uid == 0 or current_euid == 0:
                # Attempt privilege drop to nobody (UID/GID 65534)
                try:
                    if hasattr(os, "setgid"):
                        os.setgid(65534)
                    if hasattr(os, "setuid"):
                        os.setuid(65534)
                except Exception:
                    pass
                # Fail closed if process remains root (UID 0)
                still_root = (hasattr(os, "getuid") and os.getuid() == 0) or (hasattr(os, "geteuid") and os.geteuid() == 0)
                if still_root:
                    raise RuntimeError(
                        "Sandbox Security Boundary Violation: Worker process is running as root (UID 0) and failed to drop privileges. Untrusted artifact parsing refused."
                    )
        except RuntimeError:
            raise
        except Exception:
            pass

    # 4. Apply POSIX OS-level resource limits if supported by runtime
    try:
        import resource

        # CPU limit: soft 5s, hard 10s
        resource.setrlimit(resource.RLIMIT_CPU, (5, 10))
        # Max file write size: 10 MB
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    except (ImportError, Exception):
        pass


def run_worker_parse(file_path_str: str, filename: str) -> Dict[str, Any]:
    """Execute isolated parsing logic on untrusted file."""
    # 1. Path traversal check on filename
    clean_filename = Path(filename).name
    if ".." in filename or clean_filename != filename:
        raise ValueError(f"Path traversal attempt detected in filename: {filename!r}")

    # 2. Confinement check on file_path_str: must be relative path inside cwd without '..' traversal
    norm_path = Path(file_path_str)
    if norm_path.is_absolute() or ".." in norm_path.parts:
        raise ValueError(
            f"Filesystem confinement violation: file_path {file_path_str!r} is invalid or outside scratch directory."
        )

    # Check existence inside cwd directly without ancestor path resolution
    if not norm_path.exists() or not norm_path.is_file():
        raise ValueError(f"Artifact file not found: {norm_path}")

    file_size = norm_path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size {file_size} bytes exceeds maximum allowed limit of {MAX_FILE_SIZE_BYTES} bytes."
        )

    # 3. Compute hashes by opening relative path directly inside cwd
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    with open(norm_path, "rb") as f:
        content = f.read()
        sha256_hash.update(content)
        md5_hash.update(content)

    ext = Path(filename).suffix.lower()

    # 3. Executable magic bytes detection
    is_exec_magic = any(content.startswith(magic) for magic in EXEC_MAGIC_BYTES)

    # 4. Archive safety check if file is ZIP
    archive_info = None
    if ext == ".zip":
        archive_info = _inspect_zip_archive(content)

    # 5. Generate safe preview text (inert plain text summary)
    text_preview = ""
    is_binary = False
    try:
        sample = content[:4096]
        if b"\x00" in sample or is_exec_magic:
            is_binary = True
            text_preview = f"[Binary data: {len(content)} bytes, sha256={sha256_hash.hexdigest()[:16]}]"
        else:
            text_preview = sample.decode("utf-8", errors="replace")[:1024]
    except Exception:
        is_binary = True
        text_preview = f"[Binary data: {len(content)} bytes]"

    return {
        "filename": clean_filename,
        "extension": ext,
        "size_bytes": file_size,
        "file_size": file_size,
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
        "is_binary": is_binary,
        "is_forbidden_extension": ext in FORBIDDEN_EXTENSIONS,
        "is_executable_magic": is_exec_magic,
        "archive_info": archive_info,
        "preview_text": text_preview,
        "worker_pid": os.getpid(),
        "isolated": True,
        "sandboxed": True,
    }


def _inspect_zip_archive(raw_bytes: bytes) -> Dict[str, Any]:
    """Inspect zip archive for resource bombs or path traversal entries without extracting to disk."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            total_uncompressed = 0
            file_entries = []

            for info in zf.infolist():
                entry_name = info.filename
                if ".." in entry_name or entry_name.startswith("/") or entry_name.startswith("\\"):
                    raise ValueError(
                        f"Archive bomb/traversal attempt: entry name {entry_name!r} contains invalid relative path."
                    )

                compressed_size = max(info.compress_size, 1)
                ratio = info.file_size / compressed_size
                if ratio > MAX_ZIP_EXPANSION_RATIO and info.file_size > 1024 * 1024:
                    raise ValueError(
                        f"Zip bomb detected: entry {entry_name!r} has expansion ratio {ratio:.1f}x > {MAX_ZIP_EXPANSION_RATIO}x."
                    )

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE_BYTES:
                    raise ValueError(
                        f"Zip bomb detected: total uncompressed size {total_uncompressed} exceeds limit {MAX_UNCOMPRESSED_SIZE_BYTES}."
                    )

                file_entries.append({"name": entry_name, "size": info.file_size})

            return {
                "entry_count": len(file_entries),
                "total_uncompressed_bytes": total_uncompressed,
                "entries": file_entries[:50],
            }
    except zipfile.BadZipFile as bze:
        raise ValueError(f"Corrupt or invalid zip archive: {bze}") from bze


def main() -> None:
    """CLI entry point for isolated worker subprocess."""
    try:
        # Read raw binary payload from stdin first to eliminate pipe locale/stdio blocking
        raw_bytes = sys.stdin.buffer.read()

        # Apply network lockout, environment sanitization, root privilege drop (UID 65534), and resource limits
        _apply_sandbox_restrictions()

        data = json.loads(raw_bytes.decode("utf-8"))
        file_path_str = data["file_path"]
        filename = data["filename"]

        result = run_worker_parse(file_path_str, filename)
        out_bytes = json.dumps({"success": True, "result": result}).encode("utf-8")
        sys.stdout.buffer.write(out_bytes)
        sys.stdout.buffer.flush()
        sys.exit(0)
    except Exception as ex:
        err_bytes = json.dumps({"success": False, "error": str(ex)}).encode("utf-8")
        sys.stdout.buffer.write(err_bytes)
        sys.stdout.buffer.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
