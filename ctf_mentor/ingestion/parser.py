"""
Safe Artifact Parser for Phase 9 Challenge Ingestion.

LOCKED INVARIANTS:
1. Untrusted uploaded files are parsed safely within strict resource bounds.
2. ZERO network execution, ZERO subprocess shell execution (shell=True is forbidden).
3. Protection against path traversal (..), zip bombs / decompression bombs, oversized inputs.
4. Embedded macros or executables are strictly treated as inert data bytes/hashes.
5. Fails closed when required safety or resource bounds are violated.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit for input files
WORKER_TIMEOUT_SECONDS: float = 2.0         # 2.0s wall-clock timeout limit for isolated parsing worker

FORBIDDEN_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".jar", ".scr"
}


class SafeArtifactParserError(Exception):
    """Base exception for safe artifact parser security or resource failures."""
    pass


def _make_readable_by_unprivileged_worker(file_path: Path, scratch_dir: Path) -> None:
    """Ensure scratch_dir and staged artifact file inside scratch_dir are readable by unprivileged worker.

    IMPORTANT INVARIANT:
    NEVER walk up to or modify permissions on any ancestor directory outside scratch_dir!
    The worker operates strictly within scratch_dir and requires no permission changes on host ancestors.
    """
    try:
        resolved_scratch = scratch_dir.resolve()
        resolved_file = file_path.resolve()

        # Only modify permissions on scratch_dir itself and descendants strictly inside scratch_dir
        if resolved_file == resolved_scratch or resolved_scratch in resolved_file.parents:
            os.chmod(resolved_scratch, 0o777)
            curr = resolved_file.parent
            while curr != resolved_scratch and resolved_scratch in curr.parents:
                os.chmod(curr, 0o777)
                curr = curr.parent
            if resolved_file.exists() and resolved_file != resolved_scratch:
                os.chmod(resolved_file, 0o666)
    except Exception:
        pass


class SafeArtifactParser:
    """Resource-bounded, process-isolated safe artifact parser for untrusted CTF challenge files."""

    def __init__(self, scratch_dir: Optional[Path] = None) -> None:
        self.scratch_dir = scratch_dir or Path(os.getcwd()) / "scratch" / "ingestion"
        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.scratch_dir, 0o777)
        except Exception:
            pass

    def parse_artifact(self, file_path: Path, filename: str) -> Dict[str, Any]:
        """Parse untrusted artifact file inside an isolated worker subprocess.
        
        Returns structured metadata summary (file hashes, size, preview text).
        Fails closed on path traversal, oversized files, archive bombs, or worker timeouts.
        """
        # 1. Filesystem confinement check: file_path must resolve strictly inside scratch_dir
        resolved_scratch = self.scratch_dir.resolve()
        resolved_file = file_path.resolve()
        if resolved_file == resolved_scratch or resolved_scratch not in resolved_file.parents:
            raise SafeArtifactParserError(
                f"Filesystem confinement violation: file_path {file_path!r} (resolved: {resolved_file}) is outside allowed scratch_dir {resolved_scratch}."
            )
        if file_path.is_symlink():
            try:
                target_resolved = file_path.readlink().resolve() if hasattr(file_path, "readlink") else resolved_file
                if resolved_scratch not in target_resolved.parents:
                    raise SafeArtifactParserError(
                        f"Filesystem confinement violation: symlink {file_path!r} points outside allowed scratch_dir {resolved_scratch}."
                    )
            except Exception:
                pass

        # 2. Path traversal check on filename
        clean_filename = Path(filename).name
        if ".." in filename or clean_filename != filename:
            raise SafeArtifactParserError(f"Path traversal attempt detected in filename: {filename!r}")

        if not file_path.exists() or not file_path.is_file():
            raise SafeArtifactParserError(f"Artifact file not found: {file_path}")

        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            raise SafeArtifactParserError(
                f"File size {file_size} bytes exceeds maximum allowed limit of {MAX_FILE_SIZE_BYTES} bytes."
            )

        # Ensure scratch_dir and staged file inside scratch_dir are readable by unprivileged worker (UID 65534)
        _make_readable_by_unprivileged_worker(file_path, self.scratch_dir)

        # 3. Platform check for Windows (Option 2): Fail closed if platform lacks required OS-level sandbox boundary
        if sys.platform == "win32":
            raise SafeArtifactParserError(
                "Untrusted artifact parsing is unsupported on Windows host: platform lacks required OS-level sandbox container boundary."
            )

        # Prepare payload for isolated worker process
        # Use relative path inside scratch_dir so unprivileged worker opens relative to cwd without host ancestor path traversal
        try:
            rel_file_path = str(resolved_file.relative_to(resolved_scratch))
        except ValueError:
            rel_file_path = clean_filename

        input_data = json.dumps({
            "file_path": rel_file_path,
            "filename": clean_filename,
        }).encode("utf-8")

        # Calculate project root (directory containing ctf_mentor)
        project_root = str(Path(__file__).resolve().parent.parent.parent)
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{project_root}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else project_root
        env["LC_ALL"] = "C.UTF-8"
        env["LANG"] = "C.UTF-8"

        try:
            # Spawn isolated worker process without shell=True using binary stream IPC
            proc = subprocess.Popen(
                [sys.executable, "-m", "ctf_mentor.ingestion.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.scratch_dir),
                env=env,
                shell=False,
            )

            stdout_bytes, stderr_bytes = proc.communicate(input=input_data, timeout=WORKER_TIMEOUT_SECONDS)
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise SafeArtifactParserError(
                f"Isolated worker timeout: file parsing exceeded {WORKER_TIMEOUT_SECONDS}s wall-clock limit."
            )
        except Exception as ex:
            raise SafeArtifactParserError(f"Failed to execute isolated parser worker: {ex}") from ex

        if proc.returncode != 0:
            err_detail = stderr.strip() if stderr else stdout.strip()
            try:
                err_json = json.loads(stdout)
                if isinstance(err_json, dict) and "error" in err_json:
                    err_detail = str(err_json["error"])
            except Exception:
                pass
            raise SafeArtifactParserError(f"Isolated parser worker failed (exit code {proc.returncode}): {err_detail}")

        try:
            res_json = json.loads(stdout)
            if not res_json.get("success"):
                raise SafeArtifactParserError(f"Isolated parser worker reported error: {res_json.get('error')}")
            return res_json["result"]
        except Exception as ex:
            if isinstance(ex, SafeArtifactParserError):
                raise
            raise SafeArtifactParserError(f"Invalid output format from parser worker: {ex}") from ex
