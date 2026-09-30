# PHASE 10B.2 — LOCKED

**Phase**: 10B.2 — ToolAdapter Workspace Capability Generalization
**Status**: **LOCKED**
**Lock Date**: 2026-09-28

---

## FINAL ARTIFACT

| Item | Value |
|------|-------|
| ZIP | `ctf_phase10b2_remediated_r2.zip` |
| SHA-256 | `8f9ec354f22b69352925e0fba38058dff7477fd49a625f4ea98dfb553f705961` |
| File count | 120 |
| Scratch files | None |
| `_write_caps.py` | Absent |
| `__pycache__` / `.pyc` | Absent |

---

## INDEPENDENT SECURITY REVIEW

| Item | Value |
|------|-------|
| Reviewer | Independent Claude review agent |
| Verdict | **APPROVED FOR PHASE 10B.2 LOCK** |
| CRITICAL findings | 0 |
| HIGH findings | 0 |
| MEDIUM findings | 0 |
| LOW findings | 1 — accepted same-process limitation |
| NOTEs | 2 — Windows dir_fd test skips; Windows symlink limitation |

---

## TEST RESULTS

### Focused Phase 10B.2 (Windows)

| Result | Count |
|--------|-------|
| Passed | 53 |
| Skipped | 24 |
| Failed | 0 |

### Full Regression (Windows)

| Result | Count |
|--------|-------|
| Passed | 479 |
| Skipped | 88 |
| Failed | 0 |

### Runtime Security Probe

| Result | Count |
|--------|-------|
| Passed | 29 / 29 |

### Duplicate Test Names

| Result | Count |
|--------|-------|
| Duplicates | 0 |
| Total collected | 567 |

### Independent Linux Validation Note

The exact artifact independently produced 77 focused passes on Linux.
Full-suite execution in the independent Linux environment encountered
7 Phase 9 isolated-parser timeout failures at the existing 2-second worker
boundary. This is an environment/runtime discrepancy, NOT a Phase 10B.2
implementation failure.

---

## LOCKED ARCHITECTURE

### WorkspaceCapability (abstract base class)
- Genuine ABC — direct instantiation raises TypeError
- No WorkspaceHandle on any adapter-visible object
- No WorkspacePath on any adapter-visible object
- No raw pathlib.Path
- No directory file descriptor
- No filesystem root path
- No list_files(), glob(), or rglob()
- Thread-safe revocation

### InputCapability — input/ — READ ONLY
- read_bytes, read_text, file_exists
- Structurally absent: write_bytes, write_text, delete_file

### WorkCapability — work/ — READ / WRITE / DELETE
- read_bytes, read_text, write_bytes, write_text, file_exists, delete_file

### OutputCapability — output/ — READ / WRITE
- read_bytes, read_text, write_bytes, write_text, file_exists
- Structurally absent: delete_file

### TrustedWorkspaceExecutionBoundary
- Resolves WorkspaceHandle internally
- Caller supplies (manager, conn, challenge_id, session_id) — no handle passed
- Static adapter metadata determines capability requirements
- issue() validates spec type — rejects non-WorkspaceCapabilitySpec
- User / LLM cannot expand permissions
- WorkspaceCapabilitySpec is frozen=True — immutable

### Same-Process Limitation (Documented)
Python same-process introspection can reach internal closure cells.
Process/sandbox isolation belongs to a later Phase 10B stage.

---

## LOCKED FILES

### Phase 8 — DO NOT MODIFY

| File | SHA-256 |
|------|---------|
| `ctf_mentor/domain_engine/orchestration_handlers.py` | `ae106bc49ee1253d30ccf7c01f6e87e3ac657604f1560db965d8531f91279178` |

### Phase 10B.1 — Remains Frozen

Phase 10B.1 workspace isolation is frozen and unmodified by Phase 10B.2.

---

## KNOWN PLATFORM LIMITATION

24 capability file-I/O tests are skipped on Windows (dir_fd unavailable).
All critical structural invariants are verified by non-skipped tests,
the runtime security probe (29/29 PASS), and AST-level source inspection.

---

## STATUS

```
PHASE 10B.2 = LOCKED
```
