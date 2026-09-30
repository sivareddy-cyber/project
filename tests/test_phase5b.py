"""
Phase 5B Tests: SQLite persistence foundation, Blackboard repository,
optimistic concurrency, schema initialization, and event audit invariant.

Test coverage for all 20 required test cases from the architecture spec:
 1.  Database initialization
 2.  Repeated initialization (idempotent)
 3.  Foreign key enforcement
 4.  Schema version tracking
 5.  Challenge persistence (CRUD)
 6.  Blackboard version creation
 7.  Successful scoped update
 8.  Version increment
 9.  Stale-version rejection (StaleVersionError)
10.  Stale writer cannot overwrite state
11.  Rollback on failure
12.  Invalid ScopedDiff field rejection
13.  Parameterized value handling
14.  ApprovalRecord persistence
15.  ApprovalRecord lifecycle/status
16.  AuthorizedScope persistence
17.  AuthorizedScope ↔ Challenge relationship (FK enforced)
18.  Event corresponding to Blackboard mutation
19.  Repository/domain separation
20.  Deterministic concurrency behavior (two connections, not race-dependent)
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from ctf_mentor.domain.models import (
    Challenge,
    HintLevel,
    HypothesisStatus,
    ScopedDiff,
    StaleVersionError,
)
from ctf_mentor.persistence.blackboard_repo import (
    ALLOWED_BLACKBOARD_FIELDS,
    BlackboardRepository,
)
from ctf_mentor.persistence.database import (
    SCHEMA_VERSION,
    get_connection,
    initialize_schema,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_challenge(
    global_hint_level: HintLevel = HintLevel.L1,
) -> Challenge:
    now = _now()
    return Challenge(
        challenge_id=_new_id(),
        name="Test Challenge",
        description="A CTF challenge for testing",
        category="web",
        global_hint_level=global_hint_level,
        created_at=now,
        updated_at=now,
        blackboard_version=0,
        is_active=True,
        tags=["test", "web"],
        metadata={"difficulty": "easy"},
    )


def _in_memory_conn() -> sqlite3.Connection:
    """Return an initialised in-memory SQLite connection."""
    conn = get_connection(":memory:")
    initialize_schema(conn)
    return conn


def _in_memory_repo() -> tuple[sqlite3.Connection, BlackboardRepository]:
    conn = _in_memory_conn()
    repo = BlackboardRepository(conn)
    return conn, repo


# ---------------------------------------------------------------------------
# 1. Database initialization
# ---------------------------------------------------------------------------


class TestDatabaseInitialization:
    def test_initialize_creates_tables(self) -> None:
        """Initialization creates all expected tables."""
        conn = _in_memory_conn()
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        required_tables = {
            "challenges",
            "authorized_scopes",
            "blackboard_states",
            "hypotheses",
            "evidence",
            "findings",
            "attempts",
            "failed_attempts",
            "tasks",
            "task_dependencies",
            "events",
            "approval_records",
            "conflict_records",
            "hint_requests",
            "hint_candidates",
            "hint_decisions",
            "rag_queries",
            "rag_results",
            "memory_entries",
            "skill_results",
            "schema_version",
        }
        missing = required_tables - tables
        assert not missing, f"Missing tables: {missing}"

    def test_foreign_keys_pragma_enabled(self) -> None:
        """PRAGMA foreign_keys must be ON after initialization."""
        conn = _in_memory_conn()
        row = conn.execute("PRAGMA foreign_keys;").fetchone()
        assert row[0] == 1, "PRAGMA foreign_keys should be 1 (ON)"

    def test_wal_mode_enabled(self) -> None:
        """WAL journal mode must be enabled."""
        conn = _in_memory_conn()
        row = conn.execute("PRAGMA journal_mode;").fetchone()
        # :memory: databases return 'memory'; file databases return 'wal'.
        # For in-memory we accept both.
        assert row[0] in ("wal", "memory"), f"Unexpected journal_mode: {row[0]}"


# ---------------------------------------------------------------------------
# 2. Repeated initialization (idempotent / safe)
# ---------------------------------------------------------------------------


class TestRepeatedInitialization:
    def test_repeated_init_does_not_raise(self) -> None:
        """Calling initialize_schema twice must not raise."""
        conn = _in_memory_conn()
        # Second call should be a no-op
        result = initialize_schema(conn)
        assert result == SCHEMA_VERSION

    def test_repeated_init_does_not_destroy_data(self) -> None:
        """Calling initialize_schema a second time must not destroy existing rows."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch = _make_challenge()
        repo.create_challenge(ch)

        # Re-initialize
        initialize_schema(conn)

        found = repo.read_challenge(ch.challenge_id)
        assert found is not None, "Challenge was destroyed by re-initialization"
        assert found.challenge_id == ch.challenge_id


# ---------------------------------------------------------------------------
# 3. Foreign key enforcement
# ---------------------------------------------------------------------------


class TestForeignKeyEnforcement:
    def test_blackboard_state_fk_on_delete_restrict(self) -> None:
        """blackboard_states and challenges both use ON DELETE RESTRICT (H4).
        Deleting a challenge directly must fail when a blackboard_state references it.
        This is correct: the blackboard version is authoritative and should not be
        silently deleted by an external DELETE. Deletion must go through the repo.
        """
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch = _make_challenge()
        repo.create_challenge(ch)

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None

        # Direct DELETE must be rejected because blackboard_states RESTRICT deletes
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM challenges WHERE challenge_id = ?;",
                (ch.challenge_id,),
            )

    def test_authorized_scope_fk_rejects_missing_challenge(self) -> None:
        """Inserting an authorized_scope with a non-existent challenge_id must fail."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_authorized_scope(
                scope_id=_new_id(),
                challenge_id="non-existent-challenge-id",
                scheme="https",
                hostname="target.ctf.local",
                port=443,
                allowed_path_patterns=["/"],
                allowed_methods=["GET"],
                exclusions=[],
                query_restrictions={},
                environment_id="lab-1",
            )

    def test_evidence_is_fabricated_constraint(self) -> None:
        """INSERT with is_fabricated=1 must be rejected by the CHECK constraint."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch = _make_challenge()
        repo.create_challenge(ch)
        now_iso = _now().isoformat()

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO evidence (
                    evidence_id, challenge_id, hypothesis_id, source, content,
                    evidence_type, created_by, is_fabricated, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    _new_id(), ch.challenge_id, None,
                    "user_confirmed", "some content", "user_note",
                    "user", 1, "{}", now_iso,
                ),
            )


# ---------------------------------------------------------------------------
# 4. Schema version tracking
# ---------------------------------------------------------------------------


class TestSchemaVersion:
    def test_schema_version_recorded(self) -> None:
        """schema_version table must contain the current SCHEMA_VERSION."""
        conn = _in_memory_conn()
        row = conn.execute("SELECT version FROM schema_version;").fetchone()
        assert row is not None
        assert row[0] == SCHEMA_VERSION

    def test_schema_version_constant(self) -> None:
        """SCHEMA_VERSION must be a positive integer."""
        assert isinstance(SCHEMA_VERSION, int)
        assert SCHEMA_VERSION >= 1


# ---------------------------------------------------------------------------
# 5. Challenge persistence (CRUD)
# ---------------------------------------------------------------------------


class TestChallengePersistence:
    def test_create_and_read_challenge(self) -> None:
        """create_challenge then read_challenge returns identical data."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        found = repo.read_challenge(ch.challenge_id)
        assert found is not None
        assert found.challenge_id == ch.challenge_id
        assert found.name == ch.name
        assert found.category == ch.category
        assert found.global_hint_level == ch.global_hint_level
        assert found.tags == ch.tags
        assert found.metadata == ch.metadata

    def test_read_nonexistent_challenge_returns_none(self) -> None:
        _, repo = _in_memory_repo()
        assert repo.read_challenge("does-not-exist") is None

    def test_duplicate_challenge_raises(self) -> None:
        """Creating a challenge with a duplicate ID must raise IntegrityError."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_challenge(ch)


# ---------------------------------------------------------------------------
# 6. Blackboard version creation
# ---------------------------------------------------------------------------


class TestBlackboardVersionCreation:
    def test_initial_blackboard_version_is_zero(self) -> None:
        """Newly created challenge starts at blackboard_version=0."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        version = repo.read_blackboard_version(ch.challenge_id)
        assert version == 0

    def test_read_blackboard_state_initial(self) -> None:
        """Initial BlackboardState has empty lists and version 0."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.blackboard_version == 0
        assert state.active_hypothesis_ids == []
        assert state.watchlist_hypothesis_ids == []
        assert state.confirmed_findings == []
        assert state.active_evidence_ids == []
        assert state.last_hint_level == HintLevel.L0


# ---------------------------------------------------------------------------
# 7 & 8. Successful scoped update + version increment
# ---------------------------------------------------------------------------


class TestScopedUpdate:
    def test_successful_scoped_update(self) -> None:
        """apply_scoped_diff with matching version succeeds."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        diff = ScopedDiff(
            challenge_id=ch.challenge_id,
            expected_version=0,
            actor="test",
            event_type="blackboard_updated",
            changes={"session_notes": "First observation"},
        )
        new_version = repo.apply_scoped_diff(diff)
        assert new_version == 1

    def test_version_increments_after_update(self) -> None:
        """Version increments by 1 for each successful update."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        for expected, new in [(0, 1), (1, 2), (2, 3)]:
            diff = ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=expected,
                actor="test",
                event_type="blackboard_updated",
                changes={"session_notes": f"note at v{new}"},
            )
            result = repo.apply_scoped_diff(diff)
            assert result == new

    def test_state_persisted_after_update(self) -> None:
        """Changes in ScopedDiff are reflected in read_blackboard_state."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        hyp_ids = ["hyp-1", "hyp-2"]
        diff = ScopedDiff(
            challenge_id=ch.challenge_id,
            expected_version=0,
            actor="test",
            event_type="blackboard_updated",
            changes={"active_hypothesis_ids": hyp_ids, "session_notes": "updated"},
        )
        repo.apply_scoped_diff(diff)

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.blackboard_version == 1
        assert state.active_hypothesis_ids == hyp_ids
        assert state.session_notes == "updated"


# ---------------------------------------------------------------------------
# 9. Stale-version rejection
# ---------------------------------------------------------------------------


class TestStaleVersionRejection:
    def test_stale_version_raises_stale_version_error(self) -> None:
        """A diff with an outdated expected_version must raise StaleVersionError."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # Advance version to 1
        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="first_writer",
                event_type="blackboard_updated",
                changes={"session_notes": "first write"},
            )
        )

        # Stale writer still thinks version is 0
        with pytest.raises(StaleVersionError) as exc_info:
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,  # stale!
                    actor="stale_writer",
                    event_type="blackboard_updated",
                    changes={"session_notes": "stale write"},
                )
            )

        err = exc_info.value
        assert err.expected == 0
        assert err.found == 1
        assert err.challenge_id == ch.challenge_id

    def test_stale_version_error_attributes(self) -> None:
        """StaleVersionError carries correct challenge_id, expected, found."""
        err = StaleVersionError("chal-x", expected=3, found=7)
        assert err.challenge_id == "chal-x"
        assert err.expected == 3
        assert err.found == 7
        assert "chal-x" in str(err)


# ---------------------------------------------------------------------------
# 10. Stale writer cannot overwrite state
# ---------------------------------------------------------------------------


class TestStaleWriterCannotOverwrite:
    def test_stale_writer_does_not_overwrite_state(self) -> None:
        """The stale writer's data must NOT appear in the Blackboard after rejection."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # First writer succeeds
        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="writer_a",
                event_type="blackboard_updated",
                changes={"session_notes": "writer_a data"},
            )
        )

        # Stale writer fails
        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,
                    actor="stale_writer",
                    event_type="blackboard_updated",
                    changes={"session_notes": "STALE DATA - must not persist"},
                )
            )

        # Verify stale writer's data is NOT in the state
        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.session_notes == "writer_a data", (
            "Stale writer data must not overwrite state"
        )
        assert state.blackboard_version == 1


# ---------------------------------------------------------------------------
# 11. Rollback on failure
# ---------------------------------------------------------------------------


class TestRollbackOnFailure:
    def test_invalid_challenge_id_rolls_back_cleanly(self) -> None:
        """A diff for a non-existent challenge raises StaleVersionError (0 rows)."""
        _, repo = _in_memory_repo()

        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id="no-such-challenge",
                    expected_version=0,
                    actor="test",
                    event_type="blackboard_updated",
                    changes={"session_notes": "should not persist"},
                )
            )

    def test_no_partial_mutation_after_rollback(self) -> None:
        """After a failed update, the blackboard_state row must remain unchanged."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # Advance to version 1
        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="test",
                event_type="blackboard_updated",
                changes={"session_notes": "clean state"},
            )
        )

        # Stale write attempt (still expects v0)
        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,
                    actor="test",
                    event_type="blackboard_updated",
                    changes={"session_notes": "this must not persist"},
                )
            )

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.session_notes == "clean state"
        assert state.blackboard_version == 1


# ---------------------------------------------------------------------------
# 12. Invalid ScopedDiff field rejection
# ---------------------------------------------------------------------------


class TestScopedDiffFieldWhitelist:
    def test_disallowed_field_raises_value_error(self) -> None:
        """A ScopedDiff containing a disallowed field must raise ValueError."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        with pytest.raises(ValueError, match="disallowed field"):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,
                    actor="test",
                    event_type="blackboard_updated",
                    changes={"challenge_id": "injection-attempt"},
                )
            )

    def test_sql_injection_field_name_rejected(self) -> None:
        """A field name that looks like SQL must be rejected before SQL execution."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        with pytest.raises(ValueError, match="disallowed field"):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,
                    actor="test",
                    event_type="blackboard_updated",
                    changes={
                        "session_notes = 'x'; DROP TABLE challenges; --": "bad"
                    },
                )
            )

    def test_allowed_fields_accepted(self) -> None:
        """All ALLOWED_BLACKBOARD_FIELDS must be accepted by apply_scoped_diff."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # Test one allowed field update per version step
        valid_changes = [
            {"session_notes": "hello"},
            {"active_hypothesis_ids": ["h1"]},
            {"watchlist_hypothesis_ids": ["h2"]},
            {"confirmed_findings": ["f1"]},
            {"active_evidence_ids": ["e1"]},
            {"last_hint_level": 2},
            {"metadata": {"key": "value"}},
        ]
        for i, changes in enumerate(valid_changes):
            diff = ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=i,
                actor="test",
                event_type="blackboard_updated",
                changes=changes,
            )
            new_v = repo.apply_scoped_diff(diff)
            assert new_v == i + 1

    def test_allowed_blackboard_fields_whitelist_is_complete(self) -> None:
        """Verify the whitelist contains the expected set of mutable fields."""
        assert "session_notes" in ALLOWED_BLACKBOARD_FIELDS
        assert "active_hypothesis_ids" in ALLOWED_BLACKBOARD_FIELDS
        assert "watchlist_hypothesis_ids" in ALLOWED_BLACKBOARD_FIELDS
        assert "confirmed_findings" in ALLOWED_BLACKBOARD_FIELDS
        assert "active_evidence_ids" in ALLOWED_BLACKBOARD_FIELDS
        assert "last_hint_level" in ALLOWED_BLACKBOARD_FIELDS
        assert "metadata" in ALLOWED_BLACKBOARD_FIELDS
        # Immutable / identity fields must NOT be in the whitelist
        assert "challenge_id" not in ALLOWED_BLACKBOARD_FIELDS
        assert "blackboard_version" not in ALLOWED_BLACKBOARD_FIELDS


# ---------------------------------------------------------------------------
# 13. Parameterized value handling
# ---------------------------------------------------------------------------


class TestParameterizedValues:
    def test_sql_injection_value_is_stored_literally(self) -> None:
        """SQL injection in a value must be stored as literal text, not executed."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        malicious_value = "'; DROP TABLE challenges; --"
        diff = ScopedDiff(
            challenge_id=ch.challenge_id,
            expected_version=0,
            actor="test",
            event_type="blackboard_updated",
            changes={"session_notes": malicious_value},
        )
        repo.apply_scoped_diff(diff)

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.session_notes == malicious_value, (
            "Value must be stored as literal text, not executed"
        )

        # challenges table must still exist
        found = repo.read_challenge(ch.challenge_id)
        assert found is not None, "challenges table must still exist after injection attempt"

    def test_unicode_and_special_chars_stored_correctly(self) -> None:
        """Unicode and special characters in values must round-trip correctly."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        value = "🚩 CTF: <script>alert('xss')</script> \x00 null-byte test"
        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="test",
                event_type="blackboard_updated",
                changes={"session_notes": value},
            )
        )

        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.session_notes == value


# ---------------------------------------------------------------------------
# 14. ApprovalRecord persistence
# ---------------------------------------------------------------------------


class TestApprovalRecordPersistence:
    def test_create_approval_record(self) -> None:
        """Creating an ApprovalRecord persists all required fields."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        approval_id = _new_id()
        repo.create_approval_record(
            approval_id=approval_id,
            challenge_id=ch.challenge_id,
            approval_type="l6_walkthrough",
            requested_by="user",
            requested_action_ref="hint_request_42",
            status="requested",
        )

        record = repo.read_approval_record(approval_id)
        assert record is not None
        assert record["approval_id"] == approval_id
        assert record["challenge_id"] == ch.challenge_id
        assert record["approval_type"] == "l6_walkthrough"
        assert record["requested_by"] == "user"
        assert record["requested_action_ref"] == "hint_request_42"
        assert record["status"] == "requested"
        assert record["resolved_at"] is None
        assert record["resolved_by"] is None

    def test_read_nonexistent_approval_record(self) -> None:
        _, repo = _in_memory_repo()
        assert repo.read_approval_record("no-such-id") is None

    def test_approval_record_fk_requires_valid_challenge(self) -> None:
        """ApprovalRecord with a non-existent challenge_id must fail."""
        _, repo = _in_memory_repo()
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_approval_record(
                approval_id=_new_id(),
                challenge_id="ghost-challenge",
                approval_type="environment_action",
                requested_by="user",
                requested_action_ref="action-ref",
            )


# ---------------------------------------------------------------------------
# 15. ApprovalRecord lifecycle / status transitions
# ---------------------------------------------------------------------------


class TestApprovalRecordLifecycle:
    def _create_approval(self, repo: BlackboardRepository, ch: Challenge) -> str:
        approval_id = _new_id()
        repo.create_approval_record(
            approval_id=approval_id,
            challenge_id=ch.challenge_id,
            approval_type="environment_action",
            requested_by="user",
            requested_action_ref="action-ref",
            status="requested",
        )
        return approval_id

    def test_status_transition_to_approved(self) -> None:
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)
        aid = self._create_approval(repo, ch)

        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(
            approval_id=aid,
            new_status="approved",
            resolved_by="admin",
            decision_reason="Looks safe",
        )

        record = repo.read_approval_record(aid)
        assert record["status"] == "approved"
        assert record["resolved_by"] == "admin"
        assert record["decision_reason"] == "Looks safe"
        assert record["resolved_at"] is not None

    def test_status_transition_to_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)
        aid = self._create_approval(repo, ch)

        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(
            approval_id=aid,
            new_status="rejected",
            resolved_by="admin",
            decision_reason="Out of scope",
        )

        record = repo.read_approval_record(aid)
        assert record["status"] == "rejected"
        assert record["decision_reason"] == "Out of scope"

    def test_all_approval_statuses_are_valid_in_db(self) -> None:
        """All locked ApprovalStatus values must satisfy the CHECK constraint."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # requested -> pending -> approved
        aid1 = _new_id()
        repo.create_approval_record(
            approval_id=aid1, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref-1", status="requested",
        )
        repo.update_approval_record_status(aid1, "pending")
        repo.update_approval_record_status(aid1, "approved",
                                           resolved_by="admin", decision_reason="ok")
        assert repo.read_approval_record(aid1)["status"] == "approved"

        # requested -> pending -> rejected
        aid2 = _new_id()
        repo.create_approval_record(
            approval_id=aid2, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref-2", status="requested",
        )
        repo.update_approval_record_status(aid2, "pending")
        repo.update_approval_record_status(aid2, "rejected",
                                           resolved_by="admin", decision_reason="no")
        assert repo.read_approval_record(aid2)["status"] == "rejected"

        # requested -> pending -> expired
        aid3 = _new_id()
        repo.create_approval_record(
            approval_id=aid3, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref-3", status="requested",
        )
        repo.update_approval_record_status(aid3, "pending")
        repo.update_approval_record_status(aid3, "expired",
                                           resolved_by="system", decision_reason="timeout")
        assert repo.read_approval_record(aid3)["status"] == "expired"

        # requested -> pending -> cancelled
        aid4 = _new_id()
        repo.create_approval_record(
            approval_id=aid4, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref-4", status="requested",
        )
        repo.update_approval_record_status(aid4, "pending")
        repo.update_approval_record_status(aid4, "cancelled",
                                           resolved_by="user", decision_reason="withdrawn")
        assert repo.read_approval_record(aid4)["status"] == "cancelled"

    def test_invalid_approval_status_rejected_by_db(self) -> None:
        """An invalid status value must be rejected by the CHECK constraint."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        repo = BlackboardRepository(conn)
        repo.create_challenge(ch)

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO approval_records (
                    approval_id, challenge_id, approval_type, requested_by,
                    requested_action_ref, status, requested_at, decision_reason
                ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), '');
                """,
                (
                    _new_id(), ch.challenge_id, "environment_action",
                    "user", "ref", "INVALID_STATUS",
                ),
            )


# ---------------------------------------------------------------------------
# 16. AuthorizedScope persistence
# ---------------------------------------------------------------------------


class TestAuthorizedScopePersistence:
    def _create_scope(
        self, repo: BlackboardRepository, challenge_id: str
    ) -> str:
        scope_id = _new_id()
        repo.create_authorized_scope(
            scope_id=scope_id,
            challenge_id=challenge_id,
            scheme="https",
            hostname="target.ctf.local",
            port=443,
            allowed_path_patterns=["/api/*", "/flag"],
            allowed_methods=["GET", "POST"],
            exclusions=["/admin/*"],
            query_restrictions={"q": ["safe"]},
            environment_id="lab-env-1",
            challenge_relationship="primary_target",
            is_active=True,
            metadata={"notes": "test scope"},
        )
        return scope_id

    def test_create_and_read_authorized_scope(self) -> None:
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        scope_id = self._create_scope(repo, ch.challenge_id)
        scope = repo.read_authorized_scope(scope_id)

        assert scope is not None
        assert scope["scope_id"] == scope_id
        assert scope["challenge_id"] == ch.challenge_id
        assert scope["scheme"] == "https"
        assert scope["hostname"] == "target.ctf.local"
        assert scope["port"] == 443
        assert scope["environment_id"] == "lab-env-1"
        assert scope["challenge_relationship"] == "primary_target"

    def test_authorized_scope_json_fields_round_trip(self) -> None:
        """JSON array / object fields must round-trip correctly."""
        import json as _json

        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)
        scope_id = self._create_scope(repo, ch.challenge_id)
        scope = repo.read_authorized_scope(scope_id)

        assert _json.loads(scope["allowed_path_patterns"]) == ["/api/*", "/flag"]
        assert _json.loads(scope["allowed_methods"]) == ["GET", "POST"]
        assert _json.loads(scope["exclusions"]) == ["/admin/*"]
        assert _json.loads(scope["query_restrictions"]) == {"q": ["safe"]}

    def test_read_nonexistent_scope_returns_none(self) -> None:
        _, repo = _in_memory_repo()
        assert repo.read_authorized_scope("no-scope") is None


# ---------------------------------------------------------------------------
# 17. AuthorizedScope ↔ Challenge FK relationship
# ---------------------------------------------------------------------------


class TestAuthorizedScopeChallengeFk:
    def test_scope_restrict_prevents_direct_challenge_delete(self) -> None:
        """Deleting a challenge with active scopes must fail due to RESTRICT FK (H2)."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch = _make_challenge()
        repo.create_challenge(ch)

        scope_id = _new_id()
        repo.create_authorized_scope(
            scope_id=scope_id,
            challenge_id=ch.challenge_id,
            scheme="http",
            hostname="target.ctf.local",
            port=80,
            allowed_path_patterns=["/"],
            allowed_methods=["GET"],
            exclusions=[],
            query_restrictions={},
            environment_id="lab-1",
        )

        # RESTRICT: direct delete must raise IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM challenges WHERE challenge_id = ?;",
                (ch.challenge_id,),
            )

        assert repo.read_authorized_scope(scope_id) is not None

    def test_multiple_auxiliary_scopes_for_same_challenge(self) -> None:
        """A challenge may have multiple auxiliary AuthorizedScope rows.
        Only one active primary_target per challenge is allowed (H2)."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        # One primary_target
        repo.create_authorized_scope(
            scope_id=_new_id(),
            challenge_id=ch.challenge_id,
            scheme="http",
            hostname="target.ctf.local",
            port=80,
            allowed_path_patterns=["/"],
            allowed_methods=["GET"],
            exclusions=[],
            query_restrictions={},
            environment_id="lab-1",
            challenge_relationship="primary_target",
        )

        # Multiple auxiliary scopes are allowed
        for port in (8080, 9090):
            repo.create_authorized_scope(
                scope_id=_new_id(),
                challenge_id=ch.challenge_id,
                scheme="http",
                hostname="aux.ctf.local",
                port=port,
                allowed_path_patterns=["/"],
                allowed_methods=["GET"],
                exclusions=[],
                query_restrictions={},
                environment_id="lab-1",
                challenge_relationship="auxiliary",
            )

        scopes = repo.read_authorized_scopes_for_challenge(ch.challenge_id)
        assert len(scopes) == 3


# ---------------------------------------------------------------------------
# 18. Event corresponding to Blackboard mutation
# ---------------------------------------------------------------------------


class TestEventAuditInvariant:
    def test_challenge_creation_emits_event(self) -> None:
        """Creating a challenge must produce a challenge_created event."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        events = repo.read_events_for_challenge(ch.challenge_id)
        assert len(events) >= 1
        assert any(e.event_type == "challenge_created" for e in events)

    def test_blackboard_update_emits_event(self) -> None:
        """Every apply_scoped_diff must produce a corresponding event row."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="test_actor",
                event_type="blackboard_updated",
                changes={"session_notes": "annotated"},
            )
        )

        events = repo.read_events_for_challenge(ch.challenge_id)
        update_events = [e for e in events if e.event_type == "blackboard_updated"]
        assert len(update_events) == 1
        ev = update_events[0]
        assert ev.blackboard_version_after == 1
        assert ev.actor == "test_actor"
        assert ev.challenge_id == ch.challenge_id

    def test_multiple_updates_each_emit_event(self) -> None:
        """Three updates → three update events (plus creation event)."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        for i in range(3):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=i,
                    actor="test",
                    event_type="blackboard_updated",
                    changes={"session_notes": f"note {i}"},
                )
            )

        events = repo.read_events_for_challenge(ch.challenge_id)
        update_events = [e for e in events if e.event_type == "blackboard_updated"]
        assert len(update_events) == 3

        # Versions should be 1, 2, 3
        version_afters = sorted(e.blackboard_version_after for e in update_events)
        assert version_afters == [1, 2, 3]

    def test_stale_write_does_not_emit_event(self) -> None:
        """A rejected stale write must NOT produce an event."""
        _, repo = _in_memory_repo()
        ch = _make_challenge()
        repo.create_challenge(ch)

        repo.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="writer_a",
                event_type="blackboard_updated",
                changes={"session_notes": "first"},
            )
        )

        events_before = repo.read_events_for_challenge(ch.challenge_id)

        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,  # stale
                    actor="stale_writer",
                    event_type="blackboard_updated",
                    changes={"session_notes": "stale"},
                )
            )

        events_after = repo.read_events_for_challenge(ch.challenge_id)
        assert len(events_after) == len(events_before), (
            "Stale write must not add an event"
        )


# ---------------------------------------------------------------------------
# 19. Repository / domain separation
# ---------------------------------------------------------------------------


class TestRepositoryDomainSeparation:
    def test_domain_models_have_no_sql_imports(self) -> None:
        """The domain.models module must not import sqlite3 or any ORM."""
        import ast
        import importlib.util
        from pathlib import Path

        models_path = Path(__file__).parent.parent / "ctf_mentor" / "domain" / "models.py"
        source = models_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        banned = {"sqlite3", "aiosqlite", "sqlalchemy", "peewee", "tortoise"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else ([node.module] if node.module else [])
                )
                for name in names:
                    assert name not in banned and not any(
                        name.startswith(b) for b in banned
                    ), f"domain/models.py must not import {name!r}"

    def test_challenge_is_pure_dataclass(self) -> None:
        """Challenge is a pure dataclass with no persistence methods."""
        from dataclasses import fields
        ch = _make_challenge()
        # Must have dataclass fields
        field_names = {f.name for f in fields(ch)}
        assert "challenge_id" in field_names
        assert "blackboard_version" in field_names
        # Must not have SQL methods
        for attr in dir(ch):
            if attr.startswith("_"):
                continue
            val = getattr(type(ch), attr, None)
            if callable(val):
                source = getattr(val, "__doc__", "") or ""
                assert "sqlite" not in source.lower(), (
                    f"domain model method {attr!r} must not reference sqlite"
                )

    def test_blackboard_repo_does_not_expose_raw_sql(self) -> None:
        """BlackboardRepository must not expose any raw SQL as a public attribute."""
        _, repo = _in_memory_repo()
        public_attrs = [a for a in dir(repo) if not a.startswith("_")]
        for attr in public_attrs:
            val = getattr(repo, attr)
            if isinstance(val, str):
                assert "SELECT" not in val.upper() and "INSERT" not in val.upper(), (
                    f"Public attribute {attr!r} must not contain raw SQL"
                )


# ---------------------------------------------------------------------------
# 20. Deterministic concurrency behavior (two connections, no race sleeps)
# ---------------------------------------------------------------------------


class TestDeterministicConcurrency:
    def test_two_writers_same_version_only_one_succeeds(self, tmp_path: Any) -> None:
        """With two separate SQLite connections at version 0, only one update succeeds.

        This test is fully deterministic: we serialise the writes.
        Writer A goes first and wins. Writer B then finds version=1 and raises
        StaleVersionError. The test does NOT rely on timing or thread races.
        """
        db_path = tmp_path / "concurrency_test.db"

        conn_a = get_connection(str(db_path))
        initialize_schema(conn_a)
        repo_a = BlackboardRepository(conn_a)

        conn_b = get_connection(str(db_path))
        _apply_pragmas_reuse(conn_b)
        repo_b = BlackboardRepository(conn_b)

        # Both repos share the same file DB; create challenge via A
        ch = _make_challenge()
        repo_a.create_challenge(ch)

        # Both readers see version 0 (read before either writes)
        assert repo_a.read_blackboard_version(ch.challenge_id) == 0
        assert repo_b.read_blackboard_version(ch.challenge_id) == 0

        # Writer A applies the update first → succeeds
        new_v_a = repo_a.apply_scoped_diff(
            ScopedDiff(
                challenge_id=ch.challenge_id,
                expected_version=0,
                actor="writer_a",
                event_type="blackboard_updated",
                changes={"session_notes": "writer_a"},
            )
        )
        assert new_v_a == 1

        # Writer B still expects version 0 → must raise StaleVersionError
        with pytest.raises(StaleVersionError) as exc_info:
            repo_b.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=0,
                    actor="writer_b",
                    event_type="blackboard_updated",
                    changes={"session_notes": "writer_b - must not win"},
                )
            )

        err = exc_info.value
        assert err.expected == 0
        assert err.found == 1

        # Final state must reflect only writer_a's data
        final_state = repo_a.read_blackboard_state(ch.challenge_id)
        assert final_state is not None
        assert final_state.session_notes == "writer_a"
        assert final_state.blackboard_version == 1

        conn_a.close()
        conn_b.close()

    def test_sequential_writers_both_succeed(self, tmp_path: Any) -> None:
        """Sequential writes with correct version tracking all succeed."""
        db_path = tmp_path / "sequential.db"

        conn = get_connection(str(db_path))
        initialize_schema(conn)
        repo = BlackboardRepository(conn)

        ch = _make_challenge()
        repo.create_challenge(ch)

        # 5 sequential updates, each reading the current version first
        for _ in range(5):
            current_v = repo.read_blackboard_version(ch.challenge_id)
            new_v = repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ch.challenge_id,
                    expected_version=current_v,
                    actor="sequential_writer",
                    event_type="blackboard_updated",
                    changes={"session_notes": f"step {current_v}"},
                )
            )
            assert new_v == current_v + 1

        assert repo.read_blackboard_version(ch.challenge_id) == 5
        conn.close()


# ---------------------------------------------------------------------------
# Helper for concurrency test
# ---------------------------------------------------------------------------


def _apply_pragmas_reuse(conn: sqlite3.Connection) -> None:
    """Re-apply pragmas on a reused connection (no schema init needed)."""
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
