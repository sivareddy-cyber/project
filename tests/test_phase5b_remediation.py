"""
Phase 5B Audit Remediation Tests.

Tests new behavioral guarantees added by the audit remediation:
- H1: Approval lifecycle enforcement
- H2: AuthorizedScope validation / fail-closed
- H3: Blackboard value validation
- H4: Blackboard version consistency
- M1: Event immutability / integrity
- M2: Evidence provenance / referential integrity
- M3: Missing canonical persistence tables
- M4: Database constraints
- M5: Task retry/supersession constraint behavior
- M6: Repository / domain separation
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from ctf_mentor.domain.models import (
    ApprovalRecord,
    ApprovalStatus,
    AuthorizedScope,
    BlackboardState,
    Challenge,
    Event,
    HintLevel,
)
from ctf_mentor.persistence.blackboard_repo import (
    ALLOWED_BLACKBOARD_FIELDS,
    BlackboardRepository,
    validate_authorized_scope,
    _validate_blackboard_value,
)
from ctf_mentor.persistence.database import (
    SCHEMA_VERSION,
    assert_foreign_keys_enabled,
    get_connection,
    initialize_schema,
)
from ctf_mentor.persistence.errors import ScopedDiff, StaleVersionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _in_memory_conn() -> sqlite3.Connection:
    conn = get_connection(":memory:")
    initialize_schema(conn)
    return conn


def _in_memory_repo() -> tuple[sqlite3.Connection, BlackboardRepository]:
    conn = _in_memory_conn()
    return conn, BlackboardRepository(conn)


def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_challenge(cid: str | None = None) -> Challenge:
    now = _now()
    return Challenge(
        challenge_id=cid or _new_id(),
        name="Test Challenge",
        description="A test",
        category="web",
        global_hint_level=HintLevel.L3,
        created_at=now,
        updated_at=now,
        blackboard_version=0,
        is_active=True,
        tags=[],
        metadata={},
    )


def _create_challenge(repo: BlackboardRepository) -> Challenge:
    ch = _make_challenge()
    repo.create_challenge(ch)
    return ch


# ---------------------------------------------------------------------------
# H1 — Approval Lifecycle
# ---------------------------------------------------------------------------


class TestApprovalLifecycleH1:
    """H1: Approval lifecycle enforcement."""

    def test_valid_transition_requested_to_pending(self) -> None:
        """requested -> pending is a valid transition."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        updated = repo.update_approval_record_status(aid, "pending")
        assert isinstance(updated, ApprovalRecord)
        assert updated.status == ApprovalStatus.PENDING

    def test_valid_transition_pending_to_approved(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        repo.update_approval_record_status(aid, "pending")
        updated = repo.update_approval_record_status(
            aid, "approved", resolved_by="admin", decision_reason="ok"
        )
        assert updated.status == ApprovalStatus.APPROVED
        assert updated.resolved_by == "admin"
        assert updated.resolved_at is not None

    def test_terminal_state_cannot_be_reopened(self) -> None:
        """Approved approval cannot transition to pending."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(aid, "approved",
                                           resolved_by="admin", decision_reason="ok")
        with pytest.raises(ValueError, match="terminal"):
            repo.update_approval_record_status(aid, "pending")

    def test_terminal_state_rejected_cannot_be_changed(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(aid, "rejected",
                                           resolved_by="admin", decision_reason="no")
        with pytest.raises(ValueError, match="terminal"):
            repo.update_approval_record_status(aid, "pending")

    def test_direct_requested_to_approved_rejected(self) -> None:
        """Direct transition requested -> approved without pending must fail."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        with pytest.raises(ValueError, match="Invalid transition"):
            repo.update_approval_record_status(
                aid, "approved", resolved_by="admin", decision_reason="ok"
            )

    def test_invalid_transition_raises_value_error(self) -> None:
        """requested cannot jump directly to pending->... without going through transitions."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        with pytest.raises(ValueError, match="Invalid transition|Unknown"):
            # "requested" -> "requested" is not a valid transition
            repo.update_approval_record_status(aid, "requested")

    def test_terminal_state_requires_resolved_by(self) -> None:
        """Transitioning to approved without resolved_by must raise ValueError."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
        )
        repo.update_approval_record_status(aid, "pending")
        with pytest.raises(ValueError, match="resolved_by"):
            repo.update_approval_record_status(aid, "approved", resolved_by=None)

    def test_nonexistent_approval_raises_value_error(self) -> None:
        _, repo = _in_memory_repo()
        with pytest.raises(ValueError, match="does not exist"):
            repo.update_approval_record_status("no-such-id", "approved",
                                               resolved_by="admin")

    def test_decision_reason_preserved_if_not_replaced(self) -> None:
        """If new decision_reason is empty, the existing one must be preserved."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref", status="requested",
            decision_reason="original reason",
        )
        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(aid, "approved",
                                           resolved_by="admin", decision_reason="")
        record = repo.read_approval_record(aid)
        assert record["decision_reason"] == "original reason", (
            "decision_reason must be preserved when empty string is passed"
        )

    def test_related_event_id_must_exist(self) -> None:
        """related_event_id must reference a real event row."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="related_event_id"):
            repo.create_approval_record(
                approval_id=_new_id(), challenge_id=ch.challenge_id,
                approval_type="environment_action", requested_by="user",
                requested_action_ref="ref",
                related_event_id="nonexistent-event-id",
            )

    def test_cannot_create_with_terminal_initial_status(self) -> None:
        """Creating an ApprovalRecord with a terminal initial status must fail."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        for terminal in ("approved", "rejected", "expired", "cancelled"):
            with pytest.raises(ValueError, match="terminal"):
                repo.create_approval_record(
                    approval_id=_new_id(), challenge_id=ch.challenge_id,
                    approval_type="environment_action", requested_by="user",
                    requested_action_ref="ref", status=terminal,
                )

    def test_approval_mutation_creates_audit_event(self) -> None:
        """Both create and update of ApprovalRecord must produce audit events."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref",
        )
        repo.update_approval_record_status(aid, "pending")
        repo.update_approval_record_status(aid, "approved",
                                           resolved_by="admin", decision_reason="ok")
        events = repo.read_events_for_challenge(ch.challenge_id)
        event_types = [e.event_type for e in events]
        assert "approval_created" in event_types
        assert "approval_status_changed" in event_types

    def test_create_approval_returns_domain_object(self) -> None:
        """create_approval_record must return an ApprovalRecord domain object."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        result = repo.create_approval_record(
            approval_id=_new_id(), challenge_id=ch.challenge_id,
            approval_type="l6_walkthrough", requested_by="user",
            requested_action_ref="hint-req-99",
        )
        assert isinstance(result, ApprovalRecord)
        assert result.status == ApprovalStatus.REQUESTED

    def test_approval_optimistic_concurrency_conflict(self) -> None:
        """Two concurrent writers reading same status: second writer fails with StaleApprovalError."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            conn1 = get_connection(db_path)
            initialize_schema(conn1)
            ch = _make_challenge()
            repo1 = BlackboardRepository(conn1)
            repo1.create_challenge(ch)

            aid = _new_id()
            repo1.create_approval_record(
                approval_id=aid, challenge_id=ch.challenge_id,
                approval_type="environment_action", requested_by="user",
                requested_action_ref="ref", status="requested",
            )
            repo1.update_approval_record_status(aid, "pending")

            conn2 = get_connection(db_path)
            repo2 = BlackboardRepository(conn2)

            events_before = len(repo1.read_events_for_challenge(ch.challenge_id))

            # Writer A approves
            repo1.update_approval_record_status(
                aid, "approved", resolved_by="admin_a", decision_reason="approved by A"
            )

            # Writer B attempts to reject from 'pending' (stale read)
            from ctf_mentor.contracts import StaleApprovalError
            with pytest.raises((StaleApprovalError, ValueError)):
                repo2.update_approval_record_status(
                    aid, "rejected", resolved_by="admin_b", decision_reason="rejected by B"
                )

            # Check that winning decision is preserved
            rec = repo1.read_approval_record_domain(aid)
            assert rec is not None
            assert rec.status == ApprovalStatus.APPROVED
            assert rec.resolved_by == "admin_a"
            assert rec.decision_reason == "approved by A"

            # Check that losing writer created NO false audit event
            events_after = repo1.read_events_for_challenge(ch.challenge_id)
            assert len(events_after) == events_before + 1
            approval_events = [e for e in events_after if e.event_type == "approval_status_changed"]
            assert approval_events[-1].payload.get("to_status") == "approved"
        finally:
            conn1.close()
            conn2.close()
            os.unlink(db_path)


# ---------------------------------------------------------------------------
# H2 — AuthorizedScope Validation / Fail-Closed
# ---------------------------------------------------------------------------


class TestAuthorizedScopeH2:
    """H2: Scope validation and fail-closed behavior."""

    def test_empty_hostname_rejected(self) -> None:
        with pytest.raises(ValueError, match="hostname"):
            validate_authorized_scope(
                scheme="http", hostname="", port=80,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_invalid_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            validate_authorized_scope(
                scheme="ftp2", hostname="target.local", port=21,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_port_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="port"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=99999,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_negative_port_rejected(self) -> None:
        with pytest.raises(ValueError, match="port"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=-1,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_empty_environment_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="environment_id"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=80,
                environment_id="", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_invalid_relationship_rejected(self) -> None:
        with pytest.raises(ValueError, match="challenge_relationship"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=80,
                environment_id="env-1", challenge_relationship="super_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_non_string_path_pattern_rejected(self) -> None:
        with pytest.raises(ValueError, match="allowed_path_patterns"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=80,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=[123],  # type: ignore[list-item]
                allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
            )

    def test_non_dict_query_restrictions_rejected(self) -> None:
        with pytest.raises(ValueError, match="query_restrictions"):
            validate_authorized_scope(
                scheme="http", hostname="target.local", port=80,
                environment_id="env-1", challenge_relationship="primary_target",
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions="not-a-dict",  # type: ignore[arg-type]
            )

    def test_duplicate_active_primary_target_rejected(self) -> None:
        """Two active primary_target scopes for same challenge must be rejected at DB level."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        repo.create_authorized_scope(
            scope_id=_new_id(), challenge_id=ch.challenge_id,
            scheme="http", hostname="target.local", port=80,
            allowed_path_patterns=["/"], allowed_methods=["GET"],
            exclusions=[], query_restrictions={},
            environment_id="env-1", challenge_relationship="primary_target",
        )
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_authorized_scope(
                scope_id=_new_id(), challenge_id=ch.challenge_id,
                scheme="http", hostname="target2.local", port=80,
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
                environment_id="env-1", challenge_relationship="primary_target",
            )

    def test_fail_closed_no_scope(self) -> None:
        """has_active_authorized_scope returns False when no scope exists."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        assert repo.has_active_authorized_scope(ch.challenge_id) is False

    def test_has_active_scope_returns_true_when_exists(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        repo.create_authorized_scope(
            scope_id=_new_id(), challenge_id=ch.challenge_id,
            scheme="http", hostname="target.local", port=80,
            allowed_path_patterns=["/"], allowed_methods=["GET"],
            exclusions=[], query_restrictions={},
            environment_id="env-1",
        )
        assert repo.has_active_authorized_scope(ch.challenge_id) is True

    def test_deactivating_scope_makes_fail_closed(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        sid = _new_id()
        repo.create_authorized_scope(
            scope_id=sid, challenge_id=ch.challenge_id,
            scheme="http", hostname="target.local", port=80,
            allowed_path_patterns=["/"], allowed_methods=["GET"],
            exclusions=[], query_restrictions={},
            environment_id="env-1",
        )
        repo.deactivate_authorized_scope(sid)
        assert repo.has_active_authorized_scope(ch.challenge_id) is False

    def test_deactivation_creates_audit_event(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        sid = _new_id()
        repo.create_authorized_scope(
            scope_id=sid, challenge_id=ch.challenge_id,
            scheme="http", hostname="target.local", port=80,
            allowed_path_patterns=["/"], allowed_methods=["GET"],
            exclusions=[], query_restrictions={},
            environment_id="env-1",
        )
        repo.deactivate_authorized_scope(sid)
        events = repo.read_events_for_challenge(ch.challenge_id)
        assert any(e.event_type == "authorized_scope_deactivated" for e in events)

    def test_deactivate_nonexistent_scope_raises(self) -> None:
        _, repo = _in_memory_repo()
        with pytest.raises(ValueError, match="does not exist"):
            repo.deactivate_authorized_scope("no-such-scope")

    def test_invalid_scope_not_persisted(self) -> None:
        """A scope that fails validation must not appear in the database."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError):
            repo.create_authorized_scope(
                scope_id=_new_id(), challenge_id=ch.challenge_id,
                scheme="INVALID_SCHEME", hostname="target.local", port=80,
                allowed_path_patterns=["/"], allowed_methods=["GET"],
                exclusions=[], query_restrictions={},
                environment_id="env-1",
            )
        scopes = repo.read_authorized_scopes_for_challenge(ch.challenge_id)
        assert len(scopes) == 0, "Invalid scope must not be persisted"


# ---------------------------------------------------------------------------
# H3 — Blackboard Value Validation
# ---------------------------------------------------------------------------


class TestBlackboardValueValidationH3:
    """H3: Per-field value validation before SQL."""

    def test_more_than_3_active_hypotheses_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="exceeds maximum"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"active_hypothesis_ids": ["h1", "h2", "h3", "h4"]},
            ))

    def test_exactly_3_active_hypotheses_allowed(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        new_v = repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={"active_hypothesis_ids": ["h1", "h2", "h3"]},
        ))
        assert new_v == 1

    def test_hint_level_out_of_range_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="last_hint_level"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"last_hint_level": 7},
            ))

    def test_negative_hint_level_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="last_hint_level"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"last_hint_level": -1},
            ))

    def test_wrong_type_for_session_notes_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="session_notes"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"session_notes": 12345},  # type: ignore[dict-item]
            ))

    def test_wrong_type_for_list_field_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="active_hypothesis_ids"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"active_hypothesis_ids": "not-a-list"},  # type: ignore[dict-item]
            ))

    def test_wrong_type_for_metadata_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="metadata"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"metadata": ["not", "a", "dict"]},  # type: ignore[dict-item]
            ))

    def test_non_string_items_in_list_rejected(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        with pytest.raises(ValueError, match="active_hypothesis_ids"):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"active_hypothesis_ids": [1, 2]},  # type: ignore[list-item]
            ))

    def test_valid_update_still_succeeds(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        v = repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={
                "session_notes": "valid notes",
                "last_hint_level": 3,
                "active_hypothesis_ids": ["h1"],
                "metadata": {"k": "v"},
            },
        ))
        assert v == 1

    def test_invalid_value_leaves_db_unchanged(self) -> None:
        """An invalid value must not leave the DB in a partially-mutated state."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        original_state = repo.read_blackboard_state(ch.challenge_id)
        assert original_state is not None
        original_version = original_state.blackboard_version

        with pytest.raises(ValueError):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="test", event_type="update",
                changes={"active_hypothesis_ids": ["h1", "h2", "h3", "h4"]},
            ))

        state_after = repo.read_blackboard_state(ch.challenge_id)
        assert state_after is not None
        assert state_after.blackboard_version == original_version
        assert state_after.active_hypothesis_ids == original_state.active_hypothesis_ids


# ---------------------------------------------------------------------------
# H4 — Blackboard Version Consistency
# ---------------------------------------------------------------------------


class TestBlackboardVersionConsistencyH4:
    """H4: Single authoritative version in blackboard_states."""

    def test_initial_versions_agree(self) -> None:
        """At creation, blackboard_states.blackboard_version must be 0."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        bs_version = repo.read_blackboard_version(ch.challenge_id)
        assert bs_version == 0

    def test_challenge_read_reflects_authoritative_version(self) -> None:
        """read_challenge must return the version from blackboard_states."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        # Apply an update to increment version
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={"session_notes": "v1"},
        ))
        read_ch = repo.read_challenge(ch.challenge_id)
        assert read_ch is not None
        assert read_ch.blackboard_version == 1, (
            "read_challenge must reflect authoritative version from blackboard_states"
        )

    def test_version_increments_exactly_once_per_mutation(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        for i in range(5):
            v = repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=i,
                actor="test", event_type="update",
                changes={"session_notes": f"step {i}"},
            ))
            assert v == i + 1

        final = repo.read_blackboard_version(ch.challenge_id)
        assert final == 5

    def test_stale_writer_cannot_overwrite(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="writer_a", event_type="update",
            changes={"session_notes": "writer_a was here"},
        ))
        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="writer_b", event_type="update",
                changes={"session_notes": "writer_b MUST NOT overwrite"},
            ))
        state = repo.read_blackboard_state(ch.challenge_id)
        assert state is not None
        assert state.session_notes == "writer_a was here"
        assert state.blackboard_version == 1

    def test_versions_cannot_diverge(self) -> None:
        """After N mutations, both read_blackboard_version and read_blackboard_state
        must report the same version N."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        N = 3
        for i in range(N):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=i,
                actor="test", event_type="update",
                changes={"session_notes": f"step {i}"},
            ))
        v1 = repo.read_blackboard_version(ch.challenge_id)
        bs = repo.read_blackboard_state(ch.challenge_id)
        assert bs is not None
        assert v1 == N
        assert bs.blackboard_version == N, "Versions must not diverge"

    def test_only_one_version_column_is_authoritative(self) -> None:
        """challenges table must NOT have a mutable blackboard_version column."""
        conn = _in_memory_conn()
        row = conn.execute("PRAGMA table_info(challenges);").fetchall()
        col_names = [r["name"] for r in row]
        assert "blackboard_version" not in col_names, (
            "challenges table must not have blackboard_version column (H4); "
            "version lives in blackboard_states only"
        )


# ---------------------------------------------------------------------------
# M1 — Event Immutability / Integrity
# ---------------------------------------------------------------------------


class TestEventImmutabilityM1:
    """M1: Event immutability enforced at DB level via triggers."""

    def _create_event_id(self, repo: BlackboardRepository, ch: Challenge) -> str:
        """Apply a diff to generate an event and return its event_id."""
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="blackboard_updated",
            changes={"session_notes": "test"},
        ))
        events = repo.read_events_for_challenge(ch.challenge_id)
        return next(e.event_id for e in events
                    if e.event_type == "blackboard_updated")

    def test_update_event_rejected_by_trigger(self) -> None:
        """UPDATE on events table must be rejected (M1)."""
        conn, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        eid = self._create_event_id(repo, ch)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="immutable"):
            conn.execute(
                "UPDATE events SET actor = 'tampered' WHERE event_id = ?;",
                (eid,),
            )

    def test_delete_event_rejected_by_trigger(self) -> None:
        """DELETE on events table must be rejected (M1)."""
        conn, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        eid = self._create_event_id(repo, ch)
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="immutable"):
            conn.execute(
                "DELETE FROM events WHERE event_id = ?;",
                (eid,),
            )

    def test_duplicate_version_event_rejected(self) -> None:
        """Two events with same (challenge_id, blackboard_version_after) must be rejected."""
        conn, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        # First mutation creates version 1 event
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={"session_notes": "first"},
        ))
        # Try to manually insert a duplicate version event
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, datetime('now'), ?, NULL, '{}');
                """,
                (_new_id(), ch.challenge_id, "duplicate_event",
                 "attacker", "{}", 1),
            )

    def test_one_mutation_produces_exactly_one_event(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        events_before = repo.read_events_for_challenge(ch.challenge_id)
        count_before = len(events_before)
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={"session_notes": "once"},
        ))
        events_after = repo.read_events_for_challenge(ch.challenge_id)
        assert len(events_after) == count_before + 1

    def test_stale_mutation_produces_zero_events(self) -> None:
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="a", event_type="update",
            changes={"session_notes": "first"},
        ))
        events_mid = repo.read_events_for_challenge(ch.challenge_id)
        count_mid = len(events_mid)
        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="b", event_type="update",
                changes={"session_notes": "stale"},
            ))
        events_after = repo.read_events_for_challenge(ch.challenge_id)
        assert len(events_after) == count_mid, (
            "Stale write must produce zero events"
        )

    def test_event_ordering_by_version(self) -> None:
        """Events for Blackboard mutations must be ordered by blackboard_version_after."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        for i in range(4):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=i,
                actor="test", event_type="update",
                changes={"session_notes": f"step {i+1}"},
            ))
        events = repo.read_events_for_challenge(ch.challenge_id)
        mutation_events = [e for e in events if e.blackboard_version_after is not None]
        versions = [e.blackboard_version_after for e in mutation_events]
        assert versions == sorted(versions), (
            "Mutation events must be ordered by blackboard_version_after"
        )

    def test_rollback_after_partial_mutation_in_transaction(self) -> None:
        """If exception occurs mid-transaction, partial state must not persist."""
        conn, repo = _in_memory_repo()
        ch = _create_challenge(repo)

        # Apply one valid diff first
        repo.apply_scoped_diff(ScopedDiff(
            challenge_id=ch.challenge_id, expected_version=0,
            actor="test", event_type="update",
            changes={"session_notes": "clean"},
        ))

        version_before = repo.read_blackboard_version(ch.challenge_id)
        events_before = len(repo.read_events_for_challenge(ch.challenge_id))

        # Force a failure mid-transaction by using stale version
        with pytest.raises(StaleVersionError):
            repo.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,  # stale
                actor="test", event_type="update",
                changes={"session_notes": "must not persist"},
            ))

        assert repo.read_blackboard_version(ch.challenge_id) == version_before
        assert len(repo.read_events_for_challenge(ch.challenge_id)) == events_before


# ---------------------------------------------------------------------------
# M2 — Evidence Referential Integrity
# ---------------------------------------------------------------------------


class TestEvidenceIntegrityM2:
    """M2: Evidence provenance and referential integrity."""

    def test_conflict_requires_valid_evidence_a(self) -> None:
        """conflict_records.evidence_id_a must reference a real evidence row."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO conflict_records (
                    conflict_id, challenge_id, evidence_id_a, evidence_id_b,
                    conflict_description, resolution, resolved, created_at
                ) VALUES (?, ?, ?, ?, '', 'pending', 0, datetime('now'));
                """,
                (_new_id(), ch.challenge_id, "nonexistent-a", "nonexistent-b"),
            )

    def test_conflict_evidence_must_be_different(self) -> None:
        """conflict_records must not allow evidence_id_a == evidence_id_b."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)

        # Insert valid evidence first
        eid = _new_id()
        conn.execute(
            """
            INSERT INTO evidence (
                evidence_id, challenge_id, source, content, evidence_type,
                created_by, is_fabricated, created_at
            ) VALUES (?, ?, 'user_confirmed', 'data', 'file', 'user', 0, datetime('now'));
            """,
            (eid, ch.challenge_id),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO conflict_records (
                    conflict_id, challenge_id, evidence_id_a, evidence_id_b,
                    conflict_description, resolution, resolved, created_at
                ) VALUES (?, ?, ?, ?, '', 'pending', 0, datetime('now'));
                """,
                (_new_id(), ch.challenge_id, eid, eid),
            )

    def test_evidence_is_fabricated_blocked(self) -> None:
        """is_fabricated = 1 must be rejected by CHECK constraint."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO evidence (
                    evidence_id, challenge_id, source, content, evidence_type,
                    created_by, is_fabricated, created_at
                ) VALUES (?, ?, 'user_confirmed', 'fake data', 'fabricated',
                          'attacker', 1, datetime('now'));
                """,
                (_new_id(), ch.challenge_id),
            )

    def test_evidence_invalid_source_blocked(self) -> None:
        """Invalid source value must be rejected by CHECK constraint."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO evidence (
                    evidence_id, challenge_id, source, content, evidence_type,
                    created_by, is_fabricated, created_at
                ) VALUES (?, ?, 'fabricated_source', 'data', 'note',
                          'system', 0, datetime('now'));
                """,
                (_new_id(), ch.challenge_id),
            )

    def test_failed_attempt_hypothesis_restrict(self) -> None:
        """Deleting hypothesis with a failed_attempt must fail (RESTRICT)."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)

        hyp_id = _new_id()
        conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, challenge_id, title, description, status,
                confidence, hint_level, created_at, updated_at
            ) VALUES (?, ?, 'H1', '', 'active', 0.5, 2, datetime('now'), datetime('now'));
            """,
            (hyp_id, ch.challenge_id),
        )
        conn.execute(
            """
            INSERT INTO failed_attempts (
                failed_attempt_id, challenge_id, hypothesis_id, target,
                description, failed_at
            ) VALUES (?, ?, ?, 'target', '', datetime('now'));
            """,
            (_new_id(), ch.challenge_id, hyp_id),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM hypotheses WHERE hypothesis_id = ?;", (hyp_id,)
            )

    def test_cross_challenge_attempt_hypothesis_rejected(self) -> None:
        """Attempt in Challenge B referencing Hypothesis in Challenge A must fail."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch_a = _create_challenge(repo)
        ch_b = _create_challenge(repo)

        hyp_a_id = _new_id()
        conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, challenge_id, title, description, status,
                confidence, hint_level, created_at, updated_at
            ) VALUES (?, ?, 'Hyp A', '', 'active', 0.5, 1, datetime('now'), datetime('now'));
            """,
            (hyp_a_id, ch_a.challenge_id),
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO attempts (
                    attempt_id, challenge_id, hypothesis_id, description,
                    outcome, user_input, tool_output, created_at
                ) VALUES (?, ?, ?, 'Attempt in B', 'failure', '', '', datetime('now'));
                """,
                (_new_id(), ch_b.challenge_id, hyp_a_id),
            )

    def test_cross_challenge_user_action_request_hypothesis_rejected(self) -> None:
        """UserActionRequest in Challenge B referencing Hypothesis in Challenge A must fail."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch_a = _create_challenge(repo)
        ch_b = _create_challenge(repo)

        hyp_a_id = _new_id()
        conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, challenge_id, title, description, status,
                confidence, hint_level, created_at, updated_at
            ) VALUES (?, ?, 'Hyp A', '', 'active', 0.5, 1, datetime('now'), datetime('now'));
            """,
            (hyp_a_id, ch_a.challenge_id),
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO user_action_requests (
                    action_request_id, challenge_id, action_type, description,
                    rationale, related_hypothesis_id, requested_at
                ) VALUES (?, ?, 'action', '', '', ?, datetime('now'));
                """,
                (_new_id(), ch_b.challenge_id, hyp_a_id),
            )

    def test_cross_challenge_hint_request_hypothesis_rejected(self) -> None:
        """HintRequest in Challenge B referencing Hypothesis in Challenge A must fail."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch_a = _create_challenge(repo)
        ch_b = _create_challenge(repo)

        hyp_a_id = _new_id()
        conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, challenge_id, title, description, status,
                confidence, hint_level, created_at, updated_at
            ) VALUES (?, ?, 'Hyp A', '', 'active', 0.5, 1, datetime('now'), datetime('now'));
            """,
            (hyp_a_id, ch_a.challenge_id),
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hint_requests (
                    request_id, challenge_id, hypothesis_id, requested_level, requested_at
                ) VALUES (?, ?, ?, 2, datetime('now'));
                """,
                (_new_id(), ch_b.challenge_id, hyp_a_id),
            )

    def test_cross_challenge_hint_candidate_hypothesis_rejected(self) -> None:
        """HintCandidate in Challenge B referencing Hypothesis in Challenge A must fail."""
        conn = _in_memory_conn()
        repo = BlackboardRepository(conn)
        ch_a = _create_challenge(repo)
        ch_b = _create_challenge(repo)

        hyp_a_id = _new_id()
        conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, challenge_id, title, description, status,
                confidence, hint_level, created_at, updated_at
            ) VALUES (?, ?, 'Hyp A', '', 'active', 0.5, 1, datetime('now'), datetime('now'));
            """,
            (hyp_a_id, ch_a.challenge_id),
        )

        req_b_id = _new_id()
        conn.execute(
            """
            INSERT INTO hint_requests (
                request_id, challenge_id, hypothesis_id, requested_level, requested_at
            ) VALUES (?, ?, NULL, 2, datetime('now'));
            """,
            (req_b_id, ch_b.challenge_id),
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hint_candidates (
                    candidate_id, request_id, challenge_id, hypothesis_id, level, created_at
                ) VALUES (?, ?, ?, ?, 2, datetime('now'));
                """,
                (_new_id(), req_b_id, ch_b.challenge_id, hyp_a_id),
            )


# ---------------------------------------------------------------------------
# M3 — Canonical Persistence Tables
# ---------------------------------------------------------------------------


class TestCanonicalPersistenceTablesM3:
    """M3: All 23 canonical domain models have dedicated persistence tables."""

    def test_user_action_requests_table_exists(self) -> None:
        conn = _in_memory_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user_action_requests';"
        ).fetchone()
        assert row is not None, "user_action_requests table must exist"

    def test_user_action_results_table_exists(self) -> None:
        conn = _in_memory_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user_action_results';"
        ).fetchone()
        assert row is not None, "user_action_results table must exist"

    def test_approval_requests_table_exists(self) -> None:
        conn = _in_memory_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='approval_requests';"
        ).fetchone()
        assert row is not None, "approval_requests table must exist"

    def test_user_action_request_round_trip(self) -> None:
        """Can persist and retrieve a UserActionRequest."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        ar_id = _new_id()
        conn.execute(
            """
            INSERT INTO user_action_requests (
                action_request_id, challenge_id, action_type,
                description, rationale, requested_at
            ) VALUES (?, ?, 'scan', 'scan target', 'needed', datetime('now'));
            """,
            (ar_id, ch.challenge_id),
        )
        row = conn.execute(
            "SELECT * FROM user_action_requests WHERE action_request_id = ?;",
            (ar_id,),
        ).fetchone()
        assert row is not None
        assert row["action_type"] == "scan"

    def test_user_action_result_round_trip(self) -> None:
        """Can persist and retrieve a UserActionResult linked to a request."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        ar_id = _new_id()
        conn.execute(
            """
            INSERT INTO user_action_requests (
                action_request_id, challenge_id, action_type,
                description, rationale, requested_at
            ) VALUES (?, ?, 'scan', '', '', datetime('now'));
            """,
            (ar_id, ch.challenge_id),
        )
        res_id = _new_id()
        conn.execute(
            """
            INSERT INTO user_action_results (
                result_id, action_request_id, challenge_id,
                outcome, raw_output, submitted_at
            ) VALUES (?, ?, ?, 'success', 'output data', datetime('now'));
            """,
            (res_id, ar_id, ch.challenge_id),
        )
        row = conn.execute(
            "SELECT * FROM user_action_results WHERE result_id = ?;",
            (res_id,),
        ).fetchone()
        assert row is not None
        assert row["outcome"] == "success"

    def test_approval_request_round_trip(self) -> None:
        """Can persist and retrieve an ApprovalRequest."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        ap_id = _new_id()
        conn.execute(
            """
            INSERT INTO approval_requests (
                approval_id, challenge_id, approval_type, requested_by,
                requested_action_ref, status, requested_at
            ) VALUES (?, ?, 'environment_action', 'user', 'ref', 'requested', datetime('now'));
            """,
            (ap_id, ch.challenge_id),
        )
        row = conn.execute(
            "SELECT * FROM approval_requests WHERE approval_id = ?;",
            (ap_id,),
        ).fetchone()
        assert row is not None
        assert row["status"] == "requested"

    def test_all_23_models_have_persistence_coverage(self) -> None:
        """Verify all 23 canonical domain models map to persistence tables or are documented."""
        conn = _in_memory_conn()
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
        }
        required_tables = {
            "challenges",           # 1. Challenge
            "evidence",             # 2. Evidence
            "findings",             # 3. Finding
            "hypotheses",           # 4. Hypothesis
            "attempts",             # 5. Attempt
            "failed_attempts",      # 6. FailedAttempt
            "blackboard_states",    # 7. BlackboardState
            "hint_requests",        # 8. HintRequest
            "hint_candidates",      # 9. HintCandidate
            "hint_decisions",       # 10. HintDecision
            "user_action_requests", # 11. UserActionRequest
            "user_action_results",  # 12. UserActionResult
            "rag_queries",          # 13. RAGQuery
            "rag_results",          # 14. RAGResult
            "memory_entries",       # 15. MemoryEntry
            "tasks",                # 16. Task
            "task_dependencies",    # 17. TaskDependency
            "events",               # 18. Event
            "skill_results",        # 19. SkillResult
            "approval_requests",    # 20. ApprovalRequest
            "approval_records",     # 21. ApprovalRecord
            "conflict_records",     # 22. ConflictRecord
            "authorized_scopes",    # 23. AuthorizedScope
        }
        missing = required_tables - tables
        assert not missing, f"Missing persistence tables for canonical models: {missing}"


# ---------------------------------------------------------------------------
# M4 — Database Constraints
# ---------------------------------------------------------------------------


class TestDatabaseConstraintsM4:
    """M4: Domain invariants enforced by DB constraints."""

    def test_hint_request_level_too_high_rejected(self) -> None:
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hint_requests (request_id, challenge_id, requested_level, requested_at)
                VALUES (?, ?, 7, datetime('now'));
                """,
                (_new_id(), ch.challenge_id),
            )

    def test_hint_candidate_level_range_enforced(self) -> None:
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        req_id = _new_id()
        conn.execute(
            """
            INSERT INTO hint_requests (request_id, challenge_id, requested_level, requested_at)
            VALUES (?, ?, 3, datetime('now'));
            """,
            (req_id, ch.challenge_id),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hint_candidates (
                    candidate_id, request_id, challenge_id, level, created_at
                ) VALUES (?, ?, ?, 8, datetime('now'));
                """,
                (_new_id(), req_id, ch.challenge_id),
            )

    def test_task_self_dependency_rejected(self) -> None:
        """A task cannot depend on itself."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        task_id = _new_id()
        conn.execute(
            """
            INSERT INTO tasks (
                task_id, challenge_id, task_group_id, task_type, status,
                retry_key, created_at, updated_at
            ) VALUES (?, ?, 'g1', 'scan', 'queued', 'k1', datetime('now'), datetime('now'));
            """,
            (task_id, ch.challenge_id),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO task_dependencies (
                    dependency_id, task_id, depends_on_task_id,
                    dependency_type, created_at
                ) VALUES (?, ?, ?, 'hard', datetime('now'));
                """,
                (_new_id(), task_id, task_id),
            )

    def test_duplicate_task_dependency_rejected(self) -> None:
        """Duplicate (task_id, depends_on_task_id) must be rejected."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        t1 = _new_id()
        t2 = _new_id()
        for tid, rkey, ttype in [(t1, "k1", "scan"), (t2, "k2", "exploit")]:
            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, challenge_id, task_group_id, task_type, status,
                    retry_key, created_at, updated_at
                ) VALUES (?, ?, 'g1', ?, 'queued', ?, datetime('now'), datetime('now'));
                """,
                (tid, ch.challenge_id, ttype, rkey),
            )
        conn.execute(
            """
            INSERT INTO task_dependencies (
                dependency_id, task_id, depends_on_task_id, dependency_type, created_at
            ) VALUES (?, ?, ?, 'hard', datetime('now'));
            """,
            (_new_id(), t1, t2),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO task_dependencies (
                    dependency_id, task_id, depends_on_task_id, dependency_type, created_at
                ) VALUES (?, ?, ?, 'soft', datetime('now'));
                """,
                (_new_id(), t1, t2),
            )

    def test_hypothesis_hint_level_range_enforced(self) -> None:
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hypotheses (
                    hypothesis_id, challenge_id, title, status, confidence,
                    hint_level, created_at, updated_at
                ) VALUES (?, ?, 'H', 'active', 0.5, 9, datetime('now'), datetime('now'));
                """,
                (_new_id(), ch.challenge_id),
            )

    def test_blackboard_version_cannot_be_negative(self) -> None:
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE blackboard_states SET blackboard_version = -1 WHERE challenge_id = ?;",
                (ch.challenge_id,),
            )


# ---------------------------------------------------------------------------
# M5 — Task Retry / Supersession
# ---------------------------------------------------------------------------


class TestTaskRetryConstraintM5:
    """M5: Task dedup index must not block legitimate retries."""

    def test_unique_task_dedup_allows_retry_via_new_task_id(self) -> None:
        """A failed task can be retried with a new task_id (same retry_key, new id)."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)

        # First attempt - fails
        t1 = _new_id()
        conn.execute(
            """
            INSERT INTO tasks (
                task_id, challenge_id, task_group_id, task_type, status,
                retry_key, created_at, updated_at
            ) VALUES (?, ?, 'g1', 'scan', 'failed', 'retry_key_1',
                      datetime('now'), datetime('now'));
            """,
            (t1, ch.challenge_id),
        )

        # Second attempt - new task_id, same retry_key; 'failed' is excluded from
        # the dedup unique index so this must succeed
        t2 = _new_id()
        conn.execute(
            """
            INSERT INTO tasks (
                task_id, challenge_id, task_group_id, task_type, status,
                retry_key, created_at, updated_at
            ) VALUES (?, ?, 'g1', 'scan', 'queued', 'retry_key_1',
                      datetime('now'), datetime('now'));
            """,
            (t2, ch.challenge_id),
        )
        rows = conn.execute(
            "SELECT task_id FROM tasks WHERE challenge_id = ? AND retry_key = ?;",
            (ch.challenge_id, "retry_key_1"),
        ).fetchall()
        assert len(rows) == 2, "Both the failed and queued task must coexist"

    def test_duplicate_active_task_blocked(self) -> None:
        """Two queued tasks with same (challenge_id, group, type) must be blocked."""
        conn = _in_memory_conn()
        ch = _make_challenge()
        BlackboardRepository(conn).create_challenge(ch)

        conn.execute(
            """
            INSERT INTO tasks (
                task_id, challenge_id, task_group_id, task_type, status,
                retry_key, created_at, updated_at
            ) VALUES (?, ?, 'g1', 'scan', 'queued', 'k1',
                      datetime('now'), datetime('now'));
            """,
            (_new_id(), ch.challenge_id),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, challenge_id, task_group_id, task_type, status,
                    retry_key, created_at, updated_at
                ) VALUES (?, ?, 'g1', 'scan', 'queued', 'k2',
                          datetime('now'), datetime('now'));
                """,
                (_new_id(), ch.challenge_id),
            )


# ---------------------------------------------------------------------------
# M6 — Repository / Domain Separation
# ---------------------------------------------------------------------------


class TestRepoDomainSeparationM6:
    """M6: FK guard, domain object returns, ScopedDiff in persistence.errors."""

    def test_repo_rejects_connection_without_foreign_keys(self) -> None:
        """BlackboardRepository must reject a connection with foreign_keys OFF."""
        raw_conn = sqlite3.connect(":memory:", isolation_level=None)
        raw_conn.row_factory = sqlite3.Row
        raw_conn.execute("PRAGMA foreign_keys = OFF;")
        with pytest.raises(ValueError, match="foreign_keys"):
            BlackboardRepository(raw_conn)

    def test_assert_foreign_keys_enabled_passes_for_good_conn(self) -> None:
        conn = _in_memory_conn()
        # Must not raise
        assert_foreign_keys_enabled(conn)

    def test_scoped_diff_in_persistence_errors(self) -> None:
        """ScopedDiff must be importable from persistence.errors."""
        from ctf_mentor.persistence.errors import ScopedDiff as SD
        diff = SD(
            challenge_id="c1", expected_version=0,
            actor="test", event_type="update",
            changes={"session_notes": "x"},
        )
        assert diff.challenge_id == "c1"

    def test_stale_version_error_in_persistence_errors(self) -> None:
        """StaleVersionError must be importable from persistence.errors."""
        from ctf_mentor.persistence.errors import StaleVersionError as SVE
        err = SVE("c1", 0, 1)
        assert err.challenge_id == "c1"

    def test_stale_version_error_backward_compat_from_domain(self) -> None:
        """StaleVersionError re-exported from domain.models must be same class."""
        from ctf_mentor.domain.models import StaleVersionError as SVE_domain
        from ctf_mentor.persistence.errors import StaleVersionError as SVE_persist
        assert SVE_domain is SVE_persist

    def test_scoped_diff_backward_compat_from_domain(self) -> None:
        """ScopedDiff re-exported from domain.models must be same class."""
        from ctf_mentor.domain.models import ScopedDiff as SD_domain
        from ctf_mentor.persistence.errors import ScopedDiff as SD_persist
        assert SD_domain is SD_persist

    def test_read_challenge_returns_domain_object(self) -> None:
        """read_challenge must return a Challenge domain object (not raw dict)."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        result = repo.read_challenge(ch.challenge_id)
        assert isinstance(result, Challenge)

    def test_read_blackboard_state_returns_domain_object(self) -> None:
        """read_blackboard_state must return BlackboardState domain object."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        result = repo.read_blackboard_state(ch.challenge_id)
        assert isinstance(result, BlackboardState)

    def test_read_events_returns_domain_objects(self) -> None:
        """read_events_for_challenge must return list of Event domain objects."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        events = repo.read_events_for_challenge(ch.challenge_id)
        for e in events:
            assert isinstance(e, Event)

    def test_approval_record_domain_object_returned(self) -> None:
        """read_approval_record_domain must return ApprovalRecord domain object."""
        _, repo = _in_memory_repo()
        ch = _create_challenge(repo)
        aid = _new_id()
        repo.create_approval_record(
            approval_id=aid, challenge_id=ch.challenge_id,
            approval_type="environment_action", requested_by="user",
            requested_action_ref="ref",
        )
        result = repo.read_approval_record_domain(aid)
        assert isinstance(result, ApprovalRecord)
        assert result.status == ApprovalStatus.REQUESTED

    def test_concurrent_writers_second_fails(self) -> None:
        """Actual two-connection concurrent write: only one wins (no sleep)."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            conn1 = get_connection(db_path)
            initialize_schema(conn1)
            ch = _make_challenge()
            repo1 = BlackboardRepository(conn1)
            repo1.create_challenge(ch)

            conn2 = get_connection(db_path)
            repo2 = BlackboardRepository(conn2)

            # Both read version 0
            assert repo1.read_blackboard_version(ch.challenge_id) == 0
            assert repo2.read_blackboard_version(ch.challenge_id) == 0

            # First writer succeeds
            repo1.apply_scoped_diff(ScopedDiff(
                challenge_id=ch.challenge_id, expected_version=0,
                actor="writer1", event_type="update",
                changes={"session_notes": "writer1 wins"},
            ))

            # Second writer with same expected_version must fail
            with pytest.raises(StaleVersionError):
                repo2.apply_scoped_diff(ScopedDiff(
                    challenge_id=ch.challenge_id, expected_version=0,
                    actor="writer2", event_type="update",
                    changes={"session_notes": "writer2 loses"},
                ))

            final = repo1.read_blackboard_state(ch.challenge_id)
            assert final is not None
            assert final.session_notes == "writer1 wins"
        finally:
            conn1.close()
            conn2.close()
            os.unlink(db_path)

    def test_domain_has_no_persistence_imports(self) -> None:
        """ctf_mentor.domain.models must not import any submodules from ctf_mentor.persistence."""
        import ast
        from pathlib import Path
        models_file = Path("ctf_mentor/domain/models.py")
        tree = ast.parse(models_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "ctf_mentor.persistence" not in alias.name, (
                        f"Forbidden domain -> persistence import: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "ctf_mentor.persistence" not in node.module, (
                        f"Forbidden domain -> persistence import from: {node.module}"
                    )

    def test_schema_initialization_is_additive_only(self) -> None:
        """initialize_schema provides safe additive initialization without destructive migrations."""
        conn = _in_memory_conn()
        ver = initialize_schema(conn)
        assert ver == SCHEMA_VERSION
        # Re-running initialization on populated schema is safe and additive
        ver_again = initialize_schema(conn)
        assert ver_again == SCHEMA_VERSION
