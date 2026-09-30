"""
Blackboard Repository for CTF Mentor/Copilot.

This is the ONLY layer that may mutate persisted Blackboard state.

Responsibilities:
- Create challenge (initialises blackboard_state row)
- Read challenge / Blackboard version / Blackboard state
- Apply scoped diff with optimistic concurrency control
- Emit a corresponding Event for every Blackboard mutation
- ApprovalRecord persistence with lifecycle enforcement (H1)
- AuthorizedScope persistence with fail-closed validation (H2)

Concurrency model (LOCKED):
1. Read current blackboard_version.
2. Build a scoped diff.
3. Begin explicit transaction.
4. Perform conditional UPDATE:
       UPDATE blackboard_states
       SET ..., blackboard_version = blackboard_version + 1
       WHERE challenge_id = ?
         AND blackboard_version = ?
5. Check affected row count.
6. If zero rows: ROLLBACK → raise StaleVersionError.
7. If successful: COMMIT → return updated version.

Security / integrity rules:
- ScopedDiff field names validated against ALLOWED_BLACKBOARD_FIELDS whitelist (H3).
- ScopedDiff values validated before any SQL is built (H3).
- Values ALWAYS passed as parameters; never interpolated (M6).
- No SELECT FOR UPDATE.
- No arbitrary SQL identifier interpolation.
- Authoritative version lives solely in blackboard_states (H4).
- Every Blackboard mutation emits exactly one Event (M1).
- Events are immutable at DB level via triggers (M1).
- Connection must have foreign_keys = ON (M6).
- Approval lifecycle transitions are enforced (H1).
- AuthorizedScope validated before persistence (H2).
- One active primary_target per challenge enforced by DB index (H2).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from ctf_mentor.domain.models import (
    ApprovalRecord,
    ApprovalStatus,
    ApprovalType,
    AuthorizedScope,
    BlackboardState,
    Challenge,
    Event,
    HintLevel,
)
from ctf_mentor.persistence.database import assert_foreign_keys_enabled
from ctf_mentor.contracts import (
    ScopedDiff,
    StaleApprovalError,
    StaleVersionError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Whitelist of fields that are allowed to be mutated via ScopedDiff.
# ---------------------------------------------------------------------------
ALLOWED_BLACKBOARD_FIELDS: frozenset[str] = frozenset(
    {
        "active_hypothesis_ids",
        "watchlist_hypothesis_ids",
        "confirmed_findings",
        "active_evidence_ids",
        "last_hint_level",
        "session_notes",
        "metadata",
    }
)

# ---------------------------------------------------------------------------
# Approval lifecycle: valid transitions
# Terminal states may NOT be reopened.
# Canonical workflow: requested -> pending -> (approved|rejected|expired|cancelled)
# ---------------------------------------------------------------------------
_APPROVAL_TERMINAL_STATES: frozenset[str] = frozenset(
    {"approved", "rejected", "expired", "cancelled"}
)

_APPROVAL_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "requested": frozenset({"pending", "cancelled"}),
    "pending":   frozenset({"approved", "rejected", "cancelled", "expired"}),
    "approved":  frozenset(),   # terminal
    "rejected":  frozenset(),   # terminal
    "expired":   frozenset(),   # terminal
    "cancelled": frozenset(),   # terminal
}

# ---------------------------------------------------------------------------
# AuthorizedScope: allowed schemes and relationship types
# ---------------------------------------------------------------------------
_ALLOWED_SCHEMES: frozenset[str] = frozenset(
    {"http", "https", "tcp", "udp", "ftp", "ssh", "smtp", "dns", "custom"}
)
_ALLOWED_RELATIONSHIPS: frozenset[str] = frozenset(
    {"primary_target", "auxiliary", "out_of_scope"}
)

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def _to_json(value: Any) -> str:
    return json.dumps(value, default=str)


def _from_json(value: str) -> Any:
    if value is None:
        return None
    return json.loads(value)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Blackboard value validation (H3)
# ---------------------------------------------------------------------------
_MAX_ACTIVE_HYPOTHESES = 3
_HINT_LEVEL_MIN = 0
_HINT_LEVEL_MAX = 6

_BLACKBOARD_FIELD_VALIDATORS: dict[str, Any] = {
    "active_hypothesis_ids": {
        "type": list,
        "max_len": _MAX_ACTIVE_HYPOTHESES,
        "description": "list of <= 3 hypothesis ID strings",
    },
    "watchlist_hypothesis_ids": {
        "type": list,
        "description": "list of hypothesis ID strings",
    },
    "confirmed_findings": {
        "type": list,
        "description": "list of finding ID strings",
    },
    "active_evidence_ids": {
        "type": list,
        "description": "list of evidence ID strings",
    },
    "last_hint_level": {
        "type": int,
        "min_val": _HINT_LEVEL_MIN,
        "max_val": _HINT_LEVEL_MAX,
        "description": f"hint level integer in [{_HINT_LEVEL_MIN}, {_HINT_LEVEL_MAX}]",
    },
    "session_notes": {
        "type": str,
        "description": "string session notes",
    },
    "metadata": {
        "type": dict,
        "description": "JSON object (dict)",
    },
}


def _validate_blackboard_value(field_name: str, value: Any) -> None:
    """Validate a single Blackboard field value before touching the DB.

    Raises ValueError with a descriptive message if invalid.
    """
    spec = _BLACKBOARD_FIELD_VALIDATORS.get(field_name)
    if spec is None:
        raise ValueError(f"No validator registered for field {field_name!r}")

    expected_type = spec["type"]
    if isinstance(value, bool) or not isinstance(value, expected_type):
        raise ValueError(
            f"Field {field_name!r} must be {spec['description']}, "
            f"got {type(value).__name__}"
        )

    if "max_len" in spec and len(value) > spec["max_len"]:
        raise ValueError(
            f"Field {field_name!r} exceeds maximum length {spec['max_len']} "
            f"(got {len(value)})"
        )

    if "min_val" in spec and value < spec["min_val"]:
        raise ValueError(
            f"Field {field_name!r} must be >= {spec['min_val']}, got {value}"
        )

    if "max_val" in spec and value > spec["max_val"]:
        raise ValueError(
            f"Field {field_name!r} must be <= {spec['max_val']}, got {value}"
        )

    # Validate JSON serializability (list/dict round-trip)
    if isinstance(value, (list, dict)):
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Field {field_name!r} is not JSON-serializable: {exc}"
            ) from exc

    # List items must all be strings
    if isinstance(value, list):
        for i, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(
                    f"Field {field_name!r} item[{i}] must be str, "
                    f"got {type(item).__name__}"
                )


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def _row_to_challenge(row: sqlite3.Row) -> Challenge:
    """Map a DB row to a Challenge domain object.

    NOTE: blackboard_version is read from blackboard_states, not challenges.
    The row here is a JOIN of challenges LEFT JOIN blackboard_states.
    """
    return Challenge(
        challenge_id=row["challenge_id"],
        name=row["name"],
        description=row["description"],
        category=row["category"],
        global_hint_level=HintLevel(row["global_hint_level"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        blackboard_version=row["blackboard_version"] if row["blackboard_version"] is not None else 0,
        is_active=bool(row["is_active"]),
        tags=_from_json(row["tags"]),
        metadata=_from_json(row["metadata"]),
    )


def _row_to_blackboard_state(row: sqlite3.Row) -> BlackboardState:
    return BlackboardState(
        challenge_id=row["challenge_id"],
        blackboard_version=row["blackboard_version"],
        active_hypothesis_ids=_from_json(row["active_hypothesis_ids"]),
        watchlist_hypothesis_ids=_from_json(row["watchlist_hypothesis_ids"]),
        confirmed_findings=_from_json(row["confirmed_findings"]),
        active_evidence_ids=_from_json(row["active_evidence_ids"]),
        last_hint_level=HintLevel(row["last_hint_level"]),
        session_notes=row["session_notes"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
        metadata=_from_json(row["metadata"]),
    )


def _row_to_approval_record(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row["approval_id"],
        challenge_id=row["challenge_id"],
        approval_type=ApprovalType(row["approval_type"]),
        requested_by=row["requested_by"],
        requested_action_ref=row["requested_action_ref"],
        status=ApprovalStatus(row["status"]),
        requested_at=datetime.fromisoformat(row["requested_at"]),
        resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
        resolved_by=row["resolved_by"],
        decision_reason=row["decision_reason"],
        related_request_id=row["related_request_id"],
        related_event_id=row["related_event_id"],
    )


# ---------------------------------------------------------------------------
# AuthorizedScope validation (H2 - fail-closed)
# ---------------------------------------------------------------------------


def validate_authorized_scope(
    scheme: str,
    hostname: str,
    port: int,
    environment_id: str,
    challenge_relationship: str,
    allowed_path_patterns: list[str],
    allowed_methods: list[str],
    exclusions: list[str],
    query_restrictions: dict[str, Any],
) -> None:
    """Validate AuthorizedScope fields before persistence.

    Raises ValueError with a descriptive message on any violation.
    This is the fail-closed guard: if validation fails, the scope must NOT be persisted.
    """
    errors: list[str] = []

    if not hostname or not hostname.strip():
        errors.append("hostname must not be empty")

    if scheme not in _ALLOWED_SCHEMES:
        errors.append(f"scheme {scheme!r} not in allowed set {sorted(_ALLOWED_SCHEMES)}")

    if not (0 <= port <= 65535):
        errors.append(f"port {port} out of valid range [0, 65535]")

    if not environment_id or not environment_id.strip():
        errors.append("environment_id must not be empty")

    if challenge_relationship not in _ALLOWED_RELATIONSHIPS:
        errors.append(
            f"challenge_relationship {challenge_relationship!r} "
            f"not in {sorted(_ALLOWED_RELATIONSHIPS)}"
        )

    # Validate JSON structure of list/dict fields
    for name, val in [
        ("allowed_path_patterns", allowed_path_patterns),
        ("allowed_methods", allowed_methods),
        ("exclusions", exclusions),
    ]:
        if not isinstance(val, list):
            errors.append(f"{name} must be a list")
        else:
            for i, item in enumerate(val):
                if not isinstance(item, str):
                    errors.append(f"{name}[{i}] must be a string")

    if not isinstance(query_restrictions, dict):
        errors.append("query_restrictions must be a dict")
    else:
        try:
            json.dumps(query_restrictions)
        except (TypeError, ValueError) as exc:
            errors.append(f"query_restrictions is not JSON-serializable: {exc}")

    if errors:
        raise ValueError(
            "AuthorizedScope validation failed (fail-closed): " + "; ".join(errors)
        )


def validate_scoped_diff_authoritative(conn: sqlite3.Connection, diff: ScopedDiff) -> None:
    """Validate a ScopedDiff against field whitelists, value types, and database entity ownership.

    Raises ValueError if validation fails.
    """
    if not diff.changes:
        raise ValueError("ScopedDiff.changes must not be empty")

    unknown_fields = set(diff.changes.keys()) - ALLOWED_BLACKBOARD_FIELDS
    if unknown_fields:
        raise ValueError(
            f"ScopedDiff contains disallowed field(s): {sorted(unknown_fields)}. "
            f"Allowed fields: {sorted(ALLOWED_BLACKBOARD_FIELDS)}"
        )

    for field_name, value in diff.changes.items():
        _validate_blackboard_value(field_name, value)

    # Validate challenge existence
    cursor = conn.cursor()
    row = cursor.execute("SELECT 1 FROM challenges WHERE challenge_id = ?", (diff.challenge_id,)).fetchone()
    if not row:
        raise StaleVersionError(diff.challenge_id, diff.expected_version, -1)

    # Cross-challenge hypothesis validation
    for field_name in ("active_hypothesis_ids", "watchlist_hypothesis_ids"):
        if field_name in diff.changes:
            hyp_ids = diff.changes[field_name]
            for hyp_id in hyp_ids:
                h_row = cursor.execute(
                    "SELECT challenge_id FROM hypotheses WHERE hypothesis_id = ?", (hyp_id,)
                ).fetchone()
                if h_row and h_row["challenge_id"] != diff.challenge_id:
                    raise ValueError(
                        f"Cross-challenge write rejected: Hypothesis {hyp_id!r} belongs to challenge "
                        f"{h_row['challenge_id']!r}, not {diff.challenge_id!r}."
                    )

    # Cross-challenge evidence validation
    if "active_evidence_ids" in diff.changes:
        for ev_id in diff.changes["active_evidence_ids"]:
            e_row = cursor.execute(
                "SELECT challenge_id FROM evidence WHERE evidence_id = ?", (ev_id,)
            ).fetchone()
            if e_row and e_row["challenge_id"] != diff.challenge_id:
                raise ValueError(
                    f"Cross-challenge write rejected: Evidence {ev_id!r} belongs to challenge "
                    f"{e_row['challenge_id']!r}, not {diff.challenge_id!r}."
                )

    # Cross-challenge findings validation
    if "confirmed_findings" in diff.changes:
        for f_id in diff.changes["confirmed_findings"]:
            f_row = cursor.execute(
                "SELECT challenge_id FROM findings WHERE finding_id = ?", (f_id,)
            ).fetchone()
            if f_row and f_row["challenge_id"] != diff.challenge_id:
                raise ValueError(
                    f"Cross-challenge write rejected: Finding {f_id!r} belongs to challenge "
                    f"{f_row['challenge_id']!r}, not {diff.challenge_id!r}."
                )


# ---------------------------------------------------------------------------
# BlackboardRepository
# ---------------------------------------------------------------------------


class BlackboardRepository:
    """Repository for Challenge and Blackboard persistence.

    Accepts a sqlite3.Connection obtained via get_connection().
    Raises ValueError if the connection does not have foreign_keys enabled.
    All mutations use explicit BEGIN/COMMIT/ROLLBACK transactions.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        assert_foreign_keys_enabled(conn)
        self._conn = conn

    # ------------------------------------------------------------------
    # Challenge operations
    # ------------------------------------------------------------------

    def create_challenge(self, challenge: Challenge) -> Challenge:
        """Persist a new Challenge and its initial BlackboardState.

        Inserts both the challenges row and the blackboard_states row atomically.
        Also emits a 'challenge_created' Event (version_after = 0).
        Raises sqlite3.IntegrityError if challenge_id already exists.

        H4: blackboard_version is initialised to 0 in blackboard_states.
        challenges table does NOT carry a separate mutable version column.
        """
        now = _now_iso()
        self._conn.execute("BEGIN;")
        try:
            self._conn.execute(
                """
                INSERT INTO challenges (
                    challenge_id, name, description, category,
                    global_hint_level, is_active,
                    tags, metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    challenge.challenge_id,
                    challenge.name,
                    challenge.description,
                    challenge.category,
                    int(challenge.global_hint_level),
                    int(challenge.is_active),
                    _to_json(challenge.tags),
                    _to_json(challenge.metadata),
                    challenge.created_at.isoformat(),
                    challenge.updated_at.isoformat(),
                ),
            )

            # Authoritative version lives here only
            self._conn.execute(
                """
                INSERT INTO blackboard_states (
                    challenge_id, blackboard_version,
                    active_hypothesis_ids, watchlist_hypothesis_ids,
                    confirmed_findings, active_evidence_ids,
                    last_hint_level, session_notes, metadata, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    challenge.challenge_id,
                    0,
                    _to_json([]), _to_json([]),
                    _to_json([]), _to_json([]),
                    0, "", _to_json({}), now,
                ),
            )

            event_id = str(uuid.uuid4())
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    challenge.challenge_id,
                    "challenge_created",
                    "system",
                    _to_json({"challenge_id": challenge.challenge_id}),
                    now,
                    0,
                    None,
                    _to_json({}),
                ),
            )

            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

        return challenge

    def read_challenge(self, challenge_id: str) -> Optional[Challenge]:
        """Return the Challenge joined with its blackboard_version, or None."""
        row = self._conn.execute(
            """
            SELECT c.*, bs.blackboard_version
            FROM challenges c
            LEFT JOIN blackboard_states bs ON c.challenge_id = bs.challenge_id
            WHERE c.challenge_id = ?;
            """,
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_challenge(row)

    # ------------------------------------------------------------------
    # Blackboard read operations
    # ------------------------------------------------------------------

    def read_blackboard_version(self, challenge_id: str) -> Optional[int]:
        """Return the current blackboard_version from blackboard_states.

        blackboard_states is the single authoritative source (H4).
        Returns None if the challenge does not exist.
        """
        row = self._conn.execute(
            "SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?;",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        return int(row["blackboard_version"])

    def read_blackboard_state(self, challenge_id: str) -> Optional[BlackboardState]:
        """Return the full BlackboardState for the given challenge, or None."""
        row = self._conn.execute(
            "SELECT * FROM blackboard_states WHERE challenge_id = ?;",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_blackboard_state(row)

    def has_active_authorized_scope(self, challenge_id: str) -> bool:
        """Return True if the challenge has at least one active AuthorizedScope.

        H2 fail-closed: callers should check this before using a challenge
        for any scoped operation. The repository itself does not silently proceed.
        """
        row = self._conn.execute(
            "SELECT 1 FROM authorized_scopes WHERE challenge_id = ? AND is_active = 1 LIMIT 1;",
            (challenge_id,),
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # Blackboard mutation – apply scoped diff (optimistic concurrency)
    # ------------------------------------------------------------------

    def apply_scoped_diff(self, diff: ScopedDiff) -> int:
        """Apply a ScopedDiff to the Blackboard with optimistic concurrency."""
        validate_scoped_diff_authoritative(self._conn, diff)

        # ----------------------------------------------------------------
        # 2. Build SET clause from whitelisted field names.
        # ----------------------------------------------------------------
        set_parts: list[str] = []
        params: list[Any] = []
        now = _now_iso()

        for field_name in sorted(diff.changes.keys()):
            value = diff.changes[field_name]
            if isinstance(value, (list, dict)):
                value = _to_json(value)
            set_parts.append(f"{field_name} = ?")
            params.append(value)

        set_parts.append("updated_at = ?")
        params.append(now)

        set_parts.append("blackboard_version = blackboard_version + 1")

        set_clause = ", ".join(set_parts)

        params.append(diff.challenge_id)
        params.append(diff.expected_version)

        sql = (
            f"UPDATE blackboard_states "
            f"SET {set_clause} "
            f"WHERE challenge_id = ? AND blackboard_version = ?;"
        )

        # ----------------------------------------------------------------
        # 3. Begin explicit transaction.
        # ----------------------------------------------------------------
        self._conn.execute("BEGIN;")
        try:
            cursor = self._conn.execute(sql, params)
            affected = cursor.rowcount

            if affected == 0:
                self._conn.execute("ROLLBACK;")
                current = self._read_version_no_tx(diff.challenge_id)
                found = current if current is not None else -1
                raise StaleVersionError(diff.challenge_id, diff.expected_version, found)

            new_version = diff.expected_version + 1

            # ----------------------------------------------------------------
            # M1: Emit exactly one Event per mutation.
            # ----------------------------------------------------------------
            event_id = str(uuid.uuid4())
            payload = {
                "challenge_id": diff.challenge_id,
                "actor": diff.actor,
                "previous_version": diff.expected_version,
                "changes": list(diff.changes.keys()),
            }
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    diff.challenge_id,
                    diff.event_type,
                    diff.actor,
                    _to_json(payload),
                    now,
                    new_version,
                    None,
                    _to_json({}),
                ),
            )

            self._conn.execute("COMMIT;")

        except StaleVersionError:
            raise
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

        return new_version

    # ------------------------------------------------------------------
    # Event read
    # ------------------------------------------------------------------

    def read_events_for_challenge(self, challenge_id: str) -> list[Event]:
        """Return all events for a challenge, ordered by blackboard_version_after
        (for mutation events), then by occurred_at for deterministic ordering."""
        rows = self._conn.execute(
            """
            SELECT * FROM events
            WHERE challenge_id = ?
            ORDER BY
                CASE WHEN blackboard_version_after IS NOT NULL
                     THEN blackboard_version_after ELSE -1 END ASC,
                occurred_at ASC;
            """,
            (challenge_id,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    # ------------------------------------------------------------------
    # ApprovalRecord persistence (H1)
    # ------------------------------------------------------------------

    def create_approval_record(
        self,
        approval_id: str,
        challenge_id: str,
        approval_type: str,
        requested_by: str,
        requested_action_ref: str,
        status: str = "requested",
        decision_reason: str = "",
        related_request_id: Optional[str] = None,
        related_event_id: Optional[str] = None,
    ) -> ApprovalRecord:
        """Persist a new ApprovalRecord and emit an event.

        Only 'requested' or 'pending' are valid initial statuses.
        Terminal statuses may not be used as initial status.
        related_event_id, if provided, must reference a real events row.
        Returns the persisted ApprovalRecord domain object.
        """
        # H1: initial status must not be terminal
        if status in _APPROVAL_TERMINAL_STATES:
            raise ValueError(
                f"Cannot create ApprovalRecord with terminal initial status {status!r}"
            )
        if status not in _APPROVAL_VALID_TRANSITIONS:
            raise ValueError(f"Unknown ApprovalStatus {status!r}")

        # H1: initial status must not have resolver fields
        if status in ("requested", "pending"):
            pass  # resolved_at/by are None at creation; that's correct

        # H1: validate related_request_id references a real request
        if related_request_id is not None:
            row = self._conn.execute(
                """
                SELECT 1 FROM user_action_requests WHERE action_request_id = ?
                UNION ALL
                SELECT 1 FROM approval_records WHERE approval_id = ?
                UNION ALL
                SELECT 1 FROM approval_requests WHERE approval_id = ?
                UNION ALL
                SELECT 1 FROM hint_requests WHERE request_id = ?;
                """,
                (related_request_id, related_request_id, related_request_id, related_request_id),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"related_request_id {related_request_id!r} does not reference "
                    "an existing request"
                )

        # H1: validate related_event_id references a real event
        if related_event_id is not None:
            row = self._conn.execute(
                "SELECT 1 FROM events WHERE event_id = ?;", (related_event_id,)
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"related_event_id {related_event_id!r} does not reference "
                    "an existing event"
                )

        now = _now_iso()
        self._conn.execute("BEGIN;")
        try:
            self._conn.execute(
                """
                INSERT INTO approval_records (
                    approval_id, challenge_id, approval_type, requested_by,
                    requested_action_ref, status, requested_at,
                    resolved_at, resolved_by, decision_reason,
                    related_request_id, related_event_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    approval_id, challenge_id, approval_type, requested_by,
                    requested_action_ref, status, now,
                    None, None, decision_reason,
                    related_request_id, related_event_id,
                ),
            )

            # H1/M1: audit event for approval creation
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    "approval_created",
                    requested_by,
                    _to_json({
                        "approval_id": approval_id,
                        "approval_type": approval_type,
                        "status": status,
                    }),
                    now,
                    None,
                    None,
                    _to_json({}),
                ),
            )
            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

        return self.read_approval_record_domain(approval_id)  # type: ignore[return-value]

    def update_approval_record_status(
        self,
        approval_id: str,
        new_status: str,
        resolved_by: Optional[str] = None,
        decision_reason: str = "",
    ) -> ApprovalRecord:
        """Transition an ApprovalRecord to a new status with optimistic concurrency.

        H1 enforcement & Audit Fix:
        - Begins explicit transaction.
        - Reads current status inside transaction.
        - Validates requested transition.
        - Performs conditional UPDATE using current status:
              WHERE approval_id = ? AND status = ?
        - If rowcount == 0: ROLLBACK and raise StaleApprovalError.
        - If successful: inserts audit Event and COMMITs.
        """
        self._conn.execute("BEGIN;")
        try:
            existing = self.read_approval_record_domain(approval_id)
            if existing is None:
                self._conn.execute("ROLLBACK;")
                raise ValueError(
                    f"ApprovalRecord {approval_id!r} does not exist"
                )

            current_status = existing.status.value
            valid_next = _APPROVAL_VALID_TRANSITIONS.get(current_status, frozenset())

            if new_status not in _APPROVAL_VALID_TRANSITIONS:
                self._conn.execute("ROLLBACK;")
                raise ValueError(f"Unknown ApprovalStatus {new_status!r}")

            if new_status not in valid_next:
                self._conn.execute("ROLLBACK;")
                if current_status in _APPROVAL_TERMINAL_STATES:
                    raise ValueError(
                        f"ApprovalRecord is in terminal state {current_status!r} "
                        "and cannot be transitioned"
                    )
                raise ValueError(
                    f"Invalid transition from {current_status!r} to {new_status!r}"
                )

            # H1: terminal states require resolver
            if new_status in _APPROVAL_TERMINAL_STATES and not resolved_by:
                self._conn.execute("ROLLBACK;")
                raise ValueError(
                    f"Transition to terminal state {new_status!r} requires resolved_by"
                )

            # H1: non-terminal states must not have resolved_by
            if new_status not in _APPROVAL_TERMINAL_STATES and resolved_by is not None:
                self._conn.execute("ROLLBACK;")
                raise ValueError(
                    f"Non-terminal status {new_status!r} must not have resolved_by"
                )

            # H1: preserve existing decision_reason if new one is empty
            effective_reason = (
                decision_reason if decision_reason
                else existing.decision_reason
            )

            now = _now_iso()
            resolved_at = now if new_status in _APPROVAL_TERMINAL_STATES else None

            # Conditional UPDATE using current status (optimistic concurrency)
            cursor = self._conn.execute(
                """
                UPDATE approval_records
                SET status = ?, resolved_at = ?, resolved_by = ?,
                    decision_reason = ?
                WHERE approval_id = ? AND status = ?;
                """,
                (new_status, resolved_at, resolved_by, effective_reason, approval_id, current_status),
            )

            if cursor.rowcount == 0:
                self._conn.execute("ROLLBACK;")
                latest = self.read_approval_record_domain(approval_id)
                found = latest.status.value if latest else "nonexistent"
                raise StaleApprovalError(
                    approval_id=approval_id,
                    expected_status=current_status,
                    found_status=found,
                )

            # H1/M1: audit event for approval transition
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(uuid.uuid4()),
                    existing.challenge_id,
                    "approval_status_changed",
                    resolved_by or "system",
                    _to_json({
                        "approval_id": approval_id,
                        "from_status": current_status,
                        "to_status": new_status,
                        "decision_reason": effective_reason,
                    }),
                    now,
                    None,
                    None,
                    _to_json({}),
                ),
            )
            self._conn.execute("COMMIT;")
        except (ValueError, StaleApprovalError):
            raise
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

        return self.read_approval_record_domain(approval_id)  # type: ignore[return-value]

    def read_approval_record_domain(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Return an ApprovalRecord domain object, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM approval_records WHERE approval_id = ?;",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_approval_record(row)

    def read_approval_record(self, approval_id: str) -> Optional[dict[str, Any]]:
        """Return an ApprovalRecord row as a raw dict, or None.

        Kept for test compatibility. Prefer read_approval_record_domain for
        typed access.
        """
        row = self._conn.execute(
            "SELECT * FROM approval_records WHERE approval_id = ?;",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # AuthorizedScope persistence (H2)
    # ------------------------------------------------------------------

    def create_authorized_scope(
        self,
        scope_id: str,
        challenge_id: str,
        scheme: str,
        hostname: str,
        port: int,
        allowed_path_patterns: list[str],
        allowed_methods: list[str],
        exclusions: list[str],
        query_restrictions: dict[str, Any],
        environment_id: str,
        challenge_relationship: str = "primary_target",
        is_active: bool = True,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Persist an AuthorizedScope row linked to a Challenge.

        H2: validates all scope fields before persistence (fail-closed).
        H2: emits an 'authorized_scope_created' audit event.
        H2: DB-level unique partial index prevents multiple active primary_targets.
        """
        validate_authorized_scope(
            scheme=scheme,
            hostname=hostname,
            port=port,
            environment_id=environment_id,
            challenge_relationship=challenge_relationship,
            allowed_path_patterns=allowed_path_patterns,
            allowed_methods=allowed_methods,
            exclusions=exclusions,
            query_restrictions=query_restrictions,
        )

        now = _now_iso()
        self._conn.execute("BEGIN;")
        try:
            self._conn.execute(
                """
                INSERT INTO authorized_scopes (
                    scope_id, challenge_id, scheme, hostname, port,
                    allowed_path_patterns, allowed_methods, exclusions,
                    query_restrictions, environment_id,
                    challenge_relationship, is_active, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    scope_id, challenge_id, scheme, hostname, port,
                    _to_json(allowed_path_patterns),
                    _to_json(allowed_methods),
                    _to_json(exclusions),
                    _to_json(query_restrictions),
                    environment_id,
                    challenge_relationship,
                    int(is_active),
                    _to_json(metadata or {}),
                    now,
                ),
            )

            # H2/M1: audit event for scope creation
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    "authorized_scope_created",
                    "system",
                    _to_json({
                        "scope_id": scope_id,
                        "hostname": hostname,
                        "scheme": scheme,
                        "port": port,
                        "challenge_relationship": challenge_relationship,
                    }),
                    now,
                    None,
                    None,
                    _to_json({}),
                ),
            )
            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

    def deactivate_authorized_scope(self, scope_id: str, actor: str = "system") -> None:
        """Mark an AuthorizedScope as inactive and emit an audit event."""
        row = self._conn.execute(
            "SELECT challenge_id FROM authorized_scopes WHERE scope_id = ?;",
            (scope_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"AuthorizedScope {scope_id!r} does not exist")

        challenge_id = row["challenge_id"]
        now = _now_iso()
        self._conn.execute("BEGIN;")
        try:
            self._conn.execute(
                "UPDATE authorized_scopes SET is_active = 0 WHERE scope_id = ?;",
                (scope_id,),
            )
            self._conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, blackboard_version_after, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    "authorized_scope_deactivated",
                    actor,
                    _to_json({"scope_id": scope_id}),
                    now,
                    None, None,
                    _to_json({}),
                ),
            )
            self._conn.execute("COMMIT;")
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise

    def read_authorized_scope(self, scope_id: str) -> Optional[dict[str, Any]]:
        """Return an AuthorizedScope row as a dict, or None."""
        row = self._conn.execute(
            "SELECT * FROM authorized_scopes WHERE scope_id = ?;",
            (scope_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def read_authorized_scopes_for_challenge(
        self, challenge_id: str
    ) -> list[dict[str, Any]]:
        """Return all AuthorizedScope rows for a challenge."""
        rows = self._conn.execute(
            "SELECT * FROM authorized_scopes WHERE challenge_id = ?;",
            (challenge_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_version_no_tx(self, challenge_id: str) -> Optional[int]:
        """Read blackboard_version without starting a transaction."""
        row = self._conn.execute(
            "SELECT blackboard_version FROM blackboard_states WHERE challenge_id = ?;",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        return int(row["blackboard_version"])

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            challenge_id=row["challenge_id"],
            event_type=row["event_type"],
            actor=row["actor"],
            payload=_from_json(row["payload"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            blackboard_version_after=row["blackboard_version_after"],
            task_id=row["task_id"],
            metadata=_from_json(row["metadata"]),
        )
