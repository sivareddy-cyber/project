"""
IntelligenceRepository for CTF Mentor/Copilot.

Provides authoritative, validated, parameterised SQL persistence for Phase 5D intelligence entities:
- hypotheses
- evidence
- findings
- attempts
- failed_attempts
- challenge_classifications

LOCKED CONCURRENCY & ATOMICITY CONTRACTS:
1. Entity mutations, Blackboard pointer updates (ScopedDiff), and Event log entries MUST commit atomically
   within a SINGLE SQLite transaction.
2. If any part fails or encounters a StaleVersionError, the entire transaction is rolled back. No partial state remains.
3. Handlers NEVER write to SQLite directly. They return EntityWrite objects inside HandlerResult,
   which are validated against field whitelists and parameterised before execution here.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.contracts import EntityWrite, ScopedDiff, StaleVersionError
from ctf_mentor.domain.models import (
    Attempt,
    ChallengeClassification,
    Evidence,
    EvidencePriority,
    FailedAttempt,
    Finding,
    HintLevel,
    Hypothesis,
    HypothesisStatus,
)
from ctf_mentor.persistence.blackboard_repo import (
    ALLOWED_BLACKBOARD_FIELDS,
    BlackboardRepository,
)
from ctf_mentor.persistence.database import assert_foreign_keys_enabled

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-entity field whitelists & primary key mappings
# ---------------------------------------------------------------------------

ENTITY_PRIMARY_KEYS: dict[str, str] = {
    "hypothesis": "hypothesis_id",
    "evidence": "evidence_id",
    "finding": "finding_id",
    "attempt": "attempt_id",
    "failed_attempt": "failed_attempt_id",
    "classification": "classification_id",
}

ENTITY_TABLE_NAMES: dict[str, str] = {
    "hypothesis": "hypotheses",
    "evidence": "evidence",
    "finding": "findings",
    "attempt": "attempts",
    "failed_attempt": "failed_attempts",
    "classification": "challenge_classifications",
}

ALLOWED_ENTITY_FIELDS: dict[str, frozenset[str]] = {
    "hypothesis": frozenset(
        {
            "hypothesis_id",
            "challenge_id",
            "title",
            "description",
            "status",
            "confidence",
            "hint_level",
            "is_primary",
            "metadata",
            "created_at",
            "updated_at",
        }
    ),
    "evidence": frozenset(
        {
            "evidence_id",
            "challenge_id",
            "hypothesis_id",
            "source",
            "content",
            "evidence_type",
            "created_by",
            "is_fabricated",
            "metadata",
            "created_at",
        }
    ),
    "finding": frozenset(
        {
            "finding_id",
            "challenge_id",
            "hypothesis_id",
            "summary",
            "detail",
            "confidence",
            "evidence_ids",
            "metadata",
            "created_at",
        }
    ),
    "attempt": frozenset(
        {
            "attempt_id",
            "challenge_id",
            "hypothesis_id",
            "description",
            "outcome",
            "user_input",
            "tool_output",
            "metadata",
            "created_at",
        }
    ),
    "failed_attempt": frozenset(
        {
            "failed_attempt_id",
            "challenge_id",
            "hypothesis_id",
            "target",
            "description",
            "do_not_repeat_unless",
            "attempt_id",
            "metadata",
            "failed_at",
        }
    ),
    "classification": frozenset(
        {
            "classification_id",
            "challenge_id",
            "category",
            "confidence",
            "signals",
            "ruleset_version",
            "created_at",
        }
    ),
}


from ctf_mentor.persistence.blackboard_repo import (
    ALLOWED_BLACKBOARD_FIELDS,
    BlackboardRepository,
    validate_scoped_diff_authoritative,
)
from ctf_mentor.persistence.database import assert_foreign_keys_enabled

logger = logging.getLogger(__name__)


class IntelligenceReader:
    """Read-only data reader interface for TaskHandlers. No write methods exposed."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        assert_foreign_keys_enabled(conn)
        self.conn = conn
        self.conn.row_factory = sqlite3.Row

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT hypothesis_id, challenge_id, title, description, status,
                   confidence, hint_level, is_primary, metadata, created_at, updated_at
            FROM hypotheses
            WHERE hypothesis_id = ?
            """,
            (hypothesis_id,),
        )
        r = cursor.fetchone()
        if not r:
            return None
        return Hypothesis(
            hypothesis_id=r["hypothesis_id"],
            challenge_id=r["challenge_id"],
            title=r["title"],
            description=r["description"],
            status=HypothesisStatus(r["status"]),
            confidence=r["confidence"],
            hint_level=HintLevel(r["hint_level"]),
            is_primary=bool(r["is_primary"]),
            metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            created_at=datetime.fromisoformat(r["created_at"]),
            updated_at=datetime.fromisoformat(r["updated_at"]),
        )

    def has_user_confirmed_evidence(self, challenge_id: str, hypothesis_id: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM evidence
            WHERE challenge_id = ? AND hypothesis_id = ? AND source = 'user_confirmed' AND is_fabricated = 0
            LIMIT 1
            """,
            (challenge_id, hypothesis_id),
        )
        return cursor.fetchone() is not None

    def get_classifications(self, challenge_id: str) -> List[ChallengeClassification]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT classification_id, challenge_id, category, confidence,
                   signals, ruleset_version, created_at
            FROM challenge_classifications
            WHERE challenge_id = ?
            ORDER BY created_at DESC
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                ChallengeClassification(
                    classification_id=r["classification_id"],
                    challenge_id=r["challenge_id"],
                    category=r["category"],
                    confidence=r["confidence"],
                    signals=json.loads(r["signals"]) if r["signals"] else [],
                    ruleset_version=r["ruleset_version"],
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_latest_classification(self, challenge_id: str) -> Optional[ChallengeClassification]:
        clist = self.get_classifications(challenge_id)
        return clist[0] if clist else None

    def get_hypotheses(self, challenge_id: str) -> List[Hypothesis]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT hypothesis_id, challenge_id, title, description, status,
                   confidence, hint_level, is_primary, metadata, created_at, updated_at
            FROM hypotheses
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Hypothesis(
                    hypothesis_id=r["hypothesis_id"],
                    challenge_id=r["challenge_id"],
                    title=r["title"],
                    description=r["description"],
                    status=HypothesisStatus(r["status"]),
                    confidence=r["confidence"],
                    hint_level=HintLevel(r["hint_level"]),
                    is_primary=bool(r["is_primary"]),
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                    updated_at=datetime.fromisoformat(r["updated_at"]),
                )
            )
        return results

    def get_evidence(self, challenge_id: str) -> List[Evidence]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, challenge_id, hypothesis_id, source, content,
                   evidence_type, created_by, is_fabricated, metadata, created_at
            FROM evidence
            WHERE challenge_id = ?
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Evidence(
                    evidence_id=r["evidence_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    source=EvidencePriority(r["source"]),
                    content=r["content"],
                    evidence_type=r["evidence_type"],
                    created_by=r["created_by"],
                    is_fabricated=bool(r["is_fabricated"]),
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_findings(self, challenge_id: str) -> List[Finding]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT finding_id, challenge_id, hypothesis_id, summary, detail,
                   confidence, evidence_ids, metadata, created_at
            FROM findings
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Finding(
                    finding_id=r["finding_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    summary=r["summary"],
                    detail=r["detail"],
                    confidence=r["confidence"],
                    evidence_ids=json.loads(r["evidence_ids"]) if r["evidence_ids"] else [],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_attempts(self, challenge_id: str) -> List[Attempt]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT attempt_id, challenge_id, hypothesis_id, description, outcome,
                   user_input, tool_output, metadata, created_at
            FROM attempts
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Attempt(
                    attempt_id=r["attempt_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    description=r["description"],
                    outcome=r["outcome"],
                    user_input=r["user_input"],
                    tool_output=r["tool_output"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_failed_attempts(self, challenge_id: str) -> List[FailedAttempt]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT failed_attempt_id, challenge_id, hypothesis_id, attempt_id,
                   target, description, do_not_repeat_unless, metadata, failed_at
            FROM failed_attempts
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                FailedAttempt(
                    failed_attempt_id=r["failed_attempt_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    attempt_id=r["attempt_id"],
                    target=r["target"],
                    description=r["description"],
                    do_not_repeat_unless=r["do_not_repeat_unless"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    failed_at=datetime.fromisoformat(r["failed_at"]),
                )
            )
        return results


class IntelligenceRepository:
    """Repository handling SQL persistence for intelligence entities."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        blackboard_repo: Optional[BlackboardRepository] = None,
    ) -> None:
        assert_foreign_keys_enabled(conn)
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.blackboard_repo = blackboard_repo or BlackboardRepository(conn)

    # ---------------------------------------------------------------------------
    # Atomic Execution API
    # ---------------------------------------------------------------------------

    def apply_writes_and_diff_atomic(
        self,
        challenge_id: str,
        entity_writes: Optional[List[EntityWrite]] = None,
        scoped_diff: Optional[ScopedDiff] = None,
        events: Optional[List[Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
    ) -> int:
        """Atomically apply entity writes, Blackboard scoped diff, and lifecycle events within one transaction.

        Guarantees:
        1. Every Blackboard mutation emits a corresponding Event (blackboard_version_after = new_version) in the same transaction.
        2. All entity writes are validated for existence, PK identity, and challenge ownership.
        3. If any part fails or hits a StaleVersionError, the entire transaction rolls back.
        """
        assert_foreign_keys_enabled(self.conn)

        entity_writes = entity_writes or []

        # 1. Validate entity writes and scoped diff before transaction
        for ew in entity_writes:
            self._validate_entity_write(ew, challenge_id)

        if scoped_diff:
            validate_scoped_diff_authoritative(self.conn, scoped_diff)

        current_bb_ver = self.blackboard_repo.read_blackboard_version(challenge_id)

        self.conn.execute("BEGIN;")
        try:
            # 2. Execute entity writes with DB-level row existence and ownership checks
            for ew in entity_writes:
                self._execute_entity_write(ew, challenge_id)

            # Issue 2: Authoritative persistence check for max 3 active hypotheses
            active_count_row = self.conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE challenge_id = ? AND status = 'active';",
                (challenge_id,),
            ).fetchone()
            if active_count_row and active_count_row[0] > 3:
                raise ValueError(
                    f"Maximum 3 active hypotheses limit exceeded for challenge {challenge_id!r}; "
                    f"DB active hypothesis count is {active_count_row[0]}."
                )

            # 3. Execute Blackboard scoped diff and emit mutation event atomically
            new_version = current_bb_ver
            if scoped_diff:
                new_version = self._apply_scoped_diff_in_tx(scoped_diff)

                # Atomically insert Blackboard mutation event inside SAME transaction (Blocker 1)
                mutation_event = {
                    "event_id": str(uuid.uuid4()),
                    "event_type": scoped_diff.event_type,
                    "actor": scoped_diff.actor,
                    "payload": {
                        "challenge_id": challenge_id,
                        "actor": scoped_diff.actor,
                        "previous_version": scoped_diff.expected_version,
                        "new_version": new_version,
                        "changes": list(scoped_diff.changes.keys()),
                    },
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "task_id": task_id,
                }
                self._insert_event_in_tx(challenge_id, mutation_event, new_version)

            # 4. Insert any additional lifecycle events (Issue 4: blackboard_version_after = None for lifecycle events)
            if events:
                for evt in events:
                    self._insert_event_in_tx(challenge_id, evt, blackboard_version_after=None)

            self.conn.execute("COMMIT;")
            return new_version

        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    # ---------------------------------------------------------------------------
    # Read Helpers
    # ---------------------------------------------------------------------------

    def get_classifications(self, challenge_id: str) -> List[ChallengeClassification]:
        """Fetch classification history for a challenge (newest first)."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT classification_id, challenge_id, category, confidence,
                   signals, ruleset_version, created_at
            FROM challenge_classifications
            WHERE challenge_id = ?
            ORDER BY created_at DESC
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                ChallengeClassification(
                    classification_id=r["classification_id"],
                    challenge_id=r["challenge_id"],
                    category=r["category"],
                    confidence=r["confidence"],
                    signals=json.loads(r["signals"]) if r["signals"] else [],
                    ruleset_version=r["ruleset_version"],
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_latest_classification(self, challenge_id: str) -> Optional[ChallengeClassification]:
        """Fetch the latest classification for a challenge."""
        clist = self.get_classifications(challenge_id)
        return clist[0] if clist else None

    def get_hypotheses(self, challenge_id: str) -> List[Hypothesis]:
        """Fetch all hypotheses for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT hypothesis_id, challenge_id, title, description, status,
                   confidence, hint_level, is_primary, metadata, created_at, updated_at
            FROM hypotheses
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Hypothesis(
                    hypothesis_id=r["hypothesis_id"],
                    challenge_id=r["challenge_id"],
                    title=r["title"],
                    description=r["description"],
                    status=HypothesisStatus(r["status"]),
                    confidence=r["confidence"],
                    hint_level=HintLevel(r["hint_level"]),
                    is_primary=bool(r["is_primary"]),
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                    updated_at=datetime.fromisoformat(r["updated_at"]),
                )
            )
        return results

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Fetch hypothesis by hypothesis_id."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT hypothesis_id, challenge_id, title, description, status,
                   confidence, hint_level, is_primary, metadata, created_at, updated_at
            FROM hypotheses
            WHERE hypothesis_id = ?
            """,
            (hypothesis_id,),
        )
        r = cursor.fetchone()
        if not r:
            return None
        return Hypothesis(
            hypothesis_id=r["hypothesis_id"],
            challenge_id=r["challenge_id"],
            title=r["title"],
            description=r["description"],
            status=HypothesisStatus(r["status"]),
            confidence=r["confidence"],
            hint_level=HintLevel(r["hint_level"]),
            is_primary=bool(r["is_primary"]),
            metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            created_at=datetime.fromisoformat(r["created_at"]),
            updated_at=datetime.fromisoformat(r["updated_at"]),
        )

    def get_evidence(self, challenge_id: str) -> List[Evidence]:
        """Fetch all evidence for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, challenge_id, hypothesis_id, source, content,
                   evidence_type, created_by, is_fabricated, metadata, created_at
            FROM evidence
            WHERE challenge_id = ?
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Evidence(
                    evidence_id=r["evidence_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    source=EvidencePriority(r["source"]),
                    content=r["content"],
                    evidence_type=r["evidence_type"],
                    created_by=r["created_by"],
                    is_fabricated=bool(r["is_fabricated"]),
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_findings(self, challenge_id: str) -> List[Finding]:
        """Fetch all findings for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT finding_id, challenge_id, hypothesis_id, summary, detail,
                   confidence, evidence_ids, metadata, created_at
            FROM findings
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Finding(
                    finding_id=r["finding_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    summary=r["summary"],
                    detail=r["detail"],
                    confidence=r["confidence"],
                    evidence_ids=json.loads(r["evidence_ids"]) if r["evidence_ids"] else [],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_attempts(self, challenge_id: str) -> List[Attempt]:
        """Fetch all attempts for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT attempt_id, challenge_id, hypothesis_id, description, outcome,
                   user_input, tool_output, metadata, created_at
            FROM attempts
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                Attempt(
                    attempt_id=r["attempt_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    description=r["description"],
                    outcome=r["outcome"],
                    user_input=r["user_input"],
                    tool_output=r["tool_output"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return results

    def get_failed_attempts(self, challenge_id: str) -> List[FailedAttempt]:
        """Fetch all failed attempts for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT failed_attempt_id, challenge_id, hypothesis_id, attempt_id,
                   target, description, do_not_repeat_unless, metadata, failed_at
            FROM failed_attempts
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                FailedAttempt(
                    failed_attempt_id=r["failed_attempt_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    attempt_id=r["attempt_id"],
                    target=r["target"],
                    description=r["description"],
                    do_not_repeat_unless=r["do_not_repeat_unless"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    failed_at=datetime.fromisoformat(r["failed_at"]),
                )
            )
        return results

    # ---------------------------------------------------------------------------
    # Private Implementation & Validation
    # ---------------------------------------------------------------------------

    def _validate_entity_write(self, ew: EntityWrite, challenge_id: str) -> None:
        """Validate fields against allowed whitelist and challenge ownership for the given entity_type."""
        if not ew.entity_id or not str(ew.entity_id).strip():
            raise ValueError(f"EntityWrite.entity_id must not be empty for entity_type {ew.entity_type!r}")

        allowed = ALLOWED_ENTITY_FIELDS.get(ew.entity_type)
        if not allowed:
            raise ValueError(f"Unknown entity_type {ew.entity_type!r}")

        invalid_keys = set(ew.fields.keys()) - allowed
        if invalid_keys:
            raise ValueError(
                f"Invalid fields for entity_type {ew.entity_type!r}: {sorted(invalid_keys)}. "
                f"Allowed fields: {sorted(allowed)}"
            )

        pk_col = ENTITY_PRIMARY_KEYS[ew.entity_type]
        if ew.operation == "insert":
            if pk_col not in ew.fields:
                raise ValueError(
                    f"INSERT EntityWrite missing required primary key field {pk_col!r} in fields for entity_type {ew.entity_type!r}"
                )
            if ew.fields[pk_col] != ew.entity_id:
                raise ValueError(
                    f"EntityWrite entity_id {ew.entity_id!r} does not match fields[{pk_col!r}] {ew.fields[pk_col]!r}"
                )
        elif ew.operation == "update":
            if pk_col in ew.fields and ew.fields[pk_col] != ew.entity_id:
                raise ValueError(
                    f"EntityWrite entity_id {ew.entity_id!r} does not match fields[{pk_col!r}] {ew.fields[pk_col]!r}"
                )

        if "challenge_id" in ew.fields and ew.fields["challenge_id"] != challenge_id:
            raise ValueError(
                f"Cross-challenge EntityWrite rejected: fields['challenge_id'] {ew.fields['challenge_id']!r} "
                f"does not match target challenge_id {challenge_id!r}"
            )

    def _execute_entity_write(self, ew: EntityWrite, challenge_id: str) -> None:
        """Construct and execute parameterised SQL statement for an EntityWrite with DB integrity checks."""
        table = ENTITY_TABLE_NAMES[ew.entity_type]
        pk_col = ENTITY_PRIMARY_KEYS[ew.entity_type]

        cursor = self.conn.cursor()

        if ew.operation == "insert":
            # Primary key existence & cross-challenge check
            pk_row = cursor.execute(f"SELECT challenge_id FROM {table} WHERE {pk_col} = ?", (ew.entity_id,)).fetchone()
            if pk_row and pk_row["challenge_id"] != challenge_id:
                raise ValueError(
                    f"Cross-challenge INSERT rejected: Entity {ew.entity_id!r} belongs to challenge "
                    f"{pk_row['challenge_id']!r}, not {challenge_id!r}."
                )

        elif ew.operation == "update":
            # Row existence & challenge ownership check
            row = cursor.execute(f"SELECT challenge_id FROM {table} WHERE {pk_col} = ?", (ew.entity_id,)).fetchone()
            if not row:
                raise ValueError(f"UPDATE rejected: Nonexistent entity {ew.entity_id!r} in table {table!r}.")
            if row["challenge_id"] != challenge_id:
                raise ValueError(
                    f"Cross-challenge UPDATE rejected: Entity {ew.entity_id!r} belongs to challenge "
                    f"{row['challenge_id']!r}, not {challenge_id!r}."
                )

        processed_fields: dict[str, Any] = {}
        for k, v in ew.fields.items():
            if isinstance(v, (dict, list)):
                processed_fields[k] = json.dumps(v)
            elif isinstance(v, datetime):
                processed_fields[k] = v.isoformat()
            elif isinstance(v, bool) and k != "confidence":
                processed_fields[k] = 1 if v else 0
            elif hasattr(v, "value"):
                processed_fields[k] = v.value
            else:
                processed_fields[k] = v

        if ew.operation == "insert":
            cols = list(processed_fields.keys())
            placeholders = ", ".join(["?"] * len(cols))
            col_str = ", ".join(cols)
            sql = f"INSERT INTO {table} ({col_str}) VALUES ({placeholders});"
            vals = [processed_fields[c] for c in cols]
            cursor.execute(sql, vals)

        elif ew.operation == "update":
            update_cols = [c for c in processed_fields.keys() if c != pk_col]
            if not update_cols:
                return

            set_str = ", ".join([f"{c} = ?" for c in update_cols])
            sql = f"UPDATE {table} SET {set_str} WHERE {pk_col} = ?;"
            vals = [processed_fields[c] for c in update_cols] + [ew.entity_id]
            cursor.execute(sql, vals)

    def _apply_scoped_diff_in_tx(self, diff: ScopedDiff) -> int:
        """Apply ScopedDiff inside an active transaction. Raises StaleVersionError on version mismatch."""
        cursor = self.conn.cursor()

        set_parts = []
        vals = []

        for field_name, value in diff.changes.items():
            if isinstance(value, (dict, list)):
                val_str = json.dumps(value)
            elif hasattr(value, "value"):
                val_str = value.value
            else:
                val_str = value
            set_parts.append(f"{field_name} = ?")
            vals.append(val_str)

        now = datetime.now(timezone.utc).isoformat()
        set_parts.append("blackboard_version = blackboard_version + 1")
        set_parts.append("updated_at = ?")
        vals.append(now)

        vals.append(diff.challenge_id)
        vals.append(diff.expected_version)

        set_sql = ", ".join(set_parts)
        sql = f"""
        UPDATE blackboard_states
        SET {set_sql}
        WHERE challenge_id = ?
          AND blackboard_version = ?
        """

        cursor.execute(sql, vals)
        if cursor.rowcount == 0:
            found_version = self.blackboard_repo.read_blackboard_version(diff.challenge_id)
            raise StaleVersionError(
                challenge_id=diff.challenge_id,
                expected=diff.expected_version,
                found=found_version,
            )

        return diff.expected_version + 1

    def _insert_event_in_tx(
        self,
        challenge_id: str,
        event_dict: Dict[str, Any],
        blackboard_version_after: Optional[int] = None,
    ) -> None:
        """Insert a lifecycle event inside an active transaction."""
        event_id = event_dict.get("event_id") or str(uuid.uuid4())
        event_type = event_dict.get("event_type", "IntelligenceEvent")
        actor = event_dict.get("actor", "system")
        payload = event_dict.get("payload", {})
        occurred_at = event_dict.get("occurred_at") or datetime.now(timezone.utc).isoformat()
        task_id = event_dict.get("task_id")

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO events (
                event_id, challenge_id, event_type, actor, payload,
                occurred_at, blackboard_version_after, task_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                challenge_id,
                event_type,
                actor,
                json.dumps(payload),
                occurred_at,
                blackboard_version_after,
                task_id,
            ),
        )
