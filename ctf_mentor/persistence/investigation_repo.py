"""
Investigation Repository for Phase 6A Common Investigation Framework.

LOCKED SECURITY INVARIANTS:
1. Owns Phase 6A persistence (investigation_sessions, investigation_steps).
2. Enforces strict challenge-scoped ownership and composite FK validation (session_id, challenge_id) and (step_id, challenge_id).
3. Fail-closed validation for unknown target types, malformed target_json, and cross-challenge target references.
4. Human approval gate: InvestigationStep requires approval_type = 'investigation_step'.
5. Atomic concurrency-safe transactions with immutable event emission.
6. Terminal state reopening is strictly prohibited (enforced via DB triggers & repository logic).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.investigation_models import (
    ConcreteInvestigationResult,
    InvestigationResult,
    InvestigationSession,
    InvestigationSessionStatus,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationTarget,
    TargetType,
)
from ctf_mentor.domain.models import Event
from ctf_mentor.persistence.database import assert_foreign_keys_enabled

logger = logging.getLogger(__name__)



class InvestigationRepository:
    """Repository managing InvestigationSession and InvestigationStep persistence and approval lifecycle."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        assert_foreign_keys_enabled(db_conn)
        self.conn = db_conn
        self.conn.row_factory = sqlite3.Row

    # ---------------------------------------------------------------------------
    # Investigation Session API
    # ---------------------------------------------------------------------------

    def create_session_atomic(
        self,
        challenge_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InvestigationSession:
        """Atomically create a new InvestigationSession for challenge_id."""
        assert_foreign_keys_enabled(self.conn)

        ch_row = self.conn.execute(
            "SELECT challenge_id FROM challenges WHERE challenge_id = ?", (challenge_id,)
        ).fetchone()
        if not ch_row:
            raise ValueError(f"Challenge {challenge_id!r} does not exist.")

        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        now_str = now.isoformat()
        meta_json = json.dumps(metadata or {})

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute(
                """
                INSERT INTO investigation_sessions (
                    session_id, challenge_id, status, created_at, updated_at, metadata
                ) VALUES (?, ?, 'active', ?, ?, ?)
                """,
                (session_id, challenge_id, now_str, now_str, meta_json),
            )

            # Emit InvestigationSessionCreated event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "session_id": session_id,
                "challenge_id": challenge_id,
                "status": "active",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationSessionCreated', 'system', ?, ?, '{}')
                """,
                (event_id, challenge_id, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return InvestigationSession(
            session_id=session_id,
            challenge_id=challenge_id,
            status=InvestigationSessionStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )

    def get_session(self, session_id: str, challenge_id: str) -> Optional[InvestigationSession]:
        """Fetch InvestigationSession by session_id and challenge_id."""
        row = self.conn.execute(
            """
            SELECT session_id, challenge_id, status, created_at, updated_at, metadata
            FROM investigation_sessions
            WHERE session_id = ? AND challenge_id = ?
            """,
            (session_id, challenge_id),
        ).fetchone()

        if not row:
            return None

        return InvestigationSession(
            session_id=row["session_id"],
            challenge_id=row["challenge_id"],
            status=InvestigationSessionStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    # ---------------------------------------------------------------------------
    # Investigation Step API
    # ---------------------------------------------------------------------------

    def create_step_atomic(
        self,
        step: InvestigationStep,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Atomically persist InvestigationStep in PENDING_APPROVAL status with ApprovalRecord."""
        assert_foreign_keys_enabled(self.conn)

        # 1. Validate session ownership and challenge alignment
        session = self.get_session(step.session_id, step.challenge_id)
        if not session:
            raise ValueError(
                f"Invalid session {step.session_id!r} for challenge {step.challenge_id!r}. "
                "Cross-challenge session usage rejected."
            )

        # 2. Validate Target Model
        step.target.validate()

        now_utc = datetime.now(timezone.utc)
        now_str = now_utc.isoformat()
        expires_str = (now_utc + timedelta(seconds=ttl_seconds)).isoformat()
        approval_id = f"app_step_{uuid.uuid4().hex[:12]}"
        target_json_str = step.target.to_json()
        meta_json_str = json.dumps(step.metadata or {})

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # Insert InvestigationStep in PENDING_APPROVAL status
            self.conn.execute(
                """
                INSERT INTO investigation_steps (
                    step_id, session_id, challenge_id, proposal_ref, step_type, target_type,
                    target_json, rationale, status, created_at, updated_at, expires_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?)
                """,
                (
                    step.step_id,
                    step.session_id,
                    step.challenge_id,
                    step.proposal_ref,
                    step.step_type,
                    step.target.target_type.value,
                    target_json_str,
                    step.rationale,
                    now_str,
                    now_str,
                    expires_str,
                    meta_json_str,
                ),
            )

            # Insert ApprovalRecord & ApprovalRequest (approval_type = 'investigation_step')
            self.conn.execute(
                """
                INSERT INTO approval_records (
                    approval_id, challenge_id, approval_type, requested_by, requested_action_ref,
                    status, requested_at
                ) VALUES (?, ?, 'investigation_step', 'system', ?, 'requested', ?)
                """,
                (approval_id, step.challenge_id, step.step_id, now_str),
            )

            self.conn.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, challenge_id, approval_type, requested_by, requested_action_ref,
                    status, requested_at, metadata
                ) VALUES (?, ?, 'investigation_step', 'system', ?, 'requested', ?, ?)
                """,
                (approval_id, step.challenge_id, step.step_id, now_str, meta_json_str),
            )

            # Emit InvestigationStepCreated event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "step_id": step.step_id,
                "session_id": step.session_id,
                "challenge_id": step.challenge_id,
                "step_type": step.step_type,
                "target_type": step.target.target_type.value,
                "approval_id": approval_id,
                "status": "pending_approval",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationStepCreated', 'system', ?, ?, '{}')
                """,
                (event_id, step.challenge_id, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "step_id": step.step_id,
            "session_id": step.session_id,
            "challenge_id": step.challenge_id,
            "approval_id": approval_id,
            "status": "pending_approval",
            "expires_at": expires_str,
        }

    def get_step(self, step_id: str, challenge_id: str) -> Optional[InvestigationStep]:
        """Fetch InvestigationStep by step_id and challenge_id."""
        row = self.conn.execute(
            """
            SELECT step_id, session_id, challenge_id, proposal_ref, step_type, target_type,
                   target_json, rationale, status, created_at, updated_at, expires_at, metadata
            FROM investigation_steps
            WHERE step_id = ? AND challenge_id = ?
            """,
            (step_id, challenge_id),
        ).fetchone()

        if not row:
            return None

        target = InvestigationTarget.from_json(row["target_type"], row["target_json"])

        return InvestigationStep(
            step_id=row["step_id"],
            session_id=row["session_id"],
            challenge_id=row["challenge_id"],
            step_type=row["step_type"],
            target=target,
            rationale=row["rationale"],
            status=InvestigationStepStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            proposal_ref=row["proposal_ref"],
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def approve_step_atomic(
        self,
        step_id: str,
        challenge_id: str,
        user_id: str = "user",
        decision_reason: str = "Approved by user",
    ) -> None:
        """Atomically approve an InvestigationStep."""
        assert_foreign_keys_enabled(self.conn)
        now_str = datetime.now(timezone.utc).isoformat()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            step_row = self.conn.execute(
                "SELECT status, session_id FROM investigation_steps WHERE step_id = ? AND challenge_id = ?",
                (step_id, challenge_id),
            ).fetchone()

            if not step_row:
                raise ValueError(f"Step {step_id!r} for challenge {challenge_id!r} not found.")

            if step_row["status"] != "pending_approval":
                raise ValueError(
                    f"Cannot approve step {step_id!r} in status {step_row['status']!r}. Expected 'pending_approval'."
                )

            # Update step status to APPROVED
            self.conn.execute(
                "UPDATE investigation_steps SET status = 'approved', updated_at = ? WHERE step_id = ? AND challenge_id = ?",
                (now_str, step_id, challenge_id),
            )

            # Update approval records & requests
            self.conn.execute(
                """
                UPDATE approval_records
                SET status = 'approved', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ? AND approval_type = 'investigation_step'
                """,
                (now_str, user_id, decision_reason, step_id, challenge_id),
            )

            self.conn.execute(
                """
                UPDATE approval_requests
                SET status = 'approved', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ? AND approval_type = 'investigation_step'
                """,
                (now_str, user_id, decision_reason, step_id, challenge_id),
            )

            # Emit InvestigationStepApproved event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "step_id": step_id,
                "challenge_id": challenge_id,
                "approved_by": user_id,
                "status": "approved",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationStepApproved', ?, ?, ?, '{}')
                """,
                (event_id, challenge_id, user_id, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def reject_step_atomic(
        self,
        step_id: str,
        challenge_id: str,
        user_id: str = "user",
        decision_reason: str = "Rejected by user",
    ) -> None:
        """Atomically reject an InvestigationStep."""
        assert_foreign_keys_enabled(self.conn)
        now_str = datetime.now(timezone.utc).isoformat()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            step_row = self.conn.execute(
                "SELECT status FROM investigation_steps WHERE step_id = ? AND challenge_id = ?",
                (step_id, challenge_id),
            ).fetchone()

            if not step_row:
                raise ValueError(f"Step {step_id!r} for challenge {challenge_id!r} not found.")

            if step_row["status"] in ("consumed", "rejected", "expired", "cancelled"):
                raise ValueError(f"Step {step_id!r} is already in terminal state {step_row['status']!r}.")

            self.conn.execute(
                "UPDATE investigation_steps SET status = 'rejected', updated_at = ? WHERE step_id = ? AND challenge_id = ?",
                (now_str, step_id, challenge_id),
            )

            self.conn.execute(
                """
                UPDATE approval_records
                SET status = 'rejected', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ? AND approval_type = 'investigation_step'
                """,
                (now_str, user_id, decision_reason, step_id, challenge_id),
            )

            self.conn.execute(
                """
                UPDATE approval_requests
                SET status = 'rejected', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ? AND approval_type = 'investigation_step'
                """,
                (now_str, user_id, decision_reason, step_id, challenge_id),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def submit_step_result_atomic(
        self,
        step_id: str,
        challenge_id: str,
        result: InvestigationResult,
    ) -> Dict[str, Any]:
        """Atomically record an externally supplied InvestigationResult for an APPROVED step."""
        assert_foreign_keys_enabled(self.conn)
        now_str = datetime.now(timezone.utc).isoformat()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            step_row = self.conn.execute(
                "SELECT session_id, status FROM investigation_steps WHERE step_id = ? AND challenge_id = ?",
                (step_id, challenge_id),
            ).fetchone()

            if not step_row:
                raise ValueError(f"Step {step_id!r} for challenge {challenge_id!r} not found.")

            if step_row["status"] != "approved":
                raise ValueError(
                    f"Cannot submit result for step {step_id!r} in status {step_row['status']!r}. Expected 'approved'."
                )

            session_id = getattr(result, "session_id", step_row["session_id"])
            if session_id != step_row["session_id"]:
                raise ValueError(
                    f"Session mismatch: result session {session_id!r} != step session {step_row['session_id']!r}"
                )

            result_type = getattr(result, "result_type", "GENERIC")
            data_json = getattr(result, "data_json", "{}")
            raw_output = result.raw_output
            outcome = result.outcome
            submitted_by = getattr(result, "submitted_by", "user")
            submitted_at = getattr(result, "submitted_at", None)
            submitted_at_str = submitted_at.isoformat() if submitted_at else now_str

            prov_hash = getattr(result, "provenance_hash", "") or hashlib.sha256(
                f"{step_id}:{outcome}:{raw_output}".encode("utf-8")
            ).hexdigest()
            meta_json = json.dumps(getattr(result, "metadata", {}) or {})

            # 1. Insert durable result into investigation_results table
            self.conn.execute(
                """
                INSERT INTO investigation_results (
                    result_id, step_id, session_id, challenge_id, result_type, outcome_status,
                    raw_output, data_json, provenance_hash, submitted_by, submitted_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.result_id,
                    step_id,
                    step_row["session_id"],
                    challenge_id,
                    result_type,
                    outcome,
                    raw_output,
                    data_json,
                    prov_hash,
                    submitted_by,
                    submitted_at_str,
                    meta_json,
                ),
            )

            # 2. Transition step status to RESULT_SUBMITTED
            self.conn.execute(
                "UPDATE investigation_steps SET status = 'result_submitted', updated_at = ? WHERE step_id = ? AND challenge_id = ?",
                (now_str, step_id, challenge_id),
            )

            # 3. Emit InvestigationStepResultSubmitted event
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "step_id": step_id,
                "session_id": step_row["session_id"],
                "challenge_id": challenge_id,
                "result_id": result.result_id,
                "outcome": outcome,
                "status": "result_submitted",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationStepResultSubmitted', ?, ?, ?, '{}')
                """,
                (event_id, challenge_id, submitted_by, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "step_id": step_id,
            "session_id": step_row["session_id"],
            "challenge_id": challenge_id,
            "result_id": result.result_id,
            "status": "result_submitted",
        }

    def get_result(self, step_id: str, challenge_id: str) -> Optional[ConcreteInvestigationResult]:
        """Fetch durably persisted InvestigationResult for a step and challenge."""
        assert_foreign_keys_enabled(self.conn)
        row = self.conn.execute(
            """
            SELECT result_id, step_id, session_id, challenge_id, result_type, outcome_status,
                   raw_output, data_json, provenance_hash, submitted_by, submitted_at, metadata
            FROM investigation_results
            WHERE step_id = ? AND challenge_id = ?
            """,
            (step_id, challenge_id),
        ).fetchone()

        if not row:
            return None

        return ConcreteInvestigationResult(
            result_id=row["result_id"],
            step_id=row["step_id"],
            session_id=row["session_id"],
            challenge_id=row["challenge_id"],
            raw_output=row["raw_output"],
            outcome=row["outcome_status"],
            result_type=row["result_type"],
            data_json=row["data_json"],
            provenance_hash=row["provenance_hash"],
            submitted_by=row["submitted_by"],
            submitted_at=datetime.fromisoformat(row["submitted_at"]) if row["submitted_at"] else None,
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def confirm_step_result_atomic(
        self,
        step_id: str,
        challenge_id: str,
    ) -> Dict[str, Any]:
        """Atomically transition step from RESULT_SUBMITTED to CONFIRMING state and generate a reservation token."""
        assert_foreign_keys_enabled(self.conn)
        now_str = datetime.now(timezone.utc).isoformat()
        reservation_token = f"res_step_{uuid.uuid4().hex[:12]}"

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            step_row = self.conn.execute(
                "SELECT session_id, status, metadata FROM investigation_steps WHERE step_id = ? AND challenge_id = ?",
                (step_id, challenge_id),
            ).fetchone()

            if not step_row:
                raise ValueError(f"Step {step_id!r} for challenge {challenge_id!r} not found.")

            if step_row["status"] != "result_submitted":
                raise ValueError(
                    f"Cannot confirm step {step_id!r} in status {step_row['status']!r}. Expected 'result_submitted'."
                )

            meta = json.loads(step_row["metadata"]) if step_row["metadata"] else {}
            meta["reservation_token"] = reservation_token
            meta_json = json.dumps(meta)

            self.conn.execute(
                "UPDATE investigation_steps SET status = 'confirming', updated_at = ?, metadata = ? WHERE step_id = ? AND challenge_id = ?",
                (now_str, meta_json, step_id, challenge_id),
            )

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "step_id": step_id,
                "session_id": step_row["session_id"],
                "challenge_id": challenge_id,
                "reservation_token": reservation_token,
                "status": "confirming",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationStepConfirming', 'system', ?, ?, '{}')
                """,
                (event_id, challenge_id, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "step_id": step_id,
            "session_id": step_row["session_id"],
            "challenge_id": challenge_id,
            "reservation_token": reservation_token,
            "status": "confirming",
        }

    def finalize_step_confirmation_atomic(
        self,
        step_id: str,
        challenge_id: str,
        reservation_token: str,
    ) -> Dict[str, Any]:
        """Atomically transition step from CONFIRMING to CONSUMED after verifying reservation_token."""
        assert_foreign_keys_enabled(self.conn)
        now_str = datetime.now(timezone.utc).isoformat()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            step_row = self.conn.execute(
                "SELECT session_id, status, metadata FROM investigation_steps WHERE step_id = ? AND challenge_id = ?",
                (step_id, challenge_id),
            ).fetchone()

            if not step_row:
                raise ValueError(f"Step {step_id!r} for challenge {challenge_id!r} not found.")

            if step_row["status"] != "confirming":
                raise ValueError(
                    f"Cannot finalize step {step_id!r} in status {step_row['status']!r}. Expected 'confirming'."
                )

            meta = json.loads(step_row["metadata"]) if step_row["metadata"] else {}
            stored_token = meta.get("reservation_token")
            if not stored_token or stored_token != reservation_token:
                raise ValueError(
                    f"Stale or invalid reservation token for step {step_id!r}. Expected {stored_token!r}, got {reservation_token!r}."
                )

            self.conn.execute(
                "UPDATE investigation_steps SET status = 'consumed', updated_at = ? WHERE step_id = ? AND challenge_id = ?",
                (now_str, step_id, challenge_id),
            )

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            payload = json.dumps({
                "step_id": step_id,
                "session_id": step_row["session_id"],
                "challenge_id": challenge_id,
                "status": "consumed",
            })
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'InvestigationStepConsumed', 'system', ?, ?, '{}')
                """,
                (event_id, challenge_id, payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "step_id": step_id,
            "session_id": step_row["session_id"],
            "challenge_id": challenge_id,
            "status": "consumed",
        }

