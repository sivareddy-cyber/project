"""
Action Proposal Repository for Phase 6 Persistence, State Machine, & Single-Use Approval Gates.

LOCKED SECURITY INVARIANTS:
1. Owns Phase 6 persistence (action_proposals, action_results, authorized_scope_entries).
2. 1:1 single-use approval gate: Result submission is IMPOSSIBLE without an unconsumed approved ApprovalRecord.
3. Atomic concurrency-safe transactions with immutable event emission.
4. Terminal state reopening is strictly prohibited.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import (
    ActionProposal,
    ActionProposalState,
    ActionProposalTarget,
    ActionProposalType,
    ActionResult,
    ApprovalRecord,
    ApprovalStatus,
    ApprovalType,
    AuthorizedScope,
)
from ctf_mentor.persistence.database import assert_foreign_keys_enabled


class ActionProposalRepository:
    """Repository managing ActionProposal state machine, approvals, and ActionResult persistence."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        assert_foreign_keys_enabled(db_conn)
        self.conn = db_conn

    def save_authorized_scope_entry(
        self,
        scope_id: str,
        challenge_id: str,
        hostname: str,
        port: int,
        scheme: str = "http",
        path_pattern: str = "/*",
        allowed_methods: List[str] = None,
        exclusions: List[str] = None,
    ) -> str:
        """Persist a human-provisioned AuthorizedScope entry."""
        entry_id = f"entry_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()
        methods_json = json.dumps(allowed_methods or ["GET", "POST"])
        excl_json = json.dumps(exclusions or [])

        self.conn.execute(
            """
            INSERT INTO authorized_scope_entries (
                entry_id, scope_id, challenge_id, scheme, hostname, port, path_pattern, allowed_methods, exclusions, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (entry_id, scope_id, challenge_id, scheme, hostname, port, path_pattern, methods_json, excl_json, now_str),
        )
        self.conn.commit()
        return entry_id

    def create_proposal_atomic(
        self,
        proposal: ActionProposal,
        scope_id: Optional[str] = None,
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Atomically persist ActionProposal in PENDING_APPROVAL state and create ApprovalRecord."""
        now_utc = datetime.now(timezone.utc)
        now_str = now_utc.isoformat()
        expires_str = (now_utc + timedelta(seconds=ttl_seconds)).isoformat()
        approval_id = f"app_act_{uuid.uuid4().hex[:12]}"

        target_json = json.dumps({
            "scheme": proposal.target.scheme,
            "hostname": proposal.target.hostname,
            "port": proposal.target.port,
            "path": proposal.target.path,
            "method": proposal.target.method,
            "headers": proposal.target.headers,
            "query_params": proposal.target.query_params,
        })

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Insert ActionProposal (state PENDING_APPROVAL)
            self.conn.execute(
                """
                INSERT INTO action_proposals (
                    proposal_id, challenge_id, request_id, action_type, target_json, rationale, hypothesis_id, scope_id, scope_version, status, created_at, expires_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal.proposal_id,
                    proposal.challenge_id,
                    proposal.request_id,
                    proposal.action_type.value,
                    target_json,
                    proposal.rationale,
                    proposal.hypothesis_id,
                    scope_id or proposal.scope_id,
                    proposal.scope_version,
                    ActionProposalState.PENDING_APPROVAL.value,
                    now_str,
                    expires_str,
                    json.dumps(proposal.metadata),
                ),
            )

            # 2. Insert ApprovalRecord
            self.conn.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, challenge_id, approval_type, requested_by, requested_action_ref, status, requested_at, decision_reason, related_request_id, metadata
                ) VALUES (?, ?, ?, 'proposal_drafter', ?, 'pending', ?, 'Pending human review', ?, ?)
                """,
                (
                    approval_id,
                    proposal.challenge_id,
                    ApprovalType.ACTION_PROPOSAL.value,
                    proposal.proposal_id,
                    now_str,
                    proposal.request_id,
                    json.dumps({"proposal_id": proposal.proposal_id, "action_type": proposal.action_type.value}),
                ),
            )

            # 3. Emit ActionProposed event
            event_id = str(uuid.uuid4())
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionProposed', 'proposal_drafter', ?, ?, '{}')
                """,
                (
                    event_id,
                    proposal.challenge_id,
                    json.dumps({
                        "proposal_id": proposal.proposal_id,
                        "action_type": proposal.action_type.value,
                        "approval_id": approval_id,
                    }),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "proposal_id": proposal.proposal_id,
            "approval_id": approval_id,
            "status": ActionProposalState.PENDING_APPROVAL.value,
        }

    @staticmethod
    def _val(row: Any, key: str, idx: int = 0) -> Any:
        if row is None:
            return None
        if hasattr(row, "keys"):
            return row[key]
        return row[idx]

    def approve_proposal_atomic(self, proposal_id: str, challenge_id: str, user_id: str = "user") -> bool:
        """Atomically transition proposal to APPROVED and resolve ApprovalRecord."""
        now_str = datetime.now(timezone.utc).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            row = self.conn.execute(
                "SELECT status FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()

            if not row or self._val(row, "status", 0) != ActionProposalState.PENDING_APPROVAL.value:
                self.conn.execute("ROLLBACK;")
                return False

            # Update proposal
            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ?",
                (ActionProposalState.APPROVED.value, proposal_id, challenge_id),
            )

            # Update approval_requests
            self.conn.execute(
                """
                UPDATE approval_requests
                SET status = 'approved', resolved_at = ?, resolved_by = ?, decision_reason = 'Approved by human operator'
                WHERE requested_action_ref = ? AND challenge_id = ?
                """,
                (now_str, user_id, proposal_id, challenge_id),
            )

            # Emit ActionApproved event
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionApproved', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    user_id,
                    json.dumps({"proposal_id": proposal_id}),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
            return True
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def reject_proposal_atomic(
        self, proposal_id: str, challenge_id: str, rejection_reason: str = "", user_id: str = "user"
    ) -> bool:
        """Atomically transition proposal to REJECTED."""
        now_str = datetime.now(timezone.utc).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            row = self.conn.execute(
                "SELECT status FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()

            status_val = self._val(row, "status", 0)
            if not row or status_val in {ActionProposalState.CONSUMED.value, ActionProposalState.RESULT_SUBMITTED.value}:
                self.conn.execute("ROLLBACK;")
                return False

            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ?",
                (ActionProposalState.REJECTED.value, proposal_id, challenge_id),
            )

            self.conn.execute(
                """
                UPDATE approval_requests
                SET status = 'rejected', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ?
                """,
                (now_str, user_id, rejection_reason or "Rejected by human operator", proposal_id, challenge_id),
            )

            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionRejected', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    user_id,
                    json.dumps({"proposal_id": proposal_id, "reason": rejection_reason}),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
            return True
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def submit_result_atomic(
        self,
        proposal_id: str,
        challenge_id: str,
        raw_output: str,
        outcome: str = "success",
        user_id: str = "user",
    ) -> Dict[str, Any]:
        """Atomically check single-use approval, persist append-only ActionResult, and advance state."""
        now_str = datetime.now(timezone.utc).isoformat()
        result_id = f"res_{uuid.uuid4().hex[:12]}"

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Verify proposal exists and is APPROVED for challenge_id
            prop = self.conn.execute(
                "SELECT status, expires_at FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()

            if not prop:
                raise ValueError(f"Proposal {proposal_id!r} not found for challenge {challenge_id!r}.")

            prop_status = self._val(prop, "status", 0)
            if prop_status != ActionProposalState.APPROVED.value:
                raise ValueError(
                    f"Proposal {proposal_id!r} cannot submit result: status is {prop_status!r}, expected 'approved'."
                )

            # Check expiration
            expires_at = self._val(prop, "expires_at", 1)
            if expires_at:
                exp_dt = datetime.fromisoformat(expires_at)
                if datetime.now(timezone.utc) > exp_dt:
                    self.conn.execute(
                        "UPDATE action_proposals SET status = ? WHERE proposal_id = ?",
                        (ActionProposalState.EXPIRED.value, proposal_id),
                    )
                    raise ValueError(f"Proposal {proposal_id!r} has expired.")


            # 2. Check matching single-use approved ApprovalRecord
            app_row = self.conn.execute(
                """
                SELECT approval_id FROM approval_requests
                WHERE requested_action_ref = ? AND challenge_id = ? AND status = 'approved'
                """,
                (proposal_id, challenge_id),
            ).fetchone()

            if not app_row:
                raise ValueError(f"No active approved ApprovalRecord found for proposal {proposal_id!r}.")

            # 3. Check single-use: Ensure no ActionResult already exists for this proposal
            existing_res = self.conn.execute(
                "SELECT result_id FROM action_results WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()

            if existing_res:
                raise ValueError(f"Approval for proposal {proposal_id!r} has already been consumed.")

            # 4. Insert append-only ActionResult
            self.conn.execute(
                """
                INSERT INTO action_results (
                    result_id, proposal_id, challenge_id, raw_output, outcome, submitted_at, submitted_by, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    proposal_id,
                    challenge_id,
                    raw_output,
                    outcome,
                    now_str,
                    user_id,
                    json.dumps({"approval_id": app_row["approval_id"]}),
                ),
            )

            # 5. Advance proposal state to RESULT_SUBMITTED
            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ?",
                (ActionProposalState.RESULT_SUBMITTED.value, proposal_id),
            )

            # 6. Emit ActionResultSubmitted event
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionResultSubmitted', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    user_id,
                    json.dumps({"proposal_id": proposal_id, "result_id": result_id}),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "result_id": result_id,
            "proposal_id": proposal_id,
            "challenge_id": challenge_id,
            "status": ActionProposalState.RESULT_SUBMITTED.value,
        }

    def get_proposal(self, proposal_id: str, challenge_id: str) -> Optional[ActionProposal]:
        """Fetch ActionProposal domain object by ID and challenge_id."""
        row = self.conn.execute(
            "SELECT * FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
            (proposal_id, challenge_id),
        ).fetchone()

        if not row:
            return None

        t_data = json.loads(row["target_json"])
        target = ActionProposalTarget(
            scheme=t_data.get("scheme", "http"),
            hostname=t_data.get("hostname", ""),
            port=t_data.get("port", 80),
            path=t_data.get("path", "/"),
            method=t_data.get("method", "GET"),
            headers=t_data.get("headers", {}),
            query_params=t_data.get("query_params", {}),
        )

        return ActionProposal(
            proposal_id=row["proposal_id"],
            challenge_id=row["challenge_id"],
            request_id=row["request_id"],
            action_type=ActionProposalType(row["action_type"]),
            target=target,
            rationale=row["rationale"],
            hypothesis_id=row["hypothesis_id"],
            scope_id=row["scope_id"],
            scope_version=row["scope_version"],
            status=ActionProposalState(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            metadata=json.loads(row["metadata"]),
        )

    def mark_proposal_consumed_atomic(
        self, proposal_id: str, challenge_id: str, user_id: str = "user"
    ) -> bool:
        """Atomically transition proposal from RESULT_SUBMITTED to CONSUMED after human confirmation."""
        now_str = datetime.now(timezone.utc).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            row = self.conn.execute(
                "SELECT status FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()

            if not row or self._val(row, "status", 0) != ActionProposalState.RESULT_SUBMITTED.value:
                self.conn.execute("ROLLBACK;")
                return False

            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ?",
                (ActionProposalState.CONSUMED.value, proposal_id, challenge_id),
            )

            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionConsumed', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    user_id,
                    json.dumps({"proposal_id": proposal_id}),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
            return True
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def save_normalized_draft_atomic(
        self,
        draft: Any,
    ) -> str:
        """Atomically persist a NormalizedEvidenceDraft awaiting human confirmation."""
        draft_id = f"draft_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()
        headers_json = json.dumps(getattr(draft, "extracted_headers", {}) or {})
        meta_json = json.dumps(getattr(draft, "metadata", {}) or {})

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute(
                """
                INSERT INTO normalized_evidence_drafts (
                    draft_id, proposal_id, result_id, challenge_id, hypothesis_id,
                    summary_content, raw_snippet, extracted_status_code, extracted_headers,
                    is_confirmed, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    draft_id,
                    draft.proposal_id,
                    draft.result_id,
                    draft.challenge_id,
                    draft.hypothesis_id,
                    draft.summary_content,
                    draft.raw_snippet,
                    draft.extracted_status_code,
                    headers_json,
                    meta_json,
                    now_str,
                ),
            )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise
        return draft_id

    def get_normalized_draft(
        self, proposal_id: str, challenge_id: str
    ) -> Optional[Any]:
        """Fetch NormalizedEvidenceDraft by proposal_id and challenge_id."""
        row = self.conn.execute(
            """
            SELECT * FROM normalized_evidence_drafts
            WHERE proposal_id = ? AND challenge_id = ?
            """,
            (proposal_id, challenge_id),
        ).fetchone()

        if not row:
            return None

        from ctf_mentor.investigation.normalizer import NormalizedEvidenceDraft

        status_code = self._val(row, "extracted_status_code", 7)
        is_conf = bool(self._val(row, "is_confirmed", 9))
        headers_raw = self._val(row, "extracted_headers", 8) or "{}"
        headers_dict = json.loads(headers_raw) if isinstance(headers_raw, str) else {}
        meta_raw = self._val(row, "metadata", 12) or "{}"
        meta_dict = json.loads(meta_raw) if isinstance(meta_raw, str) else {}

        return NormalizedEvidenceDraft(
            challenge_id=self._val(row, "challenge_id", 3),
            proposal_id=self._val(row, "proposal_id", 1),
            result_id=self._val(row, "result_id", 2),
            summary_content=self._val(row, "summary_content", 5),
            raw_snippet=self._val(row, "raw_snippet", 6),
            hypothesis_id=self._val(row, "hypothesis_id", 4),
            extracted_status_code=status_code,
            extracted_headers=headers_dict,
            is_confirmed=is_conf,
            metadata=meta_dict,
        )

    def check_canonical_evidence_exists(
        self, proposal_id: str, challenge_id: str
    ) -> Optional[Dict[str, Any]]:
        """Check if canonical evidence for proposal_id already exists in Phase 5D evidence table."""
        try:
            row = self.conn.execute(
                """
                SELECT evidence_id, content, metadata FROM evidence
                WHERE challenge_id = ? AND json_extract(metadata, '$.proposal_id') = ?
                """,
                (challenge_id, proposal_id),
            ).fetchone()
            if row:
                ev_id = self._val(row, "evidence_id", 0)
                content = self._val(row, "content", 1)
                meta_raw = self._val(row, "metadata", 2) or "{}"
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else {}
                return {"evidence_id": ev_id, "content": content, "metadata": meta}
        except Exception:
            pass

        rows = self.conn.execute(
            """
            SELECT evidence_id, content, metadata FROM evidence
            WHERE challenge_id = ? AND metadata LIKE ?
            """,
            (challenge_id, f'%"{proposal_id}"%'),
        ).fetchall()
        for r in rows:
            meta_raw = self._val(r, "metadata", 2) or "{}"
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else {}
                if meta.get("proposal_id") == proposal_id:
                    ev_id = self._val(r, "evidence_id", 0)
                    content = self._val(r, "content", 1)
                    return {"evidence_id": ev_id, "content": content, "metadata": meta}
            except Exception:
                continue

        return None

    def prepare_draft_confirmation_atomic(
        self,
        proposal_id: str,
        result_id: str,
        challenge_id: str,
        user_id: str = "user",
        reservation_ttl_seconds: int = 30,
    ) -> Any:
        """Atomically validate draft confirmation preconditions & claim confirmation reservation under BEGIN IMMEDIATE."""
        from ctf_mentor.investigation.normalizer import NormalizedEvidenceDraft

        reservation_token = f"resv_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc)
        now_str = now_utc.isoformat()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Proposal validation
            prop = self.conn.execute(
                "SELECT status, expires_at, metadata FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()
            if not prop:
                raise ValueError(f"Proposal {proposal_id!r} not found for challenge {challenge_id!r}.")

            status_val = self._val(prop, "status", 0)
            if status_val == ActionProposalState.CONSUMED.value:
                raise ValueError(f"Proposal {proposal_id!r} has already been consumed.")
            if status_val in {ActionProposalState.CANCELLED.value, ActionProposalState.REJECTED.value}:
                raise ValueError(f"Proposal {proposal_id!r} cannot be confirmed (status is {status_val!r}).")

            # Check expiration
            expires_at = self._val(prop, "expires_at", 1)
            if expires_at:
                exp_dt = datetime.fromisoformat(expires_at)
                if now_utc > exp_dt:
                    raise ValueError(f"Proposal {proposal_id!r} has expired.")

            # 2. Result validation
            res_row = self.conn.execute(
                "SELECT result_id FROM action_results WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()
            if not res_row:
                raise ValueError(f"No result found for proposal {proposal_id!r}.")
            if self._val(res_row, "result_id", 0) != result_id:
                raise ValueError(f"Result ID mismatch: got {result_id!r}, proposal has {self._val(res_row, 'result_id', 0)!r}.")

            # 3. Draft validation
            draft_row = self.conn.execute(
                "SELECT * FROM normalized_evidence_drafts WHERE proposal_id = ? AND challenge_id = ? AND result_id = ?",
                (proposal_id, challenge_id, result_id),
            ).fetchone()

            if not draft_row:
                raise ValueError(f"No persisted normalized draft found for proposal {proposal_id!r}.")

            if self._val(draft_row, "is_confirmed", 9):
                raise ValueError(f"Confirmation for proposal {proposal_id!r} has already been consumed.")

            meta_raw = self._val(draft_row, "metadata", 12) or "{}"
            meta_dict = json.loads(meta_raw) if isinstance(meta_raw, str) else {}
            if meta_dict.get("source_provenance") != "action_result_derived":
                raise ValueError("Draft provenance must be 'action_result_derived'.")

            headers_raw = self._val(draft_row, "extracted_headers", 8) or "{}"
            headers_dict = json.loads(headers_raw) if isinstance(headers_raw, str) else {}
            status_code = self._val(draft_row, "extracted_status_code", 7)

            # 4. Check if canonical evidence ALREADY exists in Phase 5D evidence table
            existing_ev = self.check_canonical_evidence_exists(proposal_id, challenge_id)
            if existing_ev:
                meta_dict["existing_evidence_id"] = existing_ev["evidence_id"]
                meta_dict["reused_existing_evidence"] = True
                draft = NormalizedEvidenceDraft(
                    challenge_id=self._val(draft_row, "challenge_id", 3),
                    proposal_id=proposal_id,
                    result_id=result_id,
                    summary_content=self._val(draft_row, "summary_content", 5),
                    raw_snippet=self._val(draft_row, "raw_snippet", 6),
                    hypothesis_id=self._val(draft_row, "hypothesis_id", 4),
                    extracted_status_code=status_code,
                    extracted_headers=headers_dict,
                    is_confirmed=True,
                    metadata=meta_dict,
                )
                self.conn.execute("COMMIT;")
                return draft

            # 5. Check reservation status for single-use / concurrency safety
            prop_meta_raw = self._val(prop, "metadata", 2) or "{}"
            prop_meta = json.loads(prop_meta_raw) if isinstance(prop_meta_raw, str) else {}

            if status_val == ActionProposalState.CONFIRMING.value:
                # Check if reservation is active vs stale
                resv_time_str = prop_meta.get("reservation_time")
                is_stale = False
                if resv_time_str:
                    try:
                        resv_dt = datetime.fromisoformat(resv_time_str)
                        if (now_utc - resv_dt).total_seconds() > reservation_ttl_seconds:
                            is_stale = True
                    except Exception:
                        is_stale = True
                else:
                    is_stale = True

                if not is_stale:
                    raise ValueError(f"Confirmation is already in progress for proposal {proposal_id!r}.")

            elif status_val != ActionProposalState.RESULT_SUBMITTED.value:
                raise ValueError(
                    f"Proposal {proposal_id!r} cannot be confirmed: status is {status_val!r}, expected 'result_submitted'."
                )

            # 6. Claim reservation atomically inside BEGIN IMMEDIATE transaction
            prop_meta["reservation_token"] = reservation_token
            prop_meta["reservation_time"] = now_str
            prop_meta["reserved_by"] = user_id

            cur = self.conn.execute(
                """
                UPDATE action_proposals
                SET status = 'confirming', metadata = ?
                WHERE proposal_id = ? AND challenge_id = ? AND status IN ('result_submitted', 'confirming')
                """,
                (json.dumps(prop_meta), proposal_id, challenge_id),
            )
            if cur.rowcount == 0:
                raise ValueError(f"Confirmation reservation race lost for proposal {proposal_id!r}.")

            meta_dict["reservation_token"] = reservation_token
            draft = NormalizedEvidenceDraft(
                challenge_id=self._val(draft_row, "challenge_id", 3),
                proposal_id=proposal_id,
                result_id=result_id,
                summary_content=self._val(draft_row, "summary_content", 5),
                raw_snippet=self._val(draft_row, "raw_snippet", 6),
                hypothesis_id=self._val(draft_row, "hypothesis_id", 4),
                extracted_status_code=status_code,
                extracted_headers=headers_dict,
                is_confirmed=True,
                metadata=meta_dict,
            )

            self.conn.execute("COMMIT;")
            return draft
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def revert_draft_confirmation_reservation_atomic(
        self,
        proposal_id: str,
        challenge_id: str,
        reservation_token: Optional[str] = None,
    ) -> None:
        """Atomically revert proposal status from CONFIRMING back to RESULT_SUBMITTED if reservation_token matches."""
        if not reservation_token:
            return
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            row = self.conn.execute(
                "SELECT metadata FROM action_proposals WHERE proposal_id = ? AND challenge_id = ? AND status = 'confirming'",
                (proposal_id, challenge_id),
            ).fetchone()
            if row:
                meta_raw = self._val(row, "metadata", 0) or "{}"
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else {}
                if meta.get("reservation_token") == reservation_token:
                    self.conn.execute(
                        "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ?",
                        (ActionProposalState.RESULT_SUBMITTED.value, proposal_id, challenge_id),
                    )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def finalize_draft_confirmation_atomic(
        self,
        proposal_id: str,
        challenge_id: str,
        user_id: str = "user",
        reservation_token: Optional[str] = None,
    ) -> None:
        """Atomically transition proposal to CONSUMED, set draft is_confirmed=1, and emit audit event.
        Requires and verifies reservation_token if provided or if proposal is in CONFIRMING state.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            prop = self.conn.execute(
                "SELECT status, metadata FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()
            if not prop:
                raise ValueError(f"Proposal {proposal_id!r} not found for challenge {challenge_id!r}.")

            status_val = self._val(prop, "status", 0)
            if status_val == ActionProposalState.CONSUMED.value:
                self.conn.execute("COMMIT;")
                return

            prop_meta_raw = self._val(prop, "metadata", 1) or "{}"
            prop_meta = json.loads(prop_meta_raw) if isinstance(prop_meta_raw, str) else {}

            if reservation_token is not None:
                stored_token = prop_meta.get("reservation_token")
                if stored_token != reservation_token:
                    raise ValueError(f"Stale or invalid reservation token {reservation_token!r} for proposal {proposal_id!r}.")

            self.conn.execute(
                "UPDATE normalized_evidence_drafts SET is_confirmed = 1, confirmed_at = ?, confirmed_by = ? WHERE proposal_id = ?",
                (now_str, user_id, proposal_id),
            )
            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ? AND status IN ('confirming', 'result_submitted')",
                (ActionProposalState.CONSUMED.value, proposal_id, challenge_id),
            )
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionConsumed', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    user_id,
                    json.dumps({"proposal_id": proposal_id}),
                    now_str,
                ),
            )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def cancel_proposal_atomic(
        self, proposal_id: str, challenge_id: str, actor: str = "user", reason: str = "Cancelled by user"
    ) -> bool:
        """Atomically transition proposal to CANCELLED and revoke active approval."""
        now_str = datetime.now(timezone.utc).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            row = self.conn.execute(
                "SELECT status FROM action_proposals WHERE proposal_id = ? AND challenge_id = ?",
                (proposal_id, challenge_id),
            ).fetchone()

            if not row or row["status"] in {
                ActionProposalState.CONSUMED.value,
                ActionProposalState.RESULT_SUBMITTED.value,
                ActionProposalState.REJECTED.value,
                ActionProposalState.EXPIRED.value,
                ActionProposalState.CANCELLED.value,
            }:
                self.conn.execute("ROLLBACK;")
                return False

            self.conn.execute(
                "UPDATE action_proposals SET status = ? WHERE proposal_id = ? AND challenge_id = ?",
                (ActionProposalState.CANCELLED.value, proposal_id, challenge_id),
            )

            self.conn.execute(
                """
                UPDATE approval_requests
                SET status = 'cancelled', resolved_at = ?, resolved_by = ?, decision_reason = ?
                WHERE requested_action_ref = ? AND challenge_id = ? AND status IN ('pending', 'approved')
                """,
                (now_str, actor, reason, proposal_id, challenge_id),
            )

            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, 'ActionCancelled', ?, ?, ?, '{}')
                """,
                (
                    str(uuid.uuid4()),
                    challenge_id,
                    actor,
                    json.dumps({"proposal_id": proposal_id, "reason": reason}),
                    now_str,
                ),
            )

            self.conn.execute("COMMIT;")
            return True
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def expire_stale_proposals_atomic(
        self, challenge_id: str, ttl_seconds: int = 3600
    ) -> int:
        """Atomically expire proposals past TTL or stale blackboard state."""
        now_utc = datetime.now(timezone.utc)
        now_str = now_utc.isoformat()
        expired_count = 0

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            rows = self.conn.execute(
                """
                SELECT proposal_id, created_at, expires_at FROM action_proposals
                WHERE challenge_id = ? AND status IN ('pending_approval', 'approved')
                """,
                (challenge_id,),
            ).fetchall()

            for row in rows:
                p_id = row["proposal_id"]
                is_expired = False
                if row["expires_at"]:
                    exp_dt = datetime.fromisoformat(row["expires_at"])
                    if now_utc > exp_dt:
                        is_expired = True
                else:
                    created_dt = datetime.fromisoformat(row["created_at"])
                    if (now_utc - created_dt).total_seconds() > ttl_seconds:
                        is_expired = True

                if is_expired:
                    self.conn.execute(
                        "UPDATE action_proposals SET status = ? WHERE proposal_id = ?",
                        (ActionProposalState.EXPIRED.value, p_id),
                    )

                    self.conn.execute(
                        """
                        UPDATE approval_requests
                        SET status = 'expired', resolved_at = ?, decision_reason = 'Proposal TTL expired'
                        WHERE requested_action_ref = ? AND challenge_id = ? AND status IN ('pending', 'approved')
                        """,
                        (now_str, p_id, challenge_id),
                    )

                    self.conn.execute(
                        """
                        INSERT INTO events (
                            event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                        ) VALUES (?, ?, 'ActionExpired', 'system', ?, ?, '{}')
                        """,
                        (
                            str(uuid.uuid4()),
                            challenge_id,
                            json.dumps({"proposal_id": p_id}),
                            now_str,
                        ),
                    )
                    expired_count += 1

            self.conn.execute("COMMIT;")
            return expired_count
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

