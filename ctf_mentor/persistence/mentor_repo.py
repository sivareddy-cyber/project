"""
MentorRepository for Phase 5F Persistence & Approval Boundary Invariants.

LOCKED ARCHITECTURE INVARIANTS:
1. Owns Phase 5F persistence (hint_requests, hint_candidates, hint_decisions, rag_queries, rag_results).
2. L6 Walkthrough persistence is IMPOSSIBLE without an approved ApprovalRecord(approval_type='l6_walkthrough', status='approved').
3. Atomic transaction execution with event emission (HintRecorded, HintRejectedByGuard).
4. Reuses existing approval_requests / approval_records infrastructure without duplication.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import ApprovalStatus, ApprovalType, HintLevel
from ctf_mentor.knowledge.contracts import KnowledgeChunk
from ctf_mentor.mentor.contracts import HintCandidate, SpoilerGuardResult
from ctf_mentor.persistence.database import assert_foreign_keys_enabled


class MentorRepository:
    """Repository for Phase 5F mentor persistence and safety constraints."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        assert_foreign_keys_enabled(db_conn)
        self.conn = db_conn

    def record_hint_transaction_atomic(
        self,
        request_id: str,
        challenge_id: str,
        requested_level: HintLevel,
        effective_level: HintLevel,
        candidate: HintCandidate,
        guard_result: SpoilerGuardResult,
        retrieved_chunks: List[KnowledgeChunk],
        user_message: str = "",
        hypothesis_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically record hint request, candidate, decision, RAG queries, and events."""
        if not challenge_id or not request_id:
            raise ValueError("challenge_id and request_id are required")

        now_str = datetime.now(timezone.utc).isoformat()
        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        query_id = f"ragq_{uuid.uuid4().hex[:12]}"
        result_id = f"ragr_{uuid.uuid4().hex[:12]}"

        matching_approval_id: Optional[str] = None

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # CRITICAL APPROVAL BOUNDARY INVARIANT:
            # Atomic check-and-consume inside database transaction
            if effective_level == HintLevel.L6:
                matching_approval_id = self._get_l6_approval_id(challenge_id, request_id=request_id)
                if not matching_approval_id:
                    raise ValueError("L6 Walkthrough requires explicit human approval in approval_records")

            # 1. Insert hint_requests with original user requested level
            self.conn.execute(
                """
                INSERT INTO hint_requests (
                    request_id, challenge_id, hypothesis_id, requested_level, user_message, metadata, requested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    challenge_id,
                    hypothesis_id,
                    requested_level.value,
                    user_message,
                    json.dumps({"model_id": candidate.model_id, "prompt_hash": candidate.prompt_hash}),
                    now_str,
                ),
            )

            # 2. Insert hint_candidates (raw_content stored for audit; if rejected, guarded content returned)
            self.conn.execute(
                """
                INSERT INTO hint_candidates (
                    candidate_id, request_id, challenge_id, hypothesis_id, level, content, rationale, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.candidate_id,
                    request_id,
                    challenge_id,
                    hypothesis_id,
                    effective_level.value,
                    candidate.raw_content,
                    candidate.rationale,
                    json.dumps({"is_spoiler": guard_result.is_spoiler, "violation_type": guard_result.violation_type}),
                    now_str,
                ),
            )

            # 3. Insert hint_decisions with authorized effective level
            approved_int = 0 if guard_result.is_spoiler else 1
            delivered_text = guard_result.safe_content

            self.conn.execute(
                """
                INSERT INTO hint_decisions (
                    decision_id, candidate_id, request_id, challenge_id, effective_level, approved, rejection_reason, metadata, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    candidate.candidate_id,
                    request_id,
                    challenge_id,
                    effective_level.value,
                    approved_int,
                    guard_result.rejection_reason,
                    json.dumps({
                        "delivered_text": delivered_text,
                        "detected_patterns": guard_result.detected_patterns,
                        "chunk_ids": [c.chunk_id for c in retrieved_chunks],
                        "approval_id": matching_approval_id,
                        "user_requested_level": requested_level.value,
                    }),
                    now_str,
                ),
            )

            # 4. Insert rag_queries & rag_results
            self.conn.execute(
                """
                INSERT INTO rag_queries (
                    query_id, challenge_id, query_text, context_hint, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    query_id,
                    challenge_id,
                    f"category:{effective_level.value}",
                    user_message,
                    json.dumps({"requested_level": requested_level.value, "effective_level": effective_level.value}),
                    now_str,
                ),
            )

            chunk_ids = [c.chunk_id for c in retrieved_chunks]
            self.conn.execute(
                """
                INSERT INTO rag_results (
                    result_id, query_id, challenge_id, retrieved_chunks, score, metadata, created_at
                ) VALUES (?, ?, ?, ?, 1.0, ?, ?)
                """,
                (
                    result_id,
                    query_id,
                    challenge_id,
                    json.dumps(chunk_ids),
                    json.dumps({"chunk_count": len(chunk_ids)}),
                    now_str,
                ),
            )

            # 5. Advance current_hint_level in Phase 5F-owned blackboard_states when hint is delivered
            if approved_int == 1:
                self.conn.execute(
                    """
                    UPDATE blackboard_states
                    SET last_hint_level = MAX(last_hint_level, ?), updated_at = ?
                    WHERE challenge_id = ?
                    """,
                    (effective_level.value, now_str, challenge_id),
                )

            # 6. Emit Event atomically into events table
            event_id = str(uuid.uuid4())
            event_type = "HintRejectedByGuard" if guard_result.is_spoiler else "HintRecorded"
            event_payload = json.dumps({
                "request_id": request_id,
                "decision_id": decision_id,
                "requested_level": requested_level.value,
                "effective_level": effective_level.value,
                "approved": approved_int,
                "is_spoiler": guard_result.is_spoiler,
            })

            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                ) VALUES (?, ?, ?, 'mentor_repository', ?, ?, '{}')
                """,
                (event_id, challenge_id, event_type, event_payload, now_str),
            )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return {
            "decision_id": decision_id,
            "request_id": request_id,
            "challenge_id": challenge_id,
            "requested_level": requested_level.value,
            "effective_level": effective_level.value,
            "approved": approved_int == 1,
            "delivered_text": delivered_text,
            "is_spoiler": guard_result.is_spoiler,
        }

    def _get_l6_approval_id(self, challenge_id: str, request_id: Optional[str] = None) -> Optional[str]:
        """Fetch matching unconsumed approved L6 approval_id for challenge_id and request_id."""
        rows = self.conn.execute(
            """
            SELECT approval_id, requested_action_ref, related_request_id FROM approval_records
            WHERE challenge_id = ?
            AND approval_type = 'l6_walkthrough'
            AND status = 'approved'
            ORDER BY requested_at DESC
            """,
            (challenge_id,),
        ).fetchall()

        if not rows:
            return None

        for r in rows:
            app_id = r["approval_id"]
            action_ref = r["requested_action_ref"]
            rel_req_id = r["related_request_id"]

            if request_id:
                matches_request = (
                    action_ref in (request_id, "*", "global")
                    or rel_req_id == request_id
                    or not action_ref
                )
                if not matches_request:
                    continue

            consumed = self.conn.execute(
                "SELECT decision_id FROM hint_decisions WHERE challenge_id = ? AND metadata LIKE ?",
                (challenge_id, f'%"{app_id}"%'),
            ).fetchone()

            if not consumed:
                return app_id

        return None

    def _is_l6_approved(self, challenge_id: str, request_id: Optional[str] = None) -> bool:
        """Check if an approved unconsumed L6 approval record exists in approval_records."""
        return self._get_l6_approval_id(challenge_id, request_id=request_id) is not None
