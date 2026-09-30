"""
Hint Ladder State Machine for Phase 5F Hint Engine.

LOCKED ARCHITECTURE INVARIANTS:
1. Progression follows L0 -> L1 -> L2 -> L3 -> L4 -> L5 -> L6 ladder.
2. The Hint Engine alone MUST NEVER authorize L6 without an approved ApprovalRecord.
3. Does NOT allow the LLM to decide its own hint level.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from ctf_mentor.domain.models import ApprovalStatus, ApprovalType, HintLevel
from ctf_mentor.mentor.contracts import MentorContext


class HintLadderStateMachine:
    """State machine governing hint level authorization and progression."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self.conn = db_conn

    def determine_authorized_level(
        self,
        ctx: MentorContext,
        requested_level: Optional[HintLevel] = None,
        request_id: Optional[str] = None,
    ) -> HintLevel:
        """Determine the maximum authorized hint level for a request."""
        current = ctx.current_hint_level
        global_ceiling = ctx.global_hint_level

        if requested_level is not None:
            # L6 explicitly requested requires approval check
            if requested_level == HintLevel.L6:
                if self._is_l6_approved(ctx.challenge_id, request_id=request_id):
                    target = HintLevel.L6
                else:
                    target = HintLevel(min(current.value + 1, 5))
            else:
                # General escalation rule below L6: target_level <= current_level + 1
                max_allowed = min(current.value + 1, 5)
                target = HintLevel(min(requested_level.value, max_allowed))
        else:
            target = HintLevel(min(current.value + 1, 5))

        # Enforce global challenge ceiling
        if target.value > global_ceiling.value:
            target = global_ceiling

        # SPECIAL GATE: L6 requires explicit request-specific ApprovalRecord(approval_type='l6_walkthrough', status='approved')
        if target == HintLevel.L6:
            if not self._is_l6_approved(ctx.challenge_id, request_id=request_id):
                return HintLevel.L5

        return target

    def _is_l6_approved(self, challenge_id: str, request_id: Optional[str] = None) -> bool:
        """Check if an approved unconsumed L6 approval record exists for challenge_id and request_id."""
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
            return False

        for r in rows:
            app_id = r["approval_id"]
            action_ref = r["requested_action_ref"]
            rel_req_id = r["related_request_id"]

            # If request_id is supplied, ensure approval matches request_id unless action_ref is wildcard
            if request_id:
                matches_request = (
                    action_ref in (request_id, "*", "global")
                    or rel_req_id == request_id
                    or not action_ref
                )
                if not matches_request:
                    continue

            # Check if this approval was already consumed by a previous hint_decisions entry
            consumed = self.conn.execute(
                "SELECT decision_id FROM hint_decisions WHERE challenge_id = ? AND metadata LIKE ?",
                (challenge_id, f'%"{app_id}"%'),
            ).fetchone()

            if not consumed:
                return True

        return False
