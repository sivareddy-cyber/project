"""
MentorContextBuilder for constructing frozen, read-only Phase 5F snapshots.

LOCKED ARCHITECTURE INVARIANTS:
1. Performs strictly READ-ONLY queries on SQLite database.
2. Cross-challenge access MUST fail closed (raises ValueError).
3. Returns frozen MentorContext snapshot.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.mentor.contracts import MentorContext


class MentorContextBuilder:
    """Builds an immutable, read-only snapshot of 5D + 5E intelligence state for Phase 5F."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self.conn = db_conn

    def build_context(self, challenge_id: str) -> MentorContext:
        if not challenge_id:
            raise ValueError("challenge_id is required")

        # 1. Fetch challenge info
        ch_row = self.conn.execute(
            "SELECT challenge_id, name, category, global_hint_level FROM challenges WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()

        if not ch_row:
            raise ValueError(f"Challenge {challenge_id!r} does not exist")

        if ch_row["challenge_id"] != challenge_id:
            raise ValueError(f"Cross-challenge violation: expected {challenge_id!r}, found {ch_row['challenge_id']!r}")

        ch_name = ch_row["name"]
        ch_category = ch_row["category"]
        global_hint_level = HintLevel(ch_row["global_hint_level"])

        # 2. Fetch current hint level from blackboard state
        bb_row = self.conn.execute(
            "SELECT last_hint_level FROM blackboard_states WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        current_hint_level = HintLevel(bb_row["last_hint_level"]) if bb_row else HintLevel.L0

        # 3. Fetch hypotheses
        hyp_rows = self.conn.execute(
            "SELECT hypothesis_id, title, description, status, confidence FROM hypotheses WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchall()
        hypotheses = [
            {
                "hypothesis_id": r["hypothesis_id"],
                "title": r["title"],
                "description": r["description"],
                "status": r["status"],
                "confidence": r["confidence"],
            }
            for r in hyp_rows
        ]

        # 4. Fetch evidence
        ev_rows = self.conn.execute(
            "SELECT evidence_id, hypothesis_id, source, content, evidence_type FROM evidence WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchall()
        evidence = [
            {
                "evidence_id": r["evidence_id"],
                "hypothesis_id": r["hypothesis_id"],
                "source": r["source"],
                "content": r["content"],
                "evidence_type": r["evidence_type"],
            }
            for r in ev_rows
        ]

        # 5. Fetch attempts & failed_attempts
        att_rows = self.conn.execute(
            "SELECT attempt_id, hypothesis_id, description, outcome FROM attempts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchall()
        attempts = [
            {
                "attempt_id": r["attempt_id"],
                "hypothesis_id": r["hypothesis_id"],
                "description": r["description"],
                "outcome": r["outcome"],
            }
            for r in att_rows
        ]

        fa_rows = self.conn.execute(
            "SELECT failed_attempt_id, hypothesis_id, target, description FROM failed_attempts WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchall()
        failed_attempts = [
            {
                "failed_attempt_id": r["failed_attempt_id"],
                "hypothesis_id": r["hypothesis_id"],
                "target": r["target"],
                "description": r["description"],
            }
            for r in fa_rows
        ]

        # 6. Fetch latest 5E reasoning run & assessments
        run_rows = self.conn.execute(
            "SELECT run_id, run_sequence, result_hash, canonical_result FROM reasoning_runs WHERE challenge_id = ? ORDER BY run_sequence DESC LIMIT 1",
            (challenge_id,),
        ).fetchall()
        reasoning_runs = []
        gaps = []
        proposals = []

        for r in run_rows:
            canon = json.loads(r["canonical_result"]) if r["canonical_result"] else {}
            reasoning_runs.append(
                {
                    "run_id": r["run_id"],
                    "run_sequence": r["run_sequence"],
                    "result_hash": r["result_hash"],
                    "assessments": canon.get("assessments", []),
                }
            )
            gaps.extend(canon.get("detected_gaps", []))
            proposals.extend(canon.get("proposals", []))

        # 7. Fetch previous hints delivered
        hint_rows = self.conn.execute(
            "SELECT request_id, effective_level, rejection_reason FROM hint_decisions WHERE challenge_id = ? ORDER BY decided_at ASC",
            (challenge_id,),
        ).fetchall()
        previous_hints = [
            {
                "request_id": r["request_id"],
                "effective_level": r["effective_level"],
                "rejection_reason": r["rejection_reason"],
            }
            for r in hint_rows
        ]

        return MentorContext(
            challenge_id=challenge_id,
            challenge_name=ch_name,
            challenge_category=ch_category,
            global_hint_level=global_hint_level,
            current_hint_level=current_hint_level,
            hypotheses=hypotheses,
            evidence=evidence,
            attempts=attempts,
            failed_attempts=failed_attempts,
            reasoning_runs=reasoning_runs,
            information_gaps=gaps,
            investigation_proposals=proposals,
            previous_hints=previous_hints,
        )
