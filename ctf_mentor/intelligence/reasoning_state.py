"""
ReasoningState projection handler for CTF Mentor/Copilot Phase 5D.

Read-only projection constructed on-demand from current authoritative state.
CRITICAL INVARIANTS:
1. NOT persisted to database directly.
2. Returns HandlerResult(success=True, output=ReasoningState).
3. Produces NO proposed_diff, NO proposed_entity_writes, NO events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ctf_mentor.domain.models import ReasoningState
from ctf_mentor.persistence.intelligence_repo import IntelligenceReader
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class BuildReasoningStateHandler(TaskHandler):
    """Handler for constructing a read-only ReasoningState projection."""

    def __init__(self, reader: Optional[IntelligenceReader] = None) -> None:
        self.reader = reader

    async def execute(self, context: TaskContext) -> HandlerResult:
        cid = context.challenge_id
        bb = context.blackboard_snapshot
        now = datetime.now(timezone.utc)

        latest_classification = None
        all_hypotheses = []
        all_evidence = []
        all_findings = []
        all_attempts = []
        all_failed_attempts = []

        if self.reader:
            latest_classification = self.reader.get_latest_classification(cid)
            all_hypotheses = self.reader.get_hypotheses(cid)
            all_evidence = self.reader.get_evidence(cid)
            all_findings = self.reader.get_findings(cid)
            all_attempts = self.reader.get_attempts(cid)
            all_failed_attempts = self.reader.get_failed_attempts(cid)

        # Categorize active vs watchlist hypotheses
        active_ids_set = set(bb.active_hypothesis_ids)
        watchlist_ids_set = set(bb.watchlist_hypothesis_ids)

        active_hypotheses = [h for h in all_hypotheses if h.hypothesis_id in active_ids_set]
        watchlist_hypotheses = [h for h in all_hypotheses if h.hypothesis_id in watchlist_ids_set]

        # Recent evidence bounded to active_evidence_ids or top 10
        active_ev_set = set(bb.active_evidence_ids)
        recent_evidence = [e for e in all_evidence if e.evidence_id in active_ev_set]

        reasoning_state = ReasoningState(
            challenge_id=cid,
            blackboard_version=bb.blackboard_version,
            generated_at=now,
            classification=latest_classification,
            active_hypotheses=active_hypotheses,
            watchlist_hypotheses=watchlist_hypotheses,
            recent_evidence=recent_evidence,
            findings=all_findings,
            attempts=all_attempts,
            failed_attempts=all_failed_attempts,
            session_notes=bb.session_notes,
        )

        return HandlerResult(
            success=True,
            output=reasoning_state,
            proposed_diff=None,
            proposed_entity_writes=[],
        )

