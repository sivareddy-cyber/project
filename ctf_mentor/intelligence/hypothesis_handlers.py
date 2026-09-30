"""
Hypothesis handlers for CTF Mentor/Copilot Phase 5D.

Enforces locked hypothesis rules:
1. States: WATCHLIST, ACTIVE, SUPPORTED, WEAKENED, DISPROVED, CONFIRMED.
2. Max 3 ACTIVE hypotheses per challenge. Fourth active activation fails cleanly.
3. CONFIRMED state requires at least 1 USER_CONFIRMED supporting evidence.
4. Deterministic investigation confidence calculation clamped to [0.0, 1.0].
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ctf_mentor.contracts import EntityWrite, ScopedDiff
from ctf_mentor.domain.models import (
    EvidencePriority,
    HintLevel,
    Hypothesis,
    HypothesisStatus,
)
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

VALID_TRANSITIONS: Dict[HypothesisStatus, Set[HypothesisStatus]] = {
    HypothesisStatus.WATCHLIST: {HypothesisStatus.ACTIVE},
    HypothesisStatus.ACTIVE: {HypothesisStatus.SUPPORTED, HypothesisStatus.WEAKENED, HypothesisStatus.WATCHLIST},
    HypothesisStatus.SUPPORTED: {HypothesisStatus.CONFIRMED, HypothesisStatus.WEAKENED},
    HypothesisStatus.WEAKENED: {HypothesisStatus.ACTIVE, HypothesisStatus.DISPROVED},
    HypothesisStatus.DISPROVED: set(),  # terminal
    HypothesisStatus.CONFIRMED: set(),  # terminal
}


class CreateHypothesisHandler(TaskHandler):
    """Handler for creating a new investigation hypothesis."""

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        title = params.get("title", "").strip()
        if not title:
            return HandlerResult(success=False, error_message="Hypothesis title must not be empty.")

        description = params.get("description", "")
        status_str = params.get("status", HypothesisStatus.WATCHLIST.value)
        try:
            target_status = HypothesisStatus(status_str)
        except ValueError:
            return HandlerResult(
                success=False,
                error_message=f"Invalid status {status_str!r}. Must be one of {[s.value for s in HypothesisStatus]}",
            )

        if target_status not in {HypothesisStatus.WATCHLIST, HypothesisStatus.ACTIVE}:
            return HandlerResult(
                success=False,
                error_message=f"New hypothesis must start in WATCHLIST or ACTIVE state, got {target_status.value!r}",
            )

        # Enforce max 3 active hypotheses invariant
        active_ids = list(context.blackboard_snapshot.active_hypothesis_ids)
        if target_status == HypothesisStatus.ACTIVE and len(active_ids) >= 3:
            return HandlerResult(
                success=False,
                error_message=f"Cannot activate hypothesis: maximum 3 active hypotheses limit reached ({len(active_ids)} active).",
            )

        hyp_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        confidence = float(params.get("confidence", 0.5))
        confidence = min(1.0, max(0.0, confidence))

        hint_level_val = int(params.get("hint_level", 0))
        hint_level = HintLevel(hint_level_val)
        is_primary = bool(params.get("is_primary", False))

        hypothesis = Hypothesis(
            hypothesis_id=hyp_id,
            challenge_id=context.challenge_id,
            title=title,
            description=description,
            status=target_status,
            confidence=confidence,
            hint_level=hint_level,
            created_at=now,
            updated_at=now,
            is_primary=is_primary,
            metadata=params.get("metadata", {}),
        )

        ew = EntityWrite(
            entity_type="hypothesis",
            operation="insert",
            entity_id=hyp_id,
            fields={
                "hypothesis_id": hypothesis.hypothesis_id,
                "challenge_id": hypothesis.challenge_id,
                "title": hypothesis.title,
                "description": hypothesis.description,
                "status": hypothesis.status.value,
                "confidence": hypothesis.confidence,
                "hint_level": hypothesis.hint_level.value,
                "is_primary": 1 if hypothesis.is_primary else 0,
                "metadata": hypothesis.metadata,
                "created_at": hypothesis.created_at,
                "updated_at": hypothesis.updated_at,
            },
        )

        changes: Dict[str, Any] = {}
        if target_status == HypothesisStatus.ACTIVE:
            changes["active_hypothesis_ids"] = active_ids + [hyp_id]
        else:
            watchlist_ids = list(context.blackboard_snapshot.watchlist_hypothesis_ids)
            changes["watchlist_hypothesis_ids"] = watchlist_ids + [hyp_id]

        diff = ScopedDiff(
            challenge_id=context.challenge_id,
            expected_version=context.blackboard_snapshot.blackboard_version,
            actor="create_hypothesis_handler",
            event_type="HypothesisCreated",
            changes=changes,
        )

        return HandlerResult(
            success=True,
            output=hypothesis,
            proposed_entity_writes=[ew],
            proposed_diff=diff,
        )


from ctf_mentor.persistence.intelligence_repo import IntelligenceReader


class EvaluateHypothesisHandler(TaskHandler):
    """Handler for evaluating and transitioning an existing hypothesis."""

    def __init__(self, intelligence_reader: Optional[IntelligenceReader] = None) -> None:
        self.intelligence_reader = intelligence_reader

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        hyp_id = params.get("hypothesis_id")
        if not hyp_id:
            return HandlerResult(success=False, error_message="hypothesis_id is required.")

        # Blocker 3: Load stored hypothesis from DB rather than trusting caller parameters
        stored_hyp = None
        if self.intelligence_reader:
            stored_hyp = self.intelligence_reader.get_hypothesis(hyp_id)

        if not stored_hyp:
            return HandlerResult(
                success=False,
                error_message=f"Hypothesis {hyp_id!r} not found in stored database state.",
            )

        if stored_hyp.challenge_id != context.challenge_id:
            return HandlerResult(
                success=False,
                error_message=f"Cross-challenge hypothesis mutation rejected: hypothesis {hyp_id!r} belongs to challenge {stored_hyp.challenge_id!r}, not {context.challenge_id!r}.",
            )

        curr_status = stored_hyp.status

        new_status_str = params.get("new_status")
        target_status = curr_status
        if new_status_str:
            try:
                target_status = HypothesisStatus(new_status_str)
            except ValueError:
                return HandlerResult(success=False, error_message=f"Invalid new_status {new_status_str!r}.")

        # Blocker 3: Terminal state enforcement (CONFIRMED and DISPROVED cannot be reopened)
        if curr_status in {HypothesisStatus.CONFIRMED, HypothesisStatus.DISPROVED}:
            if target_status != curr_status:
                return HandlerResult(
                    success=False,
                    error_message=f"Terminal hypothesis state {curr_status.value!r} cannot transition to {target_status.value!r}.",
                )

        # Check valid state machine transition if status is changing
        if target_status != curr_status:
            allowed = VALID_TRANSITIONS.get(curr_status, set())
            if target_status not in allowed:
                return HandlerResult(
                    success=False,
                    error_message=f"Invalid hypothesis transition from {curr_status.value!r} to {target_status.value!r}.",
                )

        # Blocker 4: Enforce real persisted USER_CONFIRMED evidence requirement for CONFIRMED state
        if target_status == HypothesisStatus.CONFIRMED:
            has_real_evidence = False
            if self.intelligence_reader:
                has_real_evidence = self.intelligence_reader.has_user_confirmed_evidence(
                    context.challenge_id, hyp_id
                )

            if not has_real_evidence:
                return HandlerResult(
                    success=False,
                    error_message="Transition to CONFIRMED requires at least one real USER_CONFIRMED evidence row in database linked to this hypothesis and challenge.",
                )

        # Enforce max 3 active limit on activation
        active_ids = list(context.blackboard_snapshot.active_hypothesis_ids)
        if target_status == HypothesisStatus.ACTIVE and curr_status != HypothesisStatus.ACTIVE:
            non_current_active = [hid for hid in active_ids if hid != hyp_id]
            if len(non_current_active) >= 3:
                return HandlerResult(
                    success=False,
                    error_message=f"Cannot activate hypothesis: maximum 3 active hypotheses limit reached ({len(non_current_active)} active).",
                )

        # Deterministic Investigation Confidence Calculation
        base_confidence = float(params.get("current_confidence", 0.5))
        supporting_count_user = int(params.get("supporting_user_confirmed", 0))
        supporting_count_reasoning = int(params.get("supporting_reasoning", 0))
        supporting_count_skill = int(params.get("supporting_skill", 0))

        contradicting_count_user = int(params.get("contradicting_user_confirmed", 0))
        contradicting_count_reasoning = int(params.get("contradicting_reasoning", 0))

        delta = (
            (supporting_count_user * 0.3)
            + (supporting_count_reasoning * 0.15)
            + (supporting_count_skill * 0.05)
            - (contradicting_count_user * 0.4)
            - (contradicting_count_reasoning * 0.2)
        )

        new_confidence = min(1.0, max(0.0, base_confidence + delta))

        now = datetime.now(timezone.utc)
        ew = EntityWrite(
            entity_type="hypothesis",
            operation="update",
            entity_id=hyp_id,
            fields={
                "hypothesis_id": hyp_id,
                "status": target_status.value,
                "confidence": new_confidence,
                "updated_at": now,
            },
        )

        # ScopedDiff if active/watchlist status changed
        watchlist_ids = list(context.blackboard_snapshot.watchlist_hypothesis_ids)
        changes: Dict[str, Any] = {}

        if target_status != curr_status:
            # Remove from old list
            if hyp_id in active_ids:
                active_ids.remove(hyp_id)
            if hyp_id in watchlist_ids:
                watchlist_ids.remove(hyp_id)

            # Add to new list if active or watchlist
            if target_status == HypothesisStatus.ACTIVE:
                active_ids.append(hyp_id)
                changes["active_hypothesis_ids"] = active_ids
                changes["watchlist_hypothesis_ids"] = watchlist_ids
            elif target_status == HypothesisStatus.WATCHLIST:
                watchlist_ids.append(hyp_id)
                changes["active_hypothesis_ids"] = active_ids
                changes["watchlist_hypothesis_ids"] = watchlist_ids
            else:
                # Terminal or supported/weakened: remove from active/watchlist if present
                changes["active_hypothesis_ids"] = active_ids
                changes["watchlist_hypothesis_ids"] = watchlist_ids

        diff = None
        if changes:
            diff = ScopedDiff(
                challenge_id=context.challenge_id,
                expected_version=context.blackboard_snapshot.blackboard_version,
                actor="evaluate_hypothesis_handler",
                event_type="HypothesisTransitioned",
                changes=changes,
            )

        return HandlerResult(
            success=True,
            output={
                "hypothesis_id": hyp_id,
                "from_status": curr_status.value,
                "to_status": target_status.value,
                "confidence": new_confidence,
            },
            proposed_entity_writes=[ew],
            proposed_diff=diff,
        )
