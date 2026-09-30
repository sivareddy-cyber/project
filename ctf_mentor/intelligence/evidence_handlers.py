"""
Evidence handlers for CTF Mentor/Copilot Phase 5D.

Handles intake of user-supplied evidence and tool output.
Enforces:
- System NEVER fabricates evidence (is_fabricated must be False).
- Validates priority hierarchy (USER_CONFIRMED, REASONING_INFERENCE, SKILL_INFERENCE).
- Validates relationship (supports, contradicts, neutral) stored in metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ctf_mentor.contracts import EntityWrite, ScopedDiff
from ctf_mentor.domain.models import Evidence, EvidencePriority
from ctf_mentor.runtime.handler_registry import TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

ALLOWED_RELATIONS = {"supports", "contradicts", "neutral"}


class SubmitEvidenceHandler(TaskHandler):
    """Handler for submitting user or tool evidence."""

    async def execute(self, context: TaskContext) -> HandlerResult:
        params = context.parameters or {}
        content = params.get("content", "").strip()
        if not content:
            return HandlerResult(
                success=False,
                error_message="Evidence content must not be empty.",
            )

        source_str = params.get("source", EvidencePriority.USER_CONFIRMED.value)
        try:
            source = EvidencePriority(source_str)
        except ValueError:
            return HandlerResult(
                success=False,
                error_message=f"Invalid evidence source {source_str!r}. Must be one of {[e.value for e in EvidencePriority]}",
            )

        relation = params.get("relation", "supports")
        if relation not in ALLOWED_RELATIONS:
            return HandlerResult(
                success=False,
                error_message=f"Invalid evidence relation {relation!r}. Must be one of {sorted(ALLOWED_RELATIONS)}",
            )

        evidence_type = params.get("evidence_type", "user_observation")
        hypothesis_id = params.get("hypothesis_id")
        created_by = params.get("created_by", "user")

        is_fabricated = params.get("is_fabricated", False)
        if is_fabricated:
            return HandlerResult(
                success=False,
                error_message="Fabricated evidence is strictly prohibited by system architecture.",
            )

        user_metadata = params.get("metadata", {})
        if not isinstance(user_metadata, dict):
            user_metadata = {}

        # Preserve user metadata and attach hypothesis_relation
        meta = dict(user_metadata)
        meta["hypothesis_relation"] = relation
        if hypothesis_id:
            meta["hypothesis_id"] = hypothesis_id

        ev_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        evidence = Evidence(
            evidence_id=ev_id,
            challenge_id=context.challenge_id,
            hypothesis_id=hypothesis_id,
            source=source,
            content=content,
            evidence_type=evidence_type,
            created_by=created_by,
            is_fabricated=False,
            metadata=meta,
            created_at=now,
        )

        ew = EntityWrite(
            entity_type="evidence",
            operation="insert",
            entity_id=ev_id,
            fields={
                "evidence_id": evidence.evidence_id,
                "challenge_id": evidence.challenge_id,
                "hypothesis_id": evidence.hypothesis_id,
                "source": evidence.source.value,
                "content": evidence.content,
                "evidence_type": evidence.evidence_type,
                "created_by": evidence.created_by,
                "is_fabricated": 0,
                "metadata": evidence.metadata,
                "created_at": evidence.created_at,
            },
        )

        curr_ev_ids = list(context.blackboard_snapshot.active_evidence_ids)
        if ev_id not in curr_ev_ids:
            curr_ev_ids.append(ev_id)

        diff = ScopedDiff(
            challenge_id=context.challenge_id,
            expected_version=context.blackboard_snapshot.blackboard_version,
            actor="submit_evidence_handler",
            event_type="EvidenceRecorded",
            changes={"active_evidence_ids": curr_ev_ids},
        )

        return HandlerResult(
            success=True,
            output=evidence,
            proposed_entity_writes=[ew],
            proposed_diff=diff,
        )
