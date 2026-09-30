"""
TaskHandlers for Phase 5F Mentor Orchestration via TaskManager.

LOCKED ARCHITECTURE INVARIANTS:
1. Handlers fail closed if required dependencies are missing.
2. Zero proposed_entity_writes (Phase 5D state is NEVER mutated).
3. LLM text is NEVER canonical evidence or blackboard state.
4. All persistence routes atomically through MentorRepository.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.knowledge.contracts import RetrievalRequest
from ctf_mentor.knowledge.retrieval import RetrievalService
from ctf_mentor.llm.gateway import LLMGateway
from ctf_mentor.mentor.context import MentorContextBuilder
from ctf_mentor.mentor.hint_ladder import HintLadderStateMachine
from ctf_mentor.mentor.prompt_context import PromptContextBuilder
from ctf_mentor.mentor.spoiler_guard import SpoilerGuard
from ctf_mentor.persistence.mentor_repo import MentorRepository
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class RequestHintHandler(TaskHandler):
    """TaskHandler orchestrating the 10-step safe hint generation pipeline."""

    def __init__(
        self,
        mentor_repo: Optional[MentorRepository] = None,
        retrieval_service: Optional[RetrievalService] = None,
        spoiler_guard: Optional[SpoilerGuard] = None,
        llm_gateway: Optional[LLMGateway] = None,
        hint_ladder: Optional[HintLadderStateMachine] = None,
    ) -> None:
        self.mentor_repo = mentor_repo
        self.retrieval_service = retrieval_service
        self.spoiler_guard = spoiler_guard
        self.llm_gateway = llm_gateway
        self.hint_ladder = hint_ladder

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        # FAIL CLOSED RULE: All required dependencies MUST be present!
        if (
            not self.mentor_repo
            or not self.retrieval_service
            or not self.spoiler_guard
            or not self.llm_gateway
            or not self.hint_ladder
        ):
            return HandlerResult(
                success=False,
                error_message="MentorRepository, RetrievalService, SpoilerGuard, LLMGateway, and HintLadderStateMachine are required",
                retryable=False,
            )

        params = ctx.parameters
        req_level_num = params.get("requested_level")
        requested_level = HintLevel(req_level_num) if req_level_num is not None else None
        user_message = params.get("user_message", "")
        hypothesis_id = params.get("hypothesis_id")

        try:
            # 1. Load read-only MentorContext snapshot
            context_builder = MentorContextBuilder(self.mentor_repo.conn)
            mentor_ctx = context_builder.build_context(ctx.challenge_id)

            # 2. Determine authorized hint level via HintLadderStateMachine
            authorized_level = self.hint_ladder.determine_authorized_level(
                mentor_ctx, requested_level, request_id=ctx.task_id
            )

            # 3. Retrieve allowed educational knowledge chunks (gated by hint_level_floor <= authorized_level)
            ret_req = RetrievalRequest(
                challenge_id=ctx.challenge_id,
                category=mentor_ctx.challenge_category,
                requested_hint_level=authorized_level,
                hypothesis_id=hypothesis_id,
            )
            ret_res = self.retrieval_service.retrieve(ret_req)

            # 4. Build safe, injection-resistant PromptContext
            prompt_builder = PromptContextBuilder()
            prompt_ctx = prompt_builder.build_prompt_context(
                ctx=mentor_ctx,
                requested_level=authorized_level,
                retrieved_chunks=ret_res.chunks,
            )

            # 5. Call LLMGateway to generate untrusted HintCandidate
            candidate = await self.llm_gateway.generate_hint_candidate(
                request_id=ctx.task_id,
                challenge_id=ctx.challenge_id,
                requested_level=authorized_level,
                prompt_ctx=prompt_ctx,
            )

            # 6. Run SpoilerGuard inspection
            guard_res = self.spoiler_guard.inspect_candidate(candidate)

            # 7. Persist atomically via MentorRepository preserving requested vs effective level
            res_dict = self.mentor_repo.record_hint_transaction_atomic(
                request_id=ctx.task_id,
                challenge_id=ctx.challenge_id,
                requested_level=requested_level or authorized_level,
                effective_level=authorized_level,
                candidate=candidate,
                guard_result=guard_res,
                retrieved_chunks=ret_res.chunks,
                user_message=user_message,
                hypothesis_id=hypothesis_id,
            )

            return HandlerResult(
                success=True,
                output={
                    "decision_id": res_dict["decision_id"],
                    "requested_level": res_dict["requested_level"],
                    "effective_level": res_dict["effective_level"],
                    "approved": res_dict["approved"],
                    "delivered_text": res_dict["delivered_text"],
                    "is_spoiler": res_dict["is_spoiler"],
                    "provenance": ret_res.provenance_records,
                },
                proposed_entity_writes=[],  # CRITICAL: ZERO Phase 5D writes!
            )

        except Exception as ex:
            return HandlerResult(
                success=False,
                error_message=f"Hint generation failed: {ex}",
                retryable=False,
            )


class RecordHintOutcomeFeedbackHandler(TaskHandler):
    """TaskHandler recording user feedback on a delivered hint."""

    def __init__(self, mentor_repo: Optional[MentorRepository] = None) -> None:
        self.mentor_repo = mentor_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.mentor_repo:
            return HandlerResult(
                success=False,
                error_message="MentorRepository is required for feedback recording",
                retryable=False,
            )

        params = ctx.parameters
        decision_id = params.get("decision_id")
        feedback = params.get("feedback", "useful")

        if not decision_id:
            return HandlerResult(
                success=False,
                error_message="decision_id is required",
                retryable=False,
            )

        return HandlerResult(
            success=True,
            output={"decision_id": decision_id, "feedback": feedback},
            proposed_entity_writes=[],
        )


def register_phase5f_handlers(
    registry: HandlerRegistry,
    mentor_repo: Optional[MentorRepository] = None,
    retrieval_service: Optional[RetrievalService] = None,
    spoiler_guard: Optional[SpoilerGuard] = None,
    llm_gateway: Optional[LLMGateway] = None,
    hint_ladder: Optional[HintLadderStateMachine] = None,
) -> None:
    """Register Phase 5F task handlers into HandlerRegistry."""
    registry.register(
        "request_hint",
        RequestHintHandler(
            mentor_repo=mentor_repo,
            retrieval_service=retrieval_service,
            spoiler_guard=spoiler_guard,
            llm_gateway=llm_gateway,
            hint_ladder=hint_ladder,
        ),
    )
    registry.register(
        "record_hint_outcome_feedback",
        RecordHintOutcomeFeedbackHandler(mentor_repo=mentor_repo),
    )
