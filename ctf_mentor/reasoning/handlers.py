"""
TaskHandlers for Reasoning Engine orchestration via TaskManager.

INVARIANTS:
1. Handlers receive only ReasoningTaskContext with an immutable ReasoningView (or build it from repo).
2. Handlers do NOT execute direct SQL writes or mutate database connections.
3. Handlers require ReasoningRepository and fail closed if reasoning_repo is None.
4. AnalyzeInvestigationHandler persists results via ReasoningRepository.record_reasoning_result_atomic.
5. Prediction creation routes through ReasoningRepository.record_prediction, NEVER Phase 5D EntityWrite.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.persistence.reasoning_repo import ReasoningRepository
from ctf_mentor.reasoning.contracts import (
    HypothesisPrediction,
    HypothesisRelation,
    HypothesisRelationType,
    InvestigationLink,
    InvestigationLinkType,
    PredictionStatus,
)
from ctf_mentor.reasoning.engine import ReasoningEngine
from ctf_mentor.reasoning.view import ReasoningView, build_reasoning_view
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class ReasoningTaskContext(TaskContext):
    """Specialized TaskContext providing an immutable ReasoningView to reasoning handlers."""

    reasoning_view: ReasoningView


class AnalyzeInvestigationHandler(TaskHandler):
    """TaskHandler executing the pure ReasoningEngine pipeline and persisting atomic results."""

    def __init__(
        self,
        reasoning_repo: Optional[ReasoningRepository] = None,
        engine: Optional[ReasoningEngine] = None,
    ) -> None:
        self.reasoning_repo = reasoning_repo
        self.engine = engine or ReasoningEngine()

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.reasoning_repo:
            return HandlerResult(
                success=False,
                error_message="ReasoningRepository is required for AnalyzeInvestigationHandler",
                retryable=False,
            )

        if isinstance(ctx, ReasoningTaskContext):
            view = ctx.reasoning_view
        else:
            view = ctx.parameters.get("reasoning_view")

        if not view:
            if hasattr(self.reasoning_repo, "conn") and self.reasoning_repo.conn:
                view = build_reasoning_view(self.reasoning_repo.conn, ctx.challenge_id)
            else:
                return HandlerResult(
                    success=False,
                    error_message="ReasoningTaskContext, reasoning_view parameter, or valid repository connection is required",
                    retryable=False,
                )

        if ctx.is_cancelled():
            return HandlerResult(success=False, error_message="Task cancelled before reasoning execution", retryable=False)

        run_sequence = ctx.parameters.get("run_sequence", 1)
        result = self.engine.analyze(view, run_sequence=run_sequence)

        try:
            run_rec = self.reasoning_repo.record_reasoning_result_atomic(
                candidate_result=result,
                task_id=ctx.task_id,
            )
        except Exception as ex:
            return HandlerResult(
                success=False,
                error_message=f"Reasoning persistence failed: {ex}",
                retryable=False,
            )

        return HandlerResult(
            success=True,
            output={
                "run_id": run_rec.run_id,
                "challenge_id": result.challenge_id,
                "input_fingerprint": result.input_fingerprint,
                "result_hash": result.result_hash,
                "assessments_count": len(result.assessments),
                "proposals_count": len(result.proposals),
                "gaps_count": len(result.detected_gaps),
                "reasoning_result": result,
                "reasoning_run": run_rec,
            },
        )


class RecordPredictionHandler(TaskHandler):
    """TaskHandler creating a hypothesis prediction via ReasoningRepository.

    CRITICAL ARCHITECTURE INVARIANT:
    Must NEVER generate EntityWrite(entity_type="hypothesis").
    Performs persistence exclusively via ReasoningRepository.record_prediction.
    """

    def __init__(self, reasoning_repo: Optional[ReasoningRepository] = None) -> None:
        self.reasoning_repo = reasoning_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.reasoning_repo:
            return HandlerResult(
                success=False,
                error_message="ReasoningRepository is required for persistence",
                retryable=False,
            )

        params = ctx.parameters
        hypothesis_id = params.get("hypothesis_id")
        description = params.get("description")
        expected_obs = params.get("expected_observation", "")

        if not hypothesis_id or not description:
            return HandlerResult(
                success=False,
                error_message="hypothesis_id and description are required",
                retryable=False,
            )

        pred_id = params.get("prediction_id") or f"pred_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc)

        prediction = HypothesisPrediction(
            prediction_id=pred_id,
            challenge_id=ctx.challenge_id,
            hypothesis_id=hypothesis_id,
            description=description,
            expected_observation=expected_obs,
            status=PredictionStatus.UNTESTED,
            created_at=now_utc,
            metadata=params.get("metadata", {}),
        )

        try:
            self.reasoning_repo.record_prediction(prediction)
        except ValueError as ve:
            return HandlerResult(success=False, error_message=str(ve), retryable=False)

        return HandlerResult(
            success=True,
            output={"prediction_id": pred_id, "hypothesis_id": hypothesis_id},
            proposed_entity_writes=[],  # MUST be empty - zero Phase 5D writes!
        )


class RecordInvestigationLinkHandler(TaskHandler):
    """TaskHandler creating an investigation link via ReasoningRepository."""

    def __init__(self, reasoning_repo: Optional[ReasoningRepository] = None) -> None:
        self.reasoning_repo = reasoning_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.reasoning_repo:
            return HandlerResult(
                success=False,
                error_message="ReasoningRepository is required for persistence",
                retryable=False,
            )

        params = ctx.parameters
        link_id = params.get("link_id") or f"link_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc)

        link = InvestigationLink(
            link_id=link_id,
            challenge_id=ctx.challenge_id,
            source_id=params["source_id"],
            source_type=params["source_type"],
            target_id=params["target_id"],
            target_type=params["target_type"],
            relation_type=InvestigationLinkType(params["relation_type"]),
            independence_group=params.get("independence_group", ""),
            weight=params.get("weight", 1000),
            created_at=now_utc,
            metadata=params.get("metadata", {}),
        )

        try:
            self.reasoning_repo.record_investigation_link(link)
        except ValueError as ve:
            return HandlerResult(success=False, error_message=str(ve), retryable=False)

        return HandlerResult(
            success=True,
            output={"link_id": link_id},
        )


class RecordHypothesisRelationHandler(TaskHandler):
    """TaskHandler creating a hypothesis relation via ReasoningRepository."""

    def __init__(self, reasoning_repo: Optional[ReasoningRepository] = None) -> None:
        self.reasoning_repo = reasoning_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.reasoning_repo:
            return HandlerResult(
                success=False,
                error_message="ReasoningRepository is required for persistence",
                retryable=False,
            )

        params = ctx.parameters
        relation_id = params.get("relation_id") or f"rel_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc)

        relation = HypothesisRelation(
            relation_id=relation_id,
            challenge_id=ctx.challenge_id,
            source_hypothesis_id=params["source_hypothesis_id"],
            target_hypothesis_id=params["target_hypothesis_id"],
            relation_type=HypothesisRelationType(params["relation_type"]),
            discriminating_criteria=params.get("discriminating_criteria", ""),
            created_at=now_utc,
            metadata=params.get("metadata", {}),
        )

        try:
            self.reasoning_repo.record_hypothesis_relation(relation)
        except ValueError as ve:
            return HandlerResult(success=False, error_message=str(ve), retryable=False)

        return HandlerResult(
            success=True,
            output={"relation_id": relation_id},
        )


def register_phase5e_handlers(
    registry: HandlerRegistry,
    reasoning_repo: Optional[ReasoningRepository] = None,
    engine: Optional[ReasoningEngine] = None,
) -> None:
    """Register all Phase 5E task handlers into the provided HandlerRegistry."""
    registry.register("analyze_investigation", AnalyzeInvestigationHandler(reasoning_repo=reasoning_repo, engine=engine))
    registry.register("record_prediction", RecordPredictionHandler(reasoning_repo=reasoning_repo))
    registry.register("record_investigation_link", RecordInvestigationLinkHandler(reasoning_repo=reasoning_repo))
    registry.register("record_hypothesis_relation", RecordHypothesisRelationHandler(reasoning_repo=reasoning_repo))
