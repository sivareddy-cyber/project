"""
TaskHandlers for Phase 6 Controlled Investigation Layer via TaskManager.

LOCKED SECURITY INVARIANTS:
1. ProposeActionHandler drafts proposal, validates scope deterministically, and creates single-use approval.
2. SubmitActionResultHandler verifies single-use approval, records append-only result, and requires human confirmation before canonical Phase 5D write.
3. Zero direct SQL writes into Phase 5D canonical tables. Canonical evidence writes execute strictly via Phase 5D SubmitEvidenceHandler / EntityWrite contract.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ctf_mentor.intelligence.evidence_handlers import SubmitEvidenceHandler
from ctf_mentor.investigation.normalizer import EvidenceNormalizer
from ctf_mentor.investigation.proposal_drafter import ActionProposalDrafter
from ctf_mentor.investigation.scope_validator import DeterministicScopeValidator
from ctf_mentor.mentor.context import MentorContextBuilder
from ctf_mentor.mentor.prompt_context import PromptContextBuilder
from ctf_mentor.persistence.action_proposal_repo import ActionProposalRepository
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext


class ProposeActionHandler(TaskHandler):
    """TaskHandler for 'propose_action' task."""

    def __init__(
        self,
        proposal_repo: Optional[ActionProposalRepository] = None,
        blackboard_repo: Optional[BlackboardRepository] = None,
        drafter: Optional[ActionProposalDrafter] = None,
    ) -> None:
        self.proposal_repo = proposal_repo
        self.blackboard_repo = blackboard_repo
        self.drafter = drafter or ActionProposalDrafter()

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.proposal_repo or not self.blackboard_repo:
            return HandlerResult(
                success=False,
                error_message="ActionProposalRepository and BlackboardRepository are required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        challenge_id = ctx.challenge_id

        # 1. Fetch active AuthorizedScopes for challenge
        scopes = self.blackboard_repo.read_authorized_scopes_for_challenge(challenge_id)
        if not scopes:
            return HandlerResult(
                success=False,
                error_message=f"No active AuthorizedScope found for challenge '{challenge_id}' (fail-closed).",
                retryable=False,
            )

        # 2. Build prompt context using existing MentorContextBuilder & PromptContextBuilder
        mentor_ctx_builder = MentorContextBuilder(self.proposal_repo.conn)
        mentor_ctx = mentor_ctx_builder.build_context(challenge_id)
        prompt_builder = PromptContextBuilder()
        prompt_ctx = prompt_builder.build_prompt_context(
            ctx=mentor_ctx,
            requested_level=mentor_ctx.current_hint_level,
            retrieved_chunks=[],
        )

        # 3. Call ActionProposalDrafter to generate candidate proposal
        draft_res = await self.drafter.draft_proposal(
            challenge_id=challenge_id,
            prompt_ctx=prompt_ctx,
            request_id=ctx.task_id,
        )

        if not draft_res.is_valid or not draft_res.proposal:
            return HandlerResult(
                success=False,
                error_message=f"Proposal drafting failed schema validation: {draft_res.error_message}",
                retryable=False,
            )

        proposal = draft_res.proposal

        # 4. Run DeterministicScopeValidator
        scope_res = DeterministicScopeValidator.validate(proposal.target, scopes)
        if not scope_res.is_allowed:
            return HandlerResult(
                success=False,
                error_message=f"Proposed target is out of authorized scope: {scope_res.reason}",
                retryable=False,
            )

        proposal.scope_id = scope_res.scope_id
        proposal.scope_version = scope_res.scope_version

        # 5. Atomically persist proposal & create ApprovalRecord
        res_dict = self.proposal_repo.create_proposal_atomic(
            proposal=proposal,
            scope_id=scope_res.scope_id,
        )

        return HandlerResult(
            success=True,
            output={
                "proposal_id": res_dict["proposal_id"],
                "approval_id": res_dict["approval_id"],
                "status": res_dict["status"],
                "action_type": proposal.action_type.value,
                "target": {
                    "scheme": proposal.target.scheme,
                    "hostname": proposal.target.hostname,
                    "port": proposal.target.port,
                    "path": proposal.target.path,
                    "method": proposal.target.method,
                },
                "rationale": proposal.rationale,
            },
            proposed_entity_writes=[],  # Zero Phase 5D writes!
        )


class SubmitActionResultHandler(TaskHandler):
    """TaskHandler for 'submit_action_result' task.
    
    LOCKED SECURITY INVARIANT:
    Stage 1 ONLY: Persists raw ActionResult, advances proposal to RESULT_SUBMITTED,
    normalizes raw output, persists NormalizedEvidenceDraft in DB, and returns draft info.
    NEVER writes canonical Phase 5D evidence.
    NEVER accepts confirm_evidence or confirms in the same task execution.
    """

    def __init__(
        self,
        proposal_repo: Optional[ActionProposalRepository] = None,
    ) -> None:
        self.proposal_repo = proposal_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.proposal_repo:
            return HandlerResult(
                success=False,
                error_message="ActionProposalRepository is required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        if "confirm_evidence" in params and params["confirm_evidence"]:
            return HandlerResult(
                success=False,
                error_message="Parameter 'confirm_evidence' is forbidden in submit_action_result. Human confirmation requires a separate 'confirm_action_evidence' task execution.",
                retryable=False,
            )

        proposal_id = params.get("proposal_id")
        raw_output = params.get("raw_output", "")
        outcome = params.get("outcome", "success")
        user_id = params.get("user_id", "user")

        if not proposal_id:
            return HandlerResult(
                success=False,
                error_message="proposal_id is required.",
                retryable=False,
            )

        try:
            # 1. Atomically verify approval & persist ActionResult
            res_dict = self.proposal_repo.submit_result_atomic(
                proposal_id=proposal_id,
                challenge_id=ctx.challenge_id,
                raw_output=raw_output,
                outcome=outcome,
                user_id=user_id,
            )

            # 2. Normalize raw output
            proposal = self.proposal_repo.get_proposal(proposal_id, ctx.challenge_id)
            hypothesis_id = proposal.hypothesis_id if proposal else None

            draft = EvidenceNormalizer.normalize_action_result(
                raw_output=raw_output,
                challenge_id=ctx.challenge_id,
                proposal_id=proposal_id,
                result_id=res_dict["result_id"],
                hypothesis_id=hypothesis_id,
            )

            # 3. Persist normalized draft to server DB for out-of-band human review
            self.proposal_repo.save_normalized_draft_atomic(draft)

            return HandlerResult(
                success=True,
                output={
                    "result_id": res_dict["result_id"],
                    "proposal_id": proposal_id,
                    "status": res_dict["status"],
                    "summary": draft.summary_content,
                    "awaiting_human_confirmation": True,
                },
                proposed_entity_writes=[],  # ZERO Phase 5D writes!
            )

        except Exception as ex:
            return HandlerResult(
                success=False,
                error_message=f"Submitting action result failed: {ex}",
                retryable=False,
            )


from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository


class ConfirmActionEvidenceHandler(TaskHandler):
    """TaskHandler for 'confirm_action_evidence' task.
    
    LOCKED SECURITY INVARIANT:
    Stage 2 ONLY: Human confirmation task. Retrieves server-persisted draft by proposal_id & result_id.
    Performs server-side state & provenance checks, invokes Phase 5D SubmitEvidenceHandler,
    and atomically advances proposal state RESULT_SUBMITTED -> CONSUMED.
    NEVER accepts caller-supplied evidence text or content overrides.
    """

    def __init__(
        self,
        proposal_repo: Optional[ActionProposalRepository] = None,
        submit_evidence_handler: Optional[SubmitEvidenceHandler] = None,
        intelligence_repo: Optional[IntelligenceRepository] = None,
    ) -> None:
        self.proposal_repo = proposal_repo
        self.submit_evidence_handler = submit_evidence_handler or SubmitEvidenceHandler()
        self.intelligence_repo = intelligence_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.proposal_repo:
            return HandlerResult(
                success=False,
                error_message="ActionProposalRepository is required.",
                retryable=False,
            )

        params = ctx.parameters or {}
        proposal_id = params.get("proposal_id")
        result_id = params.get("result_id")
        user_id = params.get("user_id", "user")

        if not proposal_id or not result_id:
            return HandlerResult(
                success=False,
                error_message="Both proposal_id and result_id are required for evidence confirmation.",
                retryable=False,
            )

        reservation_token = None
        try:
            # 1. Atomically validate server-persisted draft & claim confirmation reservation under BEGIN IMMEDIATE
            draft = self.proposal_repo.prepare_draft_confirmation_atomic(
                proposal_id=proposal_id,
                result_id=result_id,
                challenge_id=ctx.challenge_id,
                user_id=user_id,
            )
            reservation_token = (draft.metadata or {}).get("reservation_token")

            # 2. Check if canonical evidence ALREADY exists (crash recovery from previous interrupted attempt)
            existing_ev_id = (draft.metadata or {}).get("existing_evidence_id")
            if existing_ev_id:
                self.proposal_repo.finalize_draft_confirmation_atomic(
                    proposal_id=proposal_id,
                    challenge_id=ctx.challenge_id,
                    user_id=user_id,
                    reservation_token=reservation_token,
                )
                return HandlerResult(
                    success=True,
                    output={
                        "status": "consumed",
                        "proposal_id": proposal_id,
                        "evidence_id": existing_ev_id,
                        "reused_existing_evidence": True,
                    },
                    proposed_entity_writes=[],
                )

            # 3. Reservation acquired successfully and no prior canonical evidence exists.
            # Invoke Phase 5D SubmitEvidenceHandler to produce EntityWrite & ScopedDiff.
            res = await EvidenceNormalizer.confirm_and_submit_to_phase5d(
                draft=draft,
                context=ctx,
                submit_handler=self.submit_evidence_handler,
            )

            # 4. EVIDENCE COMMIT ORDERING:
            # FIRST: Persist canonical Phase 5D evidence to SQLite before marking proposal CONSUMED.
            if res.success:
                if res.proposed_entity_writes:
                    intel_repo = self.intelligence_repo or IntelligenceRepository(self.proposal_repo.conn)
                    try:
                        intel_repo.apply_writes_and_diff_atomic(
                            ctx.challenge_id,
                            entity_writes=res.proposed_entity_writes,
                            scoped_diff=res.proposed_diff,
                        )
                    except Exception as write_ex:
                        # Persistence failed! Revert reservation so proposal remains RESULT_SUBMITTED and retryable
                        if reservation_token:
                            self.proposal_repo.revert_draft_confirmation_reservation_atomic(
                                proposal_id=proposal_id,
                                challenge_id=ctx.challenge_id,
                                reservation_token=reservation_token,
                            )
                        return HandlerResult(
                            success=False,
                            error_message=f"Persisting canonical Phase 5D evidence failed: {write_ex}",
                            retryable=True,
                        )

                # SECOND: Only after canonical evidence is successfully persisted in SQLite, finalize proposal as CONSUMED.
                self.proposal_repo.finalize_draft_confirmation_atomic(
                    proposal_id=proposal_id,
                    challenge_id=ctx.challenge_id,
                    user_id=user_id,
                    reservation_token=reservation_token,
                )
                res.proposed_entity_writes = []
                res.proposed_diff = None
                return res
            else:
                # Phase 5D submission failed; revert reservation so proposal is not stuck in 'confirming'
                if reservation_token:
                    self.proposal_repo.revert_draft_confirmation_reservation_atomic(
                        proposal_id=proposal_id,
                        challenge_id=ctx.challenge_id,
                        reservation_token=reservation_token,
                    )
                return res

        except Exception as ex:
            if reservation_token and self.proposal_repo and proposal_id:
                try:
                    self.proposal_repo.revert_draft_confirmation_reservation_atomic(
                        proposal_id=proposal_id,
                        challenge_id=ctx.challenge_id,
                        reservation_token=reservation_token,
                    )
                except Exception:
                    pass

            return HandlerResult(
                success=False,
                error_message=f"Confirming action evidence failed: {ex}",
                retryable=False,
            )


class ExpireStaleActionProposalsHandler(TaskHandler):
    """TaskHandler for 'expire_stale_action_proposals' housekeeping task."""

    def __init__(self, proposal_repo: Optional[ActionProposalRepository] = None) -> None:
        self.proposal_repo = proposal_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.proposal_repo:
            return HandlerResult(
                success=False,
                error_message="ActionProposalRepository is required.",
                retryable=False,
            )

        ttl_seconds = int(ctx.parameters.get("ttl_seconds", 3600))
        expired_count = self.proposal_repo.expire_stale_proposals_atomic(
            challenge_id=ctx.challenge_id,
            ttl_seconds=ttl_seconds,
        )
        return HandlerResult(
            success=True,
            output={"status": "expired_checked", "expired_count": expired_count},
            proposed_entity_writes=[],
        )


class CancelActionProposalHandler(TaskHandler):
    """TaskHandler for 'cancel_action_proposal' task."""

    def __init__(self, proposal_repo: Optional[ActionProposalRepository] = None) -> None:
        self.proposal_repo = proposal_repo

    async def execute(self, ctx: TaskContext) -> HandlerResult:
        if not self.proposal_repo:
            return HandlerResult(
                success=False,
                error_message="ActionProposalRepository is required.",
                retryable=False,
            )

        proposal_id = ctx.parameters.get("proposal_id")
        reason = ctx.parameters.get("reason", "Cancelled by user")
        actor = ctx.parameters.get("actor", "user")

        if not proposal_id:
            return HandlerResult(
                success=False,
                error_message="proposal_id is required.",
                retryable=False,
            )

        cancelled = self.proposal_repo.cancel_proposal_atomic(
            proposal_id=proposal_id,
            challenge_id=ctx.challenge_id,
            actor=actor,
            reason=reason,
        )

        if not cancelled:
            return HandlerResult(
                success=False,
                error_message=f"Proposal '{proposal_id}' could not be cancelled (wrong state or not found).",
                retryable=False,
            )

        return HandlerResult(
            success=True,
            output={"proposal_id": proposal_id, "status": "cancelled"},
            proposed_entity_writes=[],
        )


def register_phase6_handlers(
    registry: HandlerRegistry,
    proposal_repo: Optional[ActionProposalRepository] = None,
    blackboard_repo: Optional[BlackboardRepository] = None,
    drafter: Optional[ActionProposalDrafter] = None,
    submit_evidence_handler: Optional[SubmitEvidenceHandler] = None,
    intelligence_repo: Optional[IntelligenceRepository] = None,
) -> None:
    """Register Phase 6 task handlers into HandlerRegistry."""
    registry.register(
        "propose_action",
        ProposeActionHandler(
            proposal_repo=proposal_repo,
            blackboard_repo=blackboard_repo,
            drafter=drafter,
        ),
    )
    registry.register(
        "submit_action_result",
        SubmitActionResultHandler(
            proposal_repo=proposal_repo,
        ),
    )
    registry.register(
        "confirm_action_evidence",
        ConfirmActionEvidenceHandler(
            proposal_repo=proposal_repo,
            submit_evidence_handler=submit_evidence_handler,
            intelligence_repo=intelligence_repo,
        ),
    )
    registry.register(
        "expire_stale_action_proposals",
        ExpireStaleActionProposalsHandler(proposal_repo=proposal_repo),
    )
    registry.register(
        "cancel_action_proposal",
        CancelActionProposalHandler(proposal_repo=proposal_repo),
    )


