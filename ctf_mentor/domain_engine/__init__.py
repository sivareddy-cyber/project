"""
Phase 7 & Phase 8 Domain Engine and Investigation Orchestration package.
"""

from ctf_mentor.domain_engine.detector import DomainDetector
from ctf_mentor.domain_engine.loop_controller import BoundedInvestigationLoop, LoopStepResult
from ctf_mentor.domain_engine.normalizer import WebApiResultNormalizer
from ctf_mentor.domain_engine.orchestration_handlers import (
    DecideStepApprovalHandler,
    PlanInvestigationStepHandler,
    RunBoundedLoopIterationHandler,
    register_phase8_handlers,
)
from ctf_mentor.domain_engine.planner import InvestigationPlanner, PlannerResult
from ctf_mentor.domain_engine.protocol import DomainSkill, DomainSkillRegistry
from ctf_mentor.domain_engine.skills.web_api import WebApiDomainSkill
from ctf_mentor.domain_engine.target_translator import investigation_target_to_action_proposal_target

__all__ = [
    "DomainDetector",
    "DomainSkill",
    "DomainSkillRegistry",
    "WebApiDomainSkill",
    "investigation_target_to_action_proposal_target",
    "InvestigationPlanner",
    "PlannerResult",
    "WebApiResultNormalizer",
    "BoundedInvestigationLoop",
    "LoopStepResult",
    "PlanInvestigationStepHandler",
    "DecideStepApprovalHandler",
    "RunBoundedLoopIterationHandler",
    "register_phase8_handlers",
]
