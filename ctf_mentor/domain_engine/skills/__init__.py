"""
Domain skills package for Phase 7.
"""

from ctf_mentor.domain_engine.skills.osint import OsintDomainSkill, OsintTargetType
from ctf_mentor.domain_engine.skills.web_api import WebApiDomainSkill

__all__ = ["WebApiDomainSkill", "OsintDomainSkill", "OsintTargetType"]
