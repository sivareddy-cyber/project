"""
Tool Adapters for Phase 10A (OSINT) and Phase 10B.3 (Local Execution).
"""

from ctf_mentor.tools.adapters.crtsh import CrtShAdapter, CrtShInput
from ctf_mentor.tools.adapters.wayback import WaybackAdapter, WaybackInput
from ctf_mentor.tools.adapters.shodan import ShodanAdapter, ShodanInput
from ctf_mentor.tools.adapters.virustotal import VirusTotalAdapter, VirusTotalInput
from ctf_mentor.tools.adapters.github import GitHubCodeSearchAdapter, GitHubSearchInput

# Phase 10B.3 — Local Execution Adapters
from ctf_mentor.tools.adapters.tshark import TsharkAdapter, TsharkInput, TsharkOperation
from ctf_mentor.tools.adapters.steghide import SteghideAdapter, SteghideInput, SteghideOperation
from ctf_mentor.tools.adapters.local_crypto import (
    LocalCryptoOpsAdapter,
    LocalCryptoInput,
    CryptoOperation,
)

__all__ = [
    # Phase 10A — OSINT
    "CrtShAdapter",
    "CrtShInput",
    "WaybackAdapter",
    "WaybackInput",
    "ShodanAdapter",
    "ShodanInput",
    "VirusTotalAdapter",
    "VirusTotalInput",
    "GitHubCodeSearchAdapter",
    "GitHubSearchInput",
    # Phase 10B.3 — Local Execution
    "TsharkAdapter",
    "TsharkInput",
    "TsharkOperation",
    "SteghideAdapter",
    "SteghideInput",
    "SteghideOperation",
    "LocalCryptoOpsAdapter",
    "LocalCryptoInput",
    "CryptoOperation",
]
