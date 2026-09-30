"""
Runtime Orchestration Foundation package for CTF Mentor/Copilot.

Provides:
- TaskManager: Bounded asyncio orchestrator
- TaskRequest, TaskContext, HandlerResult: Context & task execution models
- TaskHandler, HandlerRegistry: Handler contract & registry
- EventBus: Pub/sub event bus with exception isolation
- RetryPolicy: Task retry configuration
- NullHandler: Echo/test handler
"""

from ctf_mentor.runtime.event_bus import EventBus
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.handlers.null_handler import NullHandler
from ctf_mentor.runtime.retry_policy import RetryPolicy
from ctf_mentor.runtime.task_context import (
    HandlerResult,
    TaskContext,
    TaskRequest,
)
from ctf_mentor.runtime.task_manager import TaskManager

__all__ = [
    "EventBus",
    "HandlerRegistry",
    "TaskHandler",
    "NullHandler",
    "RetryPolicy",
    "HandlerResult",
    "TaskContext",
    "TaskRequest",
    "TaskManager",
]
