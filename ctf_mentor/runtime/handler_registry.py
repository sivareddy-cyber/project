"""
TaskHandler interface and HandlerRegistry for Phase 5C Runtime Orchestration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from typing import Dict

from ctf_mentor.runtime.task_context import HandlerResult, TaskContext

logger = logging.getLogger(__name__)


class TaskHandler(ABC):
    """Abstract Base Class for runtime task handlers."""

    @abstractmethod
    async def execute(self, context: TaskContext) -> HandlerResult:
        """Execute task logic against read-only context and propose result/diff."""
        pass


class HandlerRegistry:
    """Registry mapping task_type to TaskHandler instances."""

    def __init__(self) -> None:
        self._handlers: Dict[str, TaskHandler] = {}

    def register(self, task_type: str, handler: TaskHandler) -> None:
        """Register a handler for a task_type."""
        if not task_type:
            raise ValueError("task_type must not be empty")
        if not isinstance(handler, TaskHandler):
            raise TypeError("handler must inherit from TaskHandler")
        self._handlers[task_type] = handler
        logger.info(f"Registered TaskHandler for task_type: '{task_type}'")

    def get(self, task_type: str) -> TaskHandler:
        """Get handler for task_type. Raises KeyError if not registered."""
        if task_type not in self._handlers:
            raise KeyError(f"No handler registered for task_type: '{task_type}'")
        return self._handlers[task_type]

    def has_handler(self, task_type: str) -> bool:
        """Check if a handler is registered for task_type."""
        return task_type in self._handlers
