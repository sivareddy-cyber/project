"""
In-memory Pub/Sub Event Bus for Phase 5C Runtime Orchestration.

Responsibilities:
- Publish runtime lifecycle events to in-memory subscribers
- Isolate subscriber failures (catch and log exceptions; never fail task execution)
- The Event Bus is NOT the durable source of truth; SQLite events table remains authoritative.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Awaitable, Callable, Dict, List, Union

from ctf_mentor.domain.models import Event

logger = logging.getLogger(__name__)

SubscriberFunc = Callable[[Event], Union[None, Awaitable[None]]]


class EventBus:
    """In-memory pub/sub event bus with subscriber error isolation."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[SubscriberFunc]] = {}
        self._all_subscribers: List[SubscriberFunc] = []

    def subscribe(self, event_type: str, callback: SubscriberFunc) -> None:
        """Subscribe a callback to a specific event_type."""
        if not event_type:
            raise ValueError("event_type must not be empty")
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: SubscriberFunc) -> None:
        """Subscribe a callback to all events."""
        self._all_subscribers.append(callback)

    async def publish(self, event: Event) -> None:
        """Publish an event to all matching subscribers.

        CRITICAL INVARIANT:
        Subscriber failures MUST be isolated so they cannot corrupt task state
        or halt event publishing to other subscribers.
        """
        callbacks = list(self._all_subscribers)
        if event.event_type in self._subscribers:
            callbacks.extend(self._subscribers[event.event_type])

        for callback in callbacks:
            try:
                if inspect.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.exception(
                    f"EventBus subscriber '{callback.__name__ if hasattr(callback, '__name__') else callback}' "
                    f"threw exception for event_type '{event.event_type}': {e}"
                )
