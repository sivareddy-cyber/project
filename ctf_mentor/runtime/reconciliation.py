"""
Startup orphan task reconciliation for Phase 5C Runtime Orchestration.

Responsibilities:
1. Find tasks left in RUNNING state on startup (from previous crash/restart).
2. Mark them FAILED with explicit reason 'orphaned_on_restart'.
3. Persist lifecycle events and emit to EventBus atomically inside an explicit transaction (F4).

OPERATIONAL INVARIANT:
reconcile_orphaned_tasks() is currently a one-shot cold-start reconciliation invoked
by TaskManager construction. It must not be externally/periodically invoked against a
live database shared with an active TaskManager instance.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from ctf_mentor.domain.models import Event, TaskStatus
from ctf_mentor.runtime.event_bus import EventBus

logger = logging.getLogger(__name__)


def reconcile_orphaned_tasks(
    conn: sqlite3.Connection,
    event_bus: Optional[EventBus] = None,
) -> List[str]:
    """Reconcile tasks orphaned in RUNNING state on process restart.

    Returns list of task_ids that were reconciled.
    Atomic transaction guarantees status update + event insertion commit together.
    """
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()

    # Find orphaned running tasks
    cursor.execute(
        "SELECT task_id, challenge_id FROM tasks WHERE status = 'running'"
    )
    rows = cursor.fetchall()
    if not rows:
        logger.info("Startup reconciliation: no orphaned RUNNING tasks found.")
        return []

    reconciled_task_ids = []

    for task_id, challenge_id in rows:
        logger.warning(
            f"Reconciling orphaned task {task_id} for challenge {challenge_id} -> FAILED ('orphaned_on_restart')"
        )
        conn.execute("BEGIN;")
        try:
            cursor.execute(
                """
                UPDATE tasks
                SET status = 'failed',
                    error_message = 'orphaned_on_restart',
                    completed_at = ?,
                    updated_at = ?
                WHERE task_id = ? AND status = 'running'
                """,
                (now, now, task_id),
            )

            event_id = str(uuid.uuid4())
            event = Event(
                event_id=event_id,
                challenge_id=challenge_id,
                event_type="TaskFailed",
                actor="system:reconciliation",
                payload={
                    "task_id": task_id,
                    "reason": "orphaned_on_restart",
                    "status": "failed",
                },
                occurred_at=datetime.fromisoformat(now),
                task_id=task_id,
            )

            cursor.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload,
                    occurred_at, task_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.challenge_id,
                    event.event_type,
                    event.actor,
                    json.dumps(event.payload),
                    now,
                    task_id,
                    json.dumps(event.metadata),
                ),
            )
            conn.execute("COMMIT;")
            reconciled_task_ids.append(task_id)

            if event_bus:
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(event_bus.publish(event))
                except Exception:
                    pass

        except Exception as e:
            conn.execute("ROLLBACK;")
            logger.exception(f"Failed atomic reconciliation for task {task_id}: {e}")
            raise

    logger.info(f"Startup reconciliation complete. Reconciled {len(reconciled_task_ids)} tasks.")
    return reconciled_task_ids
