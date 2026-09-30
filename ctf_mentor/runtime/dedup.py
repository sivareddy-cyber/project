"""
Deduplication utilities for Phase 5C Runtime Orchestration.

Deduplication Key: (challenge_id, task_group_id, task_type)

Rule:
An active task is in QUEUED or RUNNING status.
If an active task already exists for the key, duplicate submission is rejected or coalesced,
unless explicit supersession is requested.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from ctf_mentor.domain.models import Task, TaskStatus


def get_active_task_for_key(
    conn: sqlite3.Connection,
    challenge_id: str,
    task_group_id: str,
    task_type: str,
) -> Optional[Task]:
    """Query SQLite for an active (QUEUED or RUNNING) task with matching dedup key."""
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT task_id, challenge_id, task_group_id, task_type, status,
               retry_key, created_at, updated_at, started_at, completed_at,
               retry_count, error_message, result_ref, metadata
        FROM tasks
        WHERE challenge_id = ?
          AND task_group_id = ?
          AND task_type = ?
          AND status IN ('queued', 'running')
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (challenge_id, task_group_id, task_type),
    )
    row = cursor.fetchone()
    if not row:
        return None

    import json
    from datetime import datetime

    def parse_dt(val: Optional[str]) -> Optional[datetime]:
        return datetime.fromisoformat(val) if val else None

    return Task(
        task_id=row[0],
        challenge_id=row[1],
        task_group_id=row[2],
        task_type=row[3],
        status=TaskStatus(row[4]),
        retry_key=row[5],
        created_at=parse_dt(row[6]),
        updated_at=parse_dt(row[7]),
        started_at=parse_dt(row[8]),
        completed_at=parse_dt(row[9]),
        retry_count=row[10],
        error_message=row[11],
        result_ref=row[12],
        metadata=json.loads(row[13]) if row[13] else {},
    )
