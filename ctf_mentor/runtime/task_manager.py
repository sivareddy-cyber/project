"""
TaskManager orchestrator for Phase 5C Runtime Orchestration Foundation.

LOCKED ARCHITECTURE INVARIANTS:
1. BlackboardRepository.apply_scoped_diff() is the ONLY path for Blackboard mutations.
2. Handlers receive read-only TaskContext; no raw DB connection or Blackboard repository handle.
3. Stale version handling performs bounded recovery via handler recomputation against fresh state.
4. Retry = NEW task_id, SAME task_group_id.
5. Supersession = NEW task_group_id; superseded results become non-authoritative.
6. Event Bus failures are isolated and cannot break task state.
7. Startup recovery converts RUNNING tasks to FAILED ('orphaned_on_restart').
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from ctf_mentor.contracts import (
    DuplicateTaskError,
    ScopedDiff,
    StaleVersionError,
    TaskExecutionError,
    TaskNotFoundError,
)
from ctf_mentor.domain.models import (
    ApprovalStatus,
    Event,
    Task,
    TaskDependency,
    TaskStatus,
)
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import assert_foreign_keys_enabled
from ctf_mentor.persistence.intelligence_repo import IntelligenceRepository
from ctf_mentor.runtime.dedup import get_active_task_for_key
from ctf_mentor.runtime.event_bus import EventBus
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.reconciliation import reconcile_orphaned_tasks
from ctf_mentor.runtime.retry_policy import RetryPolicy
from ctf_mentor.runtime.task_context import (
    HandlerResult,
    TaskContext,
    TaskRequest,
)

logger = logging.getLogger(__name__)

TERMINAL_STATES = {
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
    TaskStatus.TIMED_OUT,
}


class TaskManager:
    """Central orchestrator for runtime tasks."""

    def __init__(
        self,
        db_connection: sqlite3.Connection,
        blackboard_repo: BlackboardRepository,
        handler_registry: HandlerRegistry,
        event_bus: Optional[EventBus] = None,
        max_concurrency: int = 10,
        intelligence_repo: Optional[IntelligenceRepository] = None,
    ) -> None:
        assert_foreign_keys_enabled(db_connection)
        self.conn = db_connection
        self.conn.row_factory = sqlite3.Row
        self.blackboard_repo = blackboard_repo
        self.handler_registry = handler_registry
        self.event_bus = event_bus or EventBus()
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.intelligence_repo = intelligence_repo or IntelligenceRepository(
            db_connection, blackboard_repo
        )

        # In-memory tracking
        self._cancellation_events: Dict[str, asyncio.Event] = {}
        self._completion_events: Dict[str, asyncio.Event] = {}
        self._superseded_task_groups: Set[str] = set()

        # Perform startup orphan task recovery
        reconcile_orphaned_tasks(self.conn, self.event_bus)

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    async def submit(self, request: TaskRequest) -> Task:
        """Submit a task request for execution."""
        # 1. Approval boundary check
        if request.requires_approval:
            if not request.approval_id:
                raise TaskExecutionError("Task requires approval but no approval_id provided.")
            app_rec = self.blackboard_repo.read_approval_record_domain(request.approval_id)
            if not app_rec or app_rec.status != ApprovalStatus.APPROVED:
                raise TaskExecutionError(
                    f"Approval check failed: approval {request.approval_id!r} is not APPROVED."
                )

        # 2. Handler check
        if not self.handler_registry.has_handler(request.task_type):
            raise TaskExecutionError(f"No handler registered for task_type '{request.task_type}'.")

        # 3. Supersession check
        if request.supersedes_task_group_id:
            self._superseded_task_groups.add(request.supersedes_task_group_id)
            logger.info(f"Task group '{request.supersedes_task_group_id}' marked as superseded.")

        # 4. Deduplication check
        active_task = get_active_task_for_key(
            self.conn, request.challenge_id, request.task_group_id, request.task_type
        )
        if active_task and active_task.task_group_id not in self._superseded_task_groups:
            raise DuplicateTaskError(
                f"Active task already exists for key ({request.challenge_id}, {request.task_group_id}, {request.task_type})"
            )

        # 5. Dependency check (fail fast if parent already failed/cancelled/timed out)
        if request.depends_on_task_ids:
            for parent_id in request.depends_on_task_ids:
                parent = self.get_task(parent_id)
                if not parent:
                    raise TaskExecutionError(f"Required parent task {parent_id!r} not found.")
                if parent.status in {TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMED_OUT}:
                    # Fast fail dependent task
                    return await self._create_failed_task(
                        request, f"dependency_failed: parent task {parent_id} was {parent.status.value}"
                    )

        # 6. Create Task record
        task_id = str(uuid.uuid4())
        retry_key = f"{request.challenge_id}:{request.task_group_id}:{request.task_type}"
        now = datetime.now(timezone.utc).isoformat()
        
        task = Task(
            task_id=task_id,
            challenge_id=request.challenge_id,
            task_group_id=request.task_group_id,
            task_type=request.task_type,
            status=TaskStatus.QUEUED,
            retry_key=retry_key,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            retry_count=0,
            metadata=request.metadata,
        )

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO tasks (
                    task_id, challenge_id, task_group_id, task_type, status,
                    retry_key, retry_count, error_message, result_ref, metadata,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.challenge_id,
                    task.task_group_id,
                    task.task_type,
                    task.status.value,
                    task.retry_key,
                    task.retry_count,
                    task.error_message,
                    task.result_ref,
                    json.dumps(task.metadata),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as ie:
            self.conn.rollback()
            raise DuplicateTaskError(
                f"Active task already exists for key ({request.challenge_id}, {request.task_group_id}, {request.task_type})"
            ) from ie

        # Insert dependency links
        for dep_task_id in request.depends_on_task_ids:
            dep_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO task_dependencies (
                    dependency_id, task_id, depends_on_task_id, dependency_type, created_at
                ) VALUES (?, ?, ?, 'hard', ?)
                """,
                (dep_id, task.task_id, dep_task_id, now),
            )

        self.conn.commit()

        # Emit TaskQueued lifecycle event
        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task.task_id,
            event_type="TaskQueued",
            payload={"task_id": task.task_id, "task_group_id": task.task_group_id, "status": "queued"},
        )

        self._cancellation_events[task.task_id] = asyncio.Event()
        self._completion_events[task.task_id] = asyncio.Event()

        # Schedule execution
        asyncio.create_task(self._run_task_execution(task, request))
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """Fetch task by task_id."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT task_id, challenge_id, task_group_id, task_type, status,
                   retry_key, created_at, updated_at, started_at, completed_at,
                   retry_count, error_message, result_ref, metadata
            FROM tasks
            WHERE task_id = ?
            """,
            (task_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        def parse_dt(v: Optional[str]) -> Optional[datetime]:
            return datetime.fromisoformat(v) if v else None

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
            result_ref=json.loads(row[12]) if (row[12] and isinstance(row[12], str) and row[12].strip().startswith(("{", "["))) else (row[12] or ""),
            metadata=json.loads(row[13]) if row[13] else {},
        )

    def get_status(self, task_id: str) -> TaskStatus:
        """Get status of a task."""
        t = self.get_task(task_id)
        if not t:
            raise TaskNotFoundError(f"Task {task_id!r} not found.")
        return t.status

    async def cancel(self, task_id: str) -> bool:
        """Cooperatively request cancellation of a task."""
        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task {task_id!r} not found.")

        if task.status in TERMINAL_STATES:
            return False

        if task_id in self._cancellation_events:
            self._cancellation_events[task_id].set()

        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE tasks
            SET status = 'cancelled',
                updated_at = ?
            WHERE task_id = ? AND status NOT IN ('completed', 'failed', 'cancelled', 'timed_out')
            """,
            (now, task_id),
        )
        self.conn.commit()

        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task_id,
            event_type="TaskCancelled",
            payload={"task_id": task_id, "status": "cancelled"},
        )

        if task_id in self._completion_events:
            self._completion_events[task_id].set()
        return True

    async def wait_for(self, task_id: str, timeout: Optional[float] = None) -> Task:
        """Wait for a task to reach a terminal state."""
        if task_id not in self._completion_events:
            self._completion_events[task_id] = asyncio.Event()

        task = self.get_task(task_id)
        if task and task.status in TERMINAL_STATES:
            return task

        try:
            await asyncio.wait_for(self._completion_events[task_id].wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        final_task = self.get_task(task_id)
        if not final_task:
            raise TaskNotFoundError(f"Task {task_id!r} not found.")
        return final_task

    # ---------------------------------------------------------------------------
    # Private Implementation & Execution Loop
    # ---------------------------------------------------------------------------

    async def _run_task_execution(self, task: Task, request: TaskRequest) -> None:
        """Execute task inside semaphore bounds with master exception safety."""
        async with self.semaphore:
            canc_event = self._cancellation_events.get(task.task_id)
            if canc_event and canc_event.is_set():
                await self._finalize_completion_event(task.task_id)
                return

            # Check hard dependencies
            if request.depends_on_task_ids:
                dep_ok = await self._wait_for_dependencies(task, request.depends_on_task_ids)
                if not dep_ok:
                    await self._finalize_completion_event(task.task_id)
                    return

            if canc_event and canc_event.is_set():
                await self._finalize_completion_event(task.task_id)
                return

            if task.task_group_id in self._superseded_task_groups:
                await self._mark_superseded(task)
                await self._finalize_completion_event(task.task_id)
                return

            # Transition to RUNNING
            now = datetime.now(timezone.utc).isoformat()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                UPDATE tasks
                SET status = 'running',
                    started_at = ?,
                    updated_at = ?
                WHERE task_id = ? AND status = 'queued'
                """,
                (now, now, task.task_id),
            )
            self.conn.commit()

            await self._emit_lifecycle_event(
                challenge_id=task.challenge_id,
                task_id=task.task_id,
                event_type="TaskStarted",
                payload={"task_id": task.task_id, "status": "running"},
            )

            retry_policy = request.retry_policy or RetryPolicy()

            try:
                # Read Blackboard snapshot
                bb_snapshot = self.blackboard_repo.read_blackboard_state(task.challenge_id)
                ctx = TaskContext(
                    task_id=task.task_id,
                    challenge_id=task.challenge_id,
                    task_group_id=task.task_group_id,
                    task_type=task.task_type,
                    parameters=request.parameters,
                    blackboard_snapshot=bb_snapshot,
                    _cancellation_event=canc_event or asyncio.Event(),
                )

                handler = self.handler_registry.get(task.task_type)

                if request.timeout_seconds and request.timeout_seconds > 0:
                    res: HandlerResult = await asyncio.wait_for(
                        handler.execute(ctx), timeout=request.timeout_seconds
                    )
                else:
                    res = await handler.execute(ctx)

                if not isinstance(res, HandlerResult):
                    raise TypeError(f"TaskHandler must return HandlerResult, got {type(res).__name__}")

                if ctx.is_cancelled() or self.get_status(task.task_id) == TaskStatus.CANCELLED:
                    logger.info(f"Task {task.task_id} cancelled during/after handler execution. Discarding output.")
                    return

                if task.task_group_id in self._superseded_task_groups:
                    logger.info(f"Task {task.task_id} superseded during execution. Discarding output.")
                    await self._mark_superseded(task)
                    return

                if not res.success:
                    await self._handle_failure(task, request, retry_policy, res.error_message or "Handler reported failure")
                    return

                # Apply proposed ScopedDiff and proposed_entity_writes via IntelligenceRepository with safe recomputation
                if res.proposed_diff or res.proposed_entity_writes:
                    if res.proposed_diff and not isinstance(res.proposed_diff, ScopedDiff):
                        raise TypeError(f"proposed_diff must be ScopedDiff, got {type(res.proposed_diff).__name__}")

                    diff_applied = await self._apply_diff_with_recovery(
                        task, request, handler, canc_event, res, retry_policy
                    )
                    if not diff_applied:
                        await self._handle_failure(
                            task, request, retry_policy, "Stale version recovery exhausted"
                        )
                        return

                import dataclasses
                if res.output is not None:
                    if dataclasses.is_dataclass(res.output):
                        result_json = json.dumps(dataclasses.asdict(res.output), default=str)
                    elif isinstance(res.output, (dict, list)):
                        result_json = json.dumps(res.output, default=str)
                    else:
                        result_json = str(res.output)
                else:
                    result_json = ""
                comp_now = datetime.now(timezone.utc).isoformat()
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'completed',
                        completed_at = ?,
                        result_ref = ?,
                        updated_at = ?
                    WHERE task_id = ? AND status = 'running'
                    """,
                    (comp_now, result_json, comp_now, task.task_id),
                )
                self.conn.commit()

                await self._emit_lifecycle_event(
                    challenge_id=task.challenge_id,
                    task_id=task.task_id,
                    event_type="TaskCompleted",
                    payload={"task_id": task.task_id, "status": "completed", "result": res.output},
                )

            except asyncio.CancelledError:
                logger.info(f"Task {task.task_id} asyncio task cancelled.")
                await self.cancel(task.task_id)

            except asyncio.TimeoutError:
                logger.warning(f"Task {task.task_id} timed out.")
                await self._handle_timeout(task, request, retry_policy)

            except Exception as e:
                logger.exception(f"Unhandled exception during task {task.task_id} execution lifecycle: {e}")
                await self._handle_failure(task, request, retry_policy, f"Unhandled exception: {e}")

            finally:
                await self._finalize_completion_event(task.task_id)

    async def _wait_for_dependencies(self, task: Task, parent_ids: List[str]) -> bool:
        """Wait for hard dependencies to complete."""
        for parent_id in parent_ids:
            parent = await self.wait_for(parent_id)
            if parent.status != TaskStatus.COMPLETED:
                now = datetime.now(timezone.utc).isoformat()
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'failed',
                        error_message = ?,
                        completed_at = ?,
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (f"dependency_failed: parent {parent_id} was {parent.status.value}", now, now, task.task_id),
                )
                self.conn.commit()

                await self._emit_lifecycle_event(
                    challenge_id=task.challenge_id,
                    task_id=task.task_id,
                    event_type="TaskFailed",
                    payload={"task_id": task.task_id, "reason": "dependency_failed"},
                )
                return False
        return True

    async def _apply_diff_with_recovery(
        self,
        task: Task,
        request: TaskRequest,
        handler: TaskHandler,
        canc_event: Optional[asyncio.Event],
        initial_res: HandlerResult,
        retry_policy: RetryPolicy,
    ) -> bool:
        """Apply ScopedDiff and EntityWrite objects to Blackboard & DB atomically with bounded stale-version recovery via handler recomputation."""
        if not initial_res.proposed_diff and not initial_res.proposed_entity_writes:
            return True

        # Cancellation check before atomic commit (Blocker 7)
        if (canc_event and canc_event.is_set()) or self.get_status(task.task_id) == TaskStatus.CANCELLED:
            logger.info(f"Task {task.task_id} cancelled prior to repository apply. Aborting transaction.")
            return False

        try:
            self.intelligence_repo.apply_writes_and_diff_atomic(
                challenge_id=task.challenge_id,
                entity_writes=initial_res.proposed_entity_writes,
                scoped_diff=initial_res.proposed_diff,
                task_id=task.task_id,
            )
            return True
        except StaleVersionError as sve:
            logger.warning(
                f"Task {task.task_id} encountered StaleVersionError on initial attempt: {sve}"
            )

        # Check if stale version recovery is enabled in retry_policy (F3)
        if not retry_policy.retry_on_stale_version:
            logger.warning(f"Task {task.task_id} stale recovery disabled by retry_policy.")
            return False

        attempts = 0
        max_stale_retries = retry_policy.max_retries

        while attempts < max_stale_retries:
            # Cancellation check before recomputation (Blocker 7)
            if (canc_event and canc_event.is_set()) or self.get_status(task.task_id) == TaskStatus.CANCELLED:
                logger.info(f"Task {task.task_id} cancelled prior to recomputation attempt {attempts}. Aborting.")
                return False

            attempts += 1
            logger.info(
                f"Task {task.task_id} recomputing handler against fresh Blackboard state (attempt {attempts}/{max_stale_retries})"
            )
            fresh_bb = self.blackboard_repo.read_blackboard_state(task.challenge_id)
            fresh_ctx = TaskContext(
                task_id=task.task_id,
                challenge_id=task.challenge_id,
                task_group_id=task.task_group_id,
                task_type=task.task_type,
                parameters=request.parameters,
                blackboard_snapshot=fresh_bb,
                _cancellation_event=canc_event or asyncio.Event(),
            )

            try:
                if request.timeout_seconds and request.timeout_seconds > 0:
                    fresh_res: HandlerResult = await asyncio.wait_for(
                        handler.execute(fresh_ctx), timeout=request.timeout_seconds
                    )
                else:
                    fresh_res = await handler.execute(fresh_ctx)
            except Exception as exc:
                logger.warning(f"Task {task.task_id} recomputation threw exception: {exc}")
                return False

            if not isinstance(fresh_res, HandlerResult) or not fresh_res.success:
                logger.warning(f"Task {task.task_id} recomputation did not produce a successful HandlerResult.")
                return False

            # Cancellation check immediately before atomic commit of recomputed result (Blocker 7)
            if (canc_event and canc_event.is_set()) or self.get_status(task.task_id) == TaskStatus.CANCELLED:
                logger.info(f"Task {task.task_id} cancelled after recomputation before atomic commit. Aborting.")
                return False

            if fresh_res.proposed_diff:
                if not isinstance(fresh_res.proposed_diff, ScopedDiff):
                    raise TypeError(f"Recomputed proposed_diff must be ScopedDiff, got {type(fresh_res.proposed_diff).__name__}")
                fresh_res.proposed_diff.expected_version = fresh_bb.blackboard_version

            try:
                self.intelligence_repo.apply_writes_and_diff_atomic(
                    challenge_id=task.challenge_id,
                    entity_writes=fresh_res.proposed_entity_writes,
                    scoped_diff=fresh_res.proposed_diff,
                    task_id=task.task_id,
                )
                # Update initial_res output to match recomputed output
                initial_res.output = fresh_res.output
                return True
            except StaleVersionError as fresh_sve:
                logger.warning(
                    f"Task {task.task_id} recomputation attempt {attempts} hit StaleVersionError: {fresh_sve}"
                )
                await asyncio.sleep(0.01)

        logger.error(f"Task {task.task_id} stale version recovery exhausted after {attempts} attempts.")
        return False

    async def _handle_timeout(self, task: Task, request: TaskRequest, retry_policy: RetryPolicy) -> None:
        """Handle task timeout and optional retry."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE tasks
            SET status = 'timed_out',
                error_message = 'Task execution timed out',
                completed_at = ?,
                updated_at = ?
            WHERE task_id = ?
            """,
            (now, now, task.task_id),
        )
        self.conn.commit()

        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task.task_id,
            event_type="TaskTimedOut",
            payload={"task_id": task.task_id, "status": "timed_out"},
        )

        if retry_policy.retry_on_timeout and task.retry_count < retry_policy.max_retries:
            await self._schedule_retry(task, request, retry_policy)

    async def _handle_failure(
        self, task: Task, request: TaskRequest, retry_policy: RetryPolicy, error_message: str
    ) -> None:
        """Handle task failure and optional retry."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE tasks
            SET status = 'failed',
                error_message = ?,
                completed_at = ?,
                updated_at = ?
            WHERE task_id = ?
            """,
            (error_message, now, now, task.task_id),
        )
        self.conn.commit()

        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task.task_id,
            event_type="TaskFailed",
            payload={"task_id": task.task_id, "status": "failed", "error": error_message},
        )

        if retry_policy.retry_on_failure and task.retry_count < retry_policy.max_retries:
            await self._schedule_retry(task, request, retry_policy)

    async def _schedule_retry(
        self, old_task: Task, request: TaskRequest, retry_policy: RetryPolicy
    ) -> Task:
        """Schedule a new retry attempt: NEW task_id, SAME task_group_id, retry_count + 1."""
        new_task_id = str(uuid.uuid4())
        new_retry_count = old_task.retry_count + 1
        now = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Scheduling retry attempt {new_retry_count} for task_group '{old_task.task_group_id}' (new task_id: {new_task_id})"
        )

        new_task = Task(
            task_id=new_task_id,
            challenge_id=old_task.challenge_id,
            task_group_id=old_task.task_group_id,
            task_type=old_task.task_type,
            status=TaskStatus.QUEUED,
            retry_key=old_task.retry_key,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            retry_count=new_retry_count,
            metadata=request.metadata,
        )

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO tasks (
                    task_id, challenge_id, task_group_id, task_type, status,
                    retry_key, retry_count, error_message, result_ref, metadata,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_task.task_id,
                    new_task.challenge_id,
                    new_task.task_group_id,
                    new_task.task_type,
                    new_task.status.value,
                    new_task.retry_key,
                    new_task.retry_count,
                    "",
                    "",
                    json.dumps(new_task.metadata),
                    now,
                    now,
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as ie:
            self.conn.rollback()
            raise DuplicateTaskError(
                f"Active task already exists for retry key ({old_task.challenge_id}, {old_task.task_group_id}, {old_task.task_type})"
            ) from ie

        await self._emit_lifecycle_event(
            challenge_id=new_task.challenge_id,
            task_id=new_task.task_id,
            event_type="TaskQueued",
            payload={
                "task_id": new_task.task_id,
                "task_group_id": new_task.task_group_id,
                "retry_count": new_retry_count,
            },
        )

        self._cancellation_events[new_task.task_id] = asyncio.Event()
        self._completion_events[new_task.task_id] = asyncio.Event()

        asyncio.create_task(self._run_task_execution(new_task, request))
        return new_task

    async def _mark_superseded(self, task: Task) -> None:
        """Mark task as superseded."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE tasks
            SET error_message = 'Task superseded by new task group',
                updated_at = ?
            WHERE task_id = ?
            """,
            (now, task.task_id),
        )
        self.conn.commit()

        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task.task_id,
            event_type="TaskSuperseded",
            payload={"task_id": task.task_id, "task_group_id": task.task_group_id},
        )

    async def _create_failed_task(self, request: TaskRequest, reason: str) -> Task:
        """Helper to create and persist a failed task immediately."""
        task_id = str(uuid.uuid4())
        retry_key = f"{request.challenge_id}:{request.task_group_id}:{request.task_type}"
        now = datetime.now(timezone.utc).isoformat()

        task = Task(
            task_id=task_id,
            challenge_id=request.challenge_id,
            task_group_id=request.task_group_id,
            task_type=request.task_type,
            status=TaskStatus.FAILED,
            retry_key=retry_key,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            started_at=datetime.fromisoformat(now),
            completed_at=datetime.fromisoformat(now),
            retry_count=0,
            error_message=reason,
            metadata=request.metadata,
        )

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO tasks (
                task_id, challenge_id, task_group_id, task_type, status,
                retry_key, retry_count, error_message, result_ref, metadata,
                started_at, completed_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.task_id,
                task.challenge_id,
                task.task_group_id,
                task.task_type,
                task.status.value,
                task.retry_key,
                task.retry_count,
                task.error_message,
                task.result_ref,
                json.dumps(task.metadata),
                now,
                now,
                now,
                now,
            ),
        )
        self.conn.commit()

        await self._emit_lifecycle_event(
            challenge_id=task.challenge_id,
            task_id=task.task_id,
            event_type="TaskFailed",
            payload={"task_id": task.task_id, "reason": reason},
        )

        evt = asyncio.Event()
        evt.set()
        self._completion_events[task.task_id] = evt
        return task

    async def _emit_lifecycle_event(
        self, challenge_id: str, task_id: str, event_type: str, payload: dict
    ) -> None:
        """Persist event to SQLite events table AND publish to EventBus."""
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())

        event = Event(
            event_id=event_id,
            challenge_id=challenge_id,
            event_type=event_type,
            actor="system:task_manager",
            payload=payload,
            occurred_at=datetime.fromisoformat(now),
            task_id=task_id,
        )

        cursor = self.conn.cursor()
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
                json.dumps(event.payload, default=str),
                now,
                task_id,
                json.dumps(event.metadata, default=str),
            ),
        )
        self.conn.commit()

        # Publish to EventBus asynchronously (error isolation inside event_bus)
        await self.event_bus.publish(event)

    async def _finalize_completion_event(self, task_id: str) -> None:
        """Signal completion event for wait_for callers."""
        if task_id in self._completion_events:
            self._completion_events[task_id].set()
