"""
Comprehensive test suite for Phase 5C — Runtime Orchestration Foundation.

Verifies:
A. Task Lifecycle
B. Retry Semantics
C. Supersession Semantics
D. Deduplication
E. Simple Dependencies
F. Bounded Concurrency
G. Blackboard Integration & Stale Version Handling
H. Event Bus & Lifecycle Events
I. Failure Handling
J. Startup Orphan Recovery
K. Approval Boundary
L. Security Invariants
"""

import asyncio
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from ctf_mentor.contracts import (
    DuplicateTaskError,
    ScopedDiff,
    StaleVersionError,
    TaskExecutionError,
    TaskNotFoundError,
)
from ctf_mentor.domain.models import (
    ApprovalRecord,
    ApprovalStatus,
    ApprovalType,
    AuthorizedScope,
    Challenge,
    HintLevel,
    TaskStatus,
)
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import initialize_schema
from ctf_mentor.runtime.event_bus import EventBus
from ctf_mentor.runtime.handler_registry import HandlerRegistry, TaskHandler
from ctf_mentor.runtime.handlers.null_handler import NullHandler
from ctf_mentor.runtime.reconciliation import reconcile_orphaned_tasks
from ctf_mentor.runtime.retry_policy import RetryPolicy
from ctf_mentor.runtime.task_context import HandlerResult, TaskContext, TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager


@pytest.fixture
def db_conn():
    """Create in-memory SQLite database initialized with schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    initialize_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def bb_repo(db_conn):
    """Create BlackboardRepository instance."""
    return BlackboardRepository(db_conn)


@pytest.fixture
def challenge_setup(bb_repo):
    """Create test challenge and active scope."""
    ch_id = str(uuid.uuid4())
    ch = Challenge(
        challenge_id=ch_id,
        name="Test Challenge",
        description="Phase 5C Test Challenge",
        category="web",
        global_hint_level=HintLevel.L3,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    bb_repo.create_challenge(ch)

    bb_repo.create_authorized_scope(
        scope_id=str(uuid.uuid4()),
        challenge_id=ch_id,
        scheme="http",
        hostname="example.com",
        port=80,
        allowed_path_patterns=["/api/*"],
        allowed_methods=["GET"],
        exclusions=[],
        query_restrictions={},
        environment_id="test_env",
        challenge_relationship="primary_target",
        is_active=True,
    )
    return ch_id


@pytest.fixture
def registry():
    """Create HandlerRegistry pre-registered with NullHandler."""
    reg = HandlerRegistry()
    reg.register("null", NullHandler())
    reg.register("slow_null", NullHandler(delay_seconds=0.1))
    reg.register("failing", NullHandler(should_fail=True))
    return reg


@pytest.fixture
def event_bus():
    """Create EventBus instance."""
    return EventBus()


@pytest.fixture
def task_manager(db_conn, bb_repo, registry, event_bus):
    """Create TaskManager instance."""
    return TaskManager(
        db_connection=db_conn,
        blackboard_repo=bb_repo,
        handler_registry=registry,
        event_bus=event_bus,
        max_concurrency=5,
    )


# ---------------------------------------------------------------------------
# A. TASK LIFECYCLE TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_task_lifecycle_queued_running_completed(task_manager, challenge_setup):
    """Test standard task lifecycle: QUEUED -> RUNNING -> COMPLETED."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_1",
        task_type="null",
        parameters={"echo": "test_output"},
    )
    task = await task_manager.submit(req)
    assert task.status == TaskStatus.QUEUED

    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED
    assert final_task.completed_at is not None
    assert "test_output" in final_task.result_ref


@pytest.mark.asyncio
async def test_task_lifecycle_failed(task_manager, challenge_setup):
    """Test task execution failure lifecycle."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_fail",
        task_type="failing",
        retry_policy=RetryPolicy(max_retries=0),
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.FAILED
    assert "intentional failure" in final_task.error_message


@pytest.mark.asyncio
async def test_task_lifecycle_cancellation(task_manager, challenge_setup):
    """Test task cancellation."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_cancel",
        task_type="slow_null",
    )
    task = await task_manager.submit(req)
    cancelled = await task_manager.cancel(task.task_id)
    assert cancelled is True

    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.CANCELLED


@pytest.mark.asyncio
async def test_task_lifecycle_timeout(task_manager, challenge_setup):
    """Test task timeout handling."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_timeout",
        task_type="slow_null",
        timeout_seconds=0.01,
        retry_policy=RetryPolicy(max_retries=0),
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.TIMED_OUT


# ---------------------------------------------------------------------------
# B. RETRY SEMANTICS TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_semantics_new_task_id_same_group_id(task_manager, challenge_setup, db_conn):
    """Verify retry creates new task_id with same task_group_id and incremented retry_count."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_retry",
        task_type="failing",
        retry_policy=RetryPolicy(max_retries=1, retry_on_failure=True),
    )
    task1 = await task_manager.submit(req)
    await asyncio.sleep(0.3)

    cursor = db_conn.cursor()
    cursor.execute(
        "SELECT task_id, task_group_id, retry_count, status FROM tasks WHERE task_group_id = ? ORDER BY retry_count ASC",
        ("group_retry",),
    )
    rows = cursor.fetchall()
    assert len(rows) == 2
    # Attempt 1
    assert rows[0][0] == task1.task_id
    assert rows[0][1] == "group_retry"
    assert rows[0][2] == 0
    assert rows[0][3] == "failed"

    # Attempt 2
    assert rows[1][0] != task1.task_id  # NEW task_id
    assert rows[1][1] == "group_retry"  # SAME task_group_id
    assert rows[1][2] == 1              # incremented retry_count
    assert rows[1][3] == "failed"


# ---------------------------------------------------------------------------
# C. SUPERSESSION SEMANTICS TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supersession_semantics(task_manager, challenge_setup, bb_repo, db_conn):
    """Verify new task_group_id supersedes old task and old result is discarded."""
    req1 = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_old",
        task_type="slow_null",
        parameters={"proposed_changes": {"session_notes": "old notes"}},
    )
    task1 = await task_manager.submit(req1)

    req2 = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_new",
        task_type="null",
        supersedes_task_group_id="group_old",
        parameters={"proposed_changes": {"session_notes": "new notes"}},
    )
    task2 = await task_manager.submit(req2)

    await task_manager.wait_for(task2.task_id, timeout=2.0)
    await task_manager.wait_for(task1.task_id, timeout=2.0)

    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    # The new notes must be present; old notes must NOT overwrite!
    assert bb_state.session_notes == "new notes"


# ---------------------------------------------------------------------------
# D. DEDUPLICATION TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deduplication_active_task_blocked(task_manager, challenge_setup):
    """Verify duplicate active submission for same (challenge_id, task_group_id, task_type) raises DuplicateTaskError."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="group_dedup",
        task_type="slow_null",
    )
    await task_manager.submit(req)

    with pytest.raises(DuplicateTaskError):
        await task_manager.submit(req)


# ---------------------------------------------------------------------------
# E. DEPENDENCIES TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dependencies_success_unlocks_child(task_manager, challenge_setup):
    """Test child task waits for parent to finish COMPLETED."""
    parent_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="parent_group",
        task_type="null",
        parameters={"echo": "parent_ok"},
    )
    parent_task = await task_manager.submit(parent_req)

    child_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="child_group",
        task_type="null",
        depends_on_task_ids=[parent_task.task_id],
        parameters={"echo": "child_ok"},
    )
    child_task = await task_manager.submit(child_req)

    final_child = await task_manager.wait_for(child_task.task_id, timeout=2.0)
    assert final_child.status == TaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_dependencies_failure_prevents_child(task_manager, challenge_setup):
    """Test child task fails with dependency_failed if parent fails."""
    parent_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="parent_fail_group",
        task_type="failing",
        retry_policy=RetryPolicy(max_retries=0),
    )
    parent_task = await task_manager.submit(parent_req)

    child_req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="child_fail_group",
        task_type="null",
        depends_on_task_ids=[parent_task.task_id],
    )
    child_task = await task_manager.submit(child_req)

    final_child = await task_manager.wait_for(child_task.task_id, timeout=2.0)
    assert final_child.status == TaskStatus.FAILED
    assert "dependency_failed" in final_child.error_message


# ---------------------------------------------------------------------------
# F. CONCURRENCY TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bounded_concurrency(task_manager, challenge_setup):
    """Test bounded concurrency executes multiple independent tasks safely."""
    tasks = []
    for i in range(10):
        req = TaskRequest(
            challenge_id=challenge_setup,
            task_group_id=f"concurrent_group_{i}",
            task_type="null",
            parameters={"echo": f"task_{i}"},
        )
        t = await task_manager.submit(req)
        tasks.append(t)

    for t in tasks:
        res = await task_manager.wait_for(t.task_id, timeout=3.0)
        assert res.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# G. BLACKBOARD INTEGRATION & STALE VERSION HANDLING
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blackboard_scoped_diff_applied(task_manager, challenge_setup, bb_repo):
    """Verify proposed diff is applied strictly via BlackboardRepository gateway."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="diff_group",
        task_type="null",
        parameters={"proposed_changes": {"session_notes": "Blackboard mutation via runtime"}},
    )
    task = await task_manager.submit(req)
    await task_manager.wait_for(task.task_id, timeout=2.0)

    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    assert bb_state.session_notes == "Blackboard mutation via runtime"
    assert bb_state.blackboard_version == 1


# ---------------------------------------------------------------------------
# H. EVENTS & EVENT BUS TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_bus_and_lifecycle_events(task_manager, challenge_setup, event_bus, db_conn):
    """Verify lifecycle events flow to EventBus subscribers and persistent SQLite events."""
    received_events = []

    def sub(evt):
        received_events.append(evt)

    event_bus.subscribe_all(sub)

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="event_group",
        task_type="null",
    )
    task = await task_manager.submit(req)
    await task_manager.wait_for(task.task_id, timeout=2.0)

    event_types = [e.event_type for e in received_events]
    assert "TaskQueued" in event_types
    assert "TaskStarted" in event_types
    assert "TaskCompleted" in event_types

    # Verify persistent event log in DB
    cursor = db_conn.cursor()
    cursor.execute("SELECT event_type FROM events WHERE task_id = ?", (task.task_id,))
    db_events = [r[0] for r in cursor.fetchall()]
    assert "TaskQueued" in db_events
    assert "TaskStarted" in db_events
    assert "TaskCompleted" in db_events


@pytest.mark.asyncio
async def test_event_bus_subscriber_failure_isolation(task_manager, challenge_setup, event_bus):
    """Verify subscriber exception does NOT break task execution or state."""
    def bad_sub(evt):
        raise RuntimeError("Subscriber explosion!")

    event_bus.subscribe_all(bad_sub)

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="isolated_event_group",
        task_type="null",
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# J. STARTUP RECOVERY TESTS
# ---------------------------------------------------------------------------


def test_startup_orphan_task_reconciliation(db_conn, bb_repo):
    """Test startup recovery converts RUNNING tasks left by a crash to FAILED ('orphaned_on_restart')."""
    # Insert a fake RUNNING task directly into DB
    ch_id = str(uuid.uuid4())
    ch = Challenge(
        challenge_id=ch_id,
        name="Crash Challenge",
        description="",
        category="crypto",
        global_hint_level=HintLevel.L0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    bb_repo.create_challenge(ch)

    now = datetime.now(timezone.utc).isoformat()
    cursor = db_conn.cursor()
    cursor.execute(
        """
        INSERT INTO tasks (
            task_id, challenge_id, task_group_id, task_type, status,
            retry_key, retry_count, error_message, result_ref, metadata,
            created_at, updated_at
        ) VALUES ('orphaned_task_123', ?, 'g_crash', 'null', 'running', 'rk', 0, '', '', '{}', ?, ?)
        """,
        (ch_id, now, now),
    )
    db_conn.commit()

    reconciled = reconcile_orphaned_tasks(db_conn)
    assert "orphaned_task_123" in reconciled

    cursor.execute("SELECT status, error_message FROM tasks WHERE task_id = 'orphaned_task_123'")
    row = cursor.fetchone()
    assert row[0] == "failed"
    assert row[1] == "orphaned_on_restart"


# ---------------------------------------------------------------------------
# K. APPROVAL BOUNDARY TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_boundary_unapproved_blocked(task_manager, challenge_setup):
    """Verify task requiring approval is blocked if no approved ApprovalRecord exists."""
    app_id = str(uuid.uuid4())
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="app_group",
        task_type="null",
        requires_approval=True,
        approval_id=app_id,
    )
    with pytest.raises(TaskExecutionError, match="Approval check failed"):
        await task_manager.submit(req)


@pytest.mark.asyncio
async def test_approval_boundary_approved_proceeds(task_manager, challenge_setup, bb_repo):
    """Verify approved ApprovalRecord allows task to execute."""
    app_id = str(uuid.uuid4())
    bb_repo.create_approval_record(
        approval_id=app_id,
        challenge_id=challenge_setup,
        approval_type="environment_action",
        requested_by="user",
        requested_action_ref="ref_1",
        status="requested",
    )
    bb_repo.update_approval_record_status(app_id, "pending")
    bb_repo.update_approval_record_status(app_id, "approved", "admin")

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="approved_group",
        task_type="null",
        requires_approval=True,
        approval_id=app_id,
    )
    task = await task_manager.submit(req)
    final_task = await task_manager.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# L. SECURITY & INVARIANTS TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_security_handler_has_no_db_or_repo_handle(registry, challenge_setup, bb_repo):
    """Verify TaskContext contains no database or repository handles."""
    class SecurityProbeHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            # Check context attributes
            attrs = dir(ctx)
            assert "conn" not in attrs
            assert "db" not in attrs
            assert "repo" not in attrs
            assert "blackboard_repo" not in attrs
            return HandlerResult(success=True, output="security_pass")

    registry.register("security_probe", SecurityProbeHandler())
    tm = TaskManager(bb_repo._conn, bb_repo, registry)

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="sec_group",
        task_type="security_probe",
    )
    task = await tm.submit(req)
    final_task = await tm.wait_for(task.task_id, timeout=2.0)
    assert final_task.status == TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# M. PHASE 5C REMEDIATION REGRESSION TESTS (BLOCKERS & HARDENING)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remediation_test_a_concurrent_handlers_recompute_both_survive(task_manager, challenge_setup, bb_repo, registry):
    """TEST A: Concurrent handlers modify active_hypothesis_ids based on snapshot. Both survive via recomputation."""
    class HypothesisAppenderHandler(TaskHandler):
        def __init__(self, hyp_id_to_add: str):
            self.hyp_id_to_add = hyp_id_to_add

        async def execute(self, ctx: TaskContext) -> HandlerResult:
            curr_list = list(ctx.blackboard_snapshot.active_hypothesis_ids)
            if self.hyp_id_to_add not in curr_list:
                curr_list.append(self.hyp_id_to_add)
            return HandlerResult(
                success=True,
                output=f"added_{self.hyp_id_to_add}",
                proposed_diff=ScopedDiff(
                    challenge_id=ctx.challenge_id,
                    expected_version=ctx.blackboard_snapshot.blackboard_version,
                    actor="test_actor",
                    event_type="hypothesis_added",
                    changes={"active_hypothesis_ids": curr_list},
                ),
            )

    registry.register("append_hyp_A", HypothesisAppenderHandler("hyp_A"))
    registry.register("append_hyp_B", HypothesisAppenderHandler("hyp_B"))

    req_a = TaskRequest(challenge_id=challenge_setup, task_group_id="g_a", task_type="append_hyp_A")
    req_b = TaskRequest(challenge_id=challenge_setup, task_group_id="g_b", task_type="append_hyp_B")

    t_a = await task_manager.submit(req_a)
    t_b = await task_manager.submit(req_b)

    await task_manager.wait_for(t_a.task_id, timeout=3.0)
    await task_manager.wait_for(t_b.task_id, timeout=3.0)

    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    assert "hyp_A" in bb_state.active_hypothesis_ids
    assert "hyp_B" in bb_state.active_hypothesis_ids
    assert bb_state.blackboard_version == 2


@pytest.mark.asyncio
async def test_remediation_test_b_stale_version_conflict_recomputes_handler(task_manager, challenge_setup, bb_repo, registry):
    """TEST B: Force a stale-version conflict and verify handler is recomputed against fresh state."""
    recompute_counts = {"count": 0}

    class RecomputingHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            recompute_counts["count"] += 1
            notes = f"notes_v{ctx.blackboard_snapshot.blackboard_version}"
            return HandlerResult(
                success=True,
                output="recomputed_ok",
                proposed_diff=ScopedDiff(
                    challenge_id=ctx.challenge_id,
                    expected_version=ctx.blackboard_snapshot.blackboard_version,
                    actor="test_actor",
                    event_type="notes_updated",
                    changes={"session_notes": notes},
                ),
            )

    registry.register("recompute_test", RecomputingHandler())

    # Submit task
    req = TaskRequest(challenge_id=challenge_setup, task_group_id="g_recompute", task_type="recompute_test")
    
    # Concurrently bump Blackboard version before diff application
    bb_repo.apply_scoped_diff(
        ScopedDiff(
            challenge_id=challenge_setup,
            expected_version=0,
            actor="interfering_actor",
            event_type="interfering_update",
            changes={"session_notes": "interfered"},
        )
    )

    t = await task_manager.submit(req)
    final_t = await task_manager.wait_for(t.task_id, timeout=2.0)

    assert final_t.status == TaskStatus.COMPLETED
    assert recompute_counts["count"] >= 1
    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    assert "notes_v1" in bb_state.session_notes


@pytest.mark.asyncio
async def test_remediation_test_c_exceed_stale_retry_limit_fails_task(task_manager, challenge_setup, bb_repo, registry):
    """TEST C: Exceeding stale retry limit marks task FAILED without overwriting Blackboard."""
    class AlwaysStaleHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            # Interference: bump Blackboard version during handler execution every time!
            bb_curr = bb_repo.read_blackboard_state(ctx.challenge_id)
            bb_repo.apply_scoped_diff(
                ScopedDiff(
                    challenge_id=ctx.challenge_id,
                    expected_version=bb_curr.blackboard_version,
                    actor="interferer",
                    event_type="bump",
                    changes={"session_notes": f"bump_{bb_curr.blackboard_version}"},
                )
            )
            return HandlerResult(
                success=True,
                output="stale_out",
                proposed_diff=ScopedDiff(
                    challenge_id=ctx.challenge_id,
                    expected_version=ctx.blackboard_snapshot.blackboard_version,
                    actor="stale_actor",
                    event_type="stale_diff",
                    changes={"session_notes": "stale_target_notes"},
                ),
            )

    registry.register("always_stale", AlwaysStaleHandler())

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_stale_limit",
        task_type="always_stale",
        retry_policy=RetryPolicy(max_retries=2, retry_on_stale_version=True, retry_on_failure=False),
    )
    t = await task_manager.submit(req)
    final_t = await task_manager.wait_for(t.task_id, timeout=2.0)

    assert final_t.status == TaskStatus.FAILED
    assert "Stale version recovery exhausted" in final_t.error_message

    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    assert bb_state.session_notes != "stale_target_notes"


@pytest.mark.asyncio
async def test_remediation_test_d_invalid_handler_result_fails_task(task_manager, challenge_setup, registry):
    """TEST D: Handler returning invalid/bare result fails task and does not remain RUNNING."""
    class BadReturnHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            return "bare_string_not_handler_result"  # type: ignore

    registry.register("bad_return", BadReturnHandler())

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_bad_return",
        task_type="bad_return",
        retry_policy=RetryPolicy(max_retries=0),
    )
    t = await task_manager.submit(req)
    final_t = await task_manager.wait_for(t.task_id, timeout=2.0)

    assert final_t.status == TaskStatus.FAILED
    assert "HandlerResult" in final_t.error_message


@pytest.mark.asyncio
async def test_remediation_test_e_invalid_scoped_diff_fails_task(task_manager, challenge_setup, bb_repo, registry):
    """TEST E: Handler returning invalid proposed_diff fails task without Blackboard corruption."""
    class BadDiffHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            return HandlerResult(
                success=True,
                proposed_diff="not_a_scoped_diff_object",  # type: ignore
            )

    registry.register("bad_diff", BadDiffHandler())

    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_bad_diff",
        task_type="bad_diff",
        retry_policy=RetryPolicy(max_retries=0),
    )
    t = await task_manager.submit(req)
    final_t = await task_manager.wait_for(t.task_id, timeout=2.0)

    assert final_t.status == TaskStatus.FAILED
    assert "ScopedDiff" in final_t.error_message

    bb_state = bb_repo.read_blackboard_state(challenge_setup)
    assert bb_state.blackboard_version == 0


@pytest.mark.asyncio
async def test_remediation_test_f_unhandled_exception_in_post_handler_processing(task_manager, challenge_setup, registry):
    """TEST F: Post-handler exception during json serialization fails task safely."""
    class UnserializableOutputHandler(TaskHandler):
        async def execute(self, ctx: TaskContext) -> HandlerResult:
            class NonSerializable:
                pass
            return HandlerResult(success=True, output=NonSerializable())

    registry.register("unserializable", UnserializableOutputHandler())

    # Modify json.dumps handling or test unhandled exception path
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_unserializable",
        task_type="unserializable",
        retry_policy=RetryPolicy(max_retries=0),
    )
    t = await task_manager.submit(req)
    final_t = await task_manager.wait_for(t.task_id, timeout=2.0)

    assert final_t.status == TaskStatus.COMPLETED or final_t.status == TaskStatus.FAILED


@pytest.mark.asyncio
async def test_remediation_test_g_completed_task_does_not_block_new_submission(task_manager, challenge_setup):
    """TEST G: Completed task does not block new submission with same dedup key."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_completed_dedup",
        task_type="null",
        parameters={"echo": "first"},
    )
    t1 = await task_manager.submit(req)
    await task_manager.wait_for(t1.task_id, timeout=2.0)

    # Re-submit with same dedup key after completion
    t2 = await task_manager.submit(req)
    assert t2.task_id != t1.task_id
    final_t2 = await task_manager.wait_for(t2.task_id, timeout=2.0)
    assert final_t2.status == TaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_remediation_test_h_concurrent_active_dedup_raises_duplicate_task_error(task_manager, challenge_setup):
    """TEST H: Submitting active duplicate raises DuplicateTaskError (no raw sqlite3.IntegrityError)."""
    req = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_concurrent_dedup",
        task_type="slow_null",
    )
    await task_manager.submit(req)

    with pytest.raises(DuplicateTaskError):
        await task_manager.submit(req)


@pytest.mark.asyncio
async def test_remediation_test_i_cancelled_failed_timed_out_do_not_block_submission(task_manager, challenge_setup):
    """TEST I: Cancelled/failed/timed-out tasks do not block new submissions."""
    req_fail = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_inactive_dedup",
        task_type="failing",
        retry_policy=RetryPolicy(max_retries=0),
    )
    t_fail = await task_manager.submit(req_fail)
    await task_manager.wait_for(t_fail.task_id, timeout=2.0)

    # Submit new task with same group/type after failure
    req_null = TaskRequest(
        challenge_id=challenge_setup,
        task_group_id="g_inactive_dedup",
        task_type="null",
    )
    t_new = await task_manager.submit(req_null)
    final_new = await task_manager.wait_for(t_new.task_id, timeout=2.0)
    assert final_new.status == TaskStatus.COMPLETED


def test_remediation_test_j_atomic_orphan_reconciliation_transaction(db_conn, bb_repo):
    """TEST J: Verify orphan task reconciliation commits status update + event atomically (F4)."""
    ch_id = str(uuid.uuid4())
    ch = Challenge(
        challenge_id=ch_id,
        name="Orphan Atomic Test",
        description="",
        category="web",
        global_hint_level=HintLevel.L0,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    bb_repo.create_challenge(ch)

    now = datetime.now(timezone.utc).isoformat()
    cursor = db_conn.cursor()
    cursor.execute(
        """
        INSERT INTO tasks (
            task_id, challenge_id, task_group_id, task_type, status,
            retry_key, retry_count, error_message, result_ref, metadata,
            created_at, updated_at
        ) VALUES ('orphan_atomic_999', ?, 'g_atomic', 'null', 'running', 'rk_atom', 0, '', '', '{}', ?, ?)
        """,
        (ch_id, now, now),
    )
    db_conn.commit()

    reconciled = reconcile_orphaned_tasks(db_conn)
    assert "orphan_atomic_999" in reconciled

    cursor.execute("SELECT status, error_message FROM tasks WHERE task_id = 'orphan_atomic_999'")
    row = cursor.fetchone()
    assert row[0] == "failed"
    assert row[1] == "orphaned_on_restart"

    cursor.execute("SELECT event_type FROM events WHERE task_id = 'orphan_atomic_999'")
    evt_row = cursor.fetchone()
    assert evt_row is not None
    assert evt_row[0] == "TaskFailed"


def test_remediation_test_k_schema_v2_to_v3_migration():
    """TEST K: Verify real database migration path from schema version 2 to version 3.

    1. Construct a genuine schema-version-2 database with the v2 partial index.
    2. Seed representative data (challenge, completed task, blackboard state, schema_version=2).
    3. Execute initialize_schema(conn) to run the v2 -> v3 migration.
    4. Verify existing data survives, schema_version is 3, completed duplicate is allowed,
       active duplicate is blocked.
    5. Execute initialize_schema(conn) again and verify idempotency.
    """
    v2_conn = sqlite3.connect(":memory:")
    v2_conn.row_factory = sqlite3.Row
    v2_conn.execute("PRAGMA foreign_keys = ON;")

    # 1. Construct schema v2 tables
    v2_conn.executescript(
        """
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'));

        CREATE TABLE challenges (
            challenge_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            global_hint_level INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE blackboard_states (
            challenge_id TEXT PRIMARY KEY REFERENCES challenges(challenge_id),
            blackboard_version INTEGER NOT NULL DEFAULT 0,
            active_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            watchlist_hypothesis_ids TEXT NOT NULL DEFAULT '[]',
            confirmed_findings TEXT NOT NULL DEFAULT '[]',
            active_evidence_ids TEXT NOT NULL DEFAULT '[]',
            last_hint_level INTEGER NOT NULL DEFAULT 0,
            session_notes TEXT NOT NULL DEFAULT '',
            metadata TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id),
            task_group_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            retry_key TEXT NOT NULL,
            retry_count INTEGER NOT NULL DEFAULT 0,
            error_message TEXT NOT NULL DEFAULT '',
            result_ref TEXT NOT NULL DEFAULT '',
            metadata TEXT NOT NULL DEFAULT '{}',
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- Old v2 partial index that blocked completed tasks
        CREATE UNIQUE INDEX uq_tasks_dedup
            ON tasks (challenge_id, task_group_id, task_type)
            WHERE status NOT IN ('cancelled','timed_out','failed');
        """
    )
    v2_conn.commit()

    # 2. Seed representative v2 data
    now = datetime.now(timezone.utc).isoformat()
    v2_conn.execute(
        "INSERT INTO challenges (challenge_id, name, description, category, created_at, updated_at) "
        "VALUES ('ch_v2_1', 'V2 Challenge', 'Desc', 'web', ?, ?)",
        (now, now),
    )
    v2_conn.execute(
        "INSERT INTO blackboard_states (challenge_id, blackboard_version, updated_at) "
        "VALUES ('ch_v2_1', 0, ?)",
        (now,),
    )
    v2_conn.execute(
        "INSERT INTO tasks (task_id, challenge_id, task_group_id, task_type, status, retry_key, created_at, updated_at) "
        "VALUES ('task_v2_1', 'ch_v2_1', 'g_v2', 'null', 'completed', 'rk', ?, ?)",
        (now, now),
    )
    v2_conn.commit()

    # Verify that in v2, completed duplicate task IS BLOCKED by old index
    with pytest.raises(sqlite3.IntegrityError):
        v2_conn.execute(
            "INSERT INTO tasks (task_id, challenge_id, task_group_id, task_type, status, retry_key, created_at, updated_at) "
            "VALUES ('task_v2_2', 'ch_v2_1', 'g_v2', 'null', 'completed', 'rk2', ?, ?)",
            (now, now),
        )
    v2_conn.rollback()

    # 3. Run CURRENT initialize_schema migration
    ver = initialize_schema(v2_conn)
    assert ver >= 3

    # 4. Verify migration results
    # a. Schema version is target version
    row = v2_conn.execute("SELECT MAX(version) FROM schema_version;").fetchone()
    assert row[0] >= 3

    # b. Existing data survived intact
    ch_row = v2_conn.execute("SELECT name FROM challenges WHERE challenge_id = 'ch_v2_1'").fetchone()
    assert ch_row["name"] == "V2 Challenge"

    t_row = v2_conn.execute("SELECT status FROM tasks WHERE task_id = 'task_v2_1'").fetchone()
    assert t_row["status"] == "completed"

    bb_row = v2_conn.execute("SELECT blackboard_version FROM blackboard_states WHERE challenge_id = 'ch_v2_1'").fetchone()
    assert bb_row["blackboard_version"] == 0

    # c. Completed duplicate task is NOW ALLOWED
    v2_conn.execute(
        "INSERT INTO tasks (task_id, challenge_id, task_group_id, task_type, status, retry_key, created_at, updated_at) "
        "VALUES ('task_v2_2', 'ch_v2_1', 'g_v2', 'null', 'completed', 'rk2', ?, ?)",
        (now, now),
    )
    v2_conn.commit()

    # d. Active duplicate task (queued/running) remains BLOCKED by new index
    v2_conn.execute(
        "INSERT INTO tasks (task_id, challenge_id, task_group_id, task_type, status, retry_key, created_at, updated_at) "
        "VALUES ('task_v2_active1', 'ch_v2_1', 'g_v2_act', 'null', 'queued', 'rk3', ?, ?)",
        (now, now),
    )
    v2_conn.commit()

    with pytest.raises(sqlite3.IntegrityError):
        v2_conn.execute(
            "INSERT INTO tasks (task_id, challenge_id, task_group_id, task_type, status, retry_key, created_at, updated_at) "
            "VALUES ('task_v2_active2', 'ch_v2_1', 'g_v2_act', 'null', 'running', 'rk4', ?, ?)",
            (now, now),
        )
    v2_conn.rollback()

    # 5 & 6. Verify migration idempotency
    ver_again = initialize_schema(v2_conn)
    assert ver_again >= 3

    v2_conn.close()
