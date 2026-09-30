"""
Copilot Session Controller for Phase 9 AI CTF Copilot.

LOCKED INVARIANTS:
1. Thin presentation and orchestration layer over canonical Phase 5D-8 substrate.
2. ZERO state duplication: delegates state changes to TaskManager and Phase 8 approval handlers.
3. Enforces MENTOR and SOLVE mode policies without modifying execution boundaries.
4. Enforces ControlPlaneSecurity for all control-plane transitions (approvals & mode changes).
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
import uuid
from typing import Any, Dict, Optional

from ctf_mentor.copilot.mode import CopilotMode
from ctf_mentor.copilot.security import (
    ControlPlaneActionType,
    ControlPlaneSecurity,
    ControlPlaneSource,
    ExternalHostAuthenticator,
    VerifiedControlPlaneIdentity,
)
from ctf_mentor.domain.models import TaskStatus
from ctf_mentor.ingestion.adapter import _ensure_ingestion_tables
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.investigation_repo import InvestigationRepository
from ctf_mentor.runtime.task_context import TaskRequest
from ctf_mentor.runtime.task_manager import TaskManager

logger = logging.getLogger(__name__)


class CopilotSessionController:
    """Central controller for copilot interaction sessions."""

    def __init__(
        self,
        db_conn: sqlite3.Connection,
        blackboard_repo: BlackboardRepository,
        investigation_repo: InvestigationRepository,
        task_manager: TaskManager,
        authenticator: Optional[ExternalHostAuthenticator] = None,
    ) -> None:
        self.conn = db_conn
        _ensure_ingestion_tables(self.conn)
        self.blackboard_repo = blackboard_repo
        self.investigation_repo = investigation_repo
        self.task_manager = task_manager
        self.authenticator = authenticator

    def initialize_copilot_session(
        self,
        challenge_id: str,
        mode: CopilotMode = CopilotMode.MENTOR,
        investigation_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or retrieve existing Copilot session for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT copilot_session_id, challenge_id, investigation_session_id, mode, created_at, updated_at
            FROM copilot_sessions
            WHERE challenge_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (challenge_id,),
        )
        row = cursor.fetchone()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if row:
            inv_sess_id = row["investigation_session_id"] or investigation_session_id
            if investigation_session_id and row["investigation_session_id"] != investigation_session_id:
                cursor.execute(
                    "UPDATE copilot_sessions SET investigation_session_id = ?, updated_at = ? WHERE copilot_session_id = ?",
                    (investigation_session_id, now, row["copilot_session_id"]),
                )
                self.conn.commit()
                inv_sess_id = investigation_session_id

            return {
                "copilot_session_id": row["copilot_session_id"],
                "challenge_id": row["challenge_id"],
                "investigation_session_id": inv_sess_id,
                "mode": row["mode"],
                "created_at": row["created_at"],
                "updated_at": now,
            }

        sess_id = f"csess_{uuid.uuid4().hex[:12]}"
        cursor.execute(
            """
            INSERT INTO copilot_sessions (
                copilot_session_id, challenge_id, investigation_session_id, mode, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sess_id, challenge_id, investigation_session_id, mode.value, now, now),
        )
        self.conn.commit()

        return {
            "copilot_session_id": sess_id,
            "challenge_id": challenge_id,
            "investigation_session_id": investigation_session_id,
            "mode": mode.value,
            "created_at": now,
            "updated_at": now,
        }

    def switch_mode(
        self,
        challenge_id: str,
        new_mode: CopilotMode,
        identity: VerifiedControlPlaneIdentity,
        source: ControlPlaneSource,
    ) -> Dict[str, Any]:
        """Switch session CopilotMode (MENTOR <-> SOLVE).
        
        CRITICAL: Control-plane action validated via ControlPlaneSecurity against self.authenticator ONLY.
        NO per-call authenticator overrides allowed.
        """
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.SWITCH_COPILOT_MODE,
            identity=identity,
            source=source,
            authenticator=self.authenticator,
        )

        session = self.initialize_copilot_session(challenge_id)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE copilot_sessions SET mode = ?, updated_at = ? WHERE copilot_session_id = ?",
            (new_mode.value, now, session["copilot_session_id"]),
        )
        self.conn.commit()

        session["mode"] = new_mode.value
        session["updated_at"] = now
        logger.info(f"Copilot mode for challenge '{challenge_id}' switched to '{new_mode.value}' by actor '{identity.user_id}'.")
        return session

    def get_session_info(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Fetch active Copilot session info."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT copilot_session_id, challenge_id, investigation_session_id, mode, created_at, updated_at
            FROM copilot_sessions
            WHERE challenge_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (challenge_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)

    async def submit_step_approval(
        self,
        challenge_id: str,
        step_id: str,
        session_id: str,
        decision: str,
        reason: str,
        identity: VerifiedControlPlaneIdentity,
        source: ControlPlaneSource,
    ) -> Dict[str, Any]:
        """Submit step approval decision through Phase 8 DecideStepApprovalHandler via TaskManager.
        
        CRITICAL: Control-plane action validated via ControlPlaneSecurity against self.authenticator ONLY.
        NO per-call authenticator overrides allowed.
        """
        ControlPlaneSecurity.validate_control_plane_action(
            action_type=ControlPlaneActionType.DECIDE_STEP_APPROVAL,
            identity=identity,
            source=source,
            authenticator=self.authenticator,
        )

        req = TaskRequest(
            challenge_id=challenge_id,
            task_group_id=f"grp_approval_{uuid.uuid4().hex[:8]}",
            task_type="decide_investigation_step_approval",
            parameters={
                "step_id": step_id,
                "session_id": session_id,
                "decision": decision,
                "reason": reason,
                "resolved_by": identity.user_id,
            },
        )

        submitted_task = await self.task_manager.submit(req)
        final_task = await self.task_manager.wait_for(submitted_task.task_id, timeout=10.0)

        if final_task.status != TaskStatus.COMPLETED:
            return {
                "success": False,
                "error": final_task.error_message or f"Approval task failed with status {final_task.status.value}",
            }

        return {
            "success": True,
            "task_id": final_task.task_id,
            "result": final_task.result_ref,
        }
