"""
Database repository for Phase 10B.1 Workspace Isolation.

Manages the local_workspaces persistence table, workspace lifecycle status transitions,
and challenge/session binding validations.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from ctf_mentor.workspace.models import (
    WorkspaceRecord,
    WorkspaceStatus,
    WorkspaceValidationError,
)

_CREATE_LOCAL_WORKSPACES_TABLE = """
CREATE TABLE IF NOT EXISTS local_workspaces (
    workspace_id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(challenge_id)
        ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES investigation_sessions(session_id)
        ON DELETE CASCADE,
    relative_root TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CREATING',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    CHECK(status IN (
        'CREATING',
        'READY',
        'EXPIRED',
        'QUARANTINED'
    )),
    UNIQUE(challenge_id, session_id)
);
"""


def ensure_workspace_table(conn: sqlite3.Connection) -> None:
    """Idempotently ensure local_workspaces table exists in SQLite database."""
    conn.execute(_CREATE_LOCAL_WORKSPACES_TABLE)


class WorkspaceRepository:
    """Repository helper for local_workspaces persistence operations."""

    @staticmethod
    def ensure_table(conn: sqlite3.Connection) -> None:
        """Ensure local_workspaces table exists."""
        ensure_workspace_table(conn)

    @staticmethod
    def validate_challenge_and_session(
        conn: sqlite3.Connection,
        challenge_id: str,
        session_id: str,
    ) -> None:
        """Validate that challenge_id exists, session_id exists, and session belongs to challenge_id.

        Raises WorkspaceValidationError on any invalid pairing or missing record.
        """
        # 1. Check challenge existence
        ch_row = conn.execute(
            "SELECT challenge_id FROM challenges WHERE challenge_id = ?;",
            (challenge_id,),
        ).fetchone()
        if not ch_row:
            raise WorkspaceValidationError(f"Challenge '{challenge_id}' does not exist.")

        # 2. Check session existence and binding
        sess_row = conn.execute(
            "SELECT session_id, challenge_id FROM investigation_sessions WHERE session_id = ?;",
            (session_id,),
        ).fetchone()
        if not sess_row:
            raise WorkspaceValidationError(f"Investigation session '{session_id}' does not exist.")

        bound_challenge_id = sess_row["challenge_id"] if isinstance(sess_row, sqlite3.Row) else sess_row[1]
        if bound_challenge_id != challenge_id:
            raise WorkspaceValidationError(
                f"Investigation session '{session_id}' belongs to challenge '{bound_challenge_id}', "
                f"not requested challenge '{challenge_id}'."
            )

    @staticmethod
    def create(conn: sqlite3.Connection, record: WorkspaceRecord) -> None:
        """Insert a new local_workspaces database record."""
        ensure_workspace_table(conn)
        conn.execute(
            """
            INSERT INTO local_workspaces (
                workspace_id, challenge_id, session_id, relative_root,
                status, created_at, updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                record.workspace_id,
                record.challenge_id,
                record.session_id,
                record.relative_root,
                record.status,
                record.created_at,
                record.updated_at,
                record.expires_at,
            ),
        )

    @staticmethod
    def get_by_challenge_and_session(
        conn: sqlite3.Connection,
        challenge_id: str,
        session_id: str,
    ) -> Optional[WorkspaceRecord]:
        """Fetch WorkspaceRecord by (challenge_id, session_id)."""
        ensure_workspace_table(conn)
        row = conn.execute(
            """
            SELECT workspace_id, challenge_id, session_id, relative_root,
                   status, created_at, updated_at, expires_at
            FROM local_workspaces
            WHERE challenge_id = ? AND session_id = ?;
            """,
            (challenge_id, session_id),
        ).fetchone()

        if not row:
            return None

        return WorkspaceRecord(
            workspace_id=row["workspace_id"],
            challenge_id=row["challenge_id"],
            session_id=row["session_id"],
            relative_root=row["relative_root"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
        )

    @staticmethod
    def get_by_id(conn: sqlite3.Connection, workspace_id: str) -> Optional[WorkspaceRecord]:
        """Fetch WorkspaceRecord by workspace_id."""
        ensure_workspace_table(conn)
        row = conn.execute(
            """
            SELECT workspace_id, challenge_id, session_id, relative_root,
                   status, created_at, updated_at, expires_at
            FROM local_workspaces
            WHERE workspace_id = ?;
            """,
            (workspace_id,),
        ).fetchone()

        if not row:
            return None

        return WorkspaceRecord(
            workspace_id=row["workspace_id"],
            challenge_id=row["challenge_id"],
            session_id=row["session_id"],
            relative_root=row["relative_root"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
        )

    @staticmethod
    def update_status(
        conn: sqlite3.Connection,
        workspace_id: str,
        status: WorkspaceStatus | str,
    ) -> None:
        """Update workspace lifecycle status and updated_at timestamp."""
        ensure_workspace_table(conn)
        st_val = status.value if isinstance(status, WorkspaceStatus) else str(status)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE local_workspaces
            SET status = ?, updated_at = ?
            WHERE workspace_id = ?;
            """,
            (st_val, now_iso, workspace_id),
        )

    @staticmethod
    def sweep_expired(conn: sqlite3.Connection, now_iso: Optional[str] = None) -> int:
        """Update status to EXPIRED for READY workspaces where expires_at < now.

        Returns the count of swept workspaces.
        """
        ensure_workspace_table(conn)
        if now_iso is None:
            now_iso = datetime.now(timezone.utc).isoformat()

        cursor = conn.execute(
            """
            UPDATE local_workspaces
            SET status = 'EXPIRED', updated_at = ?
            WHERE status = 'READY'
              AND expires_at IS NOT NULL
              AND expires_at <= ?;
            """,
            (now_iso, now_iso),
        )
        return cursor.rowcount
