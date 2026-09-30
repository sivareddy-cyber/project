"""
Phase 5F Memory Subsystem.

LOCKED ARCHITECTURE INVARIANTS:
1. Session Memory is transient (in-memory per task).
2. Challenge Memory is strictly challenge_id scoped.
3. Long-Term Memory stores ONLY abstract educational concepts.
4. NEVER store flags, credentials, payloads, challenge solutions, or raw evidence in Long-Term Memory.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SessionMemory:
    """Transient session state for an active hint task."""

    task_id: str
    challenge_id: str
    transient_notes: List[str] = field(default_factory=list)


@dataclass
class ChallengeMemory:
    """Challenge-scoped memory tracking hints delivered and citations."""

    challenge_id: str
    delivered_hint_count: int = 0
    accessed_chunk_ids: List[str] = field(default_factory=list)


@dataclass
class AbstractLearningConcept:
    """Abstract skill/proficiency concept for long-term user mentoring."""

    concept_id: str
    category: str
    topic: str  # e.g., "http_cookies", "sql_syntax", "idor_concept"
    proficiency_score: float  # 0.0 to 1.0
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MentorMemoryService:
    """Manages Phase 5F memory isolation boundaries."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self.conn = db_conn
        self._session_store: Dict[str, SessionMemory] = {}

    def get_session_memory(self, task_id: str, challenge_id: str) -> SessionMemory:
        if task_id not in self._session_store:
            self._session_store[task_id] = SessionMemory(task_id=task_id, challenge_id=challenge_id)
        return self._session_store[task_id]

    def record_learning_concept(self, category: str, topic: str, proficiency: float) -> None:
        """Record an abstract educational concept in long-term memory."""
        # Sanity check: Ensure no secrets/flags in topic
        forbidden = ["flag", "ctf{", "password", "secret", "token", "key", "admin"]
        topic_lower = topic.lower()
        for f in forbidden:
            if f in topic_lower:
                raise ValueError(f"Forbidden sensitive term {f!r} in learning concept topic")

        concept_id = f"concept_{category}_{topic}"
        now_str = datetime.now(timezone.utc).isoformat()

        self.conn.execute(
            """
            INSERT INTO mentor_learning_concepts (
                concept_id, category, topic, proficiency_score, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(concept_id) DO UPDATE SET
                proficiency_score = excluded.proficiency_score,
                updated_at = excluded.updated_at
            """,
            (concept_id, category, topic, max(0.0, min(1.0, proficiency)), now_str),
        )

    def get_learning_concepts(self, category: Optional[str] = None) -> List[AbstractLearningConcept]:
        """Fetch abstract learning concepts."""
        query = "SELECT concept_id, category, topic, proficiency_score, updated_at FROM mentor_learning_concepts"
        params = []
        if category:
            query += " WHERE category = ?"
            params.append(category)

        rows = self.conn.execute(query, params).fetchall()
        return [
            AbstractLearningConcept(
                concept_id=r["concept_id"],
                category=r["category"],
                topic=r["topic"],
                proficiency_score=r["proficiency_score"],
                updated_at=datetime.fromisoformat(r["updated_at"]),
            )
            for r in rows
        ]
