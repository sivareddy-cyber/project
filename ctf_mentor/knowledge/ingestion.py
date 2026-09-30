"""
Knowledge Ingestion Pipeline for Phase 5F Educational Knowledge Base.

LOCKED ARCHITECTURE INVARIANTS:
1. Ingestion is strictly offline/admin curated (Web / API Security).
2. Knowledge chunks are immutable and traceable by content_hash.
3. Source update creates a new version.
4. Runtime user/challenge state NEVER writes to the knowledge corpus.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.knowledge.contracts import KnowledgeChunk, KnowledgeSource


class KnowledgeIngestionService:
    """Ingests offline curated educational material into SQLite knowledge tables."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self.conn = db_conn

    def ingest_source(
        self,
        source_id: str,
        name: str,
        source_version: str,
        category: str,
        trust_tier: str,
        raw_chunks: List[Dict[str, Any]],
        challenge_id: Optional[str] = None,
    ) -> KnowledgeSource:
        """Ingest a knowledge source and its educational chunks atomically."""
        if not source_id or not name or not source_version:
            raise ValueError("source_id, name, and source_version are required")

        if category != "web" and not category.startswith("web_"):
            raise ValueError(f"Phase 5F scope limited to Web / API Security; category {category!r} invalid")

        now_str = datetime.now(timezone.utc).isoformat()
        source = KnowledgeSource(
            source_id=source_id,
            name=name,
            source_version=source_version,
            category=category,
            trust_tier=trust_tier,
            created_at=datetime.fromisoformat(now_str),
        )

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Insert or ignore knowledge source
            self.conn.execute(
                """
                INSERT INTO knowledge_sources (
                    source_id, name, source_version, category, trust_tier, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id, source_version) DO UPDATE SET
                    name = excluded.name,
                    trust_tier = excluded.trust_tier
                """,
                (source_id, name, source_version, category, trust_tier, now_str),
            )

            # 2. Insert chunks with strict immutability checks (Fix F-C)
            for item in raw_chunks:
                content = item["content"]
                content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                chunk_id = item.get("chunk_id") or f"chk_{hashlib.sha256((source_id + source_version + content_hash).encode('utf-8')).hexdigest()[:16]}"
                technique = item.get("technique", "general")
                hint_floor = HintLevel(item.get("hint_level_floor", 1))
                allowed_use = item.get("allowed_use", "education_only")

                existing = self.conn.execute(
                    "SELECT content, hint_level_floor FROM knowledge_chunks WHERE chunk_id = ?",
                    (chunk_id,),
                ).fetchone()

                if existing:
                    if existing["content"] != content or existing["hint_level_floor"] != hint_floor.value:
                        raise ValueError(f"KnowledgeChunk '{chunk_id}' already exists and is immutable")
                else:
                    self.conn.execute(
                        """
                        INSERT INTO knowledge_chunks (
                            chunk_id, source_id, source_version, content, content_hash,
                            category, technique, trust_tier, hint_level_floor, allowed_use, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            chunk_id,
                            source_id,
                            source_version,
                            content,
                            content_hash,
                            category,
                            technique,
                            trust_tier,
                            hint_floor.value,
                            allowed_use,
                            now_str,
                        ),
                    )

            # 3. Emit KnowledgeSourceIngested Event ONLY for explicitly supplied challenge_id (Fix F-D)
            if challenge_id:
                ch_check = self.conn.execute("SELECT challenge_id FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
                if ch_check:
                    event_id = str(uuid.uuid4())
                    event_payload = json_dumps({
                        "source_id": source_id,
                        "source_version": source_version,
                        "category": category,
                        "chunk_count": len(raw_chunks),
                    })
                    self.conn.execute(
                        """
                        INSERT INTO events (
                            event_id, challenge_id, event_type, actor, payload, occurred_at, metadata
                        ) VALUES (?, ?, 'KnowledgeSourceIngested', 'knowledge_ingestion_service', ?, ?, '{}')
                        """,
                        (event_id, challenge_id, event_payload, now_str),
                    )

            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

        return source


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj)
