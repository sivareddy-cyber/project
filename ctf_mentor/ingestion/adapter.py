"""
Challenge Ingestion Adapter for Phase 9 AI CTF Copilot.

LOCKED INVARIANTS:
1. Zero Outbound Network Access before explicit human approval. URLs are treated strictly as string DATA.
2. Observations are provenance-tracked, staged, and UNTRUSTED.
3. Zero automatic promotion of ingested content into approvals, Solve Mode switches, or evidence.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ctf_mentor.ingestion.models import IngestionObservation, SourceType, TrustLevel
from ctf_mentor.ingestion.parser import SafeArtifactParser
from ctf_mentor.persistence.database import assert_foreign_keys_enabled


def _ensure_ingestion_tables(conn: sqlite3.Connection) -> None:
    """Ensure copilot_sessions and ingestion_observations tables exist (schema v2 migration)."""
    assert_foreign_keys_enabled(conn)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS copilot_sessions (
            copilot_session_id        TEXT PRIMARY KEY,
            challenge_id              TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            investigation_session_id  TEXT REFERENCES investigation_sessions(session_id) ON DELETE SET NULL,
            mode                      TEXT NOT NULL DEFAULT 'MENTOR',
            created_at                TEXT NOT NULL,
            updated_at                TEXT NOT NULL,
            metadata                  TEXT NOT NULL DEFAULT '{}',
            CHECK (mode IN ('MENTOR', 'SOLVE'))
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ingestion_observations (
            observation_id       TEXT PRIMARY KEY,
            challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            copilot_session_id   TEXT REFERENCES copilot_sessions(copilot_session_id) ON DELETE CASCADE,
            source_type          TEXT NOT NULL,
            source_reference     TEXT NOT NULL,
            content_summary      TEXT NOT NULL,
            trust_level          TEXT NOT NULL DEFAULT 'UNTRUSTED',
            provenance_json      TEXT NOT NULL DEFAULT '{}',
            created_at           TEXT NOT NULL,
            CHECK (source_type IN ('CHALLENGE_URL', 'CHALLENGE_TEXT', 'ARTIFACT_FILE')),
            CHECK (trust_level IN ('UNTRUSTED', 'PROVENANCE_STAGED'))
        );
        """
    )
    conn.commit()


class ChallengeIngestionAdapter:
    """Ingestion boundary for CTF challenge materials."""

    def __init__(self, db_conn: sqlite3.Connection, parser: Optional[SafeArtifactParser] = None) -> None:
        self.conn = db_conn
        _ensure_ingestion_tables(self.conn)
        self.parser = parser or SafeArtifactParser()

    def ingest_challenge_url(
        self,
        challenge_id: str,
        url_string: str,
        copilot_session_id: Optional[str] = None,
    ) -> IngestionObservation:
        """Ingest a target challenge URL purely as text DATA.
        
        CRITICAL: ZERO OUTBOUND NETWORK ACCESS.
        No HTTP requests, DNS lookups, TLS handshakes, or url previews are performed.
        """
        parsed = urlparse(url_string.strip())
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid challenge URL syntax: {url_string!r}")

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported URL scheme {scheme!r}. Must be http or https.")

        obs_id = f"obs_url_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)

        provenance = {
            "parsed_scheme": scheme,
            "parsed_hostname": parsed.hostname,
            "parsed_port": parsed.port or (443 if scheme == "https" else 80),
            "parsed_path": parsed.path or "/",
            "network_status": "DATA_ONLY_ZERO_NETWORK",
        }

        obs = IngestionObservation(
            observation_id=obs_id,
            challenge_id=challenge_id,
            copilot_session_id=copilot_session_id,
            source_type=SourceType.CHALLENGE_URL,
            source_reference=url_string,
            content_summary=f"Ingested challenge target URL ({scheme}://{parsed.netloc})",
            trust_level=TrustLevel.UNTRUSTED,
            provenance=provenance,
            created_at=now,
        )

        self._save_observation(obs)
        return obs

    def ingest_challenge_text(
        self,
        challenge_id: str,
        text_content: str,
        title: str = "Challenge Description",
        copilot_session_id: Optional[str] = None,
    ) -> IngestionObservation:
        """Ingest raw challenge text/description."""
        if not text_content or not text_content.strip():
            raise ValueError("Challenge text content cannot be empty.")

        obs_id = f"obs_txt_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)

        summary = text_content.strip()[:300] + ("..." if len(text_content.strip()) > 300 else "")

        provenance = {
            "title": title,
            "char_count": len(text_content),
            "line_count": len(text_content.splitlines()),
        }

        obs = IngestionObservation(
            observation_id=obs_id,
            challenge_id=challenge_id,
            copilot_session_id=copilot_session_id,
            source_type=SourceType.CHALLENGE_TEXT,
            source_reference=title,
            content_summary=summary,
            trust_level=TrustLevel.UNTRUSTED,
            provenance=provenance,
            created_at=now,
        )

        self._save_observation(obs)
        return obs

    def ingest_artifact_file(
        self,
        challenge_id: str,
        file_path: Path,
        filename: str,
        copilot_session_id: Optional[str] = None,
    ) -> IngestionObservation:
        """Parse and ingest uploaded challenge artifact file using SafeArtifactParser."""
        resolved_scratch = self.parser.scratch_dir.resolve()
        resolved_file = file_path.resolve()
        if resolved_file == resolved_scratch or resolved_scratch not in resolved_file.parents:
            raise ValueError(
                f"Filesystem confinement violation: file_path {file_path!r} (resolved: {resolved_file}) is outside allowed scratch_dir {resolved_scratch}."
            )

        parse_result = self.parser.parse_artifact(file_path, filename)

        obs_id = f"obs_file_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)

        provenance = {
            "file_size": parse_result["size_bytes"],
            "sha256": parse_result["sha256"],
            "md5": parse_result["md5"],
            "is_binary": parse_result["is_binary"],
            "archive_info": parse_result.get("archive_info"),
        }

        obs = IngestionObservation(
            observation_id=obs_id,
            challenge_id=challenge_id,
            copilot_session_id=copilot_session_id,
            source_type=SourceType.ARTIFACT_FILE,
            source_reference=filename,
            content_summary=parse_result["preview_text"],
            trust_level=TrustLevel.UNTRUSTED,
            provenance=provenance,
            created_at=now,
        )

        self._save_observation(obs)
        return obs

    def get_observations(self, challenge_id: str) -> List[IngestionObservation]:
        """Fetch all observations for a challenge."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT observation_id, challenge_id, copilot_session_id, source_type,
                   source_reference, content_summary, trust_level, provenance_json, created_at
            FROM ingestion_observations
            WHERE challenge_id = ?
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        rows = cursor.fetchall()

        obs_list = []
        for r in rows:
            obs_list.append(
                IngestionObservation(
                    observation_id=r[0],
                    challenge_id=r[1],
                    copilot_session_id=r[2],
                    source_type=SourceType(r[3]),
                    source_reference=r[4],
                    content_summary=r[5],
                    trust_level=TrustLevel(r[6]),
                    provenance=json.loads(r[7]) if r[7] else {},
                    created_at=datetime.datetime.fromisoformat(r[8]),
                )
            )
        return obs_list

    def _save_observation(self, obs: IngestionObservation) -> None:
        """Persist IngestionObservation to database."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO ingestion_observations (
                observation_id, challenge_id, copilot_session_id, source_type,
                source_reference, content_summary, trust_level, provenance_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                obs.observation_id,
                obs.challenge_id,
                obs.copilot_session_id,
                obs.source_type.value,
                obs.source_reference,
                obs.content_summary,
                obs.trust_level.value,
                json.dumps(obs.provenance),
                obs.created_at.isoformat(),
            ),
        )
        self.conn.commit()
