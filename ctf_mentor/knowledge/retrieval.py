"""
Challenge-Aware Retrieval Service for Phase 5F Educational Knowledge Base.

LOCKED ARCHITECTURE INVARIANTS:
1. Enforces structural hint-level gating BEFORE results reach the LLM:
   chunk.hint_level_floor <= requested_hint_level.
2. Uses deterministic score calculation and tie-breaking (order by score DESC, chunk_id ASC).
3. Traceable provenance for every retrieved chunk.
4. Cross-challenge isolation: Retrieval query uses structured state, never cross-challenge secrets.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import HintLevel
from ctf_mentor.knowledge.contracts import KnowledgeChunk, RetrievalRequest, RetrievalResult
from ctf_mentor.knowledge.provenance import build_result_provenance


class RetrievalService:
    """Challenge-aware knowledge retrieval service with structural hint-level gating."""

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self.conn = db_conn

    def retrieve(self, request: RetrievalRequest) -> RetrievalResult:
        if not request.challenge_id:
            raise ValueError("RetrievalRequest.challenge_id is required")

        req_level_val = request.requested_hint_level.value

        # CRITICAL STRUCTURAL GATING: chunk.hint_level_floor <= request.requested_hint_level
        query = """
            SELECT chunk_id, source_id, source_version, content, content_hash,
                   category, technique, trust_tier, hint_level_floor, allowed_use, created_at
            FROM knowledge_chunks
            WHERE category = ?
            AND hint_level_floor <= ?
        """
        params: List[Any] = [request.category, req_level_val]

        if request.technique:
            query += " AND technique = ?"
            params.append(request.technique)

        rows = self.conn.execute(query, params).fetchall()

        matched_chunks: List[KnowledgeChunk] = []
        scores: List[float] = []

        for r in rows:
            chunk = KnowledgeChunk(
                chunk_id=r["chunk_id"],
                source_id=r["source_id"],
                source_version=r["source_version"],
                content=r["content"],
                content_hash=r["content_hash"],
                category=r["category"],
                technique=r["technique"],
                trust_tier=r["trust_tier"],
                hint_level_floor=HintLevel(r["hint_level_floor"]),
                allowed_use=r["allowed_use"],
                created_at=datetime.fromisoformat(r["created_at"]),
            )

            # Compute score based on category & technique match + trust tier
            base_score = 0.5
            if request.technique and chunk.technique == request.technique:
                base_score += 0.4
            if chunk.trust_tier == "curated_official":
                base_score += 0.1

            matched_chunks.append(chunk)
            scores.append(round(base_score, 4))

        # Deterministic sorting: score DESC, chunk_id ASC
        zipped = list(zip(matched_chunks, scores))
        zipped.sort(key=lambda x: (-x[1], x[0].chunk_id))

        top_pairs = zipped[: request.top_k]
        final_chunks = [p[0] for p in top_pairs]
        final_scores = [p[1] for p in top_pairs]

        provenance = build_result_provenance(final_chunks)

        return RetrievalResult(
            challenge_id=request.challenge_id,
            requested_hint_level=request.requested_hint_level,
            chunks=final_chunks,
            scores=final_scores,
            provenance_records=provenance,
        )
