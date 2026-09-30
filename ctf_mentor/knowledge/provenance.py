"""
Provenance tracking helper for Phase 5F Knowledge Retrieval.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ctf_mentor.knowledge.contracts import KnowledgeChunk


def build_chunk_provenance(chunk: KnowledgeChunk) -> Dict[str, Any]:
    """Generate reproducible provenance tracking dict for a KnowledgeChunk."""
    return {
        "chunk_id": chunk.chunk_id,
        "source_id": chunk.source_id,
        "source_version": chunk.source_version,
        "content_hash": chunk.content_hash,
        "category": chunk.category,
        "technique": chunk.technique,
        "trust_tier": chunk.trust_tier,
        "hint_level_floor": chunk.hint_level_floor.value,
    }


def build_result_provenance(chunks: List[KnowledgeChunk]) -> List[Dict[str, Any]]:
    """Generate provenance list for multiple retrieved chunks."""
    return [build_chunk_provenance(c) for c in chunks]
