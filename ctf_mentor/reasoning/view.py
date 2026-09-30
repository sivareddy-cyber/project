"""
Immutable ReasoningView snapshot builder and input fingerprint generator.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ctf_mentor.domain.models import (
    Attempt,
    BlackboardState,
    Challenge,
    ChallengeClassification,
    Evidence,
    FailedAttempt,
    Hypothesis,
    HypothesisStatus,
    HintLevel,
)
from ctf_mentor.persistence.blackboard_repo import BlackboardRepository
from ctf_mentor.persistence.database import assert_foreign_keys_enabled
from ctf_mentor.persistence.intelligence_repo import IntelligenceReader
from ctf_mentor.reasoning.canonical import compute_result_hash
from ctf_mentor.reasoning.contracts import (
    HypothesisPrediction,
    HypothesisRelation,
    HypothesisRelationType,
    InvestigationLink,
    InvestigationLinkType,
    LinkStatus,
    PredictionStatus,
)


@dataclass(frozen=True)
class ReasoningView:
    """Immutable view containing the complete structured state snapshot for a challenge.

    The ReasoningEngine operates exclusively on this immutable view.
    """

    challenge_id: str
    challenge: Challenge
    blackboard: BlackboardState
    classification: Optional[ChallengeClassification]
    hypotheses: List[Hypothesis]
    evidence: List[Evidence]
    attempts: List[Attempt]
    failed_attempts: List[FailedAttempt]
    predictions: List[HypothesisPrediction]
    investigation_links: List[InvestigationLink]
    hypothesis_relations: List[HypothesisRelation]
    input_fingerprint: str


def _serialize_view_for_fingerprint(
    challenge: Challenge,
    blackboard: BlackboardState,
    classification: Optional[ChallengeClassification],
    hypotheses: List[Hypothesis],
    evidence: List[Evidence],
    attempts: List[Attempt],
    failed_attempts: List[FailedAttempt],
    predictions: List[HypothesisPrediction],
    investigation_links: List[InvestigationLink],
    hypothesis_relations: List[HypothesisRelation],
) -> Dict[str, Any]:
    return {
        "challenge_id": challenge.challenge_id,
        "blackboard_version": blackboard.blackboard_version,
        "active_hypothesis_ids": sorted(blackboard.active_hypothesis_ids),
        "watchlist_hypothesis_ids": sorted(blackboard.watchlist_hypothesis_ids),
        "classification": {
            "category": classification.category,
            "confidence": classification.confidence,
            "signals": sorted(classification.signals),
        }
        if classification
        else None,
        "hypotheses": [
            {
                "id": h.hypothesis_id,
                "title": h.title,
                "status": h.status.value,
                "confidence": h.confidence,
                "hint_level": h.hint_level.value,
            }
            for h in sorted(hypotheses, key=lambda x: x.hypothesis_id)
        ],
        "evidence": [
            {
                "id": e.evidence_id,
                "hypothesis_id": e.hypothesis_id,
                "source": e.source,
                "content": e.content,
                "type": e.evidence_type,
            }
            for e in sorted(evidence, key=lambda x: x.evidence_id)
        ],
        "attempts": [
            {
                "id": a.attempt_id,
                "hypothesis_id": a.hypothesis_id,
                "outcome": a.outcome,
                "description": a.description,
            }
            for a in sorted(attempts, key=lambda x: x.attempt_id)
        ],
        "failed_attempts": [
            {
                "id": fa.failed_attempt_id,
                "hypothesis_id": fa.hypothesis_id,
                "target": fa.target,
            }
            for fa in sorted(failed_attempts, key=lambda x: x.failed_attempt_id)
        ],
        "predictions": [
            {
                "id": p.prediction_id,
                "hypothesis_id": p.hypothesis_id,
                "status": p.status.value,
            }
            for p in sorted(predictions, key=lambda x: x.prediction_id)
        ],
        "links": [
            {
                "id": l.link_id,
                "source_id": l.source_id,
                "target_id": l.target_id,
                "relation_type": l.relation_type.value,
                "weight": l.weight,
                "status": l.status.value,
            }
            for l in sorted(investigation_links, key=lambda x: x.link_id)
        ],
        "relations": [
            {
                "id": r.relation_id,
                "source_hypothesis_id": r.source_hypothesis_id,
                "target_hypothesis_id": r.target_hypothesis_id,
                "relation_type": r.relation_type.value,
                "status": r.status.value,
            }
            for r in sorted(hypothesis_relations, key=lambda x: x.relation_id)
        ],
    }


def build_reasoning_view(conn: sqlite3.Connection, challenge_id: str) -> ReasoningView:
    """Load all relevant state for challenge_id and build an immutable ReasoningView."""
    assert_foreign_keys_enabled(conn)
    conn.row_factory = sqlite3.Row
    reader = IntelligenceReader(conn)
    bb_repo = BlackboardRepository(conn)

    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT challenge_id, name, description, category, global_hint_level,
               is_active, tags, metadata, created_at, updated_at
        FROM challenges WHERE challenge_id = ?
        """,
        (challenge_id,),
    )
    r_ch = cursor.fetchone()
    if not r_ch:
        raise ValueError(f"Challenge {challenge_id!r} not found")

    challenge = Challenge(
        challenge_id=r_ch["challenge_id"],
        name=r_ch["name"],
        description=r_ch["description"],
        category=r_ch["category"],
        global_hint_level=HintLevel(r_ch["global_hint_level"]),
        is_active=bool(r_ch["is_active"]),
        tags=json.loads(r_ch["tags"]) if r_ch["tags"] else [],
        metadata=json.loads(r_ch["metadata"]) if r_ch["metadata"] else {},
        created_at=datetime.fromisoformat(r_ch["created_at"]),
        updated_at=datetime.fromisoformat(r_ch["updated_at"]),
    )

    bb_state = bb_repo.read_blackboard_state(challenge_id)
    classification = reader.get_latest_classification(challenge_id)
    hypotheses = reader.get_hypotheses(challenge_id)

    # Read Evidence
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT evidence_id, challenge_id, hypothesis_id, source, content, evidence_type,
               created_at, created_by, is_fabricated, metadata
        FROM evidence WHERE challenge_id = ?
        ORDER BY created_at ASC
        """,
        (challenge_id,),
    )
    evidence_list = []
    for r in cursor.fetchall():
        evidence_list.append(
            Evidence(
                evidence_id=r["evidence_id"],
                challenge_id=r["challenge_id"],
                hypothesis_id=r["hypothesis_id"],
                source=r["source"],
                content=r["content"],
                evidence_type=r["evidence_type"],
                created_at=datetime.fromisoformat(r["created_at"]),
                created_by=r["created_by"],
                is_fabricated=bool(r["is_fabricated"]),
                metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            )
        )

    # Read Attempts
    cursor.execute(
        """
        SELECT attempt_id, challenge_id, hypothesis_id, description, outcome,
               user_input, tool_output, metadata, created_at
        FROM attempts WHERE challenge_id = ?
        ORDER BY created_at ASC
        """,
        (challenge_id,),
    )
    attempt_list = []
    for r in cursor.fetchall():
        attempt_list.append(
            Attempt(
                attempt_id=r["attempt_id"],
                challenge_id=r["challenge_id"],
                hypothesis_id=r["hypothesis_id"],
                description=r["description"],
                outcome=r["outcome"],
                created_at=datetime.fromisoformat(r["created_at"]),
                user_input=r["user_input"],
                tool_output=r["tool_output"],
                metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            )
        )

    # Read FailedAttempts
    cursor.execute(
        """
        SELECT failed_attempt_id, challenge_id, hypothesis_id, attempt_id, target,
               description, do_not_repeat_unless, metadata, failed_at
        FROM failed_attempts WHERE challenge_id = ?
        ORDER BY failed_at ASC
        """,
        (challenge_id,),
    )
    failed_attempt_list = []
    for r in cursor.fetchall():
        failed_attempt_list.append(
            FailedAttempt(
                failed_attempt_id=r["failed_attempt_id"],
                challenge_id=r["challenge_id"],
                hypothesis_id=r["hypothesis_id"],
                attempt_id=r["attempt_id"],
                target=r["target"],
                description=r["description"],
                do_not_repeat_unless=r["do_not_repeat_unless"],
                metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                failed_at=datetime.fromisoformat(r["failed_at"]),
            )
        )

    # Read Predictions
    predictions: List[HypothesisPrediction] = []
    try:
        cursor.execute(
            """
            SELECT prediction_id, challenge_id, hypothesis_id, description,
                   expected_observation, status, created_at, superseded_by, metadata
            FROM hypothesis_predictions WHERE challenge_id = ?
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        for r in cursor.fetchall():
            predictions.append(
                HypothesisPrediction(
                    prediction_id=r["prediction_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    description=r["description"],
                    expected_observation=r["expected_observation"],
                    status=PredictionStatus(r["status"]),
                    created_at=datetime.fromisoformat(r["created_at"]),
                    superseded_by=r["superseded_by"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                )
            )
    except sqlite3.OperationalError:
        pass  # Schema v4 table check fallback

    # Read InvestigationLinks
    investigation_links: List[InvestigationLink] = []
    try:
        cursor.execute(
            """
            SELECT link_id, challenge_id, source_id, source_type, target_id, target_type,
                   relation_type, independence_group, weight, status, created_at, superseded_by, metadata
            FROM investigation_links WHERE challenge_id = ? AND status = 'active'
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        for r in cursor.fetchall():
            investigation_links.append(
                InvestigationLink(
                    link_id=r["link_id"],
                    challenge_id=r["challenge_id"],
                    source_id=r["source_id"],
                    source_type=r["source_type"],
                    target_id=r["target_id"],
                    target_type=r["target_type"],
                    relation_type=InvestigationLinkType(r["relation_type"]),
                    independence_group=r["independence_group"] or "",
                    weight=r["weight"],
                    status=LinkStatus(r["status"]),
                    created_at=datetime.fromisoformat(r["created_at"]) if r["created_at"] else None,
                    superseded_by=r["superseded_by"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                )
            )
    except sqlite3.OperationalError:
        pass

    # Read HypothesisRelations
    hypothesis_relations: List[HypothesisRelation] = []
    try:
        cursor.execute(
            """
            SELECT relation_id, challenge_id, source_hypothesis_id, target_hypothesis_id,
                   relation_type, discriminating_criteria, status, created_at, superseded_by, metadata
            FROM hypothesis_relations WHERE challenge_id = ? AND status = 'active'
            ORDER BY created_at ASC
            """,
            (challenge_id,),
        )
        for r in cursor.fetchall():
            hypothesis_relations.append(
                HypothesisRelation(
                    relation_id=r["relation_id"],
                    challenge_id=r["challenge_id"],
                    source_hypothesis_id=r["source_hypothesis_id"],
                    target_hypothesis_id=r["target_hypothesis_id"],
                    relation_type=HypothesisRelationType(r["relation_type"]),
                    discriminating_criteria=r["discriminating_criteria"] or "",
                    status=LinkStatus(r["status"]),
                    created_at=datetime.fromisoformat(r["created_at"]) if r["created_at"] else None,
                    superseded_by=r["superseded_by"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                )
            )
    except sqlite3.OperationalError:
        pass

    serialized = _serialize_view_for_fingerprint(
        challenge=challenge,
        blackboard=bb_state,
        classification=classification,
        hypotheses=hypotheses,
        evidence=evidence_list,
        attempts=attempt_list,
        failed_attempts=failed_attempt_list,
        predictions=predictions,
        investigation_links=investigation_links,
        hypothesis_relations=hypothesis_relations,
    )
    fingerprint = compute_result_hash(serialized)

    return ReasoningView(
        challenge_id=challenge_id,
        challenge=challenge,
        blackboard=bb_state,
        classification=classification,
        hypotheses=hypotheses,
        evidence=evidence_list,
        attempts=attempt_list,
        failed_attempts=failed_attempt_list,
        predictions=predictions,
        investigation_links=investigation_links,
        hypothesis_relations=hypothesis_relations,
        input_fingerprint=fingerprint,
    )
