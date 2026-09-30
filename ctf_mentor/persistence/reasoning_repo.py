"""
ReasoningRepository for Phase 5E Deterministic Reasoning Foundation.

INVARIANTS:
1. Performs MANDATORY REPLAY VERIFICATION before committing any ReasoningResult.
2. Persists ReasoningRun, HypothesisAssessments, and ReasoningRunRecorded Event atomically.
3. Enforces append-only storage, supersession semantics, and strict cross-challenge integrity.
4. Same-fingerprint reasoning submissions deduplicate to existing authoritative run.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ctf_mentor.contracts import StaleVersionError
from ctf_mentor.persistence.database import assert_foreign_keys_enabled
from ctf_mentor.reasoning.canonical import canonicalize_json
from ctf_mentor.reasoning.contracts import (
    HypothesisPosture,
    HypothesisPrediction,
    HypothesisRelation,
    HypothesisRelationType,
    InvestigationLink,
    InvestigationLinkType,
    LinkStatus,
    PredictionStatus,
    ReasoningAssessment,
    ReasoningResult,
    ReasoningRun,
    ReasoningRunStatus,
)
from ctf_mentor.reasoning.engine import ReasoningEngine
from ctf_mentor.reasoning.view import build_reasoning_view

logger = logging.getLogger(__name__)


class ReasoningRepository:
    """Authoritative persistence repository for Phase 5E Reasoning state."""

    def __init__(self, conn: sqlite3.Connection, engine: Optional[ReasoningEngine] = None) -> None:
        assert_foreign_keys_enabled(conn)
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.engine = engine or ReasoningEngine()

    def record_reasoning_result_atomic(
        self,
        candidate_result: ReasoningResult,
        task_id: Optional[str] = None,
        actor: str = "reasoning_engine",
    ) -> ReasoningRun:
        """Persist a ReasoningResult atomically after mandatory Replay Verification.

        REPLAY VERIFICATION GATE:
        1. Load fresh ReasoningView for challenge_id.
        2. Check current input_fingerprint matches candidate_result.input_fingerprint.
        3. Re-run ReasoningEngine on fresh view.
        4. Check computed result_hash matches candidate_result.result_hash.
        5. If replay check fails or state changed, ABORT and raise StaleVersionError / ValueError.
        6. Same-fingerprint deduplication: If identical run exists, return existing run (race-safe).
        """
        assert_foreign_keys_enabled(self.conn)
        challenge_id = candidate_result.challenge_id

        # Step 1 & 2: Load fresh view and verify fingerprint
        fresh_view = build_reasoning_view(self.conn, challenge_id)
        if fresh_view.input_fingerprint != candidate_result.input_fingerprint:
            raise StaleVersionError(
                challenge_id=challenge_id,
                expected=int(candidate_result.input_fingerprint[:8], 16),
                found=int(fresh_view.input_fingerprint[:8], 16),
            )

        # Step 3 & 4: Re-run engine and verify Hash parity
        recomputed = self.engine.analyze(fresh_view, run_sequence=candidate_result.run_sequence)
        if recomputed.result_hash != candidate_result.result_hash:
            raise ValueError(
                f"Replay verification failed for challenge {challenge_id!r}: "
                f"candidate hash {candidate_result.result_hash!r} != recomputed hash {recomputed.result_hash!r}"
            )

        # Deduplication check: return existing run if identical completed run exists
        existing_run = self.get_run_by_fingerprint_and_hash(
            challenge_id=challenge_id,
            input_fingerprint=fresh_view.input_fingerprint,
            ruleset_version=recomputed.ruleset_version,
            result_hash=recomputed.result_hash,
        )
        if existing_run:
            logger.info("Found existing identical reasoning run %s; returning dedup record.", existing_run.run_id)
            return existing_run

        now_str = datetime.now(timezone.utc).isoformat()
        canonical_str = canonicalize_json(recomputed.canonical_dict)

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # Check next sequence
            seq_row = self.conn.execute(
                "SELECT COALESCE(MAX(run_sequence), 0) + 1 FROM reasoning_runs WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            run_sequence = seq_row[0] if seq_row else 1

            run_id = f"run_{candidate_result.result_hash[:12]}_{run_sequence}"

            # Insert reasoning_runs record (Immutable - NO UPDATE statement on old records!)
            try:
                self.conn.execute(
                    """
                    INSERT INTO reasoning_runs (
                        run_id, challenge_id, run_sequence, input_fingerprint, ruleset_version,
                        canonical_result, result_hash, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?)
                    """,
                    (
                        run_id,
                        challenge_id,
                        run_sequence,
                        fresh_view.input_fingerprint,
                        recomputed.ruleset_version,
                        canonical_str,
                        recomputed.result_hash,
                        now_str,
                    ),
                )
            except sqlite3.IntegrityError:
                # Concurrent race condition: matching dedup record inserted by another thread/tx
                self.conn.execute("ROLLBACK;")
                existing_run = self.get_run_by_fingerprint_and_hash(
                    challenge_id=challenge_id,
                    input_fingerprint=fresh_view.input_fingerprint,
                    ruleset_version=recomputed.ruleset_version,
                    result_hash=recomputed.result_hash,
                )
                if existing_run:
                    return existing_run
                raise

            # Insert assessments
            for asmt in recomputed.assessments:
                assessment_id = f"asmt_{uuid.uuid4().hex[:12]}"
                self.conn.execute(
                    """
                    INSERT INTO hypothesis_assessments (
                        assessment_id, run_id, challenge_id, hypothesis_id, posture,
                        support_strength, contradiction_strength, evidence_quality,
                        evidence_coverage, is_confirmation_eligible, assessment_data, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        run_id,
                        challenge_id,
                        asmt.hypothesis_id,
                        asmt.posture.value,
                        asmt.support_strength,
                        asmt.contradiction_strength,
                        asmt.evidence_quality,
                        asmt.evidence_coverage,
                        1 if asmt.is_confirmation_eligible else 0,
                        json.dumps(asmt.assessment_data),
                        now_str,
                    ),
                )

            # Atomically insert Event into events table (blackboard_version_after = NULL)
            event_id = str(uuid.uuid4())
            event_payload = {
                "challenge_id": challenge_id,
                "run_id": run_id,
                "run_sequence": run_sequence,
                "result_hash": recomputed.result_hash,
                "assessments_count": len(recomputed.assessments),
                "proposals_count": len(recomputed.proposals),
            }
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, blackboard_version_after
                ) VALUES (?, ?, 'ReasoningRunRecorded', ?, ?, ?, NULL)
                """,
                (event_id, challenge_id, actor, json.dumps(event_payload), now_str),
            )

            self.conn.execute("COMMIT;")

            return ReasoningRun(
                run_id=run_id,
                challenge_id=challenge_id,
                run_sequence=run_sequence,
                input_fingerprint=fresh_view.input_fingerprint,
                ruleset_version=recomputed.ruleset_version,
                canonical_result=canonical_str,
                result_hash=recomputed.result_hash,
                status=ReasoningRunStatus.COMPLETED,
                created_at=datetime.fromisoformat(now_str),
            )
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def get_run_by_fingerprint_and_hash(
        self, challenge_id: str, input_fingerprint: str, ruleset_version: str, result_hash: str
    ) -> Optional[ReasoningRun]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT run_id, challenge_id, run_sequence, input_fingerprint, ruleset_version,
                   canonical_result, result_hash, status, created_at
            FROM reasoning_runs
            WHERE challenge_id = ? AND input_fingerprint = ? AND ruleset_version = ? AND result_hash = ?
            ORDER BY run_sequence ASC LIMIT 1
            """,
            (challenge_id, input_fingerprint, ruleset_version, result_hash),
        )
        r = cursor.fetchone()
        if not r:
            return None
        return ReasoningRun(
            run_id=r["run_id"],
            challenge_id=r["challenge_id"],
            run_sequence=r["run_sequence"],
            input_fingerprint=r["input_fingerprint"],
            ruleset_version=r["ruleset_version"],
            canonical_result=r["canonical_result"],
            result_hash=r["result_hash"],
            status=ReasoningRunStatus(r["status"]),
            created_at=datetime.fromisoformat(r["created_at"]),
        )

    def get_latest_reasoning_run(self, challenge_id: str) -> Optional[ReasoningRun]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT run_id, challenge_id, run_sequence, input_fingerprint, ruleset_version,
                   canonical_result, result_hash, status, created_at
            FROM reasoning_runs
            WHERE challenge_id = ? AND status = 'completed'
            ORDER BY run_sequence DESC LIMIT 1
            """,
            (challenge_id,),
        )
        r = cursor.fetchone()
        if not r:
            return None
        return ReasoningRun(
            run_id=r["run_id"],
            challenge_id=r["challenge_id"],
            run_sequence=r["run_sequence"],
            input_fingerprint=r["input_fingerprint"],
            ruleset_version=r["ruleset_version"],
            canonical_result=r["canonical_result"],
            result_hash=r["result_hash"],
            status=ReasoningRunStatus(r["status"]),
            created_at=datetime.fromisoformat(r["created_at"]),
        )

    def get_assessments_for_run(self, run_id: str) -> List[ReasoningAssessment]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT assessment_id, run_id, challenge_id, hypothesis_id, posture,
                   support_strength, contradiction_strength, evidence_quality,
                   evidence_coverage, is_confirmation_eligible, assessment_data, created_at
            FROM hypothesis_assessments
            WHERE run_id = ?
            ORDER BY hypothesis_id ASC
            """,
            (run_id,),
        )
        results = []
        for r in cursor.fetchall():
            results.append(
                ReasoningAssessment(
                    assessment_id=r["assessment_id"],
                    run_id=r["run_id"],
                    challenge_id=r["challenge_id"],
                    hypothesis_id=r["hypothesis_id"],
                    posture=HypothesisPosture(r["posture"]),
                    support_strength=r["support_strength"],
                    contradiction_strength=r["contradiction_strength"],
                    evidence_quality=r["evidence_quality"],
                    evidence_coverage=r["evidence_coverage"],
                    is_confirmation_eligible=bool(r["is_confirmation_eligible"]),
                    created_at=datetime.fromisoformat(r["created_at"]),
                    assessment_data=json.loads(r["assessment_data"]) if r["assessment_data"] else {},
                )
            )
        return results

    def record_prediction(self, prediction: HypothesisPrediction) -> None:
        assert_foreign_keys_enabled(self.conn)

        # Cross-challenge validation: hypothesis must exist and belong to prediction.challenge_id
        hyp_row = self.conn.execute(
            "SELECT challenge_id FROM hypotheses WHERE hypothesis_id = ?",
            (prediction.hypothesis_id,),
        ).fetchone()
        if not hyp_row:
            raise ValueError(f"Target hypothesis {prediction.hypothesis_id!r} does not exist.")
        if hyp_row["challenge_id"] != prediction.challenge_id:
            raise ValueError(
                f"Cross-challenge violation: hypothesis {prediction.hypothesis_id!r} "
                f"belongs to challenge {hyp_row['challenge_id']!r}, not {prediction.challenge_id!r}."
            )

        now_str = prediction.created_at.isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute(
                """
                INSERT INTO hypothesis_predictions (
                    prediction_id, challenge_id, hypothesis_id, description,
                    expected_observation, status, metadata, created_at, superseded_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    prediction.prediction_id,
                    prediction.challenge_id,
                    prediction.hypothesis_id,
                    prediction.description,
                    prediction.expected_observation,
                    prediction.status.value,
                    json.dumps(prediction.metadata),
                    now_str,
                    prediction.superseded_by,
                ),
            )
            # Emit Event
            event_id = str(uuid.uuid4())
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, blackboard_version_after
                ) VALUES (?, ?, 'PredictionRecorded', 'system', ?, ?, NULL)
                """,
                (
                    event_id,
                    prediction.challenge_id,
                    json.dumps({"prediction_id": prediction.prediction_id, "hypothesis_id": prediction.hypothesis_id}),
                    now_str,
                ),
            )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def record_investigation_link(self, link: InvestigationLink) -> None:
        assert_foreign_keys_enabled(self.conn)

        valid_sources = {"evidence": "evidence", "attempt": "attempts", "failed_attempt": "failed_attempts"}
        valid_targets = {"hypothesis": "hypotheses", "prediction": "hypothesis_predictions"}

        if link.source_type not in valid_sources:
            raise ValueError(f"Invalid source_type {link.source_type!r}. Must be one of {sorted(valid_sources)}")
        if link.target_type not in valid_targets:
            raise ValueError(f"Invalid target_type {link.target_type!r}. Must be one of {sorted(valid_targets)}")

        source_table = valid_sources[link.source_type]
        target_table = valid_targets[link.target_type]

        pk_col_source = f"{link.source_type}_id" if link.source_type != "failed_attempt" else "failed_attempt_id"
        pk_col_target = f"{link.target_type}_id"

        src_row = self.conn.execute(
            f"SELECT challenge_id FROM {source_table} WHERE {pk_col_source} = ?",
            (link.source_id,),
        ).fetchone()
        if not src_row:
            raise ValueError(f"Source entity {link.source_id!r} ({link.source_type}) does not exist.")
        if src_row["challenge_id"] != link.challenge_id:
            raise ValueError(
                f"Cross-challenge violation: source {link.source_id!r} belongs to challenge {src_row['challenge_id']!r}, not {link.challenge_id!r}."
            )

        tgt_row = self.conn.execute(
            f"SELECT challenge_id FROM {target_table} WHERE {pk_col_target} = ?",
            (link.target_id,),
        ).fetchone()
        if not tgt_row:
            raise ValueError(f"Target entity {link.target_id!r} ({link.target_type}) does not exist.")
        if tgt_row["challenge_id"] != link.challenge_id:
            raise ValueError(
                f"Cross-challenge violation: target {link.target_id!r} belongs to challenge {tgt_row['challenge_id']!r}, not {link.challenge_id!r}."
            )

        now_str = (link.created_at or datetime.now(timezone.utc)).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute(
                """
                INSERT INTO investigation_links (
                    link_id, challenge_id, source_id, source_type, target_id, target_type,
                    relation_type, independence_group, weight, status, metadata, created_at, superseded_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    link.link_id,
                    link.challenge_id,
                    link.source_id,
                    link.source_type,
                    link.target_id,
                    link.target_type,
                    link.relation_type.value,
                    link.independence_group,
                    link.weight,
                    link.status.value,
                    json.dumps(link.metadata),
                    now_str,
                    link.superseded_by,
                ),
            )
            event_id = str(uuid.uuid4())
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, blackboard_version_after
                ) VALUES (?, ?, 'InvestigationLinkRecorded', 'system', ?, ?, NULL)
                """,
                (
                    event_id,
                    link.challenge_id,
                    json.dumps({"link_id": link.link_id, "relation_type": link.relation_type.value}),
                    now_str,
                ),
            )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise

    def record_hypothesis_relation(self, relation: HypothesisRelation) -> None:
        assert_foreign_keys_enabled(self.conn)

        for hid_label, hid in [("source", relation.source_hypothesis_id), ("target", relation.target_hypothesis_id)]:
            r = self.conn.execute(
                "SELECT challenge_id FROM hypotheses WHERE hypothesis_id = ?",
                (hid,),
            ).fetchone()
            if not r:
                raise ValueError(f"Hypothesis {hid!r} ({hid_label}) does not exist.")
            if r["challenge_id"] != relation.challenge_id:
                raise ValueError(
                    f"Cross-challenge violation: hypothesis {hid!r} belongs to challenge {r['challenge_id']!r}, not {relation.challenge_id!r}."
                )

        now_str = (relation.created_at or datetime.now(timezone.utc)).isoformat()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute(
                """
                INSERT INTO hypothesis_relations (
                    relation_id, challenge_id, source_hypothesis_id, target_hypothesis_id,
                    relation_type, discriminating_criteria, status, metadata, created_at, superseded_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    relation.relation_id,
                    relation.challenge_id,
                    relation.source_hypothesis_id,
                    relation.target_hypothesis_id,
                    relation.relation_type.value,
                    relation.discriminating_criteria,
                    relation.status.value,
                    json.dumps(relation.metadata),
                    now_str,
                    relation.superseded_by,
                ),
            )
            event_id = str(uuid.uuid4())
            self.conn.execute(
                """
                INSERT INTO events (
                    event_id, challenge_id, event_type, actor, payload, occurred_at, blackboard_version_after
                ) VALUES (?, ?, 'HypothesisRelationRecorded', 'system', ?, ?, NULL)
                """,
                (
                    event_id,
                    relation.challenge_id,
                    json.dumps(
                        {
                            "relation_id": relation.relation_id,
                            "source_hypothesis_id": relation.source_hypothesis_id,
                            "target_hypothesis_id": relation.target_hypothesis_id,
                        }
                    ),
                    now_str,
                ),
            )
            self.conn.execute("COMMIT;")
        except Exception:
            self.conn.execute("ROLLBACK;")
            raise
