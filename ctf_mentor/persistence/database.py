"""
Database initialization and connection management for CTF Mentor/Copilot.

Responsibilities:
- SQLite connection handling
- Schema initialization (idempotent / safe repeated calls)
- Foreign key enforcement
- WAL mode configuration
- Schema version tracking
- Deterministic, destructive-safe initialization

Rules:
- Does not silently destroy existing data.
- Foreign keys are always enforced.
- WAL is used for improved concurrency characteristics.
- Schema is version-tracked; older schemas can be upgraded.

SCHEMA_VERSION 2 changes (Phase 5B remediation):
- Added user_action_requests, user_action_results, approval_requests tables (M3)
- Added triggers to enforce event immutability: no UPDATE/DELETE on events (M1)
- Added UNIQUE constraint on (challenge_id, blackboard_version_after) in events (M1)
- Added self-reference prevention on task_dependencies (M4)
- Added UNIQUE constraint on task_dependencies (task_id, depends_on_task_id) (M4)
- Added CHECK on hint level range in hint_requests, hint_candidates, hint_decisions (M4)
- Added evidence cross-challenge FK to hypotheses via CHECK-friendly structure (M2)
- Added unique partial index: one active primary_target per challenge (H2)
- Added conflict_records FK referencing evidence table (M2)
- Removed challenges.blackboard_version as mutable field; version lives in
  blackboard_states only. challenges.blackboard_version is kept as a VIEW-like
  convenience column populated once at creation and NOT independently maintained (H4).
  The authoritative version is ALWAYS blackboard_states.blackboard_version.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)

# Increment when making backward-incompatible schema changes.
# SCHEMA_VERSION 3: Updated uq_tasks_dedup partial index to filter WHERE status IN ('queued', 'running').
# SCHEMA_VERSION 4: Added challenge_classifications append-only table for Phase 5D.
# SCHEMA_VERSION 5: Added hypothesis_predictions, investigation_links, hypothesis_relations, reasoning_runs, hypothesis_assessments for Phase 5E.
# SCHEMA_VERSION 6: Added knowledge_sources, knowledge_chunks, mentor_learning_concepts for Phase 5F.
# SCHEMA_VERSION 7: Added authorized_scope_entries, action_proposals, action_results for Phase 6.
# SCHEMA_VERSION 8: Added uq_evidence_idempotency_key index and 'confirming' status to action_proposals.
# SCHEMA_VERSION 9: Added investigation_sessions, investigation_steps tables, updated approval CHECK constraints for Phase 6A.
# SCHEMA_VERSION 10: Added investigation_results append-only table for durable InvestigationResult content persistence.
SCHEMA_VERSION: int = 10

_DDL_PHASE5E_ADDED = """
CREATE TABLE IF NOT EXISTS hypothesis_predictions (
    prediction_id        TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id        TEXT NOT NULL,
    description          TEXT NOT NULL,
    expected_observation TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'untested',
    metadata             TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL,
    superseded_by        TEXT,
    CHECK (status IN ('untested','verified','refuted','superseded')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigation_links (
    link_id              TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    source_id            TEXT NOT NULL,
    source_type          TEXT NOT NULL,
    target_id            TEXT NOT NULL,
    target_type          TEXT NOT NULL,
    relation_type        TEXT NOT NULL,
    independence_group   TEXT NOT NULL DEFAULT '',
    weight               INTEGER NOT NULL DEFAULT 1000,
    status               TEXT NOT NULL DEFAULT 'active',
    metadata             TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL,
    superseded_by        TEXT,
    CHECK (source_type IN ('evidence','attempt','failed_attempt')),
    CHECK (target_type IN ('hypothesis','prediction')),
    CHECK (relation_type IN ('supports','contradicts','tests','weakens')),
    CHECK (status IN ('active','superseded'))
);

CREATE TABLE IF NOT EXISTS hypothesis_relations (
    relation_id             TEXT PRIMARY KEY,
    challenge_id            TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    source_hypothesis_id    TEXT NOT NULL,
    target_hypothesis_id    TEXT NOT NULL,
    relation_type           TEXT NOT NULL,
    discriminating_criteria TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'active',
    metadata                TEXT NOT NULL DEFAULT '{}',
    created_at              TEXT NOT NULL,
    superseded_by           TEXT,
    CHECK (relation_type IN ('competes','compatible')),
    CHECK (status IN ('active','superseded')),
    CHECK (source_hypothesis_id != target_hypothesis_id),
    FOREIGN KEY (source_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE,
    FOREIGN KEY (target_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reasoning_runs (
    run_id               TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    run_sequence         INTEGER NOT NULL,
    input_fingerprint    TEXT NOT NULL,
    ruleset_version      TEXT NOT NULL,
    canonical_result     TEXT NOT NULL,
    result_hash          TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'completed',
    created_at           TEXT NOT NULL,
    CHECK (status IN ('completed','superseded','failed')),
    UNIQUE (challenge_id, run_sequence)
);

CREATE TABLE IF NOT EXISTS hypothesis_assessments (
    assessment_id             TEXT PRIMARY KEY,
    run_id                    TEXT NOT NULL REFERENCES reasoning_runs(run_id) ON DELETE CASCADE,
    challenge_id              TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id             TEXT NOT NULL,
    posture                   TEXT NOT NULL,
    support_strength          INTEGER NOT NULL DEFAULT 0,
    contradiction_strength    INTEGER NOT NULL DEFAULT 0,
    evidence_quality          INTEGER NOT NULL DEFAULT 0,
    evidence_coverage         INTEGER NOT NULL DEFAULT 0,
    is_confirmation_eligible  INTEGER NOT NULL DEFAULT 0,
    assessment_data           TEXT NOT NULL DEFAULT '{}',
    created_at                TEXT NOT NULL,
    CHECK (posture IN ('untested','emerging','supported_candidate','contested','weakened_candidate','refuted_candidate')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);
"""

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id          TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    category              TEXT NOT NULL DEFAULT '',
    global_hint_level     INTEGER NOT NULL DEFAULT 0,
    is_active             INTEGER NOT NULL DEFAULT 1,
    tags                  TEXT NOT NULL DEFAULT '[]',
    metadata              TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    CHECK (global_hint_level >= 0 AND global_hint_level <= 6)
);

CREATE TABLE IF NOT EXISTS authorized_scopes (
    scope_id                  TEXT PRIMARY KEY,
    challenge_id              TEXT NOT NULL REFERENCES challenges(challenge_id)
                                  ON DELETE RESTRICT,
    scheme                    TEXT NOT NULL,
    hostname                  TEXT NOT NULL,
    port                      INTEGER NOT NULL,
    allowed_path_patterns     TEXT NOT NULL DEFAULT '[]',
    allowed_methods           TEXT NOT NULL DEFAULT '[]',
    exclusions                TEXT NOT NULL DEFAULT '[]',
    query_restrictions        TEXT NOT NULL DEFAULT '{}',
    environment_id            TEXT NOT NULL,
    challenge_relationship    TEXT NOT NULL DEFAULT 'primary_target',
    is_active                 INTEGER NOT NULL DEFAULT 1,
    metadata                  TEXT NOT NULL DEFAULT '{}',
    created_at                TEXT NOT NULL,
    CHECK (port >= 0 AND port <= 65535),
    CHECK (scheme IN ('http','https','tcp','udp','ftp','ssh','smtp','dns','custom')),
    CHECK (challenge_relationship IN ('primary_target','auxiliary','out_of_scope')),
    CHECK (hostname != ''),
    CHECK (environment_id != '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_primary_target
    ON authorized_scopes (challenge_id)
    WHERE is_active = 1 AND challenge_relationship = 'primary_target';

CREATE TABLE IF NOT EXISTS blackboard_states (
    challenge_id              TEXT PRIMARY KEY REFERENCES challenges(challenge_id)
                                  ON DELETE RESTRICT,
    blackboard_version        INTEGER NOT NULL DEFAULT 0,
    active_hypothesis_ids     TEXT NOT NULL DEFAULT '[]',
    watchlist_hypothesis_ids  TEXT NOT NULL DEFAULT '[]',
    confirmed_findings        TEXT NOT NULL DEFAULT '[]',
    active_evidence_ids       TEXT NOT NULL DEFAULT '[]',
    last_hint_level           INTEGER NOT NULL DEFAULT 0,
    session_notes             TEXT NOT NULL DEFAULT '',
    metadata                  TEXT NOT NULL DEFAULT '{}',
    updated_at                TEXT NOT NULL,
    CHECK (last_hint_level >= 0 AND last_hint_level <= 6),
    CHECK (blackboard_version >= 0)
);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id    TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'watchlist',
    confidence       REAL NOT NULL DEFAULT 0.0,
    hint_level       INTEGER NOT NULL DEFAULT 0,
    is_primary       INTEGER NOT NULL DEFAULT 0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (hint_level >= 0 AND hint_level <= 6),
    CHECK (status IN (
        'watchlist','active','supported','weakened','disproved','confirmed'
    )),
    UNIQUE (hypothesis_id, challenge_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_hypotheses_comp
    ON hypotheses (hypothesis_id, challenge_id);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id      TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    hypothesis_id    TEXT,
    source           TEXT NOT NULL,
    content          TEXT NOT NULL DEFAULT '',
    evidence_type    TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT 'system',
    is_fabricated    INTEGER NOT NULL DEFAULT 0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (is_fabricated = 0),
    CHECK (source IN (
        'user_confirmed','reasoning_inference','skill_inference'
    )),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL,
    UNIQUE (evidence_id, challenge_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_idempotency_key
    ON evidence (json_extract(metadata, '$.idempotency_key'))
    WHERE json_extract(metadata, '$.idempotency_key') IS NOT NULL;

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    hypothesis_id    TEXT,
    summary          TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    confidence       REAL NOT NULL DEFAULT 0.0,
    evidence_ids     TEXT NOT NULL DEFAULT '[]',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL,
    UNIQUE (finding_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id       TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    hypothesis_id    TEXT,
    description      TEXT NOT NULL DEFAULT '',
    outcome          TEXT NOT NULL DEFAULT 'unknown',
    user_input       TEXT NOT NULL DEFAULT '',
    tool_output      TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (outcome IN ('success','failure','partial','unknown')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS failed_attempts (
    failed_attempt_id       TEXT PRIMARY KEY,
    challenge_id            TEXT NOT NULL REFERENCES challenges(challenge_id)
                                ON DELETE CASCADE,
    hypothesis_id           TEXT NOT NULL,
    attempt_id              TEXT REFERENCES attempts(attempt_id)
                                ON DELETE SET NULL,
    target                  TEXT NOT NULL,
    description             TEXT NOT NULL DEFAULT '',
    do_not_repeat_unless    TEXT NOT NULL DEFAULT '',
    metadata                TEXT NOT NULL DEFAULT '{}',
    failed_at               TEXT NOT NULL,
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id          TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    task_group_id    TEXT NOT NULL,
    task_type        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'queued',
    retry_key        TEXT NOT NULL,
    retry_count      INTEGER NOT NULL DEFAULT 0,
    error_message    TEXT NOT NULL DEFAULT '',
    result_ref       TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    started_at       TEXT,
    completed_at     TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    CHECK (status IN (
        'queued','running','completed','failed','cancelled','timed_out'
    )),
    CHECK (retry_count >= 0)
);

CREATE TABLE IF NOT EXISTS task_dependencies (
    dependency_id        TEXT PRIMARY KEY,
    task_id              TEXT NOT NULL REFERENCES tasks(task_id)
                             ON DELETE CASCADE,
    depends_on_task_id   TEXT NOT NULL REFERENCES tasks(task_id)
                             ON DELETE CASCADE,
    dependency_type      TEXT NOT NULL DEFAULT 'hard',
    created_at           TEXT NOT NULL,
    CHECK (dependency_type IN ('hard','soft')),
    CHECK (task_id != depends_on_task_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_task_dependency
    ON task_dependencies (task_id, depends_on_task_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tasks_dedup
    ON tasks (challenge_id, task_group_id, task_type)
    WHERE status IN ('queued', 'running');

CREATE TABLE IF NOT EXISTS events (
    event_id                  TEXT PRIMARY KEY,
    challenge_id              TEXT NOT NULL REFERENCES challenges(challenge_id)
                                  ON DELETE RESTRICT,
    event_type                TEXT NOT NULL,
    actor                     TEXT NOT NULL,
    payload                   TEXT NOT NULL DEFAULT '{}',
    occurred_at               TEXT NOT NULL,
    blackboard_version_after  INTEGER,
    task_id                   TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
    metadata                  TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_challenge_version
    ON events (challenge_id, blackboard_version_after)
    WHERE blackboard_version_after IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_challenge_time
    ON events (challenge_id, occurred_at);

CREATE UNIQUE INDEX IF NOT EXISTS uq_event_version
    ON events (challenge_id, blackboard_version_after)
    WHERE blackboard_version_after IS NOT NULL;

CREATE TABLE IF NOT EXISTS approval_records (
    approval_id           TEXT PRIMARY KEY,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id)
                              ON DELETE CASCADE,
    approval_type         TEXT NOT NULL,
    requested_by          TEXT NOT NULL,
    requested_action_ref  TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'requested',
    requested_at          TEXT NOT NULL,
    resolved_at           TEXT,
    resolved_by           TEXT,
    decision_reason       TEXT NOT NULL DEFAULT '',
    related_request_id    TEXT,
    related_event_id      TEXT,
    CHECK (approval_type IN (
        'environment_action','l6_walkthrough','connector_evidence_trust','investigation_step'
    )),
    CHECK (status IN (
        'requested','pending','approved','rejected','expired','cancelled'
    ))
);

CREATE TABLE IF NOT EXISTS conflict_records (
    conflict_id           TEXT PRIMARY KEY,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id)
                              ON DELETE CASCADE,
    evidence_id_a         TEXT NOT NULL,
    evidence_id_b         TEXT NOT NULL,
    conflict_description  TEXT NOT NULL DEFAULT '',
    resolution            TEXT NOT NULL DEFAULT 'pending',
    resolved              INTEGER NOT NULL DEFAULT 0,
    metadata              TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL,
    resolved_at           TEXT,
    CHECK (resolution IN ('a_wins','b_wins','merged','pending')),
    CHECK (evidence_id_a != evidence_id_b),
    FOREIGN KEY (evidence_id_a, challenge_id) REFERENCES evidence(evidence_id, challenge_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id_b, challenge_id) REFERENCES evidence(evidence_id, challenge_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS hint_requests (
    request_id       TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    hypothesis_id    TEXT,
    requested_level  INTEGER NOT NULL DEFAULT 0,
    user_message     TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    requested_at     TEXT NOT NULL,
    CHECK (requested_level >= 0 AND requested_level <= 6),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL,
    UNIQUE (request_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS hint_candidates (
    candidate_id     TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    hypothesis_id    TEXT,
    level            INTEGER NOT NULL DEFAULT 0,
    content          TEXT NOT NULL DEFAULT '',
    rationale        TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (level >= 0 AND level <= 6),
    FOREIGN KEY (request_id, challenge_id) REFERENCES hint_requests(request_id, challenge_id)
        ON DELETE CASCADE,
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS hint_decisions (
    decision_id      TEXT PRIMARY KEY,
    candidate_id     TEXT NOT NULL REFERENCES hint_candidates(candidate_id)
                         ON DELETE CASCADE,
    request_id       TEXT NOT NULL,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    effective_level  INTEGER NOT NULL DEFAULT 0,
    approved         INTEGER NOT NULL DEFAULT 0,
    rejection_reason TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    decided_at       TEXT NOT NULL,
    CHECK (effective_level >= 0 AND effective_level <= 6),
    FOREIGN KEY (request_id, challenge_id) REFERENCES hint_requests(request_id, challenge_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rag_queries (
    query_id         TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    query_text       TEXT NOT NULL DEFAULT '',
    context_hint     TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rag_results (
    result_id        TEXT PRIMARY KEY,
    query_id         TEXT NOT NULL REFERENCES rag_queries(query_id)
                         ON DELETE CASCADE,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    retrieved_chunks TEXT NOT NULL DEFAULT '[]',
    score            REAL NOT NULL DEFAULT 0.0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_entries (
    memory_id        TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    content          TEXT NOT NULL DEFAULT '',
    memory_type      TEXT NOT NULL DEFAULT 'episodic',
    importance       REAL NOT NULL DEFAULT 0.0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    CHECK (importance >= 0.0 AND importance <= 1.0),
    CHECK (memory_type IN ('episodic','semantic','procedural'))
);

CREATE TABLE IF NOT EXISTS skill_results (
    skill_result_id  TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id)
                         ON DELETE CASCADE,
    skill_name       TEXT NOT NULL,
    success          INTEGER NOT NULL DEFAULT 0,
    output           TEXT NOT NULL DEFAULT '',
    evidence_ids     TEXT NOT NULL DEFAULT '[]',
    error_message    TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_action_requests (
    action_request_id     TEXT PRIMARY KEY,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id)
                              ON DELETE CASCADE,
    action_type           TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    rationale             TEXT NOT NULL DEFAULT '',
    related_hypothesis_id TEXT,
    metadata              TEXT NOT NULL DEFAULT '{}',
    requested_at          TEXT NOT NULL,
    FOREIGN KEY (related_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS user_action_results (
    result_id             TEXT PRIMARY KEY,
    action_request_id     TEXT NOT NULL REFERENCES user_action_requests(action_request_id)
                              ON DELETE CASCADE,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id)
                              ON DELETE CASCADE,
    outcome               TEXT NOT NULL DEFAULT '',
    raw_output            TEXT NOT NULL DEFAULT '',
    submitted_by          TEXT NOT NULL DEFAULT 'user',
    metadata              TEXT NOT NULL DEFAULT '{}',
    submitted_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id           TEXT PRIMARY KEY,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id)
                              ON DELETE CASCADE,
    approval_type         TEXT NOT NULL,
    requested_by          TEXT NOT NULL,
    requested_action_ref  TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'requested',
    requested_at          TEXT NOT NULL,
    resolved_at           TEXT,
    resolved_by           TEXT,
    decision_reason       TEXT NOT NULL DEFAULT '',
    related_request_id    TEXT,
    related_event_id      TEXT,
    metadata              TEXT NOT NULL DEFAULT '{}',
    CHECK (approval_type IN (
        'environment_action','l6_walkthrough','connector_evidence_trust','action_proposal','investigation_step'
    )),
    CHECK (status IN (
        'requested','pending','approved','rejected','expired','cancelled'
    ))
);

CREATE TABLE IF NOT EXISTS challenge_classifications (
    classification_id    TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id)
                             ON DELETE CASCADE,
    category             TEXT NOT NULL,
    confidence           REAL NOT NULL DEFAULT 0.0,
    signals              TEXT NOT NULL DEFAULT '[]',
    ruleset_version      TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE TABLE IF NOT EXISTS hypothesis_predictions (
    prediction_id        TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id        TEXT NOT NULL,
    description          TEXT NOT NULL,
    expected_observation TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'untested',
    metadata             TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL,
    superseded_by        TEXT,
    CHECK (status IN ('untested','verified','refuted','superseded')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigation_links (
    link_id              TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    source_id            TEXT NOT NULL,
    source_type          TEXT NOT NULL,
    target_id            TEXT NOT NULL,
    target_type          TEXT NOT NULL,
    relation_type        TEXT NOT NULL,
    independence_group   TEXT NOT NULL DEFAULT '',
    weight               INTEGER NOT NULL DEFAULT 1000,
    status               TEXT NOT NULL DEFAULT 'active',
    metadata             TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL,
    superseded_by        TEXT,
    CHECK (source_type IN ('evidence','attempt','failed_attempt')),
    CHECK (target_type IN ('hypothesis','prediction')),
    CHECK (relation_type IN ('supports','contradicts','tests','weakens')),
    CHECK (status IN ('active','superseded'))
);

CREATE TABLE IF NOT EXISTS hypothesis_relations (
    relation_id             TEXT PRIMARY KEY,
    challenge_id            TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    source_hypothesis_id    TEXT NOT NULL,
    target_hypothesis_id    TEXT NOT NULL,
    relation_type           TEXT NOT NULL,
    discriminating_criteria TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'active',
    metadata                TEXT NOT NULL DEFAULT '{}',
    created_at              TEXT NOT NULL,
    superseded_by           TEXT,
    CHECK (relation_type IN ('competes','compatible')),
    CHECK (status IN ('active','superseded')),
    CHECK (source_hypothesis_id != target_hypothesis_id),
    FOREIGN KEY (source_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE,
    FOREIGN KEY (target_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reasoning_runs (
    run_id               TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    run_sequence         INTEGER NOT NULL,
    input_fingerprint    TEXT NOT NULL,
    ruleset_version      TEXT NOT NULL,
    canonical_result     TEXT NOT NULL,
    result_hash          TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'completed',
    created_at           TEXT NOT NULL,
    CHECK (status IN ('completed','superseded','failed')),
    UNIQUE (challenge_id, run_sequence)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_reasoning_runs_dedup
    ON reasoning_runs (challenge_id, input_fingerprint, ruleset_version, result_hash);

CREATE TABLE IF NOT EXISTS hypothesis_assessments (
    assessment_id             TEXT PRIMARY KEY,
    run_id                    TEXT NOT NULL REFERENCES reasoning_runs(run_id) ON DELETE CASCADE,
    challenge_id              TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id             TEXT NOT NULL,
    posture                   TEXT NOT NULL,
    support_strength          INTEGER NOT NULL DEFAULT 0,
    contradiction_strength    INTEGER NOT NULL DEFAULT 0,
    evidence_quality          INTEGER NOT NULL DEFAULT 0,
    evidence_coverage         INTEGER NOT NULL DEFAULT 0,
    is_confirmation_eligible  INTEGER NOT NULL DEFAULT 0,
    assessment_data           TEXT NOT NULL DEFAULT '{}',
    created_at                TEXT NOT NULL,
    CHECK (posture IN ('untested','emerging','supported_candidate','contested','weakened_candidate','refuted_candidate')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS knowledge_sources (
    source_id        TEXT NOT NULL,
    source_version   TEXT NOT NULL,
    name             TEXT NOT NULL,
    category         TEXT NOT NULL,
    trust_tier       TEXT NOT NULL DEFAULT 'curated_official',
    created_at       TEXT NOT NULL,
    PRIMARY KEY (source_id, source_version)
);

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    chunk_id          TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL,
    source_version    TEXT NOT NULL,
    content           TEXT NOT NULL,
    content_hash      TEXT NOT NULL,
    category          TEXT NOT NULL,
    technique         TEXT NOT NULL DEFAULT 'general',
    trust_tier        TEXT NOT NULL DEFAULT 'curated_official',
    hint_level_floor  INTEGER NOT NULL DEFAULT 1,
    allowed_use       TEXT NOT NULL DEFAULT 'education_only',
    created_at        TEXT NOT NULL,
    CHECK (hint_level_floor >= 0 AND hint_level_floor <= 6),
    FOREIGN KEY (source_id, source_version) REFERENCES knowledge_sources(source_id, source_version) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mentor_learning_concepts (
    concept_id        TEXT PRIMARY KEY,
    category          TEXT NOT NULL,
    topic             TEXT NOT NULL,
    proficiency_score REAL NOT NULL DEFAULT 0.0,
    updated_at        TEXT NOT NULL,
    CHECK (proficiency_score >= 0.0 AND proficiency_score <= 1.0)
);

CREATE TABLE IF NOT EXISTS authorized_scope_entries (
    entry_id             TEXT PRIMARY KEY,
    scope_id             TEXT NOT NULL REFERENCES authorized_scopes(scope_id) ON DELETE CASCADE,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    scheme               TEXT NOT NULL DEFAULT 'http',
    hostname             TEXT NOT NULL,
    port                 INTEGER NOT NULL,
    path_pattern         TEXT NOT NULL DEFAULT '/*',
    allowed_methods      TEXT NOT NULL DEFAULT '["GET"]',
    exclusions           TEXT NOT NULL DEFAULT '[]',
    is_active            INTEGER NOT NULL DEFAULT 1,
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_proposals (
    proposal_id          TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    request_id           TEXT,
    action_type          TEXT NOT NULL,
    target_json          TEXT NOT NULL,
    rationale            TEXT NOT NULL,
    hypothesis_id        TEXT,
    scope_id             TEXT,
    scope_version        TEXT NOT NULL DEFAULT '1.0',
    status               TEXT NOT NULL DEFAULT 'draft',
    created_at           TEXT NOT NULL,
    expires_at           TEXT,
    metadata             TEXT NOT NULL DEFAULT '{}',
    CHECK (status IN ('draft','pending_approval','approved','result_submitted','confirming','consumed','rejected','expired','cancelled')),
    CHECK (action_type IN ('observe_response','inspect_header','compare_parameter_values','test_input_boundary','inspect_api_behavior'))
);

CREATE TABLE IF NOT EXISTS action_results (
    result_id            TEXT PRIMARY KEY,
    proposal_id          TEXT NOT NULL REFERENCES action_proposals(proposal_id) ON DELETE CASCADE,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    raw_output           TEXT NOT NULL,
    outcome              TEXT NOT NULL DEFAULT 'success',
    submitted_at         TEXT NOT NULL,
    submitted_by         TEXT NOT NULL DEFAULT 'user',
    metadata             TEXT NOT NULL DEFAULT '{}',
    UNIQUE (proposal_id)
);

CREATE TABLE IF NOT EXISTS normalized_evidence_drafts (
    draft_id              TEXT PRIMARY KEY,
    proposal_id           TEXT NOT NULL REFERENCES action_proposals(proposal_id) ON DELETE CASCADE,
    result_id             TEXT NOT NULL REFERENCES action_results(result_id) ON DELETE CASCADE,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id         TEXT,
    summary_content       TEXT NOT NULL,
    raw_snippet           TEXT NOT NULL,
    extracted_status_code INTEGER,
    extracted_headers     TEXT NOT NULL DEFAULT '{}',
    is_confirmed          INTEGER NOT NULL DEFAULT 0,
    confirmed_at          TEXT,
    confirmed_by          TEXT,
    metadata              TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL,
    UNIQUE (proposal_id),
    UNIQUE (result_id)
);

CREATE TABLE IF NOT EXISTS investigation_sessions (
    session_id          TEXT PRIMARY KEY,
    challenge_id        TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    status              TEXT NOT NULL DEFAULT 'active',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    metadata            TEXT NOT NULL DEFAULT '{}',
    CHECK (status IN ('active','paused','completed','terminated')),
    UNIQUE (session_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS investigation_steps (
    step_id             TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    challenge_id        TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    proposal_ref        TEXT,
    step_type           TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    target_json         TEXT NOT NULL,
    rationale           TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'draft',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    expires_at          TEXT,
    metadata            TEXT NOT NULL DEFAULT '{}',
    CHECK (status IN ('draft','pending_approval','approved','result_submitted','confirming','consumed','rejected','expired','cancelled')),
    CHECK (target_type IN ('HTTP_TARGET','FILE_TARGET','PCAP_TARGET','BINARY_TARGET','MEMORY_TARGET','CLOUD_TARGET','TEXT_TARGET')),
    FOREIGN KEY (session_id, challenge_id) REFERENCES investigation_sessions(session_id, challenge_id) ON DELETE CASCADE,
    UNIQUE (step_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS investigation_results (
    result_id            TEXT PRIMARY KEY,
    step_id              TEXT NOT NULL,
    session_id           TEXT NOT NULL,
    challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    result_type          TEXT NOT NULL DEFAULT 'GENERIC',
    outcome_status       TEXT NOT NULL DEFAULT 'success',
    raw_output           TEXT NOT NULL,
    data_json            TEXT NOT NULL DEFAULT '{}',
    provenance_hash      TEXT NOT NULL DEFAULT '',
    submitted_by         TEXT NOT NULL DEFAULT 'user',
    submitted_at         TEXT NOT NULL,
    metadata             TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (step_id, challenge_id) REFERENCES investigation_steps(step_id, challenge_id) ON DELETE CASCADE,
    FOREIGN KEY (session_id, challenge_id) REFERENCES investigation_sessions(session_id, challenge_id) ON DELETE CASCADE,
    UNIQUE (step_id)
);

CREATE TABLE IF NOT EXISTS schema_version (
    version          INTEGER PRIMARY KEY,
    applied_at       TEXT NOT NULL
);

"""

# Triggers applied individually after DDL - cannot use split approach due to
# BEGIN...END blocks containing semicolons.
_TRIGGER_STMTS: list[str] = [
    """
    CREATE TRIGGER IF NOT EXISTS trg_investigation_results_no_update
        BEFORE UPDATE ON investigation_results
    BEGIN
        SELECT RAISE(ABORT, 'investigation_results are append-only: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_investigation_results_no_delete
        BEFORE DELETE ON investigation_results
    BEGIN
        SELECT RAISE(ABORT, 'investigation_results are append-only: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_events_no_update
        BEFORE UPDATE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_events_no_delete
        BEFORE DELETE ON events
    BEGIN
        SELECT RAISE(ABORT, 'events are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_reasoning_runs_no_update
        BEFORE UPDATE ON reasoning_runs
    BEGIN
        SELECT RAISE(ABORT, 'reasoning_runs are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_reasoning_runs_no_delete
        BEFORE DELETE ON reasoning_runs
    BEGIN
        SELECT RAISE(ABORT, 'reasoning_runs are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_assessments_no_update
        BEFORE UPDATE ON hypothesis_assessments
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_assessments are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_assessments_no_delete
        BEFORE DELETE ON hypothesis_assessments
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_assessments are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_predictions_no_update
        BEFORE UPDATE ON hypothesis_predictions
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_predictions are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_predictions_no_delete
        BEFORE DELETE ON hypothesis_predictions
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_predictions are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_investigation_links_no_update
        BEFORE UPDATE ON investigation_links
    BEGIN
        SELECT RAISE(ABORT, 'investigation_links are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_investigation_links_no_delete
        BEFORE DELETE ON investigation_links
    BEGIN
        SELECT RAISE(ABORT, 'investigation_links are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_relations_no_update
        BEFORE UPDATE ON hypothesis_relations
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_relations are immutable: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_hypothesis_relations_no_delete
        BEFORE DELETE ON hypothesis_relations
    BEGIN
        SELECT RAISE(ABORT, 'hypothesis_relations are immutable: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_results_no_update
        BEFORE UPDATE ON action_results
    BEGIN
        SELECT RAISE(ABORT, 'action_results are append-only: UPDATE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_results_no_delete
        BEFORE DELETE ON action_results
    BEGIN
        SELECT RAISE(ABORT, 'action_results are append-only: DELETE is forbidden');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_action_proposals_terminal_immutable
        BEFORE UPDATE ON action_proposals
        WHEN OLD.status IN ('consumed', 'rejected', 'expired', 'cancelled')
    BEGIN
        SELECT RAISE(ABORT, 'action_proposals terminal state is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_investigation_steps_terminal_immutable
        BEFORE UPDATE ON investigation_steps
        WHEN OLD.status IN ('consumed', 'rejected', 'expired', 'cancelled')
    BEGIN
        SELECT RAISE(ABORT, 'investigation_steps terminal state is immutable');
    END
    """,
]



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_connection(db_path: Union[str, Path]) -> sqlite3.Connection:
    """Return a new SQLite connection with required pragmas applied.

    - Foreign keys are enforced.
    - WAL journal mode for better concurrency.
    - Isolation level is set to None (explicit transactions only).
    Raises ValueError if a caller passes a connection with foreign_keys disabled.
    """
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    return conn


def assert_foreign_keys_enabled(conn: sqlite3.Connection) -> None:
    """Raise ValueError if PRAGMA foreign_keys is not ON on this connection.

    Callers must pass only connections that have foreign keys enforced.
    This is a safety guard for M6: the repository must never accept a connection
    with foreign_keys disabled.
    """
    row = conn.execute("PRAGMA foreign_keys;").fetchone()
    if row is None or int(row[0]) != 1:
        raise ValueError(
            "Connection must have PRAGMA foreign_keys = ON. "
            "Use get_connection() to obtain a correctly configured connection."
        )


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Apply mandatory SQLite pragmas."""
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.OperationalError:
        pass


def initialize_schema(conn: sqlite3.Connection) -> int:
    """Initialize the database schema idempotently.

    Safe to call repeatedly; will not destroy existing data.
    Returns the current schema version after initialization.

    Raises RuntimeError if schema version is in an incompatible state.
    """
    _apply_pragmas(conn)

    current_version = _get_schema_version(conn)

    if current_version == SCHEMA_VERSION:
        logger.debug("Schema already at version %d; nothing to do.", SCHEMA_VERSION)
        return current_version

    if current_version > SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {current_version} is newer than "
            f"supported version {SCHEMA_VERSION}. Downgrade is not supported."
        )

    logger.info(
        "Initializing schema: current_version=%d -> target_version=%d",
        current_version,
        SCHEMA_VERSION,
    )

    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("BEGIN;")
    try:
        if current_version > 0 and current_version < SCHEMA_VERSION:
            conn.execute("DROP INDEX IF EXISTS uq_tasks_dedup;")
            _migrate_v7_to_v8(conn)
            _migrate_v8_to_v9(conn)
            _migrate_v9_to_v10(conn)

        for statement in _split_ddl(_DDL):
            conn.execute(statement)

        if current_version > 0 and current_version < SCHEMA_VERSION:
            _ensure_table_fk_parity(conn)

        for trigger_sql in _TRIGGER_STMTS:
            conn.execute(trigger_sql)

        if current_version == 0:
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'));",
                (SCHEMA_VERSION,),
            )
        else:
            conn.execute(
                "UPDATE schema_version SET version = ?, applied_at = datetime('now');",
                (SCHEMA_VERSION,),
            )

        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        conn.execute("PRAGMA foreign_keys = ON;")
        raise

    conn.execute("PRAGMA foreign_keys = ON;")
    fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
    if fk_violations:
        raise RuntimeError(f"Foreign key integrity check failed after migration: {fk_violations}")

    logger.info("Schema initialized at version %d.", SCHEMA_VERSION)
    return SCHEMA_VERSION


_TABLE_DDL_MAP: dict[str, str] = {
    "attempts": """
CREATE TABLE attempts_temp (
    attempt_id       TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id    TEXT,
    description      TEXT NOT NULL DEFAULT '',
    outcome          TEXT NOT NULL DEFAULT 'unknown',
    user_input       TEXT NOT NULL DEFAULT '',
    tool_output      TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (outcome IN ('success','failure','partial','unknown')),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE SET NULL
);
""",
    "hint_requests": """
CREATE TABLE hint_requests_temp (
    request_id       TEXT PRIMARY KEY,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id    TEXT,
    requested_level  INTEGER NOT NULL DEFAULT 0,
    user_message     TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    requested_at     TEXT NOT NULL,
    CHECK (requested_level >= 0 AND requested_level <= 6),
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE SET NULL,
    UNIQUE (request_id, challenge_id)
);
""",
    "hint_candidates": """
CREATE TABLE hint_candidates_temp (
    candidate_id     TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    hypothesis_id    TEXT,
    level            INTEGER NOT NULL DEFAULT 0,
    content          TEXT NOT NULL DEFAULT '',
    rationale        TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    CHECK (level >= 0 AND level <= 6),
    FOREIGN KEY (request_id, challenge_id) REFERENCES hint_requests(request_id, challenge_id) ON DELETE CASCADE,
    FOREIGN KEY (hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE SET NULL
);
""",
    "hint_decisions": """
CREATE TABLE hint_decisions_temp (
    decision_id      TEXT PRIMARY KEY,
    candidate_id     TEXT NOT NULL REFERENCES hint_candidates(candidate_id) ON DELETE CASCADE,
    request_id       TEXT NOT NULL,
    challenge_id     TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    effective_level  INTEGER NOT NULL DEFAULT 0,
    approved         INTEGER NOT NULL DEFAULT 0,
    rejection_reason TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    decided_at       TEXT NOT NULL,
    CHECK (effective_level >= 0 AND effective_level <= 6),
    FOREIGN KEY (request_id, challenge_id) REFERENCES hint_requests(request_id, challenge_id) ON DELETE CASCADE
);
""",
    "user_action_requests": """
CREATE TABLE user_action_requests_temp (
    action_request_id     TEXT PRIMARY KEY,
    challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
    action_type           TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    rationale             TEXT NOT NULL DEFAULT '',
    related_hypothesis_id TEXT,
    metadata              TEXT NOT NULL DEFAULT '{}',
    requested_at          TEXT NOT NULL,
    FOREIGN KEY (related_hypothesis_id, challenge_id) REFERENCES hypotheses(hypothesis_id, challenge_id) ON DELETE SET NULL
);
""",
}


def _get_canonical_fk_tuples(conn: sqlite3.Connection, table_name: str) -> set[tuple[str, str, str, str]]:
    """Return canonical set of FK tuples: (table_to, from_col, to_col, on_delete) for a table."""
    cursor = conn.cursor()
    rows = cursor.execute(f"PRAGMA foreign_key_list({table_name});").fetchall()
    fk_tuples = set()
    for r in rows:
        fk_tuples.add((r[2], r[3], r[4], r[6]))
    return fk_tuples


def _migrate_v7_to_v8(conn: sqlite3.Connection) -> None:
    """Migrate database schema from version 7 to 8."""
    ap_row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='action_proposals';").fetchone()
    if ap_row and "confirming" not in ap_row[0]:
        logger.info("Migrating action_proposals table to v8 schema (adding 'confirming' status).")
        conn.execute("""
        CREATE TABLE action_proposals_temp (
            proposal_id          TEXT PRIMARY KEY,
            challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            request_id           TEXT,
            action_type          TEXT NOT NULL,
            target_json          TEXT NOT NULL,
            rationale            TEXT NOT NULL,
            hypothesis_id        TEXT,
            scope_id             TEXT,
            scope_version        TEXT NOT NULL DEFAULT '1.0',
            status               TEXT NOT NULL DEFAULT 'draft',
            created_at           TEXT NOT NULL,
            expires_at           TEXT,
            metadata             TEXT NOT NULL DEFAULT '{}',
            CHECK (status IN ('draft','pending_approval','approved','result_submitted','confirming','consumed','rejected','expired','cancelled')),
            CHECK (action_type IN ('observe_response','inspect_header','compare_parameter_values','test_input_boundary','inspect_api_behavior'))
        );
        """)
        conn.execute("INSERT INTO action_proposals_temp SELECT * FROM action_proposals;")
        conn.execute("DROP TABLE action_proposals;")
        conn.execute("ALTER TABLE action_proposals_temp RENAME TO action_proposals;")

    ev_row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence';").fetchone()
    if ev_row:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_comp ON evidence(evidence_id, challenge_id);")
        conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_idempotency_key
            ON evidence (json_extract(metadata, '$.idempotency_key'))
            WHERE json_extract(metadata, '$.idempotency_key') IS NOT NULL;
        """)

    hyp_row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hypotheses';").fetchone()
    if hyp_row:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_hypotheses_comp ON hypotheses(hypothesis_id, challenge_id);")


def _migrate_v8_to_v9(conn: sqlite3.Connection) -> None:
    """Migrate database schema from version 8 to 9 (Phase 6A)."""
    ar_row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='approval_records';").fetchone()
    if ar_row and "investigation_step" not in ar_row[0]:
        logger.info("Migrating approval_records table to v9 schema (adding 'investigation_step' type).")
        conn.execute("""
        CREATE TABLE approval_records_temp (
            approval_id           TEXT PRIMARY KEY,
            challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            approval_type         TEXT NOT NULL,
            requested_by          TEXT NOT NULL,
            requested_action_ref  TEXT NOT NULL,
            status                TEXT NOT NULL DEFAULT 'requested',
            requested_at          TEXT NOT NULL,
            resolved_at           TEXT,
            resolved_by           TEXT,
            decision_reason       TEXT NOT NULL DEFAULT '',
            related_request_id    TEXT,
            related_event_id      TEXT,
            CHECK (approval_type IN ('environment_action','l6_walkthrough','connector_evidence_trust','investigation_step')),
            CHECK (status IN ('requested','pending','approved','rejected','expired','cancelled'))
        );
        """)
        conn.execute("INSERT INTO approval_records_temp SELECT * FROM approval_records;")
        conn.execute("DROP TABLE approval_records;")
        conn.execute("ALTER TABLE approval_records_temp RENAME TO approval_records;")

    req_row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='approval_requests';").fetchone()
    if req_row and "investigation_step" not in req_row[0]:
        logger.info("Migrating approval_requests table to v9 schema (adding 'investigation_step' type).")
        conn.execute("""
        CREATE TABLE approval_requests_temp (
            approval_id           TEXT PRIMARY KEY,
            challenge_id          TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            approval_type         TEXT NOT NULL,
            requested_by          TEXT NOT NULL,
            requested_action_ref  TEXT NOT NULL,
            status                TEXT NOT NULL DEFAULT 'requested',
            requested_at          TEXT NOT NULL,
            resolved_at           TEXT,
            resolved_by           TEXT,
            decision_reason       TEXT NOT NULL DEFAULT '',
            related_request_id    TEXT,
            related_event_id      TEXT,
            metadata              TEXT NOT NULL DEFAULT '{}',
            CHECK (approval_type IN ('environment_action','l6_walkthrough','connector_evidence_trust','action_proposal','investigation_step')),
            CHECK (status IN ('requested','pending','approved','rejected','expired','cancelled'))
        );
        """)
        conn.execute("INSERT INTO approval_requests_temp SELECT * FROM approval_requests;")
        conn.execute("DROP TABLE approval_requests;")
        conn.execute("ALTER TABLE approval_requests_temp RENAME TO approval_requests;")


def _migrate_v9_to_v10(conn: sqlite3.Connection) -> None:
    """Migrate database schema from version 9 to 10 (Phase 6A durable investigation_results)."""
    ir_row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_results';").fetchone()
    if not ir_row:
        logger.info("Migrating database schema to v10 (creating investigation_results table).")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS investigation_results (
            result_id            TEXT PRIMARY KEY,
            step_id              TEXT NOT NULL,
            session_id           TEXT NOT NULL,
            challenge_id         TEXT NOT NULL REFERENCES challenges(challenge_id) ON DELETE CASCADE,
            result_type          TEXT NOT NULL DEFAULT 'GENERIC',
            outcome_status       TEXT NOT NULL DEFAULT 'success',
            raw_output           TEXT NOT NULL,
            data_json            TEXT NOT NULL DEFAULT '{}',
            provenance_hash      TEXT NOT NULL DEFAULT '',
            submitted_by         TEXT NOT NULL DEFAULT 'user',
            submitted_at         TEXT NOT NULL,
            metadata             TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (step_id, challenge_id) REFERENCES investigation_steps(step_id, challenge_id) ON DELETE CASCADE,
            FOREIGN KEY (session_id, challenge_id) REFERENCES investigation_sessions(session_id, challenge_id) ON DELETE CASCADE,
            UNIQUE (step_id)
        );
        """)



def _ensure_table_fk_parity(conn: sqlite3.Connection) -> None:
    """Ensure existing legacy tables have exact FK constraint parity with fresh DDL."""
    ref_conn = sqlite3.connect(":memory:")
    ref_conn.execute("PRAGMA foreign_keys = ON;")
    for stmt in _split_ddl(_DDL):
        ref_conn.execute(stmt)

    tables_to_check = ["attempts", "hint_requests", "hint_candidates", "hint_decisions", "user_action_requests"]
    for table_name in tables_to_check:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
        if not row:
            continue

        existing_fks = _get_canonical_fk_tuples(conn, table_name)
        fresh_fks = _get_canonical_fk_tuples(ref_conn, table_name)

        if existing_fks != fresh_fks:
            logger.info("FK mismatch detected on %s during migration. Rebuilding table for parity.", table_name)
            temp_table = f"{table_name}_temp"
            ddl_temp = _TABLE_DDL_MAP[table_name]

            existing_cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table_name});").fetchall()]
            temp_conn = sqlite3.connect(":memory:")
            temp_conn.execute(ddl_temp)
            fresh_cols = [r[1] for r in temp_conn.execute(f"PRAGMA table_info({temp_table});").fetchall()]
            temp_conn.close()

            common_cols = [c for c in existing_cols if c in fresh_cols]
            col_str = ", ".join(common_cols)

            conn.execute("PRAGMA foreign_keys = OFF;")
            conn.execute(f"DROP TABLE IF EXISTS {temp_table};")
            conn.execute(ddl_temp)
            if col_str:
                conn.execute(f"INSERT INTO {temp_table} ({col_str}) SELECT {col_str} FROM {table_name};")
            conn.execute(f"DROP TABLE {table_name};")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO {table_name};")
            conn.execute("PRAGMA foreign_keys = ON;")

    ref_conn.close()


def _get_schema_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version; 0 if the version table does not exist."""
    try:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_version;"
        ).fetchone()
        if row is None or row[0] is None:
            return 0
        return int(row[0])
    except sqlite3.OperationalError:
        return 0


def _split_ddl(ddl: str) -> list[str]:
    """Split a multi-statement DDL string into individual executable statements.

    Strips line-level SQL comments (--) and blank lines before evaluating each
    candidate statement so that comment fragments never reach conn.execute().
    """
    statements: list[str] = []
    for raw in ddl.split(";"):
        cleaned_lines = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("--") or stripped == "":
                continue
            cleaned_lines.append(stripped)
        stmt = "\n".join(cleaned_lines).strip()
        if stmt:
            statements.append(stmt)
    return statements
