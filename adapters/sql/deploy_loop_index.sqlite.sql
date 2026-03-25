-- Deploy loop derived decision index (SQLite)
-- Source of truth remains the content-addressed store under state_dir.
-- This database is rebuildable derived state for query acceleration only.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;

CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

INSERT OR REPLACE INTO meta (k, v) VALUES
  ('schema_version', 'lp.sqlite.deploy_loop_index@0.1.0'),
  ('owner', 'x07-platform'),
  ('purpose', 'deploy_loop_decision_trail_query_index');

CREATE TABLE IF NOT EXISTS executions (
  exec_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'local',
  artifact_kind TEXT NOT NULL,
  created_unix_ms INTEGER NOT NULL,
  updated_unix_ms INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('planned', 'started', 'completed', 'failed', 'aborted')),
  outcome TEXT CHECK (outcome IS NULL OR outcome IN ('unknown', 'promoted', 'rolled_back', 'aborted', 'failed')),
  current_weight_pct INTEGER NOT NULL DEFAULT 0 CHECK (current_weight_pct >= 0 AND current_weight_pct <= 100),
  public_listener TEXT,
  latest_decision_id TEXT,
  plan_sha256 TEXT,
  plan_bytes_len INTEGER,
  stable_revision_sha256 TEXT,
  stable_revision_bytes_len INTEGER,
  candidate_revision_sha256 TEXT,
  candidate_revision_bytes_len INTEGER,
  exec_record_sha256 TEXT NOT NULL CHECK (length(exec_record_sha256) = 64),
  exec_record_bytes_len INTEGER NOT NULL,
  exec_store_uri TEXT NOT NULL,
  run_record_sha256 TEXT CHECK (run_record_sha256 IS NULL OR length(run_record_sha256) = 64),
  run_record_bytes_len INTEGER,
  run_store_uri TEXT
);

CREATE INDEX IF NOT EXISTS executions_target_created_idx
  ON executions (app_id, environment, created_unix_ms DESC, exec_id DESC);
CREATE INDEX IF NOT EXISTS executions_status_idx
  ON executions (status, created_unix_ms DESC);
CREATE INDEX IF NOT EXISTS executions_latest_decision_idx
  ON executions (latest_decision_id);

CREATE TABLE IF NOT EXISTS target_heads (
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  exec_id TEXT NOT NULL,
  updated_unix_ms INTEGER NOT NULL,
  PRIMARY KEY (app_id, environment),
  FOREIGN KEY (exec_id) REFERENCES executions (exec_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_steps (
  exec_id TEXT NOT NULL,
  step_idx INTEGER NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 1,
  step_name TEXT NOT NULL,
  step_kind TEXT,
  status TEXT NOT NULL CHECK (status IN ('ok', 'error', 'skipped', 'running')),
  started_unix_ms INTEGER NOT NULL,
  ended_unix_ms INTEGER,
  latest_weight_pct INTEGER CHECK (latest_weight_pct IS NULL OR (latest_weight_pct >= 0 AND latest_weight_pct <= 100)),
  analysis_decision TEXT CHECK (analysis_decision IS NULL OR analysis_decision IN ('promote', 'rollback', 'inconclusive')),
  PRIMARY KEY (exec_id, step_idx, attempt),
  FOREIGN KEY (exec_id) REFERENCES executions (exec_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS execution_steps_timeline_idx
  ON execution_steps (exec_id, step_idx ASC, attempt ASC);
CREATE INDEX IF NOT EXISTS execution_steps_status_idx
  ON execution_steps (status, started_unix_ms DESC);

CREATE TABLE IF NOT EXISTS decisions (
  decision_id TEXT PRIMARY KEY,
  exec_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  step_idx INTEGER,
  attempt INTEGER,
  created_unix_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'deny', 'error')),
  primary_code TEXT NOT NULL,
  summary_message TEXT,
  record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
  record_bytes_len INTEGER NOT NULL,
  record_store_uri TEXT NOT NULL,
  FOREIGN KEY (exec_id) REFERENCES executions (exec_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS decisions_exec_created_idx
  ON decisions (exec_id, created_unix_ms ASC, decision_id ASC);
CREATE INDEX IF NOT EXISTS decisions_code_idx
  ON decisions (primary_code, created_unix_ms DESC);
CREATE INDEX IF NOT EXISTS decisions_kind_idx
  ON decisions (kind, created_unix_ms DESC);

CREATE TABLE IF NOT EXISTS decision_reasons (
  decision_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  code TEXT NOT NULL,
  message TEXT,
  PRIMARY KEY (decision_id, ord),
  FOREIGN KEY (decision_id) REFERENCES decisions (decision_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS decision_reasons_code_idx
  ON decision_reasons (code, decision_id);

CREATE TABLE IF NOT EXISTS artifacts (
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  bytes_len INTEGER NOT NULL,
  kind TEXT,
  media_type TEXT NOT NULL,
  logical_name TEXT,
  store_uri TEXT NOT NULL,
  first_seen_unix_ms INTEGER NOT NULL,
  PRIMARY KEY (sha256, bytes_len)
);

CREATE INDEX IF NOT EXISTS artifacts_kind_idx
  ON artifacts (kind, first_seen_unix_ms DESC);
CREATE INDEX IF NOT EXISTS artifacts_logical_name_idx
  ON artifacts (logical_name, first_seen_unix_ms DESC);

CREATE TABLE IF NOT EXISTS execution_artifacts (
  exec_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  role TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes_len INTEGER NOT NULL,
  PRIMARY KEY (exec_id, ord),
  FOREIGN KEY (exec_id) REFERENCES executions (exec_id) ON DELETE CASCADE,
  FOREIGN KEY (sha256, bytes_len) REFERENCES artifacts (sha256, bytes_len)
);

CREATE INDEX IF NOT EXISTS execution_artifacts_role_idx
  ON execution_artifacts (exec_id, role, ord ASC);
CREATE INDEX IF NOT EXISTS execution_artifacts_digest_idx
  ON execution_artifacts (sha256, bytes_len);

CREATE TABLE IF NOT EXISTS decision_evidence (
  decision_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  role TEXT NOT NULL DEFAULT 'evidence',
  sha256 TEXT NOT NULL,
  bytes_len INTEGER NOT NULL,
  PRIMARY KEY (decision_id, ord),
  FOREIGN KEY (decision_id) REFERENCES decisions (decision_id) ON DELETE CASCADE,
  FOREIGN KEY (sha256, bytes_len) REFERENCES artifacts (sha256, bytes_len)
);

CREATE INDEX IF NOT EXISTS decision_evidence_digest_idx
  ON decision_evidence (sha256, bytes_len);

CREATE TABLE IF NOT EXISTS indexed_records (
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  bytes_len INTEGER NOT NULL,
  record_kind TEXT NOT NULL,
  indexed_unix_ms INTEGER NOT NULL,
  exec_id TEXT,
  PRIMARY KEY (sha256, bytes_len, record_kind)
);

CREATE INDEX IF NOT EXISTS indexed_records_exec_idx
  ON indexed_records (exec_id, indexed_unix_ms DESC);

CREATE VIEW IF NOT EXISTS latest_execution_summary_v1 AS
  SELECT
    th.app_id,
    th.environment,
    e.exec_id,
    e.run_id,
    e.status,
    e.outcome,
    e.current_weight_pct,
    e.public_listener,
    e.latest_decision_id,
    e.created_unix_ms,
    e.updated_unix_ms
  FROM target_heads AS th
  JOIN executions AS e
    ON e.exec_id = th.exec_id;
