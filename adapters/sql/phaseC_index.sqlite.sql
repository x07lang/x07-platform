-- Phase C derived incident/control index (SQLite additions)
-- Execute this after the Phase B schema has been materialized.

INSERT OR REPLACE INTO meta (k, v) VALUES
  ('phasec_schema_version', 'lp.sqlite.phasec_index@0.1.0'),
  ('phasec_purpose', 'incident_control_query_index');

CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  deployment_id TEXT,
  release_exec_id TEXT,
  run_id TEXT NOT NULL,
  classification TEXT NOT NULL,
  source TEXT NOT NULL,
  incident_status TEXT NOT NULL,
  captured_unix_ms INTEGER NOT NULL,
  request_id TEXT,
  trace_id TEXT,
  status_code INTEGER,
  decision_id TEXT,
  regression_status TEXT NOT NULL,
  regression_id TEXT,
  bundle_sha256 TEXT CHECK (bundle_sha256 IS NULL OR length(bundle_sha256) = 64),
  bundle_bytes_len INTEGER,
  bundle_store_uri TEXT NOT NULL,
  meta_store_uri TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_target_captured_idx
  ON incidents (app_id, environment, captured_unix_ms DESC, incident_id DESC);
CREATE INDEX IF NOT EXISTS incidents_deployment_idx
  ON incidents (deployment_id, captured_unix_ms DESC);
CREATE INDEX IF NOT EXISTS incidents_release_exec_idx
  ON incidents (release_exec_id, captured_unix_ms DESC);

CREATE TABLE IF NOT EXISTS incident_artifacts (
  incident_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  role TEXT NOT NULL,
  sha256 TEXT,
  bytes_len INTEGER,
  kind TEXT,
  media_type TEXT,
  logical_name TEXT,
  store_uri TEXT NOT NULL,
  PRIMARY KEY (incident_id, ord),
  FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_diagnostics (
  incident_id TEXT NOT NULL,
  ord INTEGER NOT NULL,
  code TEXT NOT NULL,
  PRIMARY KEY (incident_id, ord),
  FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS regressions (
  regression_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  created_unix_ms INTEGER NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  incident_status_after TEXT NOT NULL,
  out_dir TEXT,
  report_sha256 TEXT CHECK (report_sha256 IS NULL OR length(report_sha256) = 64),
  report_bytes_len INTEGER,
  report_store_uri TEXT,
  FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS control_actions (
  action_id TEXT PRIMARY KEY,
  created_unix_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  scope TEXT NOT NULL,
  deployment_id TEXT,
  app_id TEXT,
  environment TEXT,
  ok INTEGER NOT NULL DEFAULT 0,
  decision_id TEXT,
  signature_status TEXT NOT NULL,
  new_execution_id TEXT,
  reason TEXT
);

CREATE INDEX IF NOT EXISTS control_actions_created_idx
  ON control_actions (created_unix_ms DESC, action_id DESC);

CREATE TABLE IF NOT EXISTS kill_switches (
  scope_key TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  app_id TEXT,
  environment TEXT,
  kill_state TEXT NOT NULL,
  updated_unix_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_heads (
  app_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  latest_deployment_id TEXT,
  deployment_status TEXT,
  control_state TEXT,
  outcome TEXT,
  public_listener TEXT,
  current_weight_pct INTEGER NOT NULL DEFAULT 0,
  incident_count_total INTEGER NOT NULL DEFAULT 0,
  incident_count_open INTEGER NOT NULL DEFAULT 0,
  latest_incident_id TEXT,
  latest_decision_id TEXT,
  kill_state TEXT NOT NULL DEFAULT 'none',
  updated_unix_ms INTEGER NOT NULL,
  PRIMARY KEY (app_id, environment)
);

CREATE INDEX IF NOT EXISTS app_heads_updated_idx
  ON app_heads (updated_unix_ms DESC, app_id ASC, environment ASC);
