#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

source "$ROOT_DIR/scripts/ci/use_workspace_x07_bins.sh"

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "python not found on PATH" >&2
  exit 1
fi

NOW_UNIX_MS="1762752000000"
PACK_DIR="spec/fixtures/phaseA/pack_min"
PACK_MANIFEST="app.pack.json"
PHASEB_CHANGE="spec/fixtures/phaseB/common/change_request.app_min.json"
PHASEC_TMP="${ROOT_DIR}/_tmp/ci_phaseC"
UI_ADDR="127.0.0.1:17090"
UI_BASE_URL="http://${UI_ADDR}"

mkdir -p "$PHASEC_TMP"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if [ -n "${pid:-}" ] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

decode_solve_output_b64() {
  local report_path="$1"
  local out_path="$2"
  "$PYTHON" - "$report_path" "$out_path" <<'PY'
import base64
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
doc = json.loads(report.read_text(encoding='utf-8'))

def find_solve_output_b64(doc):
    if isinstance(doc, dict):
        if isinstance(doc.get('solve_output_b64'), str):
            return doc['solve_output_b64']
        solve = doc.get('solve')
        if isinstance(solve, dict) and isinstance(solve.get('solve_output_b64'), str):
            return solve['solve_output_b64']
        result = doc.get('result')
        if isinstance(result, dict):
            stdout_json = result.get('stdout_json')
            if isinstance(stdout_json, dict):
                solve = stdout_json.get('solve')
                if isinstance(solve, dict) and isinstance(solve.get('solve_output_b64'), str):
                    return solve['solve_output_b64']
        report2 = doc.get('report')
        if isinstance(report2, dict):
            solve = report2.get('solve')
            if isinstance(solve, dict) and isinstance(solve.get('solve_output_b64'), str):
                return solve['solve_output_b64']
    return ''

b64 = find_solve_output_b64(doc)
if not b64:
    raise SystemExit('missing solve_output_b64 in report')
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(base64.b64decode(b64))
PY
}

run_x07lp() {
  local report_path="$1"
  local out_path="$2"
  shift 2
  (
    cd "$ROOT_DIR"
    x07 run -- "$@" >"$report_path"
  )
  decode_solve_output_b64 "$report_path" "$out_path"
}

repo_path_arg() {
  local raw_path="$1"
  "$PYTHON" - "$ROOT_DIR" "$raw_path" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
raw = pathlib.Path(sys.argv[2])
path = raw if raw.is_absolute() else (root / raw)
try:
    print(path.absolute().relative_to(root).as_posix())
except ValueError:
    print(path.absolute())
PY
}

check_schema_validate_ok() {
  local schema_path="$1"
  local in_path="$2"
  local report_path="$3"
  local out_path="$4"
  local schema_arg
  local in_arg
  schema_arg="$(repo_path_arg "$schema_path")"
  in_arg="$(repo_path_arg "$in_path")"
  run_x07lp "$report_path" "$out_path" schema validate --schema "$schema_arg" --in "$in_arg" --json
  "$PYTHON" - "$out_path" <<'PY'
import json
import pathlib
import sys
p = pathlib.Path(sys.argv[1])
doc = json.loads(p.read_text(encoding='utf-8'))
if doc.get('ok') is not True or doc.get('result', {}).get('ok') is not True:
    raise SystemExit(f'schema validate not ok: {p}')
PY
}

assert_report_matches_template() {
  local actual_path="$1"
  local expected_path="$2"
  "$PYTHON" - "$actual_path" "$expected_path" <<'PY'
import json
import pathlib
import sys

def match(exp, act, path=''):
    if exp == '__ANY__':
        return True, None
    if isinstance(exp, dict):
        if not isinstance(act, dict):
            return False, f'{path}: expected object, got {type(act).__name__}'
        for k, v in exp.items():
            if k not in act:
                return False, f'{path}/{k}: missing key'
            ok, err = match(v, act[k], f'{path}/{k}')
            if not ok:
                return False, err
        return True, None
    if isinstance(exp, list):
        if not isinstance(act, list):
            return False, f'{path}: expected list, got {type(act).__name__}'
        if len(act) < len(exp):
            return False, f'{path}: expected at least {len(exp)} items, got {len(act)}'
        for i, v in enumerate(exp):
            ok, err = match(v, act[i], f'{path}[{i}]')
            if not ok:
                return False, err
        return True, None
    if exp != act:
        return False, f'{path}: expected {exp!r}, got {act!r}'
    return True, None

actual = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
expected = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding='utf-8'))
ok, err = match(expected, actual, '')
if not ok:
    print('report mismatch')
    print(err)
    print('actual:')
    print(json.dumps(actual, indent=2))
    raise SystemExit(1)
PY
}

extract_report_field() {
  local json_path="$1"
  local field_path="$2"
  "$PYTHON" - "$json_path" "$field_path" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
parts = [p for p in sys.argv[2].split('.') if p]
cur = doc
for p in parts:
    if isinstance(cur, list):
        cur = cur[int(p)]
    else:
        cur = cur[p]
if isinstance(cur, bool):
    print('true' if cur else 'false')
elif cur is None:
    print('null')
else:
    print(cur)
PY
}

extract_report_result_json() {
  local report_path="$1"
  local out_path="$2"
  "$PYTHON" - "$report_path" "$out_path" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
result = report.get('result')
if not isinstance(result, dict):
    raise SystemExit('missing report.result object')
out = pathlib.Path(sys.argv[2])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
PY
}

validate_cli_report() {
  local cli_path="$1"
  local out_dir="$2"
  check_schema_validate_ok \
    "contracts/spec/schemas/lp.cli.report.schema.json" \
    "$cli_path" \
    "$out_dir/cli_report.validate.run_report.json" \
    "$out_dir/cli_report.validate.cli.json"
}

validate_report_result_schema() {
  local schema_path="$1"
  local cli_path="$2"
  local out_dir="$3"
  local stem="$4"
  local result_json="$out_dir/${stem}.result.json"
  extract_report_result_json "$cli_path" "$result_json"
  check_schema_validate_ok \
    "$schema_path" \
    "$result_json" \
    "$out_dir/${stem}.validate.run_report.json" \
    "$out_dir/${stem}.validate.cli.json"
}

assert_exec_state() {
  local exec_path="$1"
  local expected_status="$2"
  local expected_outcome="$3"
  local expected_weight="$4"
  "$PYTHON" - "$exec_path" "$expected_status" "$expected_outcome" "$expected_weight" <<'PY'
import json
import pathlib
import sys
p = pathlib.Path(sys.argv[1])
status = sys.argv[2]
outcome = sys.argv[3]
weight = int(sys.argv[4])
doc = json.loads(p.read_text(encoding='utf-8'))
if doc.get('status') != status:
    raise SystemExit(f'unexpected exec status in {p}: {doc.get("status")} != {status}')
meta = doc.get('meta', {})
if meta.get('outcome') != outcome:
    raise SystemExit(f'unexpected exec outcome in {p}: {meta.get("outcome")} != {outcome}')
routing = meta.get('routing', {})
if int(routing.get('candidate_weight_pct', -1)) != weight:
    raise SystemExit(f'unexpected candidate_weight_pct in {p}: {routing.get("candidate_weight_pct")} != {weight}')
PY
}

wait_for_pause_step() {
  local exec_path="$1"
  local timeout_secs="${2:-10}"
  "$PYTHON" - "$exec_path" "$timeout_secs" <<'PY'
import json
import pathlib
import sys
import time
p = pathlib.Path(sys.argv[1])
timeout = float(sys.argv[2])
deadline = time.time() + timeout
while time.time() < deadline:
    if p.exists():
        try:
            doc = json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            time.sleep(0.05)
            continue
        for step in doc.get('steps', []):
            name = str(step.get('name', ''))
            status = str(step.get('status', ''))
            if 'pause' in name and status == 'running':
                print('pause-active')
                raise SystemExit(0)
    time.sleep(0.05)
raise SystemExit(f'timed out waiting for active pause step: {p}')
PY
}

wait_for_control_state() {
  local exec_path="$1"
  local desired="$2"
  local timeout_secs="${3:-10}"
  "$PYTHON" - "$exec_path" "$desired" "$timeout_secs" <<'PY'
import json
import pathlib
import sys
import time

p = pathlib.Path(sys.argv[1])
desired = sys.argv[2]
timeout = float(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    if p.exists():
        try:
            doc = json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            time.sleep(0.05)
            continue
        meta = doc.get('meta', {})
        if str(meta.get('control_state', '')) == desired:
            raise SystemExit(0)
    time.sleep(0.05)
raise SystemExit(f'timed out waiting for control_state={desired}: {p}')
PY
}

assert_file_exists() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "missing file: $path" >&2
    exit 1
  fi
}

incident_materialized_dir() {
  local state_dir_rel="$1"
  local app_id="$2"
  local env_name="$3"
  local incident_id="$4"
  printf '%s/%s/%s/%s\n' "$ROOT_DIR" "$state_dir_rel" "incidents/${app_id}/${env_name}" "$incident_id"
}

assert_phasec_sqlite_schema() {
  local db_path="$1"
  "$PYTHON" - "$db_path" <<'PY'
import pathlib
import sqlite3
import sys
p = pathlib.Path(sys.argv[1])
if not p.exists():
    raise SystemExit(f'missing sqlite index: {p}')
conn = sqlite3.connect(str(p))
try:
    cur = conn.execute("select name from sqlite_master where type in ('table','view')")
    names = {row[0] for row in cur.fetchall()}
finally:
    conn.close()
required = {
    'meta',
    'executions',
    'target_heads',
    'execution_steps',
    'decisions',
    'decision_reasons',
    'artifacts',
    'execution_artifacts',
    'decision_evidence',
    'indexed_records',
    'latest_execution_summary_v1',
    'incidents',
    'incident_artifacts',
    'incident_diagnostics',
    'regressions',
    'app_heads',
    'control_actions',
    'kill_switches',
}
missing = sorted(required - names)
if missing:
    raise SystemExit(f'missing sqlite objects in {p}: {missing}')
PY
}

assert_phasec_sqlite_rows() {
  local db_path="$1"
  local app_id="$2"
  local env_name="$3"
  local incident_id="$4"
  local regression_id="$5"
  "$PYTHON" - "$db_path" "$app_id" "$env_name" "$incident_id" "$regression_id" <<'PY'
import pathlib
import sqlite3
import sys
p = pathlib.Path(sys.argv[1])
app_id = sys.argv[2]
env_name = sys.argv[3]
incident_id = sys.argv[4]
regression_id = sys.argv[5]
conn = sqlite3.connect(str(p))
try:
    row = conn.execute('select app_id, environment from app_heads where app_id = ? and environment = ?', (app_id, env_name)).fetchone()
    if row is None:
        raise SystemExit(f'missing app_heads row for {app_id}/{env_name}')
    row = conn.execute('select incident_id from incidents where incident_id = ?', (incident_id,)).fetchone()
    if row is None:
        raise SystemExit(f'missing incidents row for {incident_id}')
    row = conn.execute('select regression_id from regressions where regression_id = ?', (regression_id,)).fetchone()
    if row is None:
        raise SystemExit(f'missing regressions row for {regression_id}')
    count = conn.execute('select count(*) from control_actions').fetchone()[0]
    if count <= 0:
        raise SystemExit('expected control_actions rows')
finally:
    conn.close()
PY
}

http_get_json() {
  local url="$1"
  local out_path="$2"
  "$PYTHON" - "$url" "$out_path" <<'PY'
import json
import pathlib
import urllib.request
import sys

url = sys.argv[1]
out = pathlib.Path(sys.argv[2])
with urllib.request.urlopen(url, timeout=5.0) as resp:
    body = resp.read().decode('utf-8')
json.loads(body)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(body + ("\n" if not body.endswith("\n") else ""), encoding='utf-8')
PY
}

wait_for_http() {
  local url="$1"
  local timeout_secs="${2:-10}"
  "$PYTHON" - "$url" "$timeout_secs" <<'PY'
import sys
import time
import urllib.request
url = sys.argv[1]
timeout = float(sys.argv[2])
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            if resp.status == 200:
                raise SystemExit(0)
    except Exception:
        time.sleep(0.1)
raise SystemExit(f'timed out waiting for HTTP endpoint: {url}')
PY
}

prepare_accepted_state() {
  local case_name="$1"
  local state_dir_rel="$2"
  local out_dir="$PHASEC_TMP/$case_name"
  mkdir -p "$out_dir"
  rm -rf "$ROOT_DIR/$state_dir_rel"
  mkdir -p "$ROOT_DIR/$state_dir_rel"

  run_x07lp \
    "$out_dir/deploy_accept.run_report.json" \
    "$out_dir/deploy_accept.cli.json" \
    deploy accept \
    --pack-dir "$PACK_DIR" \
    --pack-manifest "$PACK_MANIFEST" \
    --change "$PHASEB_CHANGE" \
    --state-dir "$state_dir_rel" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json

  validate_cli_report "$out_dir/deploy_accept.cli.json" "$out_dir"

  local exec_id
  exec_id="$(extract_report_field "$out_dir/deploy_accept.cli.json" result.exec_id)"
  check_schema_validate_ok \
    "contracts/spec/schemas/lp.deploy.execution.schema.json" \
    "$state_dir_rel/deploy/${exec_id}.json" \
    "$out_dir/deploy_accept.validate_exec.run_report.json" \
    "$out_dir/deploy_accept.validate_exec.cli.json"
  printf '%s\n' "$exec_id"
}

prepare_promoted_execution() {
  local state_dir_rel="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  local exec_id
  exec_id="$(prepare_accepted_state "prepare_promoted_$(basename "$out_dir")" "$state_dir_rel")"
  run_x07lp \
    "$out_dir/deploy_run.run_report.json" \
    "$out_dir/deploy_run.cli.json" \
    deploy run \
    --deployment-id "$exec_id" \
    --plan spec/fixtures/phaseB/promote/deploy.plan.json \
    --metrics-dir spec/fixtures/phaseB/promote \
    --pause-scale 0 \
    --state-dir "$state_dir_rel" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
  validate_cli_report "$out_dir/deploy_run.cli.json" "$out_dir"
  assert_exec_state "$ROOT_DIR/$state_dir_rel/deploy/${exec_id}.json" completed promoted 100
  printf '%s\n' "$exec_id"
}

prepare_rollback_execution() {
  local state_dir_rel="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  local exec_id
  exec_id="$(prepare_accepted_state "prepare_rollback_$(basename "$out_dir")" "$state_dir_rel")"
  run_x07lp \
    "$out_dir/deploy_run.run_report.json" \
    "$out_dir/deploy_run.cli.json" \
    deploy run \
    --deployment-id "$exec_id" \
    --plan spec/fixtures/phaseB/rollback/deploy.plan.json \
    --metrics-dir spec/fixtures/phaseB/rollback \
    --pause-scale 0 \
    --state-dir "$state_dir_rel" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
  validate_cli_report "$out_dir/deploy_run.cli.json" "$out_dir"
  assert_exec_state "$ROOT_DIR/$state_dir_rel/deploy/${exec_id}.json" completed rolled_back 0
  printf '%s\n' "$exec_id"
}

echo "case: baseline promote"
PROMOTE_STATE_REL="_tmp/ci_phaseC/promote_state"
PROMOTE_DIR="$PHASEC_TMP/promote"
mkdir -p "$PROMOTE_DIR"
PROMOTE_EXEC_ID="$(prepare_promoted_execution "$PROMOTE_STATE_REL" "$PROMOTE_DIR")"
echo "ok: baseline promote"

echo "case: incident_capture_5xx"
INCIDENT_5XX_DIR="$PHASEC_TMP/incident_capture_5xx"
mkdir -p "$INCIDENT_5XX_DIR"
run_x07lp \
  "$INCIDENT_5XX_DIR/incident_capture.run_report.json" \
  "$INCIDENT_5XX_DIR/incident_capture.cli.json" \
  incident capture \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --reason fixture_http_5xx \
  --request spec/fixtures/phaseC/common/request.envelope.json \
  --response spec/fixtures/phaseC/common/response.500.envelope.json \
  --trace spec/fixtures/phaseC/common/trace.json \
  --classification http_5xx \
  --source router \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752005000 \
  --json
validate_cli_report "$INCIDENT_5XX_DIR/incident_capture.cli.json" "$INCIDENT_5XX_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.incident.query.result.schema.json" "$INCIDENT_5XX_DIR/incident_capture.cli.json" "$INCIDENT_5XX_DIR" "incident_capture"
assert_report_matches_template "$INCIDENT_5XX_DIR/incident_capture.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/incident_capture_5xx/expected/incident.capture.report.json"
INCIDENT_5XX_ID="$(extract_report_field "$INCIDENT_5XX_DIR/incident_capture.cli.json" result.incident_id)"
INCIDENT_5XX_DIR_PATH="$ROOT_DIR/$PROMOTE_STATE_REL/incidents/app_min/staging/${INCIDENT_5XX_ID}"
assert_file_exists "$INCIDENT_5XX_DIR_PATH/incident.bundle.json"
assert_file_exists "$INCIDENT_5XX_DIR_PATH/incident.meta.local.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.incident.bundle.schema.json" \
  "$PROMOTE_STATE_REL/incidents/app_min/staging/${INCIDENT_5XX_ID}/incident.bundle.json" \
  "$INCIDENT_5XX_DIR/incident_bundle.validate.run_report.json" \
  "$INCIDENT_5XX_DIR/incident_bundle.validate.cli.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.incident.bundle.meta.local.schema.json" \
  "$PROMOTE_STATE_REL/incidents/app_min/staging/${INCIDENT_5XX_ID}/incident.meta.local.json" \
  "$INCIDENT_5XX_DIR/incident_meta.validate.run_report.json" \
  "$INCIDENT_5XX_DIR/incident_meta.validate.cli.json"
echo "ok: incident_capture_5xx"

echo "case: incident_query"
INCIDENT_QUERY_DIR="$PHASEC_TMP/incident_query"
mkdir -p "$INCIDENT_QUERY_DIR"
run_x07lp \
  "$INCIDENT_QUERY_DIR/incident_list.run_report.json" \
  "$INCIDENT_QUERY_DIR/incident_list.cli.json" \
  incident list \
  --app-id app_min \
  --env staging \
  --limit 10 \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$INCIDENT_QUERY_DIR/incident_list.cli.json" "$INCIDENT_QUERY_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.incident.query.result.schema.json" "$INCIDENT_QUERY_DIR/incident_list.cli.json" "$INCIDENT_QUERY_DIR" "incident_list"
assert_report_matches_template "$INCIDENT_QUERY_DIR/incident_list.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/incident_capture_5xx/expected/incident.list.report.json"

run_x07lp \
  "$INCIDENT_QUERY_DIR/incident_get.run_report.json" \
  "$INCIDENT_QUERY_DIR/incident_get.cli.json" \
  incident get \
  --incident-id "$INCIDENT_5XX_ID" \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$INCIDENT_QUERY_DIR/incident_get.cli.json" "$INCIDENT_QUERY_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.incident.query.result.schema.json" "$INCIDENT_QUERY_DIR/incident_get.cli.json" "$INCIDENT_QUERY_DIR" "incident_get"
assert_report_matches_template "$INCIDENT_QUERY_DIR/incident_get.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/incident_capture_5xx/expected/incident.get.report.json"
echo "ok: incident_query"

echo "case: incident_capture_slo_rollback"
ROLLBACK_STATE_REL="_tmp/ci_phaseC/rollback_state"
ROLLBACK_DIR="$PHASEC_TMP/incident_capture_slo_rollback"
mkdir -p "$ROLLBACK_DIR"
ROLLBACK_EXEC_ID="$(prepare_rollback_execution "$ROLLBACK_STATE_REL" "$ROLLBACK_DIR")"
run_x07lp \
  "$ROLLBACK_DIR/incident_list.run_report.json" \
  "$ROLLBACK_DIR/incident_list.cli.json" \
  incident list \
  --deployment-id "$ROLLBACK_EXEC_ID" \
  --limit 10 \
  --state-dir "$ROLLBACK_STATE_REL" \
  --json
validate_cli_report "$ROLLBACK_DIR/incident_list.cli.json" "$ROLLBACK_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.incident.query.result.schema.json" "$ROLLBACK_DIR/incident_list.cli.json" "$ROLLBACK_DIR" "incident_list"
assert_report_matches_template "$ROLLBACK_DIR/incident_list.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/incident_capture_slo_rollback/expected/incident.list.report.json"
echo "ok: incident_capture_slo_rollback"

echo "case: regression_from_incident"
REGRESSION_DIR="$PHASEC_TMP/regression_from_incident"
mkdir -p "$REGRESSION_DIR"
run_x07lp \
  "$REGRESSION_DIR/regress.run_report.json" \
  "$REGRESSION_DIR/regress.cli.json" \
  regress from-incident \
  --incident-id "$INCIDENT_5XX_ID" \
  --name phasec_http_5xx \
  --out-dir _tmp/ci_phaseC/generated_regression \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752010000 \
  --json
validate_cli_report "$REGRESSION_DIR/regress.cli.json" "$REGRESSION_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.regression.run.result.schema.json" "$REGRESSION_DIR/regress.cli.json" "$REGRESSION_DIR" "regress"
assert_report_matches_template "$REGRESSION_DIR/regress.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/regression_from_incident/expected/regress.from_incident.report.json"
REGRESSION_ID="$(extract_report_field "$REGRESSION_DIR/regress.cli.json" result.regression_id)"
echo "ok: regression_from_incident"

echo "case: app_list"
APP_LIST_DIR="$PHASEC_TMP/app_list"
mkdir -p "$APP_LIST_DIR"
run_x07lp \
  "$APP_LIST_DIR/app_list.run_report.json" \
  "$APP_LIST_DIR/app_list.cli.json" \
  app list \
  --state-dir "$PROMOTE_STATE_REL" \
  --rebuild-index \
  --json
validate_cli_report "$APP_LIST_DIR/app_list.cli.json" "$APP_LIST_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.app.list.result.schema.json" "$APP_LIST_DIR/app_list.cli.json" "$APP_LIST_DIR" "app_list"
assert_report_matches_template "$APP_LIST_DIR/app_list.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/app_list/expected/app.list.report.json"
echo "ok: app_list"

echo "case: pause_and_rerun"
PAUSE_STATE_REL="_tmp/ci_phaseC/pause_state"
PAUSE_DIR="$PHASEC_TMP/pause_and_rerun"
mkdir -p "$PAUSE_DIR"
PAUSE_EXEC_ID="$(prepare_accepted_state pause_and_rerun "$PAUSE_STATE_REL")"
(
  run_x07lp \
    "$PAUSE_DIR/deploy_run.run_report.json" \
    "$PAUSE_DIR/deploy_run.cli.json" \
    deploy run \
    --deployment-id "$PAUSE_EXEC_ID" \
    --plan spec/fixtures/phaseC/pause_and_rerun/deploy.plan.json \
    --metrics-dir spec/fixtures/phaseB/stop_during_pause \
    --pause-scale 0.2 \
    --state-dir "$PAUSE_STATE_REL" \
    --now-unix-ms 1762752015000 \
    --json
) &
PAUSE_RUN_PID=$!
PIDS+=("$PAUSE_RUN_PID")
wait_for_pause_step "$ROOT_DIR/$PAUSE_STATE_REL/deploy/${PAUSE_EXEC_ID}.json" 20

run_x07lp \
  "$PAUSE_DIR/deploy_pause.run_report.json" \
  "$PAUSE_DIR/deploy_pause.cli.json" \
  deploy pause \
  --deployment-id "$PAUSE_EXEC_ID" \
  --reason fixture_pause \
  --state-dir "$PAUSE_STATE_REL" \
  --now-unix-ms 1762752016000 \
  --json
validate_cli_report "$PAUSE_DIR/deploy_pause.cli.json" "$PAUSE_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$PAUSE_DIR/deploy_pause.cli.json" "$PAUSE_DIR" "deploy_pause"
assert_report_matches_template "$PAUSE_DIR/deploy_pause.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/pause_and_rerun/expected/deploy.pause.report.json"
wait_for_control_state "$ROOT_DIR/$PAUSE_STATE_REL/deploy/${PAUSE_EXEC_ID}.json" paused 10
wait "$PAUSE_RUN_PID" || true
PIDS=("${PIDS[@]/$PAUSE_RUN_PID}")

run_x07lp \
  "$PAUSE_DIR/deploy_rerun.run_report.json" \
  "$PAUSE_DIR/deploy_rerun.cli.json" \
  deploy rerun \
  --deployment-id "$PAUSE_EXEC_ID" \
  --from-step 1 \
  --reason fixture_rerun \
  --state-dir "$PAUSE_STATE_REL" \
  --now-unix-ms 1762752017000 \
  --json
validate_cli_report "$PAUSE_DIR/deploy_rerun.cli.json" "$PAUSE_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$PAUSE_DIR/deploy_rerun.cli.json" "$PAUSE_DIR" "deploy_rerun"
assert_report_matches_template "$PAUSE_DIR/deploy_rerun.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/pause_and_rerun/expected/deploy.rerun.report.json"
RERUN_EXEC_ID="$(extract_report_field "$PAUSE_DIR/deploy_rerun.cli.json" result.new_execution_id)"
assert_file_exists "$ROOT_DIR/$PAUSE_STATE_REL/deploy/${RERUN_EXEC_ID}.json"
echo "ok: pause_and_rerun"

echo "case: kill_switch"
KILL_DIR="$PHASEC_TMP/kill_switch"
mkdir -p "$KILL_DIR"
run_x07lp \
  "$KILL_DIR/app_kill.run_report.json" \
  "$KILL_DIR/app_kill.cli.json" \
  app kill \
  --app-id app_min \
  --env staging \
  --reason fixture_app_kill \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752020000 \
  --json
validate_cli_report "$KILL_DIR/app_kill.cli.json" "$KILL_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$KILL_DIR/app_kill.cli.json" "$KILL_DIR" "app_kill"
assert_report_matches_template "$KILL_DIR/app_kill.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/kill_switch/expected/app.kill.report.json"

run_x07lp \
  "$KILL_DIR/app_unkill.run_report.json" \
  "$KILL_DIR/app_unkill.cli.json" \
  app unkill \
  --app-id app_min \
  --env staging \
  --reason fixture_app_unkill \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752021000 \
  --json
validate_cli_report "$KILL_DIR/app_unkill.cli.json" "$KILL_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$KILL_DIR/app_unkill.cli.json" "$KILL_DIR" "app_unkill"
assert_report_matches_template "$KILL_DIR/app_unkill.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/kill_switch/expected/app.unkill.report.json"

run_x07lp \
  "$KILL_DIR/platform_kill.run_report.json" \
  "$KILL_DIR/platform_kill.cli.json" \
  platform kill \
  --reason fixture_platform_kill \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752022000 \
  --json
validate_cli_report "$KILL_DIR/platform_kill.cli.json" "$KILL_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$KILL_DIR/platform_kill.cli.json" "$KILL_DIR" "platform_kill"
assert_report_matches_template "$KILL_DIR/platform_kill.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/kill_switch/expected/platform.kill.report.json"

run_x07lp \
  "$KILL_DIR/platform_unkill.run_report.json" \
  "$KILL_DIR/platform_unkill.cli.json" \
  platform unkill \
  --reason fixture_platform_unkill \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms 1762752023000 \
  --json
validate_cli_report "$KILL_DIR/platform_unkill.cli.json" "$KILL_DIR"
validate_report_result_schema "contracts/spec/schemas/lp.control.action.result.schema.json" "$KILL_DIR/platform_unkill.cli.json" "$KILL_DIR" "platform_unkill"
assert_report_matches_template "$KILL_DIR/platform_unkill.cli.json" "$ROOT_DIR/spec/fixtures/phaseC/kill_switch/expected/platform.unkill.report.json"
echo "ok: kill_switch"

echo "case: ui_smoke"
UI_DIR="$PHASEC_TMP/ui"
mkdir -p "$UI_DIR"
(
  cd "$ROOT_DIR"
  scripts/x07lp-driver ui-serve --addr "$UI_ADDR" --state-dir "$PROMOTE_STATE_REL" >"$UI_DIR/x07lpd.log" 2>&1
) &
UI_PID=$!
PIDS+=("$UI_PID")
wait_for_http "$UI_BASE_URL/api/apps" 15

http_get_json "$UI_BASE_URL/api/apps" "$UI_DIR/api.apps.json"
assert_report_matches_template "$UI_DIR/api.apps.json" "$ROOT_DIR/spec/fixtures/phaseC/ui/expected/api.apps.report.json"

http_get_json "$UI_BASE_URL/api/incidents/${INCIDENT_5XX_ID}" "$UI_DIR/api.incident.get.json"
assert_report_matches_template "$UI_DIR/api.incident.get.json" "$ROOT_DIR/spec/fixtures/phaseC/ui/expected/api.incident.get.report.json"

kill "$UI_PID" >/dev/null 2>&1 || true
wait "$UI_PID" >/dev/null 2>&1 || true
PIDS=("${PIDS[@]/$UI_PID}")
echo "ok: ui_smoke"

echo "case: phasec sqlite"
PHASEC_DB="$ROOT_DIR/$PROMOTE_STATE_REL/index/phasec.sqlite"
assert_phasec_sqlite_schema "$PHASEC_DB"
assert_phasec_sqlite_rows "$PHASEC_DB" app_min staging "$INCIDENT_5XX_ID" "$REGRESSION_ID"
echo "ok: phasec sqlite"

echo "ok: phaseC"
