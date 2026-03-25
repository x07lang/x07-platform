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

NOW_UNIX_MS="1762147200000"
PACK_DIR="spec/fixtures/baseline/pack_min"
PACK_MANIFEST="app.pack.json"
DEPLOY_LOOP_CHANGE="spec/fixtures/deploy_loop/common/change_request.app_min.json"
DEPLOY_LOOP_TMP="${ROOT_DIR}/_tmp/ci_deploy_loop"

mkdir -p "$DEPLOY_LOOP_TMP"

CONFIG_DIR="${DEPLOY_LOOP_TMP}/config"
rm -rf "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
export X07LP_CONFIG_DIR="$CONFIG_DIR"

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
        stdout_json = doc.get('stdout_json')
        if isinstance(stdout_json, dict):
            found = find_solve_output_b64(stdout_json)
            if found:
                return found
        result = doc.get('result')
        if isinstance(result, dict):
            found = find_solve_output_b64(result)
            if found:
                return found
        report2 = doc.get('report')
        if isinstance(report2, dict):
            found = find_solve_output_b64(report2)
            if found:
                return found
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
  local argv=("$@")
  local has_target=0
  local arg
  if [ "${#argv[@]}" -gt 0 ] && [ "${argv[0]}" != "schema" ] && {
    [ "${argv[0]}" = "deploy" ] || [ "${argv[0]}" = "incident" ] || [ "${argv[0]}" = "regress" ];
  }; then
    for arg in "${argv[@]}"; do
      if [ "$arg" = "--target" ]; then
        has_target=1
        break
      fi
    done
    if [ "$has_target" -eq 0 ]; then
      argv+=(--target __local__)
    fi
  fi
  (
    cd "$ROOT_DIR"
    x07 run -- "${argv[@]}" >"$report_path"
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

validate_cli_report() {
  local cli_path="$1"
  local out_dir="$2"
  check_schema_validate_ok \
    "contracts/spec/schemas/lp.cli.report.schema.json" \
    "$cli_path" \
    "$out_dir/cli_report.validate.run_report.json" \
    "$out_dir/cli_report.validate.cli.json"
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

assert_retry_steps_present() {
  local exec_path="$1"
  "$PYTHON" - "$exec_path" <<'PY'
import json
import pathlib
import sys
p = pathlib.Path(sys.argv[1])
doc = json.loads(p.read_text(encoding='utf-8'))
steps = doc.get('steps', [])
if len(steps) < 3:
    raise SystemExit(f'expected at least 3 execution steps in retry case: {p}')
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

assert_sqlite_schema() {
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
}
missing = sorted(required - names)
if missing:
    raise SystemExit(f'missing sqlite objects in {p}: {missing}')
PY
}

assert_sqlite_rows() {
  local db_path="$1"
  local exec_id="$2"
  local app_id="$3"
  local env_name="$4"
  "$PYTHON" - "$db_path" "$exec_id" "$app_id" "$env_name" <<'PY'
import pathlib
import sqlite3
import sys
p = pathlib.Path(sys.argv[1])
exec_id = sys.argv[2]
app_id = sys.argv[3]
env_name = sys.argv[4]
conn = sqlite3.connect(str(p))
try:
    row = conn.execute('select exec_id, app_id, environment from executions where exec_id = ?', (exec_id,)).fetchone()
    if row is None:
        raise SystemExit(f'missing executions row for {exec_id}')
    row2 = conn.execute('select exec_id from target_heads where app_id = ? and environment = ?', (app_id, env_name)).fetchone()
    if row2 is None:
        raise SystemExit(f'missing target_heads row for {app_id}/{env_name}')
    count_steps = conn.execute('select count(*) from execution_steps where exec_id = ?', (exec_id,)).fetchone()[0]
    count_decisions = conn.execute('select count(*) from decisions where exec_id = ?', (exec_id,)).fetchone()[0]
    if count_steps <= 0:
        raise SystemExit(f'missing execution_steps rows for {exec_id}')
    if count_decisions <= 0:
        raise SystemExit(f'missing decisions rows for {exec_id}')
finally:
    conn.close()
PY
}

prepare_accepted_state() {
  local case_name="$1"
  local state_dir_rel="$2"
  local out_dir="$DEPLOY_LOOP_TMP/$case_name"
  mkdir -p "$out_dir"
  rm -rf "$ROOT_DIR/$state_dir_rel"
  mkdir -p "$ROOT_DIR/$state_dir_rel"

  run_x07lp \
    "$out_dir/deploy_accept.run_report.json" \
    "$out_dir/deploy_accept.cli.json" \
    deploy accept \
    --pack-dir "$PACK_DIR" \
    --pack-manifest "$PACK_MANIFEST" \
    --change "$DEPLOY_LOOP_CHANGE" \
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

echo "case: promote"
PROMOTE_STATE_REL="_tmp/ci_deploy_loop/promote_state"
PROMOTE_DIR="$DEPLOY_LOOP_TMP/promote"
mkdir -p "$PROMOTE_DIR"
PROMOTE_EXEC_ID="$(prepare_accepted_state promote "$PROMOTE_STATE_REL")"
run_x07lp \
  "$PROMOTE_DIR/deploy_run.run_report.json" \
  "$PROMOTE_DIR/deploy_run.cli.json" \
  deploy run \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --plan spec/fixtures/deploy_loop/promote/deploy.plan.json \
  --metrics-dir spec/fixtures/deploy_loop/promote \
  --pause-scale 0 \
  --state-dir "$PROMOTE_STATE_REL" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --json
validate_cli_report "$PROMOTE_DIR/deploy_run.cli.json" "$PROMOTE_DIR"
assert_report_matches_template "$PROMOTE_DIR/deploy_run.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/promote/expected/deploy.run.report.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "$PROMOTE_STATE_REL/deploy/${PROMOTE_EXEC_ID}.json" \
  "$PROMOTE_DIR/validate_exec.run_report.json" \
  "$PROMOTE_DIR/validate_exec.cli.json"
assert_exec_state "$ROOT_DIR/$PROMOTE_STATE_REL/deploy/${PROMOTE_EXEC_ID}.json" completed promoted 100
echo "ok: promote"

echo "case: rollback"
ROLLBACK_STATE_REL="_tmp/ci_deploy_loop/rollback_state"
ROLLBACK_DIR="$DEPLOY_LOOP_TMP/rollback"
mkdir -p "$ROLLBACK_DIR"
ROLLBACK_EXEC_ID="$(prepare_accepted_state rollback "$ROLLBACK_STATE_REL")"
run_x07lp \
  "$ROLLBACK_DIR/deploy_run.run_report.json" \
  "$ROLLBACK_DIR/deploy_run.cli.json" \
  deploy run \
  --deployment-id "$ROLLBACK_EXEC_ID" \
  --plan spec/fixtures/deploy_loop/rollback/deploy.plan.json \
  --metrics-dir spec/fixtures/deploy_loop/rollback \
  --pause-scale 0 \
  --state-dir "$ROLLBACK_STATE_REL" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --json
validate_cli_report "$ROLLBACK_DIR/deploy_run.cli.json" "$ROLLBACK_DIR"
assert_report_matches_template "$ROLLBACK_DIR/deploy_run.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/rollback/expected/deploy.run.report.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "$ROLLBACK_STATE_REL/deploy/${ROLLBACK_EXEC_ID}.json" \
  "$ROLLBACK_DIR/validate_exec.run_report.json" \
  "$ROLLBACK_DIR/validate_exec.cli.json"
assert_exec_state "$ROOT_DIR/$ROLLBACK_STATE_REL/deploy/${ROLLBACK_EXEC_ID}.json" completed rolled_back 0
echo "ok: rollback"

echo "case: retry_exhausted"
RETRY_STATE_REL="_tmp/ci_deploy_loop/retry_state"
RETRY_DIR="$DEPLOY_LOOP_TMP/retry_exhausted"
mkdir -p "$RETRY_DIR"
RETRY_EXEC_ID="$(prepare_accepted_state retry_exhausted "$RETRY_STATE_REL")"
run_x07lp \
  "$RETRY_DIR/deploy_run.run_report.json" \
  "$RETRY_DIR/deploy_run.cli.json" \
  deploy run \
  --deployment-id "$RETRY_EXEC_ID" \
  --plan spec/fixtures/deploy_loop/retry_exhausted/deploy.plan.json \
  --metrics-dir spec/fixtures/deploy_loop/retry_exhausted \
  --pause-scale 0 \
  --state-dir "$RETRY_STATE_REL" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --json
validate_cli_report "$RETRY_DIR/deploy_run.cli.json" "$RETRY_DIR"
assert_report_matches_template "$RETRY_DIR/deploy_run.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/retry_exhausted/expected/deploy.run.report.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "$RETRY_STATE_REL/deploy/${RETRY_EXEC_ID}.json" \
  "$RETRY_DIR/validate_exec.run_report.json" \
  "$RETRY_DIR/validate_exec.cli.json"
assert_exec_state "$ROOT_DIR/$RETRY_STATE_REL/deploy/${RETRY_EXEC_ID}.json" failed failed 5
assert_retry_steps_present "$ROOT_DIR/$RETRY_STATE_REL/deploy/${RETRY_EXEC_ID}.json"
echo "ok: retry_exhausted"

echo "case: stop_during_pause"
STOP_STATE_REL="_tmp/ci_deploy_loop/stop_state"
STOP_DIR="$DEPLOY_LOOP_TMP/stop_during_pause"
mkdir -p "$STOP_DIR"
STOP_EXEC_ID="$(prepare_accepted_state stop_during_pause "$STOP_STATE_REL")"
(
  run_x07lp \
    "$STOP_DIR/deploy_run.run_report.json" \
    "$STOP_DIR/deploy_run.cli.json" \
    deploy run \
    --deployment-id "$STOP_EXEC_ID" \
    --plan spec/fixtures/deploy_loop/stop_during_pause/deploy.plan.json \
    --metrics-dir spec/fixtures/deploy_loop/stop_during_pause \
    --pause-scale 0.05 \
    --state-dir "$STOP_STATE_REL" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
) &
STOP_RUN_PID=$!
wait_for_pause_step "$ROOT_DIR/$STOP_STATE_REL/deploy/${STOP_EXEC_ID}.json" 30
run_x07lp \
  "$STOP_DIR/deploy_stop.run_report.json" \
  "$STOP_DIR/deploy_stop.cli.json" \
  deploy stop \
  --deployment-id "$STOP_EXEC_ID" \
  --reason manual_stop_during_pause \
  --state-dir "$STOP_STATE_REL" \
  --now-unix-ms 1762147205000 \
  --json
wait "$STOP_RUN_PID" || true
validate_cli_report "$STOP_DIR/deploy_stop.cli.json" "$STOP_DIR"
assert_report_matches_template "$STOP_DIR/deploy_stop.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/stop_during_pause/expected/deploy.stop.report.json"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "$STOP_STATE_REL/deploy/${STOP_EXEC_ID}.json" \
  "$STOP_DIR/validate_exec.run_report.json" \
  "$STOP_DIR/validate_exec.cli.json"
assert_exec_state "$ROOT_DIR/$STOP_STATE_REL/deploy/${STOP_EXEC_ID}.json" aborted aborted 0
echo "ok: stop_during_pause"

echo "case: query"
QUERY_DIR="$DEPLOY_LOOP_TMP/query"
mkdir -p "$QUERY_DIR"
run_x07lp \
  "$QUERY_DIR/query_summary.run_report.json" \
  "$QUERY_DIR/query_summary.cli.json" \
  deploy query \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --view summary \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$QUERY_DIR/query_summary.cli.json" "$QUERY_DIR"
assert_report_matches_template "$QUERY_DIR/query_summary.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/query/expected/query.summary.report.json"
run_x07lp \
  "$QUERY_DIR/query_timeline.run_report.json" \
  "$QUERY_DIR/query_timeline.cli.json" \
  deploy query \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --view timeline \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$QUERY_DIR/query_timeline.cli.json" "$QUERY_DIR"
assert_report_matches_template "$QUERY_DIR/query_timeline.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/query/expected/query.timeline.report.json"
run_x07lp \
  "$QUERY_DIR/query_decisions.run_report.json" \
  "$QUERY_DIR/query_decisions.cli.json" \
  deploy query \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --view decisions \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$QUERY_DIR/query_decisions.cli.json" "$QUERY_DIR"
assert_report_matches_template "$QUERY_DIR/query_decisions.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/query/expected/query.decisions.report.json"
run_x07lp \
  "$QUERY_DIR/query_artifacts.run_report.json" \
  "$QUERY_DIR/query_artifacts.cli.json" \
  deploy query \
  --deployment-id "$PROMOTE_EXEC_ID" \
  --view artifacts \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$QUERY_DIR/query_artifacts.cli.json" "$QUERY_DIR"
assert_report_matches_template "$QUERY_DIR/query_artifacts.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/query/expected/query.artifacts.report.json"
run_x07lp \
  "$QUERY_DIR/query_latest.run_report.json" \
  "$QUERY_DIR/query_latest.cli.json" \
  deploy query \
  --app-id app_min \
  --env staging \
  --latest \
  --view full \
  --state-dir "$PROMOTE_STATE_REL" \
  --json
validate_cli_report "$QUERY_DIR/query_latest.cli.json" "$QUERY_DIR"
assert_report_matches_template "$QUERY_DIR/query_latest.cli.json" "$ROOT_DIR/spec/fixtures/deploy_loop/query/expected/query.latest.report.json"
SQLITE_DB="$ROOT_DIR/$PROMOTE_STATE_REL/index/deploy_loop.sqlite"
assert_sqlite_schema "$SQLITE_DB"
assert_sqlite_rows "$SQLITE_DB" "$PROMOTE_EXEC_ID" app_min staging
echo "ok: query"

echo "ok: deploy loop"
