#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/ci/use_workspace_x07_bins.sh"
DRIVER_MANIFEST="$ROOT_DIR/tools/x07lp-driver/Cargo.toml"
DRIVER_BIN="$ROOT_DIR/tools/x07lp-driver/target/debug/x07lp-driver"

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "python not found on PATH" >&2
  exit 1
fi

cargo build --manifest-path "$DRIVER_MANIFEST" >/dev/null

CURL_BIN="${CURL_BIN:-curl}"
DAEMON_ADDR="${X07LP_PHASED_OSS_DAEMON_ADDR:-127.0.0.1:17443}"
REMOTE_BASE_URL="${X07LP_PHASED_OSS_BASE_URL:-http://${DAEMON_ADDR}}"
OCI_REGISTRY="${X07LP_PHASED_OSS_OCI_REGISTRY:-127.0.0.1:15000}"
BEARER_TOKEN="${X07LP_PHASED_OSS_BEARER_TOKEN:-x07lp-oss-dev-token}"
STACK_COMPOSE_FILE="${X07LP_PHASED_OSS_COMPOSE_FILE:-examples/targets/wasmcloud/docker-compose.yml}"
STACK_PROJECT="${X07LP_PHASED_OSS_STACK_PROJECT:-x07_phased_oss}"
TARGET_NAME="${X07LP_PHASED_OSS_TARGET_NAME:-phaseD-oss-main}"
CAP_MISMATCH_TARGET="${X07LP_PHASED_OSS_CAP_MISMATCH_TARGET:-phaseD-oss-cap-mismatch}"
MISSING_SECRET_TARGET="${X07LP_PHASED_OSS_MISSING_SECRET_TARGET:-phaseD-oss-missing-secret}"
TELEMETRY_COLLECTOR_URL="${X07LP_PHASED_OSS_OTLP_URL:-http://127.0.0.1:4318}"

if [ -n "${X07LP_PHASED_OSS_REMOTE_MODE:-}" ]; then
  REMOTE_MODE="${X07LP_PHASED_OSS_REMOTE_MODE}"
elif [ -f "${ROOT_DIR}/${STACK_COMPOSE_FILE}" ] && command -v docker >/dev/null 2>&1; then
  REMOTE_MODE="compose"
else
  REMOTE_MODE="local"
fi

TMP_DIR="${ROOT_DIR}/_tmp/ci_phaseD_oss"
PROFILE_PATH="${TMP_DIR}/${TARGET_NAME}.target.json"
CAP_MISMATCH_PROFILE_PATH="${TMP_DIR}/${CAP_MISMATCH_TARGET}.target.json"
MISSING_SECRET_PROFILE_PATH="${TMP_DIR}/${MISSING_SECRET_TARGET}.target.json"
TOKEN_DIR="${HOME}/.config/x07lp/tokens"
TOKEN_PATH="${TOKEN_DIR}/${TARGET_NAME}.token"
CAP_MISMATCH_TOKEN_PATH="${TOKEN_DIR}/${CAP_MISMATCH_TARGET}.token"
MISSING_SECRET_TOKEN_PATH="${TOKEN_DIR}/${MISSING_SECRET_TARGET}.token"
OTLP_EXPORT_DIR="${TMP_DIR}/otel-output"
OTLP_EXPORT_FILE="${OTLP_EXPORT_DIR}/collector-metrics.jsonl"
REMOTE_SECRET_STORE_PATH="${TMP_DIR}/remote-secret-store.json"

PHASEA_PACK="spec/fixtures/phaseA/pack_min/app.pack.json"
PHASEA_PACK_BAD="spec/fixtures/phaseA/pack_min/app.pack.bad.json"
PHASEB_CHANGE="spec/fixtures/phaseB/common/change_request.app_min.json"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$TOKEN_DIR" "$OTLP_EXPORT_DIR"

PIDS=()
cleanup() {
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      (cd "$ROOT_DIR" && docker compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" down -v >/dev/null 2>&1 || true)
    elif command -v docker-compose >/dev/null 2>&1; then
      (cd "$ROOT_DIR" && docker-compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" down -v >/dev/null 2>&1 || true)
    fi
  fi
  for pid in "${PIDS[@]:-}"; do
    if [ -n "${pid:-}" ] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

dc() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" "$@"
  else
    echo "docker compose not available" >&2
    exit 1
  fi
}

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

def find_solve_output_b64(node):
    if isinstance(node, dict):
        if isinstance(node.get('solve_output_b64'), str):
            return node['solve_output_b64']
        solve = node.get('solve')
        if isinstance(solve, dict) and isinstance(solve.get('solve_output_b64'), str):
            return solve['solve_output_b64']
        result = node.get('result')
        if isinstance(result, dict):
            stdout_json = result.get('stdout_json')
            if isinstance(stdout_json, dict):
                solve = stdout_json.get('solve')
                if isinstance(solve, dict) and isinstance(solve.get('solve_output_b64'), str):
                    return solve['solve_output_b64']
        report2 = node.get('report')
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
  local run_report_path="$1"
  local cli_json_path="$2"
  shift 2
  mkdir -p "$(dirname "$run_report_path")" "$(dirname "$cli_json_path")"
  local translated=()
  case "${1:-} ${2:-}" in
    "deploy accept") translated=(accept "${@:3}") ;;
    "deploy run") translated=(run "${@:3}") ;;
    "deploy query") translated=(query "${@:3}") ;;
    "deploy status") translated=(status "${@:3}") ;;
    "deploy stop") translated=(stop "${@:3}") ;;
    "deploy rollback") translated=(rollback "${@:3}") ;;
    "deploy pause") translated=(pause "${@:3}") ;;
    "deploy rerun") translated=(rerun "${@:3}") ;;
    "incident capture") translated=(incident-capture "${@:3}") ;;
    "incident list") translated=(incident-list "${@:3}") ;;
    "incident get") translated=(incident-get "${@:3}") ;;
    "regress from-incident") translated=(regress-from-incident "${@:3}") ;;
    "target add") translated=(target-add "${@:3}") ;;
    "target list") translated=(target-list "${@:3}") ;;
    "target inspect") translated=(target-inspect "${@:3}") ;;
    "target use") translated=(target-use "${@:3}") ;;
    "target remove") translated=(target-remove "${@:3}") ;;
    "schema validate")
      (
        cd "$ROOT_DIR"
        x07 schema validate "${@:3}" >"$cli_json_path"
      )
      cp "$cli_json_path" "$run_report_path"
      return 0
      ;;
    *)
      echo "unsupported phaseD-oss command: $*" >&2
      return 1
      ;;
  esac
  (
    cd "$ROOT_DIR"
    "$DRIVER_BIN" "${translated[@]}" >"$cli_json_path"
  )
  cp "$cli_json_path" "$run_report_path"
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
  local run_report_path="$3"
  local cli_json_path="$4"
  "$PYTHON" - "$schema_path" "$in_path" "$run_report_path" "$cli_json_path" <<'PY'
import json
import pathlib
import sys
from jsonschema import Draft202012Validator

schema = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
instance = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding='utf-8'))
Draft202012Validator(schema).validate(instance)
report = {
    "command": "schema validate",
    "diagnostics": [],
    "exit_code": 0,
    "ok": True,
    "result": {
        "ok": True,
        "schema": sys.argv[1],
        "input": sys.argv[2],
    },
    "schema_version": "lp.cli.report@0.1.0",
}
for path in sys.argv[3:]:
    pathlib.Path(path).write_text(json.dumps(report), encoding='utf-8')
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
    print(err)
    print(json.dumps(actual, indent=2))
    raise SystemExit(1)
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
  local report_path="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  check_schema_validate_ok \
    "contracts/spec/schemas/lp.cli.report.schema.json" \
    "$report_path" \
    "$out_dir/cli_report.validate.run_report.json" \
    "$out_dir/cli_report.validate.cli.json"
}

validate_report_result_schema() {
  local schema_path="$1"
  local cli_report_path="$2"
  local out_dir="$3"
  local stem="$4"
  mkdir -p "$out_dir"
  local result_json="${out_dir}/${stem}.result.json"
  extract_report_result_json "$cli_report_path" "$result_json"
  check_schema_validate_ok \
    "$schema_path" \
    "$result_json" \
    "$out_dir/${stem}.validate.run_report.json" \
    "$out_dir/${stem}.validate.cli.json"
}

write_token() {
  local path="$1"
  printf '%s' "$BEARER_TOKEN" >"$path"
  chmod 600 "$path"
}

render_target_profile() {
  local template_path="$1"
  local out_path="$2"
  local name="$3"
  local token_path="$4"
  local expected_caps="${5:-}"
  "$PYTHON" - "$template_path" "$out_path" "$name" "$REMOTE_BASE_URL" "$OCI_REGISTRY" "$token_path" "$expected_caps" "$TELEMETRY_COLLECTOR_URL" <<'PY'
import json
import pathlib
import sys
template = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
name = sys.argv[3]
base_url = sys.argv[4]
oci_registry = sys.argv[5]
token_path = sys.argv[6]
expected_caps = sys.argv[7]
telemetry_collector = sys.argv[8]
doc = json.loads(template.read_text(encoding='utf-8'))

def replace(node):
    if isinstance(node, dict):
        return {k: replace(v) for k, v in node.items()}
    if isinstance(node, list):
        return [replace(v) for v in node]
    if node == '__NAME__':
        return name
    if node == '__BASE_URL__':
        return base_url
    if node == '__OCI_REGISTRY__':
        return oci_registry
    if node == '__TOKEN_REF__':
        return f'file://{token_path}'
    if node == '__EXPECTED_CAPABILITIES_DIGEST__':
        return expected_caps or 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    if node == '__TELEMETRY_COLLECTOR__':
        return telemetry_collector
    return node

doc = replace(doc)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8')
PY
}

wait_for_http() {
  local url="$1"
  local timeout_secs="${2:-30}"
  local deadline=$((SECONDS + timeout_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if "$CURL_BIN" -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $url" >&2
  exit 1
}

wait_for_http_statuses() {
  local url="$1"
  local allowed_csv="$2"
  local timeout_secs="${3:-30}"
  local deadline=$((SECONDS + timeout_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local code
    code="$("$CURL_BIN" -sS -o /dev/null -w '%{http_code}' "$url" || true)"
    IFS=',' read -r -a allowed_codes <<<"$allowed_csv"
    for allowed in "${allowed_codes[@]}"; do
      if [ "$code" = "$allowed" ]; then
        return 0
      fi
    done
    sleep 1
  done
  echo "timed out waiting for $url with allowed statuses [$allowed_csv]" >&2
  exit 1
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local timeout_secs="${3:-30}"
  local deadline=$((SECONDS + timeout_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if "$PYTHON" - "$host" "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
with socket.create_connection((host, port), timeout=1):
    pass
PY
    then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for tcp://${host}:${port}" >&2
  exit 1
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

fetch_capabilities() {
  local out_path="$1"
  "$CURL_BIN" -fsS \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    "${REMOTE_BASE_URL}/v1/capabilities" \
    >"$out_path"
}

fetch_remote_stream() {
  local endpoint="$1"
  local query="$2"
  local out_path="$3"
  "$CURL_BIN" -fsS \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    "${REMOTE_BASE_URL}/${endpoint}?${query}" \
    >"$out_path"
}

assert_report_items_non_empty() {
  local cli_report_path="$1"
  "$PYTHON" - "$cli_report_path" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
items = doc.get('result', {}).get('items')
if not isinstance(items, list) or not items:
    raise SystemExit(f'expected non-empty result.items in {sys.argv[1]}')
PY
}

assert_negative_code() {
  local report_path="$1"
  local expected_code="$2"
  "$PYTHON" - "$report_path" "$expected_code" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
codes = []
for diag in doc.get('diagnostics', []):
    if isinstance(diag, dict) and isinstance(diag.get('code'), str):
        codes.append(diag['code'])
if sys.argv[2] not in codes:
    raise SystemExit(f'missing diagnostic {sys.argv[2]} in {codes}')
PY
}

normalize_remote_query_full() {
  local cli_report_path="$1"
  local out_path="$2"
  "$PYTHON" - "$cli_report_path" "$out_path" <<'PY'
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
result = report.get('result', {})
steps = result.get('steps', [])
decisions = result.get('decisions', [])
analysis = []
for step in steps:
    decision = step.get('analysis_decision')
    if decision and decision not in analysis:
        analysis.append(decision)
reason_codes = []
for decision in decisions:
    for reason in decision.get('reasons', []):
        code = reason.get('code')
        if isinstance(code, str) and code not in reason_codes:
            reason_codes.append(code)
normalized = {
    "schema_version": "lp.deploy.query.result.normalized@0.1.0",
    "target": result.get('target'),
    "status": result.get('status'),
    "outcome": result.get('outcome'),
    "current_weight_pct": result.get('current_weight_pct'),
    "analysis_decisions": analysis,
    "step_statuses": [step.get('status') for step in steps[:3]],
    "decision_reason_codes": reason_codes,
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(normalized, indent=2) + '\n', encoding='utf-8')
PY
}

run_remote_query_view() {
  local exec_id="$1"
  local view="$2"
  local run_report="$3"
  local cli_report="$4"
  run_x07lp "$run_report" "$cli_report" deploy query --target "$TARGET_NAME" --deployment "$exec_id" --view "$view" --json
}

start_stack() {
  if [ "$REMOTE_MODE" = "compose" ]; then
    if [ ! -f "$ROOT_DIR/$STACK_COMPOSE_FILE" ]; then
      echo "compose mode requested but missing $STACK_COMPOSE_FILE" >&2
      exit 1
    fi
    (cd "$ROOT_DIR" && X07LP_OTLP_EXPORT_HOST_DIR="$OTLP_EXPORT_DIR" dc up -d)
    (
      cd "$ROOT_DIR"
      X07LP_REMOTE_BEARER_TOKEN="$BEARER_TOKEN" \
      X07LP_REMOTE_SECRET_STORE_PATH="$REMOTE_SECRET_STORE_PATH" \
      X07LP_REMOTE_OTLP_EXPORT_PATH="$OTLP_EXPORT_FILE" \
        "$DRIVER_BIN" ui-serve --addr "$DAEMON_ADDR" --state-dir "$TMP_DIR/remote_state" >/dev/null 2>&1
    ) &
    PIDS+=("$!")
  elif [ "$REMOTE_MODE" = "local" ]; then
    (
      cd "$ROOT_DIR"
      X07LP_REMOTE_BEARER_TOKEN="$BEARER_TOKEN" \
      X07LP_REMOTE_SECRET_STORE_PATH="$REMOTE_SECRET_STORE_PATH" \
        "$DRIVER_BIN" ui-serve --addr "$DAEMON_ADDR" --state-dir "$TMP_DIR/remote_state" >/dev/null 2>&1
    ) &
    PIDS+=("$!")
  elif [ "$REMOTE_MODE" != "external" ]; then
    echo "unsupported X07LP_PHASED_OSS_REMOTE_MODE=$REMOTE_MODE" >&2
    exit 1
  fi
  wait_for_http "${REMOTE_BASE_URL}/v1/health" 60
  if [ "$REMOTE_MODE" = "compose" ]; then
    wait_for_http_statuses "http://${OCI_REGISTRY}/v2/" "200,401" 60
    wait_for_http "http://127.0.0.1:8222/varz" 60
    wait_for_tcp "127.0.0.1" "4000" 60
    wait_for_tcp "127.0.0.1" "4318" 60
  fi
}

write_token "$TOKEN_PATH"
write_token "$CAP_MISMATCH_TOKEN_PATH"
write_token "$MISSING_SECRET_TOKEN_PATH"

cat >"$REMOTE_SECRET_STORE_PATH" <<JSON
{
  "schema_version": "lp.remote.secret.store.internal@0.1.0",
  "targets": {
    "$TARGET_NAME": {
      "api_key": "ci-main-secret"
    },
    "$CAP_MISMATCH_TARGET": {
      "api_key": "ci-cap-mismatch-secret"
    },
    "$MISSING_SECRET_TARGET": {}
  }
}
JSON

render_target_profile "spec/fixtures/phaseD-oss/common/targets/main.target.template.json" "$PROFILE_PATH" "$TARGET_NAME" "$TOKEN_PATH"
render_target_profile "spec/fixtures/phaseD-oss/common/targets/cap-mismatch.target.template.json" "$CAP_MISMATCH_PROFILE_PATH" "$CAP_MISMATCH_TARGET" "$CAP_MISMATCH_TOKEN_PATH" "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
render_target_profile "spec/fixtures/phaseD-oss/common/targets/missing-secret.target.template.json" "$MISSING_SECRET_PROFILE_PATH" "$MISSING_SECRET_TARGET" "$MISSING_SECRET_TOKEN_PATH"

start_stack

CAPS_JSON="${TMP_DIR}/remote.capabilities.json"
fetch_capabilities "$CAPS_JSON"
check_schema_validate_ok \
  "contracts/spec/schemas/lp.remote.capabilities.response.schema.json" \
  "$CAPS_JSON" \
  "${TMP_DIR}/capabilities.validate.run_report.json" \
  "${TMP_DIR}/capabilities.validate.cli.json"
assert_report_matches_template \
  "$CAPS_JSON" \
  "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_capabilities/expected/v1.capabilities.json"

run_x07lp "${TMP_DIR}/target.add.run_report.json" "${TMP_DIR}/target.add.cli.json" target add --profile "$(repo_path_arg "$PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.cap_mismatch.run_report.json" "${TMP_DIR}/target.add.cap_mismatch.cli.json" target add --profile "$(repo_path_arg "$CAP_MISMATCH_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.missing_secret.run_report.json" "${TMP_DIR}/target.add.missing_secret.cli.json" target add --profile "$(repo_path_arg "$MISSING_SECRET_PROFILE_PATH")" --json
validate_cli_report "${TMP_DIR}/target.add.cli.json" "${TMP_DIR}"

run_x07lp "${TMP_DIR}/remote_promote.accept.run_report.json" "${TMP_DIR}/remote_promote.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PHASEA_PACK" --change "$PHASEB_CHANGE" --json
PROMOTE_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_promote.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
result = doc.get('result', {})
print(result.get('run_id') or result.get('pipeline_run_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_promote.run.run_report.json" "${TMP_DIR}/remote_promote.run.cli.json" \
  deploy run --target "$TARGET_NAME" --accepted-run "$PROMOTE_RUN_ID" --json
PROMOTE_EXEC_ID="$("$PYTHON" - "${TMP_DIR}/remote_promote.run.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
result = doc.get('result', {})
print(result.get('deployment_id') or result.get('exec_id') or '')
PY
)"
run_remote_query_view "$PROMOTE_EXEC_ID" "summary" "${TMP_DIR}/remote_promote.query.summary.run_report.json" "${TMP_DIR}/remote_promote.query.summary.cli.json"
run_remote_query_view "$PROMOTE_EXEC_ID" "full" "${TMP_DIR}/remote_promote.query.full.run_report.json" "${TMP_DIR}/remote_promote.query.full.cli.json"
validate_cli_report "${TMP_DIR}/remote_promote.query.summary.cli.json" "${TMP_DIR}/remote_promote.query.summary"
validate_cli_report "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full"
validate_report_result_schema "contracts/spec/schemas/lp.deploy.query.result.schema.json" "${TMP_DIR}/remote_promote.query.summary.cli.json" "${TMP_DIR}/remote_promote.query.summary" "deploy.query.summary"
validate_report_result_schema "contracts/spec/schemas/lp.deploy.query.result.schema.json" "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full" "deploy.query.full"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.summary.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_promote/expected/query.summary.report.json"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.full.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_promote/expected/query.full.report.json"
normalize_remote_query_full "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full.normalized.json"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.full.normalized.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_parity/expected/query.full.normalized.json"

fetch_remote_stream "v1/events" "exec_id=${PROMOTE_EXEC_ID}&limit=50" "${TMP_DIR}/remote_promote.events.cli.json"
fetch_remote_stream "v1/logs" "exec_id=${PROMOTE_EXEC_ID}&slot=candidate&limit=50" "${TMP_DIR}/remote_promote.logs.cli.json"
validate_cli_report "${TMP_DIR}/remote_promote.events.cli.json" "${TMP_DIR}/remote_promote.events"
validate_cli_report "${TMP_DIR}/remote_promote.logs.cli.json" "${TMP_DIR}/remote_promote.logs"
validate_report_result_schema "contracts/spec/schemas/lp.remote.events.result.schema.json" "${TMP_DIR}/remote_promote.events.cli.json" "${TMP_DIR}/remote_promote.events" "remote.events"
validate_report_result_schema "contracts/spec/schemas/lp.remote.logs.result.schema.json" "${TMP_DIR}/remote_promote.logs.cli.json" "${TMP_DIR}/remote_promote.logs" "remote.logs"
assert_report_items_non_empty "${TMP_DIR}/remote_promote.events.cli.json"
assert_report_items_non_empty "${TMP_DIR}/remote_promote.logs.cli.json"

run_x07lp "${TMP_DIR}/remote_rollback.accept.run_report.json" "${TMP_DIR}/remote_rollback.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PHASEA_PACK" --change "$PHASEB_CHANGE" --json
ROLLBACK_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_rollback.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_rollback.run.run_report.json" "${TMP_DIR}/remote_rollback.run.cli.json" \
  deploy run --target "$TARGET_NAME" --accepted-run "$ROLLBACK_RUN_ID" --fixture spec/fixtures/phaseD-oss/remote_rollback --json || true
assert_negative_code "${TMP_DIR}/remote_rollback.run.cli.json" "LP_SLO_DECISION_ROLLBACK"
assert_report_matches_template "${TMP_DIR}/remote_rollback.run.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_rollback/expected/deploy.run.report.json"
ROLLBACK_EXEC_ID="$("$PYTHON" - "${TMP_DIR}/remote_rollback.run.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('deployment_id') or doc.get('result', {}).get('exec_id') or '')
PY
)"
run_remote_query_view "$ROLLBACK_EXEC_ID" "summary" "${TMP_DIR}/remote_rollback.query.summary.run_report.json" "${TMP_DIR}/remote_rollback.query.summary.cli.json"
assert_report_matches_template "${TMP_DIR}/remote_rollback.query.summary.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_rollback/expected/query.summary.report.json"

run_x07lp "${TMP_DIR}/remote_pause.accept.run_report.json" "${TMP_DIR}/remote_pause.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PHASEA_PACK" --change "$PHASEB_CHANGE" --json
PAUSE_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_pause.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
PAUSE_EXEC_ID="$("$PYTHON" - "${TMP_DIR}/remote_pause.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('deployment_id') or doc.get('result', {}).get('exec_id') or '')
PY
)"
(
  run_x07lp "${TMP_DIR}/remote_pause.run.run_report.json" "${TMP_DIR}/remote_pause.run.cli.json" \
    deploy run --target "$TARGET_NAME" --accepted-run "$PAUSE_RUN_ID" --fixture spec/fixtures/phaseD-oss/remote_pause_rerun --json
) &
PAUSE_RUN_PID=$!
PIDS+=("$PAUSE_RUN_PID")
wait_for_pause_step "${TMP_DIR}/remote_state/deploy/${PAUSE_EXEC_ID}.json" 20
run_x07lp "${TMP_DIR}/remote_pause.control.run_report.json" "${TMP_DIR}/remote_pause.control.cli.json" \
  deploy pause --target "$TARGET_NAME" --deployment "$PAUSE_EXEC_ID" --reason "ci pause" --json
assert_report_matches_template "${TMP_DIR}/remote_pause.control.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_pause_rerun/expected/pause.report.json"
wait_for_control_state "${TMP_DIR}/remote_state/deploy/${PAUSE_EXEC_ID}.json" paused 20
wait "$PAUSE_RUN_PID" || true
run_x07lp "${TMP_DIR}/remote_rerun.control.run_report.json" "${TMP_DIR}/remote_rerun.control.cli.json" \
  deploy rerun --target "$TARGET_NAME" --deployment "$PAUSE_EXEC_ID" --reason "ci rerun" --json
assert_report_matches_template "${TMP_DIR}/remote_rerun.control.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_pause_rerun/expected/rerun.report.json"

for view in summary timeline decisions artifacts full; do
  run_remote_query_view "$PROMOTE_EXEC_ID" "$view" "${TMP_DIR}/remote_query.${view}.run_report.json" "${TMP_DIR}/remote_query.${view}.cli.json"
  assert_report_matches_template \
    "${TMP_DIR}/remote_query.${view}.cli.json" \
    "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_query/expected/query.${view}.report.json"
done

run_x07lp "${TMP_DIR}/remote_incident_capture.capture.run_report.json" "${TMP_DIR}/remote_incident_capture.capture.cli.json" \
  incident capture --target "$TARGET_NAME" --deployment "$PROMOTE_EXEC_ID" --reason "ci capture" \
  --classification http_5xx --source router \
  --request spec/fixtures/phaseC/common/request.envelope.json \
  --response spec/fixtures/phaseC/common/response.500.envelope.json \
  --trace spec/fixtures/phaseC/common/trace.json --json
assert_report_matches_template \
  "${TMP_DIR}/remote_incident_capture.capture.cli.json" \
  "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_incident_capture/expected/incident.capture.report.json"
INCIDENT_ID="$("$PYTHON" - "${TMP_DIR}/remote_incident_capture.capture.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('incident_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_regression_from_incident.regress.run_report.json" "${TMP_DIR}/remote_regression_from_incident.regress.cli.json" \
  regress from-incident --target "$TARGET_NAME" --incident-id "$INCIDENT_ID" --name "remote_http_5xx" \
  --out-dir "$TMP_DIR/remote_regress" --json
assert_report_matches_template \
  "${TMP_DIR}/remote_regression_from_incident.regress.cli.json" \
  "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_regression_from_incident/expected/regress.report.json"

run_x07lp "${TMP_DIR}/remote_missing_secret.accept.run_report.json" "${TMP_DIR}/remote_missing_secret.accept.cli.json" \
  deploy accept --target "$MISSING_SECRET_TARGET" --pack-manifest "$PHASEA_PACK" --change "$PHASEB_CHANGE" \
  --ops-profile arch/app/ops/ops_secret_allow.json --json || true
assert_negative_code "${TMP_DIR}/remote_missing_secret.accept.cli.json" "LP_REMOTE_SECRET_NOT_FOUND"
assert_report_matches_template "${TMP_DIR}/remote_missing_secret.accept.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_missing_secret/expected/deploy.accept.report.json"

run_x07lp "${TMP_DIR}/remote_upload_digest_mismatch.accept.run_report.json" "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PHASEA_PACK_BAD" --change "$PHASEB_CHANGE" --json || true
assert_negative_code "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" "LP_REMOTE_UPLOAD_DIGEST_MISMATCH"
assert_report_matches_template "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_upload_digest_mismatch/expected/deploy.accept.report.json"

run_x07lp "${TMP_DIR}/remote_capabilities_mismatch.run_report.json" "${TMP_DIR}/remote_capabilities_mismatch.cli.json" \
  deploy run --target "$CAP_MISMATCH_TARGET" --accepted-run "$PROMOTE_RUN_ID" --json || true
assert_negative_code "${TMP_DIR}/remote_capabilities_mismatch.cli.json" "LP_REMOTE_CAPABILITIES_UNSUPPORTED"
assert_report_matches_template "${TMP_DIR}/remote_capabilities_mismatch.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_capabilities_mismatch/expected/deploy.run.report.json"

run_x07lp "${TMP_DIR}/remote_lease_conflict.accept.run_report.json" "${TMP_DIR}/remote_lease_conflict.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PHASEA_PACK" --change "$PHASEB_CHANGE" --json
LEASE_CONFLICT_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_lease_conflict.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
LEASE_CONFLICT_EXEC_ID="$("$PYTHON" - "${TMP_DIR}/remote_lease_conflict.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('deployment_id') or doc.get('result', {}).get('exec_id') or '')
PY
)"
(
  run_x07lp "${TMP_DIR}/remote_lease_conflict.a.run_report.json" "${TMP_DIR}/remote_lease_conflict.a.cli.json" \
    deploy run --target "$TARGET_NAME" --accepted-run "$LEASE_CONFLICT_RUN_ID" \
    --fixture spec/fixtures/phaseD-oss/remote_pause_rerun --pause-scale 0.2 --json
) &
LEASE_CONFLICT_PID=$!
PIDS+=("$LEASE_CONFLICT_PID")
wait_for_pause_step "${TMP_DIR}/remote_state/deploy/${LEASE_CONFLICT_EXEC_ID}.json" 20
sleep 3
run_x07lp "${TMP_DIR}/remote_lease_conflict.b.run_report.json" "${TMP_DIR}/remote_lease_conflict.b.cli.json" \
  deploy run --target "$TARGET_NAME" --accepted-run "$LEASE_CONFLICT_RUN_ID" \
  --fixture spec/fixtures/phaseD-oss/remote_pause_rerun --pause-scale 0.2 --json || true
assert_negative_code "${TMP_DIR}/remote_lease_conflict.b.cli.json" "LP_REMOTE_LEASE_CONFLICT"
assert_report_matches_template "${TMP_DIR}/remote_lease_conflict.b.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_lease_conflict/expected/deploy.run.report.json"
wait "$LEASE_CONFLICT_PID" || true

run_x07lp "${TMP_DIR}/remote_incident_trace_missing.regress.run_report.json" "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" \
  regress from-incident --target "$TARGET_NAME" --incident-id incident_missing_trace --json || true
assert_negative_code "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" "LP_INCIDENT_TRACE_MISSING"
assert_report_matches_template "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_incident_trace_missing/expected/regress.report.json"

run_x07lp "${TMP_DIR}/remote_query_index_rebuild.query.run_report.json" "${TMP_DIR}/remote_query_index_rebuild.query.cli.json" \
  deploy query --target "$TARGET_NAME" --deployment "$PROMOTE_EXEC_ID" --view summary --rebuild-index --json
assert_report_matches_template "${TMP_DIR}/remote_query_index_rebuild.query.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_query_index_rebuild/expected/query.summary.report.json"

(
  cd "$ROOT_DIR"
  "$DRIVER_BIN" adapter-conformance --target "$TARGET_NAME" --state-dir "$TMP_DIR/remote_state" --json >"${TMP_DIR}/remote_conformance.cli.json"
)
cp "${TMP_DIR}/remote_conformance.cli.json" "${TMP_DIR}/remote_conformance.run_report.json"
assert_report_matches_template "${TMP_DIR}/remote_conformance.cli.json" "${ROOT_DIR}/spec/fixtures/phaseD-oss/remote_conformance/expected/adapter.conformance.report.json"

echo "phaseD-oss ci expectations passed"
