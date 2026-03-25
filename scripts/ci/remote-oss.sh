#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
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
PUBLIC_GATEWAY_ADDR="${X07LP_REMOTE_OSS_DAEMON_ADDR:-localhost:17443}"
DAEMON_BIND_ADDR="${X07LP_REMOTE_OSS_DAEMON_BIND_ADDR:-127.0.0.1:17080}"
REMOTE_BASE_URL="${X07LP_REMOTE_OSS_BASE_URL:-https://${PUBLIC_GATEWAY_ADDR}}"
OCI_REGISTRY="${X07LP_REMOTE_OSS_OCI_REGISTRY:-localhost:15443}"
BEARER_TOKEN="${X07LP_REMOTE_OSS_BEARER_TOKEN:-x07lp-oss-dev-token}"
OCI_USERNAME="${X07LP_REMOTE_OSS_OCI_USERNAME:-x07lp-oci-dev-user}"
OCI_PASSWORD="${X07LP_REMOTE_OSS_OCI_PASSWORD:-x07lp-oci-dev-pass}"
STACK_COMPOSE_FILE="${X07LP_REMOTE_OSS_COMPOSE_FILE:-examples/targets/wasmcloud/docker-compose.yml}"
STACK_PROJECT="${X07LP_REMOTE_OSS_STACK_PROJECT:-x07_remote_oss}"
TARGET_NAME="${X07LP_REMOTE_OSS_TARGET_NAME:-remote-oss-main}"
CAP_MISMATCH_TARGET="${X07LP_REMOTE_OSS_CAP_MISMATCH_TARGET:-remote-oss-cap-mismatch}"
MISSING_SECRET_TARGET="${X07LP_REMOTE_OSS_MISSING_SECRET_TARGET:-remote-oss-missing-secret}"
PINNED_TARGET="${X07LP_REMOTE_OSS_PINNED_TARGET:-remote-oss-pinned}"
BAD_CA_TARGET="${X07LP_REMOTE_OSS_BAD_CA_TARGET:-remote-oss-bad-ca}"
BAD_PIN_TARGET="${X07LP_REMOTE_OSS_BAD_PIN_TARGET:-remote-oss-bad-pin}"
BAD_OCI_AUTH_TARGET="${X07LP_REMOTE_OSS_BAD_OCI_AUTH_TARGET:-remote-oss-bad-oci-auth}"
BAD_OCI_TLS_TARGET="${X07LP_REMOTE_OSS_BAD_OCI_TLS_TARGET:-remote-oss-bad-oci-tls}"
TELEMETRY_COLLECTOR_URL="${X07LP_REMOTE_OSS_OTLP_URL:-http://127.0.0.1:4318}"
X07LP_REMOTE_SYNTHETIC_TELEMETRY="${X07LP_REMOTE_SYNTHETIC_TELEMETRY:-0}"
export X07LP_REMOTE_SYNTHETIC_TELEMETRY

if [ -n "${X07LP_REMOTE_OSS_REMOTE_MODE:-}" ]; then
  REMOTE_MODE="${X07LP_REMOTE_OSS_REMOTE_MODE}"
elif [ -f "${ROOT_DIR}/${STACK_COMPOSE_FILE}" ] && command -v docker >/dev/null 2>&1; then
  REMOTE_MODE="compose"
else
  REMOTE_MODE="local"
fi

if [ "$REMOTE_MODE" = "local" ] && [ -z "${X07LP_REMOTE_OSS_BASE_URL:-}" ]; then
  REMOTE_BASE_URL="http://${PUBLIC_GATEWAY_ADDR}"
fi

TMP_DIR="${ROOT_DIR}/_tmp/ci_remote_oss"
PROFILE_PATH="${TMP_DIR}/${TARGET_NAME}.target.json"
CAP_MISMATCH_PROFILE_PATH="${TMP_DIR}/${CAP_MISMATCH_TARGET}.target.json"
MISSING_SECRET_PROFILE_PATH="${TMP_DIR}/${MISSING_SECRET_TARGET}.target.json"
PINNED_PROFILE_PATH="${TMP_DIR}/${PINNED_TARGET}.target.json"
BAD_CA_PROFILE_PATH="${TMP_DIR}/${BAD_CA_TARGET}.target.json"
BAD_PIN_PROFILE_PATH="${TMP_DIR}/${BAD_PIN_TARGET}.target.json"
BAD_OCI_AUTH_PROFILE_PATH="${TMP_DIR}/${BAD_OCI_AUTH_TARGET}.target.json"
BAD_OCI_TLS_PROFILE_PATH="${TMP_DIR}/${BAD_OCI_TLS_TARGET}.target.json"
TOKEN_DIR="${TMP_DIR}/tokens"
TOKEN_PATH="${TOKEN_DIR}/${TARGET_NAME}.token"
CAP_MISMATCH_TOKEN_PATH="${TOKEN_DIR}/${CAP_MISMATCH_TARGET}.token"
MISSING_SECRET_TOKEN_PATH="${TOKEN_DIR}/${MISSING_SECRET_TARGET}.token"
PINNED_TOKEN_PATH="${TOKEN_DIR}/${PINNED_TARGET}.token"
BAD_CA_TOKEN_PATH="${TOKEN_DIR}/${BAD_CA_TARGET}.token"
BAD_PIN_TOKEN_PATH="${TOKEN_DIR}/${BAD_PIN_TARGET}.token"
BAD_OCI_AUTH_TOKEN_PATH="${TOKEN_DIR}/${BAD_OCI_AUTH_TARGET}.token"
BAD_OCI_TLS_TOKEN_PATH="${TOKEN_DIR}/${BAD_OCI_TLS_TARGET}.token"
OCI_CRED_DIR="${TMP_DIR}/oci-creds"
OCI_USERNAME_PATH="${OCI_CRED_DIR}/registry.username"
OCI_PASSWORD_PATH="${OCI_CRED_DIR}/registry.password"
OCI_BAD_PASSWORD_PATH="${OCI_CRED_DIR}/registry.bad.password"
OTLP_EXPORT_DIR="${TMP_DIR}/otel-output"
OTLP_EXPORT_FILE="${OTLP_EXPORT_DIR}/collector-metrics.jsonl"
DEV_CERT_DIR="${TMP_DIR}/dev-certs"
REMOTE_CA_CERT_PATH="${DEV_CERT_DIR}/dev-ca.pem"
REMOTE_CERT_PATH="${DEV_CERT_DIR}/dev-cert.pem"
BAD_CA_CERT_PATH="${TMP_DIR}/bad-ca.pem"
REMOTE_SECRET_STORE_SOURCE_PATH="${TMP_DIR}/remote-secret-store.plain.json"
REMOTE_SECRET_STORE_PATH="${TMP_DIR}/remote-secret-store.enc.json"
REMOTE_SECRET_MASTER_KEY_PATH="${TMP_DIR}/remote-secret-store.key"
BAD_SECRET_MASTER_KEY_PATH="${TMP_DIR}/remote-secret-store.bad.key"

PACK_FIXTURE="spec/fixtures/baseline/pack_min/app.pack.json"
ROLLBACK_PACK_FIXTURE="spec/fixtures/remote-oss/common/pack_app_min_spin/app.pack.json"
PACK_DIGEST_MISMATCH_FIXTURE="spec/fixtures/baseline/pack_min/app.pack.bad.json"
CHANGE_FIXTURE="spec/fixtures/deploy_loop/common/change_request.app_min.json"
REMOTE_FIXTURE_INDEX="spec/fixtures/remote-oss/fixture_index.json"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$TOKEN_DIR" "$OCI_CRED_DIR" "$OTLP_EXPORT_DIR"
bash "$ROOT_DIR/scripts/ci/prepare_otlp_export_mount.sh" "$OTLP_EXPORT_DIR"

CONFIG_DIR="${TMP_DIR}/config"
mkdir -p "$CONFIG_DIR"
export X07LP_CONFIG_DIR="$CONFIG_DIR"

PIDS=()
DAEMON_PID=""
cleanup() {
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      if [ "${REMOTE_MODE:-}" = "compose" ]; then
        mkdir -p "$TMP_DIR"
        (cd "$ROOT_DIR" && docker compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" logs --no-color >"$TMP_DIR/docker-compose.log" 2>&1 || true)
      fi
      (cd "$ROOT_DIR" && docker compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" down -v >/dev/null 2>&1 || true)
    elif command -v docker-compose >/dev/null 2>&1; then
      if [ "${REMOTE_MODE:-}" = "compose" ]; then
        mkdir -p "$TMP_DIR"
        (cd "$ROOT_DIR" && docker-compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" logs --no-color >"$TMP_DIR/docker-compose.log" 2>&1 || true)
      fi
      (cd "$ROOT_DIR" && docker-compose -p "$STACK_PROJECT" -f "$STACK_COMPOSE_FILE" down -v >/dev/null 2>&1 || true)
    fi
  fi
  stop_daemon || true
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

write_text_file() {
  local path="$1"
  local value="$2"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$value" >"$path"
  chmod 600 "$path"
}

generate_dev_certificates() {
  (
    cd "$ROOT_DIR"
    ./examples/targets/wasmcloud/scripts/gen-dev-cert.sh "$DEV_CERT_DIR" >/dev/null
  )
}

generate_bad_ca_certificate() {
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 365 \
    -nodes \
    -subj "/CN=x07lp bad ca" \
    -keyout "${TMP_DIR}/bad-ca.key.pem" \
    -out "$BAD_CA_CERT_PATH" >/dev/null 2>&1
  chmod 600 "${TMP_DIR}/bad-ca.key.pem"
  chmod 644 "$BAD_CA_CERT_PATH"
}

compute_spki_pin() {
  local cert_path="$1"
  local hex
  hex="$(
    openssl x509 -in "$cert_path" -pubkey -noout \
      | openssl pkey -pubin -outform der \
      | openssl dgst -sha256 -binary \
      | xxd -p -c 256
  )"
  printf 'sha256:%s' "$hex"
}

pack_remote_secret_store() {
  (
    cd "$ROOT_DIR"
    X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$REMOTE_SECRET_MASTER_KEY_PATH" \
      "$DRIVER_BIN" secret-store-pack \
        --input "$(repo_path_arg "$REMOTE_SECRET_STORE_SOURCE_PATH")" \
        --output "$(repo_path_arg "$REMOTE_SECRET_STORE_PATH")" >/dev/null
  )
}

start_daemon() {
  local key_path="${1:-$REMOTE_SECRET_MASTER_KEY_PATH}"
  (
    cd "$ROOT_DIR"
    X07LP_REMOTE_BEARER_TOKEN="$BEARER_TOKEN" \
    X07LP_REMOTE_SECRET_STORE_PATH="$REMOTE_SECRET_STORE_PATH" \
    X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$key_path" \
    X07LP_REMOTE_OTLP_EXPORT_PATH="$OTLP_EXPORT_FILE" \
      "$DRIVER_BIN" ui-serve --addr "$DAEMON_BIND_ADDR" --state-dir "$TMP_DIR/remote_state" >/dev/null 2>&1
  ) &
  DAEMON_PID="$!"
  PIDS+=("$DAEMON_PID")
}

stop_daemon() {
  local pattern="x07lp-driver ui-serve --addr ${DAEMON_BIND_ADDR} --state-dir ${TMP_DIR}/remote_state"
  if [ -z "${DAEMON_PID:-}" ]; then
    pkill -f "$pattern" >/dev/null 2>&1 || true
    return 0
  fi
  local pid="$DAEMON_PID"
  if [ -n "${pid:-}" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  pkill -f "$pattern" >/dev/null 2>&1 || true
  DAEMON_PID=""
}

restart_daemon_with_key() {
  local key_path="$1"
  stop_daemon
  sleep 1
  start_daemon "$key_path"
  wait_for_http "${REMOTE_BASE_URL}/v1/health" 60
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
        stdout_json = node.get('stdout_json')
        if isinstance(stdout_json, dict):
            found = find_solve_output_b64(stdout_json)
            if found:
                return found
        result = node.get('result')
        if isinstance(result, dict):
            found = find_solve_output_b64(result)
            if found:
                return found
        report2 = node.get('report')
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
      echo "unsupported remote-oss command: $*" >&2
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

remote_fixture_field() {
  local fixture_name="$1"
  local field_name="$2"
  "$PYTHON" - "$ROOT_DIR" "$REMOTE_FIXTURE_INDEX" "$fixture_name" "$field_name" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
index_path = root / sys.argv[2]
fixture_name = sys.argv[3]
field_name = sys.argv[4]
doc = json.loads(index_path.read_text(encoding='utf-8'))
items = {item["name"]: item for item in doc.get("fixtures", [])}
seen = set()
current = fixture_name
while True:
    if current in seen:
        raise SystemExit(f"fixture alias cycle for {fixture_name}")
    seen.add(current)
    item = items[current]
    alias = item.get("alias_of")
    if not alias:
        value = item.get(field_name)
        if value is None and field_name == "plan":
            fixture_dir = item.get("dir")
            if fixture_dir:
                value = fixture_dir.rstrip("/") + "/deploy.plan.json"
        if value is None:
            raise SystemExit(f"missing {field_name} for fixture {fixture_name}")
        print(value)
        break
    current = alias
PY
}

REMOTE_PROMOTE_FIXTURE_DIR="$(remote_fixture_field remote_promote dir)"
REMOTE_ROLLBACK_FIXTURE_DIR="$(remote_fixture_field remote_rollback dir)"
REMOTE_PAUSE_RERUN_FIXTURE_DIR="$(remote_fixture_field remote_pause_rerun dir)"

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
  write_text_file "$path" "$BEARER_TOKEN"
}

render_target_profile() {
  local template_path="$1"
  local out_path="$2"
  local name="$3"
  local token_path="$4"
  local expected_caps="${5:-}"
  local tls_mode="${6:-ca_bundle}"
  local ca_bundle_path="${7:-$REMOTE_CA_CERT_PATH}"
  local pinned_spki="${8:-}"
  local oci_username_path="${9:-$OCI_USERNAME_PATH}"
  local oci_password_path="${10:-$OCI_PASSWORD_PATH}"
  local oci_ca_bundle_path="${11:-$REMOTE_CA_CERT_PATH}"
  "$PYTHON" \
    - "$template_path" "$out_path" "$name" "$REMOTE_BASE_URL" "$OCI_REGISTRY" "$token_path" \
    "$expected_caps" "$TELEMETRY_COLLECTOR_URL" "$tls_mode" "$ca_bundle_path" "$pinned_spki" \
    "$oci_username_path" "$oci_password_path" "$oci_ca_bundle_path" <<'PY'
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
tls_mode = sys.argv[9]
ca_bundle_path = sys.argv[10]
pinned_spki = sys.argv[11]
oci_username_path = sys.argv[12]
oci_password_path = sys.argv[13]
oci_ca_bundle_path = sys.argv[14]
doc = json.loads(template.read_text(encoding='utf-8'))

def replace(node):
    if isinstance(node, dict):
        result = {}
        for k, v in node.items():
            value = replace(v)
            if value is not None:
                result[k] = value
        return result
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
    if node == '__TLS_MODE__':
        return tls_mode
    if node == '__CA_BUNDLE_PATH__':
        return ca_bundle_path
    if node == '__PINNED_SPKI_SHA256__':
        return pinned_spki or None
    if node == '__OCI_USERNAME_REF__':
        return f'file://{oci_username_path}'
    if node == '__OCI_PASSWORD_REF__':
        return f'file://{oci_password_path}'
    if node == '__OCI_CA_BUNDLE_PATH__':
        return oci_ca_bundle_path
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
    if "$CURL_BIN" -fsS --cacert "$REMOTE_CA_CERT_PATH" "$url" >/dev/null 2>&1; then
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
    code="$("$CURL_BIN" --cacert "$REMOTE_CA_CERT_PATH" -sS -o /dev/null -w '%{http_code}' "$url" || true)"
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
    --cacert "$REMOTE_CA_CERT_PATH" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    "${REMOTE_BASE_URL}/v1/capabilities" \
    >"$out_path"
}

fetch_remote_stream() {
  local endpoint="$1"
  local query="$2"
  local out_path="$3"
  "$CURL_BIN" -fsS \
    --cacert "$REMOTE_CA_CERT_PATH" \
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

assert_report_not_ok() {
  local report_path="$1"
  "$PYTHON" - "$report_path" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if doc.get('ok') is not False:
    raise SystemExit(f'expected ok=false in {sys.argv[1]}')
PY
}

assert_metrics_snapshot_labels() {
  local snapshot_path="$1"
  local expected_exec_id="$2"
  local expected_source="$3"
  "$PYTHON" - "$snapshot_path" "$expected_exec_id" "$expected_source" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
labels = doc.get('labels', {})
required = [
    'x07.exec_id',
    'x07.run_id',
    'x07.pack_sha256',
    'x07.slot',
    'x07.app_id',
    'x07.environment',
    'x07.analysis_seq',
    'x07.telemetry_source',
]
missing = [key for key in required if not isinstance(labels.get(key), str) or not labels.get(key)]
if missing:
    raise SystemExit(f'missing snapshot labels {missing} in {sys.argv[1]}')
if labels['x07.exec_id'] != sys.argv[2]:
    raise SystemExit(f'unexpected exec_id label in {sys.argv[1]}: {labels["x07.exec_id"]!r}')
if labels['x07.telemetry_source'] != sys.argv[3]:
    raise SystemExit(
        f'unexpected telemetry source in {sys.argv[1]}: {labels["x07.telemetry_source"]!r}'
    )
metrics = {item.get('name') for item in doc.get('metrics', []) if isinstance(item, dict)}
expected_metrics = {'http_error_rate', 'http_latency_p95_ms', 'http_availability'}
if metrics != expected_metrics:
    raise SystemExit(f'unexpected metrics set in {sys.argv[1]}: {metrics!r}')
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
  local attempt=1
  local max_attempts=20
  while true; do
    run_x07lp "$run_report" "$cli_report" deploy query --target "$TARGET_NAME" --deployment "$exec_id" --view "$view" --json
    if "$PYTHON" - "$cli_report" <<'PY' >/dev/null 2>&1; then
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
schema_version = doc.get("schema_version")
if isinstance(schema_version, str) and schema_version:
    raise SystemExit(0)
raise SystemExit(1)
PY
      return 0
    fi

    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "remote query did not produce a schema_version: exec_id=$exec_id view=$view" >&2
      cat "$cli_report" >&2 || true
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
}

start_stack() {
  if [ "$REMOTE_MODE" = "compose" ]; then
    if [ ! -f "$ROOT_DIR/$STACK_COMPOSE_FILE" ]; then
      echo "compose mode requested but missing $STACK_COMPOSE_FILE" >&2
      exit 1
    fi
    (cd "$ROOT_DIR" && X07LP_OTLP_EXPORT_HOST_DIR="$OTLP_EXPORT_DIR" X07LP_DEV_CERT_DIR="$DEV_CERT_DIR" dc up -d)
    start_daemon
  elif [ "$REMOTE_MODE" = "local" ]; then
    (
      cd "$ROOT_DIR"
      X07LP_REMOTE_BEARER_TOKEN="$BEARER_TOKEN" \
      X07LP_REMOTE_SECRET_STORE_PATH="$REMOTE_SECRET_STORE_PATH" \
      X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$REMOTE_SECRET_MASTER_KEY_PATH" \
        "$DRIVER_BIN" ui-serve --addr "$PUBLIC_GATEWAY_ADDR" --state-dir "$TMP_DIR/remote_state" >/dev/null 2>&1
    ) &
    DAEMON_PID="$!"
    PIDS+=("$DAEMON_PID")
  elif [ "$REMOTE_MODE" != "external" ]; then
    echo "unsupported X07LP_REMOTE_OSS_REMOTE_MODE=$REMOTE_MODE" >&2
    exit 1
  fi
  wait_for_http "${REMOTE_BASE_URL}/v1/health" 60
  if [ "$REMOTE_MODE" = "compose" ]; then
    wait_for_http_statuses "https://${OCI_REGISTRY}/v2/" "200,401" 60
    wait_for_http "http://127.0.0.1:8222/varz" 60
    wait_for_tcp "127.0.0.1" "4000" 60
    wait_for_tcp "127.0.0.1" "4318" 60
  fi
}

write_token "$TOKEN_PATH"
write_token "$CAP_MISMATCH_TOKEN_PATH"
write_token "$MISSING_SECRET_TOKEN_PATH"
write_token "$PINNED_TOKEN_PATH"
write_token "$BAD_CA_TOKEN_PATH"
write_token "$BAD_PIN_TOKEN_PATH"
write_token "$BAD_OCI_AUTH_TOKEN_PATH"
write_token "$BAD_OCI_TLS_TOKEN_PATH"
write_text_file "$OCI_USERNAME_PATH" "$OCI_USERNAME"
write_text_file "$OCI_PASSWORD_PATH" "$OCI_PASSWORD"
write_text_file "$OCI_BAD_PASSWORD_PATH" "wrong-${OCI_PASSWORD}"
write_text_file "$REMOTE_SECRET_MASTER_KEY_PATH" "$(openssl rand -hex 32)"
write_text_file "$BAD_SECRET_MASTER_KEY_PATH" "$(openssl rand -hex 32)"
generate_dev_certificates
generate_bad_ca_certificate
REMOTE_SPKI_PIN="$(compute_spki_pin "$REMOTE_CERT_PATH")"

cat >"$REMOTE_SECRET_STORE_SOURCE_PATH" <<JSON
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
pack_remote_secret_store

render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$PROFILE_PATH" "$TARGET_NAME" "$TOKEN_PATH"
render_target_profile "spec/fixtures/remote-oss/common/targets/cap-mismatch.target.template.json" "$CAP_MISMATCH_PROFILE_PATH" "$CAP_MISMATCH_TARGET" "$CAP_MISMATCH_TOKEN_PATH" "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
render_target_profile "spec/fixtures/remote-oss/common/targets/missing-secret.target.template.json" "$MISSING_SECRET_PROFILE_PATH" "$MISSING_SECRET_TARGET" "$MISSING_SECRET_TOKEN_PATH"
render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$PINNED_PROFILE_PATH" "$PINNED_TARGET" "$PINNED_TOKEN_PATH" "" "pinned_spki" "$REMOTE_CA_CERT_PATH" "$REMOTE_SPKI_PIN"
render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$BAD_CA_PROFILE_PATH" "$BAD_CA_TARGET" "$BAD_CA_TOKEN_PATH" "" "ca_bundle" "$BAD_CA_CERT_PATH"
render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$BAD_PIN_PROFILE_PATH" "$BAD_PIN_TARGET" "$BAD_PIN_TOKEN_PATH" "" "pinned_spki" "$REMOTE_CA_CERT_PATH" "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$BAD_OCI_AUTH_PROFILE_PATH" "$BAD_OCI_AUTH_TARGET" "$BAD_OCI_AUTH_TOKEN_PATH" "" "ca_bundle" "$REMOTE_CA_CERT_PATH" "" "$OCI_USERNAME_PATH" "$OCI_BAD_PASSWORD_PATH" "$REMOTE_CA_CERT_PATH"
render_target_profile "spec/fixtures/remote-oss/common/targets/main.target.template.json" "$BAD_OCI_TLS_PROFILE_PATH" "$BAD_OCI_TLS_TARGET" "$BAD_OCI_TLS_TOKEN_PATH" "" "ca_bundle" "$REMOTE_CA_CERT_PATH" "" "$OCI_USERNAME_PATH" "$OCI_PASSWORD_PATH" "$BAD_CA_CERT_PATH"

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
  "${ROOT_DIR}/spec/fixtures/remote-oss/remote_capabilities/expected/v1.capabilities.json"

run_x07lp "${TMP_DIR}/target.add.run_report.json" "${TMP_DIR}/target.add.cli.json" target add --profile "$(repo_path_arg "$PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.cap_mismatch.run_report.json" "${TMP_DIR}/target.add.cap_mismatch.cli.json" target add --profile "$(repo_path_arg "$CAP_MISMATCH_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.missing_secret.run_report.json" "${TMP_DIR}/target.add.missing_secret.cli.json" target add --profile "$(repo_path_arg "$MISSING_SECRET_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.pinned.run_report.json" "${TMP_DIR}/target.add.pinned.cli.json" target add --profile "$(repo_path_arg "$PINNED_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.bad_oci_auth.run_report.json" "${TMP_DIR}/target.add.bad_oci_auth.cli.json" target add --profile "$(repo_path_arg "$BAD_OCI_AUTH_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.bad_oci_tls.run_report.json" "${TMP_DIR}/target.add.bad_oci_tls.cli.json" target add --profile "$(repo_path_arg "$BAD_OCI_TLS_PROFILE_PATH")" --json
run_x07lp "${TMP_DIR}/target.add.bad_ca.run_report.json" "${TMP_DIR}/target.add.bad_ca.cli.json" target add --profile "$(repo_path_arg "$BAD_CA_PROFILE_PATH")" --json || true
run_x07lp "${TMP_DIR}/target.add.bad_pin.run_report.json" "${TMP_DIR}/target.add.bad_pin.cli.json" target add --profile "$(repo_path_arg "$BAD_PIN_PROFILE_PATH")" --json || true
validate_cli_report "${TMP_DIR}/target.add.cli.json" "${TMP_DIR}"
assert_negative_code "${TMP_DIR}/target.add.bad_ca.cli.json" "LP_REMOTE_TARGET_UNREACHABLE"
assert_negative_code "${TMP_DIR}/target.add.bad_pin.cli.json" "LP_REMOTE_TARGET_UNREACHABLE"

run_x07lp "${TMP_DIR}/remote_promote.accept.run_report.json" "${TMP_DIR}/remote_promote.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
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
assert_metrics_snapshot_labels \
  "${TMP_DIR}/remote_state/.x07lp/telemetry/${PROMOTE_EXEC_ID}/analysis.1.json" \
  "$PROMOTE_EXEC_ID" \
  "remote_runtime_probe"
validate_cli_report "${TMP_DIR}/remote_promote.query.summary.cli.json" "${TMP_DIR}/remote_promote.query.summary"
validate_cli_report "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full"
validate_report_result_schema "contracts/spec/schemas/lp.deploy.query.result.schema.json" "${TMP_DIR}/remote_promote.query.summary.cli.json" "${TMP_DIR}/remote_promote.query.summary" "deploy.query.summary"
validate_report_result_schema "contracts/spec/schemas/lp.deploy.query.result.schema.json" "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full" "deploy.query.full"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.summary.cli.json" "${ROOT_DIR}/${REMOTE_PROMOTE_FIXTURE_DIR}/expected/query.summary.report.json"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.full.cli.json" "${ROOT_DIR}/${REMOTE_PROMOTE_FIXTURE_DIR}/expected/query.full.report.json"
normalize_remote_query_full "${TMP_DIR}/remote_promote.query.full.cli.json" "${TMP_DIR}/remote_promote.query.full.normalized.json"
assert_report_matches_template "${TMP_DIR}/remote_promote.query.full.normalized.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_parity/expected/query.full.normalized.json"

fetch_remote_stream "v1/events" "exec_id=${PROMOTE_EXEC_ID}&limit=50" "${TMP_DIR}/remote_promote.events.cli.json"
fetch_remote_stream "v1/logs" "exec_id=${PROMOTE_EXEC_ID}&slot=candidate&limit=50" "${TMP_DIR}/remote_promote.logs.cli.json"
validate_cli_report "${TMP_DIR}/remote_promote.events.cli.json" "${TMP_DIR}/remote_promote.events"
validate_cli_report "${TMP_DIR}/remote_promote.logs.cli.json" "${TMP_DIR}/remote_promote.logs"
validate_report_result_schema "contracts/spec/schemas/lp.remote.events.result.schema.json" "${TMP_DIR}/remote_promote.events.cli.json" "${TMP_DIR}/remote_promote.events" "remote.events"
validate_report_result_schema "contracts/spec/schemas/lp.remote.logs.result.schema.json" "${TMP_DIR}/remote_promote.logs.cli.json" "${TMP_DIR}/remote_promote.logs" "remote.logs"
assert_report_items_non_empty "${TMP_DIR}/remote_promote.events.cli.json"
assert_report_items_non_empty "${TMP_DIR}/remote_promote.logs.cli.json"

run_x07lp "${TMP_DIR}/remote_rollback.accept.run_report.json" "${TMP_DIR}/remote_rollback.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$ROLLBACK_PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
ROLLBACK_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_rollback.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_rollback.run.run_report.json" "${TMP_DIR}/remote_rollback.run.cli.json" \
  deploy run --target "$TARGET_NAME" --accepted-run "$ROLLBACK_RUN_ID" --fixture "$REMOTE_ROLLBACK_FIXTURE_DIR" --json || true
assert_negative_code "${TMP_DIR}/remote_rollback.run.cli.json" "LP_SLO_DECISION_ROLLBACK"
assert_report_matches_template "${TMP_DIR}/remote_rollback.run.cli.json" "${ROOT_DIR}/${REMOTE_ROLLBACK_FIXTURE_DIR}/expected/deploy.run.report.json"
ROLLBACK_EXEC_ID="$("$PYTHON" - "${TMP_DIR}/remote_rollback.run.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('deployment_id') or doc.get('result', {}).get('exec_id') or '')
PY
)"
run_remote_query_view "$ROLLBACK_EXEC_ID" "summary" "${TMP_DIR}/remote_rollback.query.summary.run_report.json" "${TMP_DIR}/remote_rollback.query.summary.cli.json"
assert_metrics_snapshot_labels \
  "${TMP_DIR}/remote_state/.x07lp/telemetry/${ROLLBACK_EXEC_ID}/analysis.1.json" \
  "$ROLLBACK_EXEC_ID" \
  "remote_runtime_probe"
assert_report_matches_template "${TMP_DIR}/remote_rollback.query.summary.cli.json" "${ROOT_DIR}/${REMOTE_ROLLBACK_FIXTURE_DIR}/expected/query.summary.report.json"
run_x07lp "${TMP_DIR}/remote_rollback.stop.run_report.json" "${TMP_DIR}/remote_rollback.stop.cli.json" \
  deploy stop --target "$TARGET_NAME" --deployment "$ROLLBACK_EXEC_ID" --reason "ci cleanup rollback" --json

run_x07lp "${TMP_DIR}/remote_pause.accept.run_report.json" "${TMP_DIR}/remote_pause.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
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
    deploy run --target "$TARGET_NAME" --accepted-run "$PAUSE_RUN_ID" --fixture "$REMOTE_PAUSE_RERUN_FIXTURE_DIR" --json
) &
PAUSE_RUN_PID=$!
PIDS+=("$PAUSE_RUN_PID")
wait_for_pause_step "${TMP_DIR}/remote_state/deploy/${PAUSE_EXEC_ID}.json" 20
run_x07lp "${TMP_DIR}/remote_pause.control.run_report.json" "${TMP_DIR}/remote_pause.control.cli.json" \
  deploy pause --target "$TARGET_NAME" --deployment "$PAUSE_EXEC_ID" --reason "ci pause" --json
assert_report_matches_template "${TMP_DIR}/remote_pause.control.cli.json" "${ROOT_DIR}/${REMOTE_PAUSE_RERUN_FIXTURE_DIR}/expected/pause.report.json"
wait_for_control_state "${TMP_DIR}/remote_state/deploy/${PAUSE_EXEC_ID}.json" paused 20
wait "$PAUSE_RUN_PID" || true
run_x07lp "${TMP_DIR}/remote_rerun.control.run_report.json" "${TMP_DIR}/remote_rerun.control.cli.json" \
  deploy rerun --target "$TARGET_NAME" --deployment "$PAUSE_EXEC_ID" --reason "ci rerun" --json
assert_report_matches_template "${TMP_DIR}/remote_rerun.control.cli.json" "${ROOT_DIR}/${REMOTE_PAUSE_RERUN_FIXTURE_DIR}/expected/rerun.report.json"
run_x07lp "${TMP_DIR}/remote_pause.stop.run_report.json" "${TMP_DIR}/remote_pause.stop.cli.json" \
  deploy stop --target "$TARGET_NAME" --deployment "$PAUSE_EXEC_ID" --reason "ci cleanup" --json

for view in summary timeline decisions artifacts full; do
  run_remote_query_view "$PROMOTE_EXEC_ID" "$view" "${TMP_DIR}/remote_query.${view}.run_report.json" "${TMP_DIR}/remote_query.${view}.cli.json"
  assert_report_matches_template \
    "${TMP_DIR}/remote_query.${view}.cli.json" \
    "${ROOT_DIR}/spec/fixtures/remote-oss/remote_query/expected/query.${view}.report.json"
done

run_x07lp "${TMP_DIR}/remote_incident_capture.capture.run_report.json" "${TMP_DIR}/remote_incident_capture.capture.cli.json" \
  incident capture --target "$TARGET_NAME" --deployment "$PROMOTE_EXEC_ID" --reason "ci capture" \
  --classification http_5xx --source router \
  --request spec/fixtures/control_plane/common/request.envelope.json \
  --response spec/fixtures/control_plane/common/response.500.envelope.json \
  --trace spec/fixtures/control_plane/common/trace.json --json
assert_report_matches_template \
  "${TMP_DIR}/remote_incident_capture.capture.cli.json" \
  "${ROOT_DIR}/spec/fixtures/remote-oss/remote_incident_capture/expected/incident.capture.report.json"
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
  "${ROOT_DIR}/spec/fixtures/remote-oss/remote_regression_from_incident/expected/regress.report.json"

run_x07lp "${TMP_DIR}/remote_missing_secret.accept.run_report.json" "${TMP_DIR}/remote_missing_secret.accept.cli.json" \
  deploy accept --target "$MISSING_SECRET_TARGET" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" \
  --ops-profile arch/app/ops/ops_secret_allow.json --json || true
assert_negative_code "${TMP_DIR}/remote_missing_secret.accept.cli.json" "LP_REMOTE_SECRET_NOT_FOUND"
assert_report_matches_template "${TMP_DIR}/remote_missing_secret.accept.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_missing_secret/expected/deploy.accept.report.json"

restart_daemon_with_key "$BAD_SECRET_MASTER_KEY_PATH"
run_x07lp "${TMP_DIR}/remote_secret_store.bad_key.run_report.json" "${TMP_DIR}/remote_secret_store.bad_key.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" \
  --ops-profile arch/app/ops/ops_secret_allow.json --json || true
assert_negative_code "${TMP_DIR}/remote_secret_store.bad_key.cli.json" "LP_REMOTE_SECRET_STORE_INVALID"
restart_daemon_with_key "$REMOTE_SECRET_MASTER_KEY_PATH"

chmod 0644 "$REMOTE_SECRET_STORE_PATH"
run_x07lp "${TMP_DIR}/remote_secret_store.bad_perm.run_report.json" "${TMP_DIR}/remote_secret_store.bad_perm.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" \
  --ops-profile arch/app/ops/ops_secret_allow.json --json || true
assert_negative_code "${TMP_DIR}/remote_secret_store.bad_perm.cli.json" "LP_REMOTE_SECRET_STORE_INVALID"
chmod 0600 "$REMOTE_SECRET_STORE_PATH"

run_x07lp "${TMP_DIR}/remote_oci_auth.accept.run_report.json" "${TMP_DIR}/remote_oci_auth.accept.cli.json" \
  deploy accept --target "$BAD_OCI_AUTH_TARGET" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
BAD_OCI_AUTH_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_oci_auth.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_oci_auth.run.run_report.json" "${TMP_DIR}/remote_oci_auth.run.cli.json" \
  deploy run --target "$BAD_OCI_AUTH_TARGET" --accepted-run "$BAD_OCI_AUTH_RUN_ID" --json || true
assert_report_not_ok "${TMP_DIR}/remote_oci_auth.run.cli.json"
assert_negative_code "${TMP_DIR}/remote_oci_auth.run.cli.json" "LP_RUNTIME_START_FAILED"

run_x07lp "${TMP_DIR}/remote_oci_tls.accept.run_report.json" "${TMP_DIR}/remote_oci_tls.accept.cli.json" \
  deploy accept --target "$BAD_OCI_TLS_TARGET" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
BAD_OCI_TLS_RUN_ID="$("$PYTHON" - "${TMP_DIR}/remote_oci_tls.accept.cli.json" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(doc.get('result', {}).get('run_id') or '')
PY
)"
run_x07lp "${TMP_DIR}/remote_oci_tls.run.run_report.json" "${TMP_DIR}/remote_oci_tls.run.cli.json" \
  deploy run --target "$BAD_OCI_TLS_TARGET" --accepted-run "$BAD_OCI_TLS_RUN_ID" --json || true
assert_report_not_ok "${TMP_DIR}/remote_oci_tls.run.cli.json"
assert_negative_code "${TMP_DIR}/remote_oci_tls.run.cli.json" "LP_RUNTIME_START_FAILED"

run_x07lp "${TMP_DIR}/remote_upload_digest_mismatch.accept.run_report.json" "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_DIGEST_MISMATCH_FIXTURE" --change "$CHANGE_FIXTURE" --json || true
assert_negative_code "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" "LP_REMOTE_UPLOAD_DIGEST_MISMATCH"
assert_report_matches_template "${TMP_DIR}/remote_upload_digest_mismatch.accept.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_upload_digest_mismatch/expected/deploy.accept.report.json"

run_x07lp "${TMP_DIR}/remote_capabilities_mismatch.run_report.json" "${TMP_DIR}/remote_capabilities_mismatch.cli.json" \
  deploy run --target "$CAP_MISMATCH_TARGET" --accepted-run "$PROMOTE_RUN_ID" --json || true
assert_negative_code "${TMP_DIR}/remote_capabilities_mismatch.cli.json" "LP_REMOTE_CAPABILITIES_UNSUPPORTED"
assert_report_matches_template "${TMP_DIR}/remote_capabilities_mismatch.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_capabilities_mismatch/expected/deploy.run.report.json"

run_x07lp "${TMP_DIR}/remote_lease_conflict.accept.run_report.json" "${TMP_DIR}/remote_lease_conflict.accept.cli.json" \
  deploy accept --target "$TARGET_NAME" --pack-manifest "$PACK_FIXTURE" --change "$CHANGE_FIXTURE" --json
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
    --fixture "$REMOTE_PAUSE_RERUN_FIXTURE_DIR" --pause-scale 0.2 --json
) &
LEASE_CONFLICT_PID=$!
PIDS+=("$LEASE_CONFLICT_PID")
wait_for_pause_step "${TMP_DIR}/remote_state/deploy/${LEASE_CONFLICT_EXEC_ID}.json" 20
sleep 3
run_x07lp "${TMP_DIR}/remote_lease_conflict.b.run_report.json" "${TMP_DIR}/remote_lease_conflict.b.cli.json" \
  deploy run --target "$TARGET_NAME" --accepted-run "$LEASE_CONFLICT_RUN_ID" \
  --fixture "$REMOTE_PAUSE_RERUN_FIXTURE_DIR" --pause-scale 0.2 --json || true
assert_negative_code "${TMP_DIR}/remote_lease_conflict.b.cli.json" "LP_REMOTE_LEASE_CONFLICT"
assert_report_matches_template "${TMP_DIR}/remote_lease_conflict.b.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_lease_conflict/expected/deploy.run.report.json"
wait "$LEASE_CONFLICT_PID" || true

run_x07lp "${TMP_DIR}/remote_incident_trace_missing.regress.run_report.json" "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" \
  regress from-incident --target "$TARGET_NAME" --incident-id incident_missing_trace --json || true
assert_negative_code "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" "LP_INCIDENT_TRACE_MISSING"
assert_report_matches_template "${TMP_DIR}/remote_incident_trace_missing.regress.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_incident_trace_missing/expected/regress.report.json"

run_x07lp "${TMP_DIR}/remote_query_index_rebuild.query.run_report.json" "${TMP_DIR}/remote_query_index_rebuild.query.cli.json" \
  deploy query --target "$TARGET_NAME" --deployment "$PROMOTE_EXEC_ID" --view summary --rebuild-index --json
assert_report_matches_template "${TMP_DIR}/remote_query_index_rebuild.query.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_query_index_rebuild/expected/query.summary.report.json"

(
  cd "$ROOT_DIR"
  "$DRIVER_BIN" adapter-conformance --target "$TARGET_NAME" --state-dir "$TMP_DIR/remote_state" --json >"${TMP_DIR}/remote_conformance.cli.json"
)
cp "${TMP_DIR}/remote_conformance.cli.json" "${TMP_DIR}/remote_conformance.run_report.json"
assert_report_matches_template "${TMP_DIR}/remote_conformance.cli.json" "${ROOT_DIR}/spec/fixtures/remote-oss/remote_conformance/expected/adapter.conformance.report.json"

echo "remote-oss ci expectations passed"
