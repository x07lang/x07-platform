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
TMP_DIR="${ROOT_DIR}/_tmp/ci_device_release"
STATE_DIR="${TMP_DIR}/state"
UI_ADDR="127.0.0.1:17091"
UI_BASE_URL="http://${UI_ADDR}"
SECRET_DIR="${TMP_DIR}/device-secrets"
SECRET_STORE_SOURCE_PATH="${SECRET_DIR}/device-secret-store.plain.json"
SECRET_STORE_PATH="${SECRET_DIR}/device-secret-store.enc.json"
SECRET_MASTER_KEY_PATH="${SECRET_DIR}/device-secret-store.key"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$STATE_DIR"

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

stop_pid() {
  local pid="$1"
  if [ -n "${pid:-}" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
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
  local report_path="$1"
  local out_path="$2"
  shift 2
  mkdir -p "$(dirname "$report_path")" "$(dirname "$out_path")"
  (
    cd "$ROOT_DIR"
    X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$SECRET_MASTER_KEY_PATH" \
    X07LP_REMOTE_SECRET_STORE_PATH="$SECRET_STORE_PATH" \
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

extract_json_value() {
  local json_path="$1"
  local path_expr="$2"
  "$PYTHON" - "$json_path" "$path_expr" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
value = doc
for part in sys.argv[2].split('.'):
    if not part:
        continue
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value[part]
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
else:
    print(value)
PY
}

assert_json_expr() {
  local json_path="$1"
  local expr="$2"
  local message="$3"
  "$PYTHON" - "$json_path" "$expr" "$message" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
expr = sys.argv[2]
message = sys.argv[3]
allowed = {"any": any, "all": all, "len": len}
if not eval(expr, {"__builtins__": {}}, {"doc": doc, **allowed}):
    raise SystemExit(f"{message}\n{json.dumps(doc, indent=2)}")
PY
}

assert_tools_present() {
  "$PYTHON" - "$ROOT_DIR/gateway/mcp/config/mcp.tools.json" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
names = {tool["name"] for tool in doc["tools"]}
required = {
    "lp.device.release.create",
    "lp.device.release.validate",
    "lp.device.release.run",
    "lp.device.release.query",
    "lp.device.release.observe",
    "lp.device.release.pause",
    "lp.device.release.resume",
    "lp.device.release.halt",
    "lp.device.release.stop",
    "lp.device.release.complete",
    "lp.device.release.rerun",
    "lp.device.release.rollback",
    "lp.device.incident.list",
    "lp.device.incident.get",
}
missing = sorted(required - names)
if missing:
    raise SystemExit(f"missing MCP tools: {missing}")
PY
}

pack_device_secret_store() {
  mkdir -p "$SECRET_DIR"
  printf '%064d' 0 >"$SECRET_MASTER_KEY_PATH"
  chmod 600 "$SECRET_MASTER_KEY_PATH"
  "$PYTHON" - "$SECRET_STORE_SOURCE_PATH" <<'PY'
import json
import pathlib
import sys

doc = {
    "schema_version": "lp.remote.secret.store.internal@0.1.0",
    "targets": {},
    "device": {
        "mock-beta-ios": "fixture-mock-beta-ios",
        "mock-production-ios": "fixture-mock-production-ios",
        "mock-production-android": "fixture-mock-production-android",
        "appstore-production-ios": json.dumps(
            {
                "issuer_id": "fixture-appstore-issuer",
                "key_id": "fixture-appstore-key",
                "private_key_pem": "-----BEGIN PRIVATE KEY-----\nfixture-appstore-key\n-----END PRIVATE KEY-----\n",
            }
        ),
        "googleplay-production-android": json.dumps(
            {
                "client_email": "fixture-device-release@example.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----\nfixture-googleplay-key\n-----END PRIVATE KEY-----\n",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        ),
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$SECRET_STORE_SOURCE_PATH"
  (
    cd "$ROOT_DIR"
    X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$SECRET_MASTER_KEY_PATH" \
      scripts/x07lp-driver secret-store-pack \
        --input "$(repo_path_arg "$SECRET_STORE_SOURCE_PATH")" \
        --output "$(repo_path_arg "$SECRET_STORE_PATH")" >/dev/null
  )
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-30}"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $url" >&2
  return 1
}

assert_tools_present

STATE_DIR_ARG="$(repo_path_arg "$STATE_DIR")"
pack_device_secret_store

IOS_PACKAGE="spec/fixtures/device-release/common/package_ios_demo/device.package.manifest.json"
ANDROID_PACKAGE="spec/fixtures/device-release/common/package_android_demo/device.package.manifest.json"
MOCK_BETA_PROVIDER="spec/fixtures/device-release/common/providers/mock_beta_ios.json"
MOCK_PROD_PROVIDER="spec/fixtures/device-release/common/providers/mock_production_ios.json"
MOCK_PROD_ANDROID_PROVIDER="spec/fixtures/device-release/common/providers/mock_production_android.json"
GOOGLEPLAY_PROVIDER="spec/fixtures/device-release/common/providers/googleplay_production_android.json"
APPSTORE_PROVIDER="spec/fixtures/device-release/common/providers/appstoreconnect_production_ios.json"
INVALID_PLAN="spec/fixtures/device-release/provider_validation_ios_invalid_percent/invalid.plan.json"
SLO_PROFILE="spec/fixtures/device-release/common/slo_min.json"
TRACE_FIXTURE="spec/fixtures/device-release/common/device.trace.json"

run_create() {
  local report_path="$1"
  local out_path="$2"
  local provider="$3"
  local package_manifest="$4"
  local plan_path="$5"
  local slo_profile="${6:-}"
  local metrics_window_seconds="${7:-}"
  local metrics_on_fail="${8:-}"
  local provider_arg
  local package_arg
  local plan_arg
  local argv=()
  provider_arg="$(repo_path_arg "$provider")"
  package_arg="$(repo_path_arg "$package_manifest")"
  plan_arg="$(repo_path_arg "$plan_path")"
  argv=(
    device release-create
    --provider-profile "$provider_arg"
    --package-manifest "$package_arg"
    --out "$plan_arg"
  )
  if [ -n "$slo_profile" ]; then
    argv+=(--slo-profile "$(repo_path_arg "$slo_profile")")
  fi
  if [ -n "$metrics_window_seconds" ]; then
    argv+=(--metrics-window-seconds "$metrics_window_seconds")
  fi
  if [ -n "$metrics_on_fail" ]; then
    argv+=(--metrics-on-fail "$metrics_on_fail")
  fi
  argv+=(--state-dir "$STATE_DIR_ARG" --now-unix-ms "$NOW_UNIX_MS" --json)
  run_x07lp "$report_path" "$out_path" "${argv[@]}"
}

run_validate() {
  local report_path="$1"
  local out_path="$2"
  local plan_path="$3"
  local provider="${4:-}"
  local plan_arg
  plan_arg="$(repo_path_arg "$plan_path")"
  if [ -n "$provider" ]; then
    local provider_arg
    provider_arg="$(repo_path_arg "$provider")"
    run_x07lp "$report_path" "$out_path" \
      device release-validate \
      --plan "$plan_arg" \
      --provider-profile "$provider_arg" \
      --state-dir "$STATE_DIR_ARG" \
      --now-unix-ms "$NOW_UNIX_MS" \
      --json
  else
    run_x07lp "$report_path" "$out_path" \
      device release-validate \
      --plan "$plan_arg" \
      --state-dir "$STATE_DIR_ARG" \
      --now-unix-ms "$NOW_UNIX_MS" \
      --json
  fi
}

run_release() {
  local report_path="$1"
  local out_path="$2"
  local plan_path="$3"
  local package_manifest="${4:-}"
  local plan_arg
  plan_arg="$(repo_path_arg "$plan_path")"
  if [ -n "$package_manifest" ]; then
    local package_arg
    package_arg="$(repo_path_arg "$package_manifest")"
    run_x07lp "$report_path" "$out_path" \
      device release-run \
      --plan "$plan_arg" \
      --package-manifest "$package_arg" \
      --state-dir "$STATE_DIR_ARG" \
      --now-unix-ms "$NOW_UNIX_MS" \
      --json
  else
    run_x07lp "$report_path" "$out_path" \
      device release-run \
      --plan "$plan_arg" \
      --state-dir "$STATE_DIR_ARG" \
      --now-unix-ms "$NOW_UNIX_MS" \
      --json
  fi
}

run_query() {
  local report_path="$1"
  local out_path="$2"
  local release_exec_id="$3"
  local view="${4:-full}"
  run_x07lp "$report_path" "$out_path" \
    device release-query \
    --release "$release_exec_id" \
    --view "$view" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
}

run_control() {
  local report_path="$1"
  local out_path="$2"
  local action="$3"
  local release_exec_id="$4"
  local reason="$5"
  run_x07lp "$report_path" "$out_path" \
    device "release-${action}" \
    --release "$release_exec_id" \
    --reason "$reason" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
}

run_incident_capture() {
  local report_path="$1"
  local out_path="$2"
  local release_exec_id="$3"
  local trace_path="$4"
  run_x07lp "$report_path" "$out_path" \
    incident capture \
    --release "$release_exec_id" \
    --reason device_trace_capture \
    --classification device_js_unhandled \
    --source device_host \
    --trace "$(repo_path_arg "$trace_path")" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
}

run_incident_list() {
  local report_path="$1"
  local out_path="$2"
  local release_exec_id="$3"
  run_x07lp "$report_path" "$out_path" \
    incident list \
    --release "$release_exec_id" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
}

run_regress() {
  local report_path="$1"
  local out_path="$2"
  local incident_id="$3"
  local out_dir="$4"
  local name="$5"
  run_x07lp "$report_path" "$out_path" \
    regress from-incident \
    --incident-id "$incident_id" \
    --out-dir "$(repo_path_arg "$out_dir")" \
    --name "$name" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
}

seed_otlp_export() {
  local release_exec_id="$1"
  local scenario="$2"
  local seq="${3:-1}"
  local dst_dir="${STATE_DIR}/device_release/telemetry/${release_exec_id}"
  mkdir -p "$dst_dir"
  "$PYTHON" - "$STATE_DIR" "$release_exec_id" "$scenario" >"${dst_dir}/analysis.${seq}.jsonl" <<'PY'
import json
import pathlib
import sys

state_dir = pathlib.Path(sys.argv[1])
exec_id = sys.argv[2]
scenario = sys.argv[3]
exec_doc = json.loads(
    (state_dir / "device_release" / "executions" / f"{exec_id}.json").read_text(encoding="utf-8")
)
plan_id = exec_doc["plan_id"]
app_id = exec_doc["meta"]["app"]["app_id"]
package_sha = exec_doc["meta"]["package_digest"]["sha256"]

resource_attrs = [
    {"key": "x07.release.exec_id", "value": {"stringValue": exec_id}},
    {"key": "x07.release.plan_id", "value": {"stringValue": plan_id}},
    {"key": "x07.app_id", "value": {"stringValue": app_id}},
    {"key": "x07.package.sha256", "value": {"stringValue": package_sha}},
]

def log_record(class_name, event_name, attrs, body=None):
    record = {
        "attributes": [
            {"key": "x07.event.class", "value": {"stringValue": class_name}},
            {"key": "x07.event.name", "value": {"stringValue": event_name}},
        ]
        + attrs
    }
    if body is not None:
        record["body"] = {"stringValue": body}
    return record

if scenario == "ok":
    records = [
        log_record(
            "app.http",
            "app.http",
            [
                {"key": "status", "value": {"intValue": "200"}},
                {"key": "duration_ms", "value": {"doubleValue": 90.0}},
            ],
            "app.http",
        ),
        log_record(
            "app.http",
            "app.http",
            [
                {"key": "status", "value": {"intValue": "200"}},
                {"key": "duration_ms", "value": {"doubleValue": 110.0}},
            ],
            "app.http",
        ),
    ]
elif scenario == "bridge_error":
    records = [
        log_record(
            "app.http",
            "app.http",
            [
                {"key": "status", "value": {"intValue": "500"}},
                {"key": "duration_ms", "value": {"doubleValue": 420.0}},
            ],
            "app.http",
        ),
        log_record(
            "app.http",
            "app.http",
            [
                {"key": "status", "value": {"intValue": "503"}},
                {"key": "duration_ms", "value": {"doubleValue": 460.0}},
            ],
            "app.http",
        ),
        log_record(
            "runtime.error",
            "runtime.error",
            [
                {"key": "message", "value": {"stringValue": "bridge payload invalid"}},
                {"key": "stage", "value": {"stringValue": "bridge_parse"}},
            ],
            "bridge payload invalid",
        ),
    ]
elif scenario == "webview_crash":
    records = [
        log_record(
            "app.http",
            "app.http",
            [
                {"key": "status", "value": {"intValue": "500"}},
                {"key": "duration_ms", "value": {"doubleValue": 420.0}},
            ],
            "app.http",
        ),
        log_record(
            "host.webview_crash",
            "host.webview_crash",
            [
                {"key": "message", "value": {"stringValue": "device host webview crashed"}},
            ],
            "device host webview crashed",
        ),
    ]
else:
    raise SystemExit(f"unsupported telemetry scenario: {scenario}")

payload = {
    "resourceLogs": [
        {
            "resource": {"attributes": resource_attrs},
            "scopeLogs": [{"logRecords": records}],
        }
    ]
}
print(json.dumps(payload))
PY
}

# Beta release
BETA_DIR="${TMP_DIR}/mock_beta_release"
mkdir -p "$BETA_DIR"
BETA_PLAN="${BETA_DIR}/plan.json"
run_create "${BETA_DIR}/create.run.json" "${BETA_DIR}/create.cli.json" "$MOCK_BETA_PROVIDER" "$IOS_PACKAGE" "$BETA_PLAN"
run_release "${BETA_DIR}/run.run.json" "${BETA_DIR}/run.cli.json" "$BETA_PLAN" "$IOS_PACKAGE"
BETA_EXEC_ID="$(extract_json_value "${BETA_DIR}/run.cli.json" "result.exec_id")"
run_query "${BETA_DIR}/query.run.json" "${BETA_DIR}/query.cli.json" "$BETA_EXEC_ID" full
assert_json_expr "${BETA_DIR}/query.cli.json" 'doc["ok"] is True and doc["result"]["current_state"] == "available" and doc["result"]["current_rollout_percent"] == 100 and doc["result"]["distribution_lane"] == "beta"' "mock beta release query did not show an available full rollout"

# Production promote with pause/resume/complete
PROMOTE_DIR="${TMP_DIR}/mock_production_promote"
mkdir -p "$PROMOTE_DIR"
PROMOTE_PLAN="${PROMOTE_DIR}/plan.json"
run_create "${PROMOTE_DIR}/create.run.json" "${PROMOTE_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$PROMOTE_PLAN"
run_validate "${PROMOTE_DIR}/validate.run.json" "${PROMOTE_DIR}/validate.cli.json" "$PROMOTE_PLAN"
assert_json_expr "${PROMOTE_DIR}/validate.cli.json" 'doc["ok"] is True and doc["result"]["provider_kind"] == "mock_v1"' "mock production plan validate failed"
run_release "${PROMOTE_DIR}/run.run.json" "${PROMOTE_DIR}/run.cli.json" "$PROMOTE_PLAN" "$IOS_PACKAGE"
PROMOTE_EXEC_ID="$(extract_json_value "${PROMOTE_DIR}/run.cli.json" "result.exec_id")"
assert_json_expr "${PROMOTE_DIR}/run.cli.json" 'doc["ok"] is True and doc["result"]["status"] == "completed" and doc["result"]["decision_count"] == 2' "mock production run did not finish with two decisions"
run_control "${PROMOTE_DIR}/pause.run.json" "${PROMOTE_DIR}/pause.cli.json" pause "$PROMOTE_EXEC_ID" cli_pause
run_control "${PROMOTE_DIR}/resume.run.json" "${PROMOTE_DIR}/resume.cli.json" resume "$PROMOTE_EXEC_ID" cli_resume
run_control "${PROMOTE_DIR}/complete.run.json" "${PROMOTE_DIR}/complete.cli.json" complete "$PROMOTE_EXEC_ID" cli_complete
run_query "${PROMOTE_DIR}/query.run.json" "${PROMOTE_DIR}/query.cli.json" "$PROMOTE_EXEC_ID" full
assert_json_expr "${PROMOTE_DIR}/query.cli.json" 'doc["ok"] is True and doc["result"]["current_state"] == "completed" and doc["result"]["current_rollout_percent"] == 100 and doc["result"]["provider_kind"] == "mock_v1"' "mock production release did not reach completed rollout"

# Provider validation: App Store Connect cannot use rollout.set_percent
INVALID_DIR="${TMP_DIR}/provider_validation_ios_invalid_percent"
mkdir -p "$INVALID_DIR"
run_validate "${INVALID_DIR}/validate.run.json" "${INVALID_DIR}/validate.cli.json" "$INVALID_PLAN" "$APPSTORE_PROVIDER"
assert_json_expr "${INVALID_DIR}/validate.cli.json" 'doc["ok"] is False and doc["exit_code"] == 10 and doc["diagnostics"][0]["code"] == "LP_DEVICE_RELEASE_PLAN_INVALID"' "App Store Connect invalid percent plan was not rejected"

# Live-provider gating stays explicit outside the default CI lane.
LIVE_REQUIRED_DIR="${TMP_DIR}/live_provider_required"
mkdir -p "$LIVE_REQUIRED_DIR"
APPSTORE_LIVE_PLAN="${LIVE_REQUIRED_DIR}/appstore.plan.json"
GOOGLEPLAY_LIVE_PLAN="${LIVE_REQUIRED_DIR}/googleplay.plan.json"
run_create "${LIVE_REQUIRED_DIR}/appstore.create.run.json" "${LIVE_REQUIRED_DIR}/appstore.create.cli.json" "$APPSTORE_PROVIDER" "$IOS_PACKAGE" "$APPSTORE_LIVE_PLAN"
run_release "${LIVE_REQUIRED_DIR}/appstore.run.run.json" "${LIVE_REQUIRED_DIR}/appstore.run.cli.json" "$APPSTORE_LIVE_PLAN" "$IOS_PACKAGE" || true
APPSTORE_LIVE_EXEC_ID="$(extract_json_value "${LIVE_REQUIRED_DIR}/appstore.run.cli.json" "result.exec_id")"
assert_json_expr "${LIVE_REQUIRED_DIR}/appstore.run.cli.json" 'doc["ok"] is False and doc["exit_code"] == 18 and doc["result"]["provider_kind"] == "appstoreconnect_v1" and doc["result"]["status"] == "failed"' "App Store Connect run did not surface a failed live-provider execution"
assert_json_expr "${STATE_DIR}/device_release/executions/${APPSTORE_LIVE_EXEC_ID}.json" 'doc["status"] == "failed" and "X07LP_DEVICE_PROVIDER_LIVE=1" in doc["meta"]["decisions"][0]["reasons"][0]["message"]' "App Store Connect execution did not record the live-provider requirement"
run_create "${LIVE_REQUIRED_DIR}/googleplay.create.run.json" "${LIVE_REQUIRED_DIR}/googleplay.create.cli.json" "$GOOGLEPLAY_PROVIDER" "$ANDROID_PACKAGE" "$GOOGLEPLAY_LIVE_PLAN"
run_release "${LIVE_REQUIRED_DIR}/googleplay.run.run.json" "${LIVE_REQUIRED_DIR}/googleplay.run.cli.json" "$GOOGLEPLAY_LIVE_PLAN" "$ANDROID_PACKAGE" || true
GOOGLEPLAY_LIVE_EXEC_ID="$(extract_json_value "${LIVE_REQUIRED_DIR}/googleplay.run.cli.json" "result.exec_id")"
assert_json_expr "${LIVE_REQUIRED_DIR}/googleplay.run.cli.json" 'doc["ok"] is False and doc["exit_code"] == 18 and doc["result"]["provider_kind"] == "googleplay_v1" and doc["result"]["status"] == "failed"' "Google Play run did not surface a failed live-provider execution"
assert_json_expr "${STATE_DIR}/device_release/executions/${GOOGLEPLAY_LIVE_EXEC_ID}.json" 'doc["status"] == "failed" and "X07LP_DEVICE_PROVIDER_LIVE=1" in doc["meta"]["decisions"][0]["reasons"][0]["message"]' "Google Play execution did not record the live-provider requirement"

# Android staged rollback stays on the mock lane in default CI.
ROLLBACK_DIR="${TMP_DIR}/mock_android_rollback"
mkdir -p "$ROLLBACK_DIR"
ROLLBACK_PLAN="${ROLLBACK_DIR}/plan.json"
run_create "${ROLLBACK_DIR}/create.run.json" "${ROLLBACK_DIR}/create.cli.json" "$MOCK_PROD_ANDROID_PROVIDER" "$ANDROID_PACKAGE" "$ROLLBACK_PLAN"
run_validate "${ROLLBACK_DIR}/validate.run.json" "${ROLLBACK_DIR}/validate.cli.json" "$ROLLBACK_PLAN"
run_release "${ROLLBACK_DIR}/run.run.json" "${ROLLBACK_DIR}/run.cli.json" "$ROLLBACK_PLAN" "$ANDROID_PACKAGE"
ROLLBACK_EXEC_ID="$(extract_json_value "${ROLLBACK_DIR}/run.cli.json" "result.exec_id")"
run_control "${ROLLBACK_DIR}/rollback.run.json" "${ROLLBACK_DIR}/rollback.cli.json" rollback "$ROLLBACK_EXEC_ID" cli_rollback
run_query "${ROLLBACK_DIR}/query.run.json" "${ROLLBACK_DIR}/query.cli.json" "$ROLLBACK_EXEC_ID" full
assert_json_expr "${ROLLBACK_DIR}/query.cli.json" 'doc["ok"] is True and doc["result"]["provider_kind"] == "mock_v1" and doc["result"]["target"] == "android" and doc["result"]["current_state"] == "rolled_back" and doc["result"]["current_rollout_percent"] == 0' "mock Android release did not roll back to zero percent"

# Command Center list/detail/actions
UI_DIR="${TMP_DIR}/command_center_device_release"
mkdir -p "$UI_DIR"
UI_PLAN="${UI_DIR}/plan.json"
run_create "${UI_DIR}/create.run.json" "${UI_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$UI_PLAN"
run_release "${UI_DIR}/run.run.json" "${UI_DIR}/run.cli.json" "$UI_PLAN" "$IOS_PACKAGE"
UI_EXEC_ID="$(extract_json_value "${UI_DIR}/run.cli.json" "result.exec_id")"
(
  cd "$ROOT_DIR"
  exec scripts/x07lp-driver ui-serve --addr "$UI_ADDR" --state-dir "$STATE_DIR" >/dev/null 2>&1
) &
UI_SERVER_PID="$!"
PIDS+=("$UI_SERVER_PID")
wait_for_http "${UI_BASE_URL}/healthz" 30
curl -fsS "${UI_BASE_URL}/api/device-releases" >"${UI_DIR}/api.device-releases.json"
curl -fsS "${UI_BASE_URL}/api/device-releases/${UI_EXEC_ID}" >"${UI_DIR}/api.device-release.get.json"
curl -fsS -X POST -H 'content-type: application/json' -d '{"reason":"ui_pause"}' "${UI_BASE_URL}/api/device-releases/${UI_EXEC_ID}/pause" >"${UI_DIR}/api.device-release.pause.json"
curl -fsS -X POST -H 'content-type: application/json' -d '{"reason":"ui_resume"}' "${UI_BASE_URL}/api/device-releases/${UI_EXEC_ID}/resume" >"${UI_DIR}/api.device-release.resume.json"
curl -fsS -X POST -H 'content-type: application/json' -d '{"reason":"ui_complete"}' "${UI_BASE_URL}/api/device-releases/${UI_EXEC_ID}/complete" >"${UI_DIR}/api.device-release.complete.json"
curl -fsS "${UI_BASE_URL}/api/device-releases/${UI_EXEC_ID}" >"${UI_DIR}/api.device-release.after.json"
assert_json_expr "${UI_DIR}/api.device-releases.json" 'doc["ok"] is True and any(item["exec_id"] == "'"${UI_EXEC_ID}"'" for item in doc["result"]["items"])' "device release list did not include the UI execution"
assert_json_expr "${UI_DIR}/api.device-release.get.json" 'doc["ok"] is True and doc["result"]["exec_id"] == "'"${UI_EXEC_ID}"'" and doc["result"]["current_state"] == "in_progress"' "device release detail did not show the expected in-progress state"
assert_json_expr "${UI_DIR}/api.device-release.complete.json" 'doc["ok"] is True and doc["result"]["kind"] == "device.release.complete.manual" and doc["result"]["state_after"]["current_state"] == "completed"' "device release complete control did not produce the expected state transition"
assert_json_expr "${UI_DIR}/api.device-release.after.json" 'doc["ok"] is True and doc["result"]["current_state"] == "completed" and doc["result"]["current_rollout_percent"] == 100' "device release detail did not show a completed rollout after UI actions"
stop_pid "$UI_SERVER_PID"

# Metrics observe / stop / rerun
OBSERVE_OK_DIR="${TMP_DIR}/metrics_continue"
mkdir -p "$OBSERVE_OK_DIR"
OBSERVE_OK_PLAN="${OBSERVE_OK_DIR}/plan.json"
run_create "${OBSERVE_OK_DIR}/create.run.json" "${OBSERVE_OK_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$OBSERVE_OK_PLAN" "$SLO_PROFILE" "300" "release.pause"
run_release "${OBSERVE_OK_DIR}/run.run.json" "${OBSERVE_OK_DIR}/run.cli.json" "$OBSERVE_OK_PLAN" "$IOS_PACKAGE"
OBSERVE_OK_EXEC_ID="$(extract_json_value "${OBSERVE_OK_DIR}/run.cli.json" "result.exec_id")"
assert_json_expr "${OBSERVE_OK_DIR}/run.cli.json" 'doc["ok"] is True and doc["result"]["status"] == "started"' "metrics-gated release did not pause at the observe waitpoint"
run_query "${OBSERVE_OK_DIR}/query.before.run.json" "${OBSERVE_OK_DIR}/query.before.cli.json" "$OBSERVE_OK_EXEC_ID" full
assert_json_expr "${OBSERVE_OK_DIR}/query.before.cli.json" 'doc["ok"] is True and doc["result"]["automation_state"] == "waiting_for_observation" and doc["result"]["meta"]["source_package_manifest_path"] != doc["result"]["meta"]["staged_package_manifest_path"] and doc["result"]["meta"]["staged_package_manifest_path"].endswith("/device_release/packages/" + doc["result"]["exec_id"] + "/device.package.manifest.json")' "release run did not stop at waiting_for_observation with an isolated staged package"
seed_otlp_export "$OBSERVE_OK_EXEC_ID" ok
run_control "${OBSERVE_OK_DIR}/observe.run.json" "${OBSERVE_OK_DIR}/observe.cli.json" observe "$OBSERVE_OK_EXEC_ID" cli_observe
run_query "${OBSERVE_OK_DIR}/query.after.run.json" "${OBSERVE_OK_DIR}/query.after.cli.json" "$OBSERVE_OK_EXEC_ID" full
assert_json_expr "${OBSERVE_OK_DIR}/observe.cli.json" 'doc["ok"] is True and doc["result"]["kind"] == "device.release.observe.manual"' "observe did not emit the expected control action result"
assert_json_expr "${OBSERVE_OK_DIR}/query.after.cli.json" 'doc["ok"] is True and doc["result"]["status"] == "completed" and doc["result"]["latest_eval_outcome"] == "ok" and doc["result"]["latest_metrics_snapshot"] is not None and doc["result"]["latest_slo_eval_report"] is not None and doc["result"]["meta"]["staged_package_manifest_path"].endswith("/device_release/packages/" + doc["result"]["exec_id"] + "/device.package.manifest.json")' "observe did not promote and persist the OTLP-derived metrics evaluation artifacts"

OBSERVE_BAD_DIR="${TMP_DIR}/metrics_pause"
mkdir -p "$OBSERVE_BAD_DIR"
OBSERVE_BAD_PLAN="${OBSERVE_BAD_DIR}/plan.json"
run_create "${OBSERVE_BAD_DIR}/create.run.json" "${OBSERVE_BAD_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$OBSERVE_BAD_PLAN" "$SLO_PROFILE" "300" "release.pause"
run_release "${OBSERVE_BAD_DIR}/run.run.json" "${OBSERVE_BAD_DIR}/run.cli.json" "$OBSERVE_BAD_PLAN" "$IOS_PACKAGE"
OBSERVE_BAD_EXEC_ID="$(extract_json_value "${OBSERVE_BAD_DIR}/run.cli.json" "result.exec_id")"
seed_otlp_export "$OBSERVE_BAD_EXEC_ID" bridge_error
run_control "${OBSERVE_BAD_DIR}/observe.run.json" "${OBSERVE_BAD_DIR}/observe.cli.json" observe "$OBSERVE_BAD_EXEC_ID" cli_observe_bad
run_query "${OBSERVE_BAD_DIR}/query.after.run.json" "${OBSERVE_BAD_DIR}/query.after.cli.json" "$OBSERVE_BAD_EXEC_ID" full
assert_json_expr "${OBSERVE_BAD_DIR}/query.after.cli.json" 'doc["ok"] is True and doc["result"]["current_state"] == "paused" and doc["result"]["automation_state"] == "paused" and doc["result"]["latest_eval_outcome"] == "fail" and any(item["classification"] == "device_bridge_parse" for item in doc["result"]["linked_incidents"])' "bad OTLP telemetry did not pause the release and capture the bridge incident"
run_control "${OBSERVE_BAD_DIR}/stop.run.json" "${OBSERVE_BAD_DIR}/stop.cli.json" stop "$OBSERVE_BAD_EXEC_ID" cli_stop
run_query "${OBSERVE_BAD_DIR}/query.stopped.run.json" "${OBSERVE_BAD_DIR}/query.stopped.cli.json" "$OBSERVE_BAD_EXEC_ID" full
assert_json_expr "${OBSERVE_BAD_DIR}/stop.cli.json" 'doc["ok"] is True and doc["result"]["kind"] == "device.release.stop.manual"' "stop did not emit the expected control action result"
assert_json_expr "${OBSERVE_BAD_DIR}/query.stopped.cli.json" 'doc["ok"] is True and doc["result"]["automation_state"] == "stopped" and doc["result"]["current_rollout_percent"] == 25' "stop changed rollout state instead of only stopping automation"
run_control "${OBSERVE_BAD_DIR}/rerun.run.json" "${OBSERVE_BAD_DIR}/rerun.cli.json" rerun "$OBSERVE_BAD_EXEC_ID" cli_rerun
RERUN_EXEC_ID="$(extract_json_value "${OBSERVE_BAD_DIR}/rerun.cli.json" "result.new_execution_id")"
run_query "${OBSERVE_BAD_DIR}/rerun.query.run.json" "${OBSERVE_BAD_DIR}/rerun.query.cli.json" "$RERUN_EXEC_ID" full
assert_json_expr "${OBSERVE_BAD_DIR}/rerun.cli.json" 'doc["ok"] is True and doc["result"]["kind"] == "device.release.rerun.manual" and doc["result"]["new_execution_id"] == "'"${RERUN_EXEC_ID}"'"' "rerun did not create a new execution id"
assert_json_expr "${OBSERVE_BAD_DIR}/rerun.query.cli.json" 'doc["ok"] is True and doc["result"]["automation_state"] == "waiting_for_observation" and doc["result"]["meta"]["parent_exec_id"] == "'"${OBSERVE_BAD_EXEC_ID}"'" and doc["result"]["meta"]["staged_package_manifest_path"].endswith("/device_release/packages/" + doc["result"]["exec_id"] + "/device.package.manifest.json")' "rerun did not create a fresh execution with a new staged package at the next metrics waitpoint"

HALT_DIR="${TMP_DIR}/metrics_halt"
mkdir -p "$HALT_DIR"
HALT_PLAN="${HALT_DIR}/plan.json"
run_create "${HALT_DIR}/create.run.json" "${HALT_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$HALT_PLAN" "$SLO_PROFILE" "300" "release.halt"
run_release "${HALT_DIR}/run.run.json" "${HALT_DIR}/run.cli.json" "$HALT_PLAN" "$IOS_PACKAGE"
HALT_EXEC_ID="$(extract_json_value "${HALT_DIR}/run.cli.json" "result.exec_id")"
seed_otlp_export "$HALT_EXEC_ID" webview_crash
run_control "${HALT_DIR}/observe.run.json" "${HALT_DIR}/observe.cli.json" observe "$HALT_EXEC_ID" cli_observe_halt
run_query "${HALT_DIR}/query.after.run.json" "${HALT_DIR}/query.after.cli.json" "$HALT_EXEC_ID" full
assert_json_expr "${HALT_DIR}/query.after.cli.json" 'doc["ok"] is True and doc["result"]["status"] == "aborted" and doc["result"]["current_state"] == "halted" and doc["result"]["automation_state"] == "stopped" and doc["result"]["latest_eval_outcome"] == "fail" and any(item["classification"] == "device_webview_crash" for item in doc["result"]["linked_incidents"])' "bad OTLP telemetry did not halt the release on a webview crash"

INCIDENT_DIR="${TMP_DIR}/device_incident_to_regression"
mkdir -p "$INCIDENT_DIR" "${INCIDENT_DIR}/regress"
INCIDENT_PLAN="${INCIDENT_DIR}/plan.json"
run_create "${INCIDENT_DIR}/create.run.json" "${INCIDENT_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$INCIDENT_PLAN"
run_release "${INCIDENT_DIR}/run.run.json" "${INCIDENT_DIR}/run.cli.json" "$INCIDENT_PLAN" "$IOS_PACKAGE"
INCIDENT_EXEC_ID="$(extract_json_value "${INCIDENT_DIR}/run.cli.json" "result.exec_id")"
run_incident_capture "${INCIDENT_DIR}/capture.run.json" "${INCIDENT_DIR}/capture.cli.json" "$INCIDENT_EXEC_ID" "$TRACE_FIXTURE"
INCIDENT_ID="$(extract_json_value "${INCIDENT_DIR}/capture.cli.json" "result.incident_id")"
run_incident_list "${INCIDENT_DIR}/list.run.json" "${INCIDENT_DIR}/list.cli.json" "$INCIDENT_EXEC_ID"
run_regress "${INCIDENT_DIR}/regress.run.json" "${INCIDENT_DIR}/regress.cli.json" "$INCIDENT_ID" "${INCIDENT_DIR}/regress" device_incident
run_query "${INCIDENT_DIR}/query.run.json" "${INCIDENT_DIR}/query.cli.json" "$INCIDENT_EXEC_ID" full
assert_json_expr "${INCIDENT_DIR}/capture.cli.json" 'doc["ok"] is True and doc["result"]["release_exec_id"] == "'"${INCIDENT_EXEC_ID}"'" and doc["result"]["device_release"]["release_exec_id"] == "'"${INCIDENT_EXEC_ID}"'"' "device incident capture did not bind to the release execution"
assert_json_expr "${INCIDENT_DIR}/list.cli.json" 'doc["ok"] is True and any(item["incident_id"] == "'"${INCIDENT_ID}"'" for item in doc["result"]["items"])' "device incident list did not include the captured incident"
assert_json_expr "${INCIDENT_DIR}/regress.cli.json" 'doc["ok"] is True and doc["result"]["tool"]["command"] == "device regress from-incident" and doc["result"]["incident_status_after"] == "generated" and len(doc["result"]["generated"]) >= 1' "device incident regression did not complete through the device regression path"
assert_json_expr "${INCIDENT_DIR}/query.cli.json" 'doc["ok"] is True and any(item["incident_id"] == "'"${INCIDENT_ID}"'" and item["regression_status"] == "generated" for item in doc["result"]["linked_incidents"])' "device release query did not reflect the linked incident regression state"

echo "ok: device release"
