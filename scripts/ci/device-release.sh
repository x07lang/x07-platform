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
    "lp.device.release.pause",
    "lp.device.release.resume",
    "lp.device.release.halt",
    "lp.device.release.complete",
    "lp.device.release.rollback",
}
missing = sorted(required - names)
if missing:
    raise SystemExit(f"missing MCP tools: {missing}")
PY
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

IOS_PACKAGE="spec/fixtures/device-release/common/package_ios_demo/device.package.manifest.json"
ANDROID_PACKAGE="spec/fixtures/device-release/common/package_android_demo/device.package.manifest.json"
MOCK_BETA_PROVIDER="spec/fixtures/device-release/common/providers/mock_beta_ios.json"
MOCK_PROD_PROVIDER="spec/fixtures/device-release/common/providers/mock_production_ios.json"
GOOGLEPLAY_PROVIDER="spec/fixtures/device-release/common/providers/googleplay_production_android.json"
APPSTORE_PROVIDER="spec/fixtures/device-release/common/providers/appstoreconnect_production_ios.json"
INVALID_PLAN="spec/fixtures/device-release/provider_validation_ios_invalid_percent/invalid.plan.json"

run_create() {
  local report_path="$1"
  local out_path="$2"
  local provider="$3"
  local package_manifest="$4"
  local plan_path="$5"
  local provider_arg
  local package_arg
  local plan_arg
  provider_arg="$(repo_path_arg "$provider")"
  package_arg="$(repo_path_arg "$package_manifest")"
  plan_arg="$(repo_path_arg "$plan_path")"
  run_x07lp "$report_path" "$out_path" \
    device release-create \
    --provider-profile "$provider_arg" \
    --package-manifest "$package_arg" \
    --out "$plan_arg" \
    --state-dir "$STATE_DIR_ARG" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --json
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

# 11A: beta release
BETA_DIR="${TMP_DIR}/mock_beta_release"
mkdir -p "$BETA_DIR"
BETA_PLAN="${BETA_DIR}/plan.json"
run_create "${BETA_DIR}/create.run.json" "${BETA_DIR}/create.cli.json" "$MOCK_BETA_PROVIDER" "$IOS_PACKAGE" "$BETA_PLAN"
run_release "${BETA_DIR}/run.run.json" "${BETA_DIR}/run.cli.json" "$BETA_PLAN" "$IOS_PACKAGE"
BETA_EXEC_ID="$(extract_json_value "${BETA_DIR}/run.cli.json" "result.exec_id")"
run_query "${BETA_DIR}/query.run.json" "${BETA_DIR}/query.cli.json" "$BETA_EXEC_ID" full
assert_json_expr "${BETA_DIR}/query.cli.json" 'doc["ok"] is True and doc["result"]["current_state"] == "available" and doc["result"]["current_rollout_percent"] == 100 and doc["result"]["distribution_lane"] == "beta"' "mock beta release query did not show an available full rollout"

# 11B: production promote with pause/resume/complete
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

# Google Play rollback
ROLLBACK_DIR="${TMP_DIR}/mock_googleplay_rollback"
mkdir -p "$ROLLBACK_DIR"
ROLLBACK_PLAN="${ROLLBACK_DIR}/plan.json"
run_create "${ROLLBACK_DIR}/create.run.json" "${ROLLBACK_DIR}/create.cli.json" "$GOOGLEPLAY_PROVIDER" "$ANDROID_PACKAGE" "$ROLLBACK_PLAN"
run_validate "${ROLLBACK_DIR}/validate.run.json" "${ROLLBACK_DIR}/validate.cli.json" "$ROLLBACK_PLAN" "$GOOGLEPLAY_PROVIDER"
run_release "${ROLLBACK_DIR}/run.run.json" "${ROLLBACK_DIR}/run.cli.json" "$ROLLBACK_PLAN" "$ANDROID_PACKAGE"
ROLLBACK_EXEC_ID="$(extract_json_value "${ROLLBACK_DIR}/run.cli.json" "result.exec_id")"
run_control "${ROLLBACK_DIR}/rollback.run.json" "${ROLLBACK_DIR}/rollback.cli.json" rollback "$ROLLBACK_EXEC_ID" cli_rollback
run_query "${ROLLBACK_DIR}/query.run.json" "${ROLLBACK_DIR}/query.cli.json" "$ROLLBACK_EXEC_ID" full
assert_json_expr "${ROLLBACK_DIR}/query.cli.json" 'doc["ok"] is True and doc["result"]["provider_kind"] == "googleplay_v1" and doc["result"]["current_state"] == "rolled_back" and doc["result"]["current_rollout_percent"] == 0' "Google Play release did not roll back to zero percent"

# Command Center list/detail/actions
UI_DIR="${TMP_DIR}/command_center_device_release"
mkdir -p "$UI_DIR"
UI_PLAN="${UI_DIR}/plan.json"
run_create "${UI_DIR}/create.run.json" "${UI_DIR}/create.cli.json" "$MOCK_PROD_PROVIDER" "$IOS_PACKAGE" "$UI_PLAN"
run_release "${UI_DIR}/run.run.json" "${UI_DIR}/run.cli.json" "$UI_PLAN" "$IOS_PACKAGE"
UI_EXEC_ID="$(extract_json_value "${UI_DIR}/run.cli.json" "result.exec_id")"
(
  cd "$ROOT_DIR"
  scripts/x07lp-driver ui-serve --addr "$UI_ADDR" --state-dir "$STATE_DIR" >/dev/null 2>&1
) &
PIDS+=("$!")
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

echo "ok: device release"
