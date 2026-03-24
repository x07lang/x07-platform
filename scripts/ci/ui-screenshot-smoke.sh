#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LP="$ROOT_DIR/scripts/x07lp-driver"

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "python not found on PATH" >&2
  exit 1
fi

STATE_DIR=""
OUT_DIR=""
ADDR="127.0.0.1:17090"
WAIT_SELECTOR=".top-bar"
WAIT_TIMEOUT_MS="2000"

usage() {
  cat <<'USAGE' >&2
Usage: ui-screenshot-smoke.sh --state-dir <dir> --out-dir <dir> [--addr 127.0.0.1:17090]

Starts `x07lp-driver ui-serve` against the provided state dir, then captures a
minimum screenshot set via Playwright:
- /apps
- /device-releases
- /deployments/<latest> (if discoverable)
- /incidents/<latest> (if discoverable)
- /device-releases/<latest> (if discoverable)

This script never reads global x07lp target config and always uses `--target __local__`
for any CLI discovery calls.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-dir)
      STATE_DIR="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --addr)
      ADDR="${2:-}"
      shift 2
      ;;
    --wait-selector)
      WAIT_SELECTOR="${2:-}"
      shift 2
      ;;
    --wait-timeout-ms)
      WAIT_TIMEOUT_MS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$STATE_DIR" || -z "$OUT_DIR" ]]; then
  usage
  exit 2
fi

mkdir -p "$OUT_DIR"

BASE_URL="http://${ADDR}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

(
  cd "$ROOT_DIR"
  exec "$LP" ui-serve --addr "$ADDR" --state-dir "$STATE_DIR" >"$OUT_DIR/x07lpd.log" 2>&1
) &
UI_PID=$!
PIDS+=("$UI_PID")

wait_for_http() {
  local url="$1"
  local attempts="${2:-30}"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for UI server: $url" >&2
  return 1
}

wait_for_http "${BASE_URL}/" 30

discover_latest_deployment_id() {
  local out_path="$1"
  (
    cd "$ROOT_DIR"
    "$LP" app-list --state-dir "$STATE_DIR" --rebuild-index --limit 1 --json >"$out_path"
  ) || return 1
  "$PYTHON" - "$out_path" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items = doc.get("result", {}).get("items", [])
for item in items:
    value = item.get("latest_deployment_id")
    if isinstance(value, str) and value:
        print(value)
        break
PY
}

discover_latest_incident_id() {
  local out_path="$1"
  (
    cd "$ROOT_DIR"
    "$LP" incident-list --target __local__ --state-dir "$STATE_DIR" --rebuild-index --limit 1 --json >"$out_path"
  ) || return 1
  "$PYTHON" - "$out_path" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items = doc.get("result", {}).get("items", [])
for item in items:
    value = item.get("incident_id")
    if isinstance(value, str) and value:
        print(value)
        break
PY
}

discover_latest_device_release_id() {
  local out_path="$1"
  (
    cd "$ROOT_DIR"
    "$LP" device-release-query --target __local__ --state-dir "$STATE_DIR" --latest --limit 1 --json >"$out_path"
  ) || return 1
  "$PYTHON" - "$out_path" <<'PY'
import json
import pathlib
import sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items = doc.get("result", {}).get("items", [])
for item in items:
    for key in ("exec_id", "release_exec_id", "id"):
        value = item.get(key)
        if isinstance(value, str) and value:
            print(value)
            raise SystemExit(0)
PY
}

shot() {
  local path="$1"
  local filename="$2"
  npx --yes playwright screenshot \
    --browser chromium \
    --color-scheme dark \
    --wait-for-selector "$WAIT_SELECTOR" \
    --wait-for-timeout "$WAIT_TIMEOUT_MS" \
    --full-page \
    "${BASE_URL}${path}" \
    "${OUT_DIR}/${filename}" \
    >/dev/null
}

DEPLOYMENT_ID=""
INCIDENT_ID=""
DEVICE_RELEASE_ID=""

if DEPLOYMENT_ID="$(discover_latest_deployment_id "$OUT_DIR/app-list.json" 2>/dev/null)"; then
  true
fi
if INCIDENT_ID="$(discover_latest_incident_id "$OUT_DIR/incident-list.json" 2>/dev/null)"; then
  true
fi
if DEVICE_RELEASE_ID="$(discover_latest_device_release_id "$OUT_DIR/device-release-query.json" 2>/dev/null)"; then
  true
fi

shot "/apps" "apps.png"
shot "/device-releases" "device-releases.png"

if [[ -n "${DEPLOYMENT_ID:-}" ]]; then
  shot "/deployments/${DEPLOYMENT_ID}" "deployment.png"
fi
if [[ -n "${INCIDENT_ID:-}" ]]; then
  shot "/incidents/${INCIDENT_ID}" "incident.png"
fi
if [[ -n "${DEVICE_RELEASE_ID:-}" ]]; then
  shot "/device-releases/${DEVICE_RELEASE_ID}" "device-release-detail.png"
fi

cat >"$OUT_DIR/ids.json" <<JSON
{
  "base_url": "${BASE_URL}",
  "deployment_id": "${DEPLOYMENT_ID}",
  "incident_id": "${INCIDENT_ID}",
  "device_release_id": "${DEVICE_RELEASE_ID}"
}
JSON

echo "ok: ui screenshots at $OUT_DIR"
