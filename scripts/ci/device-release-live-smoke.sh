#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/ci/use_workspace_x07_bins.sh"
DRIVER="$ROOT_DIR/scripts/x07lp-driver"

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "python not found on PATH" >&2
  exit 1
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "missing required env: ${name}" >&2
    exit 1
  fi
}

require_env X07LP_DEVICE_PROVIDER_LIVE
require_env X07LP_DEVICE_SECRET_ID
require_env X07LP_DEVICE_SECRET_JSON

if [ "${X07LP_DEVICE_PROVIDER_LIVE}" != "1" ]; then
  echo "X07LP_DEVICE_PROVIDER_LIVE must be set to 1" >&2
  exit 1
fi

PROVIDER_PROFILE="${X07LP_DEVICE_PROVIDER_PROFILE:-spec/fixtures/device-release/common/providers/appstoreconnect_production_ios.json}"
PACKAGE_MANIFEST="${X07LP_DEVICE_PACKAGE_MANIFEST:-spec/fixtures/device-release/common/package_ios_demo/device.package.manifest.json}"
TMP_DIR="${X07LP_DEVICE_SMOKE_TMP_DIR:-$ROOT_DIR/_tmp/device_release_live_smoke}"
STATE_DIR="${TMP_DIR}/state"
PLAN_PATH="${TMP_DIR}/device-release.plan.json"
SECRET_STORE_SOURCE_PATH="${TMP_DIR}/remote-secret-store.plain.json"
SECRET_STORE_PATH="${TMP_DIR}/remote-secret-store.enc.json"
MASTER_KEY_PATH="${TMP_DIR}/remote-secret-store.key"
RUN_JSON_PATH="${TMP_DIR}/release-run.json"
KEEP_TMP="${X07LP_DEVICE_SMOKE_KEEP_TMP:-0}"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR" "$STATE_DIR"

cleanup() {
  local status=$?
  if [ "$status" -eq 0 ] && [ "$KEEP_TMP" != "1" ]; then
    rm -rf "$TMP_DIR"
  else
    echo "device-release live smoke artifacts: $TMP_DIR" >&2
  fi
  return "$status"
}
trap cleanup EXIT

printf '%s' "$(openssl rand -hex 32)" >"$MASTER_KEY_PATH"
chmod 600 "$MASTER_KEY_PATH"

"$PYTHON" - "$SECRET_STORE_SOURCE_PATH" "$X07LP_DEVICE_SECRET_ID" "$X07LP_DEVICE_SECRET_JSON" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
secret_id = sys.argv[2]
secret_json = sys.argv[3]
doc = {
    "schema_version": "lp.remote.secret.store.internal@0.1.0",
    "device": {
        secret_id: secret_json,
    },
}
path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
chmod 600 "$SECRET_STORE_SOURCE_PATH"

export X07LP_REMOTE_SECRET_MASTER_KEY_FILE="$MASTER_KEY_PATH"
export X07LP_REMOTE_SECRET_STORE_PATH="$SECRET_STORE_PATH"

"$DRIVER" secret-store-pack \
  --input "$SECRET_STORE_SOURCE_PATH" \
  --output "$SECRET_STORE_PATH" >/dev/null
chmod 600 "$SECRET_STORE_PATH"

"$DRIVER" device-release-create \
  --provider-profile "$PROVIDER_PROFILE" \
  --package-manifest "$PACKAGE_MANIFEST" \
  --out "$PLAN_PATH" \
  --state-dir "$STATE_DIR" \
  --json

"$DRIVER" device-release-validate \
  --plan "$PLAN_PATH" \
  --provider-profile "$PROVIDER_PROFILE" \
  --state-dir "$STATE_DIR" \
  --json

"$DRIVER" device-release-run \
  --plan "$PLAN_PATH" \
  --package-manifest "$PACKAGE_MANIFEST" \
  --state-dir "$STATE_DIR" \
  --json >"$RUN_JSON_PATH"

EXEC_ID="$("$PYTHON" - "$RUN_JSON_PATH" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(doc.get("result", {}).get("exec_id") or "")
PY
)"

if [ -z "$EXEC_ID" ]; then
  echo "device release run did not return exec_id" >&2
  cat "$RUN_JSON_PATH" >&2
  exit 1
fi

"$DRIVER" device-release-query \
  --release "$EXEC_ID" \
  --view full \
  --state-dir "$STATE_DIR" \
  --json
