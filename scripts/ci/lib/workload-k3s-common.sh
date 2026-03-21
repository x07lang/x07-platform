#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$(cd "$ROOT_DIR/.." && pwd)}"
X07_WASM_DIR="${X07_WASM_DIR:-$WORKSPACE_DIR/x07-wasm-backend}"
X07_DIR="${X07_DIR:-$WORKSPACE_DIR/x07}"
LP_SCRIPT="${LP_SCRIPT:-$ROOT_DIR/scripts/x07lp-driver}"
WORKLOAD_ID="${WORKLOAD_ID:-svc_api_cell_v1}"

x07lp_k3s_require_prereqs() {
  for bin in k3d kubectl curl python3; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "missing required binary: $bin" >&2
      exit 1
    fi
  done

  if [[ ! -d "$X07_WASM_DIR" || ! -d "$X07_DIR" ]]; then
    echo "expected sibling repos x07-wasm-backend and x07" >&2
    exit 1
  fi
}

x07lp_pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

x07lp_k3s_init_env() {
  local lane="${1:-k3s_smoke}"
  if [[ -n "${K3D_CLUSTER_NAME:-}" ]]; then
    CLUSTER_NAME="$K3D_CLUSTER_NAME"
  else
    CLUSTER_NAME="x07lp-${lane//_/-}-$$"
  fi
  CLUSTER_CONTEXT="k3d-${CLUSTER_NAME}"
  if [[ -n "${K3D_PORT:-}" ]]; then
    PUBLIC_PORT="$K3D_PORT"
  elif [[ -n "${K3D_CLUSTER_NAME:-}" ]]; then
    PUBLIC_PORT=18081
  else
    PUBLIC_PORT="$(x07lp_pick_free_port)"
  fi
  PUBLIC_BASE_URL="http://127.0.0.1:${PUBLIC_PORT}"
  CONFIG_DIR="${X07LP_CONFIG_DIR:-$ROOT_DIR/_tmp/${lane}/config}"
  STATE_DIR="${STATE_DIR:-$ROOT_DIR/_tmp/${lane}/state}"
  OUT_DIR="${OUT_DIR:-$ROOT_DIR/_tmp/${lane}/out}"
  PACK_DIR="$OUT_DIR/workload-pack"
  TARGET_PROFILE="$OUT_DIR/k3s.target.json"
  TOKEN_PATH="$CONFIG_DIR/tokens/k3s-local.token"
  NAMESPACE="${X07LP_K8S_NAMESPACE:-x07-smoke}"
  CREATED_CLUSTER=0
}

x07lp_k3s_cleanup() {
  set +e
  if [[ "${CREATED_CLUSTER:-0}" -eq 1 ]]; then
    k3d cluster delete "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
}

x07lp_k3s_prepare_target() {
  mkdir -p "$CONFIG_DIR/tokens" "$STATE_DIR" "$OUT_DIR"
  printf 'local-k8s-token\n' >"$TOKEN_PATH"
  chmod 600 "$TOKEN_PATH"

  if ! k3d cluster list | awk 'NR>1 {print $1}' | grep -Fxq "$CLUSTER_NAME"; then
    k3d cluster create "$CLUSTER_NAME" --agents 1 -p "${PUBLIC_PORT}:80@loadbalancer"
    CREATED_CLUSTER=1
  fi

  kubectl --context "$CLUSTER_CONTEXT" get nodes >/dev/null

  cat >"$TARGET_PROFILE" <<JSON
{
  "schema_version": "lp.target.profile@0.1.0",
  "name": "k3s-local",
  "kind": "k8s",
  "base_url": "${PUBLIC_BASE_URL}",
  "api_version": "v1",
  "auth": {
    "kind": "static_bearer",
    "token_ref": "file://${TOKEN_PATH}"
  },
  "tls": {
    "mode": "system"
  },
  "runtime_provider": "lp.impl.runtime.k8s_v1",
  "routing_provider": "lp.impl.routing.k8s_ingress_v1",
  "cluster_ref": "${CLUSTER_CONTEXT}",
  "default_namespace": "${NAMESPACE}"
}
JSON

  X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" target-add --profile "$TARGET_PROFILE" >"$OUT_DIR/target-add.json"
  X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" target-use --name k3s-local >"$OUT_DIR/target-use.json"
}

x07lp_k3s_pack_api_example() {
  (
    cd "$X07_WASM_DIR"
    cargo run -p x07-wasm -- workload pack \
      --project "$X07_DIR/docs/examples/service_api_cell_v1/x07.json" \
      --manifest "$X07_DIR/docs/examples/service_api_cell_v1/arch/service/index.x07service.json" \
      --out-dir "$PACK_DIR" \
      --runtime-image traefik/whoami:v1.10.3 \
      --container-port 80 \
      --json pretty >"$OUT_DIR/workload.pack.report.json"
  )
}

x07lp_k3s_accept_api_workload() {
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload accept \
    --pack-manifest "$PACK_DIR/workload.pack.json" \
    --target k3s-local \
    --state-dir "$STATE_DIR" >"$OUT_DIR/workload.accept.json"
}

x07lp_k3s_run_api_workload() {
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload run \
    --workload "$WORKLOAD_ID" \
    --target k3s-local \
    --profile prod \
    --state-dir "$STATE_DIR" >"$OUT_DIR/workload.run.json"
}

x07lp_k3s_query_api_workload() {
  local output_path="${1:-$OUT_DIR/workload.query.full.json}"
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload query \
    --workload "$WORKLOAD_ID" \
    --target k3s-local \
    --view full \
    --state-dir "$STATE_DIR" >"$output_path"
}

x07lp_k3s_query_workload_list() {
  local output_path="${1:-$OUT_DIR/workload.query.list.json}"
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload query \
    --state-dir "$STATE_DIR" >"$output_path"
}

x07lp_k3s_query_bindings() {
  local output_path="${1:-$OUT_DIR/workload.bindings.json}"
  X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" workload bindings \
    --workload "$WORKLOAD_ID" \
    --target k3s-local \
    --state-dir "$STATE_DIR" >"$output_path"
}

x07lp_k3s_reconcile_api_workload() {
  local output_path="${1:-$OUT_DIR/workload.reconcile.json}"
  local cycles="${2:-1}"
  local interval_seconds="${3:-1}"
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload reconcile \
    --workload "$WORKLOAD_ID" \
    --target k3s-local \
    --cycles "$cycles" \
    --interval-seconds "$interval_seconds" \
    --state-dir "$STATE_DIR" >"$output_path"
}

x07lp_k3s_stop_api_workload() {
  X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload stop \
    --workload "$WORKLOAD_ID" \
    --target k3s-local \
    --state-dir "$STATE_DIR" >"$OUT_DIR/workload.stop.json"
}

x07lp_k3s_route_url_from_report() {
  local report_path="$1"
  python3 - <<'PY' "$report_path"
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print(doc["result"]["deployment"]["cells"][0]["route_url"])
PY
}

x07lp_k3s_resource_name_from_report() {
  local report_path="$1"
  local key="$2"
  python3 - <<'PY' "$report_path" "$key"
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
value = doc["result"]["deployment"]["cells"][0].get(sys.argv[2])
print("" if value is None else value)
PY
}

x07lp_k3s_wait_for_route() {
  local route_url="$1"
  local attempts="${2:-30}"
  local response_path="${3:-$OUT_DIR/curl.response.txt}"
  local ready=0
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$route_url" >"$response_path" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "route did not become ready: $route_url" >&2
    exit 1
  fi
}

x07lp_k3s_wait_for_stop() {
  local route_url="$1"
  local attempts="${2:-30}"
  local stopped=0
  for _ in $(seq 1 "$attempts"); do
    local status_code
    local remaining
    status_code="$(curl -sS -o /dev/null -w '%{http_code}' "$route_url" 2>/dev/null || true)"
    remaining="$(kubectl --context "$CLUSTER_CONTEXT" -n "$NAMESPACE" get deployment,service,ingress,cronjob,horizontalpodautoscaler -o name 2>/dev/null || true)"
    if [[ "$status_code" != "200" && -z "$remaining" ]]; then
      stopped=1
      break
    fi
    sleep 1
  done
  if [[ "$stopped" -ne 1 ]]; then
    echo "expected stopped workload route to become unavailable and resources to be removed" >&2
    exit 1
  fi
}

x07lp_k3s_assert_query_running() {
  local report_path="$1"
  python3 - <<'PY' "$report_path"
import json, sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
result = doc["result"]["workload"]
if result["observed_state"] != "running":
    raise SystemExit(f"expected observed_state=running, got {result['observed_state']}")
PY
}

x07lp_k3s_wait_for_resource_absent() {
  local kind="$1"
  local name="$2"
  local attempts="${3:-30}"
  local missing=0
  for _ in $(seq 1 "$attempts"); do
    if ! kubectl --context "$CLUSTER_CONTEXT" -n "$NAMESPACE" get "$kind" "$name" >/dev/null 2>&1; then
      missing=1
      break
    fi
    sleep 1
  done
  if [[ "$missing" -ne 1 ]]; then
    echo "expected ${kind}/${name} to be absent" >&2
    exit 1
  fi
}
