#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE_DIR="$(cd "$ROOT_DIR/.." && pwd)"
X07_WASM_DIR="$WORKSPACE_DIR/x07-wasm-backend"
X07_DIR="$WORKSPACE_DIR/x07"
LP_SCRIPT="$ROOT_DIR/scripts/x07lp-driver"

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

pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

if [[ -n "${K3D_CLUSTER_NAME:-}" ]]; then
  CLUSTER_NAME="$K3D_CLUSTER_NAME"
else
  CLUSTER_NAME="x07lp-smoke-$$"
fi
CLUSTER_CONTEXT="k3d-${CLUSTER_NAME}"
if [[ -n "${K3D_PORT:-}" ]]; then
  PUBLIC_PORT="$K3D_PORT"
elif [[ -n "${K3D_CLUSTER_NAME:-}" ]]; then
  PUBLIC_PORT=18081
else
  PUBLIC_PORT="$(pick_free_port)"
fi
PUBLIC_BASE_URL="http://127.0.0.1:${PUBLIC_PORT}"
CONFIG_DIR="${X07LP_CONFIG_DIR:-$ROOT_DIR/_tmp/k3s_smoke/config}"
STATE_DIR="${STATE_DIR:-$ROOT_DIR/_tmp/k3s_smoke/state}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/_tmp/k3s_smoke/out}"
PACK_DIR="$OUT_DIR/workload-pack"
TARGET_PROFILE="$OUT_DIR/k3s.target.json"
TOKEN_PATH="$CONFIG_DIR/tokens/k3s-local.token"
NAMESPACE="${X07LP_K8S_NAMESPACE:-x07-smoke}"

created_cluster=0
cleanup() {
  set +e
  if [[ $created_cluster -eq 1 ]]; then
    k3d cluster delete "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "$CONFIG_DIR/tokens" "$STATE_DIR" "$OUT_DIR"
printf 'local-k8s-token\n' >"$TOKEN_PATH"
chmod 600 "$TOKEN_PATH"

if ! k3d cluster list | awk 'NR>1 {print $1}' | grep -Fxq "$CLUSTER_NAME"; then
  k3d cluster create "$CLUSTER_NAME" --agents 1 -p "${PUBLIC_PORT}:80@loadbalancer"
  created_cluster=1
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

X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" target-add --profile "$TARGET_PROFILE" >"$OUT_DIR/target-add.json"
X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" target-use --name k3s-local >"$OUT_DIR/target-use.json"
X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload accept \
  --pack-manifest "$PACK_DIR/workload.pack.json" \
  --target k3s-local \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.accept.json"
X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload run \
  --workload svc_api_cell_v1 \
  --target k3s-local \
  --profile prod \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.run.json"

route_url="$(python3 - <<'PY' "$OUT_DIR/workload.run.json"
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print(doc["result"]["deployment"]["cells"][0]["route_url"])
PY
)"

route_ready=0
for _ in $(seq 1 30); do
  if curl -fsS "$route_url" >"$OUT_DIR/curl.response.txt" 2>/dev/null; then
    route_ready=1
    break
  fi
  sleep 1
done
if [[ "$route_ready" -ne 1 ]]; then
  echo "route did not become ready: $route_url" >&2
  exit 1
fi

X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload query \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.query.list.json"
X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload query \
  --workload svc_api_cell_v1 \
  --target k3s-local \
  --view full \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.query.full.json"
X07LP_CONFIG_DIR="$CONFIG_DIR" "$LP_SCRIPT" workload bindings \
  --workload svc_api_cell_v1 \
  --target k3s-local \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.bindings.json"

X07LP_CONFIG_DIR="$CONFIG_DIR" X07LP_K8S_PUBLIC_BASE_URL="$PUBLIC_BASE_URL" "$LP_SCRIPT" workload stop \
  --workload svc_api_cell_v1 \
  --target k3s-local \
  --state-dir "$STATE_DIR" >"$OUT_DIR/workload.stop.json"

route_stopped=0
for _ in $(seq 1 30); do
  status_code="$(curl -sS -o /dev/null -w '%{http_code}' "$route_url" 2>/dev/null || true)"
  remaining="$(kubectl --context "$CLUSTER_CONTEXT" -n "$NAMESPACE" get deployment,service,ingress -o name 2>/dev/null || true)"
  if [[ "$status_code" != "200" && -z "$remaining" ]]; then
    route_stopped=1
    break
  fi
  sleep 1
done
if [[ "$route_stopped" -ne 1 ]]; then
  echo "expected stopped workload route to become unavailable and resources to be removed" >&2
  exit 1
fi

echo "ok: k3s workload smoke passed"
