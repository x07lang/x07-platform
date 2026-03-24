#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE_DIR="$(cd "$ROOT_DIR/.." && pwd)"

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/_tmp/preprod/$RUN_ID}"

note() {
  printf '%s\n' "$*"
}

mkdir -p "$RUN_DIR"

export X07LP_CONFIG_DIR="${X07LP_CONFIG_DIR:-$RUN_DIR/config}"
mkdir -p "$X07LP_CONFIG_DIR"

note "preprod run id: $RUN_ID"
note "run dir: $RUN_DIR"
note "x07lp config dir: $X07LP_CONFIG_DIR"

cd "$ROOT_DIR"
source "$ROOT_DIR/scripts/ci/use_workspace_x07_bins.sh"

note "==> x07-platform check_all"
./scripts/ci/check_all.sh 2>&1 | tee "$RUN_DIR/check_all.log"

note "==> UI screenshots (Phase C promote_state)"
mkdir -p "$RUN_DIR/ui/phaseC"
./scripts/ci/ui-screenshot-smoke.sh \
  --state-dir "$ROOT_DIR/_tmp/ci_phaseC/promote_state" \
  --out-dir "$RUN_DIR/ui/phaseC" \
  --addr 127.0.0.1:17090

note "==> DB index snapshot (Phase C promote_state)"
STATE_DIR="$ROOT_DIR/_tmp/ci_phaseC/promote_state"
mkdir -p "$RUN_DIR/db"
{
  echo "== phaseb meta ==";
  sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select k,v from meta order by k;";
  echo "== phaseb counts ==";
  sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select count(*) as executions from executions;";
  echo "== phasec meta ==";
  sqlite3 "$STATE_DIR/index/phasec.sqlite" "select k,v from meta order by k;";
  echo "== phasec counts ==";
  sqlite3 "$STATE_DIR/index/phasec.sqlite" "select count(*) as incidents from incidents;";
} 2>&1 | tee "$RUN_DIR/db/index_checks.txt"

note "==> UI screenshots (device release state)"
mkdir -p "$RUN_DIR/ui/device_release"
./scripts/ci/ui-screenshot-smoke.sh \
  --state-dir "$ROOT_DIR/_tmp/ci_device_release/state" \
  --out-dir "$RUN_DIR/ui/device_release" \
  --addr 127.0.0.1:17091

note "==> k3s extended lane (k3d)"
K3D_CLUSTER_NAME="${K3D_CLUSTER_NAME:-x07lp-preprod}"
K3D_PORT="${K3D_PORT:-18081}"
export K3D_CLUSTER_NAME K3D_PORT

cleanup_k3d() {
  set +e
  if command -v k3d >/dev/null 2>&1; then
    k3d cluster delete "$K3D_CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup_k3d EXIT

if ! k3d cluster list | awk 'NR>1 {print $1}' | grep -Fxq "$K3D_CLUSTER_NAME"; then
  note "creating k3d cluster: $K3D_CLUSTER_NAME"
  k3d cluster create "$K3D_CLUSTER_NAME" --agents 1 -p "${K3D_PORT}:80@loadbalancer" >/dev/null
fi

(
  export X07LP_CONFIG_DIR="$RUN_DIR/k8s/config"
  export STATE_DIR="$RUN_DIR/k8s/state"
  export OUT_DIR="$RUN_DIR/k8s/out"
  mkdir -p "$X07LP_CONFIG_DIR" "$STATE_DIR" "$OUT_DIR"
  bash ./scripts/ci/target-conformance.sh k8s-extended 2>&1 | tee "$RUN_DIR/k8s_extended.log"
)

note "==> k8s snapshot"
mkdir -p "$RUN_DIR/k8s/snapshots"
kubectl --context "k3d-${K3D_CLUSTER_NAME}" get nodes -o wide >"$RUN_DIR/k8s/snapshots/nodes.txt"
kubectl --context "k3d-${K3D_CLUSTER_NAME}" get pods -A -o wide >"$RUN_DIR/k8s/snapshots/pods_all.txt"
kubectl --context "k3d-${K3D_CLUSTER_NAME}" get svc -A -o wide >"$RUN_DIR/k8s/snapshots/svc_all.txt"
kubectl --context "k3d-${K3D_CLUSTER_NAME}" get ingress -A -o wide >"$RUN_DIR/k8s/snapshots/ingress_all.txt"
kubectl --context "k3d-${K3D_CLUSTER_NAME}" get events -A --sort-by=.lastTimestamp >"$RUN_DIR/k8s/snapshots/events_all.txt"

note "==> optional CrewOps full gate"
if [[ -d "$WORKSPACE_DIR/x07-crewops" ]]; then
  (
    cd "$WORKSPACE_DIR/x07-crewops"
    bash scripts/ci/check_all.sh 2>&1 | tee "$RUN_DIR/crewops_check_all.log"
  )
else
  note "skip: missing sibling repo x07-crewops at $WORKSPACE_DIR/x07-crewops"
fi

note "ok: preprod run complete: $RUN_DIR"
