#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIND="${1:-k8s}"

case "$KIND" in
  local)
    bash "$ROOT_DIR/scripts/ci/check_phaseA_golden.sh"
    bash "$ROOT_DIR/scripts/ci/phaseB.sh"
    exec bash "$ROOT_DIR/scripts/ci/phaseC.sh"
    ;;
  wasmcloud|remote-oss)
    exec bash "$ROOT_DIR/scripts/ci/remote-oss.sh"
    ;;
  k8s|k3s|local-k3s)
    exec bash "$ROOT_DIR/scripts/ci/workload-k3s-smoke.sh"
    ;;
  all)
    bash "$ROOT_DIR/scripts/ci/target-conformance.sh" local
    bash "$ROOT_DIR/scripts/ci/target-conformance.sh" wasmcloud
    exec bash "$ROOT_DIR/scripts/ci/target-conformance.sh" k8s
    ;;
  *)
    echo "usage: $0 [local|wasmcloud|remote-oss|k8s|k3s|local-k3s|all]" >&2
    echo "unsupported target conformance suite: $KIND" >&2
    exit 2
    ;;
esac
