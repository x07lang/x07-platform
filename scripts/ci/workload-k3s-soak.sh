#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/ci/lib/workload-k3s-common.sh"

SOAK_CYCLES="${X07LP_K8S_SOAK_CYCLES:-5}"

x07lp_k3s_require_prereqs
x07lp_k3s_init_env "k3s_soak"
trap x07lp_k3s_cleanup EXIT

x07lp_k3s_prepare_target
x07lp_k3s_pack_api_example
x07lp_k3s_accept_api_workload
x07lp_k3s_run_api_workload

route_url="$(x07lp_k3s_route_url_from_report "$OUT_DIR/workload.run.json")"
x07lp_k3s_wait_for_route "$route_url" 30 "$OUT_DIR/curl.response.initial.txt"

for cycle in $(seq 1 "$SOAK_CYCLES"); do
  x07lp_k3s_reconcile_api_workload "$OUT_DIR/workload.reconcile.${cycle}.json"
  x07lp_k3s_query_api_workload "$OUT_DIR/workload.query.full.${cycle}.json"
  x07lp_k3s_assert_query_running "$OUT_DIR/workload.query.full.${cycle}.json"
  x07lp_k3s_wait_for_route "$route_url" 10 "$OUT_DIR/curl.response.${cycle}.txt"
done

x07lp_k3s_stop_api_workload
x07lp_k3s_wait_for_stop "$route_url" 30

echo "ok: k3s workload soak passed (${SOAK_CYCLES} cycles)"
