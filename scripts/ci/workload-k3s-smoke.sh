#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/ci/lib/workload-k3s-common.sh"

x07lp_k3s_require_prereqs
x07lp_k3s_init_env "k3s_smoke"
trap x07lp_k3s_cleanup EXIT

x07lp_k3s_prepare_target
x07lp_k3s_pack_api_example
x07lp_k3s_accept_api_workload
x07lp_k3s_run_api_workload

route_url="$(x07lp_k3s_route_url_from_report "$OUT_DIR/workload.run.json")"
x07lp_k3s_wait_for_route "$route_url" 30 "$OUT_DIR/curl.response.txt"
x07lp_k3s_query_workload_list
x07lp_k3s_query_api_workload
x07lp_k3s_query_bindings
x07lp_k3s_stop_api_workload
x07lp_k3s_wait_for_stop "$route_url" 30

echo "ok: k3s workload smoke passed"
