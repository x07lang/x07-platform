#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/ci/lib/workload-k3s-common.sh"

x07lp_k3s_require_prereqs
x07lp_k3s_init_env "k3s_chaos"
trap x07lp_k3s_cleanup EXIT

x07lp_k3s_prepare_target
x07lp_k3s_pack_api_example
x07lp_k3s_accept_api_workload
x07lp_k3s_run_api_workload

route_url="$(x07lp_k3s_route_url_from_report "$OUT_DIR/workload.run.json")"
deployment_name="$(x07lp_k3s_resource_name_from_report "$OUT_DIR/workload.run.json" deployment_name)"
service_name="$(x07lp_k3s_resource_name_from_report "$OUT_DIR/workload.run.json" service_name)"

x07lp_k3s_wait_for_route "$route_url" 30 "$OUT_DIR/curl.response.initial.txt"
x07lp_k3s_seed_example_bindings

kubectl --context "$CLUSTER_CONTEXT" -n "$NAMESPACE" delete deployment "$deployment_name"
x07lp_k3s_wait_for_resource_absent deployment "$deployment_name" 30
x07lp_k3s_reconcile_api_workload "$OUT_DIR/workload.reconcile.after-deployment.json"
x07lp_k3s_wait_for_route "$route_url" 40 "$OUT_DIR/curl.response.after-deployment.txt"

kubectl --context "$CLUSTER_CONTEXT" -n "$NAMESPACE" delete service "$service_name"
x07lp_k3s_wait_for_resource_absent service "$service_name" 30
x07lp_k3s_reconcile_api_workload "$OUT_DIR/workload.reconcile.after-service.json"
x07lp_k3s_wait_for_route "$route_url" 40 "$OUT_DIR/curl.response.after-service.txt"
x07lp_k3s_query_api_workload "$OUT_DIR/workload.query.after-chaos.json"
x07lp_k3s_assert_query_running "$OUT_DIR/workload.query.after-chaos.json"

x07lp_k3s_stop_api_workload
x07lp_k3s_wait_for_stop "$route_url" 30

echo "ok: k3s workload chaos passed"
