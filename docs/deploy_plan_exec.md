# Plan Execution

`deploy run` consumes an accepted deployment execution and an `x07.deploy.plan@0.2.0` plan.

If `--plan` is omitted, the platform generates a plan with `x07-wasm deploy plan`.

The x07 module entry path is:
- `lp.engine.deploy_run_v1`
- `lp.engine.deploy_retry_v1`
- `lp.engine.deploy_plan_exec_v1`

The local adapter path is:
- `lp.adapters.runtime_v1` via `lp.impl.runtime.wasmtime_v1`
- `lp.adapters.routing_v1` via `lp.impl.routing.devserver_v1`
- `lp.adapters.metrics_snapshot_v1` via `lp.impl.metrics_snapshot.local_http_v1`
- `lp.adapters.decision_index_v1` via `lp.impl.decision_index.sqlite_v1`

Execution flow:
- prepare and persist the plan
- start runtime slots
- update routing weights
- pause where required by the plan
- evaluate SLO gates with `x07-wasm slo eval`
- retry transient adapter failures and inconclusive analysis up to the bounded retry budget
- promote or roll back and persist the final decision trail

Explicit deploy diagnostics surfaced by the executor include:

- `LP_PLAN_GENERATE_FAILED`
- `LP_PLAN_EXEC_STEP_FAILED`
- `LP_RUNTIME_START_FAILED`
- `LP_RUNTIME_HEALTHCHECK_FAILED`
- `LP_ROUTER_BIND_FAILED`
- `LP_ROUTER_SET_WEIGHT_FAILED`
- `LP_SLO_EVAL_FAILED`
- `LP_DEPLOY_STOPPED`
- `LP_RUNTIME_STOP_FAILED`
- `LP_ROUTER_STOP_FAILED`
