# Local Deploy

`x07-platform` can execute accepted `x07.app.pack@0.1.0` artifacts locally.

Behavior:
- `deploy accept` records the accepted pack, run record, decision record, and deployment execution.
- `deploy run` executes `x07.deploy.plan@0.2.0`, starts the local candidate runtime, applies routing weights, evaluates SLOs, and either promotes or rolls back.
- `deploy query` returns summary, timeline, decisions, artifacts, or full execution views.

The local execution path is deterministic:
- routing uses `X-LP-Route-Key`
- metrics and SLO reports are persisted as artifacts
- decisions and execution state are materialized under `lp.deploy.execution@0.1.0`

`x07.vm.bundle.manifest@0.2.0` remains an accepted platform artifact, but local execution is implemented for `x07.app.pack@0.1.0`.
