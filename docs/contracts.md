# Contracts

Schemas live under `spec/schemas/` and are indexed by `spec/schemas/index.json`.

Primary platform artifacts:

- `lp.change_request@0.1.0`
- `lp.pipeline.run@0.1.0`
- `lp.decision.record@0.1.0`
- `lp.deploy.execution@0.1.0`
- `lp.deploy.execution.meta.local@0.1.0`
- `lp.deploy.query.result@0.1.0`
- `lp.incident.bundle@0.1.0`
- `lp.regression.request@0.1.0`
- `lp.cli.report@0.1.0` (CLI + MCP report envelope)

`lp.deploy.execution@0.1.0` executes `x07.deploy.plan@0.2.0`.
`lp.pipeline.run@0.1.0` exposes `state.stage`.
