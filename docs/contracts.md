# Contracts

Public schemas are authored in `x07-platform-contracts` and consumed here from `contracts/spec/schemas/`.
The local index path is `contracts/spec/schemas/index.json`.

Primary platform artifacts:

- `lp.change_request@0.1.0`
- `lp.pipeline.run@0.1.0`
- `lp.decision.record@0.1.0`
- `lp.deploy.execution@0.1.0`
- `lp.deploy.execution.meta.local@0.1.0`
- `lp.deploy.execution.meta.remote@0.1.0`
- `lp.deploy.query.result@0.1.0`
- `lp.incident.bundle@0.1.0`
- `lp.incident.bundle.meta.remote@0.1.0`
- `lp.regression.request@0.1.0`
- `lp.cli.report@0.1.0` (CLI + MCP report envelope)
- `lp.target.profile@0.1.0`
- `lp.target.list.result@0.1.0`
- `lp.deploy.push.result@0.1.0`
- `lp.deploy.remote.result@0.1.0`
- `lp.remote.capabilities.response@0.1.0`
- `lp.adapter.capabilities@0.1.0`
- `lp.adapter.conformance.report@0.1.0`

`lp.deploy.execution@0.1.0` executes `x07.deploy.plan@0.2.0`.
`lp.pipeline.run@0.1.0` exposes `state.stage`.
