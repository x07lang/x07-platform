# MCP gateway

Gateway files:

- Config: `gateway/mcp/config/mcp.server.json`
- Tools: `gateway/mcp/config/mcp.tools.json`
- Policies: `gateway/mcp/policy/`

Run the stdio router (default config path is `gateway/mcp/config/mcp.server.json`):

```bash
X07_MCP_CFG_PATH=gateway/mcp/config/mcp.server.json ./out/x07lp-mcp-router
```

The tool manifest exposes:

- `lp.change.new`
- `lp.change.validate`
- `lp.deploy.accept`
- `lp.deploy.run`
- `lp.deploy.query`
- `lp.deploy.status`
- `lp.deploy.pause`
- `lp.deploy.rerun`
- `lp.deploy.stop`
- `lp.deploy.rollback`
- `lp.device.release.create`
- `lp.device.release.validate`
- `lp.device.release.run`
- `lp.device.release.query`
- `lp.device.release.observe`
- `lp.device.release.pause`
- `lp.device.release.resume`
- `lp.device.release.halt`
- `lp.device.release.stop`
- `lp.device.release.complete`
- `lp.device.release.rerun`
- `lp.device.release.rollback`
- `lp.incident.list`
- `lp.incident.get`
- `lp.device.incident.list`
- `lp.device.incident.get`
- `lp.incident.capture`
- `lp.regress.from_incident`
- `lp.app.list`
- `lp.app.kill`
- `lp.app.unkill`
- `lp.platform.kill`
- `lp.platform.unkill`

Device release notes:

- `lp.device.release.create` accepts optional `slo_profile`, `metrics_window_seconds`, and `metrics_on_fail` inputs to seed a metrics gate into the generated plan.
- `lp.device.release.observe`, `lp.device.release.stop`, and `lp.device.release.rerun` accept `release_exec_id`; `reason` is supported and defaults to an internal audit label when omitted, and `lp.device.release.rerun` also accepts optional `from_step`.
- `lp.device.incident.list` and `lp.device.incident.get` are thin aliases over the existing incident list/get flow. `lp.device.incident.list` accepts the same filters as `lp.incident.list` plus `release_exec_id`.

All deploy, device release, incident, regression, app, and platform tools delegate through `lp.impl.deploy_exec.driver_v1`, which shells into the shared Rust `x07lp-driver`. That keeps the CLI, MCP, and `x07lpd` daemon on the same execution path instead of duplicating the control-plane logic in separate x07 modules.
