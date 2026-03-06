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
- `lp.incident.list`
- `lp.incident.get`
- `lp.incident.capture`
- `lp.regress.from_incident`
- `lp.app.list`
- `lp.app.kill`
- `lp.app.unkill`
- `lp.platform.kill`
- `lp.platform.unkill`

All deploy, incident, regression, app, and platform tools delegate through `lp.impl.deploy_exec.driver_v1`, which shells into the shared Rust `x07lp-driver`. That keeps the CLI, MCP, and `x07lpd` daemon on the same execution path instead of duplicating the control-plane logic in separate x07 modules.
