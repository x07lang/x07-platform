# MCP gateway (Phase A)

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
- `lp.deploy.status`
- `lp.deploy.stop`
- `lp.deploy.rollback`

