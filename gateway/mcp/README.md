# MCP Server (stdio) — x07 Platform (Phase A)

This is an MCP **stdio** server with a router/worker split:

- **Router**: stdio transport + lifecycle + JSON-RPC dispatch
- **Worker**: one `tools/call` execution under `run-os-sandboxed`

## Layout

- `config/mcp.server.json`: server config (`x07.mcp.server_config@0.3.0`)
- `config/mcp.tools.json`: tools manifest (`x07.mcp.tools_manifest@0.2.0`)
- `src/main.x07.json`: router entry
- `src/worker_main.x07.json`: worker entry
- `src/mcp/user.x07.json`: tool implementations
- `tests/`: smoke fixtures

## Quickstart

Dependencies are declared in the root project (`x07.json`). If you need to refresh lock/deps:

```sh
x07 pkg lock --project x07.json
```

Bundle router + worker:

```sh
x07 bundle --project x07.mcp.router.json --profile os --out out/x07lp-mcp-router

# Local dev backend (no VM guest bundle required):
x07 bundle \
  --project x07.mcp.worker.json \
  --profile sandbox \
  --sandbox-backend os \
  --i-accept-weaker-isolation \
  --out out/x07lp-mcp-worker
```

Run the router:

```sh
./out/x07lp-mcp-router
```

Run tests:

```sh
x07 test --manifest gateway/mcp/tests/tests.json --module-root gateway/mcp/tests
```
