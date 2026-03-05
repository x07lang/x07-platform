# x07-platform (x07 Platform / x07-LP)

Phase A delivers the platform foundation:
- `lp.*` contracts (`spec/schemas/`)
- local content-addressed store (`.x07lp/`)
- `x07lp` CLI (bundle target)
- MCP router/worker skeleton (`gateway/mcp/`)
- CI gates + goldens (`scripts/ci/`, `spec/fixtures/phaseA/golden/`)

Repo entrypoints:
- CLI: `cli/src/main.x07.json`
- MCP router: `gateway/mcp/src/main.x07.json`
- MCP worker: `gateway/mcp/src/worker_main.x07.json`

Developer commands:
- Generate schema index: `python3 scripts/gen_schema_index.py`
- Lock deps: `x07 pkg lock --project x07.json`
- Bundle CLI: `x07 bundle --project x07.json --profile os --out out/x07lp`
- Run Phase A checks: `./scripts/ci/check_all.sh`
