# x07-platform (x07 Platform / x07-LP)

`x07-platform` is the local deployment lifecycle repo for X07 sealed artifacts.

Public surface:
- `lp.*` contracts in `spec/schemas/`
- `x07lp` CLI for `change`, `deploy`, and `schema` workflows
- local content-addressed state under `.x07lp/` or `--state-dir`
- local runtime, routing, and query/index support for `x07.app.pack@0.1.0`
- MCP router/worker integration under `gateway/mcp/`

Repo entrypoints:
- CLI: `cli/src/main.x07.json`
- MCP router: `gateway/mcp/src/main.x07.json`
- MCP worker: `gateway/mcp/src/worker_main.x07.json`

Developer commands:
- Generate schema index: `python3 scripts/gen_schema_index.py`
- Lock deps: `x07 pkg lock --project x07.json`
- Bundle CLI: `x07 bundle --project x07.json --profile os --out out/x07lp`
- Run checks: `./scripts/ci/check_all.sh`
