# x07-platform (x07 Platform / x07-LP)

`x07-platform` is the local deployment lifecycle repo for X07 sealed artifacts.

Public surface:
- `lp.*` contracts in `spec/schemas/`
- `x07lp` CLI for `change`, `deploy`, `incident`, `regress`, `app`, `platform`, `ui`, and `schema` workflows
- local content-addressed state under `.x07lp/` or `--state-dir`
- local runtime, routing, signed control actions, incident capture, regression generation, and query/index support for `x07.app.pack@0.1.0`
- MCP router/worker integration under `gateway/mcp/`
- local Command Center HTTP surface served by `x07lpd`

Repo entrypoints:
- CLI: `cli/src/main.x07.json`
- MCP router: `gateway/mcp/src/main.x07.json`
- MCP worker: `gateway/mcp/src/worker_main.x07.json`
- Shared engine/daemon implementation: `tools/x07lp-driver/src/main.rs`

Implementation note:
- The x07 CLI and MCP modules are thin wrappers around the shared Rust `x07lp-driver`.
- Phase C behavior is implemented in that driver: incident capture, regression execution, signed control actions, SQLite indexing, and the `x07lpd` HTTP daemon.

Developer commands:
- Generate schema index: `./scripts/gen_schema_index.sh`
- Lock deps: `x07 pkg lock --project x07.json`
- Bundle CLI: `x07 bundle --project x07.json --profile os --out out/x07lp`
- Run checks: `./scripts/ci/check_all.sh`
