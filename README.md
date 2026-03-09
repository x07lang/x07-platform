# x07-platform (x07 Platform / x07-LP)

`x07-platform` is the public lifecycle runtime and self-hosted control-plane repo for X07 sealed artifacts.

Public surface:
- public `lp.*` contracts consumed from `contracts/spec/schemas/` with `x07-platform-contracts` as the authoritative source
- `x07lp` CLI for `change`, `deploy`, `target`, `adapter`, `incident`, `regress`, `app`, `platform`, `ui`, and `schema` workflows
- local content-addressed state under `.x07lp/` or `--state-dir`
- local runtime, routing, signed control actions, incident capture, regression generation, and query/index support for `x07.app.pack@0.1.0`
- self-hosted remote target management, remote deploy API, remote event/log streams, and reference adapter work for the OSS remote path
- MCP router/worker integration under `gateway/mcp/`
- local Command Center HTTP surface served by `x07lpd`
- compose-backed self-hosted reference target with HTTPS control-plane ingress, authenticated/TLS OCI publishing, and encrypted server-side secret storage

Repo entrypoints:
- CLI: `cli/src/main.x07.json`
- MCP router: `gateway/mcp/src/main.x07.json`
- MCP worker: `gateway/mcp/src/worker_main.x07.json`
- Shared engine/daemon implementation: `tools/x07lp-driver/src/main.rs`

Implementation note:
- The x07 CLI and MCP modules are thin wrappers around the shared Rust `x07lp-driver`.
- The shared driver implements local execution, remote target flows, incident capture, regression execution, signed control actions, SQLite indexing, and the `x07lpd` HTTP daemon.

Developer commands:
- Check contract schema index: `./scripts/gen_schema_index.sh --check`
- Lock deps: `x07 pkg lock --project x07.json`
- Bundle CLI: `x07 bundle --project x07.json --profile os --out out/x07lp`
- Run checks: `./scripts/ci/check_all.sh`

CI note:
- The platform CI scripts prefer sibling workspace builds from `../x07/target/debug` and `../x07-wasm-backend/target/release` when those directories exist so the repo tests the current release train rather than an older installed toolchain.

Reference stack:
- self-hosted wasmCloud target assets: `examples/targets/wasmcloud/`
- the wasmCloud reference target now expects the generated dev CA under `examples/targets/wasmcloud/certs/out/` and uses `https://localhost:17443` plus `https://localhost:15443` for the creator-facing path
