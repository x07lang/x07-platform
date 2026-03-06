# x07 Platform (x07-LP)

`x07-platform` is a contract-first lifecycle engine for accepting sealed artifacts (starting with `x07.app.pack@0.1.0`) and producing deterministic, machine-readable run + decision artifacts.

Current surface:

- `lp.*` JSON Schemas under `spec/schemas/`
- `x07lp` CLI for accept, run, query, status, stop, and rollback flows
- Local filesystem content-addressed store (`--state-dir`, default `.x07lp/`)
- Local runtime and routing for `x07.app.pack@0.1.0`
- MCP router/worker surface under `gateway/mcp/`
- Compatibility landing page for the historical `docs/phaseB.md` path
- CI gates for accept, local deploy execution, query, and MCP coverage

For an end-to-end check, run `./scripts/ci/check_all.sh`.
