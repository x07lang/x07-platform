# x07 Platform (x07-LP)

`x07-platform` is a contract-first lifecycle engine for accepting sealed artifacts (starting with `x07.app.pack@0.1.0`) and producing deterministic, machine-readable run + decision artifacts.

Phase A ships:

- `lp.*` JSON Schemas under `spec/schemas/`
- `x07lp` CLI (local mode)
- Local filesystem content-addressed store (`--state-dir`, default `.x07lp/`)
- MCP router/worker surface under `gateway/mcp/`
- CI gates + golden fixtures under `scripts/ci/` and `spec/fixtures/phaseA/`

For an end-to-end check, run `./scripts/ci/check_all.sh`.

