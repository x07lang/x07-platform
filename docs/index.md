# x07 Platform (x07-LP)

`x07-platform` is a contract-first lifecycle engine for accepting sealed artifacts (starting with `x07.app.pack@0.1.0`) and producing deterministic, machine-readable run + decision artifacts.

## Vision

- Turn X07 app delivery into a contract-first closed loop from change request through deploy, incident capture, and regression generation.
- Keep the same CLI and sealed artifacts usable across local development, self-hosted remote targets, and the future hosted platform.
- Give creators a default path that does not require learning provider-specific infrastructure, while keeping operators in control through auditable artifacts and explicit control actions.

## Audience

- creators who want to build and ship X07 apps without becoming infrastructure specialists
- operators who need policy, SLO, query, control, and audit surfaces that stay machine-readable

## Current goals

- provide a strong OSS baseline for local deploy plus self-hosted remote deploy parity
- keep runtime, routing, telemetry, secrets, and publish behavior behind adapters and conformance
- preserve a clean split between the public engine and the hosted private product layer

Current surface:

- public `lp.*` JSON Schemas consumed from `contracts/spec/schemas/` with `x07-platform-contracts` as the authority
- `x07lp` CLI for local and remote `change`, `deploy`, `target`, `adapter`, `incident`, `regress`, `app`, `platform`, `ui`, and `schema` flows plus hosted `login`, `whoami`, `logout`, `org`, `project`, `env`, and `context`
- Local filesystem content-addressed store (`--state-dir`, default `.x07lp/`)
- Hosted session document under `~/.config/x07lp/session.json` (or `X07LP_CONFIG_DIR` / `XDG_CONFIG_HOME`)
- Local runtime and routing for `x07.app.pack@0.1.0`
- Remote target selection, CAS push, remote query/control parity, and adapter conformance for self-hosted targets
- MCP router/worker surface under `gateway/mcp/`
- Historical deploy compatibility note for the preserved `docs/phaseB.md` path
- CI gates for accept, local deploy execution, query, and MCP coverage

For an end-to-end check, run `./scripts/ci/check_all.sh`.
