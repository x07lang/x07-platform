# x07-platform (x07 Platform / x07-LP)

`x07-platform` is the public lifecycle runtime and self-hosted control-plane repo for X07 sealed artifacts.

Vision:
- Make X07 application delivery contract-first, machine-readable, and auditable from change request through deploy, incident capture, and regression generation.
- Keep the same creator-facing CLI and sealed artifacts usable across local development, self-hosted remote targets, and the future hosted platform.
- Let creators focus on making things while humans supervise through one control surface for deploy, query, approval, pause, stop, rerun, rollback, and audit.

Audience:
- creators who want a serious default deploy and operations path without learning provider-specific infrastructure
- operators who need deterministic reports, policy and SLO gates, audit trails, and pluggable adapters

Current goals:
- ship a strong public OSS baseline for local and self-hosted remote deploys
- keep provider support behind adapters and conformance rather than hard-coded cloud logic
- keep hosted-only account, tenancy, metering, and billing work out of this repo so the public engine stays reusable

Public surface:
- public `lp.*` contracts consumed from `contracts/spec/schemas/` with `x07-platform-contracts` as the authoritative source
- `x07lp` CLI for `change`, `deploy`, `target`, `adapter`, `incident`, `regress`, `app`, `device`, `platform`, `ui`, and `schema` workflows
- local content-addressed state under `.x07lp/` or `--state-dir`
- local runtime, routing, signed control actions, incident capture, regression generation, and query/index support for `x07.app.pack@0.1.0`
- self-hosted remote target management, remote deploy API, remote event/log streams, and reference adapter work for the OSS remote path
- device package release planning, optional metrics-gate bootstrap inputs, staged rollout control, Command Center device-release views, and MCP tools for `lp.device.release.*`
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
- Check device release orchestration: `./scripts/ci/device-release.sh`
- Run checks: `./scripts/ci/check_all.sh`

Device distribution note:
- `x07lp device release-create`, `release-validate`, `release-run`, `release-query`, `release-observe`, `release-pause`, `release-resume`, `release-halt`, `release-stop`, `release-complete`, `release-rerun`, and `release-rollback` drive the shared device-release engine.
- `x07lp device release-create` also accepts `--slo-profile`, `--metrics-window-seconds`, and `--metrics-on-fail` to seed a release metrics gate, and `x07lp device release-rerun` accepts `--from-step` to restart from a later step boundary.
- Default CI and local fixture validation use deterministic provider-matrix simulation for `appstoreconnect_v1` and `googleplay_v1`.
- Manual live-provider validation remains explicit through `X07LP_DEVICE_PROVIDER_LIVE=1`.

CI note:
- The platform CI scripts prefer sibling workspace builds from `../x07/target/debug` and `../x07-wasm-backend/target/release` when those directories exist so the repo tests the current release train rather than an older installed toolchain.

Reference stack:
- self-hosted wasmCloud target assets: `examples/targets/wasmcloud/`
- the wasmCloud reference target now expects the generated dev CA under `examples/targets/wasmcloud/certs/out/` and uses `https://localhost:17443` plus `https://localhost:15443` for the creator-facing path
