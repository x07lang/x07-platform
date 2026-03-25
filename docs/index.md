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
- widen the target-profile boundary so hosted, Kubernetes, and wasmCloud attachments share one creator-side document shape
- carry draft workload, topology, binding, scale, and release schemas without leaking hosted-only internals into the public repo

Current surface:

- public `lp.*` JSON Schemas consumed from `contracts/spec/schemas/` with `x07-platform-contracts` as the authority
- `x07lp` CLI for local and remote `change`, `deploy`, `target`, `adapter`, `incident`, `regress`, `app`, `platform`, `ui`, `workload`, and `schema` flows plus hosted `login`, `whoami`, `logout`, `org`, `project`, `env`, `context`, `release-*`, and `binding-status`
- Local filesystem content-addressed store (`--state-dir`, default `.x07lp/`)
- Hosted session document under `~/.config/x07lp/session.json` (or `X07LP_CONFIG_DIR` / `XDG_CONFIG_HOME`)
- Local runtime and routing for `x07.app.pack@0.1.0`
- Local Kubernetes runtime, ingress, query, and binding-status flow for `x07.workload.pack@0.1.0`
- Remote target selection, CAS push, remote query/control parity, and adapter conformance for self-hosted targets
- Additive target-profile kinds: `oss_remote`, `hosted`, `k8s`, and `wasmcloud`
- Public draft schemas for `lp.workload.*`, `lp.topology.preview.result@0.1.0`, `lp.binding.*`, `lp.scale.profile@0.1.0`, and `lp.release.*`
- MCP router/worker surface under `gateway/mcp/`
- Deploy loop compatibility note in `docs/deploy_loop_compatibility.md`
- CI gates for accept, local deploy execution, query, and MCP coverage

For an end-to-end check, run `./scripts/ci/check_all.sh`.

For the target matrix, run `bash scripts/ci/target-conformance.sh` with `local`, `wasmcloud`, `k8s`, `k8s-soak`, `k8s-chaos`, `k8s-extended`, or `all`. The Kubernetes workload lane is also available directly as `bash scripts/ci/workload-k3s-smoke.sh`, `bash scripts/ci/workload-k3s-soak.sh`, and `bash scripts/ci/workload-k3s-chaos.sh`.
