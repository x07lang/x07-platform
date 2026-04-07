# x07-platform

Public runtime and self-hosted control plane for X07 workloads and release flows.

`x07-platform` is the operations layer for X07 artifacts. It accepts workload and app outputs, runs deploy and rollout flows, captures incidents, generates regressions, and exposes the same state through CLI, UI, and MCP-friendly contracts.

**Start here:** [`docs/`](docs/) · [`scripts/x07lp-driver`](scripts/x07lp-driver) · [`x07lang/x07-platform-contracts`](https://github.com/x07lang/x07-platform-contracts) · [Agent Quickstart](https://x07lang.org/docs/getting-started/agent-quickstart)

## What This Repo Does

- workload intake and deploy execution
- release review and rollout state
- incident capture and regression feedback loops
- operator controls through `x07lp`, UI, and MCP tools

The current first lane is governed backend delivery: API, event-consumer, and scheduled-job cells packaged as `x07.workload.pack@0.1.0` and operated through `x07lp`.

## Choose Your Path

### Try the local workload lane

```sh
bash scripts/ci/workload-k3s-smoke.sh
```

This is the fastest end-to-end verification path for the current Kubernetes workload line.

### Try the local control-plane demo

```sh
./scripts/x07lp-driver ui-serve --state-dir _tmp/ci_control_plane/promote_state --addr 127.0.0.1:17090
```

### Work on the CLI/runtime directly

The source entrypoint is:

- [`scripts/x07lp-driver`](scripts/x07lp-driver)

You can also bundle a standalone CLI:

```sh
x07 bundle --project x07.json --profile os --out out/x07lp
```

## How It Fits The X07 Ecosystem

- [`x07`](https://github.com/x07lang/x07) is where services and workloads are authored
- [`x07-wasm-backend`](https://github.com/x07lang/x07-wasm-backend) produces workload, app, and device artifacts
- [`x07-platform-contracts`](https://github.com/x07lang/x07-platform-contracts) defines the public `lp.*` contract layer
- `x07-platform` runs the operational loop around those artifacts
- the managed hosted layer built on top of this split lives separately in `x07-platform-cloud`

## Install

Install the X07 toolchain and required components:

```sh
curl -fsSL https://x07lang.org/install.sh | sh -s -- --yes --channel stable
x07up update
x07up component add wasm
x07up component add device-host
x07 wasm doctor --json
```

## Key Docs

- `docs/adr/` for architecture decisions
- `docs/observability_identity.md` for telemetry identity
- repo scripts under `scripts/ci/` for the canonical smoke and verification flows

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE).
