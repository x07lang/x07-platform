# x07-platform

**x07-platform** is the public runtime and self-hosted control plane for operating X07 workloads and release flows. The current first lane is governed backend delivery: API, event-consumer, and scheduled-job cells packaged as `x07.workload.pack@0.1.0` and run through `x07lp`.

In the X07 ecosystem, `x07` is where you write services and scaffolds, `x07-wasm-backend` turns them into workload, app, and device artifacts, and `x07-platform` runs the operational loop around them: workload accept, binding and topology inspection, release review, deploy, incident capture, regression generation, and control actions.

The vision is simple: an end user or coding agent should be able to move from "the workload is ready" to "the workload is running safely in production" without switching to a separate ad hoc stack with different contracts, different state, and different tooling.

The platform operates as one closed loop:

```
change request -> sealed artifact -> deploy plan -> execution -> incident capture -> regression -> control actions
```

The repo is local-first. The same contracts and operator model are used for:

- local Kubernetes workload demos and release-review flows
- self-hosted OSS remote targets, currently the wasmCloud reference target
- additive target-profile support for hosted, Kubernetes, and wasmCloud control-plane attachments
- older app and device-release demos that still share the same control plane
- a managed hosted boundary built separately; the public repo is not the managed product

It ships a dark-themed **Command Center** web UI, a full-featured **CLI** (`x07lp`), and an **MCP tool surface** so AI agents can consume the same deploy, incident, and release state programmatically.

## Design docs

- Scale classes: `docs/adr/adr-scale-classes.md`
- Rollout state machine: `docs/adr/adr-rollout-state-machine.md`
- Kubernetes traffic shifting: `docs/adr/adr-traffic-shifting.md`
- Telemetry identity: `docs/observability_identity.md`

## What Is In This Repo

- **Lifecycle engine** for workload intake, release control, deploy plans, executions, incidents, regressions, and control actions
- **`x07lp` CLI and driver scripts** for platform and control-plane workflows across local, self-hosted, and hosted lanes
- **Command Center UI** for operators who want a browser view over the same state the CLI exposes
- **Public docs and fixtures** for Kubernetes workload demos, hosted review flows, and contract-backed examples
- **MCP-facing platform surface** so coding agents can read platform state and invoke safe controls

## How It Fits The Whole X07 Story

The broader X07 release path looks like this:

1. Build the program in [`x07`](https://github.com/x07lang/x07)
2. Package workload, web, app, or device artifacts in [`x07-wasm-backend`](https://github.com/x07lang/x07-wasm-backend)
3. Operate workloads, bindings, releases, incidents, and regressions through `x07-platform`
4. If needed, run the same reducer on desktop or mobile with [`x07-device-host`](https://github.com/x07lang/x07-device-host)
5. Publish packages through [`x07-registry`](https://github.com/x07lang/x07-registry) and browse them on [`x07.io`](https://x07.io)

That makes `x07-platform` the public operations part of the language ecosystem, not a separate product bolted on later. The managed control layer built on top of this split is x07 Sentinel, backed by the private `x07-platform-cloud` repo.

## What The Platform Does

| Capability | Description |
|---|---|
| **Artifact intake** | Admits `x07.workload.pack@0.1.0` and `x07.app.pack@0.1.0` artifacts, validates digests, and stores them in a content-addressed store. |
| **Deploy execution** | Executes `x07.deploy.plan@0.2.0` locally with weighted canary or blue/green routing, SLO gating, deterministic recovery checkpoints, and automatic promotion or rollback. |
| **Incident capture** | Captures HTTP 5xx responses, runtime failures, SLO rollbacks, and manual operator captures as `lp.incident.bundle@0.1.0`, and accepts explicit incident-trigger ingestion for deployment-scoped signals. |
| **Regression generation** | Generates automated test fixtures from incidents via `x07-wasm app regress from-incident`. |
| **Operator controls** | Pause, rerun, rollback, stop, app kill/unkill, and platform kill/unkill from CLI, UI, or MCP tools. |
| **Workload and release surfaces** | Carry workload-pack inventory, topology preview, binding status, hosted release-review documents, and a Kubernetes workload lane for HTTP, event-consumer, and scheduled-job cells. |
| **Control-plane attachments** | Attach Kubernetes, hosted, and wasmCloud target profiles to the same public contract model without changing the control surface. |
| **Device release orchestration** | Create staged iOS and Android release plans and supervise rollout through App Store Connect and Google Play mock providers. |
| **Command Center UI** | Dark-themed web dashboard for real-time monitoring of apps, deployments, incidents, regressions, and device releases. |
| **MCP tool integration** | Expose all surfaces (deploy, incident, regression, app, platform, device release) as MCP tools for agent consumption. |

## Install

Install the X07 toolchain:

```bash
curl -fsSL https://x07lang.org/install.sh | sh -s -- --yes --channel stable
```

Add the required components:

```bash
x07up update
x07up component add wasm
x07up component add device-host
x07 wasm doctor --json
```

Extra prerequisites:

- **Python 3** for helper scripts and JSON parsing in the walkthrough below
- **Docker** if you want to run the self-hosted wasmCloud target
- **A remote v1 control-plane endpoint** if you want to attach hosted or Kubernetes targets through `lp.target.profile@0.1.0`

## Practical Ways To Use It

- **Kubernetes workload lane:** package `x07.workload.pack@0.1.0` artifacts and run them through `x07lp workload ...` for HTTP, event-consumer, and scheduled-job cells
- **Hosted Sentinel review loop:** use `x07lp login`, `release-submit`, `release-query`, `release-explain`, `release-rollback`, and `binding-status` against a hosted control-plane session
- **Self-hosted control plane:** point `x07lp` at a target and run the same contracts against a remote environment
- **Agent-operated platform:** let an MCP-aware coding agent inspect workloads, releases, incidents, and executions without scraping logs or dashboards
- **Secondary app and device loops:** pair it with `x07-wasm app pack`, `x07-wasm deploy plan`, incident-derived regression generation, or device release supervision when those broader flows are needed

## Run From Source

The repo carries its pinned `.x07/` dependency snapshot. From the repo root:

```bash
cd x07-platform
x07 pkg lock --project x07.json --check
```

The source entrypoint is `./scripts/x07lp-driver`. For a bundled standalone CLI:

```bash
x07 bundle --project x07.json --profile os --out out/x07lp
```

If you want to use it as part of the full ecosystem story, keep `x07-platform` alongside the sibling repos it consumes most often:

- [`x07`](https://github.com/x07lang/x07) for the toolchain and canonical docs
- [`x07-wasm-backend`](https://github.com/x07lang/x07-wasm-backend) for app/device build, verify, pack, and incident-regression commands
- [`x07-crewops`](https://github.com/x07lang/x07-crewops) or another app repo for a realistic sealed-artifact input

## Quick Start: Local Demo

For service-oriented backend work, start with [Local K3s workload smoke](#local-k3s-workload-smoke) below. The local deploy loop here remains useful for the older app/deploy fixtures and Command Center state.

Run a minimal local deploy using the bundled fixtures:

```bash
cd x07-platform
LP="./scripts/x07lp-driver"

STATE_DIR="$PWD/_tmp/demo_state"
CHANGE="$PWD/spec/fixtures/baseline/change_request.min.json"
PACK_DIR="$PWD/spec/fixtures/baseline/pack_min"
PLAN="$PWD/spec/fixtures/deploy_loop/promote/deploy.plan.json"
METRICS_DIR="$PWD/spec/fixtures/deploy_loop/promote"

$LP accept \
  --target __local__ \
  --pack-dir "$PACK_DIR" \
  --pack-manifest app.pack.json \
  --change "$CHANGE" \
  --state-dir "$STATE_DIR" \
  --json >"$STATE_DIR.accept.json"

DEPLOY_ID="$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(doc["result"]["exec_id"])' "$STATE_DIR.accept.json")"

$LP run \
  --target __local__ \
  --deployment-id "$DEPLOY_ID" \
  --plan "$PLAN" \
  --metrics-dir "$METRICS_DIR" \
  --state-dir "$STATE_DIR" \
  --json

$LP query \
  --target __local__ \
  --deployment-id "$DEPLOY_ID" \
  --view full \
  --state-dir "$STATE_DIR" \
  --json

./scripts/x07lp-driver ui-serve \
  --state-dir "$STATE_DIR" \
  --addr 127.0.0.1:17090
```

Open `http://127.0.0.1:17090` to view the Command Center.

Use `--target __local__` for local commands when you may also have a saved remote target.

### Rich Demo States

Generate richer state for the UI:

```bash
./scripts/ci/control_plane.sh
./scripts/x07lp-driver ui-serve --state-dir _tmp/ci_control_plane/promote_state --addr 127.0.0.1:17090

./scripts/ci/device-release.sh
./scripts/x07lp-driver ui-serve --state-dir _tmp/ci_device_release/state --addr 127.0.0.1:17091
```

Control-plane state covers app, deployment, incident, and regression flows. Device-release state covers staged store rollout and release controls.

### Local K3s workload smoke

The OSS platform now has a dedicated workload lane for `x07.workload.pack@0.1.0` artifacts on Kubernetes. This is the current first backend-delivery lane and the fastest end-to-end verification path in the repo:

```bash
cd x07-platform
bash scripts/ci/workload-k3s-smoke.sh
```

That smoke:

- creates or reuses a local K3s cluster through `k3d`
- packs `x07/docs/examples/service_api_cell_v1` with `traefik/whoami`
- adds a `k8s` target profile to `x07lp`
- runs `x07lp workload accept`, `workload run`, `workload query`, `workload bindings`, and `workload stop`
- verifies the ingress route from the host before and after teardown

The workload driver now keeps the richer `x07.workload.pack@0.1.0` cell hints intact across accept, manifest render, and query refresh:

- `http` cells render `Deployment`, `Service`, and `Ingress` resources with HTTP or exec probes and optional CPU-backed HPA objects
- `event` cells render `Deployment` resources with probe, rollout, autoscaling, and event-bus metadata carried as container env plus workload annotations
- `schedule` cells render `CronJob` resources with cron, timezone, concurrency, retry, and suspend settings, and workload query now reports desired versus observed state for those cells instead of flattening everything into the old HTTP-only status view

Use `bash scripts/ci/target-conformance.sh k8s` when you want the stable target-suite entrypoint for the same local lane. The same entrypoint also carries `local`, `wasmcloud`, and `all` so target conformance is no longer a Kubernetes-only one-off.

For longer-running controller and failure-injection coverage, the repo now also carries:

- `bash scripts/ci/workload-k3s-soak.sh`
- `bash scripts/ci/workload-k3s-chaos.sh`
- `bash scripts/ci/target-conformance.sh k8s-extended`

For manual use, the workload CLI is:

```bash
./scripts/x07lp-driver workload accept --pack-manifest /path/to/workload.pack.json --target k3s-local --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload run --workload svc_api_cell_v1 --target k3s-local --profile prod --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload query --workload svc_api_cell_v1 --target k3s-local --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload reconcile --workload svc_api_cell_v1 --target k3s-local --cycles 5 --interval-seconds 5 --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload bindings --workload svc_api_cell_v1 --target k3s-local --state-dir /tmp/x07lp-state
./scripts/x07lp-driver workload stop --workload svc_api_cell_v1 --target k3s-local --state-dir /tmp/x07lp-state
```

`workload reconcile` is the controller loop for the Kubernetes lane. It re-applies the rendered manifests from the accepted deployment state, waits for deployment-backed cells to settle, refreshes the live desired versus observed state, and writes the reconciled deployment record back into the state directory.

Binding readiness is probe-backed when connector-aware probe results are available, and otherwise falls back to local advisory wiring checks (for example Kubernetes Secret or Service presence). The advisory checks are not treated as authoritative dependency readiness for connector bindings.

## User Flows

### 1. Deploy a sealed app pack locally

Accept a sealed artifact, execute its deploy plan with SLO-gated canary routing, and inspect the result through the CLI or the Command Center.

### 2. Supervise a deployment

Use pause, rerun, rollback, stop, app kill, and app unkill controls from the CLI, the Command Center UI, or MCP tools to manage a running or completed execution.

### 3. Capture and investigate incidents

Capture an incident bundle from an HTTP 5xx, runtime failure, or manual trigger. List and inspect incidents in the Command Center. Generate a regression fixture from any captured incident.

### 4. Deploy to a self-hosted remote target

Add a self-hosted wasmCloud target, inspect its adapter capabilities, select it, and deploy the same sealed artifact remotely without changing the artifact format. The target profile boundary is additive now: `oss_remote`, `hosted`, `k8s`, and `wasmcloud` all use the same `lp.target.profile@0.1.0` document, with example profiles under `examples/targets/`.

### 5. Orchestrate device releases

Build iOS and Android packages with `x07-wasm device package`, create staged release plans, and supervise rollout from the same control plane. Controls: observe, pause, resume, halt, stop, complete, rerun, rollback.

### 6. Consume state through MCP

AI agents can consume deploy, incident, regression, app, platform, and device-release state through the MCP tool surface. The MCP router serves the same data as the CLI and UI.

### 7. Drive hosted release review and binding checks

When you have a hosted session (`x07lp login`), the same CLI can submit a workload candidate and inspect the hosted Sentinel review state:

```bash
x07lp release-submit \
  --workload-id demo.api \
  --pack-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --environment-id env_demo \
  --target-id target.hosted.demo \
  --rollout-strategy canary \
  --notes "candidate ready" \
  --json

x07lp release-query --release lprel_demo --json
x07lp release-query --release lprel_demo --view evidence --json
x07lp release-explain --release lprel_demo --json
x07lp binding-status --json
```

## Command Center UI

The Command Center is a dark-themed SPA served by `x07lpd` at the address you specify with `--addr`. It polls the backend every 3 seconds and exposes all operator surfaces.

**Views:**

| Route | Description |
|---|---|
| `/device-releases` | Device release list with rollout health, readiness gates, and native incident counts. |
| `/device-releases/:id` | Single release detail with observe, pause, resume, halt, stop, complete, rerun, and rollback controls. |
| `/apps` | Application list with deployment status, kill state, open incident counts, and platform kill controls. |
| `/deployments/:id` | Deployment detail with pause, rerun, rollback, and stop controls. |
| `/incidents/:id` | Incident detail with classification, regression state, release linkage, captured artifacts, and regress action. |

**Screenshots:**

![Command Center - Device Releases](/docs/screenshots/device-releases.png)
![Command Center - Applications](/docs/screenshots/apps.png)
![Command Center - Device Release Detail](/docs/screenshots/device-release-detail.png)
![Command Center - Incident Detail](/docs/screenshots/incident.png)

## Tutorial: Build and Deploy CrewOps

This walkthrough assumes `x07-platform` and `x07-crewops` are sibling repos:

```
.../x07-platform
.../x07-crewops
```

### Step 1: Build the CrewOps release pack and deploy plan

```bash
cd ../x07-crewops

mkdir -p build/crewops_gate/reports dist/crewops_gate
./scripts/ci/seed_demo.sh

x07-wasm app build \
  --index arch/app/index.x07app.json \
  --profile crewops_release \
  --out-dir dist/crewops_gate/app.crewops_release \
  --clean \
  --strict

node scripts/postprocess_app_host.mjs dist/crewops_gate/app.crewops_release

x07-wasm app pack \
  --bundle-manifest dist/crewops_gate/app.crewops_release/app.bundle.json \
  --profile-id crewops_release \
  --out-dir dist/crewops_gate/pack.crewops_release

x07-wasm app verify \
  --pack-manifest dist/crewops_gate/pack.crewops_release/app.pack.json

x07-wasm provenance attest \
  --pack-manifest dist/crewops_gate/pack.crewops_release/app.pack.json \
  --ops arch/app/ops/ops_release.json \
  --signing-key arch/provenance/dev.ed25519.signing_key.b64 \
  --out dist/crewops_gate/pack.crewops_release/app.provenance.dsse.json

x07-wasm provenance verify \
  --attestation dist/crewops_gate/pack.crewops_release/app.provenance.dsse.json \
  --pack-dir dist/crewops_gate/pack.crewops_release \
  --trusted-public-key arch/provenance/dev.ed25519.public_key.b64

x07-wasm deploy plan \
  --pack-manifest dist/crewops_gate/pack.crewops_release/app.pack.json \
  --ops arch/app/ops/ops_release.json \
  --out-dir dist/crewops_gate/deploy.crewops_release

mkdir -p build/crewops_gate/platform_metrics
for n in 1 2 3; do
  cp tests/fixtures/metrics/crewops_canary_ok.json "build/crewops_gate/platform_metrics/analysis.${n}.json"
done
```

Artifacts produced:

- **App pack:** `dist/crewops_gate/pack.crewops_release/app.pack.json`
- **Deploy plan:** `dist/crewops_gate/deploy.crewops_release/deploy.plan.json`
- **Canary metrics:** `build/crewops_gate/platform_metrics/`

For the full CrewOps release gate, run `./scripts/ci/check_all.sh` instead.

### Step 2: Deploy CrewOps locally

```bash
cd ../x07-platform
LP="./scripts/x07lp-driver"

STATE_DIR="$PWD/_tmp/crewops_local_state"
CHANGE="$PWD/spec/fixtures/baseline/change_request.min.json"
PACK_DIR="$PWD/../x07-crewops/dist/crewops_gate/pack.crewops_release"
PLAN="$PWD/../x07-crewops/dist/crewops_gate/deploy.crewops_release/deploy.plan.json"
METRICS_DIR="$PWD/../x07-crewops/build/crewops_gate/platform_metrics"

$LP accept \
  --target __local__ \
  --pack-dir "$PACK_DIR" \
  --pack-manifest app.pack.json \
  --change "$CHANGE" \
  --state-dir "$STATE_DIR" \
  --json >"$STATE_DIR.accept.json"

DEPLOY_ID="$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(doc["result"]["exec_id"])' "$STATE_DIR.accept.json")"

$LP run \
  --target __local__ \
  --deployment-id "$DEPLOY_ID" \
  --plan "$PLAN" \
  --metrics-dir "$METRICS_DIR" \
  --state-dir "$STATE_DIR" \
  --json

$LP query \
  --target __local__ \
  --deployment-id "$DEPLOY_ID" \
  --view full \
  --state-dir "$STATE_DIR" \
  --json

./scripts/x07lp-driver ui-serve \
  --state-dir "$STATE_DIR" \
  --addr 127.0.0.1:17090
```

Open `http://127.0.0.1:17090` for a full local CrewOps deployment record in the Command Center.

### Step 3: Deploy CrewOps to a self-hosted wasmCloud target

Start the reference stack:

```bash
cd ../x07-platform
LP="./scripts/x07lp-driver"

./examples/targets/wasmcloud/scripts/gen-dev-cert.sh

X07LP_DEV_CERT_DIR=examples/targets/wasmcloud/certs/out \
  docker compose -f examples/targets/wasmcloud/docker-compose.yml up -d
```

Create local auth files:

```bash
mkdir -p "$HOME/.config/x07lp/tokens" "$HOME/.config/x07lp/targets"
printf 'x07lp-oss-dev-token\n' > "$HOME/.config/x07lp/tokens/oss-wasmcloud.token"
printf 'x07lp-oci-dev-user\n' > "$HOME/.config/x07lp/targets/oss-wasmcloud.oci.username"
printf 'x07lp-oci-dev-pass\n' > "$HOME/.config/x07lp/targets/oss-wasmcloud.oci.password"
```

Materialize the target profile:

```bash
python3 - <<'PY'
from pathlib import Path
import json

root = Path.cwd()
home = Path.home()
profile = json.loads((root / "examples/targets/wasmcloud/target.example.json").read_text(encoding="utf-8"))
profile["auth"]["token_ref"] = f"file://{home}/.config/x07lp/tokens/oss-wasmcloud.token"
profile["tls"]["ca_bundle_path"] = str(root / "examples/targets/wasmcloud/certs/out/dev-ca.pem")
profile["oci_auth"]["username_ref"] = f"file://{home}/.config/x07lp/targets/oss-wasmcloud.oci.username"
profile["oci_auth"]["password_ref"] = f"file://{home}/.config/x07lp/targets/oss-wasmcloud.oci.password"
profile["oci_tls"]["ca_bundle_path"] = str(root / "examples/targets/wasmcloud/certs/out/dev-ca.pem")
(root / "_tmp").mkdir(exist_ok=True)
(root / "_tmp/oss-wasmcloud.target.json").write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
PY
```

Onboard and deploy:

```bash
$LP target-add --profile "$PWD/_tmp/oss-wasmcloud.target.json" --json
$LP target-list --json
$LP target-inspect --name oss-wasmcloud --json
$LP target-use --name oss-wasmcloud --json

$LP accept \
  --target oss-wasmcloud \
  --pack-manifest "$PWD/../x07-crewops/dist/crewops_gate/pack.crewops_release/app.pack.json" \
  --change "$PWD/spec/fixtures/baseline/change_request.min.json" \
  --json >"$PWD/_tmp/crewops.remote.accept.json"

REMOTE_RUN_ID="$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(doc["result"].get("run_id") or doc["result"].get("pipeline_run_id") or "")' "$PWD/_tmp/crewops.remote.accept.json")"

$LP run \
  --target oss-wasmcloud \
  --accepted-run "$REMOTE_RUN_ID" \
  --json >"$PWD/_tmp/crewops.remote.run.json"

REMOTE_DEPLOY_ID="$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(doc["result"].get("deployment_id") or doc["result"].get("exec_id") or "")' "$PWD/_tmp/crewops.remote.run.json")"

$LP query \
  --target oss-wasmcloud \
  --deployment "$REMOTE_DEPLOY_ID" \
  --view full \
  --json

$LP incident-list \
  --target oss-wasmcloud \
  --deployment "$REMOTE_DEPLOY_ID" \
  --json
```

Cleanup:

```bash
$LP target-remove --name oss-wasmcloud --json
docker compose -f examples/targets/wasmcloud/docker-compose.yml down
```

### Step 4: Build CrewOps iOS and Android packages

```bash
cd ../x07-crewops

x07-wasm device build \
  --index arch/device/index.x07device.json \
  --profile device_ios_dev \
  --out-dir dist/crewops_gate/device_ios_dev_bundle \
  --clean --json \
  --report-out build/crewops_gate/reports/device.build.device_ios_dev.json \
  --quiet-json

x07-wasm device verify \
  --dir dist/crewops_gate/device_ios_dev_bundle --json \
  --report-out build/crewops_gate/reports/device.verify.device_ios_dev.json \
  --quiet-json

x07-wasm device package \
  --bundle dist/crewops_gate/device_ios_dev_bundle \
  --target ios \
  --out-dir dist/crewops_gate/device_ios_dev_package --json \
  --report-out build/crewops_gate/reports/device.package.device_ios_dev.json \
  --quiet-json

x07-wasm device build \
  --index arch/device/index.x07device.json \
  --profile device_android_dev \
  --out-dir dist/crewops_gate/device_android_dev_bundle \
  --clean --json \
  --report-out build/crewops_gate/reports/device.build.device_android_dev.json \
  --quiet-json

x07-wasm device verify \
  --dir dist/crewops_gate/device_android_dev_bundle --json \
  --report-out build/crewops_gate/reports/device.verify.device_android_dev.json \
  --quiet-json

x07-wasm device package \
  --bundle dist/crewops_gate/device_android_dev_bundle \
  --target android \
  --out-dir dist/crewops_gate/device_android_dev_package --json \
  --report-out build/crewops_gate/reports/device.package.device_android_dev.json \
  --quiet-json
```

### Step 5: Supervise CrewOps device releases

Create mock provider profiles and run the iOS release:

```bash
cd ../x07-platform
LP="./scripts/x07lp-driver"
mkdir -p _tmp

python3 - <<'PY'
from pathlib import Path
import json

root = Path.cwd()
profiles = {
    "crewops_ios_mock_provider.json": {
        "schema_version": "lp.device.store.provider.profile@0.1.0",
        "provider_id": "crewops_ios_demo",
        "provider_kind": "mock_v1",
        "distribution_lane": "production",
        "target": "ios",
        "credentials_ref": "secrets://device/crewops-ios-demo",
        "app_ref": {"bundle_id": "io.x07.crewops.ios.dev"},
        "policy": {"approval_mode": "not_required"},
        "track": "production",
        "rollout_defaults": {"initial_percent": 25},
    },
    "crewops_android_mock_provider.json": {
        "schema_version": "lp.device.store.provider.profile@0.1.0",
        "provider_id": "crewops_android_demo",
        "provider_kind": "mock_v1",
        "distribution_lane": "production",
        "target": "android",
        "credentials_ref": "secrets://device/crewops-android-demo",
        "app_ref": {"package_name": "io.x07.crewops.android.dev"},
        "policy": {"approval_mode": "not_required"},
        "track": "production",
        "rollout_defaults": {"initial_percent": 25},
    },
}

for name, doc in profiles.items():
    (root / "_tmp" / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
```

Run the iOS release demo:

```bash
DEVICE_STATE_DIR="$PWD/_tmp/crewops_device_state"
IOS_PLAN="$PWD/_tmp/crewops_ios_release.plan.json"

$LP device-release-create \
  --provider-profile "$PWD/_tmp/crewops_ios_mock_provider.json" \
  --package-manifest "$PWD/../x07-crewops/dist/crewops_gate/device_ios_dev_package/package.manifest.json" \
  --package-report "$PWD/../x07-crewops/build/crewops_gate/reports/device.package.device_ios_dev.json" \
  --out "$IOS_PLAN" \
  --state-dir "$DEVICE_STATE_DIR" \
  --json

$LP device-release-validate \
  --plan "$IOS_PLAN" \
  --provider-profile "$PWD/_tmp/crewops_ios_mock_provider.json" \
  --state-dir "$DEVICE_STATE_DIR" \
  --json

$LP device-release-run \
  --plan "$IOS_PLAN" \
  --package-manifest "$PWD/../x07-crewops/dist/crewops_gate/device_ios_dev_package/package.manifest.json" \
  --state-dir "$DEVICE_STATE_DIR" \
  --json >"$DEVICE_STATE_DIR.ios.run.json"

IOS_RELEASE_ID="$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(doc["result"]["exec_id"])' "$DEVICE_STATE_DIR.ios.run.json")"

$LP device-release-query \
  --release "$IOS_RELEASE_ID" \
  --view full \
  --state-dir "$DEVICE_STATE_DIR" \
  --json

./scripts/x07lp-driver ui-serve \
  --state-dir "$DEVICE_STATE_DIR" \
  --addr 127.0.0.1:17091
```

Open `http://127.0.0.1:17091` for the device-release Command Center view.

Release controls:

```bash
$LP device-release-observe --release "$IOS_RELEASE_ID" --reason "promote after review" --state-dir "$DEVICE_STATE_DIR" --json
$LP device-release-stop --release "$IOS_RELEASE_ID" --reason "demo stop" --state-dir "$DEVICE_STATE_DIR" --json
$LP device-release-rerun --release "$IOS_RELEASE_ID" --reason "demo rerun" --from-step 1 --state-dir "$DEVICE_STATE_DIR" --json
```

Run the Android release the same way, swapping in `crewops_android_mock_provider.json` and the Android package paths.

## Hosted Note

The CLI includes hosted auth and context commands (`login`, `whoami`, `org`, `project`, `env`, `context`). It also now carries the draft workload, topology, binding, and release schema set consumed from `x07-platform-contracts`. Those are the client boundary for the managed product line, while the production-ready demo remains the local plus self-hosted OSS path described above.

## Verification and CI

```bash
./scripts/gen_schema_index.sh --check
x07 pkg lock --project x07.json --check
./scripts/ci/check_all.sh
```

Focused gates:

- `./scripts/ci/control_plane.sh` - app, incident, regression, and control-loop coverage
- `./scripts/ci/device-release.sh` - device-release creation, execution, and control coverage
- `./scripts/ci/remote-oss.sh` - target onboarding, remote deploy, query, event, and log coverage

## Repo Entry Points

| Entry point | Path |
|---|---|
| CLI | `cli/src/main.x07.json` |
| MCP router | `gateway/mcp/src/main.x07.json` |
| MCP worker | `gateway/mcp/src/worker_main.x07.json` |
| Engine and daemon | `tools/x07lp-driver/src/main.rs` |
| Command Center UI | `ui/command-center/dist/` |

For more detail: `docs/quickstart.md`, `docs/ci.md`, `examples/targets/wasmcloud/README.md`, `examples/targets/kubernetes/README.md`.
