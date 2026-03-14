# x07-platform (x07 Platform / x07-LP)

`x07-platform` is the public lifecycle runtime and self-hosted control plane for sealed X07 app and device artifacts.

It is built around one closed loop:

`change request -> sealed artifact -> deploy or release plan -> execution -> incident capture -> regression generation -> supervised control actions`

The repo is local-first. The same contracts and operator model are used for:

- local deploy and device-release demos
- self-hosted OSS remote targets, currently the wasmCloud reference target
- a future hosted boundary; the managed product is intentionally not the main demo path in this repo

## What The Platform Does Today

- admits sealed `x07.app.pack@0.1.0` artifacts and executes deploy plans locally
- captures incidents from request, response, and trace inputs and generates regressions from those incidents
- exposes operator controls for pause, rerun, rollback, stop, app kill, app unkill, platform kill, and platform unkill
- onboards self-hosted remote targets with `target add|ls|inspect|use|rm` and reuses the same sealed artifacts for remote `deploy accept|run|query|pause|rerun|rollback|stop`
- creates staged iOS and Android device-release plans from `x07-wasm device package` outputs and supervises release rollout with `device release-create|validate|run|query|observe|pause|resume|halt|stop|complete|rerun|rollback`
- serves the local Command Center UI through `x07lpd`
- exposes the same deploy, incident, regression, app, platform, and device-release surfaces through MCP tools

## Install

Recommended toolchain install:

```bash
curl -fsSL https://x07lang.org/install.sh | sh -s -- --yes --channel stable
```

Required components for the full demo path:

```bash
x07up update
x07up component add wasm
x07up component add device-host
x07 wasm doctor --json
```

Extra prerequisites:

- Python 3 for helper scripts and JSON parsing in the walkthrough below
- Docker Desktop or Docker Engine if you want to run the self-hosted wasmCloud target

## Run From Source

The repo already carries its pinned `.x07/` dependency snapshot. From the repo root:

```bash
cd x07-platform
x07 pkg lock --project x07.json --check
```

The direct source entrypoint is `./scripts/x07lp-driver`. If you bundle the repo, replace it with `out/x07lp`; the CLI arguments stay the same.

If you want a bundled standalone CLI:

```bash
x07 bundle --project x07.json --profile os --out out/x07lp
```

### Minimal Local Demo

This is the fastest local path that uses the fixture pack and plan shipped in the repo:

```bash
cd x07-platform
LP="./scripts/x07lp-driver"

STATE_DIR="$PWD/_tmp/demo_state"
CHANGE="$PWD/spec/fixtures/phaseA/change_request.min.json"
PACK_DIR="$PWD/spec/fixtures/phaseA/pack_min"
PLAN="$PWD/spec/fixtures/phaseB/promote/deploy.plan.json"
METRICS_DIR="$PWD/spec/fixtures/phaseB/promote"

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

Open `http://127.0.0.1:17090`.

Use `--target __local__` for local `deploy`, `incident`, and `regress` commands when you may also have a saved remote target. That pins the command to the local state machine instead of the ambient target profile in `~/.config/x07lp/current_target`.

### Rich Demo States For The UI

The repo already includes richer UI/demo generators:

```bash
./scripts/ci/phaseC.sh
./scripts/x07lp-driver ui-serve --state-dir _tmp/ci_phaseC/promote_state --addr 127.0.0.1:17090

./scripts/ci/device-release.sh
./scripts/x07lp-driver ui-serve --state-dir _tmp/ci_device_release/state --addr 127.0.0.1:17091
```

Use the Phase C state to demo app, deployment, incident, and regression flows. Use the device-release state to demo staged store rollout and release controls.

## Main User Flows

1. Admit a sealed app pack, execute a local deploy plan, and inspect the result through `deploy query` and the Command Center.
2. Supervise an execution with pause, rerun, rollback, stop, app kill, and app unkill controls from the CLI or the UI.
3. Capture an incident bundle, list and inspect incidents, and generate a regression directly from the stored incident artifacts.
4. Add a self-hosted remote target, inspect its capabilities, select it, and deploy the same pack to a remote runtime without changing the artifact format.
5. Build iOS and Android packages with `x07-wasm`, turn those package outputs into device-release plans, and supervise staged rollout from the same control plane.
6. Consume the same lifecycle state through MCP when another agent needs structured deploy, incident, regression, app, platform, or device-release truth.

## CrewOps Tutorial

The walkthrough below assumes `x07-platform` and `x07-crewops` are sibling repos in the same workspace:

```text
.../x07-platform
.../x07-crewops
```

### 1. Build The CrewOps Release Pack And Deploy Plan

Build the web release artifact, verify it, attest it, and materialize a deploy plan:

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

At this point the canonical CrewOps demo artifacts are:

- app pack: `../x07-crewops/dist/crewops_gate/pack.crewops_release/app.pack.json`
- deploy plan: `../x07-crewops/dist/crewops_gate/deploy.crewops_release/deploy.plan.json`
- canary metrics: `../x07-crewops/build/crewops_gate/platform_metrics/`

If you want the full CrewOps release gate instead of the minimal artifact path above, run:

```bash
./scripts/ci/check_all.sh
```

### 2. Deploy CrewOps Locally With x07-platform

Use the CrewOps pack and plan with the platform's local control loop:

```bash
cd ../x07-platform
LP="./scripts/x07lp-driver"

STATE_DIR="$PWD/_tmp/crewops_local_state"
CHANGE="$PWD/spec/fixtures/phaseA/change_request.min.json"
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

This gives you a full local CrewOps deployment record in the Command Center at `http://127.0.0.1:17090`. The explicit `--target __local__` flags keep the flow local even if you previously selected a remote target with `target use`.

### 3. Deploy The Same CrewOps Pack To A Self-Hosted wasmCloud Target

Start the reference target:

```bash
cd ../x07-platform
LP="./scripts/x07lp-driver"

./examples/targets/wasmcloud/scripts/gen-dev-cert.sh

X07LP_DEV_CERT_DIR=examples/targets/wasmcloud/certs/out \
  docker compose -f examples/targets/wasmcloud/docker-compose.yml up -d
```

Create the local auth files expected by the example target:

```bash
mkdir -p "$HOME/.config/x07lp/tokens" "$HOME/.config/x07lp/targets"
printf 'x07lp-oss-dev-token\n' > "$HOME/.config/x07lp/tokens/oss-wasmcloud.token"
printf 'x07lp-oci-dev-user\n' > "$HOME/.config/x07lp/targets/oss-wasmcloud.oci.username"
printf 'x07lp-oci-dev-pass\n' > "$HOME/.config/x07lp/targets/oss-wasmcloud.oci.password"
```

Materialize a target profile from the shipped example:

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

Onboard the target and deploy CrewOps remotely:

```bash
$LP target-add --profile "$PWD/_tmp/oss-wasmcloud.target.json" --json
$LP target-list --json
$LP target-inspect --name oss-wasmcloud --json
$LP target-use --name oss-wasmcloud --json

$LP accept \
  --target oss-wasmcloud \
  --pack-manifest "$PWD/../x07-crewops/dist/crewops_gate/pack.crewops_release/app.pack.json" \
  --change "$PWD/spec/fixtures/phaseA/change_request.min.json" \
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

When you are done:

```bash
$LP target-remove --name oss-wasmcloud --json
docker compose -f examples/targets/wasmcloud/docker-compose.yml down
```

### 4. Build CrewOps iOS And Android Packages

The checked-in mobile dev profiles still point at `https://example.invalid`. Update `backend.base_url` and `allowed_hosts` in the CrewOps device profiles before packaging for a real simulator, device, App Store Connect, or Google Play release.

For the demo path, package the dev iOS and Android bundles and keep the machine-readable package reports:

```bash
cd ../x07-crewops

x07-wasm device build \
  --index arch/device/index.x07device.json \
  --profile device_ios_dev \
  --out-dir dist/crewops_gate/device_ios_dev_bundle \
  --clean \
  --json \
  --report-out build/crewops_gate/reports/device.build.device_ios_dev.json \
  --quiet-json

x07-wasm device verify \
  --dir dist/crewops_gate/device_ios_dev_bundle \
  --json \
  --report-out build/crewops_gate/reports/device.verify.device_ios_dev.json \
  --quiet-json

x07-wasm device package \
  --bundle dist/crewops_gate/device_ios_dev_bundle \
  --target ios \
  --out-dir dist/crewops_gate/device_ios_dev_package \
  --json \
  --report-out build/crewops_gate/reports/device.package.device_ios_dev.json \
  --quiet-json

x07-wasm device build \
  --index arch/device/index.x07device.json \
  --profile device_android_dev \
  --out-dir dist/crewops_gate/device_android_dev_bundle \
  --clean \
  --json \
  --report-out build/crewops_gate/reports/device.build.device_android_dev.json \
  --quiet-json

x07-wasm device verify \
  --dir dist/crewops_gate/device_android_dev_bundle \
  --json \
  --report-out build/crewops_gate/reports/device.verify.device_android_dev.json \
  --quiet-json

x07-wasm device package \
  --bundle dist/crewops_gate/device_android_dev_bundle \
  --target android \
  --out-dir dist/crewops_gate/device_android_dev_package \
  --json \
  --report-out build/crewops_gate/reports/device.package.device_android_dev.json \
  --quiet-json
```

### 5. Turn The CrewOps Packages Into Device Releases

Create demo provider profiles that match the CrewOps mobile app ids:

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

Open `http://127.0.0.1:17091` to inspect the device-release Command Center view.

Useful follow-up controls:

```bash
$LP device-release-observe --release "$IOS_RELEASE_ID" --reason "promote after review" --state-dir "$DEVICE_STATE_DIR" --json
$LP device-release-stop --release "$IOS_RELEASE_ID" --reason "demo stop" --state-dir "$DEVICE_STATE_DIR" --json
$LP device-release-rerun --release "$IOS_RELEASE_ID" --reason "demo rerun" --from-step 1 --state-dir "$DEVICE_STATE_DIR" --json
```

Run the Android release demo the same way, swapping in:

- `crewops_android_mock_provider.json`
- `dist/crewops_gate/device_android_dev_package/package.manifest.json`
- `build/crewops_gate/reports/device.package.device_android_dev.json`
- a separate plan output such as `_tmp/crewops_android_release.plan.json`

## Hosted Note

The CLI already includes hosted auth and context commands such as `login`, `whoami`, `org`, `project`, `env`, `context`, and explicit `deploy --hosted` flows. In this repo, treat those as the client boundary for the future managed product, not as the primary production-ready demo path. The production-ready demo in `x07-platform` is the local plus self-hosted OSS line described above.

## Verification And CI

Main checks:

```bash
./scripts/gen_schema_index.sh --check
x07 pkg lock --project x07.json --check
./scripts/ci/check_all.sh
```

Useful focused gates:

- `./scripts/ci/phaseC.sh` for app, incident, regression, and control-loop coverage
- `./scripts/ci/device-release.sh` for staged device-release creation, execution, and control coverage
- `./scripts/ci/remote-oss.sh` for target onboarding plus remote deploy, query, event, and log coverage against the self-hosted wasmCloud stack

## Repo Entry Points

- CLI: `cli/src/main.x07.json`
- MCP router: `gateway/mcp/src/main.x07.json`
- MCP worker: `gateway/mcp/src/worker_main.x07.json`
- shared engine and daemon: `tools/x07lp-driver/src/main.rs`
- Command Center UI bundle: `ui/command-center/dist/`

For more detail:

- quickstart: `docs/quickstart.md`
- CI gates: `docs/ci.md`
- wasmCloud self-hosted target: `examples/targets/wasmcloud/README.md`
