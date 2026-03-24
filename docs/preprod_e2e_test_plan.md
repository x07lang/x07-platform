# Pre-production release readiness: end-to-end test plan (OSS)

Scope: `x07-platform` (OSS) only.

Non-goals for this plan:
- **Do not** test `x07-platform-cloud` / hosted control-plane.
- **Do not** run live mobile store providers (App Store Connect / Google Play). Mock device providers are in scope.

This plan is written to be repeatable: every run should capture evidence (JSON outputs, logs, screenshots, DB queries) under a single run directory.

## 0) Prerequisites

Required tools:
- `x07` toolchain with wasm + device-host components (`x07up component add wasm`, `x07up component add device-host`)
- `python3`
- `node` + `npx` (for Playwright UI screenshots and CrewOps trace generation)
- `docker` + `docker compose` (for the self-hosted wasmCloud target, and for `k3d`)
- `kubectl`
- `k3d` (K3s-in-Docker)
- `sqlite3` (for PhaseB/PhaseC query-index verification)

Optional (but recommended) verification tools:
- Playwright (UI screenshots + basic click-path smoke)
- `kubestl` (k8s manifest/status inspection)
- `jq` (JSON inspection)

Repo layout assumed (sibling repos):
```
.../x07-platform
.../x07-crewops
.../x07
```

### Use workspace `x07` binaries (recommended)

Some CI scripts expect a workspace toolchain build (native backends present).

From `x07-platform/`:
```bash
source scripts/ci/use_workspace_x07_bins.sh
```

## 1) Evidence capture conventions

Create a dedicated run directory:
```bash
cd x07-platform
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$PWD/_tmp/preprod/$RUN_ID"
mkdir -p "$RUN_DIR"
```

Guidelines:
- Every command below should be run with `--json` where available and written into `$RUN_DIR/...`.
- Collect docker / k8s logs into `$RUN_DIR/logs/`.
- Collect UI screenshots into `$RUN_DIR/ui/`.
- Keep large raw artifacts out of git; only commit summaries (this doc + issue log).

## 2) Supported targets (OSS) and required user flows

Targets in scope:
- **Local** (`__local__`): sealed pack accept → deploy plan run → query → controls → incident/regression → UI
- **Self-hosted wasmCloud remote target** (`oss-wasmcloud`): target onboarding → remote accept/run/query → OCI publish + TLS auth checks → logs
- **Kubernetes (K3s)** (`k3s-local`): workload accept/run/query/bindings/reconcile/stop → ingress verification → soak/chaos lanes
- **MCP**: router/worker manifests and smoke tests
- **Device release (mock providers)**: create/run/control/query + UI pages

### Flow checklist (run in order)

0. One-command orchestrator (recommended for repeatable evidence capture)
   - `./scripts/ci/preprod_e2e.sh`
   - This runs `check_all`, captures UI screenshots, runs `k8s-extended`, and optionally runs the CrewOps gate if the sibling repo exists.

1. Repo gate baseline (fast correctness)
   - `./scripts/ci/check_all.sh`
   - Evidence:
     - `$RUN_DIR/check_all.log`
     - `$RUN_DIR/ci_artifacts/` (copy `_tmp/ci_*` directories you want to keep)

2. Local deploy + query + UI smoke (Phase C)
   - `./scripts/ci/phaseC.sh`
   - Serve UI against the produced state dir, then capture screenshots.
   - Evidence:
     - `$RUN_DIR/phaseC.log`
     - `$RUN_DIR/db/phaseb.sqlite.*` and `$RUN_DIR/db/phasec.sqlite.*` (query output)
     - `$RUN_DIR/ui/*.png` screenshots

3. Local controls + incident + regression
   - Use the Phase C state (or produce a new local state) and run:
     - pause/rerun/rollback/stop controls
     - incident capture and regression generation
   - Evidence:
     - `$RUN_DIR/local_controls/*.json`
     - `$RUN_DIR/runtime_logs/`

4. Self-hosted remote wasmCloud target (docker compose)
   - `./scripts/ci/remote-oss.sh`
   - Evidence:
     - `$RUN_DIR/remote_oss.log`
     - `$RUN_DIR/docker_logs/wasmcloud-stack.log`

5. Kubernetes (K3s via `k3d`) workload lane
   - Smoke (required): `bash scripts/ci/workload-k3s-smoke.sh`
   - Extended (recommended): `bash scripts/ci/target-conformance.sh k8s-extended`
   - Evidence:
     - `$RUN_DIR/k8s_smoke.log`
     - `$RUN_DIR/k8s_extended.log`
     - `$RUN_DIR/k8s/` (`kubectl get/describe/events` snapshots)

6. Device release loop (mock providers)
   - `./scripts/ci/device-release.sh`
   - Evidence:
     - `$RUN_DIR/device_release.log`
     - `$RUN_DIR/ui_device_release/*.png`

7. MCP smoke
   - Included in `check_all.sh`, but can be run explicitly:
     - `x07 test --manifest gateway/mcp/tests/tests.json`
   - Evidence:
     - `$RUN_DIR/mcp_tests.json`

8. CrewOps end-to-end (real app input)
   - Build + pack CrewOps in `x07-crewops/`, then deploy with `x07lp` to:
     - local (`__local__`)
     - self-hosted wasmCloud (`oss-wasmcloud`)
     - (optional) k8s workload lane if/when CrewOps ships `x07.workload.pack@0.1.0`
   - Evidence:
     - `$RUN_DIR/crewops/*.json`
     - `$RUN_DIR/ui_crewops/*.png`

## 3) Evidence collection steps (by target)

### 3.1 Local (`__local__`) deploy execution + DB checks

Run Phase C (creates a rich local state dir used throughout the UI/controls flows):
```bash
cd x07-platform
./scripts/ci/phaseC.sh 2>&1 | tee "$RUN_DIR/phaseC.log"
```

Phase C state directory (current convention):
- `_tmp/ci_phaseC/promote_state`

Serve UI:
```bash
./scripts/x07lp-driver ui-serve \
  --state-dir _tmp/ci_phaseC/promote_state \
  --addr 127.0.0.1:17090
```

DB index checks (derived state; query acceleration):
```bash
STATE_DIR="$PWD/_tmp/ci_phaseC/promote_state"
sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select k,v from meta order by k;"
sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select count(*) as executions from executions;"
sqlite3 "$STATE_DIR/index/phasec.sqlite" "select count(*) as incidents from incidents;"
```

Capture the outputs (example):
```bash
{
  echo "== phaseb meta ==";
  sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select k,v from meta order by k;";
  echo "== phaseb counts ==";
  sqlite3 "$STATE_DIR/index/phaseb.sqlite" "select count(*) as executions from executions;";
  echo "== phasec counts ==";
  sqlite3 "$STATE_DIR/index/phasec.sqlite" "select count(*) as incidents from incidents;";
} 2>&1 | tee "$RUN_DIR/db/index_checks.txt"
```

### 3.2 Self-hosted wasmCloud (`oss-wasmcloud`) remote target logs

When the remote lane uses the reference stack in `examples/targets/wasmcloud/`, collect logs:
```bash
cd x07-platform
docker compose -f examples/targets/wasmcloud/docker-compose.yml logs --no-color \
  >"$RUN_DIR/docker_logs/wasmcloud-stack.log"
```

### 3.3 Kubernetes (`k3s-local`) snapshots

Collect a minimal k8s snapshot:
```bash
mkdir -p "$RUN_DIR/k8s"
kubectl get nodes -o wide >"$RUN_DIR/k8s/nodes.txt"
kubectl get pods -A -o wide >"$RUN_DIR/k8s/pods_all.txt"
kubectl get svc -A -o wide >"$RUN_DIR/k8s/svc_all.txt"
kubectl get ingress -A -o wide >"$RUN_DIR/k8s/ingress_all.txt"
kubectl get events -A --sort-by=.lastTimestamp >"$RUN_DIR/k8s/events_all.txt"
```

If a lane fails, add targeted details (replace namespace/pod):
```bash
kubectl describe pod -n default <pod> >"$RUN_DIR/k8s/describe_pod.txt"
kubectl logs -n default <pod> --all-containers >"$RUN_DIR/k8s/pod_logs.txt"
```

## 4) UI verification (screenshots + click-path smoke)

Minimum screenshot set (Command Center):
- `/apps`
- `/device-releases`
- `/deployments/<id>` (from Phase C)
- `/incidents/<id>` (from Phase C)

Recommended automation:
- Use Playwright to (1) wait for the UI to load, (2) navigate to each route, and (3) save screenshots to `$RUN_DIR/ui/`.
- Repo helper: `./scripts/ci/ui-screenshot-smoke.sh --state-dir <state> --out-dir <dir>`

## 5) Pass/fail criteria

A run is **green** when:
- `./scripts/ci/check_all.sh` passes cleanly.
- Target conformance:
  - `k8s` smoke passes at minimum, and `k8s-extended` is recommended for release readiness.
  - `remote-oss` lane passes cleanly (TLS, OCI auth, encrypted secret-store checks).
- UI screenshots are captured for the minimum set and are visually sane (no blank pages, error banners, missing data).
- DB index checks show non-zero expected rows for Phase B/C (when Phase C state is present).
- No open P0/P1 issues remain in `docs/preprod_issue_log.md`.

## 6) Troubleshooting notes (common failure modes)

- If a CI script fails with missing native backends, re-run after sourcing:
  - `source scripts/ci/use_workspace_x07_bins.sh`
- If k3s/K3d fails to start, verify Docker Desktop is running and `k3d cluster list` is healthy.
- If UI shows empty lists, confirm `--state-dir` points at a populated state directory (for example `_tmp/ci_phaseC/promote_state`).
