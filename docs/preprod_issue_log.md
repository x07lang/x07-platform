# Pre-production release readiness: issue log (OSS)

Scope: `x07-platform` OSS lanes only (no `x07-platform-cloud`).

Format:
- Keep entries short and factual.
- Every resolved issue should include the **root cause** and the **fix** (with repo + commit SHA once committed).

## 2026-03-23

### Resolved

#### CrewOps gate: `bootstrap_api_error` trace did not fail + did not produce an incident bundle

- **Where:** `x07-crewops` `tests/traces/bootstrap_api_error.trace.json`
- **Symptom:** `x07-wasm app test bootstrap_api_error` returned `ok=true` with `incident_dir=null`; CrewOps gate expects a failing run with an incident so it can generate a regression from the captured bundle
- **Root cause:** the fixture returned HTTP `200` for `/api/bootstrap` instead of a 5xx response
- **Fix:** updated the trace fixture to return HTTP `500` so the incident pipeline runs (`x07-wasm app test` fails + writes `incident_dir`, `x07-wasm app regress from-incident` produces a stable regression trace that replays cleanly)
- **Status:** committed: `x07-crewops@bfa5b02`

#### CrewOps gate: desktop smoke required `x07-device-host-desktop`

- **Where:** `x07-crewops` `scripts/ci/check_all.sh` (`run_desktop_smoke`)
- **Symptom:** gate failed with `FAIL: device_desktop_dev smoke requires x07-device-host-desktop`
- **Root cause:** missing `x07-device-host-desktop` binary in the local toolchain / workspace build outputs
- **Fix:** build `x07-device-host` (or install the `device-host` toolchain component) so `x07-device-host-desktop --host-abi-hash` matches `x07-wasm-backend/vendor/x07-device-host/host_abi.snapshot.json`
- **Status:** resolved (no code changes); documented: `x07-crewops@bfa5b02`

#### `k3s` workload lane: null probe entries crash pack parsing

- **Where:** `scripts/ci/workload-k3s-smoke.sh` (workload accept path)
- **Symptom:** pack parsing failed when a cell had `"probe": null` (driver expected a probe object)
- **Root cause:** probe parsing treated JSON null as an object and errored instead of treating it as “probe absent”
- **Fix:** `x07-platform` `tools/x07lp-driver/src/workload_runtime.rs` now maps `probe: null` to `None` and includes a regression test (`deployable_cells_allows_null_probe_entries`)
- **Status:** committed: `x07-platform@90f6291`

#### `k3s` workload lane: HTTP probe port mismatch when `runtime_image` override is used

- **Where:** `scripts/ci/workload-k3s-smoke.sh` (ingress reachability / readiness)
- **Symptom:** Kubernetes probes used the wrong port for `traefik/whoami` when runtime image overrides were applied
- **Root cause:** probe generator used the default runtime port even when the workload cell specified a different container port
- **Fix:** `x07-wasm-backend` `crates/x07-wasm/src/workload/surface.rs` now aligns generated HTTP probes with the cell’s container port when `runtime_image` overrides are in effect (plus updated test expectations)
- **Status:** committed: `x07-wasm-backend@ff787ca` (released via `v0.2.11`)

#### Local deploy CI (Phase B): `deploy run` fails with `deploy_driver_empty_stdout` when a stale remote target is selected

- **Where:** `./scripts/ci/check_all.sh` → `./scripts/ci/phaseB.sh`
- **Symptom:** Phase B `deploy run` returned `LP_INTERNAL deploy_driver_empty_stdout`; direct `x07lp-driver run ...` printed a non-JSON error about a missing remote CA cert under `_tmp/ci_remote_oss/...`
- **Root cause:** Phase B invoked `deploy run` without `--target`; when a non-local target was selected in `x07lp` config, the driver tried to load remote TLS material and exited before emitting JSON (the wrapper only validates driver stdout)
- **Fix:** `scripts/ci/phaseB.sh` now injects `--target __local__` for deploy/incident/regress commands when not provided
- **Status:** committed: `x07-platform@90f6291`

#### Remote OSS lane: missing OTLP export mount helper

- **Where:** `./scripts/ci/remote-oss.sh`
- **Symptom:** `bash .../scripts/ci/prepare_otlp_export_mount.sh: No such file or directory`
- **Root cause:** script referenced a non-existent workspace-level helper path
- **Fix:** added `scripts/ci/prepare_otlp_export_mount.sh` to `x07-platform` and updated `remote-oss.sh` to call it from this repo
- **Status:** committed: `x07-platform@90f6291`

#### Remote OSS lane: regression report schema version drift

- **Where:** `./scripts/ci/remote-oss.sh` → `remote_regression_from_incident`
- **Symptom:** expected `lp.regression.run.result@0.1.0` but got `lp.regression.run.result@0.2.0`
- **Root cause:** regression run result schema version advanced; expected fixture was stale
- **Fix:** updated `spec/fixtures/remote-oss/remote_regression_from_incident/expected/regress.report.json`
- **Status:** committed: `x07-platform@90f6291`

#### `k3s` soak/chaos lanes: workload query stayed `degraded` and stop checks failed after seeding bindings

- **Where:** `scripts/ci/workload-k3s-soak.sh`, `scripts/ci/workload-k3s-chaos.sh`, `tools/x07lp-driver` k8s advisory binding checks
- **Symptom:** `k3s-soak`/`k3s-chaos` expected `observed_state=running` but got `degraded` due to required binding `db.primary` staying `pending`; first attempted fix (adding a dummy Service) made stop checks fail because the Service remained after `workload stop`
- **Root cause:** k8s advisory binding provider treated non-secret bindings as perpetually `pending` (even when configured) and also required a Kubernetes Service for postgres-like bindings; soak/chaos lanes require required bindings to be `ready` and `workload stop` to remove only workload resources
- **Fix:** k8s advisory binding provider now treats secret-present bindings as `ready` for CI semantics; soak/chaos lanes seed only Secrets (no extra Services) so required bindings can become `ready` without interfering with stop teardown assertions
- **Status:** committed: `x07-platform@90f6291`

#### Phase A accept golden drift after probe fixes

- **Where:** `scripts/ci/check_phaseA_golden.sh`
- **Symptom:** golden fixtures drifted due to updated pack digest / verify report digest
- **Root cause:** pack verification evidence digest changed after upstream pack/verify changes; fixtures were stale
- **Fix:** updated `spec/fixtures/phaseA/golden/deploy_accept.*.json` to match current deterministic outputs
- **Status:** committed: `x07-platform@90f6291`

#### Phase C pause flow: `pause_and_rerun` timed out waiting for `pause_*` step

- **Where:** `scripts/ci/phaseC.sh` (`pause_and_rerun` case)
- **Symptom:** `timed out waiting for active pause step` during `deploy run` background execution
- **Root cause:** the first `pause_*` step only becomes visible after candidate runtime start + runtime probe; 20s was insufficient on slower machines
- **Fix:** increased `wait_for_pause_step` timeout to 60s
- **Status:** committed: `x07-platform@90f6291`

#### Phase C UI smoke: `x07lp-driver ui-serve` leaked in the background

- **Where:** `scripts/ci/phaseC.sh` (`ui_smoke` case) and `scripts/ci/ui-screenshot-smoke.sh`
- **Symptom:** a `ui-serve` process stayed running after the gate completed, leaving the default UI port bound (for example `127.0.0.1:17090`) and breaking later screenshot steps
- **Root cause:** the gate launched `ui-serve` in a background subshell and later killed the subshell PID, leaving the child `x07lp-driver` process alive
- **Fix:** use `exec` inside the background subshell so the tracked PID is the `x07lp-driver` process
- **Status:** committed: `x07-platform@90f6291`

#### `k3s` workload lane: route never becomes ready in extended runs

- **Where:** `scripts/ci/workload-k3s-smoke.sh` (used by `target-conformance.sh k8s-extended`)
- **Symptom:** `route did not become ready` for the API example workload
- **Root cause:** the example workload declares a required binding (`db.primary`); without a placeholder Secret, the deployment can fail readiness and never serve the ingress route
- **Fix:** seed example binding Secrets (`db-primary`, `obj-documents`) before `workload run`
- **Status:** committed: `x07-platform@90f6291`

#### Remote OSS lane: `deploy query` intermittently returned `{}` (missing `schema_version`)

- **Where:** `scripts/ci/remote-oss.sh` (`remote_rollback.query.summary` in particular)
- **Symptom:** CI failed with `/schema_version: missing key` after a `deploy query` step wrote `{}` to the report file
- **Root cause:** transient remote query boundary returned an empty JSON document before the full report was ready (flake surfaced on slower / loaded machines)
- **Fix:** `run_remote_query_view` now retries until the query result includes `schema_version` (or times out with a helpful error)
- **Status:** committed: `x07-platform@90f6291`

### Open

(none yet)
