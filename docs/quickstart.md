# Quickstart

Run directly from source:

```bash
cd x07-platform
LP="./scripts/x07lp-driver"

$LP accept \
  --target __local__ \
  --pack-dir path/to/pack \
  --pack-manifest app.pack.json \
  --change path/to/change_request.json \
  --state-dir _tmp/demo_state \
  --json

$LP run \
  --target __local__ \
  --deployment-id lpexec_example \
  --plan path/to/deploy.plan.json \
  --metrics-dir path/to/metrics \
  --state-dir _tmp/demo_state \
  --json

$LP query \
  --target __local__ \
  --deployment-id lpexec_example \
  --view full \
  --state-dir _tmp/demo_state \
  --json

$LP incident-list \
  --target __local__ \
  --deployment-id lpexec_example \
  --state-dir _tmp/demo_state \
  --json

$LP regress-from-incident \
  --target __local__ \
  --incident-id lpinc_example \
  --name smoke_regression \
  --out-dir _tmp/regress \
  --state-dir _tmp/demo_state \
  --json

./scripts/x07lp-driver ui-serve \
  --state-dir _tmp/demo_state \
  --addr 127.0.0.1:17090
```

All commands emit `lp.cli.report@0.1.0`.

Hosted auth/context examples against a local cloud stack:

```bash
LP="./scripts/x07lp-driver"

$LP login --api-base http://127.0.0.1:18081 --json
$LP login --device --api-base http://127.0.0.1:18081 --json
$LP whoami --json
$LP org list --json
$LP project list --org org_demo --json
$LP env list --project prj_demo --json
$LP context use --org org_demo --project prj_demo --env env_demo --json
```

Hosted deploy examples against the same cloud session:

```bash
$LP accept \
  --hosted \
  --pack-dir path/to/pack \
  --pack-manifest app.pack.json \
  --json

$LP run \
  --hosted \
  --deployment-id lpexec_example \
  --json

$LP status \
  --hosted \
  --deployment-id lpexec_example \
  --json

$LP query \
  --hosted \
  --deployment-id lpexec_example \
  --view summary \
  --json
```

Hosted deploy routing rules:

- Use `--hosted` explicitly to send deploy commands through the saved hosted session and selected hosted context.
- Use `--target` for the OSS self-hosted remote path.
- Use `--target __local__` to force local deploy, incident, and regression commands even when a saved remote target is active.
- Hosted status uses `GET /v1/deployments/:id`, not `/v1/deployments/:id/status`.

Implementation note:

- `./scripts/x07lp-driver` is the direct source entrypoint. A bundled `out/x07lp` uses the same commands.
- The higher-level X07 entrypoints and the MCP tools delegate to the shared Rust driver in `tools/x07lp-driver/`.
- That driver implements the local deploy executor, hosted auth/session commands, incident pipeline, signed control actions, regression runner bridge, SQLite index, and the `x07lpd` HTTP daemon.
- Hosted login state persists separately from OSS target profiles in `~/.config/x07lp/session.json` unless `X07LP_CONFIG_DIR` or `XDG_CONFIG_HOME` overrides it.

Generate or check the schema index:

```bash
./scripts/gen_schema_index.sh
./scripts/gen_schema_index.sh --check
```
