# Quickstart

Run directly from source:

```bash
cd x07-platform

x07 run -- deploy accept \
  --pack-dir path/to/pack \
  --pack-manifest app.pack.json \
  --change path/to/change_request.json \
  --state-dir _tmp/demo_state \
  --json

x07 run -- deploy run \
  --deployment-id lpexec_example \
  --plan path/to/deploy.plan.json \
  --metrics-dir path/to/metrics \
  --state-dir _tmp/demo_state \
  --json

x07 run -- deploy query \
  --deployment-id lpexec_example \
  --view full \
  --state-dir _tmp/demo_state \
  --json

x07 run -- incident list \
  --deployment-id lpexec_example \
  --state-dir _tmp/demo_state \
  --json

x07 run -- regress from-incident \
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

Implementation note:

- `x07 run -- ...` and the MCP tools delegate to the shared Rust driver in `tools/x07lp-driver/`.
- That driver implements the local deploy executor, incident pipeline, signed control actions, regression runner bridge, SQLite index, and the `x07lpd` HTTP daemon.

Generate or check the schema index:

```bash
./scripts/gen_schema_index.sh
./scripts/gen_schema_index.sh --check
```
