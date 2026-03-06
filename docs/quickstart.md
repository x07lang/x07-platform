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
```

All commands emit `lp.cli.report@0.1.0`.

Generate or check the schema index:

```bash
python3 scripts/gen_schema_index.py
python3 scripts/gen_schema_index.py --check
```
