# Phase A quickstart

## CLI

Run directly from source:

```bash
cd x07-platform

# Allow case
x07 run -- deploy accept \
  --pack-dir spec/fixtures/phaseA/pack_min \
  --pack-manifest app.pack.json \
  --change spec/fixtures/phaseA/change_request.min.json \
  --state-dir _tmp/demo_state \
  --now-unix-ms 1762147200000 \
  --json
```

All Phase A commands emit a canonical `lp.cli.report@0.1.0` JSON object.

## Schemas

Generate (or check) the local schema index:

```bash
python3 scripts/gen_schema_index.py
python3 scripts/gen_schema_index.py --check
```

## MCP gateway

Bundle router + worker:

```bash
x07 bundle --project x07.mcp.router.json --profile os --out out/x07lp-mcp-router
x07 bundle --project x07.mcp.worker.json --profile sandbox --out out/x07lp-mcp-worker
```

See `docs/mcp.md` for tool list + config.

