# wasmCloud Reference Target

This directory contains the self-hosted reference stack used by the D-OSS gate.

Components:

- `nats` `2.12.4`
- `wasmcloud` `1.9.2`
- `wadm` `0.21.1`
- local OCI registry on `127.0.0.1:15000`
- OpenTelemetry Collector `0.147.0`

Start the stack from the repo root:

```bash
docker compose -f examples/targets/wasmcloud/docker-compose.yml up -d
```

Run the D-OSS gate against the compose-backed target:

```bash
X07LP_PHASED_OSS_REMOTE_MODE=compose ./scripts/ci/phaseD-oss.sh
```

The control-plane daemon is still started by `phaseD-oss.sh` via `scripts/x07lp-driver ui-serve`. The compose stack provides the pinned wasmCloud/NATS/registry/OTLP dependencies that the self-hosted target profile expects.

`target.example.json` shows the expected creator-side target profile. Replace the token path with your local bearer-token file before importing it with `x07lp target add --profile ...`.
