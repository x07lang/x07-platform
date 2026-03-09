# wasmCloud Reference Target

This directory contains the self-hosted reference stack used by the remote OSS gate.

Components:

- `nats` `2.12.4`
- `wasmcloud` `1.9.2`
- `wadm` `0.21.1`
- Caddy TLS gateway on `https://localhost:17443`
- authenticated OCI registry on `https://localhost:15443`
- OpenTelemetry Collector `0.147.0`

Generate the dev CA and gateway certificate first:

```bash
./examples/targets/wasmcloud/scripts/gen-dev-cert.sh
```

Start the stack from the repo root:

```bash
X07LP_DEV_CERT_DIR=examples/targets/wasmcloud/certs/out \
  docker compose -f examples/targets/wasmcloud/docker-compose.yml up -d
```

Run the remote OSS gate against the compose-backed target:

```bash
X07LP_REMOTE_OSS_REMOTE_MODE=compose \
X07LP_REMOTE_SYNTHETIC_TELEMETRY=0 \
./scripts/ci/remote-oss.sh
```

The control-plane daemon is still started by `remote-oss.sh` via `scripts/x07lp-driver ui-serve`, but it now listens behind the TLS gateway on a plain local backend port. The compose stack provides the pinned wasmCloud/NATS/registry/OTLP dependencies that the self-hosted target profile expects.

Rollout telemetry flow:

- The deployed candidate workload serves real `GET /api/ping` traffic on the remote candidate upstream.
- During each analysis step, `x07lp-driver` samples that live candidate endpoint and emits the observed canary metrics to the OpenTelemetry Collector at `http://127.0.0.1:4318/v1/metrics`.
- The collector persists those OTLP metrics to `otel-output/collector-metrics.jsonl`; the driver then materializes the corresponding `x07.metrics.snapshot@0.1.0` and runs `x07-wasm slo eval`.
- The default remote path does not use seeded telemetry. Synthetic telemetry remains test-only behind `X07LP_REMOTE_SYNTHETIC_TELEMETRY=1`.

Required rollout-correlation attributes on the OTLP metrics are:

- `x07.exec_id`
- `x07.run_id`
- `x07.pack_sha256`
- `x07.slot`
- `x07.app_id`
- `x07.environment`

Fixture behavior:

- Promote uses the baseline `app_min_release` pack, which serves `/api/ping` successfully and stays within the SLO budget.
- Rollback uses the `app_min_release_spin` pack, whose backend exhausts CPU fuel and yields unhealthy canary samples, so the analysis step rolls the candidate back to `0%`.

The reference registry credentials are:

- username: `x07lp-oci-dev-user`
- password: `x07lp-oci-dev-pass`

The server-side secret store is encrypted at rest. Point `X07LP_REMOTE_SECRET_MASTER_KEY_FILE` at a 32-byte hex key file and pack the plaintext JSON store into `remote-secret-store.enc.json` with:

```bash
X07LP_REMOTE_SECRET_MASTER_KEY_FILE=/path/to/master.key \
  tools/x07lp-driver/target/debug/x07lp-driver secret-store-pack \
    --input /path/to/remote-secret-store.json \
    --output /path/to/remote-secret-store.enc.json
```

Create local files for the bearer token plus the OCI username/password refs shown in `target.example.json`, then import the profile with `x07lp target add --profile ...`.
