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
X07LP_REMOTE_OSS_REMOTE_MODE=compose ./scripts/ci/remote-oss.sh
```

The control-plane daemon is still started by `remote-oss.sh` via `scripts/x07lp-driver ui-serve`, but it now listens behind the TLS gateway on a plain local backend port. The compose stack provides the pinned wasmCloud/NATS/registry/OTLP dependencies that the self-hosted target profile expects.

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
