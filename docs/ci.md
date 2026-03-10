# CI gates

Run all local checks:

```bash
./scripts/ci/check_all.sh
```

This covers:

- Schema index drift (`./scripts/gen_schema_index.sh --check`)
- Lockfile drift (`x07 pkg lock --check`)
- accept-path goldens using fixture packs under `spec/fixtures/`
- local deploy execution + query coverage using the deploy gates under `scripts/ci/`
- device-release create/run/control/query coverage using `./scripts/ci/device-release.sh`, with staged package copies, `mock_v1` runtime providers, and OTLP-derived metrics gates
- self-hosted remote target coverage and adapter conformance using `./scripts/ci/remote-oss.sh`, including HTTPS trust enforcement, authenticated/TLS OCI publishing, and encrypted server-side secret-store checks
- MCP architecture manifest lock + checks (`gateway/mcp/arch/manifest.x07arch.json`)
- MCP smoke tests (`x07 test --manifest gateway/mcp/tests/tests.json`)

Manual device-store smoke coverage is intentionally separate from the default gate. Use `./scripts/ci/device-release-live-smoke.sh` only with real App Store Connect or Google Play credentials loaded into the encrypted secret store and `X07LP_DEVICE_PROVIDER_LIVE=1`.
