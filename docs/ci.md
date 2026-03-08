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
- self-hosted remote target coverage and adapter conformance using `./scripts/ci/phaseD-oss.sh`
- MCP architecture manifest lock + checks (`gateway/mcp/arch/manifest.x07arch.json`)
- MCP smoke tests (`x07 test --manifest gateway/mcp/tests/tests.json`)
