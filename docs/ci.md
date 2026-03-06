# CI gates

Run all local checks:

```bash
./scripts/ci/check_all.sh
```

This covers:

- Schema index drift (`scripts/gen_schema_index.py --check`)
- Lockfile drift (`x07 pkg lock --check`)
- accept-path goldens using fixture packs under `spec/fixtures/`
- local deploy execution + query coverage using the deploy gate under `scripts/ci/`
- MCP architecture manifest lock + checks (`gateway/mcp/arch/manifest.x07arch.json`)
- MCP smoke tests (`x07 test --manifest gateway/mcp/tests/tests.json`)
