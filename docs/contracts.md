# Contracts

Authoritative public platform contracts live in:

- `x07-platform-contracts/spec/schemas/`
- `x07-platform-contracts/docs/contracts/README.md`

The local `contracts/` directory in this repo is a consumed checkout.
Do not edit `*.schema.json` or `index.json` here directly.

Regenerate boundary files via:

```bash
./scripts/contracts_sync.sh
```
