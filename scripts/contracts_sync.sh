#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_PATH="${ROOT_DIR}/docs/contracts.md"

tmp="$(mktemp)"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

cat >"$tmp" <<'EOF'
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
EOF

if [[ ! -e "${ROOT_DIR}/contracts/spec/schemas/index.json" ]]; then
  echo "missing contracts checkout at contracts/spec/schemas/index.json" >&2
  exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  if ! diff -u "$tmp" "$OUT_PATH"; then
    echo "contracts boundary drift detected" >&2
    exit 1
  fi
  echo "ok: contracts boundary"
  exit 0
fi

cp "$tmp" "$OUT_PATH"
echo "wrote: ${OUT_PATH}"

