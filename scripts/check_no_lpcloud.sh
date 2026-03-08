#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

paths=(engine cli gateway ui adapters scripts docs README.md x07.json x07.lock.json x07.mcp.router.json x07.mcp.worker.json)
matches=0
if grep -R -n \
  --include='*.x07.json' \
  --include='*.json' \
  --include='*.sh' \
  --include='*.py' \
  --include='*.rs' \
  --include='*.md' \
  --exclude='check_no_lpcloud.sh' \
  'lpcloud\.' "${paths[@]}"; then
  matches=1
fi

if [[ "$matches" -ne 0 ]]; then
  echo 'public repo must not reference lpcloud.*' >&2
  exit 1
fi

echo 'ok: no lpcloud references'
