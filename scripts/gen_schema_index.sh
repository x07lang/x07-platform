#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -e "$ROOT_DIR/contracts/scripts/gen_schema_index.sh" ]; then
  echo "missing contracts repo at $ROOT_DIR/contracts" >&2
  exit 1
fi

exec "$ROOT_DIR/contracts/scripts/gen_schema_index.sh" "$@"
