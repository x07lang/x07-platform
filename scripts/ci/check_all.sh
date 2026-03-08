#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/ci/use_workspace_x07_bins.sh"

./scripts/ci/check_schema_index.sh

x07 pkg lock --project x07.json --check
echo "ok: lockfile"

./scripts/ci/check_phaseA_golden.sh
./scripts/ci/phaseB.sh
./scripts/ci/phaseC.sh
./scripts/ci/phaseD-oss.sh

(cd gateway/mcp && x07 arch check --manifest arch/manifest.x07arch.json >/dev/null)
echo "ok: mcp arch"

x07 test --manifest gateway/mcp/tests/tests.json >/dev/null
echo "ok: tests"
