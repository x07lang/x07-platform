#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

prepend_path_if_dir() {
  local dir="$1"
  if [ -d "$dir" ]; then
    PATH="${dir}:${PATH}"
  fi
}

prepend_path_if_dir "${ROOT_DIR}/../x07/target/debug"
prepend_path_if_dir "${ROOT_DIR}/../x07-wasm-backend/target/debug"
prepend_path_if_dir "${ROOT_DIR}/../x07-wasm-backend/target/release"

export PATH
