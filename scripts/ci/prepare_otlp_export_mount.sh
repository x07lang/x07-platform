#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <host-export-dir>" >&2
  exit 1
fi

export_dir="$1"
export_file="${export_dir}/collector-metrics.jsonl"

mkdir -p "${export_dir}"
chmod 0777 "${export_dir}"

if [[ -e "${export_file}" && ! -f "${export_file}" ]]; then
  echo "OTLP export path must be a regular file: ${export_file}" >&2
  exit 1
fi

: >"${export_file}"
chmod 0666 "${export_file}"

if [[ ! -w "${export_file}" ]]; then
  echo "OTLP export file is not writable: ${export_file}" >&2
  exit 1
fi
