#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMAS_DIR="$ROOT_DIR/spec/schemas"
OUT_PATH="$SCHEMAS_DIR/index.json"

check=0
if [ "${1:-}" = "--check" ]; then
  check=1
fi

tmp_pairs="$(mktemp)"
tmp_out="$(mktemp)"
cleanup() {
  rm -f "$tmp_pairs" "$tmp_out"
}
trap cleanup EXIT

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

shopt -s nullglob
for path in "$SCHEMAS_DIR"/*.schema.json; do
  schema_id="$(sed -n 's/^[[:space:]]*"\$id":[[:space:]]*"\([^"]*\)".*/\1/p' "$path" | head -n 1)"
  if [ -z "$schema_id" ]; then
    echo "missing \$id in schema: $path" >&2
    exit 1
  fi
  printf '%s\t%s\n' "$schema_id" "$(basename "$path")" >>"$tmp_pairs"
done
shopt -u nullglob

{
  printf '{\n'
  printf '  "schemas": [\n'
  first=1
  while IFS=$'\t' read -r schema_id schema_path; do
    [ -n "$schema_id" ] || continue
    if [ $first -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {\n'
    printf '      "id": "%s",\n' "$(json_escape "$schema_id")"
    printf '      "path": "%s"\n' "$(json_escape "$schema_path")"
    printf '    }'
  done < <(sort -t $'\t' -k1,1 "$tmp_pairs")
  printf '\n'
  printf '  ]\n'
  printf '}\n'
} >"$tmp_out"

if [ "$check" -eq 1 ]; then
  if [ ! -f "$OUT_PATH" ]; then
    echo "missing: $OUT_PATH" >&2
    exit 2
  fi
  if ! cmp -s "$OUT_PATH" "$tmp_out"; then
    echo "schema index out of date: $OUT_PATH" >&2
    echo "run: ./scripts/gen_schema_index.sh" >&2
    exit 1
  fi
  exit 0
fi

cp "$tmp_out" "$OUT_PATH"
