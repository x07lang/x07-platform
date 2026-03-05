#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys


def build_index(schemas_dir: pathlib.Path) -> dict:
    entries = []
    for path in sorted(schemas_dir.glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        schema_id = doc.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise SystemExit(f"missing $id in schema: {path}")
        entries.append({"id": schema_id, "path": path.name})
    entries.sort(key=lambda e: e["id"])
    return {"schemas": entries}


def expected_bytes(index_doc: dict) -> bytes:
    return (json.dumps(index_doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    schemas_dir = root / "spec" / "schemas"
    out_path = schemas_dir / "index.json"

    index_doc = build_index(schemas_dir)
    want = expected_bytes(index_doc)

    if args.check:
        if not out_path.is_file():
            print(f"missing: {out_path}", file=sys.stderr)
            return 2
        got = out_path.read_bytes()
        if got != want:
            print(f"schema index out of date: {out_path}", file=sys.stderr)
            print("run: python3 scripts/gen_schema_index.py", file=sys.stderr)
            return 1
        return 0

    out_path.write_bytes(want)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
