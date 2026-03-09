#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "python not found on PATH" >&2
  exit 1
fi

decode_solve_output_b64() {
  local report_path="$1"
  local out_path="$2"
  "$PYTHON" - "$report_path" "$out_path" <<'PY'
import base64
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
doc = json.loads(report.read_text(encoding="utf-8"))

def find_solve_output_b64(doc: dict) -> str:
    if not isinstance(doc, dict):
        return ""
    if isinstance(doc.get("solve_output_b64"), str):
        return doc["solve_output_b64"]
    solve = doc.get("solve")
    if isinstance(solve, dict) and isinstance(solve.get("solve_output_b64"), str):
        return solve["solve_output_b64"]
    result = doc.get("result")
    if isinstance(result, dict):
        stdout_json = result.get("stdout_json")
        if isinstance(stdout_json, dict):
            solve = stdout_json.get("solve")
            if isinstance(solve, dict) and isinstance(solve.get("solve_output_b64"), str):
                return solve["solve_output_b64"]
    report2 = doc.get("report")
    if isinstance(report2, dict):
        solve = report2.get("solve")
        if isinstance(solve, dict) and isinstance(solve.get("solve_output_b64"), str):
            return solve["solve_output_b64"]
    return ""

b64 = find_solve_output_b64(doc)
if not b64:
    raise SystemExit("missing solve_output_b64 in report")
data = base64.b64decode(b64)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(data)
PY
}

run_x07lp() {
  local report_path="$1"
  local out_path="$2"
  shift 2
  (
    cd "$ROOT_DIR"
    x07 run -- "$@" >"$report_path"
  )
  decode_solve_output_b64 "$report_path" "$out_path"
}

golden_matches() {
  local expected_path="$1"
  local actual_path="$2"
  "$PYTHON" - "$expected_path" "$actual_path" <<'PY'
import pathlib
import sys

expected = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").rstrip("\n")
actual = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").rstrip("\n")
raise SystemExit(0 if expected == actual else 1)
PY
}

check_cli_report_fields() {
  local cli_out="$1"
  local expect_ok="$2"
  local expect_exit_code="$3"
  local expect_outcome="$4"
  local expect_diag_code="$5"

  "$PYTHON" - "$cli_out" "$expect_ok" "$expect_exit_code" "$expect_outcome" "$expect_diag_code" <<'PY'
import json
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
expect_ok = sys.argv[2] == "true"
expect_exit_code = int(sys.argv[3])
expect_outcome = sys.argv[4]
expect_diag_code = sys.argv[5]

doc = json.loads(p.read_text(encoding="utf-8"))
ok = doc.get("ok")
exit_code = int(doc.get("exit_code", -1))
command = doc.get("command")
outcome = doc.get("result", {}).get("outcome")

if ok is not expect_ok:
    print("unexpected ok:", ok, "expected:", expect_ok, "file:", p)
    sys.exit(1)
if exit_code != expect_exit_code:
    print("unexpected exit_code:", exit_code, "expected:", expect_exit_code, "file:", p)
    sys.exit(1)
if command != "deploy accept":
    print("unexpected command:", command, "file:", p)
    sys.exit(1)
if expect_outcome and outcome != expect_outcome:
    print("unexpected outcome:", outcome, "expected:", expect_outcome, "file:", p)
    sys.exit(1)

if expect_diag_code:
    codes = [d.get("code") for d in doc.get("diagnostics", []) if isinstance(d, dict)]
    if expect_diag_code not in codes:
        print("missing diagnostic code:", expect_diag_code, "got:", codes, "file:", p)
        sys.exit(1)
PY
}

extract_store_rel_path() {
  local cli_out="$1"
  local logical_name="$2"
  "$PYTHON" - "$cli_out" "$logical_name" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
name = sys.argv[2]
for a in doc.get("meta", {}).get("artifacts_written", []):
    if not isinstance(a, dict):
        continue
    if a.get("logical_name") != name:
        continue
    uri = a.get("store_uri") or ""
    if isinstance(uri, str) and uri.startswith("file:"):
        print(uri[len("file:"):])
        sys.exit(0)

raise SystemExit(f"missing file store_uri for {name}")
PY
}

check_schema_validate_ok() {
  local schema_path="$1"
  local in_path="$2"
  local report_path="$3"
  local out_path="$4"
  run_x07lp "$report_path" "$out_path" schema validate --schema "$schema_path" --in "$in_path" --json
  "$PYTHON" - "$out_path" <<'PY'
import json
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
doc = json.loads(p.read_text(encoding="utf-8"))
if doc.get("ok") is not True:
    print("schema validate not ok:", p)
    print(json.dumps(doc.get("diagnostics", []), indent=2))
    sys.exit(1)
res = doc.get("result", {})
if res.get("ok") is not True:
    print("schema validate result not ok:", p)
    print(json.dumps(res, indent=2))
    sys.exit(1)
PY
}

PACK_DIR="spec/fixtures/phaseA/pack_min"
NOW_UNIX_MS="1762147200000"

CHANGE_ALLOW="spec/fixtures/phaseA/change_request.min.json"
CHANGE_DENY="spec/fixtures/phaseA/change_request.ops_required.json"

GOLDEN_ALLOW="spec/fixtures/phaseA/golden/deploy_accept.allow.json"
GOLDEN_DENY="spec/fixtures/phaseA/golden/deploy_accept.deny.ops_required.json"

mkdir -p "${ROOT_DIR}/_tmp"

echo "case: allow"
rm -rf "${ROOT_DIR}/_tmp/ci_phaseA_allow_state"
run_x07lp \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" \
  deploy accept \
  --pack-dir "${PACK_DIR}" \
  --pack-manifest app.pack.json \
  --change "${CHANGE_ALLOW}" \
  --state-dir _tmp/ci_phaseA_allow_state \
  --now-unix-ms "${NOW_UNIX_MS}" \
  --json

golden_matches "${ROOT_DIR}/${GOLDEN_ALLOW}" "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" || {
  echo "deploy accept allow output drifted" >&2
  diff -u "${ROOT_DIR}/${GOLDEN_ALLOW}" "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" >&2
  exit 1
}
check_cli_report_fields "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" true 0 allow ""

run_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" lp.pipeline.run)"
dec_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" lp.decision.record)"
exec_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_allow.cli.json" lp.deploy.execution)"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.pipeline.run.schema.json" \
  "_tmp/ci_phaseA_allow_state/${run_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_run.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_run.cli.json"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.decision.record.schema.json" \
  "_tmp/ci_phaseA_allow_state/${dec_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_dec.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_dec.cli.json"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "_tmp/ci_phaseA_allow_state/${exec_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_exec.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_allow.validate_exec.cli.json"

echo "ok: allow"

echo "case: deny (ops required, missing --ops-profile)"
rm -rf "${ROOT_DIR}/_tmp/ci_phaseA_deny_state"
run_x07lp \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" \
  deploy accept \
  --pack-dir "${PACK_DIR}" \
  --pack-manifest app.pack.json \
  --change "${CHANGE_DENY}" \
  --state-dir _tmp/ci_phaseA_deny_state \
  --now-unix-ms "${NOW_UNIX_MS}" \
  --json

golden_matches "${ROOT_DIR}/${GOLDEN_DENY}" "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" || {
  echo "deploy accept deny output drifted" >&2
  diff -u "${ROOT_DIR}/${GOLDEN_DENY}" "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" >&2
  exit 1
}
check_cli_report_fields "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" false 13 deny "LP_GATE_REJECTED"

run_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" lp.pipeline.run)"
dec_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" lp.decision.record)"
exec_rel="$(extract_store_rel_path "${ROOT_DIR}/_tmp/ci_phaseA_deny.cli.json" lp.deploy.execution)"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.pipeline.run.schema.json" \
  "_tmp/ci_phaseA_deny_state/${run_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_run.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_run.cli.json"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.decision.record.schema.json" \
  "_tmp/ci_phaseA_deny_state/${dec_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_dec.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_dec.cli.json"

check_schema_validate_ok \
  "contracts/spec/schemas/lp.deploy.execution.schema.json" \
  "_tmp/ci_phaseA_deny_state/${exec_rel}" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_exec.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_deny.validate_exec.cli.json"

echo "ok: deny"

echo "case: bad pack digest mismatch"
rm -rf "${ROOT_DIR}/_tmp/ci_phaseA_bad_digest_state"
run_x07lp \
  "${ROOT_DIR}/_tmp/ci_phaseA_bad_digest.run_report.json" \
  "${ROOT_DIR}/_tmp/ci_phaseA_bad_digest.cli.json" \
  deploy accept \
  --pack-dir "${PACK_DIR}" \
  --pack-manifest app.pack.bad.json \
  --change "${CHANGE_ALLOW}" \
  --state-dir _tmp/ci_phaseA_bad_digest_state \
  --now-unix-ms "${NOW_UNIX_MS}" \
  --json
check_cli_report_fields "${ROOT_DIR}/_tmp/ci_phaseA_bad_digest.cli.json" false 12 "" "LP_PACK_DIGEST_MISMATCH_FILE"
echo "ok: bad digest"
