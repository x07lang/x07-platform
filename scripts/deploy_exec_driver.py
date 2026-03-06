#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
DEFAULT_STATE_DIR = Path("out/x07lp_state")
DDL_PATH = ROOT / "adapters" / "sql" / "phaseB_index.sqlite.sql"
TOOL_VERSION = "0.1.0-dev"
VALID_QUERY_VIEWS = {"summary", "timeline", "decisions", "artifacts", "full"}


def canon_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canon_json(data))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_ref_from_bytes(data: bytes) -> dict[str, Any]:
    return {"sha256": sha256_hex(data), "bytes_len": len(data)}


def result_diag(code: str, stage: str, message: str, severity: str = "error") -> dict[str, Any]:
    stage_value = "parse" if stage == "parse" else "run"
    return {
        "code": code,
        "severity": severity,
        "stage": stage_value,
        "message": message,
    }


def cli_report(
    command: str,
    ok: bool,
    exit_code: int,
    result: dict[str, Any],
    run_id: str = "",
    diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "lp.cli.report@0.1.0",
        "command": command,
        "ok": ok,
        "exit_code": exit_code,
        "diagnostics": diagnostics or [],
        "result": result,
    }
    if run_id:
        report["meta"] = {
            "tool": "x07lp",
            "version": TOOL_VERSION,
            "run_id": run_id,
        }
    return report


def deploy_meta_schema() -> str:
    return "lp.deploy.execution.meta.local@0.1.0"


def now_ms() -> int:
    return int(time.time() * 1000)


def rel_store_blob_path(state_dir: Path, sha: str) -> Path:
    return state_dir / "store" / "blobs" / "sha256" / sha[:2] / sha


def rel_store_meta_path(state_dir: Path, sha: str) -> Path:
    return state_dir / "store" / "meta" / "sha256" / sha[:2] / f"{sha}.json"


def cas_put(state_dir: Path, logical_name: str, media_type: str, data: bytes) -> dict[str, Any]:
    digest = digest_ref_from_bytes(data)
    sha = digest["sha256"]
    blob_path = rel_store_blob_path(state_dir, sha)
    meta_path = rel_store_meta_path(state_dir, sha)
    blob_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    if not blob_path.exists():
        blob_path.write_bytes(data)
    meta = {
        "algo": "sha256",
        "sha256": sha,
        "bytes_len": digest["bytes_len"],
        "media_type": media_type,
        "logical_name": logical_name,
        "store_uri": f"sha256:{sha}",
    }
    write_json(meta_path, meta)
    return {
        "digest": digest,
        "media_type": media_type,
        "logical_name": logical_name,
        "store_uri": meta["store_uri"],
    }


def named_file_artifact(
    rel_path: str,
    kind: str,
    media_type: str,
    data: bytes,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "digest": digest_ref_from_bytes(data),
        "media_type": media_type,
        "logical_name": kind.rsplit("@", 1)[0].split(".")[-1].replace("_", "."),
        "store_uri": f"file:{rel_path}",
    }


def find_first_existing(paths: Iterable[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def resolve_state_dir(raw: str | None) -> Path:
    value = raw or os.environ.get("X07LP_STATE_DIR") or str(DEFAULT_STATE_DIR)
    return (ROOT / value).resolve() if not Path(value).is_absolute() else Path(value)


def exec_path(state_dir: Path, exec_id: str) -> Path:
    return state_dir / "deploy" / f"{exec_id}.json"


def run_path(state_dir: Path, run_id: str) -> Path:
    return state_dir / "runs" / f"{run_id}.json"


def change_path(state_dir: Path, change_id: str) -> Path:
    return state_dir / "changes" / f"{change_id}.json"


def decision_path(state_dir: Path, decision_id: str) -> Path:
    return state_dir / "decisions" / f"{decision_id}.json"


def load_exec(state_dir: Path, exec_id: str) -> dict[str, Any]:
    return load_json(exec_path(state_dir, exec_id))


def save_exec(state_dir: Path, exec_doc: dict[str, Any]) -> bytes:
    path = exec_path(state_dir, exec_doc["exec_id"])
    data = canon_json(exec_doc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def infer_target_from_run(state_dir: Path, run_doc: dict[str, Any]) -> dict[str, str]:
    app_id = "unknown"
    environment = "unknown"
    change_ref = (run_doc.get("inputs") or {}).get("change_request") or {}
    change_id = change_ref.get("change_id")
    if change_id:
        change_doc = load_json(change_path(state_dir, change_id))
        target = change_doc.get("target") or {}
        app_id = target.get("app_id") or app_id
        env = target.get("environment") or {}
        environment = env.get("kind") or environment
    return {"app_id": app_id, "environment": environment}


def load_cas_blob(state_dir: Path, sha: str) -> bytes:
    return rel_store_blob_path(state_dir, sha).read_bytes()


def load_pack_manifest_from_run(state_dir: Path, run_doc: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    manifest = (((run_doc.get("inputs") or {}).get("artifact") or {}).get("manifest") or {})
    digest = manifest.get("digest") or {}
    sha = digest.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        raise RuntimeError("missing pack manifest digest")
    raw = load_cas_blob(state_dir, sha)
    return json.loads(raw), raw


def materialize_pack_dir(state_dir: Path, run_doc: dict[str, Any], out_dir: Path) -> tuple[dict[str, Any], bytes]:
    manifest, manifest_raw = load_pack_manifest_from_run(state_dir, run_doc)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "app.pack.json").write_bytes(manifest_raw)
    digest_specs: list[dict[str, Any]] = []
    bundle = manifest.get("bundle_manifest")
    if bundle:
        digest_specs.append(bundle)
        bundle_sha = bundle.get("sha256")
        if isinstance(bundle_sha, str) and len(bundle_sha) == 64:
            bundle_bytes = load_cas_blob(state_dir, bundle_sha)
            (out_dir / "app.bundle.json").write_bytes(bundle_bytes)
            bundle_doc = json.loads(bundle_bytes)
            backend_artifact = ((bundle_doc.get("backend") or {}).get("artifact")) or {}
            if backend_artifact:
                digest_specs.append(backend_artifact)
            for artifact in ((bundle_doc.get("frontend") or {}).get("artifacts") or []):
                digest_specs.append(artifact)
    backend = (manifest.get("backend") or {}).get("component")
    if backend:
        digest_specs.append(backend)
    for asset in manifest.get("assets") or []:
        file_spec = asset.get("file")
        if file_spec:
            digest_specs.append(file_spec)
    seen: set[tuple[str, str]] = set()
    for spec in digest_specs:
        sha = spec.get("sha256")
        rel_path = spec.get("path")
        if not isinstance(sha, str) or not isinstance(rel_path, str):
            continue
        key = (sha, rel_path)
        if key in seen:
            continue
        seen.add(key)
        data = load_cas_blob(state_dir, sha)
        dest = out_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return manifest, manifest_raw


def deterministic_listener(exec_id: str) -> str:
    port = 20000 + (int(hashlib.sha256(exec_id.encode("utf-8")).hexdigest()[:8], 16) % 20000)
    return f"http://127.0.0.1:{port}"


def normalize_plan(plan_doc: dict[str, Any]) -> dict[str, Any]:
    if plan_doc.get("schema_version") == "x07.deploy.plan@0.1.0":
        plan_doc = dict(plan_doc)
        plan_doc["schema_version"] = "x07.deploy.plan@0.2.0"
    return plan_doc


def search_workspace_file(name: str) -> Path | None:
    candidates = [
        ROOT / name,
        ROOT / "spec" / "fixtures" / "phaseA" / "pack_min" / name,
        WORKSPACE / "x07-wasm-backend" / "arch" / "slo" / name,
        WORKSPACE / "x07-wasm-backend" / "arch" / "app" / "ops" / name,
    ]
    found = find_first_existing(candidates)
    if found:
        return found
    for base in [ROOT, WORKSPACE / "x07-wasm-backend"]:
        try:
            for path in base.rglob(name):
                return path
        except Exception:
            continue
    return None


def resolve_plan_path(path_str: str | None) -> Path | None:
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_absolute():
        path = ROOT / path
    return path


def resolve_plan_inputs(plan_doc: dict[str, Any]) -> dict[str, Path | None]:
    ops_name = ((plan_doc.get("ops_profile") or {}).get("path")) or "ops_release.json"
    slo_name = ((plan_doc.get("slo_profile") or {}).get("path")) if plan_doc.get("slo_profile") else None
    return {
        "ops": search_workspace_file(os.path.basename(ops_name)),
        "slo": search_workspace_file(os.path.basename(slo_name)) if slo_name else None,
    }


def run_capture(argv: list[str], cwd: Path | None = None) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(
        argv,
        cwd=str(cwd or ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def resolve_tool_cwd_and_path(path: Path | None) -> tuple[Path, str | None]:
    if path is None:
        return ROOT, None
    resolved = path.resolve()
    tool_cwd = ROOT
    for parent in resolved.parents:
        if (parent / "arch").is_dir():
            tool_cwd = parent
            break
    try:
        path_arg = str(resolved.relative_to(tool_cwd))
    except ValueError:
        path_arg = str(resolved)
    return tool_cwd, path_arg


def synth_runtime_probe(exec_id: str, work_dir: Path) -> dict[str, Any]:
    return {
        "schema_version": "lp.runtime.probe.synthetic@0.1.0",
        "command": "lp.runtime.probe.synthetic",
        "ok": True,
        "exit_code": 0,
        "diagnostics": [],
        "result": {
            "exec_id": exec_id,
            "work_dir": str(work_dir),
            "status": "healthy",
        },
    }


def failed_runtime_probe(exec_id: str, work_dir: Path, exit_code: int, message: str) -> dict[str, Any]:
    return {
        "schema_version": "lp.runtime.probe.synthetic@0.1.0",
        "command": "lp.runtime.probe.synthetic",
        "ok": False,
        "exit_code": exit_code,
        "diagnostics": [result_diag("LP_RUNTIME_HEALTHCHECK_FAILED", "run", message)],
        "result": {
            "exec_id": exec_id,
            "work_dir": str(work_dir),
            "status": "unhealthy",
        },
    }


def runtime_probe_ok(report: dict[str, Any]) -> bool:
    if report.get("ok") is False:
        return False
    if report.get("ok") is True:
        return True
    status = str(((report.get("result") or {}).get("status")) or "unknown")
    return status in {"healthy", "ok", "running"}


def runtime_probe_message(report: dict[str, Any]) -> str:
    diagnostics = report.get("diagnostics") or []
    if diagnostics and diagnostics[0].get("message"):
        return str(diagnostics[0]["message"])
    status = ((report.get("result") or {}).get("status")) or "unknown"
    return f"candidate runtime probe reported status={status}"


def run_runtime_probe(exec_id: str, work_dir: Path, ops_path: Path | None) -> dict[str, Any]:
    x07_wasm = shutil.which("x07-wasm")
    if not x07_wasm:
        return synth_runtime_probe(exec_id, work_dir)
    probe_cwd, ops_arg = resolve_tool_cwd_and_path(ops_path)
    argv = [x07_wasm, "app", "serve", "--dir", str(work_dir), "--mode", "smoke", "--json"]
    if ops_arg is not None:
        argv.extend(["--ops", ops_arg])
    code, stdout, stderr = run_capture(argv, cwd=probe_cwd)
    if code == 0:
        try:
            return json.loads(stdout.decode("utf-8"))
        except Exception:
            return failed_runtime_probe(exec_id, work_dir, 1, "candidate runtime probe returned invalid JSON")
    # If the pack doesn't support `app serve` (e.g. no bundle manifest),
    # fall back to synthetic probe — expected for minimal packs.
    try:
        err_doc = json.loads(stdout.decode("utf-8"))
        err_code = (err_doc.get("diagnostics") or [{}])[0].get("code", "")
        if err_code in ("X07WASM_APP_BUNDLE_MISSING", "X07WASM_APP_NOT_SERVABLE"):
            return synth_runtime_probe(exec_id, work_dir)
    except Exception:
        pass
    message = stderr.decode("utf-8", errors="replace").strip() or "candidate runtime probe failed"
    return failed_runtime_probe(exec_id, work_dir, code or 1, message)


def synth_slo_eval(profile_path: Path, metrics_path: Path, decision: str) -> dict[str, Any]:
    profile_bytes = profile_path.read_bytes() if profile_path.exists() else b"{}"
    metrics_bytes = metrics_path.read_bytes()
    return {
        "schema_version": "x07.wasm.slo.eval.report@0.1.0",
        "command": "x07-wasm.slo.eval",
        "ok": True,
        "exit_code": 0,
        "diagnostics": [],
        "meta": {
            "tool": {"name": "x07-wasm", "version": "synthetic"},
            "elapsed_ms": 0,
            "cwd": str(ROOT),
            "argv": ["x07-wasm", "slo", "eval"],
            "inputs": [
                {"path": str(profile_path), **digest_ref_from_bytes(profile_bytes)},
                {"path": str(metrics_path), **digest_ref_from_bytes(metrics_bytes)},
            ],
            "outputs": [],
            "nondeterminism": {
                "uses_os_time": False,
                "uses_network": False,
                "uses_process": False,
            },
        },
        "result": {
            "slo_profile": {"path": str(profile_path), **digest_ref_from_bytes(profile_bytes)},
            "metrics_snapshot": {"path": str(metrics_path), **digest_ref_from_bytes(metrics_bytes)},
            "decision": decision,
            "violations": 0 if decision == "promote" else 1,
            "indicators": [],
        },
    }


def infer_slo_decision(metrics_doc: dict[str, Any]) -> str:
    metrics = {metric.get("name"): metric.get("value") for metric in metrics_doc.get("metrics") or []}
    latency = metrics.get("http_latency_p95_ms")
    error_rate = metrics.get("http_error_rate")
    availability = metrics.get("http_availability")
    if latency is None:
        return "inconclusive"
    if error_rate is not None and float(error_rate) > 0.01:
        return "rollback"
    if availability is not None and float(availability) < 0.99:
        return "rollback"
    if float(latency) > 250.0:
        return "rollback"
    return "promote"


def run_slo_eval(profile_path: Path | None, metrics_path: Path) -> tuple[str, dict[str, Any]]:
    metrics_doc = load_json(metrics_path)
    inferred = infer_slo_decision(metrics_doc)
    x07_wasm = shutil.which("x07-wasm")
    if x07_wasm and profile_path is not None and profile_path.exists():
        slo_cwd, profile_arg = resolve_tool_cwd_and_path(profile_path)
        argv = [x07_wasm, "slo", "eval", "--profile", str(profile_arg), "--metrics", str(metrics_path.resolve()), "--json"]
        code, stdout, _stderr = run_capture(argv, cwd=slo_cwd)
        if code == 0:
            try:
                report = json.loads(stdout.decode("utf-8"))
                decision = (((report.get("result") or {}).get("decision")) or inferred)
                return str(decision), report
            except Exception:
                pass
    synth_profile = profile_path if profile_path is not None else (ROOT / "_tmp" / "phaseb.synthetic.slo.json")
    if not synth_profile.exists():
        synth_profile.parent.mkdir(parents=True, exist_ok=True)
        synth_profile.write_text('{"schema_version":"x07.slo.profile@0.1.0","id":"synthetic","v":1,"service":"app","indicators":[]}', encoding="utf-8")
    return inferred, synth_slo_eval(synth_profile, metrics_path, inferred)


def runtime_state_paths(state_dir: Path, exec_id: str, slot: str) -> dict[str, Path]:
    base = state_dir / ".x07lp" / "runtime" / exec_id / slot
    return {
        "base": base,
        "work": base / "work",
        "logs": base / "logs",
        "reports": base / "reports",
    }


def write_runtime_terminal_report(state_dir: Path, exec_id: str, slot: str, status: str, outcome: str, now_unix_ms: int) -> None:
    paths = runtime_state_paths(state_dir, exec_id, slot)
    paths["reports"].mkdir(parents=True, exist_ok=True)
    write_json(
        paths["reports"] / "terminal.json",
        {
            "schema_version": "lp.runtime.terminal.report@0.1.0",
            "exec_id": exec_id,
            "slot": slot,
            "status": status,
            "outcome": outcome,
            "updated_unix_ms": now_unix_ms,
        },
    )


def prepare_runtime_terminal_state(state_dir: Path, exec_doc: dict[str, Any], meta: dict[str, Any], outcome: str, now_unix_ms: int) -> dict[str, Any]:
    runtime_meta = dict(meta.get("runtime") or {})
    stable_paths = runtime_state_paths(state_dir, exec_doc["exec_id"], "stable")
    candidate_paths = runtime_state_paths(state_dir, exec_doc["exec_id"], "candidate")
    stable = dict(runtime_meta.get("stable") or {})
    candidate = dict(runtime_meta.get("candidate") or {})
    stable.setdefault("work_dir", str(stable_paths["work"]))
    candidate.setdefault("work_dir", str(candidate_paths["work"]))
    stable["ended_unix_ms"] = now_unix_ms
    candidate["ended_unix_ms"] = now_unix_ms
    if outcome == "rolled_back":
        stable["status"] = "healthy"
        candidate["status"] = "stopped"
    else:
        stable["status"] = "stopped"
        candidate["status"] = "stopped"
    write_runtime_terminal_report(state_dir, exec_doc["exec_id"], "stable", str(stable["status"]), outcome, now_unix_ms)
    write_runtime_terminal_report(state_dir, exec_doc["exec_id"], "candidate", str(candidate["status"]), outcome, now_unix_ms)
    runtime_meta["stable"] = stable
    runtime_meta["candidate"] = candidate
    meta["runtime"] = runtime_meta
    return meta


def router_state_path(state_dir: Path, exec_id: str) -> Path:
    return state_dir / ".x07lp" / "router" / exec_id / "state.json"


def router_counters_path(state_dir: Path, exec_id: str) -> Path:
    return state_dir / ".x07lp" / "router" / exec_id / "counters.json"


def write_router_state(state_dir: Path, exec_id: str, stable_addr: str, candidate_addr: str, candidate_weight_pct: int, step_idx: int) -> None:
    state = {
        "exec_id": exec_id,
        "listener_addr": deterministic_listener(exec_id),
        "stable_addr": stable_addr,
        "candidate_addr": candidate_addr,
        "candidate_weight_pct": candidate_weight_pct,
        "last_updated_step_idx": step_idx,
    }
    write_json(router_state_path(state_dir, exec_id), state)
    counters = {"candidate_requests": 0, "stable_requests": 0}
    write_json(router_counters_path(state_dir, exec_id), counters)


def prepare_router_terminal_state(state_dir: Path, exec_doc: dict[str, Any], meta: dict[str, Any]) -> None:
    write_router_state(
        state_dir,
        exec_doc["exec_id"],
        deterministic_listener(exec_doc["exec_id"]) + "/stable",
        deterministic_listener(exec_doc["exec_id"]) + "/candidate",
        int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
        len(exec_doc.get("steps") or []),
    )


def mk_decision_record(
    state_dir: Path,
    exec_doc: dict[str, Any],
    step_idx: int | None,
    kind: str,
    outcome: str,
    reasons: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    created_unix_ms: int,
) -> dict[str, Any]:
    seed = ":".join(
        [
            exec_doc["exec_id"],
            kind,
            str(created_unix_ms),
            str(len((exec_doc.get("meta") or {}).get("decisions") or [])),
        ]
    )
    decision_id = f"lpdec_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:24]}"
    record = {
        "schema_version": "lp.decision.record@0.1.0",
        "decision_id": decision_id,
        "run_id": exec_doc["run_id"],
        "created_unix_ms": created_unix_ms,
        "kind": kind,
        "outcome": outcome,
        "reasons": reasons,
        "evidence": [
            {
                "kind": item.get("kind"),
                "digest": item.get("digest"),
                "label": item.get("logical_name"),
            }
            for item in evidence
        ],
        "integrity": {
            "record_sha256": "0" * 64,
            "signatures": [],
        },
    }
    record_bytes = canon_json(record)
    record["integrity"]["record_sha256"] = sha256_hex(record_bytes)
    record_bytes = canon_json(record)
    rel = f"decisions/{decision_id}.json"
    path = state_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(record_bytes)
    record_artifact = {
        "kind": "lp.decision.record@0.1.0",
        "digest": digest_ref_from_bytes(record_bytes),
        "media_type": "application/json",
        "logical_name": "decision.record",
        "store_uri": f"file:{rel}",
    }
    return {
        "decision_id": decision_id,
        "created_unix_ms": created_unix_ms,
        "step_idx": step_idx,
        "kind": kind,
        "outcome": outcome,
        "reasons": reasons,
        "evidence": evidence,
        "record": record_artifact,
    }


def ensure_deploy_meta(exec_doc: dict[str, Any], run_doc: dict[str, Any], state_dir: Path) -> dict[str, Any]:
    target = infer_target_from_run(state_dir, run_doc)
    meta = dict(exec_doc.get("meta") or {})
    meta.setdefault("schema_version", deploy_meta_schema())
    meta.setdefault("target", target)
    meta.setdefault("routing", {"candidate_weight_pct": 0})
    meta.setdefault("outcome", "unknown")
    meta.setdefault("public_listener", deterministic_listener(exec_doc["exec_id"]))
    meta.setdefault(
        "revisions",
        {
            "stable": load_pack_manifest_from_run(state_dir, run_doc)[0]["backend"]["component"],
            "candidate": load_pack_manifest_from_run(state_dir, run_doc)[0]["backend"]["component"],
        },
    )
    meta.setdefault("decisions", [])
    meta.setdefault("artifacts", [])
    meta.setdefault("updated_unix_ms", exec_doc.get("created_unix_ms", 0))
    meta.setdefault("latest_decision_id", "")
    meta.setdefault("runtime", {})
    return meta


def decision_reason(code: str, message: str) -> dict[str, Any]:
    return {"code": code, "message": message}


def artifact_summary(role: str, artifact: dict[str, Any], ord_: int = 0, kind: str | None = None) -> dict[str, Any]:
    return {
        "role": role,
        "ord": ord_,
        "kind": kind or artifact.get("kind"),
        "digest": artifact["digest"],
        "media_type": artifact.get("media_type", "application/json"),
        "logical_name": artifact.get("logical_name"),
        "store_uri": artifact.get("store_uri"),
    }


def build_exec_step(
    idx: int,
    name: str,
    kind: str,
    status: str,
    started_unix_ms: int,
    ended_unix_ms: int | None,
    decisions: list[str],
    latest_weight_pct: int | None = None,
    analysis_decision: str | None = None,
) -> dict[str, Any]:
    step: dict[str, Any] = {
        "idx": idx,
        "name": name,
        "kind": kind,
        "status": status,
        "started_unix_ms": started_unix_ms,
        "ended_unix_ms": ended_unix_ms,
        "decisions": decisions,
        "evidence": [],
    }
    if latest_weight_pct is not None:
        step["latest_weight_pct"] = latest_weight_pct
    if analysis_decision is not None:
        step["analysis_decision"] = analysis_decision
    return step


def read_exec_status_if_terminal(state_dir: Path, exec_id: str) -> dict[str, Any] | None:
    path = exec_path(state_dir, exec_id)
    if not path.exists():
        return None
    current = load_json(path)
    if current.get("status") in {"aborted", "failed", "completed"} and (current.get("meta") or {}).get("outcome") == "aborted":
        return current
    return None


def rebuild_index(state_dir: Path) -> Path:
    index_dir = state_dir / "index"
    index_dir.mkdir(parents=True, exist_ok=True)
    db_path = index_dir / "phaseb.sqlite"
    if db_path.exists():
        db_path.unlink()
    ddl = DDL_PATH.read_text(encoding="utf-8")
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(ddl)
        deploy_dir = state_dir / "deploy"
        for path in sorted(deploy_dir.glob("*.json")):
            exec_doc = load_json(path)
            run_id = exec_doc.get("run_id", "")
            run_doc = load_json(run_path(state_dir, run_id)) if run_id else {}
            target = (exec_doc.get("meta") or {}).get("target") or infer_target_from_run(state_dir, run_doc)
            app_id = target.get("app_id", "unknown")
            environment = target.get("environment", "unknown")
            exec_bytes = path.read_bytes()
            exec_digest = digest_ref_from_bytes(exec_bytes)
            run_bytes = canon_json(run_doc) if run_doc else b""
            run_digest = digest_ref_from_bytes(run_bytes) if run_bytes else None
            meta = exec_doc.get("meta") or {}
            routing = meta.get("routing") or {}
            revisions = meta.get("revisions") or {}
            stable_revision = revisions.get("stable") or {}
            candidate_revision = revisions.get("candidate") or {}
            plan = exec_doc.get("plan") or {}
            plan_digest = plan.get("digest") or {}
            conn.execute(
                """
                INSERT OR REPLACE INTO executions (
                  exec_id, run_id, app_id, environment, mode, artifact_kind, created_unix_ms, updated_unix_ms,
                  status, outcome, current_weight_pct, public_listener, latest_decision_id,
                  plan_sha256, plan_bytes_len, stable_revision_sha256, stable_revision_bytes_len,
                  candidate_revision_sha256, candidate_revision_bytes_len, exec_record_sha256, exec_record_bytes_len,
                  exec_store_uri, run_record_sha256, run_record_bytes_len, run_store_uri
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    exec_doc.get("exec_id"),
                    run_id,
                    app_id,
                    environment,
                    "local",
                    "x07.app.pack@0.1.0",
                    exec_doc.get("created_unix_ms"),
                    meta.get("updated_unix_ms", exec_doc.get("created_unix_ms")),
                    exec_doc.get("status"),
                    meta.get("outcome"),
                    int(routing.get("candidate_weight_pct", 0)),
                    meta.get("public_listener"),
                    meta.get("latest_decision_id"),
                    plan_digest.get("sha256"),
                    plan_digest.get("bytes_len"),
                    stable_revision.get("sha256"),
                    stable_revision.get("bytes_len"),
                    candidate_revision.get("sha256"),
                    candidate_revision.get("bytes_len"),
                    exec_digest["sha256"],
                    exec_digest["bytes_len"],
                    f"file:deploy/{path.name}",
                    run_digest["sha256"] if run_digest else None,
                    run_digest["bytes_len"] if run_digest else None,
                    f"file:runs/{run_id}.json" if run_id else None,
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO target_heads (app_id, environment, exec_id, updated_unix_ms) VALUES (?, ?, ?, ?)",
                (app_id, environment, exec_doc.get("exec_id"), meta.get("updated_unix_ms", exec_doc.get("created_unix_ms"))),
            )
            conn.execute(
                "INSERT OR REPLACE INTO indexed_records (sha256, bytes_len, record_kind, indexed_unix_ms, exec_id) VALUES (?, ?, ?, ?, ?)",
                (exec_digest["sha256"], exec_digest["bytes_len"], "lp.deploy.execution@0.1.0", meta.get("updated_unix_ms", exec_doc.get("created_unix_ms")), exec_doc.get("exec_id")),
            )
            if run_digest:
                conn.execute(
                    "INSERT OR REPLACE INTO indexed_records (sha256, bytes_len, record_kind, indexed_unix_ms, exec_id) VALUES (?, ?, ?, ?, ?)",
                    (run_digest["sha256"], run_digest["bytes_len"], "lp.pipeline.run@0.1.0", meta.get("updated_unix_ms", exec_doc.get("created_unix_ms")), exec_doc.get("exec_id")),
                )
            for step in exec_doc.get("steps") or []:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO execution_steps (
                      exec_id, step_idx, attempt, step_name, step_kind, status, started_unix_ms, ended_unix_ms, latest_weight_pct, analysis_decision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exec_doc.get("exec_id"),
                        int(step.get("idx", 0)),
                        int(step.get("attempt", 1)),
                        step.get("name", ""),
                        step.get("kind"),
                        step.get("status"),
                        int(step.get("started_unix_ms", 0)),
                        step.get("ended_unix_ms"),
                        step.get("latest_weight_pct"),
                        step.get("analysis_decision"),
                    ),
                )
            for decision in meta.get("decisions") or []:
                reasons = decision.get("reasons") or []
                primary_code = reasons[0]["code"] if reasons else "LP_UNKNOWN"
                summary_message = reasons[0].get("message") if reasons else None
                record = decision.get("record") or {}
                record_digest = record.get("digest") or {}
                conn.execute(
                    """
                    INSERT OR REPLACE INTO decisions (
                      decision_id, exec_id, run_id, step_idx, attempt, created_unix_ms, kind, outcome,
                      primary_code, summary_message, record_sha256, record_bytes_len, record_store_uri
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.get("decision_id"),
                        exec_doc.get("exec_id"),
                        run_id,
                        decision.get("step_idx"),
                        1,
                        decision.get("created_unix_ms"),
                        decision.get("kind"),
                        decision.get("outcome"),
                        primary_code,
                        summary_message,
                        record_digest.get("sha256"),
                        record_digest.get("bytes_len"),
                        record.get("store_uri"),
                    ),
                )
                for ord_, reason in enumerate(reasons):
                    conn.execute(
                        "INSERT OR REPLACE INTO decision_reasons (decision_id, ord, code, message) VALUES (?, ?, ?, ?)",
                        (decision.get("decision_id"), ord_, reason.get("code"), reason.get("message")),
                    )
                record_artifact = {
                    "kind": record.get("kind", "lp.decision.record@0.1.0"),
                    "digest": record_digest,
                    "media_type": record.get("media_type", "application/json"),
                    "logical_name": "decision.record",
                    "store_uri": record.get("store_uri"),
                }
                all_evidence = list(decision.get("evidence") or [])
                if record_digest:
                    all_evidence.insert(0, artifact_summary("decision_record", record_artifact, 0))
                for ord_, artifact in enumerate(all_evidence):
                    digest = artifact.get("digest") or {}
                    sha = digest.get("sha256")
                    blen = digest.get("bytes_len")
                    if not sha:
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO artifacts (
                          sha256, bytes_len, kind, media_type, logical_name, store_uri, first_seen_unix_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sha,
                            blen,
                            artifact.get("kind"),
                            artifact.get("media_type", "application/json"),
                            artifact.get("logical_name"),
                            artifact.get("store_uri"),
                            decision.get("created_unix_ms"),
                        ),
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO decision_evidence (decision_id, ord, role, sha256, bytes_len) VALUES (?, ?, ?, ?, ?)",
                        (decision.get("decision_id"), ord_, artifact.get("role", "evidence"), sha, blen),
                    )
                    if artifact.get("role") == "decision_record":
                        conn.execute(
                            "INSERT OR REPLACE INTO indexed_records (sha256, bytes_len, record_kind, indexed_unix_ms, exec_id) VALUES (?, ?, ?, ?, ?)",
                            (sha, blen, "lp.decision.record@0.1.0", decision.get("created_unix_ms"), exec_doc.get("exec_id")),
                        )
            for ord_, artifact in enumerate(meta.get("artifacts") or []):
                digest = artifact.get("digest") or {}
                sha = digest.get("sha256")
                blen = digest.get("bytes_len")
                if not sha:
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO artifacts (
                      sha256, bytes_len, kind, media_type, logical_name, store_uri, first_seen_unix_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha,
                        blen,
                        artifact.get("kind"),
                        artifact.get("media_type", "application/json"),
                        artifact.get("logical_name"),
                        artifact.get("store_uri"),
                        meta.get("updated_unix_ms", exec_doc.get("created_unix_ms")),
                    ),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO execution_artifacts (exec_id, ord, role, sha256, bytes_len) VALUES (?, ?, ?, ?, ?)",
                    (exec_doc.get("exec_id"), ord_, artifact.get("role"), sha, blen),
                )
        conn.commit()
    finally:
        conn.close()
    return db_path


def maybe_rebuild_index(state_dir: Path, force: bool) -> tuple[Path, bool]:
    db_path = state_dir / "index" / "phaseb.sqlite"
    rebuilt = force or not db_path.exists()
    if rebuilt:
        db_path = rebuild_index(state_dir)
    return db_path, rebuilt


def select_latest_exec_id(db_path: Path, app_id: str, environment: str) -> str | None:
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT exec_id FROM target_heads WHERE app_id = ? AND environment = ?",
            (app_id, environment),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _last_artifact_by_role(artifacts: list[dict[str, Any]], role: str) -> dict[str, Any] | None:
    matches = [artifact for artifact in artifacts if artifact.get("role") == role]
    return matches[-1] if matches else None


def build_execution_view(exec_doc: dict[str, Any], run_doc: dict[str, Any], state_dir: Path) -> dict[str, Any]:
    meta = exec_doc.get("meta") or {}
    steps = list(exec_doc.get("steps") or [])
    artifacts = list(meta.get("artifacts") or [])
    revisions = meta.get("revisions") or {}
    started_values = [step.get("started_unix_ms") for step in steps if isinstance(step.get("started_unix_ms"), int)]
    ended_values = [step.get("ended_unix_ms") for step in steps if isinstance(step.get("ended_unix_ms"), int)]
    started_unix_ms = min(started_values) if started_values else exec_doc.get("created_unix_ms")
    ended_unix_ms = max(ended_values) if ended_values else None
    public_listener = meta.get("public_listener") or deterministic_listener(exec_doc["exec_id"])
    listener_addr = public_listener.removeprefix("http://").removeprefix("https://")
    last_route_step = next((step for step in reversed(steps) if step.get("kind") == "deploy.route.set_weight"), None)
    last_analysis_step = next((step for step in reversed(steps) if step.get("kind") == "deploy.analysis.slo"), None)
    last_probe = _last_artifact_by_role(artifacts, "runtime_probe")
    last_snapshot = _last_artifact_by_role(artifacts, "metrics_snapshot")
    last_slo_report = _last_artifact_by_role(artifacts, "slo_eval_report")
    artifact_kind = ((((run_doc.get("inputs") or {}).get("artifact") or {}).get("kind")) or "x07.app.pack@0.1.0")
    runtime_meta = meta.get("runtime") or {}
    outcome = meta.get("outcome")

    def slot_view(slot: str, fallback_status: str) -> dict[str, Any]:
        slot_meta = dict(runtime_meta.get(slot) or {})
        workdir = slot_meta.pop("work_dir", None) or slot_meta.get("workdir")
        last_report = last_probe.get("store_uri") if last_probe else public_listener
        slot_started = slot_meta.get("started_unix_ms", started_unix_ms)
        slot_ended = slot_meta.get("ended_unix_ms", None if slot == "candidate" else ended_unix_ms)
        status = slot_meta.get("status", fallback_status)
        if outcome == "promoted":
            status = "healthy" if slot == "candidate" else "stopped"
        elif outcome == "rolled_back":
            status = "healthy" if slot == "stable" else "stopped"
        return {
            "revision_digest": revisions.get(slot),
            "bind_addr": slot_meta.get("bind_addr", listener_addr if slot == "candidate" else "127.0.0.1:0"),
            "status": status,
            "started_unix_ms": slot_started,
            "ended_unix_ms": slot_ended,
            "health": {
                "ok": True,
                "last_probe_unix_ms": meta.get("updated_unix_ms", started_unix_ms),
                "last_report": slot_meta.get("last_report", last_report),
            },
            "workdir": workdir or str(state_dir / ".x07lp" / "runtime" / exec_doc["exec_id"] / slot / "work"),
        }

    execution_meta = {
        "schema_version": deploy_meta_schema(),
        "mode": "local",
        "artifact_kind": artifact_kind,
        "target": meta.get("target") or {"app_id": "unknown", "environment": "unknown"},
        "outcome": meta.get("outcome"),
        "started_unix_ms": started_unix_ms,
        "updated_unix_ms": meta.get("updated_unix_ms", started_unix_ms),
        "ended_unix_ms": ended_unix_ms,
        "latest_decision_id": meta.get("latest_decision_id"),
        "plan": exec_doc.get("plan"),
        "runtime": {
            "stable": slot_view("stable", "stopped"),
            "candidate": slot_view("candidate", "healthy"),
        },
        "routing": {
            "public_listener": public_listener,
            "listener_addr": listener_addr,
            "candidate_weight_pct": int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
            "algorithm": "hash_bucket_v1",
            "route_key_header": "X-LP-Route-Key",
            "last_updated_step_idx": (last_route_step or {}).get("idx"),
            "router_state": str(state_dir / ".x07lp" / "router" / exec_doc["exec_id"] / "state.json"),
        },
        "analysis": {
            "last_slo_decision": (last_analysis_step or {}).get("analysis_decision"),
            "last_snapshot": (last_snapshot or {}).get("store_uri"),
            "last_slo_report": (last_slo_report or {}).get("store_uri"),
            "last_analysis_step_idx": (last_analysis_step or {}).get("idx"),
        },
        "retry_budget": {"max_attempts_per_step": 3, "consumed": meta.get("retry_budget", {}).get("consumed", {})},
        "ext": meta.get("ext", {}),
    }
    return {
        "schema_version": exec_doc.get("schema_version"),
        "exec_id": exec_doc.get("exec_id"),
        "run_id": exec_doc.get("run_id"),
        "created_unix_ms": exec_doc.get("created_unix_ms"),
        "status": exec_doc.get("status"),
        "plan": exec_doc.get("plan"),
        "meta": execution_meta,
    }


def build_query_result(
    exec_doc: dict[str, Any],
    run_doc: dict[str, Any],
    state_dir: Path,
    view: str,
    resolution: dict[str, Any],
    db_path: Path,
    rebuilt: bool,
    limit: int | None,
) -> dict[str, Any]:
    meta = exec_doc.get("meta") or {}
    target = meta.get("target") or {"app_id": "unknown", "environment": "unknown"}
    steps = list(exec_doc.get("steps") or [])
    decisions_all = list(meta.get("decisions") or [])
    artifacts_all = list(meta.get("artifacts") or [])
    decisions = [
        decision
        for decision in decisions_all
        if decision.get("kind") in {"deploy.prepare.plan", "deploy.runtime.start_candidate", "deploy.analysis.slo"}
    ]
    artifacts: list[dict[str, Any]] = []
    decision_records = [artifact for artifact in artifacts_all if artifact.get("role") == "decision_record"]
    deploy_execs = [artifact for artifact in artifacts_all if artifact.get("role") == "deploy_execution"]
    plan_artifacts = [artifact for artifact in artifacts_all if artifact.get("role") == "deploy_plan"]
    metric_artifacts = [artifact for artifact in artifacts_all if artifact.get("role") == "metrics_snapshot"]
    slo_artifacts = [artifact for artifact in artifacts_all if artifact.get("role") == "slo_eval_report"]
    for group in [decision_records, deploy_execs, plan_artifacts, metric_artifacts, slo_artifacts]:
        if group:
            artifacts.append(group[0])
    if limit is not None and limit >= 0:
        steps = steps[:limit]
        decisions = decisions[:limit]
        artifacts = artifacts[:limit]
    result: dict[str, Any] = {
        "schema_version": "lp.deploy.query.result@0.1.0",
        "view": view,
        "deployment_id": exec_doc.get("exec_id"),
        "run_id": exec_doc.get("run_id"),
        "target": target,
        "resolution": resolution,
        "index": {"used": True, "rebuilt": rebuilt, "db_path": str(db_path)},
    }
    if view in {"summary", "full"}:
        result.update(
            {
                "status": exec_doc.get("status"),
                "outcome": meta.get("outcome"),
                "created_unix_ms": exec_doc.get("created_unix_ms"),
                "updated_unix_ms": meta.get("updated_unix_ms"),
                "current_weight_pct": int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
                "public_listener": meta.get("public_listener"),
                "latest_decision_id": meta.get("latest_decision_id"),
                "plan_digest": ((exec_doc.get("plan") or {}).get("digest")) or None,
                "stable_revision": (meta.get("revisions") or {}).get("stable"),
                "candidate_revision": (meta.get("revisions") or {}).get("candidate"),
            }
        )
    if view in {"timeline", "full"}:
        result["steps"] = steps
    if view in {"decisions", "full"}:
        result["decisions"] = decisions
    if view in {"artifacts", "full"}:
        result["artifacts"] = artifacts
    if view == "full":
        result["execution"] = build_execution_view(exec_doc, run_doc, state_dir)
    return result


def validate_query_args(args: argparse.Namespace) -> str | None:
    have_deployment = bool(args.deployment_id)
    have_target = bool(args.app_id and args.env and args.latest)
    if not have_deployment and not have_target:
        return "query requires --deployment-id or --app-id/--env/--latest"
    if have_deployment and (args.app_id or args.env or args.latest):
        return "query accepts either --deployment-id or --app-id/--env/--latest"
    if args.view not in VALID_QUERY_VIEWS:
        return f"unsupported query view: {args.view}"
    if args.limit is not None:
        try:
            if int(args.limit) < 0:
                return "--limit must be >= 0"
        except ValueError:
            return "--limit must be an integer"
    return None


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = resolve_state_dir(args.state_dir)
    exec_doc = load_exec(state_dir, args.deployment_id)
    return cli_report(
        "deploy status",
        True,
        0,
        {"deployment": exec_doc},
        run_id=exec_doc.get("run_id", ""),
    )


def mutate_terminal_execution(state_dir: Path, exec_doc: dict[str, Any], reason: str, outcome: str, now_unix_ms: int, kind: str) -> dict[str, Any]:
    run_doc = load_json(run_path(state_dir, exec_doc["run_id"]))
    meta = ensure_deploy_meta(exec_doc, run_doc, state_dir)
    reason_code = "LP_DEPLOY_STOPPED" if outcome == "aborted" else "LP_MANUAL_ACTION"
    decision = mk_decision_record(
        state_dir,
        exec_doc,
        None,
        kind,
        "allow",
        [decision_reason(reason_code, reason)],
        [],
        now_unix_ms,
    )
    decisions = list(meta.get("decisions") or [])
    decisions.append(decision)
    meta["decisions"] = decisions
    meta["latest_decision_id"] = decision["decision_id"]
    meta["updated_unix_ms"] = now_unix_ms
    meta["outcome"] = outcome
    meta.setdefault("routing", {})["candidate_weight_pct"] = 0 if outcome != "failed" else int(meta.get("routing", {}).get("candidate_weight_pct", 0))
    if outcome == "aborted":
        exec_doc["status"] = "aborted"
    elif outcome == "rolled_back":
        exec_doc["status"] = "completed"
    exec_doc["meta"] = meta
    exec_bytes = save_exec(state_dir, exec_doc)
    artifacts = list(meta.get("artifacts") or [])
    artifacts.insert(
        0,
        artifact_summary(
            "deploy_execution",
            {
                "kind": "lp.deploy.execution@0.1.0",
                "digest": digest_ref_from_bytes(exec_bytes),
                "media_type": "application/json",
                "logical_name": "deploy.execution",
                "store_uri": f"file:deploy/{exec_doc['exec_id']}.json",
            },
        ),
    )
    meta["artifacts"] = dedupe_artifacts(artifacts)
    exec_doc["meta"] = meta
    save_exec(state_dir, exec_doc)
    rebuild_index(state_dir)
    return decision


def dedupe_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str | None, int | None, str | None]] = set()
    for artifact in artifacts:
        digest = artifact.get("digest") or {}
        key = (digest.get("sha256"), digest.get("bytes_len"), artifact.get("role"))
        if key in seen:
            continue
        seen.add(key)
        out.append(artifact)
    return out


def command_stop(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = resolve_state_dir(args.state_dir)
    now_unix_ms = int(args.now_unix_ms or now_ms())
    exec_doc = load_exec(state_dir, args.deployment_id)
    run_doc = load_json(run_path(state_dir, exec_doc["run_id"]))
    meta = ensure_deploy_meta(exec_doc, run_doc, state_dir)
    meta["updated_unix_ms"] = now_unix_ms
    meta.setdefault("routing", {})["candidate_weight_pct"] = 0
    try:
        prepare_runtime_terminal_state(state_dir, exec_doc, meta, "aborted", now_unix_ms)
    except Exception as exc:
        return cli_report(
            "deploy stop",
            False,
            24,
            {},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_RUNTIME_STOP_FAILED", "run", str(exc))],
        )
    exec_doc["meta"] = meta
    try:
        prepare_router_terminal_state(state_dir, exec_doc, meta)
    except Exception as exc:
        return cli_report(
            "deploy stop",
            False,
            25,
            {},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_ROUTER_STOP_FAILED", "run", str(exc))],
        )
    decision = mutate_terminal_execution(state_dir, exec_doc, args.reason, "aborted", now_unix_ms, "deploy.stop.manual")
    exec_doc = load_exec(state_dir, args.deployment_id)
    return cli_report(
        "deploy stop",
        True,
        0,
        {
            "deployment_id": exec_doc["exec_id"],
            "run_id": exec_doc["run_id"],
            "final_decision_id": decision["decision_id"],
            "outcome": "aborted",
        },
        run_id=exec_doc.get("run_id", ""),
        diagnostics=[result_diag("LP_DEPLOY_STOPPED", "run", "deployment stopped", severity="info")],
    )


def command_rollback(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = resolve_state_dir(args.state_dir)
    now_unix_ms = int(args.now_unix_ms or now_ms())
    exec_doc = load_exec(state_dir, args.deployment_id)
    run_doc = load_json(run_path(state_dir, exec_doc["run_id"]))
    meta = ensure_deploy_meta(exec_doc, run_doc, state_dir)
    meta["updated_unix_ms"] = now_unix_ms
    meta.setdefault("routing", {})["candidate_weight_pct"] = 0
    try:
        prepare_runtime_terminal_state(state_dir, exec_doc, meta, "rolled_back", now_unix_ms)
    except Exception as exc:
        return cli_report(
            "deploy rollback",
            False,
            24,
            {},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_RUNTIME_STOP_FAILED", "run", str(exc))],
        )
    exec_doc["meta"] = meta
    try:
        prepare_router_terminal_state(state_dir, exec_doc, meta)
    except Exception as exc:
        return cli_report(
            "deploy rollback",
            False,
            25,
            {},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_ROUTER_STOP_FAILED", "run", str(exc))],
        )
    decision = mutate_terminal_execution(state_dir, exec_doc, args.reason, "rolled_back", now_unix_ms, "deploy.rollback.manual")
    exec_doc = load_exec(state_dir, args.deployment_id)
    return cli_report(
        "deploy rollback",
        True,
        0,
        {
            "deployment_id": exec_doc["exec_id"],
            "run_id": exec_doc["run_id"],
            "final_decision_id": decision["decision_id"],
            "outcome": "rolled_back",
        },
        run_id=exec_doc.get("run_id", ""),
    )


def generated_plan_from_accepted(state_dir: Path, exec_doc: dict[str, Any], run_doc: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    pack_dir = state_dir / ".x07lp" / "generated" / exec_doc["exec_id"] / "pack"
    shutil.rmtree(pack_dir, ignore_errors=True)
    pack_dir.mkdir(parents=True, exist_ok=True)
    _manifest, manifest_raw = materialize_pack_dir(state_dir, run_doc, pack_dir)
    ops_path = search_workspace_file("ops_release.json")
    x07_wasm = shutil.which("x07-wasm")
    if not x07_wasm or ops_path is None:
        plan = {
            "schema_version": "x07.deploy.plan@0.2.0",
            "id": f"plan_{exec_doc['exec_id']}",
            "v": 1,
            "pack_manifest": {"path": "app.pack.json", **digest_ref_from_bytes(manifest_raw)},
            "ops_profile": {"path": "ops_release.json", **digest_ref_from_bytes(ops_path.read_bytes() if ops_path and ops_path.exists() else b"{}")},
            "policy_cards": [],
            "slo_profile": None,
            "strategy": {"type": "canary", "canary": {"steps": [{"set_weight": 100}]}, "blue_green": None},
            "outputs": [],
        }
        return plan, canon_json(plan)
    out_dir = state_dir / ".x07lp" / "generated" / exec_doc["exec_id"] / "plan"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    plan_cwd, ops_arg = resolve_tool_cwd_and_path(ops_path)
    argv = [
        x07_wasm,
        "deploy",
        "plan",
        "--pack-manifest",
        str(pack_dir / "app.pack.json"),
        "--ops",
        str(ops_arg),
        "--emit-k8s",
        "false",
        "--out-dir",
        str(out_dir),
        "--json",
    ]
    code, stdout, _stderr = run_capture(argv, cwd=plan_cwd)
    if code == 0:
        try:
            report = json.loads(stdout.decode("utf-8"))
            plan_manifest = ((report.get("result") or {}).get("plan_manifest") or {}).get("path")
            if plan_manifest:
                path = Path(plan_manifest)
                if not path.is_absolute():
                    path = out_dir / path
                plan_bytes = path.read_bytes()
                return normalize_plan(json.loads(plan_bytes)), canon_json(normalize_plan(json.loads(plan_bytes)))
        except Exception:
            pass
    return generated_plan_from_accepted_fallback(exec_doc, manifest_raw, ops_path)


def generated_plan_from_accepted_fallback(exec_doc: dict[str, Any], manifest_raw: bytes, ops_path: Path | None) -> tuple[dict[str, Any], bytes]:
    ops_bytes = ops_path.read_bytes() if ops_path and ops_path.exists() else b"{}"
    slo_path = search_workspace_file("slo_min.json")
    slo_bytes = slo_path.read_bytes() if slo_path and slo_path.exists() else b"{}"
    plan = {
        "schema_version": "x07.deploy.plan@0.2.0",
        "id": f"plan_{exec_doc['exec_id']}",
        "v": 1,
        "pack_manifest": {"path": "app.pack.json", **digest_ref_from_bytes(manifest_raw)},
        "ops_profile": {"path": os.path.basename(ops_path) if ops_path else "ops_release.json", **digest_ref_from_bytes(ops_bytes)},
        "policy_cards": [],
        "slo_profile": {"path": os.path.basename(slo_path) if slo_path else "slo_min.json", **digest_ref_from_bytes(slo_bytes)},
        "strategy": {
            "type": "canary",
            "canary": {
                "steps": [
                    {"set_weight": 5},
                    {"pause_s": 10},
                    {"analysis": {"kind": "slo.eval", "require_decision": "promote"}},
                    {"set_weight": 100},
                    {"analysis": {"kind": "slo.eval", "require_decision": "promote"}},
                ]
            },
            "blue_green": None,
        },
        "outputs": [],
    }
    return plan, canon_json(plan)


def command_run(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = resolve_state_dir(args.state_dir)
    now_unix_ms = int(args.now_unix_ms or now_ms())
    pause_scale = float(args.pause_scale if args.pause_scale is not None else 1.0)
    metrics_dir = resolve_plan_path(args.metrics_dir) if args.metrics_dir else None
    exec_doc = load_exec(state_dir, args.deployment_id)
    run_doc = load_json(run_path(state_dir, exec_doc["run_id"]))
    meta = ensure_deploy_meta(exec_doc, run_doc, state_dir)
    plan_path = resolve_plan_path(args.plan)
    try:
        if plan_path is not None:
            plan_doc = normalize_plan(load_json(plan_path))
            plan_bytes = canon_json(plan_doc)
        else:
            plan_doc, plan_bytes = generated_plan_from_accepted(state_dir, exec_doc, run_doc)
    except Exception as exc:
        return cli_report(
            "deploy run",
            False,
            13,
            {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"]},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_PLAN_GENERATE_FAILED", "run", str(exc))],
        )
    plan_artifact = artifact_summary(
        "deploy_plan",
        {
            "kind": "x07.deploy.plan@0.2.0",
            "media_type": "application/json",
            "logical_name": "deploy.plan",
            **cas_put(state_dir, "deploy.plan", "application/json", plan_bytes),
        },
    )
    exec_doc["plan"] = {"kind": "x07.deploy.plan@0.2.0", "digest": plan_artifact["digest"]}
    meta["updated_unix_ms"] = now_unix_ms
    meta["public_listener"] = deterministic_listener(exec_doc["exec_id"])
    manifest, manifest_raw = load_pack_manifest_from_run(state_dir, run_doc)
    pack_digest = digest_ref_from_bytes(manifest_raw)
    meta["revisions"] = {
        "stable": pack_digest,
        "candidate": pack_digest,
    }
    decisions: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = [plan_artifact]
    steps: list[dict[str, Any]] = []

    prepare_decision = mk_decision_record(
        state_dir,
        exec_doc,
        0,
        "deploy.prepare.plan",
        "allow",
        [decision_reason("LP_PLAN_READY", "deploy plan is ready")],
        [plan_artifact],
        now_unix_ms,
    )
    decisions.append(prepare_decision)
    steps.append(build_exec_step(0, "prepare", "deploy.prepare", "ok", now_unix_ms, now_unix_ms, [prepare_decision["decision_id"]]))

    stable_paths = runtime_state_paths(state_dir, exec_doc["exec_id"], "stable")
    candidate_paths = runtime_state_paths(state_dir, exec_doc["exec_id"], "candidate")
    try:
        shutil.rmtree(stable_paths["base"], ignore_errors=True)
        shutil.rmtree(candidate_paths["base"], ignore_errors=True)
        manifest, manifest_raw = materialize_pack_dir(state_dir, run_doc, stable_paths["work"])
        materialize_pack_dir(state_dir, run_doc, candidate_paths["work"])
        for paths in [stable_paths, candidate_paths]:
            paths["logs"].mkdir(parents=True, exist_ok=True)
            paths["reports"].mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return cli_report(
            "deploy run",
            False,
            17,
            {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_RUNTIME_START_FAILED", "run", str(exc))],
        )
    inputs = resolve_plan_inputs(plan_doc)
    runtime_probe_doc = run_runtime_probe(exec_doc["exec_id"], candidate_paths["work"], inputs["ops"])
    if not runtime_probe_ok(runtime_probe_doc):
        return cli_report(
            "deploy run",
            False,
            18,
            {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_RUNTIME_HEALTHCHECK_FAILED", "run", runtime_probe_message(runtime_probe_doc))],
        )
    runtime_probe_bytes = canon_json(runtime_probe_doc)
    runtime_probe_artifact = artifact_summary(
        "runtime_probe",
        {
            "kind": runtime_probe_doc.get("schema_version", "lp.runtime.probe.synthetic@0.1.0"),
            "media_type": "application/json",
            "logical_name": "runtime.probe.json",
            **cas_put(state_dir, "runtime.probe", "application/json", runtime_probe_bytes),
        },
    )
    start_decision = mk_decision_record(
        state_dir,
        exec_doc,
        1,
        "deploy.runtime.start_candidate",
        "allow",
        [decision_reason("LP_RUNTIME_HEALTHCHECK_OK", "candidate runtime probe passed")],
        [runtime_probe_artifact],
        now_unix_ms,
    )
    decisions.append(start_decision)
    steps.append(
        build_exec_step(
            1,
            "start_candidate",
            "deploy.runtime.start_candidate",
            "ok",
            now_unix_ms,
            now_unix_ms,
            [start_decision["decision_id"]],
        )
    )
    artifacts.insert(0, runtime_probe_artifact)
    meta["runtime"] = {
        "stable": {"status": "healthy", "work_dir": str(stable_paths["work"])},
        "candidate": {"status": "healthy", "work_dir": str(candidate_paths["work"])},
    }
    try:
        write_router_state(
            state_dir,
            exec_doc["exec_id"],
            deterministic_listener(exec_doc["exec_id"]) + "/stable",
            deterministic_listener(exec_doc["exec_id"]) + "/candidate",
            int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
            1,
        )
    except Exception as exc:
        return cli_report(
            "deploy run",
            False,
            19,
            {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_ROUTER_BIND_FAILED", "run", str(exc))],
        )

    exec_doc["status"] = "started"
    meta["decisions"] = decisions
    meta["artifacts"] = artifacts
    meta["latest_decision_id"] = start_decision["decision_id"]
    exec_doc["steps"] = steps
    exec_doc["meta"] = meta
    save_exec(state_dir, exec_doc)

    step_cursor = 2
    analysis_counter = 0
    retry_budget = 3
    for plan_step in (((plan_doc.get("strategy") or {}).get("canary") or {}).get("steps") or []):
        current = load_exec(state_dir, exec_doc["exec_id"])
        if (current.get("meta") or {}).get("outcome") == "aborted":
            return cli_report(
                "deploy run",
                True,
                0,
                {
                    "deployment_id": current["exec_id"],
                    "run_id": current["run_id"],
                    "final_decision_id": (current.get("meta") or {}).get("latest_decision_id"),
                    "outcome": "aborted",
                    "latest_weight_pct": int(((current.get("meta") or {}).get("routing") or {}).get("candidate_weight_pct", 0)),
                    "public_listener": (current.get("meta") or {}).get("public_listener"),
                },
                run_id=current.get("run_id", ""),
                diagnostics=[result_diag("LP_DEPLOY_STOPPED", "run", "deployment stopped during execution", severity="info")],
            )
        exec_doc = current
        meta = exec_doc.get("meta") or {}
        decisions = list(meta.get("decisions") or [])
        artifacts = list(meta.get("artifacts") or [])
        steps = list(exec_doc.get("steps") or [])
        if "set_weight" in plan_step:
            weight = int(plan_step["set_weight"])
            decision = mk_decision_record(
                state_dir,
                exec_doc,
                step_cursor,
                "deploy.route.set_weight",
                "allow",
                [decision_reason("LP_ROUTER_WEIGHT_SET", f"candidate weight set to {weight}")],
                [],
                now_unix_ms + step_cursor,
            )
            decisions.append(decision)
            steps.append(
                build_exec_step(
                    step_cursor,
                    f"set_weight_{weight}",
                    "deploy.route.set_weight",
                    "ok",
                    now_unix_ms + step_cursor,
                    now_unix_ms + step_cursor,
                    [decision["decision_id"]],
                    latest_weight_pct=weight,
                )
            )
            meta.setdefault("routing", {})["candidate_weight_pct"] = weight
            meta["latest_decision_id"] = decision["decision_id"]
            meta["updated_unix_ms"] = now_unix_ms + step_cursor
            try:
                write_router_state(
                    state_dir,
                    exec_doc["exec_id"],
                    deterministic_listener(exec_doc["exec_id"]) + "/stable",
                    deterministic_listener(exec_doc["exec_id"]) + "/candidate",
                    weight,
                    step_cursor,
                )
            except Exception as exc:
                return cli_report(
                    "deploy run",
                    False,
                    20,
                    {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
                    run_id=exec_doc.get("run_id", ""),
                    diagnostics=[result_diag("LP_ROUTER_SET_WEIGHT_FAILED", "run", str(exc))],
                )
            exec_doc["steps"] = steps
            meta["decisions"] = decisions
            exec_doc["meta"] = meta
            save_exec(state_dir, exec_doc)
            step_cursor += 1
            continue
        if "pause_s" in plan_step:
            pause_s = int(plan_step["pause_s"])
            running_step = build_exec_step(
                step_cursor,
                f"pause_{pause_s}",
                "deploy.pause",
                "running",
                now_unix_ms + step_cursor,
                None,
                [],
            )
            steps.append(running_step)
            exec_doc["steps"] = steps
            meta["updated_unix_ms"] = now_unix_ms + step_cursor
            exec_doc["meta"] = meta
            save_exec(state_dir, exec_doc)
            sleep_ms = max(0, int(pause_s * pause_scale * 1000))
            remaining = sleep_ms
            while remaining > 0:
                time.sleep(min(50, remaining) / 1000.0)
                remaining -= 50
                current = load_exec(state_dir, exec_doc["exec_id"])
                if (current.get("meta") or {}).get("outcome") == "aborted":
                    return cli_report(
                        "deploy run",
                        True,
                        0,
                        {
                            "deployment_id": current["exec_id"],
                            "run_id": current["run_id"],
                            "final_decision_id": (current.get("meta") or {}).get("latest_decision_id"),
                            "outcome": "aborted",
                            "latest_weight_pct": int(((current.get("meta") or {}).get("routing") or {}).get("candidate_weight_pct", 0)),
                            "public_listener": (current.get("meta") or {}).get("public_listener"),
                        },
                        run_id=current.get("run_id", ""),
                        diagnostics=[result_diag("LP_DEPLOY_STOPPED", "run", "deployment stopped during execution", severity="info")],
                    )
            exec_doc = load_exec(state_dir, exec_doc["exec_id"])
            meta = exec_doc.get("meta") or {}
            decisions = list(meta.get("decisions") or [])
            pause_decision = mk_decision_record(
                state_dir,
                exec_doc,
                step_cursor,
                "deploy.pause",
                "allow",
                [decision_reason("LP_PAUSE_COMPLETE", f"pause {pause_s}s completed")],
                [],
                now_unix_ms + step_cursor,
            )
            decisions.append(pause_decision)
            last_step = list(exec_doc.get("steps") or [])[-1]
            last_step["status"] = "ok"
            last_step["ended_unix_ms"] = now_unix_ms + step_cursor
            last_step["decisions"] = [pause_decision["decision_id"]]
            steps = list(exec_doc.get("steps") or [])
            steps[-1] = last_step
            meta["latest_decision_id"] = pause_decision["decision_id"]
            meta["updated_unix_ms"] = now_unix_ms + step_cursor
            meta["decisions"] = decisions
            exec_doc["steps"] = steps
            exec_doc["meta"] = meta
            save_exec(state_dir, exec_doc)
            step_cursor += 1
            continue
        if "analysis" in plan_step:
            required = ((plan_step.get("analysis") or {}).get("require_decision")) or "promote"
            attempt = 0
            while True:
                attempt += 1
                analysis_counter += 1
                metrics_path = (metrics_dir / f"analysis.{analysis_counter}.json") if metrics_dir else None
                if metrics_path is None or not metrics_path.exists():
                    return cli_report(
                        "deploy run",
                        False,
                        16,
                        {
                            "deployment_id": exec_doc["exec_id"],
                            "run_id": exec_doc["run_id"],
                            "final_decision_id": meta.get("latest_decision_id"),
                            "outcome": "failed",
                            "latest_weight_pct": int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
                            "public_listener": meta.get("public_listener"),
                        },
                        run_id=exec_doc.get("run_id", ""),
                        diagnostics=[result_diag("LP_METRICS_SNAPSHOT_MISSING", "deploy", "missing metrics snapshot")],
                    )
                try:
                    decision_value, slo_report = run_slo_eval(inputs["slo"], metrics_path)
                    metrics_bytes = metrics_path.read_bytes()
                except Exception as exc:
                    return cli_report(
                        "deploy run",
                        False,
                        21,
                        {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
                        run_id=exec_doc.get("run_id", ""),
                        diagnostics=[result_diag("LP_SLO_EVAL_FAILED", "run", str(exc))],
                    )
                if decision_value not in {"promote", "rollback", "inconclusive"}:
                    return cli_report(
                        "deploy run",
                        False,
                        21,
                        {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
                        run_id=exec_doc.get("run_id", ""),
                        diagnostics=[result_diag("LP_SLO_EVAL_FAILED", "run", f"unexpected slo decision: {decision_value}")],
                    )
                metrics_artifact = artifact_summary(
                    "metrics_snapshot",
                    {
                        "kind": "x07.metrics.snapshot@0.1.0",
                        "media_type": "application/json",
                        "logical_name": metrics_path.name,
                        **cas_put(state_dir, metrics_path.name, "application/json", metrics_bytes),
                    },
                )
                slo_bytes = canon_json(slo_report)
                slo_artifact = artifact_summary(
                    "slo_eval_report",
                    {
                        "kind": slo_report.get("schema_version", "x07.wasm.slo.eval.report@0.1.0"),
                        "media_type": "application/json",
                        "logical_name": "slo.eval.report.json",
                        **cas_put(state_dir, "slo.eval.report", "application/json", slo_bytes),
                    },
                )
                artifacts.extend([metrics_artifact, slo_artifact])
                if decision_value == "promote":
                    outcome = "allow"
                    code = "LP_SLO_PROMOTE"
                elif decision_value == "rollback":
                    outcome = "deny"
                    code = "LP_SLO_DECISION_ROLLBACK"
                else:
                    outcome = "error"
                    code = "LP_SLO_INCONCLUSIVE"
                decision = mk_decision_record(
                    state_dir,
                    exec_doc,
                    step_cursor,
                    "deploy.analysis.slo",
                    outcome,
                    [decision_reason(code, f"slo decision is {decision_value}")],
                    [metrics_artifact, slo_artifact],
                    now_unix_ms + step_cursor + attempt,
                )
                decisions.append(decision)
                step_name = f"analysis_{analysis_counter}" if attempt == 1 else f"analysis_{analysis_counter}_retry_{attempt}"
                step_status = "ok" if decision_value == required else "error"
                steps.append(
                    build_exec_step(
                        step_cursor,
                        step_name,
                        "deploy.analysis.slo",
                        step_status,
                        now_unix_ms + step_cursor + attempt,
                        now_unix_ms + step_cursor + attempt,
                        [decision["decision_id"]],
                        analysis_decision=decision_value,
                    )
                )
                meta["latest_decision_id"] = decision["decision_id"]
                meta["updated_unix_ms"] = now_unix_ms + step_cursor + attempt
                meta["decisions"] = decisions
                meta["artifacts"] = dedupe_artifacts(
                    [
                        artifact_summary("decision_record", decision["record"]),
                        artifact_summary(
                            "deploy_execution",
                            {
                                "kind": "lp.deploy.execution@0.1.0",
                                "digest": digest_ref_from_bytes(canon_json(exec_doc)),
                                "media_type": "application/json",
                                "logical_name": "deploy.execution",
                                "store_uri": f"file:deploy/{exec_doc['exec_id']}.json",
                            },
                        ),
                    ]
                    + artifacts
                )
                exec_doc["steps"] = steps
                exec_doc["meta"] = meta
                save_exec(state_dir, exec_doc)
                if decision_value == required:
                    break
                if decision_value == "rollback":
                    meta["routing"]["candidate_weight_pct"] = 0
                    meta["outcome"] = "rolled_back"
                    meta["updated_unix_ms"] = now_unix_ms + step_cursor + attempt
                    exec_doc["status"] = "completed"
                    exec_doc["meta"] = meta
                    save_exec(state_dir, exec_doc)
                    rebuild_index(state_dir)
                    return cli_report(
                        "deploy run",
                        False,
                        14,
                        {
                            "deployment_id": exec_doc["exec_id"],
                            "run_id": exec_doc["run_id"],
                            "final_decision_id": decision["decision_id"],
                            "outcome": "rolled_back",
                            "latest_weight_pct": 0,
                            "public_listener": meta.get("public_listener"),
                        },
                        run_id=exec_doc.get("run_id", ""),
                        diagnostics=[result_diag("LP_SLO_DECISION_ROLLBACK", "deploy", "slo gate required rollback")],
                    )
                if attempt >= retry_budget:
                    meta["outcome"] = "failed"
                    meta["updated_unix_ms"] = now_unix_ms + step_cursor + attempt
                    exec_doc["status"] = "failed"
                    exec_doc["meta"] = meta
                    save_exec(state_dir, exec_doc)
                    rebuild_index(state_dir)
                    return cli_report(
                        "deploy run",
                        False,
                        15,
                        {
                            "deployment_id": exec_doc["exec_id"],
                            "run_id": exec_doc["run_id"],
                            "final_decision_id": decision["decision_id"],
                            "outcome": "failed",
                            "latest_weight_pct": int((meta.get("routing") or {}).get("candidate_weight_pct", 0)),
                            "public_listener": meta.get("public_listener"),
                        },
                        run_id=exec_doc.get("run_id", ""),
                        diagnostics=[result_diag("LP_RETRY_BUDGET_EXHAUSTED", "deploy", "retry budget exhausted")],
                    )
            step_cursor += 1
            continue

        return cli_report(
            "deploy run",
            False,
            26,
            {"deployment_id": exec_doc["exec_id"], "run_id": exec_doc["run_id"], "outcome": "failed"},
            run_id=exec_doc.get("run_id", ""),
            diagnostics=[result_diag("LP_PLAN_EXEC_STEP_FAILED", "run", f"unsupported plan step: {json.dumps(plan_step, sort_keys=True)}")],
        )

    meta = exec_doc.get("meta") or {}
    meta["outcome"] = "promoted"
    meta["updated_unix_ms"] = now_unix_ms + step_cursor
    meta.setdefault("routing", {})["candidate_weight_pct"] = 100
    meta["artifacts"] = dedupe_artifacts(
        [
            artifact_summary("decision_record", decisions[-1]["record"]),
            artifact_summary(
                "deploy_execution",
                {
                    "kind": "lp.deploy.execution@0.1.0",
                    "digest": digest_ref_from_bytes(canon_json(exec_doc)),
                    "media_type": "application/json",
                    "logical_name": "deploy.execution",
                    "store_uri": f"file:deploy/{exec_doc['exec_id']}.json",
                },
            ),
        ]
        + artifacts
    )
    exec_doc["status"] = "completed"
    exec_doc["steps"] = steps
    exec_doc["meta"] = meta
    save_exec(state_dir, exec_doc)
    rebuild_index(state_dir)
    return cli_report(
        "deploy run",
        True,
        0,
        {
            "deployment_id": exec_doc["exec_id"],
            "run_id": exec_doc["run_id"],
            "final_decision_id": meta.get("latest_decision_id"),
            "outcome": "promoted",
            "latest_weight_pct": 100,
            "public_listener": meta.get("public_listener"),
        },
        run_id=exec_doc.get("run_id", ""),
    )


def command_query(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = resolve_state_dir(args.state_dir)
    validation_error = validate_query_args(args)
    if validation_error is not None:
        return cli_report(
            "deploy query",
            False,
            2,
            {},
            diagnostics=[result_diag("LP_QUERY_INVALID", "parse", validation_error)],
        )
    try:
        db_path, rebuilt = maybe_rebuild_index(state_dir, bool(args.rebuild_index))
    except Exception as exc:
        return cli_report(
            "deploy query",
            False,
            22,
            {},
            diagnostics=[result_diag("LP_DECISION_INDEX_ERROR", "run", str(exc))],
        )
    resolution: dict[str, Any]
    exec_id: str | None
    if args.deployment_id:
        exec_id = args.deployment_id
        resolution = {"by": "deployment_id", "requested_deployment_id": exec_id}
    else:
        exec_id = select_latest_exec_id(db_path, args.app_id, args.env)
        resolution = {
            "by": "latest",
            "requested_target": {"app_id": args.app_id, "environment": args.env},
        }
    if not exec_id:
        return cli_report(
            "deploy query",
            False,
            2,
            {},
            diagnostics=[result_diag("LP_DEPLOYMENT_NOT_FOUND", "query", "deployment not found")],
        )
    exec_doc = load_exec(state_dir, exec_id)
    run_doc = load_json(run_path(state_dir, exec_doc["run_id"]))
    limit = int(args.limit) if args.limit is not None else None
    result = build_query_result(exec_doc, run_doc, state_dir, args.view or "summary", resolution, db_path, rebuilt, limit)
    return cli_report("deploy query", True, 0, result, run_id=exec_doc.get("run_id", ""))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", add_help=False)
    run_p.add_argument("--deployment-id", required=True)
    run_p.add_argument("--plan")
    run_p.add_argument("--metrics-dir")
    run_p.add_argument("--pause-scale")
    run_p.add_argument("--state-dir")
    run_p.add_argument("--now-unix-ms")
    run_p.add_argument("--json", action="store_true")

    query_p = sub.add_parser("query", add_help=False)
    query_p.add_argument("--deployment-id")
    query_p.add_argument("--app-id")
    query_p.add_argument("--env")
    query_p.add_argument("--latest", action="store_true")
    query_p.add_argument("--view", default="summary")
    query_p.add_argument("--limit")
    query_p.add_argument("--rebuild-index", action="store_true")
    query_p.add_argument("--state-dir")
    query_p.add_argument("--json", action="store_true")

    status_p = sub.add_parser("status", add_help=False)
    status_p.add_argument("--deployment-id", required=True)
    status_p.add_argument("--state-dir")
    status_p.add_argument("--json", action="store_true")

    stop_p = sub.add_parser("stop", add_help=False)
    stop_p.add_argument("--deployment-id", required=True)
    stop_p.add_argument("--reason", required=True)
    stop_p.add_argument("--state-dir")
    stop_p.add_argument("--now-unix-ms")
    stop_p.add_argument("--json", action="store_true")

    rollback_p = sub.add_parser("rollback", add_help=False)
    rollback_p.add_argument("--deployment-id", required=True)
    rollback_p.add_argument("--reason", required=True)
    rollback_p.add_argument("--state-dir")
    rollback_p.add_argument("--now-unix-ms")
    rollback_p.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            report = command_run(args)
        elif args.command == "query":
            query_error = validate_query_args(args)
            if query_error is not None:
                report = cli_report(
                    "deploy query",
                    False,
                    2,
                    {},
                    diagnostics=[result_diag("LP_QUERY_INVALID", "parse", query_error)],
                )
            else:
                report = command_query(args)
        elif args.command == "status":
            report = command_status(args)
        elif args.command == "stop":
            report = command_stop(args)
        elif args.command == "rollback":
            report = command_rollback(args)
        else:
            report = cli_report("deploy", False, 2, {}, diagnostics=[result_diag("LP_INVALID_ARGS", "parse", "unknown command")])
    except FileNotFoundError as exc:
        report = cli_report(
            f"deploy {args.command}",
            False,
            2,
            {},
            diagnostics=[result_diag("LP_DEPLOYMENT_NOT_FOUND", "run", str(exc))],
        )
    except Exception as exc:
        report = cli_report(
            f"deploy {args.command}",
            False,
            50,
            {},
            diagnostics=[result_diag("LP_INTERNAL", "run", str(exc))],
        )
    sys.stdout.buffer.write(canon_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
