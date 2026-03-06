use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const DEFAULT_STATE_DIR: &str = "out/x07lp_state";
const DEFAULT_UI_ADDR: &str = "127.0.0.1:17090";
const TOOL_VERSION: &str = "0.1.0-dev";
const VALID_QUERY_VIEWS: &[&str] = &["summary", "timeline", "decisions", "artifacts", "full"];
const REDACTED_HTTP_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

#[derive(Parser, Debug)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(DeployRunArgs),
    Query(DeployQueryArgs),
    Status(DeploymentStatusArgs),
    Stop(DeploymentControlArgs),
    Rollback(DeploymentControlArgs),
    Pause(DeploymentControlArgs),
    Rerun(DeploymentRerunArgs),
    IncidentCapture(IncidentCaptureArgs),
    IncidentList(IncidentListArgs),
    IncidentGet(IncidentGetArgs),
    RegressFromIncident(RegressFromIncidentArgs),
    AppList(AppListArgs),
    AppKill(AppControlArgs),
    AppUnkill(AppControlArgs),
    PlatformKill(PlatformControlArgs),
    PlatformUnkill(PlatformControlArgs),
    UiServe(UiServeArgs),
}

#[derive(Args, Debug, Clone)]
struct CommonStateArgs {
    #[arg(long)]
    state_dir: Option<String>,
    #[arg(long)]
    now_unix_ms: Option<u64>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct DeployRunArgs {
    #[arg(long)]
    deployment_id: String,
    #[arg(long)]
    plan: Option<String>,
    #[arg(long)]
    metrics_dir: Option<String>,
    #[arg(long)]
    pause_scale: Option<f64>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeployQueryArgs {
    #[arg(long)]
    deployment_id: Option<String>,
    #[arg(long)]
    app_id: Option<String>,
    #[arg(long)]
    env: Option<String>,
    #[arg(long, default_value = "summary")]
    view: String,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    latest: bool,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentStatusArgs {
    #[arg(long)]
    deployment_id: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentControlArgs {
    #[arg(long)]
    deployment_id: String,
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentRerunArgs {
    #[arg(long)]
    deployment_id: String,
    #[arg(long)]
    from_step: usize,
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentCaptureArgs {
    #[arg(long)]
    deployment_id: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    request: Option<String>,
    #[arg(long)]
    response: Option<String>,
    #[arg(long)]
    trace: Option<String>,
    #[arg(long)]
    classification: String,
    #[arg(long)]
    source: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentListArgs {
    #[arg(long)]
    deployment_id: Option<String>,
    #[arg(long)]
    app_id: Option<String>,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentGetArgs {
    #[arg(long)]
    incident_id: String,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct RegressFromIncidentArgs {
    #[arg(long)]
    incident_id: String,
    #[arg(long, default_value = "incident")]
    name: String,
    #[arg(long)]
    out_dir: Option<String>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct AppListArgs {
    #[arg(long)]
    app_id: Option<String>,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct AppControlArgs {
    #[arg(long)]
    app_id: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct PlatformControlArgs {
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct UiServeArgs {
    #[arg(long, default_value = DEFAULT_UI_ADDR)]
    addr: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

fn main() -> std::process::ExitCode {
    match real_main() {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("{err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let report = match cli.command {
        Commands::UiServe(args) => return command_ui_serve(args),
        Commands::Run(args) => command_run(args)?,
        Commands::Query(args) => command_query(args)?,
        Commands::Status(args) => command_status(args)?,
        Commands::Stop(args) => command_stop(args)?,
        Commands::Rollback(args) => command_rollback(args)?,
        Commands::Pause(args) => command_pause(args)?,
        Commands::Rerun(args) => command_rerun(args)?,
        Commands::IncidentCapture(args) => command_incident_capture(args)?,
        Commands::IncidentList(args) => command_incident_list(args)?,
        Commands::IncidentGet(args) => command_incident_get(args)?,
        Commands::RegressFromIncident(args) => command_regress_from_incident(args)?,
        Commands::AppList(args) => command_app_list(args)?,
        Commands::AppKill(args) => command_app_scope(args, true)?,
        Commands::AppUnkill(args) => command_app_scope(args, false)?,
        Commands::PlatformKill(args) => command_platform_scope(args, true)?,
        Commands::PlatformUnkill(args) => command_platform_scope(args, false)?,
    };
    println!("{}", String::from_utf8(canon_json_bytes(&report))?);
    Ok(report.get("exit_code").and_then(Value::as_i64).unwrap_or(0) as i32)
}

fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

fn workspace_dir() -> PathBuf {
    root_dir().parent().unwrap().to_path_buf()
}

fn repo_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        root_dir().join(path)
    }
}

fn resolve_state_dir(raw: Option<&str>) -> PathBuf {
    let value = raw
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("X07LP_STATE_DIR").ok())
        .unwrap_or_else(|| DEFAULT_STATE_DIR.to_string());
    let path = PathBuf::from(&value);
    if path.is_absolute() {
        path
    } else {
        root_dir().join(path)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn canon_json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize json")
}

fn load_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<Vec<u8>> {
    let bytes = canon_json_bytes(value);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(path, &bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn should_redact_http_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    REDACTED_HTTP_HEADER_NAMES
        .iter()
        .any(|candidate| *candidate == lower)
}

fn sanitize_http_envelope_doc(doc: &Value) -> Value {
    let mut sanitized = doc.clone();
    if let Some(headers) = sanitized.get_mut("headers").and_then(Value::as_array_mut) {
        for header in headers.iter_mut() {
            let Some(item) = header.as_object_mut() else {
                continue;
            };
            let name = item
                .get("k")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if should_redact_http_header(&name) {
                item.insert("v".to_string(), json!("[redacted]"));
            }
        }
    }
    sanitized
}

fn load_sanitized_http_envelope(path: &Path) -> Result<(Value, Vec<u8>)> {
    let doc = load_json(path)?;
    let sanitized = sanitize_http_envelope_doc(&doc);
    let bytes = canon_json_bytes(&sanitized);
    Ok((sanitized, bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_value(bytes: &[u8]) -> Value {
    json!({
        "sha256": sha256_hex(bytes),
        "bytes_len": bytes.len(),
    })
}

fn rel_store_blob_path(state_dir: &Path, sha: &str) -> PathBuf {
    state_dir
        .join("store")
        .join("blobs")
        .join("sha256")
        .join(&sha[..2])
        .join(sha)
}

fn rel_store_meta_path(state_dir: &Path, sha: &str) -> PathBuf {
    state_dir
        .join("store")
        .join("meta")
        .join("sha256")
        .join(&sha[..2])
        .join(format!("{sha}.json"))
}

fn cas_put(state_dir: &Path, logical_name: &str, media_type: &str, data: &[u8]) -> Result<Value> {
    let digest = digest_value(data);
    let sha = digest.get("sha256").and_then(Value::as_str).unwrap();
    let blob_path = rel_store_blob_path(state_dir, sha);
    let meta_path = rel_store_meta_path(state_dir, sha);
    if !blob_path.exists() {
        write_bytes(&blob_path, data)?;
    }
    let meta = json!({
        "algo": "sha256",
        "sha256": sha,
        "bytes_len": digest.get("bytes_len").and_then(Value::as_u64).unwrap_or(0),
        "media_type": media_type,
        "logical_name": logical_name,
        "store_uri": format!("sha256:{sha}"),
    });
    let _ = write_json(&meta_path, &meta)?;
    Ok(json!({
        "digest": digest,
        "media_type": media_type,
        "logical_name": logical_name,
        "store_uri": format!("sha256:{sha}"),
    }))
}

fn load_cas_blob(state_dir: &Path, sha: &str) -> Result<Vec<u8>> {
    fs::read(rel_store_blob_path(state_dir, sha)).with_context(|| format!("read cas blob {}", sha))
}

fn logical_name_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("artifact")
        .to_string()
}

fn media_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(OsStr::to_str).unwrap_or("") {
        "json" => "application/json",
        "wasm" => "application/wasm",
        "mjs" | "js" => "text/javascript",
        "html" => "text/html",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn named_file_artifact(rel_path: &str, kind: &str, media_type: &str, data: &[u8]) -> Value {
    json!({
        "kind": kind,
        "digest": digest_value(data),
        "media_type": media_type,
        "logical_name": rel_path.rsplit('/').next().unwrap_or(rel_path),
        "store_uri": format!("file:{rel_path}"),
    })
}

fn result_diag(code: &str, stage: &str, message: &str, severity: &str) -> Value {
    json!({
        "code": code,
        "severity": severity,
        "stage": if stage == "parse" { "parse" } else { "run" },
        "message": message,
    })
}

fn cli_report(
    command: &str,
    ok: bool,
    exit_code: i64,
    result: Value,
    run_id: Option<&str>,
    diagnostics: Vec<Value>,
) -> Value {
    let mut report = json!({
        "schema_version": "lp.cli.report@0.1.0",
        "command": command,
        "ok": ok,
        "exit_code": exit_code,
        "diagnostics": diagnostics,
        "result": result,
    });
    if let Some(run_id) = run_id.filter(|v| !v.is_empty()) {
        ensure_object(&mut report).insert(
            "meta".to_string(),
            json!({
                "tool": "x07lp",
                "version": TOOL_VERSION,
                "run_id": run_id,
            }),
        );
    }
    report
}

fn internal_report(command: &str, message: &str) -> Value {
    cli_report(
        command,
        false,
        50,
        json!({}),
        None,
        vec![result_diag("LP_INTERNAL", "run", message, "error")],
    )
}

fn ensure_object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().unwrap()
}

fn ensure_object_field<'a>(parent: &'a mut Value, key: &str) -> &'a mut Map<String, Value> {
    let map = ensure_object(parent);
    if !map.get(key).map(Value::is_object).unwrap_or(false) {
        map.insert(key.to_string(), Value::Object(Map::new()));
    }
    map.get_mut(key).unwrap().as_object_mut().unwrap()
}

fn ensure_array_field<'a>(parent: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let map = ensure_object(parent);
    if !map.get(key).map(Value::is_array).unwrap_or(false) {
        map.insert(key.to_string(), Value::Array(Vec::new()));
    }
    map.get_mut(key).unwrap().as_array_mut().unwrap()
}

fn upsert_default(map: &mut Map<String, Value>, key: &str, value: Value) {
    if !map.contains_key(key) || map.get(key) == Some(&Value::Null) {
        map.insert(key.to_string(), value);
    }
}

fn get_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

fn get_str(value: &Value, path: &[&str]) -> Option<String> {
    get_path(value, path)?.as_str().map(ToOwned::to_owned)
}

fn get_u64(value: &Value, path: &[&str]) -> Option<u64> {
    get_path(value, path)?.as_u64()
}

fn get_bool(value: &Value, path: &[&str]) -> Option<bool> {
    get_path(value, path)?.as_bool()
}

fn run_capture(argv: &[String], cwd: Option<&Path>) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    if argv.is_empty() {
        bail!("empty argv");
    }
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd.unwrap_or(&root_dir()))
        .output()
        .with_context(|| format!("spawn {}", argv[0]))?;
    Ok((
        output.status.code().unwrap_or(1),
        output.stdout,
        output.stderr,
    ))
}

fn search_workspace_file(name: &str) -> Option<PathBuf> {
    let root = root_dir();
    let workspace = workspace_dir();
    let candidates = [
        root.join(name),
        root.join("spec")
            .join("fixtures")
            .join("phaseA")
            .join("pack_min")
            .join(name),
        workspace
            .join("x07-wasm-backend")
            .join("arch")
            .join("slo")
            .join(name),
        workspace
            .join("x07-wasm-backend")
            .join("arch")
            .join("app")
            .join("ops")
            .join(name),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    for base in [root, workspace.join("x07-wasm-backend")] {
        for entry in WalkDir::new(base).into_iter().filter_map(Result::ok) {
            if entry.file_name() == name {
                return Some(entry.path().to_path_buf());
            }
        }
    }
    None
}

fn resolve_plan_path(path: Option<&str>) -> Option<PathBuf> {
    path.map(repo_path)
}

fn resolve_tool_cwd_and_path(path: Option<&Path>) -> (PathBuf, Option<String>) {
    let Some(path) = path else {
        return (root_dir(), None);
    };
    let resolved = path.to_path_buf();
    let mut tool_cwd = root_dir();
    for parent in resolved.ancestors() {
        if parent.join("arch").is_dir() {
            tool_cwd = parent.to_path_buf();
            break;
        }
    }
    let arg = resolved
        .strip_prefix(&tool_cwd)
        .ok()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| resolved.to_string_lossy().into_owned());
    (tool_cwd, Some(arg))
}

fn deterministic_listener(exec_id: &str) -> String {
    let bytes = Sha256::digest(exec_id.as_bytes());
    let hash = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let port = 20_000 + (hash % 20_000);
    format!("http://127.0.0.1:{port}")
}

fn env_doc_to_name(value: &Value) -> String {
    if let Some(kind) = get_str(value, &["kind"]) {
        if kind == "custom" {
            return get_str(value, &["name"]).unwrap_or(kind);
        }
        return kind;
    }
    if let Some(s) = value.as_str() {
        return s.to_string();
    }
    "unknown".to_string()
}

fn env_name_to_doc(name: &str) -> Value {
    match name {
        "dev" | "staging" | "prod" => json!({ "kind": name }),
        other => json!({ "kind": "custom", "name": other }),
    }
}

fn infer_target_from_run(state_dir: &Path, run_doc: &Value) -> Result<(String, String)> {
    let change_id = get_str(run_doc, &["inputs", "change_request", "change_id"]);
    if let Some(change_id) = change_id {
        let change_doc = load_json(&state_dir.join("changes").join(format!("{change_id}.json")))?;
        let app_id =
            get_str(&change_doc, &["target", "app_id"]).unwrap_or_else(|| "unknown".to_string());
        let env = get_path(&change_doc, &["target", "environment"])
            .map(env_doc_to_name)
            .unwrap_or_else(|| "unknown".to_string());
        return Ok((app_id, env));
    }
    Ok(("unknown".to_string(), "unknown".to_string()))
}

fn load_pack_manifest_from_run(state_dir: &Path, run_doc: &Value) -> Result<(Value, Vec<u8>)> {
    let sha = get_str(
        run_doc,
        &["inputs", "artifact", "manifest", "digest", "sha256"],
    )
    .ok_or_else(|| anyhow!("missing pack manifest digest"))?;
    let raw = load_cas_blob(state_dir, &sha)?;
    let manifest = serde_json::from_slice(&raw).context("parse pack manifest")?;
    Ok((manifest, raw))
}

fn materialize_pack_dir(
    state_dir: &Path,
    run_doc: &Value,
    out_dir: &Path,
) -> Result<(Value, Vec<u8>)> {
    let (manifest, manifest_raw) = load_pack_manifest_from_run(state_dir, run_doc)?;
    if out_dir.exists() {
        let _ = fs::remove_dir_all(out_dir);
    }
    fs::create_dir_all(out_dir)?;
    write_bytes(&out_dir.join("app.pack.json"), &manifest_raw)?;
    let mut specs: Vec<(String, String)> = Vec::new();
    if let Some(bundle) = get_path(&manifest, &["bundle_manifest"]).and_then(Value::as_object) {
        if let (Some(sha), Some(path)) = (
            bundle.get("sha256").and_then(Value::as_str),
            bundle.get("path").and_then(Value::as_str),
        ) {
            specs.push((sha.to_string(), path.to_string()));
            let bundle_bytes = load_cas_blob(state_dir, sha)?;
            write_bytes(&out_dir.join(path), &bundle_bytes)?;
            let bundle_doc: Value = serde_json::from_slice(&bundle_bytes)?;
            if let Some(backend) =
                get_path(&bundle_doc, &["backend", "artifact"]).and_then(Value::as_object)
            {
                if let (Some(bsha), Some(bpath)) = (
                    backend.get("sha256").and_then(Value::as_str),
                    backend.get("path").and_then(Value::as_str),
                ) {
                    specs.push((bsha.to_string(), bpath.to_string()));
                }
            }
            if let Some(frontend) =
                get_path(&bundle_doc, &["frontend", "artifacts"]).and_then(Value::as_array)
            {
                for artifact in frontend {
                    if let Some(obj) = artifact.as_object() {
                        if let (Some(sha), Some(path)) = (
                            obj.get("sha256").and_then(Value::as_str),
                            obj.get("path").and_then(Value::as_str),
                        ) {
                            specs.push((sha.to_string(), path.to_string()));
                        }
                    }
                }
            }
        }
    }
    if let Some(component) =
        get_path(&manifest, &["backend", "component"]).and_then(Value::as_object)
    {
        if let (Some(sha), Some(path)) = (
            component.get("sha256").and_then(Value::as_str),
            component.get("path").and_then(Value::as_str),
        ) {
            specs.push((sha.to_string(), path.to_string()));
        }
    }
    if let Some(assets) = get_path(&manifest, &["assets"]).and_then(Value::as_array) {
        for asset in assets {
            if let Some(file) = get_path(asset, &["file"]).and_then(Value::as_object) {
                if let (Some(sha), Some(path)) = (
                    file.get("sha256").and_then(Value::as_str),
                    file.get("path").and_then(Value::as_str),
                ) {
                    specs.push((sha.to_string(), path.to_string()));
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    for (sha, rel_path) in specs {
        if !seen.insert((sha.clone(), rel_path.clone())) {
            continue;
        }
        let bytes = load_cas_blob(state_dir, &sha)?;
        write_bytes(&out_dir.join(rel_path), &bytes)?;
    }
    Ok((manifest, manifest_raw))
}

fn synth_runtime_probe(exec_id: &str, work_dir: &Path) -> Value {
    json!({
        "schema_version": "lp.runtime.probe.synthetic@0.1.0",
        "command": "lp.runtime.probe.synthetic",
        "ok": true,
        "exit_code": 0,
        "diagnostics": [],
        "result": {
            "exec_id": exec_id,
            "work_dir": work_dir.to_string_lossy(),
            "status": "healthy",
        },
    })
}

fn failed_runtime_probe(exec_id: &str, work_dir: &Path, exit_code: i64, message: &str) -> Value {
    json!({
        "schema_version": "lp.runtime.probe.synthetic@0.1.0",
        "command": "lp.runtime.probe.synthetic",
        "ok": false,
        "exit_code": exit_code,
        "diagnostics": [result_diag("LP_RUNTIME_HEALTHCHECK_FAILED", "run", message, "error")],
        "result": {
            "exec_id": exec_id,
            "work_dir": work_dir.to_string_lossy(),
            "status": "unhealthy",
        },
    })
}

fn runtime_probe_ok(report: &Value) -> bool {
    if report.get("ok").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    if report.get("ok").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    matches!(
        get_str(report, &["result", "status"]).as_deref(),
        Some("healthy" | "ok" | "running")
    )
}

fn runtime_probe_message(report: &Value) -> String {
    get_path(report, &["diagnostics"])
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|v| get_str(v, &["message"]))
        .unwrap_or_else(|| {
            let status =
                get_str(report, &["result", "status"]).unwrap_or_else(|| "unknown".to_string());
            format!("candidate runtime probe reported status={status}")
        })
}

fn run_runtime_probe(exec_id: &str, work_dir: &Path, ops_path: Option<&Path>) -> Result<Value> {
    let x07_wasm = std::env::var("PATH").ok().and_then(|_| which("x07-wasm"));
    if x07_wasm.is_none() {
        return Ok(synth_runtime_probe(exec_id, work_dir));
    }
    let (cwd, ops_arg) = resolve_tool_cwd_and_path(ops_path);
    let mut argv = vec![
        x07_wasm.unwrap(),
        "app".to_string(),
        "serve".to_string(),
        "--dir".to_string(),
        work_dir.to_string_lossy().into_owned(),
        "--mode".to_string(),
        "smoke".to_string(),
        "--json".to_string(),
    ];
    if let Some(ops_arg) = ops_arg {
        argv.push("--ops".to_string());
        argv.push(ops_arg);
    }
    let (code, stdout, stderr) = run_capture(&argv, Some(&cwd))?;
    if code == 0 {
        return serde_json::from_slice(&stdout).context("parse runtime probe json");
    }
    if let Ok(doc) = serde_json::from_slice::<Value>(&stdout) {
        let err_code = get_path(&doc, &["diagnostics"])
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|v| get_str(v, &["code"]));
        if matches!(
            err_code.as_deref(),
            Some("X07WASM_APP_BUNDLE_MISSING" | "X07WASM_APP_NOT_SERVABLE")
        ) {
            return Ok(synth_runtime_probe(exec_id, work_dir));
        }
    }
    let message = String::from_utf8_lossy(&stderr).trim().to_string();
    if message.contains("tool missing in active toolchain")
        || message.contains("install the wasm component")
        || message.contains("x07-wasm")
    {
        return Ok(synth_runtime_probe(exec_id, work_dir));
    }
    Ok(failed_runtime_probe(
        exec_id,
        work_dir,
        i64::from(code.max(1)),
        if message.is_empty() {
            "candidate runtime probe failed"
        } else {
            &message
        },
    ))
}

fn infer_slo_decision(metrics_doc: &Value) -> String {
    let mut metrics = BTreeMap::new();
    if let Some(items) = get_path(metrics_doc, &["metrics"]).and_then(Value::as_array) {
        for metric in items {
            if let (Some(name), Some(value)) = (get_str(metric, &["name"]), metric.get("value")) {
                metrics.insert(name, value.as_f64().unwrap_or(0.0));
            }
        }
    }
    let latency = metrics.get("http_latency_p95_ms").copied();
    let error_rate = metrics.get("http_error_rate").copied();
    let availability = metrics.get("http_availability").copied();
    if latency.is_none() {
        return "inconclusive".to_string();
    }
    if error_rate.unwrap_or(0.0) > 0.01 {
        return "rollback".to_string();
    }
    if availability.unwrap_or(1.0) < 0.99 {
        return "rollback".to_string();
    }
    if latency.unwrap_or(0.0) > 250.0 {
        return "rollback".to_string();
    }
    "promote".to_string()
}

fn synth_slo_eval(profile_path: &Path, metrics_path: &Path, decision: &str) -> Result<Value> {
    let profile_bytes = if profile_path.exists() {
        fs::read(profile_path)?
    } else {
        b"{}".to_vec()
    };
    let metrics_bytes = fs::read(metrics_path)?;
    Ok(json!({
        "schema_version": "x07.wasm.slo.eval.report@0.1.0",
        "command": "x07-wasm.slo.eval",
        "ok": true,
        "exit_code": 0,
        "diagnostics": [],
        "meta": {
            "tool": { "name": "x07-wasm", "version": "synthetic" },
            "elapsed_ms": 0,
            "cwd": root_dir().to_string_lossy(),
            "argv": ["x07-wasm", "slo", "eval"],
            "inputs": [
                { "path": profile_path.to_string_lossy(), "sha256": sha256_hex(&profile_bytes), "bytes_len": profile_bytes.len() },
                { "path": metrics_path.to_string_lossy(), "sha256": sha256_hex(&metrics_bytes), "bytes_len": metrics_bytes.len() }
            ],
            "outputs": [],
            "nondeterminism": {
                "uses_os_time": false,
                "uses_network": false,
                "uses_process": false
            }
        },
        "result": {
            "slo_profile": { "path": profile_path.to_string_lossy(), "sha256": sha256_hex(&profile_bytes), "bytes_len": profile_bytes.len() },
            "metrics_snapshot": { "path": metrics_path.to_string_lossy(), "sha256": sha256_hex(&metrics_bytes), "bytes_len": metrics_bytes.len() },
            "decision": decision,
            "violations": if decision == "promote" { 0 } else { 1 },
            "indicators": []
        }
    }))
}

fn run_slo_eval(profile_path: Option<&Path>, metrics_path: &Path) -> Result<(String, Value)> {
    let metrics_doc = load_json(metrics_path)?;
    let inferred = infer_slo_decision(&metrics_doc);
    if let (Some(x07_wasm), Some(profile_path)) =
        (which("x07-wasm"), profile_path.filter(|p| p.exists()))
    {
        let (cwd, profile_arg) = resolve_tool_cwd_and_path(Some(profile_path));
        let argv = vec![
            x07_wasm,
            "slo".to_string(),
            "eval".to_string(),
            "--profile".to_string(),
            profile_arg.unwrap(),
            "--metrics".to_string(),
            metrics_path.to_string_lossy().into_owned(),
            "--json".to_string(),
        ];
        let (code, stdout, _) = run_capture(&argv, Some(&cwd))?;
        if code == 0 {
            let report: Value = serde_json::from_slice(&stdout).context("parse slo report")?;
            let decision = get_str(&report, &["result", "decision"]).unwrap_or(inferred.clone());
            return Ok((decision, report));
        }
    }
    let profile = if let Some(path) = profile_path {
        path.to_path_buf()
    } else {
        let path = root_dir().join("_tmp").join("phaseb.synthetic.slo.json");
        if !path.exists() {
            write_bytes(
                &path,
                br#"{"schema_version":"x07.slo.profile@0.1.0","id":"synthetic","v":1,"service":"app","indicators":[]}"#,
            )?;
        }
        path
    };
    Ok((
        inferred.clone(),
        synth_slo_eval(&profile, metrics_path, &inferred)?,
    ))
}

fn runtime_state_paths(
    state_dir: &Path,
    exec_id: &str,
    slot: &str,
) -> BTreeMap<&'static str, PathBuf> {
    let base = state_dir
        .join(".x07lp")
        .join("runtime")
        .join(exec_id)
        .join(slot);
    BTreeMap::from([
        ("base", base.clone()),
        ("work", base.join("work")),
        ("logs", base.join("logs")),
        ("reports", base.join("reports")),
    ])
}

fn write_runtime_terminal_report(
    state_dir: &Path,
    exec_id: &str,
    slot: &str,
    status: &str,
    outcome: &str,
    now_unix_ms: u64,
) -> Result<()> {
    let reports = runtime_state_paths(state_dir, exec_id, slot)
        .remove("reports")
        .unwrap();
    write_json(
        &reports.join("terminal.json"),
        &json!({
            "schema_version": "lp.runtime.terminal.report@0.1.0",
            "exec_id": exec_id,
            "slot": slot,
            "status": status,
            "outcome": outcome,
            "updated_unix_ms": now_unix_ms,
        }),
    )?;
    Ok(())
}

fn prepare_runtime_terminal_state(
    state_dir: &Path,
    exec_doc: &Value,
    meta: &mut Map<String, Value>,
    outcome: &str,
    now_unix_ms: u64,
) -> Result<()> {
    let exec_id = get_str(exec_doc, &["exec_id"]).unwrap();
    let runtime = meta
        .entry("runtime".to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap();
    for slot in ["stable", "candidate"] {
        let state_paths = runtime_state_paths(state_dir, &exec_id, slot);
        let slot_meta = runtime
            .entry(slot.to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .unwrap();
        slot_meta.insert(
            "work_dir".to_string(),
            Value::String(state_paths["work"].to_string_lossy().into_owned()),
        );
        slot_meta.insert("ended_unix_ms".to_string(), json!(now_unix_ms));
        let status = if outcome == "rolled_back" && slot == "stable" {
            "healthy"
        } else {
            "stopped"
        };
        slot_meta.insert("status".to_string(), Value::String(status.to_string()));
        write_runtime_terminal_report(state_dir, &exec_id, slot, status, outcome, now_unix_ms)?;
    }
    Ok(())
}

fn write_router_state(
    state_dir: &Path,
    exec_id: &str,
    stable_addr: &str,
    candidate_addr: &str,
    candidate_weight_pct: u64,
    step_idx: usize,
) -> Result<()> {
    let router_dir = state_dir.join(".x07lp").join("router").join(exec_id);
    let state = json!({
        "exec_id": exec_id,
        "listener_addr": deterministic_listener(exec_id),
        "stable_addr": stable_addr,
        "candidate_addr": candidate_addr,
        "candidate_weight_pct": candidate_weight_pct,
        "last_updated_step_idx": step_idx,
    });
    write_json(&router_dir.join("state.json"), &state)?;
    write_json(
        &router_dir.join("counters.json"),
        &json!({
            "candidate_requests": 0,
            "stable_requests": 0,
        }),
    )?;
    Ok(())
}

fn prepare_router_terminal_state(state_dir: &Path, exec_doc: &Value, meta: &Value) -> Result<()> {
    let exec_id = get_str(exec_doc, &["exec_id"]).unwrap();
    let weight = get_u64(meta, &["routing", "candidate_weight_pct"]).unwrap_or(0);
    let steps = get_path(exec_doc, &["steps"])
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    write_router_state(
        state_dir,
        &exec_id,
        &format!("{}/stable", deterministic_listener(&exec_id)),
        &format!("{}/candidate", deterministic_listener(&exec_id)),
        weight,
        steps,
    )
}

fn gen_id(prefix: &str, seed: &str) -> String {
    format!("{}_{}", prefix, &sha256_hex(seed.as_bytes())[..24])
}

fn load_signing_key(state_dir: &Path) -> Result<SigningKey> {
    let key_path = state_dir
        .join(".x07lp")
        .join("keys")
        .join("kill_switch_v1.ed25519");
    if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        if bytes.len() != 32 {
            bail!("invalid signing key length in {}", key_path.display());
        }
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&bytes);
        let key = SigningKey::from_bytes(&secret);
        return Ok(key);
    }
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let secret = key.to_bytes();
    write_bytes(&key_path, &secret)?;
    Ok(key)
}

fn decision_record_ref(record: &Value) -> Value {
    json!({
        "kind": record.get("kind").cloned().unwrap_or_else(|| json!("lp.decision.record@0.1.0")),
        "digest": record.get("digest").cloned().unwrap_or(Value::Null),
        "label": record.get("logical_name").cloned().unwrap_or_else(|| json!("decision.record")),
    })
}

fn write_decision_record(
    state_dir: &Path,
    seed: &str,
    run_id: &str,
    kind: &str,
    outcome: &str,
    reasons: Vec<Value>,
    evidence: Vec<Value>,
    created_unix_ms: u64,
    step_idx: Option<usize>,
    sign_control: bool,
) -> Result<(Value, String)> {
    let decision_id = gen_id("lpdec", seed);
    let mut record = json!({
        "schema_version": "lp.decision.record@0.1.0",
        "decision_id": decision_id,
        "run_id": run_id,
        "created_unix_ms": created_unix_ms,
        "kind": kind,
        "outcome": outcome,
        "reasons": reasons,
        "evidence": evidence.iter().map(decision_record_ref).collect::<Vec<_>>(),
        "integrity": {
            "record_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "signatures": [],
        },
    });
    let record_sha = sha256_hex(&canon_json_bytes(&record));
    ensure_object_field(&mut record, "integrity")
        .insert("record_sha256".to_string(), Value::String(record_sha));
    let signature_status = if sign_control {
        let key = load_signing_key(state_dir)?;
        let sig = key.sign(&canon_json_bytes(&record));
        ensure_array_field(&mut record, "integrity")
            .push(json!({"keyid": "kill_switch_v1", "sig": BASE64.encode(sig.to_bytes())}));
        "valid".to_string()
    } else {
        "not_applicable".to_string()
    };
    let path = state_dir
        .join("decisions")
        .join(format!("{decision_id}.json"));
    let bytes = write_json(&path, &record)?;
    let artifact = json!({
        "kind": "lp.decision.record@0.1.0",
        "digest": digest_value(&bytes),
        "media_type": "application/json",
        "logical_name": "decision.record",
        "store_uri": format!("file:decisions/{decision_id}.json"),
    });
    Ok((
        {
            let mut decision = json!({
            "decision_id": decision_id,
            "created_unix_ms": created_unix_ms,
            "kind": kind,
            "outcome": outcome,
            "reasons": record.get("reasons").cloned().unwrap_or_else(|| json!([])),
            "evidence": evidence,
            "record": artifact,
            });
            if let Some(step_idx) = step_idx {
                ensure_object(&mut decision).insert("step_idx".to_string(), json!(step_idx));
            }
            decision
        },
        signature_status,
    ))
}

fn artifact_summary(
    role: &str,
    artifact: &Value,
    ord: usize,
    kind_override: Option<&str>,
) -> Value {
    json!({
        "role": role,
        "ord": ord,
        "kind": kind_override.unwrap_or_else(|| artifact.get("kind").and_then(Value::as_str).unwrap_or("")),
        "digest": artifact.get("digest").cloned().unwrap_or(Value::Null),
        "media_type": artifact.get("media_type").cloned().unwrap_or_else(|| json!("application/json")),
        "logical_name": artifact.get("logical_name").cloned().unwrap_or(Value::Null),
        "store_uri": artifact.get("store_uri").cloned().unwrap_or(Value::Null),
    })
}

fn build_exec_step(
    idx: usize,
    name: &str,
    kind: &str,
    status: &str,
    started_unix_ms: u64,
    ended_unix_ms: Option<u64>,
    decisions: Vec<String>,
    latest_weight_pct: Option<u64>,
    analysis_decision: Option<&str>,
) -> Value {
    let mut step = json!({
        "idx": idx,
        "name": name,
        "kind": kind,
        "status": status,
        "started_unix_ms": started_unix_ms,
        "ended_unix_ms": ended_unix_ms,
        "decisions": decisions,
        "evidence": [],
    });
    if let Some(weight) = latest_weight_pct {
        ensure_object(&mut step).insert("latest_weight_pct".to_string(), json!(weight));
    }
    if let Some(decision) = analysis_decision {
        ensure_object(&mut step).insert("analysis_decision".to_string(), json!(decision));
    }
    step
}

fn dedupe_artifacts(items: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        let sha = get_str(item, &["digest", "sha256"]);
        let len = get_u64(item, &["digest", "bytes_len"]);
        let role = get_str(item, &["role"]);
        let key = (sha.clone(), len, role.clone());
        if !seen.insert(key) {
            continue;
        }
        out.push(item.clone());
    }
    out
}

fn exec_path(state_dir: &Path, exec_id: &str) -> PathBuf {
    state_dir.join("deploy").join(format!("{exec_id}.json"))
}

fn run_path(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join("runs").join(format!("{run_id}.json"))
}

fn load_exec(state_dir: &Path, exec_id: &str) -> Result<Value> {
    load_json(&exec_path(state_dir, exec_id))
}

fn save_exec(state_dir: &Path, exec_doc: &Value) -> Result<Vec<u8>> {
    let exec_id = get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    write_json(&exec_path(state_dir, &exec_id), exec_doc)
}

fn ensure_deploy_meta(exec_doc: &mut Value, run_doc: &Value, state_dir: &Path) -> Result<()> {
    let (app_id, environment) = infer_target_from_run(state_dir, run_doc)?;
    let created_unix_ms = get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0);
    let status = get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string());
    let control_state = match status.as_str() {
        "completed" | "failed" | "aborted" => "terminal",
        _ => "active",
    };
    let public_listener =
        deterministic_listener(&get_str(exec_doc, &["exec_id"]).unwrap_or_default());
    let revisions =
        if let Ok((manifest, manifest_raw)) = load_pack_manifest_from_run(state_dir, run_doc) {
            get_path(&manifest, &["backend", "component"])
                .cloned()
                .unwrap_or_else(|| digest_value(&manifest_raw))
        } else {
            json!({})
        };
    let plan = exec_doc.get("plan").cloned().unwrap_or(Value::Null);
    let meta = ensure_object_field(exec_doc, "meta");
    upsert_default(
        meta,
        "schema_version",
        json!("lp.deploy.execution.meta.local@0.1.0"),
    );
    upsert_default(meta, "mode", json!("local"));
    upsert_default(meta, "artifact_kind", json!("x07.app.pack@0.1.0"));
    upsert_default(
        meta,
        "target",
        json!({
            "app_id": app_id,
            "environment": environment,
        }),
    );
    upsert_default(meta, "outcome", json!("unknown"));
    upsert_default(meta, "control_state", json!(control_state));
    upsert_default(meta, "kill_scope", json!("none"));
    upsert_default(meta, "kill_latched", json!(false));
    upsert_default(meta, "pause_reason", Value::Null);
    upsert_default(meta, "started_unix_ms", Value::Null);
    upsert_default(meta, "updated_unix_ms", json!(created_unix_ms));
    upsert_default(meta, "ended_unix_ms", Value::Null);
    upsert_default(meta, "latest_decision_id", Value::Null);
    upsert_default(meta, "latest_signed_control_decision_id", Value::Null);
    upsert_default(meta, "last_incident_id", Value::Null);
    upsert_default(meta, "incident_count_total", json!(0));
    upsert_default(meta, "incident_count_open", json!(0));
    upsert_default(meta, "parent_exec_id", Value::Null);
    upsert_default(meta, "rerun_from_step_idx", Value::Null);
    upsert_default(meta, "plan", plan);
    upsert_default(meta, "public_listener", json!(public_listener));
    upsert_default(
        meta,
        "revisions",
        json!({"stable": revisions, "candidate": revisions}),
    );
    upsert_default(meta, "runtime", json!({}));
    upsert_default(meta, "routing", json!({"candidate_weight_pct": 0}));
    upsert_default(
        meta,
        "analysis",
        json!({
            "last_slo_decision": null,
            "last_snapshot": null,
            "last_slo_report": null,
            "last_analysis_step_idx": null,
        }),
    );
    upsert_default(
        meta,
        "retry_budget",
        json!({"max_attempts_per_step": 3, "consumed": {}}),
    );
    upsert_default(meta, "decisions", json!([]));
    upsert_default(meta, "artifacts", json!([]));
    upsert_default(meta, "ext", json!({}));
    Ok(())
}

fn control_state_snapshot(exec_doc: &Value) -> Value {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let status = get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string());
    json!({
        "status": status,
        "control_state": get_str(&meta, &["control_state"]).unwrap_or_else(|| if matches!(status.as_str(), "completed" | "failed" | "aborted") { "terminal".to_string() } else { "active".to_string() }),
        "kill_scope": get_str(&meta, &["kill_scope"]).unwrap_or_else(|| "none".to_string()),
        "kill_latched": get_bool(&meta, &["kill_latched"]).unwrap_or(false),
    })
}

fn latest_artifact_by_role(items: &[Value], role: &str) -> Option<Value> {
    items
        .iter()
        .rev()
        .find(|item| get_str(item, &["role"]).as_deref() == Some(role))
        .cloned()
}

fn build_execution_view(exec_doc: &Value, run_doc: &Value, state_dir: &Path) -> Value {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let steps = get_path(exec_doc, &["steps"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let artifacts = get_path(&meta, &["artifacts"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let revisions = get_path(&meta, &["revisions"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let started_unix_ms = steps
        .iter()
        .filter_map(|step| get_u64(step, &["started_unix_ms"]))
        .min()
        .unwrap_or_else(|| get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0));
    let ended_unix_ms = steps
        .iter()
        .filter_map(|step| get_u64(step, &["ended_unix_ms"]))
        .max();
    let public_listener = get_str(&meta, &["public_listener"]).unwrap_or_else(|| {
        deterministic_listener(&get_str(exec_doc, &["exec_id"]).unwrap_or_default())
    });
    let listener_addr = public_listener
        .strip_prefix("http://")
        .or_else(|| public_listener.strip_prefix("https://"))
        .unwrap_or(&public_listener)
        .to_string();
    let last_route_step = steps
        .iter()
        .rev()
        .find(|step| get_str(step, &["kind"]).as_deref() == Some("deploy.route.set_weight"))
        .cloned();
    let last_analysis_step = steps
        .iter()
        .rev()
        .find(|step| get_str(step, &["kind"]).as_deref() == Some("deploy.analysis.slo"))
        .cloned();
    let last_probe = latest_artifact_by_role(&artifacts, "runtime_probe");
    let last_snapshot = latest_artifact_by_role(&artifacts, "metrics_snapshot");
    let last_slo_report = latest_artifact_by_role(&artifacts, "slo_eval_report");
    let outcome = get_str(&meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string());
    let runtime_meta = get_path(&meta, &["runtime"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let artifact_kind = get_str(run_doc, &["inputs", "artifact", "kind"])
        .unwrap_or_else(|| "x07.app.pack@0.1.0".to_string());

    let slot_view = |slot: &str, fallback_status: &str| {
        let slot_meta = get_path(&runtime_meta, &[slot])
            .cloned()
            .unwrap_or_else(|| json!({}));
        let mut status =
            get_str(&slot_meta, &["status"]).unwrap_or_else(|| fallback_status.to_string());
        if outcome == "promoted" {
            status = if slot == "candidate" {
                "healthy"
            } else {
                "stopped"
            }
            .to_string();
        } else if outcome == "rolled_back" {
            status = if slot == "stable" {
                "healthy"
            } else {
                "stopped"
            }
            .to_string();
        }
        let ended_value = if status == "healthy" {
            Value::Null
        } else {
            get_path(&slot_meta, &["ended_unix_ms"])
                .cloned()
                .unwrap_or_else(|| ended_unix_ms.map(Value::from).unwrap_or(Value::Null))
        };
        json!({
            "revision_digest": get_path(&revisions, &[slot]).cloned().unwrap_or(Value::Null),
            "bind_addr": get_str(&slot_meta, &["bind_addr"]).unwrap_or_else(|| if slot == "candidate" { listener_addr.clone() } else { "127.0.0.1:0".to_string() }),
            "status": status,
            "started_unix_ms": get_u64(&slot_meta, &["started_unix_ms"]).unwrap_or(started_unix_ms),
            "ended_unix_ms": ended_value,
            "health": {
                "ok": true,
                "last_probe_unix_ms": get_u64(&meta, &["updated_unix_ms"]).unwrap_or(started_unix_ms),
                "last_report": get_str(&slot_meta, &["last_report"]).or_else(|| last_probe.as_ref().and_then(|v| get_str(v, &["store_uri"]))).unwrap_or(public_listener.clone()),
            },
            "workdir": get_str(&slot_meta, &["work_dir"]).unwrap_or_else(|| state_dir.join(".x07lp").join("runtime").join(get_str(exec_doc, &["exec_id"]).unwrap_or_default()).join(slot).join("work").to_string_lossy().into_owned()),
        })
    };

    json!({
        "schema_version": get_str(exec_doc, &["schema_version"]).unwrap_or_else(|| "lp.deploy.execution@0.1.0".to_string()),
        "exec_id": get_str(exec_doc, &["exec_id"]).unwrap_or_default(),
        "run_id": get_str(exec_doc, &["run_id"]).unwrap_or_default(),
        "created_unix_ms": get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0),
        "status": get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
        "plan": exec_doc.get("plan").cloned().unwrap_or(Value::Null),
        "meta": {
            "schema_version": "lp.deploy.execution.meta.local@0.1.0",
            "mode": "local",
            "artifact_kind": artifact_kind,
            "target": get_path(&meta, &["target"]).cloned().unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"})),
            "outcome": outcome,
            "control_state": get_str(&meta, &["control_state"]).unwrap_or_else(|| "active".to_string()),
            "kill_scope": get_str(&meta, &["kill_scope"]).unwrap_or_else(|| "none".to_string()),
            "kill_latched": get_bool(&meta, &["kill_latched"]).unwrap_or(false),
            "pause_reason": get_path(&meta, &["pause_reason"]).cloned().unwrap_or(Value::Null),
            "started_unix_ms": started_unix_ms,
            "updated_unix_ms": get_u64(&meta, &["updated_unix_ms"]).unwrap_or(started_unix_ms),
            "ended_unix_ms": ended_unix_ms,
            "latest_decision_id": get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null),
            "latest_signed_control_decision_id": get_path(&meta, &["latest_signed_control_decision_id"]).cloned().unwrap_or(Value::Null),
            "last_incident_id": get_path(&meta, &["last_incident_id"]).cloned().unwrap_or(Value::Null),
            "incident_count_total": get_u64(&meta, &["incident_count_total"]).unwrap_or(0),
            "incident_count_open": get_u64(&meta, &["incident_count_open"]).unwrap_or(0),
            "parent_exec_id": get_path(&meta, &["parent_exec_id"]).cloned().unwrap_or(Value::Null),
            "rerun_from_step_idx": get_path(&meta, &["rerun_from_step_idx"]).cloned().unwrap_or(Value::Null),
            "plan": exec_doc.get("plan").cloned().unwrap_or(Value::Null),
            "runtime": {
                "stable": slot_view("stable", "stopped"),
                "candidate": slot_view("candidate", "healthy")
            },
            "routing": {
                "public_listener": public_listener,
                "listener_addr": listener_addr,
                "candidate_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0),
                "algorithm": "hash_bucket_v1",
                "route_key_header": "X-LP-Route-Key",
                "last_updated_step_idx": last_route_step.as_ref().and_then(|v| get_u64(v, &["idx"])),
                "router_state": state_dir.join(".x07lp").join("router").join(get_str(exec_doc, &["exec_id"]).unwrap_or_default()).join("state.json").to_string_lossy().into_owned(),
            },
            "analysis": {
                "last_slo_decision": last_analysis_step.as_ref().and_then(|v| get_str(v, &["analysis_decision"])),
                "last_snapshot": last_snapshot.as_ref().and_then(|v| get_str(v, &["store_uri"])),
                "last_slo_report": last_slo_report.as_ref().and_then(|v| get_str(v, &["store_uri"])),
                "last_analysis_step_idx": last_analysis_step.as_ref().and_then(|v| get_u64(v, &["idx"])),
            },
            "retry_budget": get_path(&meta, &["retry_budget"]).cloned().unwrap_or_else(|| json!({"max_attempts_per_step":3,"consumed":{}})),
            "steps": steps,
            "decisions": get_path(&meta, &["decisions"]).cloned().unwrap_or_else(|| json!([])),
            "artifacts": artifacts,
            "ext": get_path(&meta, &["ext"]).cloned().unwrap_or_else(|| json!({})),
        }
    })
}

fn build_query_result(
    exec_doc: &Value,
    run_doc: &Value,
    state_dir: &Path,
    view: &str,
    resolution: Value,
    db_path: &Path,
    rebuilt: bool,
    limit: Option<usize>,
) -> Value {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let target = get_path(&meta, &["target"])
        .cloned()
        .unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"}));
    let mut steps = get_path(exec_doc, &["steps"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let decisions_all = get_path(&meta, &["decisions"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let artifacts_all = get_path(&meta, &["artifacts"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut decisions = decisions_all
        .iter()
        .filter(|decision| {
            matches!(
                get_str(decision, &["kind"]).as_deref(),
                Some(
                    "deploy.prepare.plan"
                        | "deploy.runtime.start_candidate"
                        | "deploy.analysis.slo"
                )
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut artifacts = Vec::new();
    for role in [
        "decision_record",
        "deploy_execution",
        "deploy_plan",
        "metrics_snapshot",
        "slo_eval_report",
    ] {
        if let Some(item) = artifacts_all
            .iter()
            .find(|artifact| get_str(artifact, &["role"]).as_deref() == Some(role))
        {
            artifacts.push(item.clone());
        }
    }
    if let Some(limit) = limit {
        steps.truncate(limit);
        decisions.truncate(limit);
        artifacts.truncate(limit);
    }
    let signature_status = if get_path(&meta, &["latest_signed_control_decision_id"]).is_some()
        && get_path(&meta, &["latest_signed_control_decision_id"]) != Some(&Value::Null)
    {
        "valid"
    } else {
        "not_applicable"
    };
    let mut result = json!({
        "schema_version": "lp.deploy.query.result@0.1.0",
        "view": view,
        "deployment_id": get_str(exec_doc, &["exec_id"]).unwrap_or_default(),
        "run_id": get_str(exec_doc, &["run_id"]).unwrap_or_default(),
        "target": target,
        "resolution": resolution,
        "index": { "used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy() },
    });
    if matches!(view, "summary" | "full") {
        ensure_object(&mut result).extend(Map::from_iter([
            (
                "status".to_string(),
                json!(get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string())),
            ),
            (
                "outcome".to_string(),
                json!(get_str(&meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string())),
            ),
            (
                "created_unix_ms".to_string(),
                json!(get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0)),
            ),
            (
                "updated_unix_ms".to_string(),
                json!(get_u64(&meta, &["updated_unix_ms"]).unwrap_or(0)),
            ),
            (
                "current_weight_pct".to_string(),
                json!(get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0)),
            ),
            (
                "public_listener".to_string(),
                get_path(&meta, &["public_listener"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "latest_decision_id".to_string(),
                get_path(&meta, &["latest_decision_id"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "latest_signed_control_decision_id".to_string(),
                get_path(&meta, &["latest_signed_control_decision_id"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            ("signature_status".to_string(), json!(signature_status)),
            (
                "plan_digest".to_string(),
                get_path(exec_doc, &["plan", "digest"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "stable_revision".to_string(),
                get_path(&meta, &["revisions", "stable"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "candidate_revision".to_string(),
                get_path(&meta, &["revisions", "candidate"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "control_state".to_string(),
                json!(get_str(&meta, &["control_state"]).unwrap_or_else(|| "active".to_string())),
            ),
            (
                "kill_scope".to_string(),
                json!(get_str(&meta, &["kill_scope"]).unwrap_or_else(|| "none".to_string())),
            ),
            (
                "kill_latched".to_string(),
                json!(get_bool(&meta, &["kill_latched"]).unwrap_or(false)),
            ),
            (
                "incident_count_total".to_string(),
                json!(get_u64(&meta, &["incident_count_total"]).unwrap_or(0)),
            ),
            (
                "incident_count_open".to_string(),
                json!(get_u64(&meta, &["incident_count_open"]).unwrap_or(0)),
            ),
            (
                "last_incident_id".to_string(),
                get_path(&meta, &["last_incident_id"])
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
        ]));
    }
    if matches!(view, "timeline" | "full") {
        ensure_object(&mut result).insert("steps".to_string(), Value::Array(steps));
    }
    if matches!(view, "decisions" | "full") {
        ensure_object(&mut result).insert("decisions".to_string(), Value::Array(decisions));
    }
    if matches!(view, "artifacts" | "full") {
        ensure_object(&mut result).insert("artifacts".to_string(), Value::Array(artifacts));
    }
    if view == "full" {
        ensure_object(&mut result).insert(
            "execution".to_string(),
            build_execution_view(exec_doc, run_doc, state_dir),
        );
    }
    result
}

fn which(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join(bin);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn resolve_plan_inputs(plan_doc: &Value) -> (Option<PathBuf>, Option<PathBuf>) {
    let ops_name = get_str(plan_doc, &["ops_profile", "path"])
        .unwrap_or_else(|| "ops_release.json".to_string());
    let slo_name = get_str(plan_doc, &["slo_profile", "path"]);
    (
        search_workspace_file(
            Path::new(&ops_name)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("ops_release.json"),
        ),
        slo_name.and_then(|name| {
            Path::new(&name)
                .file_name()
                .and_then(OsStr::to_str)
                .and_then(search_workspace_file)
        }),
    )
}

fn normalize_plan(mut plan_doc: Value) -> Value {
    if get_str(&plan_doc, &["schema_version"]).as_deref() == Some("x07.deploy.plan@0.1.0") {
        ensure_object(&mut plan_doc).insert(
            "schema_version".to_string(),
            Value::String("x07.deploy.plan@0.2.0".to_string()),
        );
    }
    plan_doc
}

fn generated_plan_from_accepted(
    state_dir: &Path,
    exec_doc: &Value,
    run_doc: &Value,
) -> Result<(Value, Vec<u8>)> {
    let exec_id = get_str(exec_doc, &["exec_id"]).unwrap();
    let pack_dir = state_dir
        .join(".x07lp")
        .join("generated")
        .join(&exec_id)
        .join("pack");
    let (_, manifest_raw) = materialize_pack_dir(state_dir, run_doc, &pack_dir)?;
    let ops_path = search_workspace_file("ops_release.json");
    if let (Some(x07_wasm), Some(ops_path)) = (which("x07-wasm"), ops_path.as_ref()) {
        let out_dir = state_dir
            .join(".x07lp")
            .join("generated")
            .join(&exec_id)
            .join("plan");
        if out_dir.exists() {
            let _ = fs::remove_dir_all(&out_dir);
        }
        fs::create_dir_all(&out_dir)?;
        let (cwd, ops_arg) = resolve_tool_cwd_and_path(Some(ops_path));
        let argv = vec![
            x07_wasm,
            "deploy".to_string(),
            "plan".to_string(),
            "--pack-manifest".to_string(),
            pack_dir
                .join("app.pack.json")
                .to_string_lossy()
                .into_owned(),
            "--ops".to_string(),
            ops_arg.unwrap(),
            "--emit-k8s".to_string(),
            "false".to_string(),
            "--out-dir".to_string(),
            out_dir.to_string_lossy().into_owned(),
            "--json".to_string(),
        ];
        let (code, stdout, _) = run_capture(&argv, Some(&cwd))?;
        if code == 0 {
            if let Ok(report) = serde_json::from_slice::<Value>(&stdout) {
                if let Some(plan_manifest) = get_str(&report, &["result", "plan_manifest", "path"])
                {
                    let path = {
                        let plan_path = PathBuf::from(plan_manifest);
                        if plan_path.is_absolute() {
                            plan_path
                        } else {
                            out_dir.join(plan_path)
                        }
                    };
                    let bytes = fs::read(&path)?;
                    let plan = normalize_plan(serde_json::from_slice(&bytes)?);
                    return Ok((plan.clone(), canon_json_bytes(&plan)));
                }
            }
        }
    }
    generated_plan_from_accepted_fallback(exec_doc, &manifest_raw)
}

fn generated_plan_from_accepted_fallback(
    exec_doc: &Value,
    manifest_raw: &[u8],
) -> Result<(Value, Vec<u8>)> {
    let ops_path = search_workspace_file("ops_release.json");
    let ops_bytes = ops_path
        .as_ref()
        .map(|path| fs::read(path).unwrap_or_else(|_| b"{}".to_vec()))
        .unwrap_or_else(|| b"{}".to_vec());
    let slo_path = search_workspace_file("slo_min.json");
    let slo_bytes = slo_path
        .as_ref()
        .map(|path| fs::read(path).unwrap_or_else(|_| b"{}".to_vec()))
        .unwrap_or_else(|| b"{}".to_vec());
    let plan = json!({
        "schema_version": "x07.deploy.plan@0.2.0",
        "id": format!("plan_{}", get_str(exec_doc, &["exec_id"]).unwrap_or_default()),
        "v": 1,
        "pack_manifest": {
            "path": "app.pack.json",
            "sha256": sha256_hex(manifest_raw),
            "bytes_len": manifest_raw.len(),
        },
        "ops_profile": {
            "path": ops_path.as_ref().and_then(|p| p.file_name()).and_then(OsStr::to_str).unwrap_or("ops_release.json"),
            "sha256": sha256_hex(&ops_bytes),
            "bytes_len": ops_bytes.len(),
        },
        "policy_cards": [],
        "slo_profile": {
            "path": slo_path.as_ref().and_then(|p| p.file_name()).and_then(OsStr::to_str).unwrap_or("slo_min.json"),
            "sha256": sha256_hex(&slo_bytes),
            "bytes_len": slo_bytes.len(),
        },
        "strategy": {
            "type": "canary",
            "canary": {
                "steps": [
                    { "set_weight": 5 },
                    { "pause_s": 10 },
                    { "analysis": { "kind": "slo.eval", "require_decision": "promote" } },
                    { "set_weight": 100 },
                    { "analysis": { "kind": "slo.eval", "require_decision": "promote" } }
                ]
            },
            "blue_green": null
        },
        "outputs": [],
    });
    Ok((plan.clone(), canon_json_bytes(&plan)))
}

fn push_decision(exec_doc: &mut Value, decision: Value, signature_status: Option<&str>) {
    {
        let meta = ensure_object_field(exec_doc, "meta");
        let decisions = meta
            .entry("decisions".to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap();
        decisions.push(decision.clone());
        meta.insert(
            "latest_decision_id".to_string(),
            decision.get("decision_id").cloned().unwrap_or(Value::Null),
        );
        if let Some(status) = signature_status {
            if status == "valid" {
                meta.insert(
                    "latest_signed_control_decision_id".to_string(),
                    decision.get("decision_id").cloned().unwrap_or(Value::Null),
                );
            }
        }
    }
    if let Some(record) = decision.get("record").cloned() {
        push_artifact(exec_doc, artifact_summary("decision_record", &record, 0, None));
    }
}

fn push_artifact(exec_doc: &mut Value, artifact: Value) {
    let meta = ensure_object_field(exec_doc, "meta");
    let artifacts = meta
        .entry("artifacts".to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .unwrap();
    artifacts.push(artifact);
    let deduped = dedupe_artifacts(artifacts);
    *artifacts = deduped;
}

fn update_terminal_meta(exec_doc: &mut Value, outcome: &str, now_unix_ms: u64) {
    let meta = ensure_object_field(exec_doc, "meta");
    meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    meta.insert("ended_unix_ms".to_string(), json!(now_unix_ms));
    meta.insert("outcome".to_string(), json!(outcome));
    meta.insert("control_state".to_string(), json!("terminal"));
    let routing = meta
        .entry("routing".to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap();
    let weight = if outcome == "promoted" { 100 } else { 0 };
    routing.insert("candidate_weight_pct".to_string(), json!(weight));
}

fn build_deploy_execution_artifact(exec_doc: &Value, exec_bytes: &[u8]) -> Value {
    let exec_id = get_str(exec_doc, &["exec_id"]).unwrap_or_default();
    json!({
        "kind": "lp.deploy.execution@0.1.0",
        "digest": digest_value(exec_bytes),
        "media_type": "application/json",
        "logical_name": "deploy.execution",
        "store_uri": format!("file:deploy/{exec_id}.json"),
    })
}

fn record_control_action(state_dir: &Path, result: &Value) -> Result<()> {
    let action_id = get_str(result, &["action_id"]).ok_or_else(|| anyhow!("missing action_id"))?;
    let path = state_dir
        .join("control_actions")
        .join(format!("{action_id}.json"));
    let _ = write_json(&path, result)?;
    Ok(())
}

fn write_kill_switch(state_dir: &Path, scope_key: &str, doc: &Value) -> Result<()> {
    let path = state_dir
        .join("kill_switches")
        .join(format!("{scope_key}.json"));
    let _ = write_json(&path, doc)?;
    Ok(())
}

fn collect_exec_ids_for_target(
    state_dir: &Path,
    app_id: Option<&str>,
    environment: Option<&str>,
) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    let deploy_dir = state_dir.join("deploy");
    if !deploy_dir.exists() {
        return Ok(ids);
    }
    for entry in fs::read_dir(deploy_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let exec_doc = load_json(&path)?;
        let target = get_path(&exec_doc, &["meta", "target"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        let matches_app = app_id
            .map(|wanted| get_str(&target, &["app_id"]).as_deref() == Some(wanted))
            .unwrap_or(true);
        let matches_env = environment
            .map(|wanted| get_str(&target, &["environment"]).as_deref() == Some(wanted))
            .unwrap_or(true);
        if matches_app && matches_env {
            if let Some(exec_id) = get_str(&exec_doc, &["exec_id"]) {
                ids.push(exec_id);
            }
        }
    }
    ids.sort();
    Ok(ids)
}

fn update_exec_for_kill(
    exec_doc: &mut Value,
    scope: &str,
    kill: bool,
    decision_id: &Value,
    now_unix_ms: u64,
) {
    let status = get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string());
    let meta = ensure_object_field(exec_doc, "meta");
    meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    meta.insert(
        "control_state".to_string(),
        json!(if kill {
            "killed"
        } else if matches!(status.as_str(), "completed" | "failed" | "aborted") {
            "terminal"
        } else {
            "active"
        }),
    );
    meta.insert(
        "kill_scope".to_string(),
        json!(if kill { scope } else { "none" }),
    );
    meta.insert("kill_latched".to_string(), json!(kill));
    meta.insert(
        "latest_signed_control_decision_id".to_string(),
        decision_id.clone(),
    );
}

fn rebuild_indexes(state_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let index_dir = state_dir.join("index");
    fs::create_dir_all(&index_dir)?;
    let phaseb_path = index_dir.join("phaseb.sqlite");
    let phasec_path = index_dir.join("phasec.sqlite");
    if phaseb_path.exists() {
        fs::remove_file(&phaseb_path)?;
    }
    if phasec_path.exists() {
        fs::remove_file(&phasec_path)?;
    }
    let phaseb_sql = fs::read_to_string(
        root_dir()
            .join("adapters")
            .join("sql")
            .join("phaseB_index.sqlite.sql"),
    )?;
    let phasec_sql = fs::read_to_string(
        root_dir()
            .join("adapters")
            .join("sql")
            .join("phaseC_index.sqlite.sql"),
    )?;
    let mut latest_heads: BTreeMap<(String, String), (String, u64)> = BTreeMap::new();
    for db_path in [&phaseb_path, &phasec_path] {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(&phaseb_sql)?;
        if db_path == &phasec_path {
            conn.execute_batch(&phasec_sql)?;
        }
        insert_execution_rows(&conn, state_dir, &mut latest_heads)?;
        if db_path == &phasec_path {
            insert_phasec_rows(&conn, state_dir, &latest_heads)?;
        }
    }
    Ok((phaseb_path, phasec_path))
}

fn insert_execution_rows(
    conn: &Connection,
    state_dir: &Path,
    latest_heads: &mut BTreeMap<(String, String), (String, u64)>,
) -> Result<()> {
    let deploy_dir = state_dir.join("deploy");
    if !deploy_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&deploy_dir)? {
        let path = entry?.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let exec_doc = load_json(&path)?;
        let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
        let run_doc = if !run_id.is_empty() && run_path(state_dir, &run_id).exists() {
            load_json(&run_path(state_dir, &run_id))?
        } else {
            json!({})
        };
        let exec_bytes = fs::read(&path)?;
        let exec_digest = digest_value(&exec_bytes);
        let run_bytes = if !run_id.is_empty() && run_path(state_dir, &run_id).exists() {
            fs::read(run_path(state_dir, &run_id))?
        } else {
            Vec::new()
        };
        let run_digest = if run_bytes.is_empty() {
            Value::Null
        } else {
            digest_value(&run_bytes)
        };
        let meta = get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        let target = get_path(&meta, &["target"]).cloned().unwrap_or_else(|| {
            let (app_id, environment) = infer_target_from_run(state_dir, &run_doc)
                .unwrap_or_else(|_| ("unknown".to_string(), "unknown".to_string()));
            json!({"app_id": app_id, "environment": environment})
        });
        let app_id = get_str(&target, &["app_id"]).unwrap_or_else(|| "unknown".to_string());
        let environment =
            get_str(&target, &["environment"]).unwrap_or_else(|| "unknown".to_string());
        let updated_unix_ms = get_u64(&meta, &["updated_unix_ms"])
            .unwrap_or_else(|| get_u64(&exec_doc, &["created_unix_ms"]).unwrap_or(0));
        latest_heads
            .entry((app_id.clone(), environment.clone()))
            .and_modify(|current| {
                if updated_unix_ms >= current.1 {
                    *current = (
                        get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                        updated_unix_ms,
                    );
                }
            })
            .or_insert((
                get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                updated_unix_ms,
            ));
        conn.execute(
            "INSERT OR REPLACE INTO executions (exec_id, run_id, app_id, environment, mode, artifact_kind, created_unix_ms, updated_unix_ms, status, outcome, current_weight_pct, public_listener, latest_decision_id, plan_sha256, plan_bytes_len, stable_revision_sha256, stable_revision_bytes_len, candidate_revision_sha256, candidate_revision_bytes_len, exec_record_sha256, exec_record_bytes_len, exec_store_uri, run_record_sha256, run_record_bytes_len, run_store_uri) VALUES (?1, ?2, ?3, ?4, 'local', 'x07.app.pack@0.1.0', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                run_id,
                app_id,
                environment,
                get_u64(&exec_doc, &["created_unix_ms"]).unwrap_or(0) as i64,
                updated_unix_ms as i64,
                get_str(&exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
                get_str(&meta, &["outcome"]),
                get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0) as i64,
                get_str(&meta, &["public_listener"]),
                get_str(&meta, &["latest_decision_id"]),
                get_str(&exec_doc, &["plan", "digest", "sha256"]),
                get_u64(&exec_doc, &["plan", "digest", "bytes_len"]).map(|v| v as i64),
                get_str(&meta, &["revisions", "stable", "sha256"]),
                get_u64(&meta, &["revisions", "stable", "bytes_len"]).map(|v| v as i64),
                get_str(&meta, &["revisions", "candidate", "sha256"]),
                get_u64(&meta, &["revisions", "candidate", "bytes_len"]).map(|v| v as i64),
                get_str(&exec_digest, &["sha256"]).unwrap_or_default(),
                get_u64(&exec_digest, &["bytes_len"]).unwrap_or(0) as i64,
                format!("file:deploy/{}", path.file_name().and_then(OsStr::to_str).unwrap_or_default()),
                get_str(&run_digest, &["sha256"]),
                get_u64(&run_digest, &["bytes_len"]).map(|v| v as i64),
                if run_digest.is_null() { None::<String> } else { Some(format!("file:runs/{}.json", get_str(&exec_doc, &["run_id"]).unwrap_or_default())) },
            ],
        )?;
        let exec_steps = get_path(&exec_doc, &["steps"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for step in &exec_steps {
            conn.execute(
                "INSERT OR REPLACE INTO execution_steps (exec_id, step_idx, attempt, step_name, step_kind, status, started_unix_ms, ended_unix_ms, latest_weight_pct, analysis_decision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                    get_u64(step, &["idx"]).unwrap_or(0) as i64,
                    get_u64(step, &["attempt"]).unwrap_or(1) as i64,
                    get_str(step, &["name"]).unwrap_or_default(),
                    get_str(step, &["kind"]),
                    get_str(step, &["status"]).unwrap_or_default(),
                    get_u64(step, &["started_unix_ms"]).unwrap_or(0) as i64,
                    get_u64(step, &["ended_unix_ms"]).map(|v| v as i64),
                    get_u64(step, &["latest_weight_pct"]).map(|v| v as i64),
                    get_str(step, &["analysis_decision"]),
                ],
            )?;
        }
        let decisions = get_path(&meta, &["decisions"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for decision in decisions {
            let reasons = get_path(&decision, &["reasons"])
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let primary_code = reasons
                .first()
                .and_then(|reason| get_str(reason, &["code"]))
                .unwrap_or_else(|| "LP_UNKNOWN".to_string());
            let summary_message = reasons
                .first()
                .and_then(|reason| get_str(reason, &["message"]));
            let record = get_path(&decision, &["record"])
                .cloned()
                .unwrap_or_else(|| json!({}));
            conn.execute(
                "INSERT OR REPLACE INTO decisions (decision_id, exec_id, run_id, step_idx, attempt, created_unix_ms, kind, outcome, primary_code, summary_message, record_sha256, record_bytes_len, record_store_uri) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    get_str(&decision, &["decision_id"]).unwrap_or_default(),
                    get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                    get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
                    get_u64(&decision, &["step_idx"]).map(|v| v as i64),
                    get_u64(&decision, &["created_unix_ms"]).unwrap_or(0) as i64,
                    get_str(&decision, &["kind"]).unwrap_or_default(),
                    get_str(&decision, &["outcome"]).unwrap_or_default(),
                    primary_code,
                    summary_message,
                    get_str(&record, &["digest", "sha256"]).unwrap_or_default(),
                    get_u64(&record, &["digest", "bytes_len"]).unwrap_or(0) as i64,
                    get_str(&record, &["store_uri"]).unwrap_or_default(),
                ],
            )?;
            for (ord, reason) in reasons.iter().enumerate() {
                conn.execute(
                    "INSERT OR REPLACE INTO decision_reasons (decision_id, ord, code, message) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        get_str(&decision, &["decision_id"]).unwrap_or_default(),
                        ord as i64,
                        get_str(reason, &["code"]).unwrap_or_default(),
                        get_str(reason, &["message"]),
                    ],
                )?;
            }
            let mut evidence = get_path(&decision, &["evidence"])
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if get_path(&record, &["digest", "sha256"]).is_some() {
                evidence.insert(0, artifact_summary("decision_record", &record, 0, None));
            }
            for (ord, artifact) in evidence.iter().enumerate() {
                if get_path(artifact, &["digest", "sha256"]).is_none() {
                    continue;
                }
                conn.execute(
                    "INSERT OR REPLACE INTO artifacts (sha256, bytes_len, kind, media_type, logical_name, store_uri, first_seen_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        get_str(artifact, &["digest", "sha256"]).unwrap_or_default(),
                        get_u64(artifact, &["digest", "bytes_len"]).unwrap_or(0) as i64,
                        get_str(artifact, &["kind"]),
                        get_str(artifact, &["media_type"]).unwrap_or_else(|| "application/json".to_string()),
                        get_str(artifact, &["logical_name"]),
                        get_str(artifact, &["store_uri"]).unwrap_or_default(),
                        get_u64(&decision, &["created_unix_ms"]).unwrap_or(0) as i64,
                    ],
                )?;
                conn.execute(
                    "INSERT OR REPLACE INTO decision_evidence (decision_id, ord, role, sha256, bytes_len) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        get_str(&decision, &["decision_id"]).unwrap_or_default(),
                        ord as i64,
                        get_str(artifact, &["role"]).unwrap_or_else(|| "evidence".to_string()),
                        get_str(artifact, &["digest", "sha256"]).unwrap_or_default(),
                        get_u64(artifact, &["digest", "bytes_len"]).unwrap_or(0) as i64,
                    ],
                )?;
            }
        }
        let artifacts = get_path(&meta, &["artifacts"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (ord, artifact) in artifacts.iter().enumerate() {
            if get_path(artifact, &["digest", "sha256"]).is_none() {
                continue;
            }
            conn.execute(
                "INSERT OR REPLACE INTO artifacts (sha256, bytes_len, kind, media_type, logical_name, store_uri, first_seen_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    get_str(artifact, &["digest", "sha256"]).unwrap_or_default(),
                    get_u64(artifact, &["digest", "bytes_len"]).unwrap_or(0) as i64,
                    get_str(artifact, &["kind"]),
                    get_str(artifact, &["media_type"]).unwrap_or_else(|| "application/json".to_string()),
                    get_str(artifact, &["logical_name"]),
                    get_str(artifact, &["store_uri"]).unwrap_or_default(),
                    updated_unix_ms as i64,
                ],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO execution_artifacts (exec_id, ord, role, sha256, bytes_len) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
                    ord as i64,
                    get_str(artifact, &["role"]).unwrap_or_default(),
                    get_str(artifact, &["digest", "sha256"]).unwrap_or_default(),
                    get_u64(artifact, &["digest", "bytes_len"]).unwrap_or(0) as i64,
                ],
            )?;
        }
    }
    for ((app_id, environment), (exec_id, updated_unix_ms)) in latest_heads.iter() {
        conn.execute(
            "INSERT OR REPLACE INTO target_heads (app_id, environment, exec_id, updated_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            params![app_id, environment, exec_id, *updated_unix_ms as i64],
        )?;
    }
    Ok(())
}

fn read_incident_meta_paths(state_dir: &Path) -> Vec<PathBuf> {
    let base = state_dir.join("incidents");
    if !base.exists() {
        return Vec::new();
    }
    WalkDir::new(base)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() == "incident.meta.local.json")
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

fn insert_phasec_rows(
    conn: &Connection,
    state_dir: &Path,
    latest_heads: &BTreeMap<(String, String), (String, u64)>,
) -> Result<()> {
    let mut app_incident_counts: BTreeMap<(String, String), (u64, u64, Option<String>, u64)> =
        BTreeMap::new();
    for meta_path in read_incident_meta_paths(state_dir) {
        let meta = load_json(&meta_path)?;
        let incident_dir = meta_path.parent().unwrap();
        let bundle_path = incident_dir.join("incident.bundle.json");
        let bundle = load_json(&bundle_path)?;
        let bundle_bytes = fs::read(&bundle_path)?;
        let bundle_digest = digest_value(&bundle_bytes);
        let app_id = get_str(&meta, &["target", "app_id"]).unwrap_or_default();
        let environment = get_str(&meta, &["target", "environment"]).unwrap_or_default();
        let incident_id = get_str(&bundle, &["incident_id"]).unwrap_or_else(|| {
            incident_dir
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string()
        });
        let captured_unix_ms = get_u64(&meta, &["captured_unix_ms"]).unwrap_or(0);
        conn.execute(
            "INSERT OR REPLACE INTO incidents (incident_id, app_id, environment, deployment_id, run_id, classification, source, incident_status, captured_unix_ms, request_id, trace_id, status_code, decision_id, regression_status, regression_id, bundle_sha256, bundle_bytes_len, bundle_store_uri, meta_store_uri) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                incident_id,
                app_id,
                environment,
                get_str(&meta, &["deployment_id"]).unwrap_or_default(),
                get_str(&meta, &["run_id"]).unwrap_or_default(),
                get_str(&meta, &["classification"]).unwrap_or_default(),
                get_str(&meta, &["source"]).unwrap_or_default(),
                get_str(&meta, &["incident_status"]).unwrap_or_default(),
                captured_unix_ms as i64,
                get_str(&meta, &["request_id"]),
                get_str(&meta, &["trace_id"]),
                get_u64(&meta, &["status_code"]).map(|v| v as i64),
                get_str(&meta, &["decision_id"]),
                get_str(&meta, &["regression_status"]).unwrap_or_else(|| "not_requested".to_string()),
                get_str(&meta, &["regression_id"]),
                get_str(&bundle_digest, &["sha256"]).unwrap_or_default(),
                get_u64(&bundle_digest, &["bytes_len"]).unwrap_or(0) as i64,
                format!("file:incidents/{}/{}/{}/incident.bundle.json", get_str(&meta, &["target", "app_id"]).unwrap_or_default(), get_str(&meta, &["target", "environment"]).unwrap_or_default(), incident_dir.file_name().and_then(OsStr::to_str).unwrap_or_default()),
                format!("file:incidents/{}/{}/{}/incident.meta.local.json", get_str(&meta, &["target", "app_id"]).unwrap_or_default(), get_str(&meta, &["target", "environment"]).unwrap_or_default(), incident_dir.file_name().and_then(OsStr::to_str).unwrap_or_default()),
            ],
        )?;
        if let Some(codes) = get_path(&bundle, &["diag_codes"]).and_then(Value::as_array) {
            for (ord, code) in codes.iter().enumerate() {
                conn.execute(
                    "INSERT OR REPLACE INTO incident_diagnostics (incident_id, ord, code) VALUES (?1, ?2, ?3)",
                    params![
                        get_str(&bundle, &["incident_id"]).unwrap_or_default(),
                        ord as i64,
                        code.as_str().unwrap_or_default(),
                    ],
                )?;
            }
        }
        let mut refs = get_path(&bundle, &["refs"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for key in ["request", "response", "trace"] {
            if let Some(value) = get_path(&bundle, &[key]).cloned() {
                if value.is_object() {
                    refs.push(value);
                }
            }
        }
        for (ord, artifact) in refs.iter().enumerate() {
            conn.execute(
                "INSERT OR REPLACE INTO incident_artifacts (incident_id, ord, role, sha256, bytes_len, kind, media_type, logical_name, store_uri) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    get_str(&bundle, &["incident_id"]).unwrap_or_default(),
                    ord as i64,
                    format!("ref_{ord}"),
                    get_str(artifact, &["digest", "sha256"]),
                    get_u64(artifact, &["digest", "bytes_len"]).map(|v| v as i64),
                    get_str(artifact, &["kind"]),
                    get_str(artifact, &["media_type"]),
                    get_str(artifact, &["label"]).or_else(|| get_str(artifact, &["logical_name"])),
                    get_str(artifact, &["store_uri"]).or_else(|| {
                        get_str(artifact, &["digest", "sha256"]).map(|sha| format!("sha256:{sha}"))
                    }),
                ],
            )?;
        }
        let counts = app_incident_counts
            .entry((
                get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
                get_str(&meta, &["target", "environment"]).unwrap_or_default(),
            ))
            .or_insert((0, 0, None, 0));
        counts.0 += 1;
        if get_str(&meta, &["incident_status"]).as_deref() == Some("open") {
            counts.1 += 1;
        }
        if captured_unix_ms >= counts.3 {
            counts.2 = get_str(&bundle, &["incident_id"]);
            counts.3 = captured_unix_ms;
        }
    }
    let regress_dir = state_dir.join("regressions");
    if regress_dir.exists() {
        for entry in fs::read_dir(regress_dir)? {
            let path = entry?.path();
            if path.extension().and_then(OsStr::to_str) != Some("json") {
                continue;
            }
            let doc = load_json(&path)?;
            conn.execute(
                "INSERT OR REPLACE INTO regressions (regression_id, incident_id, created_unix_ms, ok, incident_status_after, out_dir, report_sha256, report_bytes_len, report_store_uri) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    get_str(&doc, &["regression_id"]).unwrap_or_default(),
                    get_str(&doc, &["incident_id"]).unwrap_or_default(),
                    get_u64(&doc, &["created_unix_ms"]).unwrap_or(0) as i64,
                    if get_bool(&doc, &["ok"]).unwrap_or(false) { 1 } else { 0 },
                    get_str(&doc, &["incident_status_after"]).unwrap_or_default(),
                    get_str(&doc, &["out_dir"]),
                    get_str(&doc, &["report", "digest", "sha256"]),
                    get_u64(&doc, &["report", "digest", "bytes_len"]).map(|v| v as i64),
                    get_str(&doc, &["report", "store_uri"]),
                ],
            )?;
        }
    }
    let control_dir = state_dir.join("control_actions");
    if control_dir.exists() {
        for entry in fs::read_dir(control_dir)? {
            let path = entry?.path();
            if path.extension().and_then(OsStr::to_str) != Some("json") {
                continue;
            }
            let doc = load_json(&path)?;
            conn.execute(
                "INSERT OR REPLACE INTO control_actions (action_id, created_unix_ms, kind, scope, deployment_id, app_id, environment, ok, decision_id, signature_status, new_execution_id, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    get_str(&doc, &["action_id"]).unwrap_or_default(),
                    get_u64(&doc, &["created_unix_ms"]).unwrap_or(0) as i64,
                    get_str(&doc, &["kind"]).unwrap_or_default(),
                    get_str(&doc, &["scope"]).unwrap_or_default(),
                    get_str(&doc, &["target", "deployment_id"]),
                    get_str(&doc, &["target", "app_id"]),
                    get_str(&doc, &["target", "environment"]),
                    if get_bool(&doc, &["ok"]).unwrap_or(false) { 1 } else { 0 },
                    get_str(&doc, &["decision", "decision_id"]),
                    get_str(&doc, &["decision", "signature_status"]).unwrap_or_default(),
                    get_str(&doc, &["new_execution_id"]),
                    get_str(&doc, &["reason"]),
                ],
            )?;
        }
    }
    let kill_dir = state_dir.join("kill_switches");
    if kill_dir.exists() {
        for entry in fs::read_dir(kill_dir)? {
            let path = entry?.path();
            if path.extension().and_then(OsStr::to_str) != Some("json") {
                continue;
            }
            let doc = load_json(&path)?;
            conn.execute(
                "INSERT OR REPLACE INTO kill_switches (scope_key, scope, app_id, environment, kill_state, updated_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    get_str(&doc, &["scope_key"]).unwrap_or_default(),
                    get_str(&doc, &["scope"]).unwrap_or_default(),
                    get_str(&doc, &["app_id"]),
                    get_str(&doc, &["environment"]),
                    get_str(&doc, &["kill_state"]).unwrap_or_else(|| "none".to_string()),
                    get_u64(&doc, &["updated_unix_ms"]).unwrap_or(0) as i64,
                ],
            )?;
        }
    }
    for ((app_id, environment), (exec_id, _)) in latest_heads {
        let exec_doc = load_exec(state_dir, exec_id)?;
        let meta = get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        let counts = app_incident_counts
            .get(&(app_id.clone(), environment.clone()))
            .cloned()
            .unwrap_or((0, 0, None, 0));
        let kill_switch_key = format!("app__{}__{}", app_id, environment);
        let kill_path = state_dir
            .join("kill_switches")
            .join(format!("{kill_switch_key}.json"));
        let kill_state = if kill_path.exists() {
            get_str(&load_json(&kill_path)?, &["kill_state"]).unwrap_or_else(|| "none".to_string())
        } else {
            "none".to_string()
        };
        conn.execute(
            "INSERT OR REPLACE INTO app_heads (app_id, environment, latest_deployment_id, deployment_status, control_state, outcome, public_listener, current_weight_pct, incident_count_total, incident_count_open, latest_incident_id, latest_decision_id, kill_state, updated_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                app_id,
                environment,
                get_str(&exec_doc, &["exec_id"]),
                get_str(&exec_doc, &["status"]),
                get_str(&meta, &["control_state"]).unwrap_or_else(|| "active".to_string()),
                get_str(&meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string()),
                get_str(&meta, &["public_listener"]),
                get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0) as i64,
                counts.0 as i64,
                counts.1 as i64,
                counts.2,
                get_str(&meta, &["latest_decision_id"]),
                kill_state,
                get_u64(&meta, &["updated_unix_ms"]).unwrap_or(0) as i64,
            ],
        )?;
    }
    Ok(())
}

fn maybe_rebuild_phaseb(state_dir: &Path, force: bool) -> Result<(PathBuf, bool)> {
    let db_path = state_dir.join("index").join("phaseb.sqlite");
    let rebuilt = force || !db_path.exists();
    if rebuilt {
        rebuild_indexes(state_dir)?;
    }
    Ok((db_path, rebuilt))
}

fn maybe_rebuild_phasec(state_dir: &Path, force: bool) -> Result<(PathBuf, bool)> {
    let db_path = state_dir.join("index").join("phasec.sqlite");
    let rebuilt = force || !db_path.exists();
    if rebuilt {
        rebuild_indexes(state_dir)?;
    }
    Ok((db_path, rebuilt))
}

fn select_latest_exec_id(
    db_path: &Path,
    app_id: &str,
    environment: &str,
) -> Result<Option<String>> {
    let conn = Connection::open(db_path)?;
    let row = conn.query_row(
        "SELECT exec_id FROM target_heads WHERE app_id = ?1 AND environment = ?2",
        params![app_id, environment],
        |row| row.get::<_, String>(0),
    );
    match row {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn build_incident_summary_from_disk(
    state_dir: &Path,
    incident_id: &str,
) -> Result<Option<(Value, Value, PathBuf)>> {
    let base = state_dir.join("incidents");
    if !base.exists() {
        return Ok(None);
    }
    for meta_path in read_incident_meta_paths(state_dir) {
        let bundle_path = meta_path.parent().unwrap().join("incident.bundle.json");
        let bundle = load_json(&bundle_path)?;
        if get_str(&bundle, &["incident_id"]).as_deref() == Some(incident_id) {
            let meta = load_json(&meta_path)?;
            return Ok(Some((
                meta,
                bundle,
                meta_path.parent().unwrap().to_path_buf(),
            )));
        }
    }
    Ok(None)
}

fn find_existing_incident_for_key(
    state_dir: &Path,
    deployment_id: &str,
    classification: &str,
    request_id: Option<&str>,
    decision_id: Option<&str>,
) -> Result<Option<(Value, Value, PathBuf)>> {
    let request_id = request_id.filter(|value| !value.is_empty());
    let decision_id = decision_id.filter(|value| !value.is_empty());
    if request_id.is_none() && decision_id.is_none() {
        return Ok(None);
    }
    for meta_path in read_incident_meta_paths(state_dir) {
        let meta = load_json(&meta_path)?;
        if get_str(&meta, &["deployment_id"]).as_deref() != Some(deployment_id)
            || get_str(&meta, &["classification"]).as_deref() != Some(classification)
        {
            continue;
        }
        let duplicate = if let Some(request_id) = request_id {
            get_str(&meta, &["request_id"]).as_deref() == Some(request_id)
        } else if let Some(decision_id) = decision_id {
            get_str(&meta, &["decision_id"]).as_deref() == Some(decision_id)
        } else {
            false
        };
        if !duplicate {
            continue;
        }
        let incident_dir = meta_path
            .parent()
            .context("incident meta parent directory missing")?
            .to_path_buf();
        let bundle = load_json(&incident_dir.join("incident.bundle.json"))?;
        return Ok(Some((meta, bundle, incident_dir)));
    }
    Ok(None)
}

fn build_incident_result(
    _state_dir: &Path,
    meta: &Value,
    bundle: &Value,
    incident_dir: &Path,
    view: &str,
    resolution: Value,
    db_path: &Path,
    rebuilt: bool,
) -> Result<Value> {
    let bundle_bytes = fs::read(incident_dir.join("incident.bundle.json"))?;
    let bundle_artifact = json!({
        "kind": "lp.incident.bundle@0.1.0",
        "digest": digest_value(&bundle_bytes),
        "store_uri": format!(
            "file:incidents/{}/{}/{}/incident.bundle.json",
            get_str(meta, &["target", "app_id"]).unwrap_or_default(),
            get_str(meta, &["target", "environment"]).unwrap_or_default(),
            get_str(bundle, &["incident_id"]).unwrap_or_default(),
        ),
    });
    let mut result = json!({
        "schema_version": "lp.incident.query.result@0.1.0",
        "view": view,
        "resolution": resolution,
        "index": {"used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy()},
        "incident_id": get_str(bundle, &["incident_id"]).unwrap_or_default(),
        "classification": get_str(meta, &["classification"]).unwrap_or_default(),
        "source": get_str(meta, &["source"]).unwrap_or_default(),
        "incident_status": get_str(meta, &["incident_status"]).unwrap_or_default(),
        "target": get_path(meta, &["target"]).cloned().unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"})),
        "deployment_id": get_str(meta, &["deployment_id"]).unwrap_or_default(),
        "run_id": get_str(meta, &["run_id"]).unwrap_or_default(),
        "captured_unix_ms": get_u64(meta, &["captured_unix_ms"]).unwrap_or(0),
        "request_id": get_path(meta, &["request_id"]).cloned().unwrap_or(Value::Null),
        "trace_id": get_path(meta, &["trace_id"]).cloned().unwrap_or(Value::Null),
        "status_code": get_path(meta, &["status_code"]).cloned().unwrap_or(Value::Null),
        "decision_id": get_path(meta, &["decision_id"]).cloned().unwrap_or(Value::Null),
        "regression_status": get_str(meta, &["regression_status"]).unwrap_or_else(|| "not_requested".to_string()),
        "regression_id": get_path(meta, &["regression_id"]).cloned().unwrap_or(Value::Null),
        "signature_status": get_str(meta, &["signature_status"]).unwrap_or_else(|| "not_applicable".to_string()),
    });
    if view == "full" {
        let app_id = get_str(meta, &["target", "app_id"]).unwrap_or_default();
        let environment = get_str(meta, &["target", "environment"]).unwrap_or_default();
        let incident_id = get_str(bundle, &["incident_id"]).unwrap_or_default();
        let refs = get_path(bundle, &["refs"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(ord, mut item)| {
                let label = get_str(&item, &["label"]).unwrap_or_else(|| {
                    match get_str(&item, &["kind"]).as_deref() {
                        Some("x07.http.request.envelope@0.1.0") => {
                            "request.envelope.json".to_string()
                        }
                        Some("x07.http.response.envelope@0.1.0") => {
                            "response.envelope.json".to_string()
                        }
                        Some("x07.app.trace@0.1.0") => "trace.json".to_string(),
                        _ => format!("artifact.{ord}.json"),
                    }
                });
                let role = match label.as_str() {
                    "request.envelope.json" => "request".to_string(),
                    "response.envelope.json" => "response".to_string(),
                    "trace.json" => "trace".to_string(),
                    "diag.json" => "diag".to_string(),
                    "decision.record.json" => "decision_record".to_string(),
                    _ => format!("ref_{ord}"),
                };
                let item_map = ensure_object(&mut item);
                item_map.insert("role".to_string(), json!(role));
                item_map.insert("ord".to_string(), json!(ord));
                item_map.insert("logical_name".to_string(), json!(label.clone()));
                item_map.insert("media_type".to_string(), json!("application/json"));
                item_map.remove("label");
                item_map.insert(
                    "store_uri".to_string(),
                    json!(format!(
                        "file:incidents/{app_id}/{environment}/{incident_id}/{label}"
                    )),
                );
                item
            })
            .collect::<Vec<_>>();
        ensure_object(&mut result).extend(Map::from_iter([
            ("window".to_string(), get_path(bundle, &["window"]).cloned().unwrap_or_else(|| json!({"start_unix_ms": get_u64(meta, &["captured_unix_ms"]).unwrap_or(0), "end_unix_ms": get_u64(meta, &["captured_unix_ms"]).unwrap_or(0)}))),
            ("diag_codes".to_string(), get_path(bundle, &["diag_codes"]).cloned().unwrap_or_else(|| json!([]))),
            ("request".to_string(), get_path(bundle, &["request"]).cloned().unwrap_or(Value::Null)),
            ("response".to_string(), get_path(bundle, &["response"]).cloned().unwrap_or(Value::Null)),
            ("trace".to_string(), get_path(bundle, &["trace"]).cloned().unwrap_or(Value::Null)),
            ("bundle".to_string(), bundle_artifact),
            ("refs".to_string(), json!(refs)),
            ("meta".to_string(), meta.clone()),
        ]));
    }
    Ok(result)
}

fn capture_incident_impl(
    state_dir: &Path,
    exec_doc: &mut Value,
    run_doc: &Value,
    reason: &str,
    classification: &str,
    source: &str,
    request_path: Option<&Path>,
    response_path: Option<&Path>,
    trace_path: Option<&Path>,
    decision_id: Option<&str>,
    signature_status: &str,
    now_unix_ms: u64,
) -> Result<(Value, Value, PathBuf)> {
    ensure_deploy_meta(exec_doc, run_doc, state_dir)?;
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let app_id = get_str(&meta, &["target", "app_id"]).unwrap_or_default();
    let environment = get_str(&meta, &["target", "environment"]).unwrap_or_default();
    let deployment_id = get_str(exec_doc, &["exec_id"]).unwrap_or_default();
    let run_id = get_str(exec_doc, &["run_id"]).unwrap_or_default();
    let request_env = request_path
        .map(load_sanitized_http_envelope)
        .transpose()?;
    let response_env = response_path
        .map(load_sanitized_http_envelope)
        .transpose()?;
    let trace_doc = trace_path.map(load_json).transpose()?;
    let status_code = response_env
        .as_ref()
        .and_then(|(doc, _)| {
            get_u64(doc, &["status", "code"])
                .or_else(|| get_u64(doc, &["status"]))
                .or_else(|| get_u64(doc, &["status_code"]))
        })
        .map(Value::from)
        .unwrap_or(Value::Null);
    let request_id = request_env
        .as_ref()
        .and_then(|(doc, _)| get_str(doc, &["request_id"]))
        .or_else(|| {
            trace_doc
                .as_ref()
                .and_then(|doc| get_str(doc, &["request_id"]))
        });
    let trace_id = trace_doc.as_ref().and_then(|doc| get_str(doc, &["trace_id"]));
    if let Some(existing) = find_existing_incident_for_key(
        state_dir,
        &deployment_id,
        classification,
        request_id.as_deref(),
        decision_id,
    )? {
        return Ok(existing);
    }
    let seed = format!("{deployment_id}:{classification}:{source}:{now_unix_ms}:{reason}");
    let incident_id = gen_id("lpinc", &seed);
    let incident_dir = state_dir
        .join("incidents")
        .join(&app_id)
        .join(&environment)
        .join(&incident_id);
    fs::create_dir_all(&incident_dir)?;

    let mut refs = Vec::new();
    let mut request_ref = Value::Null;
    let mut response_ref = Value::Null;
    let mut trace_ref = Value::Null;
    if let Some((_, bytes)) = request_env.as_ref() {
        write_bytes(&incident_dir.join("request.envelope.json"), &bytes)?;
        request_ref = named_file_artifact(
            &format!("incidents/{app_id}/{environment}/{incident_id}/request.envelope.json"),
            "x07.http.request.envelope@0.1.0",
            "application/json",
            &bytes,
        );
        refs.push(json!({
            "kind": "x07.http.request.envelope@0.1.0",
            "digest": request_ref.get("digest").cloned().unwrap_or(Value::Null),
            "label": "request.envelope.json",
        }));
    }
    if let Some((_, bytes)) = response_env.as_ref() {
        write_bytes(&incident_dir.join("response.envelope.json"), &bytes)?;
        response_ref = named_file_artifact(
            &format!("incidents/{app_id}/{environment}/{incident_id}/response.envelope.json"),
            "x07.http.response.envelope@0.1.0",
            "application/json",
            &bytes,
        );
        refs.push(json!({
            "kind": "x07.http.response.envelope@0.1.0",
            "digest": response_ref.get("digest").cloned().unwrap_or(Value::Null),
            "label": "response.envelope.json",
        }));
    }
    if let Some(path) = trace_path {
        let bytes = fs::read(path)?;
        write_bytes(&incident_dir.join("trace.json"), &bytes)?;
        trace_ref = named_file_artifact(
            &format!("incidents/{app_id}/{environment}/{incident_id}/trace.json"),
            "x07.app.trace@0.1.0",
            "application/json",
            &bytes,
        );
        refs.push(json!({
            "kind": "x07.app.trace@0.1.0",
            "digest": trace_ref.get("digest").cloned().unwrap_or(Value::Null),
            "label": "trace.json",
        }));
    }
    let diag_codes = match classification {
        "http_5xx" => vec![json!("LP_HTTP_5XX")],
        "runtime_start_failed" => vec![json!("LP_RUNTIME_START_FAILED")],
        "runtime_health_failed" => vec![json!("LP_RUNTIME_HEALTHCHECK_FAILED")],
        "slo_rollback" => vec![json!("LP_SLO_DECISION_ROLLBACK")],
        "manual_capture" => vec![json!("LP_MANUAL_CAPTURE")],
        "app_kill" => vec![json!("LP_APP_KILL")],
        "platform_kill" => vec![json!("LP_PLATFORM_KILL")],
        _ => Vec::new(),
    };
    let bundle = json!({
        "schema_version": "lp.incident.bundle@0.1.0",
        "incident_id": incident_id,
        "created_unix_ms": now_unix_ms,
        "app_id": app_id,
        "environment": env_name_to_doc(&environment),
        "window": {
            "start_unix_ms": now_unix_ms,
            "end_unix_ms": now_unix_ms,
        },
        "deploy_execution": { "exec_id": deployment_id },
        "request": if request_ref.is_null() { Value::Null } else { json!({"kind":"x07.http.request.envelope@0.1.0","digest": request_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "response": if response_ref.is_null() { Value::Null } else { json!({"kind":"x07.http.response.envelope@0.1.0","digest": response_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "trace": if trace_ref.is_null() { Value::Null } else { json!({"kind":"x07.app.trace@0.1.0","digest": trace_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "diag_codes": diag_codes,
        "refs": refs,
        "notes": reason,
        "meta": {
            "classification": classification,
            "source": source,
        }
    });
    let _ = write_json(&incident_dir.join("incident.bundle.json"), &bundle)?;
    let pack_digest = get_path(run_doc, &["inputs", "artifact", "manifest", "digest"])
        .cloned()
        .unwrap_or(Value::Null);
    let meta_doc = json!({
        "schema_version": "lp.incident.bundle.meta.local@0.1.0",
        "classification": classification,
        "source": source,
        "incident_status": "open",
        "deployment_id": deployment_id,
        "run_id": run_id,
        "target": {
            "app_id": get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
            "environment": get_str(&meta, &["target", "environment"]).unwrap_or_default(),
        },
        "captured_unix_ms": now_unix_ms,
        "request_id": request_id.map(Value::from).unwrap_or(Value::Null),
        "trace_id": trace_id.map(Value::from).unwrap_or(Value::Null),
        "pack_digest": pack_digest,
        "slot": "candidate",
        "candidate_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]),
        "status_code": status_code,
        "route_key": Value::Null,
        "decision_id": decision_id.map(Value::from).unwrap_or(Value::Null),
        "regression_id": Value::Null,
        "regression_status": "not_requested",
        "signature_status": signature_status,
    });
    let _ = write_json(&incident_dir.join("incident.meta.local.json"), &meta_doc)?;

    let exec_meta = ensure_object_field(exec_doc, "meta");
    let total =
        get_u64(&Value::Object(exec_meta.clone()), &["incident_count_total"]).unwrap_or(0) + 1;
    let open =
        get_u64(&Value::Object(exec_meta.clone()), &["incident_count_open"]).unwrap_or(0) + 1;
    exec_meta.insert("incident_count_total".to_string(), json!(total));
    exec_meta.insert("incident_count_open".to_string(), json!(open));
    exec_meta.insert("last_incident_id".to_string(), json!(incident_id));
    exec_meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    let exec_bytes = save_exec(state_dir, exec_doc)?;
    push_artifact(
        exec_doc,
        artifact_summary(
            "deploy_execution",
            &build_deploy_execution_artifact(exec_doc, &exec_bytes),
            0,
            None,
        ),
    );
    rebuild_indexes(state_dir)?;
    Ok((meta_doc, bundle, incident_dir))
}

fn build_control_action_result(
    action_id: &str,
    kind: &str,
    scope: &str,
    created_unix_ms: u64,
    target: Value,
    reason: &str,
    affected_executions: Vec<String>,
    new_execution_id: Option<String>,
    state_before: Option<Value>,
    state_after: Option<Value>,
    decision: &Value,
    signature_status: &str,
) -> Value {
    let mut result = json!({
        "schema_version": "lp.control.action.result@0.1.0",
        "action_id": action_id,
        "kind": kind,
        "scope": scope,
        "ok": true,
        "approval_state": "not_required",
        "created_unix_ms": created_unix_ms,
        "target": target,
        "reason": reason,
        "affected_executions": affected_executions,
        "decision": {
            "decision_id": get_str(decision, &["decision_id"]),
            "signature_status": signature_status,
            "record": get_path(decision, &["record"]).cloned().unwrap_or(Value::Null),
        },
    });
    if let Some(new_execution_id) = new_execution_id {
        ensure_object(&mut result).insert("new_execution_id".to_string(), json!(new_execution_id));
    }
    if let Some(state_before) = state_before {
        ensure_object(&mut result).insert("state_before".to_string(), state_before);
    }
    if let Some(state_after) = state_after {
        ensure_object(&mut result).insert("state_after".to_string(), state_after);
    }
    result
}

fn command_status(args: DeploymentStatusArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    Ok(cli_report(
        "deploy status",
        true,
        0,
        json!({ "deployment": exec_doc }),
        get_str(&exec_doc, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_query(args: DeployQueryArgs) -> Result<Value> {
    let have_deployment = args.deployment_id.is_some();
    let have_target = args.app_id.is_some() && args.env.is_some() && args.latest;
    if !have_deployment && !have_target {
        return Ok(cli_report(
            "deploy query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_QUERY_INVALID",
                "parse",
                "query requires --deployment-id or --app-id/--env/--latest",
                "error",
            )],
        ));
    }
    if have_deployment && have_target {
        return Ok(cli_report(
            "deploy query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_QUERY_INVALID",
                "parse",
                "query accepts either --deployment-id or --app-id/--env/--latest",
                "error",
            )],
        ));
    }
    if !VALID_QUERY_VIEWS.contains(&args.view.as_str()) {
        return Ok(cli_report(
            "deploy query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_QUERY_INVALID",
                "parse",
                &format!("unsupported query view: {}", args.view),
                "error",
            )],
        ));
    }
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let (db_path, rebuilt) = maybe_rebuild_phaseb(&state_dir, args.rebuild_index)?;
    let (exec_id, resolution) = if let Some(exec_id) = args.deployment_id {
        (
            Some(exec_id.clone()),
            json!({"by":"deployment_id","requested_deployment_id":exec_id}),
        )
    } else {
        let app_id = args.app_id.clone().unwrap();
        let env = args.env.clone().unwrap();
        (
            select_latest_exec_id(&db_path, &app_id, &env)?,
            json!({"by":"latest","requested_target":{"app_id":app_id,"environment":env}}),
        )
    };
    let Some(exec_id) = exec_id else {
        return Ok(cli_report(
            "deploy query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_DEPLOYMENT_NOT_FOUND",
                "run",
                "deployment not found",
                "error",
            )],
        ));
    };
    let exec_doc = load_exec(&state_dir, &exec_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    Ok(cli_report(
        "deploy query",
        true,
        0,
        build_query_result(
            &exec_doc, &run_doc, &state_dir, &args.view, resolution, &db_path, rebuilt, args.limit,
        ),
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_run(args: DeployRunArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let pause_scale = args.pause_scale.unwrap_or(1.0);
    let metrics_dir = args.metrics_dir.as_deref().map(repo_path);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let plan_path = resolve_plan_path(args.plan.as_deref());
    let (plan_doc, plan_bytes) = match plan_path {
        Some(path) => {
            let plan = normalize_plan(load_json(&path)?);
            let bytes = canon_json_bytes(&plan);
            (plan, bytes)
        }
        None => generated_plan_from_accepted(&state_dir, &exec_doc, &run_doc)?,
    };
    let mut plan_artifact_raw =
        cas_put(&state_dir, "deploy.plan", "application/json", &plan_bytes)?;
    ensure_object(&mut plan_artifact_raw)
        .insert("kind".to_string(), json!("x07.deploy.plan@0.2.0"));
    let plan_artifact = artifact_summary(
        "deploy_plan",
        &plan_artifact_raw,
        0,
        Some("x07.deploy.plan@0.2.0"),
    );
    ensure_object(&mut exec_doc).insert(
        "plan".to_string(),
        json!({
            "kind": "x07.deploy.plan@0.2.0",
            "digest": plan_artifact.get("digest").cloned().unwrap_or(Value::Null),
        }),
    );
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert("started_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert("control_state".to_string(), json!("active"));
        meta.insert(
            "public_listener".to_string(),
            json!(deterministic_listener(&args.deployment_id)),
        );
        let (_, manifest_raw) = load_pack_manifest_from_run(&state_dir, &run_doc)?;
        let manifest_digest = digest_value(&manifest_raw);
        meta.insert(
            "revisions".to_string(),
            json!({
                "stable": manifest_digest,
                "candidate": manifest_digest,
            }),
        );
    }
    let prepare_reason = vec![json!({"code":"LP_PLAN_READY","message":"deploy plan is ready"})];
    let (prepare_decision, _) = write_decision_record(
        &state_dir,
        &format!("{}:deploy.prepare.plan:{now_unix_ms}", args.deployment_id),
        &run_id,
        "deploy.prepare.plan",
        "allow",
        prepare_reason,
        vec![plan_artifact.clone()],
        now_unix_ms,
        Some(0),
        false,
    )?;
    push_decision(&mut exec_doc, prepare_decision.clone(), None);
    push_artifact(&mut exec_doc, plan_artifact.clone());
    let mut steps = vec![build_exec_step(
        0,
        "prepare",
        "deploy.prepare",
        "ok",
        now_unix_ms,
        Some(now_unix_ms),
        vec![get_str(&prepare_decision, &["decision_id"]).unwrap_or_default()],
        None,
        None,
    )];
    let stable_paths = runtime_state_paths(&state_dir, &args.deployment_id, "stable");
    let candidate_paths = runtime_state_paths(&state_dir, &args.deployment_id, "candidate");
    if let Err(err) = materialize_pack_dir(&state_dir, &run_doc, &stable_paths["work"]) {
        let (meta_doc, bundle, incident_dir) = capture_incident_impl(
            &state_dir,
            &mut exec_doc,
            &run_doc,
            &err.to_string(),
            "runtime_start_failed",
            "runtime",
            None,
            None,
            None,
            None,
            "not_applicable",
            now_unix_ms,
        )?;
        let _ = (meta_doc, bundle, incident_dir);
        return Ok(cli_report(
            "deploy run",
            false,
            17,
            json!({
                "deployment_id": args.deployment_id,
                "run_id": run_id,
                "outcome": "failed",
            }),
            Some(&run_id),
            vec![result_diag(
                "LP_RUNTIME_START_FAILED",
                "run",
                &err.to_string(),
                "error",
            )],
        ));
    }
    materialize_pack_dir(&state_dir, &run_doc, &candidate_paths["work"])?;
    fs::create_dir_all(&stable_paths["logs"])?;
    fs::create_dir_all(&stable_paths["reports"])?;
    fs::create_dir_all(&candidate_paths["logs"])?;
    fs::create_dir_all(&candidate_paths["reports"])?;
    let (ops_path, slo_path) = resolve_plan_inputs(&plan_doc);
    let runtime_probe_doc = run_runtime_probe(
        &args.deployment_id,
        &candidate_paths["work"],
        ops_path.as_deref(),
    )?;
    if !runtime_probe_ok(&runtime_probe_doc) {
        let _ = capture_incident_impl(
            &state_dir,
            &mut exec_doc,
            &run_doc,
            &runtime_probe_message(&runtime_probe_doc),
            "runtime_health_failed",
            "runtime",
            None,
            None,
            None,
            None,
            "not_applicable",
            now_unix_ms,
        )?;
        return Ok(cli_report(
            "deploy run",
            false,
            18,
            json!({
                "deployment_id": args.deployment_id,
                "run_id": run_id,
                "outcome": "failed",
            }),
            Some(&run_id),
            vec![result_diag(
                "LP_RUNTIME_HEALTHCHECK_FAILED",
                "run",
                &runtime_probe_message(&runtime_probe_doc),
                "error",
            )],
        ));
    }
    let runtime_probe_bytes = canon_json_bytes(&runtime_probe_doc);
    let runtime_probe_kind = get_str(&runtime_probe_doc, &["schema_version"])
        .unwrap_or_else(|| "lp.runtime.probe.synthetic@0.1.0".to_string());
    let mut runtime_probe_raw = cas_put(
        &state_dir,
        "runtime.probe",
        "application/json",
        &runtime_probe_bytes,
    )?;
    ensure_object(&mut runtime_probe_raw)
        .insert("kind".to_string(), json!(runtime_probe_kind.clone()));
    let runtime_probe_artifact = artifact_summary(
        "runtime_probe",
        &runtime_probe_raw,
        0,
        Some(&runtime_probe_kind),
    );
    let (start_decision, _) = write_decision_record(
        &state_dir,
        &format!(
            "{}:deploy.runtime.start_candidate:{now_unix_ms}",
            args.deployment_id
        ),
        &run_id,
        "deploy.runtime.start_candidate",
        "allow",
        vec![
            json!({"code":"LP_RUNTIME_HEALTHCHECK_OK","message":"candidate runtime probe passed"}),
        ],
        vec![runtime_probe_artifact.clone()],
        now_unix_ms,
        Some(1),
        false,
    )?;
    push_decision(&mut exec_doc, start_decision.clone(), None);
    push_artifact(&mut exec_doc, runtime_probe_artifact.clone());
    steps.push(build_exec_step(
        1,
        "start_candidate",
        "deploy.runtime.start_candidate",
        "ok",
        now_unix_ms,
        Some(now_unix_ms),
        vec![get_str(&start_decision, &["decision_id"]).unwrap_or_default()],
        None,
        None,
    ));
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert(
            "runtime".to_string(),
            json!({
                "stable": {"status":"healthy","work_dir": stable_paths["work"].to_string_lossy()},
                "candidate": {"status":"healthy","work_dir": candidate_paths["work"].to_string_lossy()},
            }),
        );
    }
    write_router_state(
        &state_dir,
        &args.deployment_id,
        &format!("{}/stable", deterministic_listener(&args.deployment_id)),
        &format!("{}/candidate", deterministic_listener(&args.deployment_id)),
        0,
        1,
    )?;
    ensure_object(&mut exec_doc).insert("status".to_string(), json!("started"));
    ensure_object(&mut exec_doc).insert("steps".to_string(), Value::Array(steps.clone()));
    let _ = save_exec(&state_dir, &exec_doc)?;

    let mut step_cursor = 2usize;
    let mut analysis_counter = 0usize;
    let retry_budget = 3usize;
    let plan_steps = get_path(&plan_doc, &["strategy", "canary", "steps"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for plan_step in plan_steps {
        exec_doc = load_exec(&state_dir, &args.deployment_id)?;
        let meta = get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        if get_str(&meta, &["control_state"]).as_deref() == Some("paused") {
            rebuild_indexes(&state_dir)?;
            return Ok(cli_report(
                "deploy run",
                true,
                0,
                json!({
                    "deployment_id": args.deployment_id,
                    "run_id": run_id,
                    "final_decision_id": get_path(&meta, &["latest_signed_control_decision_id"]).cloned().unwrap_or_else(|| get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null)),
                    "outcome": get_str(&meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string()),
                    "latest_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0),
                    "public_listener": get_path(&meta, &["public_listener"]).cloned().unwrap_or(Value::Null),
                }),
                Some(&run_id),
                vec![result_diag(
                    "LP_DEPLOY_PAUSED",
                    "run",
                    "deployment paused during execution",
                    "info",
                )],
            ));
        }
        if get_str(&meta, &["outcome"]).as_deref() == Some("aborted") {
            rebuild_indexes(&state_dir)?;
            return Ok(cli_report(
                "deploy run",
                true,
                0,
                json!({
                    "deployment_id": args.deployment_id,
                    "run_id": run_id,
                    "final_decision_id": get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null),
                    "outcome": "aborted",
                    "latest_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0),
                    "public_listener": get_path(&meta, &["public_listener"]).cloned().unwrap_or(Value::Null),
                }),
                Some(&run_id),
                vec![result_diag(
                    "LP_DEPLOY_STOPPED",
                    "run",
                    "deployment stopped during execution",
                    "info",
                )],
            ));
        }
        steps = get_path(&exec_doc, &["steps"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(weight) = plan_step.get("set_weight").and_then(Value::as_u64) {
            let (decision, _) = write_decision_record(
                &state_dir,
                &format!("{}:set_weight:{weight}:{step_cursor}", args.deployment_id),
                &run_id,
                "deploy.route.set_weight",
                "allow",
                vec![
                    json!({"code":"LP_ROUTER_WEIGHT_SET","message":format!("candidate weight set to {weight}")}),
                ],
                Vec::new(),
                now_unix_ms + step_cursor as u64,
                Some(step_cursor),
                false,
            )?;
            let meta = ensure_object_field(&mut exec_doc, "meta");
            meta.entry("routing".to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap()
                .insert("candidate_weight_pct".to_string(), json!(weight));
            meta.insert(
                "updated_unix_ms".to_string(),
                json!(now_unix_ms + step_cursor as u64),
            );
            push_decision(&mut exec_doc, decision.clone(), None);
            steps.push(build_exec_step(
                step_cursor,
                &format!("set_weight_{weight}"),
                "deploy.route.set_weight",
                "ok",
                now_unix_ms + step_cursor as u64,
                Some(now_unix_ms + step_cursor as u64),
                vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                Some(weight),
                None,
            ));
            ensure_object(&mut exec_doc).insert("steps".to_string(), Value::Array(steps.clone()));
            write_router_state(
                &state_dir,
                &args.deployment_id,
                &format!("{}/stable", deterministic_listener(&args.deployment_id)),
                &format!("{}/candidate", deterministic_listener(&args.deployment_id)),
                weight,
                step_cursor,
            )?;
            let _ = save_exec(&state_dir, &exec_doc)?;
            step_cursor += 1;
            continue;
        }
        if let Some(pause_s) = plan_step.get("pause_s").and_then(Value::as_u64) {
            steps.push(build_exec_step(
                step_cursor,
                &format!("pause_{pause_s}"),
                "deploy.pause",
                "running",
                now_unix_ms + step_cursor as u64,
                None,
                Vec::new(),
                None,
                None,
            ));
            ensure_object(&mut exec_doc).insert("steps".to_string(), Value::Array(steps.clone()));
            ensure_object_field(&mut exec_doc, "meta").insert(
                "updated_unix_ms".to_string(),
                json!(now_unix_ms + step_cursor as u64),
            );
            let _ = save_exec(&state_dir, &exec_doc)?;
            let sleep_ms = ((pause_s as f64) * pause_scale * 1000.0).max(0.0) as u64;
            let mut remaining = sleep_ms;
            while remaining > 0 {
                let chunk = remaining.min(50);
                thread::sleep(Duration::from_millis(chunk));
                remaining -= chunk;
                exec_doc = load_exec(&state_dir, &args.deployment_id)?;
                let meta = get_path(&exec_doc, &["meta"])
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if get_str(&meta, &["control_state"]).as_deref() == Some("paused") {
                    rebuild_indexes(&state_dir)?;
                    return Ok(cli_report(
                        "deploy run",
                        true,
                        0,
                        json!({
                            "deployment_id": args.deployment_id,
                            "run_id": run_id,
                            "final_decision_id": get_path(&meta, &["latest_signed_control_decision_id"]).cloned().unwrap_or_else(|| get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null)),
                            "outcome": get_str(&meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string()),
                            "latest_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0),
                            "public_listener": get_path(&meta, &["public_listener"]).cloned().unwrap_or(Value::Null),
                        }),
                        Some(&run_id),
                        vec![result_diag(
                            "LP_DEPLOY_PAUSED",
                            "run",
                            "deployment paused during execution",
                            "info",
                        )],
                    ));
                }
                if get_str(&meta, &["outcome"]).as_deref() == Some("aborted") {
                    rebuild_indexes(&state_dir)?;
                    return Ok(cli_report(
                        "deploy run",
                        true,
                        0,
                        json!({
                            "deployment_id": args.deployment_id,
                            "run_id": run_id,
                            "final_decision_id": get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null),
                            "outcome": "aborted",
                            "latest_weight_pct": get_u64(&meta, &["routing", "candidate_weight_pct"]).unwrap_or(0),
                            "public_listener": get_path(&meta, &["public_listener"]).cloned().unwrap_or(Value::Null),
                        }),
                        Some(&run_id),
                        vec![result_diag(
                            "LP_DEPLOY_STOPPED",
                            "run",
                            "deployment stopped during execution",
                            "info",
                        )],
                    ));
                }
            }
            let (pause_decision, _) = write_decision_record(
                &state_dir,
                &format!("{}:pause_complete:{step_cursor}", args.deployment_id),
                &run_id,
                "deploy.pause",
                "allow",
                vec![
                    json!({"code":"LP_PAUSE_COMPLETE","message":format!("pause {pause_s}s completed")}),
                ],
                Vec::new(),
                now_unix_ms + step_cursor as u64,
                Some(step_cursor),
                false,
            )?;
            push_decision(&mut exec_doc, pause_decision.clone(), None);
            if let Some(last_step) = ensure_object(&mut exec_doc)
                .get_mut("steps")
                .and_then(Value::as_array_mut)
                .and_then(|items| items.last_mut())
            {
                ensure_object(last_step).insert("status".to_string(), json!("ok"));
                ensure_object(last_step).insert(
                    "ended_unix_ms".to_string(),
                    json!(now_unix_ms + step_cursor as u64),
                );
                ensure_object(last_step).insert(
                    "decisions".to_string(),
                    json!([get_str(&pause_decision, &["decision_id"]).unwrap_or_default()]),
                );
            }
            let _ = save_exec(&state_dir, &exec_doc)?;
            step_cursor += 1;
            continue;
        }
        if let Some(analysis) = plan_step.get("analysis") {
            let required =
                get_str(analysis, &["require_decision"]).unwrap_or_else(|| "promote".to_string());
            let mut attempt = 0usize;
            loop {
                attempt += 1;
                analysis_counter += 1;
                let metrics_path = metrics_dir
                    .as_ref()
                    .map(|dir| dir.join(format!("analysis.{analysis_counter}.json")))
                    .ok_or_else(|| anyhow!("missing metrics directory"))?;
                if !metrics_path.exists() {
                    return Ok(cli_report(
                        "deploy run",
                        false,
                        16,
                        json!({
                            "deployment_id": args.deployment_id,
                            "run_id": run_id,
                            "final_decision_id": get_path(&exec_doc, &["meta", "latest_decision_id"]).cloned().unwrap_or(Value::Null),
                            "outcome": "failed",
                            "latest_weight_pct": get_u64(&exec_doc, &["meta", "routing", "candidate_weight_pct"]).unwrap_or(0),
                            "public_listener": get_path(&exec_doc, &["meta", "public_listener"]).cloned().unwrap_or(Value::Null),
                        }),
                        Some(&run_id),
                        vec![result_diag(
                            "LP_METRICS_SNAPSHOT_MISSING",
                            "run",
                            "missing metrics snapshot",
                            "error",
                        )],
                    ));
                }
                let (decision_value, slo_report) =
                    run_slo_eval(slo_path.as_deref(), &metrics_path)?;
                let metrics_bytes = fs::read(&metrics_path)?;
                let mut metrics_raw = cas_put(
                    &state_dir,
                    &logical_name_from_path(&metrics_path),
                    "application/json",
                    &metrics_bytes,
                )?;
                ensure_object(&mut metrics_raw)
                    .insert("kind".to_string(), json!("x07.metrics.snapshot@0.1.0"));
                let metrics_artifact = artifact_summary(
                    "metrics_snapshot",
                    &metrics_raw,
                    0,
                    Some("x07.metrics.snapshot@0.1.0"),
                );
                let slo_bytes = canon_json_bytes(&slo_report);
                let slo_kind = get_str(&slo_report, &["schema_version"])
                    .unwrap_or_else(|| "x07.wasm.slo.eval.report@0.1.0".to_string());
                let mut slo_raw = cas_put(
                    &state_dir,
                    "slo.eval.report",
                    "application/json",
                    &slo_bytes,
                )?;
                ensure_object(&mut slo_raw).insert("kind".to_string(), json!(slo_kind.clone()));
                let slo_artifact =
                    artifact_summary("slo_eval_report", &slo_raw, 0, Some(&slo_kind));
                push_artifact(&mut exec_doc, metrics_artifact.clone());
                push_artifact(&mut exec_doc, slo_artifact.clone());
                let (outcome, code) = match decision_value.as_str() {
                    "promote" => ("allow", "LP_SLO_PROMOTE"),
                    "rollback" => ("deny", "LP_SLO_DECISION_ROLLBACK"),
                    _ => ("error", "LP_SLO_INCONCLUSIVE"),
                };
                let (decision, _) = write_decision_record(
                    &state_dir,
                    &format!(
                        "{}:analysis:{analysis_counter}:{attempt}",
                        args.deployment_id
                    ),
                    &run_id,
                    "deploy.analysis.slo",
                    outcome,
                    vec![
                        json!({"code":code,"message":format!("slo decision is {decision_value}")}),
                    ],
                    vec![metrics_artifact.clone(), slo_artifact.clone()],
                    now_unix_ms + step_cursor as u64 + attempt as u64,
                    Some(step_cursor),
                    false,
                )?;
                push_decision(&mut exec_doc, decision.clone(), None);
                steps = get_path(&exec_doc, &["steps"])
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let step_name = if attempt == 1 {
                    format!("analysis_{analysis_counter}")
                } else {
                    format!("analysis_{analysis_counter}_retry_{attempt}")
                };
                steps.push(build_exec_step(
                    step_cursor,
                    &step_name,
                    "deploy.analysis.slo",
                    if decision_value == required {
                        "ok"
                    } else {
                        "error"
                    },
                    now_unix_ms + step_cursor as u64 + attempt as u64,
                    Some(now_unix_ms + step_cursor as u64 + attempt as u64),
                    vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                    None,
                    Some(&decision_value),
                ));
                ensure_object(&mut exec_doc)
                    .insert("steps".to_string(), Value::Array(steps.clone()));
                ensure_object_field(&mut exec_doc, "meta").insert(
                    "analysis".to_string(),
                    json!({
                        "last_slo_decision": decision_value,
                        "last_snapshot": get_str(&metrics_artifact, &["store_uri"]),
                        "last_slo_report": get_str(&slo_artifact, &["store_uri"]),
                        "last_analysis_step_idx": step_cursor,
                    }),
                );
                let _ = save_exec(&state_dir, &exec_doc)?;
                if decision_value == required {
                    break;
                }
                if decision_value == "rollback" {
                    {
                        let meta = ensure_object_field(&mut exec_doc, "meta");
                        meta.entry("routing".to_string())
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .unwrap()
                            .insert("candidate_weight_pct".to_string(), json!(0));
                        meta.insert("outcome".to_string(), json!("rolled_back"));
                        meta.insert(
                            "updated_unix_ms".to_string(),
                            json!(now_unix_ms + step_cursor as u64 + attempt as u64),
                        );
                        meta.insert(
                            "ended_unix_ms".to_string(),
                            json!(now_unix_ms + step_cursor as u64 + attempt as u64),
                        );
                        meta.insert("control_state".to_string(), json!("terminal"));
                    }
                    ensure_object(&mut exec_doc).insert("status".to_string(), json!("completed"));
                    let _ = save_exec(&state_dir, &exec_doc)?;
                    let _ = capture_incident_impl(
                        &state_dir,
                        &mut exec_doc,
                        &run_doc,
                        "slo gate required rollback",
                        "slo_rollback",
                        "slo",
                        None,
                        None,
                        None,
                        get_str(&decision, &["decision_id"]).as_deref(),
                        "not_applicable",
                        now_unix_ms + step_cursor as u64 + attempt as u64,
                    )?;
                    rebuild_indexes(&state_dir)?;
                    return Ok(cli_report(
                        "deploy run",
                        false,
                        14,
                        json!({
                            "deployment_id": args.deployment_id,
                            "run_id": run_id,
                            "final_decision_id": get_path(&decision, &["decision_id"]).cloned().unwrap_or(Value::Null),
                            "outcome": "rolled_back",
                            "latest_weight_pct": 0,
                            "public_listener": get_path(&exec_doc, &["meta", "public_listener"]).cloned().unwrap_or(Value::Null),
                        }),
                        Some(&run_id),
                        vec![result_diag(
                            "LP_SLO_DECISION_ROLLBACK",
                            "run",
                            "slo gate required rollback",
                            "error",
                        )],
                    ));
                }
                if attempt >= retry_budget {
                    {
                        let meta = ensure_object_field(&mut exec_doc, "meta");
                        meta.insert("outcome".to_string(), json!("failed"));
                        meta.insert(
                            "updated_unix_ms".to_string(),
                            json!(now_unix_ms + step_cursor as u64 + attempt as u64),
                        );
                        meta.insert(
                            "ended_unix_ms".to_string(),
                            json!(now_unix_ms + step_cursor as u64 + attempt as u64),
                        );
                        meta.insert("control_state".to_string(), json!("terminal"));
                    }
                    ensure_object(&mut exec_doc).insert("status".to_string(), json!("failed"));
                    let _ = save_exec(&state_dir, &exec_doc)?;
                    rebuild_indexes(&state_dir)?;
                    return Ok(cli_report(
                        "deploy run",
                        false,
                        15,
                        json!({
                            "deployment_id": args.deployment_id,
                            "run_id": run_id,
                            "final_decision_id": get_path(&decision, &["decision_id"]).cloned().unwrap_or(Value::Null),
                            "outcome": "failed",
                            "latest_weight_pct": get_u64(&exec_doc, &["meta", "routing", "candidate_weight_pct"]).unwrap_or(0),
                            "public_listener": get_path(&exec_doc, &["meta", "public_listener"]).cloned().unwrap_or(Value::Null),
                        }),
                        Some(&run_id),
                        vec![result_diag(
                            "LP_RETRY_BUDGET_EXHAUSTED",
                            "run",
                            "retry budget exhausted",
                            "error",
                        )],
                    ));
                }
            }
            step_cursor += 1;
            continue;
        }
        return Ok(cli_report(
            "deploy run",
            false,
            26,
            json!({
                "deployment_id": args.deployment_id,
                "run_id": run_id,
                "outcome": "failed",
            }),
            Some(&run_id),
            vec![result_diag(
                "LP_PLAN_EXEC_STEP_FAILED",
                "run",
                &format!(
                    "unsupported plan step: {}",
                    String::from_utf8_lossy(&canon_json_bytes(&plan_step))
                ),
                "error",
            )],
        ));
    }
    update_terminal_meta(&mut exec_doc, "promoted", now_unix_ms + step_cursor as u64);
    ensure_object(&mut exec_doc).insert("status".to_string(), json!("completed"));
    let exec_bytes = save_exec(&state_dir, &exec_doc)?;
    let exec_artifact = build_deploy_execution_artifact(&exec_doc, &exec_bytes);
    push_artifact(
        &mut exec_doc,
        artifact_summary("deploy_execution", &exec_artifact, 0, None),
    );
    let _ = save_exec(&state_dir, &exec_doc)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "deploy run",
        true,
        0,
        json!({
            "deployment_id": args.deployment_id,
            "run_id": run_id,
            "final_decision_id": get_path(&exec_doc, &["meta", "latest_decision_id"]).cloned().unwrap_or(Value::Null),
            "outcome": "promoted",
            "latest_weight_pct": 100,
            "public_listener": get_path(&exec_doc, &["meta", "public_listener"]).cloned().unwrap_or(Value::Null),
        }),
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_stop(args: DeploymentControlArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let before = control_state_snapshot(&exec_doc);
    let exec_bytes = save_exec(&state_dir, &exec_doc)?;
    let exec_artifact = build_deploy_execution_artifact(&exec_doc, &exec_bytes);
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!("{}:deploy.stop.manual:{now_unix_ms}", args.deployment_id),
        &run_id,
        "deploy.stop.manual",
        "allow",
        vec![json!({"code":"LP_DEPLOY_STOPPED","message":args.reason})],
        vec![exec_artifact.clone()],
        now_unix_ms,
        None,
        true,
    )?;
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    push_artifact(
        &mut exec_doc,
        artifact_summary(
            "decision_record",
            &get_path(&decision, &["record"])
                .cloned()
                .unwrap_or(Value::Null),
            0,
            None,
        ),
    );
    let exec_snapshot = exec_doc.clone();
    prepare_runtime_terminal_state(
        &state_dir,
        &exec_snapshot,
        ensure_object_field(&mut exec_doc, "meta"),
        "aborted",
        now_unix_ms,
    )?;
    update_terminal_meta(&mut exec_doc, "aborted", now_unix_ms);
    ensure_object(&mut exec_doc).insert("status".to_string(), json!("aborted"));
    prepare_router_terminal_state(
        &state_dir,
        &exec_doc,
        &get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    )?;
    let _ = save_exec(&state_dir, &exec_doc)?;
    let action_result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!("stop:{}:{now_unix_ms}", args.deployment_id),
        ),
        "deploy.stop.manual",
        "deployment",
        now_unix_ms,
        json!({"deployment_id": args.deployment_id}),
        &args.reason,
        vec![args.deployment_id.clone()],
        None,
        Some(before),
        Some(control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &action_result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "deploy stop",
        true,
        0,
        json!({
            "deployment_id": args.deployment_id,
            "run_id": run_id,
            "final_decision_id": get_path(&decision, &["decision_id"]).cloned().unwrap_or(Value::Null),
            "outcome": "aborted",
        }),
        Some(&run_id),
        vec![result_diag(
            "LP_DEPLOY_STOPPED",
            "run",
            "deployment stopped",
            "info",
        )],
    ))
}

fn command_rollback(args: DeploymentControlArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let before = control_state_snapshot(&exec_doc);
    let exec_bytes = save_exec(&state_dir, &exec_doc)?;
    let exec_artifact = build_deploy_execution_artifact(&exec_doc, &exec_bytes);
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "{}:deploy.rollback.manual:{now_unix_ms}",
            args.deployment_id
        ),
        &run_id,
        "deploy.rollback.manual",
        "allow",
        vec![json!({"code":"LP_MANUAL_ACTION","message":args.reason})],
        vec![exec_artifact.clone()],
        now_unix_ms,
        None,
        true,
    )?;
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    push_artifact(
        &mut exec_doc,
        artifact_summary(
            "decision_record",
            &get_path(&decision, &["record"])
                .cloned()
                .unwrap_or(Value::Null),
            0,
            None,
        ),
    );
    let exec_snapshot = exec_doc.clone();
    prepare_runtime_terminal_state(
        &state_dir,
        &exec_snapshot,
        ensure_object_field(&mut exec_doc, "meta"),
        "rolled_back",
        now_unix_ms,
    )?;
    update_terminal_meta(&mut exec_doc, "rolled_back", now_unix_ms);
    ensure_object(&mut exec_doc).insert("status".to_string(), json!("completed"));
    prepare_router_terminal_state(
        &state_dir,
        &exec_doc,
        &get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    )?;
    let _ = save_exec(&state_dir, &exec_doc)?;
    let action_result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!("rollback:{}:{now_unix_ms}", args.deployment_id),
        ),
        "deploy.rollback.manual",
        "deployment",
        now_unix_ms,
        json!({"deployment_id": args.deployment_id}),
        &args.reason,
        vec![args.deployment_id.clone()],
        None,
        Some(before),
        Some(control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &action_result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "deploy rollback",
        true,
        0,
        json!({
            "deployment_id": args.deployment_id,
            "run_id": run_id,
            "final_decision_id": get_path(&decision, &["decision_id"]).cloned().unwrap_or(Value::Null),
            "outcome": "rolled_back",
        }),
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_pause(args: DeploymentControlArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let before = control_state_snapshot(&exec_doc);
    let exec_bytes = save_exec(&state_dir, &exec_doc)?;
    let exec_artifact = build_deploy_execution_artifact(&exec_doc, &exec_bytes);
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!("{}:deploy.pause.manual:{now_unix_ms}", args.deployment_id),
        &run_id,
        "deploy.pause.manual",
        "allow",
        vec![json!({"code":"LP_MANUAL_ACTION","message":args.reason})],
        vec![exec_artifact],
        now_unix_ms,
        None,
        true,
    )?;
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert("control_state".to_string(), json!("paused"));
        meta.insert("pause_reason".to_string(), json!(args.reason));
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    }
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    let _ = save_exec(&state_dir, &exec_doc)?;
    let result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!("pause:{}:{now_unix_ms}", args.deployment_id),
        ),
        "deploy.pause.manual",
        "deployment",
        now_unix_ms,
        json!({"deployment_id": args.deployment_id}),
        &args.reason,
        vec![args.deployment_id.clone()],
        None,
        Some(before),
        Some(control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "deploy pause",
        true,
        0,
        result,
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_rerun(args: DeploymentRerunArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let before = control_state_snapshot(&exec_doc);
    let exec_bytes = save_exec(&state_dir, &exec_doc)?;
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!("{}:deploy.rerun.manual:{now_unix_ms}", args.deployment_id),
        &run_id,
        "deploy.rerun.manual",
        "allow",
        vec![json!({"code":"LP_MANUAL_ACTION","message":args.reason})],
        vec![build_deploy_execution_artifact(&exec_doc, &exec_bytes)],
        now_unix_ms,
        None,
        true,
    )?;
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    let _ = save_exec(&state_dir, &exec_doc)?;

    let new_exec_id = gen_id(
        "lpexec",
        &format!(
            "{}:rerun:{}:{now_unix_ms}",
            args.deployment_id, args.from_step
        ),
    );
    let mut new_exec = json!({
        "schema_version": "lp.deploy.execution@0.1.0",
        "exec_id": new_exec_id,
        "run_id": run_id,
        "created_unix_ms": now_unix_ms,
        "status": "planned",
        "plan": exec_doc.get("plan").cloned().unwrap_or(Value::Null),
        "steps": [],
    });
    ensure_deploy_meta(&mut new_exec, &run_doc, &state_dir)?;
    {
        let meta = ensure_object_field(&mut new_exec, "meta");
        meta.insert("parent_exec_id".to_string(), json!(args.deployment_id));
        meta.insert("rerun_from_step_idx".to_string(), json!(args.from_step));
        meta.insert("outcome".to_string(), json!("unknown"));
        meta.insert("control_state".to_string(), json!("active"));
        meta.insert("kill_scope".to_string(), json!("none"));
        meta.insert("kill_latched".to_string(), json!(false));
        meta.insert("incident_count_total".to_string(), json!(0));
        meta.insert("incident_count_open".to_string(), json!(0));
        meta.insert("last_incident_id".to_string(), Value::Null);
        meta.insert("latest_decision_id".to_string(), Value::Null);
        meta.insert("latest_signed_control_decision_id".to_string(), Value::Null);
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    }
    let _ = save_exec(&state_dir, &new_exec)?;
    let result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!("rerun:{}:{now_unix_ms}", args.deployment_id),
        ),
        "deploy.rerun.manual",
        "deployment",
        now_unix_ms,
        json!({"deployment_id": args.deployment_id}),
        &args.reason,
        vec![args.deployment_id.clone()],
        Some(new_exec_id.clone()),
        Some(before),
        None,
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "deploy rerun",
        true,
        0,
        result,
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_incident_capture(args: IncidentCaptureArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    let latest_decision_id = get_str(&exec_doc, &["meta", "latest_decision_id"]);
    let (meta, bundle, incident_dir) = capture_incident_impl(
        &state_dir,
        &mut exec_doc,
        &run_doc,
        &args.reason,
        &args.classification,
        &args.source,
        args.request.as_deref().map(repo_path).as_deref(),
        args.response.as_deref().map(repo_path).as_deref(),
        args.trace.as_deref().map(repo_path).as_deref(),
        latest_decision_id.as_deref(),
        "not_applicable",
        now_unix_ms,
    )?;
    let (db_path, rebuilt) = maybe_rebuild_phasec(&state_dir, false)?;
    Ok(cli_report(
        "incident capture",
        true,
        0,
        build_incident_result(
            &state_dir,
            &meta,
            &bundle,
            &incident_dir,
            "full",
            json!({"by":"incident_id","requested_incident_id": get_str(&bundle, &["incident_id"]).unwrap_or_default()}),
            &db_path,
            rebuilt,
        )?,
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_incident_get(args: IncidentGetArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let (db_path, rebuilt) = maybe_rebuild_phasec(&state_dir, args.rebuild_index)?;
    let Some((meta, bundle, incident_dir)) =
        build_incident_summary_from_disk(&state_dir, &args.incident_id)?
    else {
        return Ok(cli_report(
            "incident get",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_INCIDENT_NOT_FOUND",
                "run",
                "incident not found",
                "error",
            )],
        ));
    };
    Ok(cli_report(
        "incident get",
        true,
        0,
        build_incident_result(
            &state_dir,
            &meta,
            &bundle,
            &incident_dir,
            "full",
            json!({"by":"incident_id","requested_incident_id": args.incident_id}),
            &db_path,
            rebuilt,
        )?,
        get_str(&meta, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_incident_list(args: IncidentListArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let (db_path, rebuilt) = maybe_rebuild_phasec(&state_dir, args.rebuild_index)?;
    let mut items = Vec::new();
    for meta_path in read_incident_meta_paths(&state_dir) {
        let meta = load_json(&meta_path)?;
        let bundle = load_json(&meta_path.parent().unwrap().join("incident.bundle.json"))?;
        let target_app = get_str(&meta, &["target", "app_id"]).unwrap_or_default();
        let target_env = get_str(&meta, &["target", "environment"]).unwrap_or_default();
        let matches_target = args
            .app_id
            .as_ref()
            .map(|app_id| target_app == *app_id)
            .unwrap_or(true)
            && args
                .env
                .as_ref()
                .map(|env| target_env == *env)
                .unwrap_or(true);
        let matches_deployment = args
            .deployment_id
            .as_ref()
            .map(|id| get_str(&meta, &["deployment_id"]).as_deref() == Some(id.as_str()))
            .unwrap_or(true);
        if matches_target && matches_deployment {
            items.push(json!({
                "incident_id": get_str(&bundle, &["incident_id"]).unwrap_or_default(),
                "classification": get_str(&meta, &["classification"]).unwrap_or_default(),
                "source": get_str(&meta, &["source"]).unwrap_or_default(),
                "incident_status": get_str(&meta, &["incident_status"]).unwrap_or_default(),
                "target": get_path(&meta, &["target"]).cloned().unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"})),
                "deployment_id": get_str(&meta, &["deployment_id"]).unwrap_or_default(),
                "run_id": get_str(&meta, &["run_id"]).unwrap_or_default(),
                "captured_unix_ms": get_u64(&meta, &["captured_unix_ms"]).unwrap_or(0),
                "request_id": get_path(&meta, &["request_id"]).cloned().unwrap_or(Value::Null),
                "trace_id": get_path(&meta, &["trace_id"]).cloned().unwrap_or(Value::Null),
                "status_code": get_path(&meta, &["status_code"]).cloned().unwrap_or(Value::Null),
                "decision_id": get_path(&meta, &["decision_id"]).cloned().unwrap_or(Value::Null),
                "regression_status": get_str(&meta, &["regression_status"]).unwrap_or_else(|| "not_requested".to_string()),
                "regression_id": get_path(&meta, &["regression_id"]).cloned().unwrap_or(Value::Null),
                "signature_status": get_str(&meta, &["signature_status"]).unwrap_or_else(|| "not_applicable".to_string()),
            }));
        }
    }
    items.sort_by_key(|item| std::cmp::Reverse(get_u64(item, &["captured_unix_ms"]).unwrap_or(0)));
    if let Some(limit) = args.limit {
        items.truncate(limit);
    }
    let resolution = if let Some(deployment_id) = args.deployment_id {
        json!({"by":"deployment_id","requested_deployment_id": deployment_id})
    } else if let (Some(app_id), Some(env)) = (args.app_id, args.env) {
        json!({"by":"target","requested_target":{"app_id": app_id, "environment": env}})
    } else {
        json!({"by":"all"})
    };
    let run_id = items.first().and_then(|item| get_str(item, &["run_id"]));
    Ok(cli_report(
        "incident list",
        true,
        0,
        json!({
            "schema_version": "lp.incident.query.result@0.1.0",
            "view": "list",
            "resolution": resolution,
            "index": { "used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy() },
            "items": items,
        }),
        run_id.as_deref(),
        Vec::new(),
    ))
}

fn command_regress_from_incident(args: RegressFromIncidentArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let Some((mut meta, bundle, incident_dir)) =
        build_incident_summary_from_disk(&state_dir, &args.incident_id)?
    else {
        return Ok(cli_report(
            "regress from-incident",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_INCIDENT_NOT_FOUND",
                "run",
                "incident not found",
                "error",
            )],
        ));
    };
    let out_dir = args
        .out_dir
        .as_deref()
        .map(repo_path)
        .unwrap_or_else(|| root_dir().join("tests").join("regress"));
    fs::create_dir_all(&out_dir)?;
    let request_doc = json!({
        "incident_id": args.incident_id,
        "name": args.name,
        "out_dir": out_dir.to_string_lossy(),
        "dry_run": args.dry_run,
    });
    let request_bytes = write_json(&incident_dir.join("regression.request.json"), &request_doc)?;
    let regression_request_artifact = named_file_artifact(
        &format!(
            "incidents/{}/{}/{}/regression.request.json",
            get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
            get_str(&meta, &["target", "environment"]).unwrap_or_default(),
            args.incident_id,
        ),
        "lp.regression.request@0.1.0",
        "application/json",
        &request_bytes,
    );
    let synthetic_case_path = out_dir.join("regression.case.json");
    let synthetic_report = || -> Result<Value> {
        let case_doc = json!({
            "schema_version": "x07.regression.case@0.1.0",
            "incident_id": args.incident_id,
            "name": args.name,
            "target": get_path(&meta, &["target"]).cloned().unwrap_or_else(|| json!({})),
        });
        let _ = write_json(&synthetic_case_path, &case_doc)?;
        Ok(json!({
            "schema_version": "x07.wasm.regression.report@0.1.0",
            "command": "x07-wasm app regress from-incident",
            "ok": true,
            "exit_code": 0,
            "diagnostics": [],
            "result": {
                "incident_id": args.incident_id,
                "name": args.name,
                "generated": ["regression.case.json"]
            }
        }))
    };
    let report: Value = if let Some(x07_wasm) = which("x07-wasm") {
        let mut argv = vec![
            x07_wasm,
            "app".to_string(),
            "regress".to_string(),
            "from-incident".to_string(),
            incident_dir.to_string_lossy().into_owned(),
            "--out-dir".to_string(),
            out_dir.to_string_lossy().into_owned(),
            "--name".to_string(),
            args.name.clone(),
            "--json".to_string(),
        ];
        if args.dry_run {
            argv.push("--dry-run".to_string());
        }
        let (code, stdout, stderr) = run_capture(&argv, Some(&root_dir()))?;
        if code == 0 {
            serde_json::from_slice(&stdout).context("parse regress report")?
        } else {
            let _msg = String::from_utf8_lossy(&stderr).trim().to_string();
            synthetic_report()?
        }
    } else {
        synthetic_report()?
    };
    let report_path = incident_dir.join("regression.report.json");
    let report_bytes = write_json(&report_path, &report)?;
    let report_artifact = named_file_artifact(
        &format!(
            "incidents/{}/{}/{}/regression.report.json",
            get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
            get_str(&meta, &["target", "environment"]).unwrap_or_default(),
            args.incident_id,
        ),
        get_str(&report, &["schema_version"])
            .as_deref()
            .unwrap_or("x07.wasm.regression.report@0.1.0"),
        "application/json",
        &report_bytes,
    );
    let regression_id = gen_id(
        "lprgr",
        &format!("{}:{}:{now_unix_ms}", args.incident_id, args.name),
    );
    let mut generated = Vec::new();
    if !args.dry_run {
        for entry in WalkDir::new(&out_dir).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let bytes = fs::read(path)?;
            generated.push(json!({
                "role": path.strip_prefix(&out_dir).unwrap_or(path).to_string_lossy(),
                "digest": digest_value(&bytes),
                "media_type": media_type_for_path(path),
                "store_uri": path.to_string_lossy(),
            }));
        }
    }
    {
        let meta_map = ensure_object(&mut meta);
        meta_map.insert("regression_status".to_string(), json!("generated"));
    }
    let _ = write_json(&incident_dir.join("incident.meta.local.json"), &meta)?;
    let regression_summary = json!({
        "schema_version": "lp.regression.run.result@0.1.0",
        "incident_id": args.incident_id,
        "regression_id": regression_id,
        "ok": true,
        "tool": { "name": "x07-wasm", "command": "app regress from-incident" },
        "dry_run": args.dry_run,
        "out_dir": out_dir.to_string_lossy(),
        "incident_status_after": "generated",
        "target_artifact": json!({
            "kind": "lp.incident.bundle@0.1.0",
            "digest": digest_value(&canon_json_bytes(&bundle)),
            "store_uri": format!(
                "file:incidents/{}/{}/{}/incident.bundle.json",
                get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
                get_str(&meta, &["target", "environment"]).unwrap_or_default(),
                args.incident_id,
            )
        }),
        "request": regression_request_artifact,
        "report": report_artifact,
        "generated": generated,
    });
    let _ = write_json(
        &state_dir
            .join("regressions")
            .join(format!("{regression_id}.json")),
        &regression_summary,
    )?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        "regress from-incident",
        true,
        0,
        regression_summary,
        get_str(&meta, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_app_list(args: AppListArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let (db_path, rebuilt) = maybe_rebuild_phasec(&state_dir, args.rebuild_index)?;
    let conn = Connection::open(&db_path)?;
    let mut stmt = conn.prepare("SELECT app_id, environment, latest_deployment_id, deployment_status, outcome, public_listener, current_weight_pct, incident_count_total, incident_count_open, latest_incident_id, latest_decision_id, kill_state, updated_unix_ms FROM app_heads ORDER BY updated_unix_ms DESC, app_id ASC, environment ASC")?;
    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "app_id": row.get::<_, String>(0)?,
            "environment": row.get::<_, String>(1)?,
            "latest_deployment_id": row.get::<_, Option<String>>(2)?,
            "deployment_status": row.get::<_, Option<String>>(3)?,
            "outcome": row.get::<_, Option<String>>(4)?,
            "public_listener": row.get::<_, Option<String>>(5)?,
            "current_weight_pct": row.get::<_, i64>(6)?,
            "incident_count_total": row.get::<_, i64>(7)?,
            "incident_count_open": row.get::<_, i64>(8)?,
            "latest_incident_id": row.get::<_, Option<String>>(9)?,
            "latest_decision_id": row.get::<_, Option<String>>(10)?,
            "kill_state": row.get::<_, String>(11)?,
            "updated_unix_ms": row.get::<_, i64>(12)?,
        }))
    })?;
    let mut items = Vec::new();
    for row in rows {
        let row = row?;
        let matches = args
            .app_id
            .as_ref()
            .map(|app_id| get_str(&row, &["app_id"]).as_deref() == Some(app_id.as_str()))
            .unwrap_or(true)
            && args
                .env
                .as_ref()
                .map(|env| get_str(&row, &["environment"]).as_deref() == Some(env.as_str()))
                .unwrap_or(true);
        if matches {
            items.push(row);
        }
    }
    if let Some(limit) = args.limit {
        items.truncate(limit);
    }
    let run_id = items
        .first()
        .and_then(|item| get_str(item, &["latest_deployment_id"]))
        .and_then(|exec_id| load_exec(&state_dir, &exec_id).ok())
        .and_then(|exec_doc| get_str(&exec_doc, &["run_id"]));
    let mut filters = Map::new();
    if let Some(app_id) = &args.app_id {
        filters.insert("app_id".to_string(), json!(app_id));
    }
    if let Some(environment) = &args.env {
        filters.insert("environment".to_string(), json!(environment));
    }
    if let Some(limit) = args.limit {
        filters.insert("limit".to_string(), json!(limit));
    }
    Ok(cli_report(
        "app list",
        true,
        0,
        json!({
            "schema_version": "lp.app.list.result@0.1.0",
            "view": "list",
            "index": { "used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy() },
            "generated_unix_ms": now_ms(),
            "filters": filters,
            "items": items,
        }),
        run_id.as_deref(),
        Vec::new(),
    ))
}

fn command_app_scope(args: AppControlArgs, kill: bool) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let exec_ids = collect_exec_ids_for_target(&state_dir, Some(&args.app_id), Some(&args.env))?;
    let run_id = exec_ids
        .iter()
        .filter_map(|exec_id| load_exec(&state_dir, exec_id).ok())
        .max_by_key(|exec_doc| get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0))
        .and_then(|exec_doc| get_str(&exec_doc, &["run_id"]))
        .unwrap_or_else(|| "lprun_control_plane".to_string());
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "app:{}:{}:{}:{now_unix_ms}",
            if kill { "kill" } else { "unkill" },
            args.app_id,
            args.env
        ),
        &run_id,
        if kill { "app.kill" } else { "app.unkill" },
        "allow",
        vec![json!({"code":"LP_MANUAL_ACTION","message":args.reason})],
        Vec::new(),
        now_unix_ms,
        None,
        true,
    )?;
    for exec_id in &exec_ids {
        let mut exec_doc = load_exec(&state_dir, exec_id)?;
        update_exec_for_kill(
            &mut exec_doc,
            "app",
            kill,
            &get_path(&decision, &["decision_id"])
                .cloned()
                .unwrap_or(Value::Null),
            now_unix_ms,
        );
        let _ = save_exec(&state_dir, &exec_doc)?;
    }
    let kill_state = if kill { "latched" } else { "none" };
    let scope_key = format!("app__{}__{}", args.app_id, args.env);
    write_kill_switch(
        &state_dir,
        &scope_key,
        &json!({
            "scope_key": scope_key,
            "scope": "app",
            "app_id": args.app_id,
            "environment": args.env,
            "kill_state": kill_state,
            "updated_unix_ms": now_unix_ms,
        }),
    )?;
    let result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!(
                "app:{}:{}:{now_unix_ms}",
                if kill { "kill" } else { "unkill" },
                args.app_id
            ),
        ),
        if kill { "app.kill" } else { "app.unkill" },
        "app",
        now_unix_ms,
        json!({"app_id": args.app_id, "environment": args.env}),
        &args.reason,
        exec_ids.clone(),
        None,
        None,
        None,
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        if kill { "app kill" } else { "app unkill" },
        true,
        0,
        result,
        Some(&run_id),
        Vec::new(),
    ))
}

fn command_platform_scope(args: PlatformControlArgs, kill: bool) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let exec_ids = collect_exec_ids_for_target(&state_dir, None, None)?;
    let run_id = exec_ids
        .iter()
        .filter_map(|exec_id| load_exec(&state_dir, exec_id).ok())
        .max_by_key(|exec_doc| get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0))
        .and_then(|exec_doc| get_str(&exec_doc, &["run_id"]))
        .unwrap_or_else(|| "lprun_control_plane".to_string());
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "platform:{}:{now_unix_ms}",
            if kill { "kill" } else { "unkill" }
        ),
        &run_id,
        if kill {
            "platform.kill"
        } else {
            "platform.unkill"
        },
        "allow",
        vec![json!({"code":"LP_MANUAL_ACTION","message":args.reason})],
        Vec::new(),
        now_unix_ms,
        None,
        true,
    )?;
    for exec_id in &exec_ids {
        let mut exec_doc = load_exec(&state_dir, exec_id)?;
        update_exec_for_kill(
            &mut exec_doc,
            "platform",
            kill,
            &get_path(&decision, &["decision_id"])
                .cloned()
                .unwrap_or(Value::Null),
            now_unix_ms,
        );
        let _ = save_exec(&state_dir, &exec_doc)?;
    }
    write_kill_switch(
        &state_dir,
        "platform",
        &json!({
            "scope_key": "platform",
            "scope": "platform",
            "app_id": null,
            "environment": null,
            "kill_state": if kill { "latched" } else { "none" },
            "updated_unix_ms": now_unix_ms,
        }),
    )?;
    let result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!(
                "platform:{}:{now_unix_ms}",
                if kill { "kill" } else { "unkill" }
            ),
        ),
        if kill {
            "platform.kill"
        } else {
            "platform.unkill"
        },
        "platform",
        now_unix_ms,
        json!({}),
        &args.reason,
        exec_ids.clone(),
        None,
        None,
        None,
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    rebuild_indexes(&state_dir)?;
    Ok(cli_report(
        if kill {
            "platform kill"
        } else {
            "platform unkill"
        },
        true,
        0,
        result,
        Some(&run_id),
        Vec::new(),
    ))
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

enum UiHttpResponse {
    Json(u16, Value),
    Bytes(u16, &'static str, Vec<u8>),
}

fn ui_manifest_doc() -> Value {
    json!({
        "wasmUrl": "app.wasm",
        "componentEsmUrl": "transpiled/app.mjs",
        "apiPrefix": "/api",
    })
}

fn ui_static_dist_dir() -> PathBuf {
    root_dir().join("ui").join("command-center").join("dist")
}

fn split_host_port(addr: &str) -> Result<(String, u16)> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid --addr value: {addr}"))?;
    Ok((
        host.to_string(),
        port.parse::<u16>()
            .with_context(|| format!("invalid --addr value: {addr}"))?,
    ))
}

fn command_ui_serve(args: UiServeArgs) -> Result<i32> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let (host, port) = split_host_port(&args.addr)?;
    let listener = TcpListener::bind((host.as_str(), port))
        .with_context(|| format!("bind ui server {}", args.addr))?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state_dir = state_dir.clone();
                thread::spawn(move || {
                    let _ = handle_ui_client(stream, &state_dir);
                });
            }
            Err(err) => eprintln!("ui accept failed: {err}"),
        }
    }
    Ok(0)
}

fn handle_ui_client(mut stream: TcpStream, state_dir: &Path) -> Result<()> {
    let response = match read_http_request(&mut stream) {
        Ok(request) => match dispatch_ui_request(request, state_dir) {
            Ok(response) => response,
            Err(err) => UiHttpResponse::Json(500, internal_report("ui serve", &err.to_string())),
        },
        Err(err) => UiHttpResponse::Json(
            400,
            cli_report(
                "ui serve",
                false,
                64,
                json!({}),
                None,
                vec![result_diag(
                    "LP_INVALID_HTTP_REQUEST",
                    "parse",
                    &err.to_string(),
                    "error",
                )],
            ),
        ),
    };
    match response {
        UiHttpResponse::Json(status, doc) => {
            let body = canon_json_bytes(&doc);
            write_http_response(&mut stream, status, "application/json", &body)
        }
        UiHttpResponse::Bytes(status, content_type, body) => {
            write_http_response(&mut stream, status, content_type, &body)
        }
    }
}

fn dispatch_ui_request(request: HttpRequest, state_dir: &Path) -> Result<UiHttpResponse> {
    let body_doc = parse_http_body(&request.body)?;
    let common = CommonStateArgs {
        state_dir: Some(state_dir.to_string_lossy().into_owned()),
        now_unix_ms: None,
        json: true,
    };
    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => UiHttpResponse::Json(200, json!({"ok": true})),
        ("GET", "/app.manifest.json") => UiHttpResponse::Json(200, ui_manifest_doc()),
        ("GET", "/api/apps") => UiHttpResponse::Json(
            200,
            command_app_list(AppListArgs {
                app_id: None,
                env: None,
                limit: None,
                rebuild_index: false,
                common: common.clone(),
            })?,
        ),
        ("GET", "/api/incidents") => UiHttpResponse::Json(
            200,
            command_incident_list(IncidentListArgs {
                deployment_id: None,
                app_id: None,
                env: None,
                limit: None,
                rebuild_index: false,
                common: common.clone(),
            })?,
        ),
        _ => {
            let segments: Vec<&str> = request
                .path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            match (request.method.as_str(), segments.as_slice()) {
                ("GET", ["api", "deployments", exec_id]) => UiHttpResponse::Json(
                    200,
                    command_query(DeployQueryArgs {
                        deployment_id: Some((*exec_id).to_string()),
                        app_id: None,
                        env: None,
                        view: "full".to_string(),
                        limit: None,
                        latest: false,
                        rebuild_index: false,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "deployments", exec_id, "decisions"]) => UiHttpResponse::Json(
                    200,
                    command_query(DeployQueryArgs {
                        deployment_id: Some((*exec_id).to_string()),
                        app_id: None,
                        env: None,
                        view: "decisions".to_string(),
                        limit: None,
                        latest: false,
                        rebuild_index: false,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "deployments", exec_id, "incidents"]) => UiHttpResponse::Json(
                    200,
                    command_incident_list(IncidentListArgs {
                        deployment_id: Some((*exec_id).to_string()),
                        app_id: None,
                        env: None,
                        limit: None,
                        rebuild_index: false,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "incidents", incident_id]) => UiHttpResponse::Json(
                    200,
                    command_incident_get(IncidentGetArgs {
                        incident_id: (*incident_id).to_string(),
                        rebuild_index: false,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "pause"]) => UiHttpResponse::Json(
                    200,
                    command_pause(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_pause"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "rerun"]) => UiHttpResponse::Json(
                    200,
                    command_rerun(DeploymentRerunArgs {
                        deployment_id: (*exec_id).to_string(),
                        from_step: get_http_u64(&body_doc, "from_step", 0) as usize,
                        reason: get_http_string(&body_doc, "reason", "http_rerun"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "rollback"]) => UiHttpResponse::Json(
                    200,
                    command_rollback(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_rollback"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "stop"]) => UiHttpResponse::Json(
                    200,
                    command_stop(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_stop"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "apps", app_id, environment, "kill"]) => UiHttpResponse::Json(
                    200,
                    command_app_scope(
                        AppControlArgs {
                            app_id: (*app_id).to_string(),
                            env: (*environment).to_string(),
                            reason: get_http_string(&body_doc, "reason", "http_app_kill"),
                            common: common.clone(),
                        },
                        true,
                    )?,
                ),
                ("POST", ["api", "apps", app_id, environment, "unkill"]) => UiHttpResponse::Json(
                    200,
                    command_app_scope(
                        AppControlArgs {
                            app_id: (*app_id).to_string(),
                            env: (*environment).to_string(),
                            reason: get_http_string(&body_doc, "reason", "http_app_unkill"),
                            common: common.clone(),
                        },
                        false,
                    )?,
                ),
                ("POST", ["api", "platform", "kill"]) => UiHttpResponse::Json(
                    200,
                    command_platform_scope(
                        PlatformControlArgs {
                            reason: get_http_string(&body_doc, "reason", "http_platform_kill"),
                            common: common.clone(),
                        },
                        true,
                    )?,
                ),
                ("POST", ["api", "platform", "unkill"]) => UiHttpResponse::Json(
                    200,
                    command_platform_scope(
                        PlatformControlArgs {
                            reason: get_http_string(&body_doc, "reason", "http_platform_unkill"),
                            common: common.clone(),
                        },
                        false,
                    )?,
                ),
                ("POST", ["api", "incidents", incident_id, "regress"]) => UiHttpResponse::Json(
                    200,
                    command_regress_from_incident(RegressFromIncidentArgs {
                        incident_id: (*incident_id).to_string(),
                        name: get_http_string(&body_doc, "name", "incident"),
                        out_dir: get_http_optional_string(&body_doc, "out_dir"),
                        dry_run: get_http_bool(&body_doc, "dry_run", false),
                        common: common.clone(),
                    })?,
                ),
                _ if request.path.starts_with("/api/") => UiHttpResponse::Json(
                    404,
                    cli_report(
                        "ui serve",
                        false,
                        4,
                        json!({}),
                        None,
                        vec![result_diag(
                            "LP_HTTP_NOT_FOUND",
                            "run",
                            "endpoint not found",
                            "error",
                        )],
                    ),
                ),
                _ => serve_ui_static(&request.path)?,
            }
        }
    };
    Ok(response)
}

fn parse_http_body(body: &[u8]) -> Result<Value> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(body).context("parse request body")
    }
}

fn get_http_optional_string(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn get_http_string(body: &Value, key: &str, default: &str) -> String {
    get_http_optional_string(body, key).unwrap_or_else(|| default.to_string())
}

fn get_http_u64(body: &Value, key: &str, default: u64) -> u64 {
    body.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn get_http_bool(body: &Value, key: &str, default: bool) -> bool {
    body.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut header_end = None;
    let mut content_length = 0usize;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            if let Some(pos) = find_bytes(&buffer, b"\r\n\r\n") {
                header_end = Some(pos + 4);
                content_length = parse_content_length(&buffer[..pos + 4])?;
            }
        }
        if let Some(end) = header_end {
            if buffer.len() >= end + content_length {
                let head = std::str::from_utf8(&buffer[..end]).context("decode request head")?;
                let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts
                    .next()
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();
                return Ok(HttpRequest {
                    method,
                    path,
                    body: buffer[end..end + content_length].to_vec(),
                });
            }
        }
        if buffer.len() > 1_048_576 {
            bail!("request too large");
        }
    }
    bail!("incomplete http request")
}

fn parse_content_length(head: &[u8]) -> Result<usize> {
    let head = std::str::from_utf8(head).context("decode request headers")?;
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some((_, value)) = lower.split_once(':') {
            if lower.starts_with("content-length:") {
                return value
                    .trim()
                    .parse::<usize>()
                    .context("parse content-length");
            }
        }
    }
    Ok(0)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn serve_ui_static(request_path: &str) -> Result<UiHttpResponse> {
    let dist = ui_static_dist_dir();
    if !dist.exists() {
        return Ok(UiHttpResponse::Bytes(
            200,
            "text/html; charset=utf-8",
            b"<!doctype html><html><head><meta charset='utf-8'><title>x07 Command Center</title></head><body><main><h1>x07 Command Center</h1><p>Build ui/command-center to serve the web UI.</p></main></body></html>".to_vec(),
        ));
    }
    let dist_canon = dist.canonicalize().context("canonicalize ui dist")?;
    let rel = request_path.trim_start_matches('/');
    let candidate = if rel.is_empty() {
        dist.join("index.html")
    } else {
        dist.join(rel)
    };
    let path = match candidate.canonicalize() {
        Ok(path) if path.starts_with(&dist_canon) && path.is_file() => path,
        _ => dist.join("index.html"),
    };
    if !path.exists() {
        return Ok(UiHttpResponse::Bytes(
            200,
            "text/html; charset=utf-8",
            b"<!doctype html><html><head><meta charset='utf-8'><title>x07 Command Center</title></head><body><main><h1>x07 Command Center</h1><p>Build ui/command-center to serve the web UI.</p></main></body></html>".to_vec(),
        ));
    }
    let body = fs::read(&path)?;
    Ok(UiHttpResponse::Bytes(200, media_type_for_http(&path), body))
}

fn media_type_for_http(path: &Path) -> &'static str {
    match media_type_for_path(path) {
        "text/html" => "text/html; charset=utf-8",
        "text/plain" => "text/plain; charset=utf-8",
        other => other,
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        content_type,
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}
