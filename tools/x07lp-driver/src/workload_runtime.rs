use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use sha2::Digest as _;

use super::{
    CommonStateArgs, cli_report, digest_value, get_path, get_str, load_json,
    load_target_profile_doc, now_ms, repo_path, resolve_state_dir, resolve_target_name,
    result_diag, which, write_json,
};

const WORKLOAD_ACCEPT_SCHEMA: &str = "lp.workload.accept.internal@0.1.0";
const WORKLOAD_DEPLOYMENT_SCHEMA: &str = "lp.workload.deployment.internal@0.1.0";
const DEFAULT_K8S_PUBLIC_BASE_URL: &str = "http://127.0.0.1";

#[derive(Args, Debug)]
pub(crate) struct WorkloadArgs {
    #[command(subcommand)]
    command: WorkloadCommand,
}

#[derive(Subcommand, Debug)]
enum WorkloadCommand {
    Accept(WorkloadAcceptArgs),
    Run(WorkloadRunArgs),
    Query(WorkloadQueryArgs),
    Stop(WorkloadStopArgs),
    Bindings(WorkloadBindingsArgs),
}

#[derive(Args, Debug)]
struct WorkloadAcceptArgs {
    #[arg(long)]
    pack_manifest: String,
    #[arg(long)]
    runtime_pack: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct WorkloadRunArgs {
    #[arg(long)]
    workload: Option<String>,
    #[arg(long)]
    pack_manifest: Option<String>,
    #[arg(long)]
    runtime_pack: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    profile: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct WorkloadQueryArgs {
    #[arg(long)]
    workload: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long, default_value = "summary")]
    view: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct WorkloadStopArgs {
    #[arg(long)]
    workload: String,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct WorkloadBindingsArgs {
    #[arg(long)]
    workload: String,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Debug, Clone)]
struct LoadedWorkloadPack {
    pack_dir: PathBuf,
    pack_manifest_path: PathBuf,
    runtime_pack_path: PathBuf,
    public_manifest: Value,
    runtime_pack: Value,
    workload: Value,
    binding_requirements: Value,
    topology: Vec<Value>,
}

#[derive(Debug, Clone)]
struct K8sCellDeployment {
    cell_key: String,
    image: String,
    container_port: u16,
    health_path: String,
    deployment_name: String,
    service_name: String,
    ingress_name: String,
    route_path: String,
}

pub(crate) fn command_workload(args: WorkloadArgs) -> Result<Value> {
    match args.command {
        WorkloadCommand::Accept(args) => command_accept(args),
        WorkloadCommand::Run(args) => command_run(args),
        WorkloadCommand::Query(args) => command_query(args),
        WorkloadCommand::Stop(args) => command_stop(args),
        WorkloadCommand::Bindings(args) => command_bindings(args),
    }
}

pub(crate) fn k8s_target_reachable(profile: &Value) -> bool {
    if get_str(profile, &["kind"]).as_deref() != Some("k8s") {
        return false;
    }
    kubectl_run(
        profile,
        None,
        &["get", "namespace", "default", "-o", "name"],
    )
    .is_ok()
}

fn command_accept(args: WorkloadAcceptArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let loaded = load_workload_pack(args.pack_manifest.as_str(), args.runtime_pack.as_deref())?;
    let workload_id = workload_id(&loaded.workload)?;
    let target_profile = args
        .target
        .as_deref()
        .map(required_k8s_target_profile)
        .transpose()?;
    let binding_status = binding_status_doc(
        &workload_id,
        &loaded.binding_requirements,
        target_profile.as_ref(),
    )?;
    let accepted_doc = accepted_doc(&loaded, target_profile.as_ref(), &binding_status)?;
    let accepted_path = accepted_path(&state_dir, &workload_id);
    let _ = write_json(&accepted_path, &accepted_doc)?;
    Ok(cli_report(
        "workload accept",
        true,
        0,
        json!({
            "accepted_path": accepted_path.to_string_lossy(),
            "workload": loaded.workload,
            "bindings": binding_status,
            "topology": loaded.topology,
            "target": target_profile.as_ref().map(target_summary).unwrap_or(Value::Null),
        }),
        None,
        Vec::new(),
    ))
}

fn command_run(args: WorkloadRunArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let accepted = load_or_accept_workload_for_run(&state_dir, &args)?;
    let workload_id = workload_id(
        accepted
            .get("workload")
            .ok_or_else(|| anyhow!("missing workload"))?,
    )?;
    let target_profile = resolve_k8s_target_for_workload(
        args.target.as_deref(),
        accepted.get("target").and_then(Value::as_object),
    )?;
    let namespace = get_str(&target_profile, &["default_namespace"])
        .ok_or_else(|| anyhow!("k8s target missing default_namespace"))?;
    ensure_k8s_namespace(&target_profile, &namespace)?;

    let runtime_pack = accepted
        .get("runtime_pack")
        .ok_or_else(|| anyhow!("missing runtime_pack"))?;
    let cells = deployable_cells(&workload_id, runtime_pack)?;
    if cells.is_empty() {
        bail!("workload {workload_id} does not contain deployable k8s cells");
    }
    let deployment_id = format!("wlrun_{}_{}", sanitize_k8s_name(&workload_id), now_ms());
    let manifest_dir = manifests_dir(&state_dir, &deployment_id);
    fs::create_dir_all(&manifest_dir)
        .with_context(|| format!("mkdir {}", manifest_dir.display()))?;

    let public_base_url = std::env::var("X07LP_K8S_PUBLIC_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_K8S_PUBLIC_BASE_URL.to_string());
    let profile_id = args
        .profile
        .clone()
        .or_else(|| select_topology_profile_id(accepted.get("topology").and_then(Value::as_array)))
        .unwrap_or_else(|| "k8s".to_string());

    let mut diagnostics = Vec::new();
    let binding_status = binding_status_doc(
        &workload_id,
        accepted.get("binding_requirements").unwrap_or(&Value::Null),
        Some(&target_profile),
    )?;
    for item in binding_status
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if item.get("status").and_then(Value::as_str) == Some("pending") {
            let message = item
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("binding is pending");
            diagnostics.push(result_diag(
                "LP_WORKLOAD_BINDING_PENDING",
                "run",
                message,
                "warning",
            ));
        }
    }

    let manifest_paths = write_k8s_manifests(
        &manifest_dir,
        &namespace,
        &deployment_id,
        &workload_id,
        &public_base_url,
        &cells,
    )?;
    for path in &manifest_paths {
        kubectl_apply_path(&target_profile, path)?;
    }
    for cell in &cells {
        kubectl_rollout_status(&target_profile, &namespace, &cell.deployment_name)?;
    }

    let deployment_doc = live_deployment_doc(
        &deployment_id,
        &workload_id,
        &profile_id,
        &namespace,
        &public_base_url,
        &target_profile,
        &cells,
    )?;
    let deployment_path = deployment_path(&state_dir, &deployment_id);
    let _ = write_json(&deployment_path, &deployment_doc)?;
    let _ = write_json(
        &head_path(&state_dir, &workload_id),
        &json!({
            "schema_version": "lp.workload.head.internal@0.1.0",
            "workload_id": workload_id,
            "deployment_id": deployment_id,
            "updated_unix_ms": now_ms(),
        }),
    )?;

    Ok(cli_report(
        "workload run",
        true,
        0,
        json!({
            "deployment_id": deployment_doc.get("deployment_id").cloned().unwrap_or(Value::Null),
            "workload_id": workload_id,
            "target": target_summary(&target_profile),
            "namespace": namespace,
            "bindings": binding_status,
            "deployment": deployment_doc,
            "manifests_dir": manifest_dir.to_string_lossy(),
        }),
        None,
        diagnostics,
    ))
}

fn command_query(args: WorkloadQueryArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    if let Some(workload_id) = args.workload.as_deref() {
        let accepted = load_accepted_doc(&state_dir, workload_id)?;
        let target_profile = resolve_k8s_target_for_workload(
            args.target.as_deref(),
            accepted.get("target").and_then(Value::as_object),
        )
        .ok();
        let bindings = binding_status_doc(
            workload_id,
            accepted.get("binding_requirements").unwrap_or(&Value::Null),
            target_profile.as_ref(),
        )?;
        let deployment = current_deployment_doc(&state_dir, workload_id)?
            .map(|doc| refresh_deployment_doc(target_profile.as_ref(), doc))
            .transpose()?;
        return Ok(cli_report(
            "workload query",
            true,
            0,
            json!({
                "workload": accepted.get("workload").cloned().unwrap_or(Value::Null),
                "bindings": bindings,
                "topology": accepted.get("topology").cloned().unwrap_or_else(|| json!([])),
                "deployment": deployment.unwrap_or(Value::Null),
                "target": target_profile.as_ref().map(target_summary).unwrap_or_else(|| accepted.get("target").cloned().unwrap_or(Value::Null)),
                "view": args.view,
            }),
            None,
            Vec::new(),
        ));
    }

    let mut items = Vec::new();
    for path in accepted_docs(&state_dir)? {
        let accepted = load_json(&path)?;
        let workload = accepted.get("workload").cloned().unwrap_or(Value::Null);
        let workload_id = workload_id(&workload)?;
        let display_name =
            get_str(&workload, &["display_name"]).unwrap_or_else(|| workload_id.clone());
        let cell_count = workload
            .get("cells")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        let deployment = current_deployment_doc(&state_dir, &workload_id)?;
        let health = deployment
            .as_ref()
            .and_then(|doc| get_str(doc, &["health"]))
            .unwrap_or_else(|| "unknown".to_string());
        let latest_release_id = deployment
            .as_ref()
            .and_then(|doc| get_str(doc, &["deployment_id"]))
            .map(Value::String)
            .unwrap_or(Value::Null);
        let updated_unix_ms = deployment
            .as_ref()
            .and_then(|doc| get_path(doc, &["updated_unix_ms"]).and_then(Value::as_u64))
            .or_else(|| get_path(&accepted, &["accepted_unix_ms"]).and_then(Value::as_u64))
            .unwrap_or(0);
        items.push(json!({
            "workload_id": workload_id,
            "display_name": display_name,
            "cell_count": cell_count.max(1),
            "latest_release_id": latest_release_id,
            "health": health,
            "updated_unix_ms": updated_unix_ms,
        }));
    }
    items.sort_by_key(|item| get_str(item, &["workload_id"]).unwrap_or_default());
    Ok(cli_report(
        "workload query",
        true,
        0,
        json!({
            "schema_version": "lp.workload.list.result@0.1.0",
            "view": "list",
            "filters": {},
            "items": items,
            "generated_unix_ms": now_ms(),
        }),
        None,
        Vec::new(),
    ))
}

fn command_stop(args: WorkloadStopArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let deployment = current_deployment_doc(&state_dir, &args.workload)?
        .ok_or_else(|| anyhow!("no active workload deployment for {}", args.workload))?;
    let target_profile = resolve_k8s_target_for_workload(
        args.target.as_deref(),
        deployment.get("target").and_then(Value::as_object),
    )?;
    let namespace =
        get_str(&deployment, &["namespace"]).ok_or_else(|| anyhow!("missing namespace"))?;
    let cells = deployment
        .get("cells")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for cell in &cells {
        for (kind, key) in [
            ("ingress", "ingress_name"),
            ("service", "service_name"),
            ("deployment", "deployment_name"),
        ] {
            if let Some(name) = cell.get(key).and_then(Value::as_str) {
                let _ = kubectl_delete_named(&target_profile, &namespace, kind, name);
            }
        }
    }
    let mut stopped = deployment;
    if let Some(map) = stopped.as_object_mut() {
        map.insert("status".to_string(), json!("stopped"));
        map.insert("health".to_string(), json!("unknown"));
        map.insert("updated_unix_ms".to_string(), json!(now_ms()));
        if let Some(cells) = map.get_mut("cells").and_then(Value::as_array_mut) {
            for cell in cells {
                if let Some(cell_map) = cell.as_object_mut() {
                    cell_map.insert("status".to_string(), json!("stopped"));
                    cell_map.insert("replicas".to_string(), json!(0));
                    cell_map.insert("ready_replicas".to_string(), json!(0));
                }
            }
        }
    }
    let deployment_id =
        get_str(&stopped, &["deployment_id"]).ok_or_else(|| anyhow!("missing deployment_id"))?;
    let _ = write_json(&deployment_path(&state_dir, &deployment_id), &stopped)?;
    Ok(cli_report(
        "workload stop",
        true,
        0,
        json!({
            "workload_id": args.workload,
            "deployment": stopped,
        }),
        None,
        Vec::new(),
    ))
}

fn command_bindings(args: WorkloadBindingsArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let accepted = load_accepted_doc(&state_dir, &args.workload)?;
    let target_profile = resolve_k8s_target_for_workload(
        args.target.as_deref(),
        accepted.get("target").and_then(Value::as_object),
    )
    .ok();
    Ok(cli_report(
        "workload bindings",
        true,
        0,
        binding_status_doc(
            &args.workload,
            accepted.get("binding_requirements").unwrap_or(&Value::Null),
            target_profile.as_ref(),
        )?,
        None,
        Vec::new(),
    ))
}

fn workload_root(state_dir: &Path) -> PathBuf {
    state_dir.join("workloads")
}

fn accepted_dir(state_dir: &Path) -> PathBuf {
    workload_root(state_dir).join("accepted")
}

fn deployments_dir(state_dir: &Path) -> PathBuf {
    workload_root(state_dir).join("deployments")
}

fn heads_dir(state_dir: &Path) -> PathBuf {
    workload_root(state_dir).join("heads")
}

fn manifests_dir(state_dir: &Path, deployment_id: &str) -> PathBuf {
    workload_root(state_dir)
        .join("manifests")
        .join(deployment_id)
}

fn accepted_path(state_dir: &Path, workload_id: &str) -> PathBuf {
    accepted_dir(state_dir).join(format!("{workload_id}.json"))
}

fn deployment_path(state_dir: &Path, deployment_id: &str) -> PathBuf {
    deployments_dir(state_dir).join(format!("{deployment_id}.json"))
}

fn head_path(state_dir: &Path, workload_id: &str) -> PathBuf {
    heads_dir(state_dir).join(format!("{workload_id}.json"))
}

fn load_accepted_doc(state_dir: &Path, workload_id: &str) -> Result<Value> {
    load_json(&accepted_path(state_dir, workload_id))
}

fn current_deployment_doc(state_dir: &Path, workload_id: &str) -> Result<Option<Value>> {
    let path = head_path(state_dir, workload_id);
    if !path.exists() {
        return Ok(None);
    }
    let head = load_json(&path)?;
    let deployment_id =
        get_str(&head, &["deployment_id"]).ok_or_else(|| anyhow!("missing deployment_id"))?;
    let path = deployment_path(state_dir, &deployment_id);
    if !path.exists() {
        return Ok(None);
    }
    load_json(&path).map(Some)
}

fn accepted_docs(state_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = accepted_dir(state_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn load_or_accept_workload_for_run(state_dir: &Path, args: &WorkloadRunArgs) -> Result<Value> {
    if let Some(workload_id) = args.workload.as_deref() {
        return load_accepted_doc(state_dir, workload_id);
    }
    let pack_manifest = args
        .pack_manifest
        .as_deref()
        .ok_or_else(|| anyhow!("workload run requires --workload or --pack-manifest"))?;
    let loaded = load_workload_pack(pack_manifest, args.runtime_pack.as_deref())?;
    let workload_id = workload_id(&loaded.workload)?;
    let target_profile = args
        .target
        .as_deref()
        .map(required_k8s_target_profile)
        .transpose()?;
    let bindings = binding_status_doc(
        &workload_id,
        &loaded.binding_requirements,
        target_profile.as_ref(),
    )?;
    let accepted = accepted_doc(&loaded, target_profile.as_ref(), &bindings)?;
    let _ = write_json(&accepted_path(state_dir, &workload_id), &accepted)?;
    Ok(accepted)
}

fn accepted_doc(
    loaded: &LoadedWorkloadPack,
    target_profile: Option<&Value>,
    binding_status: &Value,
) -> Result<Value> {
    let runtime_pack_bytes = fs::read(&loaded.runtime_pack_path)
        .with_context(|| format!("read {}", loaded.runtime_pack_path.display()))?;
    Ok(json!({
        "schema_version": WORKLOAD_ACCEPT_SCHEMA,
        "accepted_unix_ms": now_ms(),
        "target": target_profile.map(target_summary).unwrap_or(Value::Null),
        "pack_dir": loaded.pack_dir.to_string_lossy(),
        "pack_manifest_path": loaded.pack_manifest_path.to_string_lossy(),
        "runtime_pack_path": loaded.runtime_pack_path.to_string_lossy(),
        "manifest_digest": digest_value(&runtime_pack_bytes),
        "public_manifest": loaded.public_manifest,
        "runtime_pack": loaded.runtime_pack,
        "workload": loaded.workload,
        "binding_requirements": loaded.binding_requirements,
        "binding_status": binding_status,
        "topology": loaded.topology,
    }))
}

fn load_workload_pack(
    pack_manifest: &str,
    runtime_pack: Option<&str>,
) -> Result<LoadedWorkloadPack> {
    let pack_manifest_path = repo_path(pack_manifest);
    let pack_dir = pack_manifest_path
        .parent()
        .ok_or_else(|| anyhow!("workload pack manifest must have a parent directory"))?
        .to_path_buf();
    let runtime_pack_path = runtime_pack
        .map(repo_path)
        .unwrap_or_else(|| pack_dir.join("x07.workload.pack.json"));
    let public_manifest = load_json(&pack_manifest_path)?;
    let runtime_pack = load_json(&runtime_pack_path)?;
    if get_str(&public_manifest, &["schema_version"]).as_deref()
        != Some("lp.workload.pack.manifest@0.1.0")
    {
        bail!("invalid workload pack manifest schema_version");
    }
    if get_str(&runtime_pack, &["schema_version"]).as_deref() != Some("x07.workload.pack@0.1.0") {
        bail!("invalid runtime workload pack schema_version");
    }
    let workload = load_relative_json(&pack_dir, &runtime_pack, "workload")?;
    let binding_requirements =
        load_relative_json(&pack_dir, &runtime_pack, "binding_requirements")?;
    let mut topology = Vec::new();
    for item in runtime_pack
        .get("topology")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let rel = item
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("runtime pack topology entry missing path"))?;
        topology.push(load_json(&pack_dir.join(rel))?);
    }
    let public_id = get_str(&public_manifest, &["workload_id"])
        .ok_or_else(|| anyhow!("missing public workload_id"))?;
    let runtime_id = get_str(&runtime_pack, &["workload_id"])
        .ok_or_else(|| anyhow!("missing runtime workload_id"))?;
    let described_id = get_str(&workload, &["workload_id"])
        .ok_or_else(|| anyhow!("missing workload description id"))?;
    if public_id != runtime_id || public_id != described_id {
        bail!("workload ids do not match across workload pack documents");
    }
    Ok(LoadedWorkloadPack {
        pack_dir,
        pack_manifest_path,
        runtime_pack_path,
        public_manifest,
        runtime_pack,
        workload,
        binding_requirements,
        topology,
    })
}

fn load_relative_json(pack_dir: &Path, runtime_pack: &Value, key: &str) -> Result<Value> {
    let rel = runtime_pack
        .get(key)
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("runtime pack missing {key}.path"))?;
    load_json(&pack_dir.join(rel))
}

fn workload_id(workload: &Value) -> Result<String> {
    get_str(workload, &["workload_id"]).ok_or_else(|| anyhow!("missing workload_id"))
}

fn target_summary(profile: &Value) -> Value {
    json!({
        "name": get_str(profile, &["name"]).unwrap_or_default(),
        "kind": get_str(profile, &["kind"]).unwrap_or_default(),
        "cluster_ref": get_path(profile, &["cluster_ref"]).cloned().unwrap_or(Value::Null),
        "default_namespace": get_path(profile, &["default_namespace"]).cloned().unwrap_or(Value::Null),
        "runtime_provider": get_path(profile, &["runtime_provider"]).cloned().unwrap_or(Value::Null),
        "routing_provider": get_path(profile, &["routing_provider"]).cloned().unwrap_or(Value::Null),
    })
}

fn required_k8s_target_profile(explicit: &str) -> Result<Value> {
    let name =
        resolve_target_name(Some(explicit))?.ok_or_else(|| anyhow!("missing workload target"))?;
    let profile = load_target_profile_doc(&name)?;
    if get_str(&profile, &["kind"]).as_deref() != Some("k8s") {
        bail!("target {name} is not a k8s target");
    }
    Ok(profile)
}

fn resolve_k8s_target_for_workload(
    explicit: Option<&str>,
    stored_target: Option<&serde_json::Map<String, Value>>,
) -> Result<Value> {
    if let Some(name) = explicit.filter(|value| !value.trim().is_empty()) {
        return required_k8s_target_profile(name);
    }
    if let Some(name) = stored_target
        .and_then(|target| target.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return required_k8s_target_profile(name);
    }
    let name =
        resolve_target_name(None)?.ok_or_else(|| anyhow!("no active k8s target selected"))?;
    required_k8s_target_profile(&name)
}

fn deployable_cells(workload_id: &str, runtime_pack: &Value) -> Result<Vec<K8sCellDeployment>> {
    let mut cells = Vec::new();
    for cell in runtime_pack
        .get("cells")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(executable) = cell.get("executable") else {
            continue;
        };
        if executable.get("kind").and_then(Value::as_str) != Some("oci_image") {
            continue;
        }
        if cell.get("ingress_kind").and_then(Value::as_str) != Some("http") {
            continue;
        }
        let cell_key = cell
            .get("cell_key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("deployable runtime pack cell missing cell_key"))?
            .to_string();
        let image = executable
            .get("image")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("deployable runtime pack cell missing executable.image"))?
            .to_string();
        let container_port = executable
            .get("container_port")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                anyhow!("deployable runtime pack cell missing executable.container_port")
            })? as u16;
        let health_path = executable
            .get("health_path")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        let stem = sanitize_k8s_name(&format!("{workload_id}-{cell_key}"));
        cells.push(K8sCellDeployment {
            cell_key: cell_key.clone(),
            image,
            container_port,
            health_path,
            deployment_name: format!("{stem}-deploy"),
            service_name: format!("{stem}-svc"),
            ingress_name: format!("{stem}-ing"),
            route_path: format!(
                "/{}",
                sanitize_route_path(&format!("{}/{}", workload_id, cell_key))
            ),
        });
    }
    Ok(cells)
}

fn write_k8s_manifests(
    manifest_dir: &Path,
    namespace: &str,
    deployment_id: &str,
    workload_id: &str,
    public_base_url: &str,
    cells: &[K8sCellDeployment],
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let ingress_class_name = std::env::var("X07LP_K8S_INGRESS_CLASS")
        .ok()
        .filter(|value| !value.trim().is_empty());
    for cell in cells {
        let deployment_doc = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": cell.deployment_name,
                "namespace": namespace,
                "labels": {
                    "x07.io/workload-id": workload_id,
                    "x07.io/deployment-id": deployment_id,
                    "x07.io/cell-key": cell.cell_key,
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "x07.io/workload-id": workload_id,
                        "x07.io/cell-key": cell.cell_key,
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "x07.io/workload-id": workload_id,
                            "x07.io/deployment-id": deployment_id,
                            "x07.io/cell-key": cell.cell_key,
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": sanitize_k8s_name(&cell.cell_key),
                            "image": cell.image,
                            "imagePullPolicy": "IfNotPresent",
                            "ports": [{
                                "name": "http",
                                "containerPort": cell.container_port
                            }],
                            "readinessProbe": {
                                "httpGet": {
                                    "path": cell.health_path,
                                    "port": cell.container_port
                                }
                            }
                        }]
                    }
                }
            }
        });
        let service_doc = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": cell.service_name,
                "namespace": namespace,
                "labels": {
                    "x07.io/workload-id": workload_id,
                    "x07.io/deployment-id": deployment_id,
                    "x07.io/cell-key": cell.cell_key,
                }
            },
            "spec": {
                "selector": {
                    "x07.io/workload-id": workload_id,
                    "x07.io/cell-key": cell.cell_key,
                },
                "ports": [{
                    "name": "http",
                    "port": cell.container_port,
                    "targetPort": cell.container_port
                }]
            }
        });
        let mut ingress_doc = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": cell.ingress_name,
                "namespace": namespace,
                "labels": {
                    "x07.io/workload-id": workload_id,
                    "x07.io/deployment-id": deployment_id,
                    "x07.io/cell-key": cell.cell_key,
                },
                "annotations": {
                    "x07.io/public-base-url": public_base_url,
                }
            },
            "spec": {
                "rules": [{
                    "http": {
                        "paths": [{
                            "path": cell.route_path,
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": cell.service_name,
                                    "port": {
                                        "number": cell.container_port
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        });
        if let Some(class_name) = ingress_class_name.as_deref() {
            ingress_doc
                .get_mut("spec")
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert("ingressClassName".to_string(), json!(class_name));
        }
        for (prefix, doc) in [
            ("deployment", deployment_doc),
            ("service", service_doc),
            ("ingress", ingress_doc),
        ] {
            let path = manifest_dir.join(format!("{prefix}.{}.json", cell.cell_key));
            let _ = write_json(&path, &doc)?;
            paths.push(path);
        }
    }
    Ok(paths)
}

fn live_deployment_doc(
    deployment_id: &str,
    workload_id: &str,
    profile_id: &str,
    namespace: &str,
    public_base_url: &str,
    target_profile: &Value,
    cells: &[K8sCellDeployment],
) -> Result<Value> {
    let mut cell_docs = Vec::new();
    let mut all_ready = true;
    let mut any_failed = false;
    for cell in cells {
        let status = kubectl_get_json(
            target_profile,
            namespace,
            &[
                "get",
                "deployment",
                cell.deployment_name.as_str(),
                "-o",
                "json",
            ],
        )?;
        let replicas = status
            .get("status")
            .and_then(|value| value.get("replicas"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let ready_replicas = status
            .get("status")
            .and_then(|value| value.get("readyReplicas"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let status_label = if ready_replicas >= replicas.max(1) {
            "running"
        } else if deployment_failed(&status) {
            any_failed = true;
            "failed"
        } else {
            all_ready = false;
            "degraded"
        };
        if status_label != "running" {
            all_ready = false;
        }
        cell_docs.push(json!({
            "cell_key": cell.cell_key,
            "deployment_name": cell.deployment_name,
            "service_name": cell.service_name,
            "ingress_name": cell.ingress_name,
            "image": cell.image,
            "container_port": cell.container_port,
            "route_path": cell.route_path,
            "route_url": format!("{}{}", public_base_url.trim_end_matches('/'), cell.route_path),
            "replicas": replicas,
            "ready_replicas": ready_replicas,
            "status": status_label,
        }));
    }
    let health = if any_failed {
        "failed"
    } else if all_ready {
        "healthy"
    } else {
        "degraded"
    };
    Ok(json!({
        "schema_version": WORKLOAD_DEPLOYMENT_SCHEMA,
        "deployment_id": deployment_id,
        "workload_id": workload_id,
        "profile_id": profile_id,
        "namespace": namespace,
        "status": if health == "failed" { "failed" } else { "running" },
        "health": health,
        "public_base_url": public_base_url,
        "target": target_summary(target_profile),
        "cells": cell_docs,
        "created_unix_ms": now_ms(),
        "updated_unix_ms": now_ms(),
    }))
}

fn refresh_deployment_doc(target_profile: Option<&Value>, mut deployment: Value) -> Result<Value> {
    if get_str(&deployment, &["status"]).as_deref() == Some("stopped") {
        if let Some(map) = deployment.as_object_mut() {
            map.insert("updated_unix_ms".to_string(), json!(now_ms()));
            if let Some(cells) = map.get_mut("cells").and_then(Value::as_array_mut) {
                for cell in cells {
                    if let Some(cell_map) = cell.as_object_mut() {
                        cell_map.insert("status".to_string(), json!("stopped"));
                        cell_map.insert("replicas".to_string(), json!(0));
                        cell_map.insert("ready_replicas".to_string(), json!(0));
                    }
                }
            }
        }
        return Ok(deployment);
    }
    let Some(target_profile) = target_profile else {
        return Ok(deployment);
    };
    let namespace =
        get_str(&deployment, &["namespace"]).ok_or_else(|| anyhow!("missing namespace"))?;
    let public_base_url = get_str(&deployment, &["public_base_url"])
        .unwrap_or_else(|| DEFAULT_K8S_PUBLIC_BASE_URL.to_string());
    let mut cell_docs = Vec::new();
    let mut all_ready = true;
    let mut any_failed = false;
    for cell in deployment
        .get("cells")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let deployment_name = cell
            .get("deployment_name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("deployment cell missing deployment_name"))?;
        let status = match kubectl_get_json(
            target_profile,
            &namespace,
            &["get", "deployment", deployment_name, "-o", "json"],
        ) {
            Ok(status) => status,
            Err(err) if is_k8s_not_found(&err) => {
                let mut refreshed = cell.clone();
                if let Some(map) = refreshed.as_object_mut() {
                    map.insert("replicas".to_string(), json!(0));
                    map.insert("ready_replicas".to_string(), json!(0));
                    map.insert("status".to_string(), json!("stopped"));
                }
                cell_docs.push(refreshed);
                all_ready = false;
                continue;
            }
            Err(err) => return Err(err),
        };
        let replicas = status
            .get("status")
            .and_then(|value| value.get("replicas"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let ready_replicas = status
            .get("status")
            .and_then(|value| value.get("readyReplicas"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let status_label = if ready_replicas >= replicas.max(1) {
            "running"
        } else if deployment_failed(&status) {
            any_failed = true;
            "failed"
        } else {
            all_ready = false;
            "degraded"
        };
        if status_label != "running" {
            all_ready = false;
        }
        let mut refreshed = cell.clone();
        if let Some(map) = refreshed.as_object_mut() {
            map.insert("replicas".to_string(), json!(replicas));
            map.insert("ready_replicas".to_string(), json!(ready_replicas));
            map.insert("status".to_string(), json!(status_label));
            if let Some(route_path) = map.get("route_path").and_then(Value::as_str) {
                map.insert(
                    "route_url".to_string(),
                    json!(format!(
                        "{}{}",
                        public_base_url.trim_end_matches('/'),
                        route_path
                    )),
                );
            }
        }
        cell_docs.push(refreshed);
    }
    let health = if any_failed {
        "failed"
    } else if all_ready {
        "healthy"
    } else {
        "degraded"
    };
    if let Some(map) = deployment.as_object_mut() {
        map.insert("cells".to_string(), Value::Array(cell_docs));
        map.insert(
            "status".to_string(),
            json!(deployment_status_for_health(health)),
        );
        map.insert("health".to_string(), json!(health));
        map.insert("updated_unix_ms".to_string(), json!(now_ms()));
    }
    Ok(deployment)
}

fn deployment_status_for_health(health: &str) -> &str {
    match health {
        "failed" => "failed",
        "unknown" => "stopped",
        _ => "running",
    }
}

fn is_k8s_not_found(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("NotFound") || message.contains("not found")
}

fn deployment_failed(status: &Value) -> bool {
    status
        .get("status")
        .and_then(|value| value.get("conditions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|condition| {
            condition.get("type").and_then(Value::as_str) == Some("Progressing")
                && condition.get("status").and_then(Value::as_str) == Some("False")
        })
}

fn binding_status_doc(
    workload_id: &str,
    binding_requirements: &Value,
    target_profile: Option<&Value>,
) -> Result<Value> {
    let namespace = target_profile.and_then(|profile| get_str(profile, &["default_namespace"]));
    let mut items = Vec::new();
    for binding in binding_requirements
        .get("bindings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = binding
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("binding requirement missing name"))?;
        let kind = binding
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("binding requirement missing kind"))?;
        let (status, provider_kind, message, last_checked_unix_ms) =
            match (target_profile, namespace.as_deref()) {
                (Some(profile), Some(namespace))
                    if get_str(profile, &["kind"]).as_deref() == Some("k8s") =>
                {
                    k8s_binding_status(profile, namespace, name, kind)?
                }
                _ => (
                    "pending".to_string(),
                    None,
                    Some("binding target not selected".to_string()),
                    None,
                ),
            };
        let mut item = json!({
            "binding_id": sanitize_binding_id(workload_id, name),
            "name": name,
            "kind": kind,
            "status": status,
        });
        if let Some(provider_kind) = provider_kind {
            item["provider_kind"] = json!(provider_kind);
        }
        if let Some(message) = message {
            item["message"] = json!(message);
        }
        if let Some(last_checked_unix_ms) = last_checked_unix_ms {
            item["last_checked_unix_ms"] = json!(last_checked_unix_ms);
        }
        items.push(item);
    }
    Ok(json!({
        "schema_version": "lp.binding.status.result@0.1.0",
        "view": "detail",
        "items": items,
        "generated_unix_ms": now_ms(),
    }))
}

fn k8s_binding_status(
    target_profile: &Value,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<(String, Option<String>, Option<String>, Option<u64>)> {
    let provider_kind = Some("lp.impl.bindings.k8s_v1".to_string());
    let checked = Some(now_ms());
    if kind == "otlp" {
        if get_str(target_profile, &["telemetry_collector_hint"]).is_some() {
            return Ok((
                "ready".to_string(),
                provider_kind,
                Some("telemetry collector hint present on target profile".to_string()),
                checked,
            ));
        }
        return Ok((
            "pending".to_string(),
            provider_kind,
            Some("target profile does not advertise telemetry_collector_hint".to_string()),
            checked,
        ));
    }
    let object_name = sanitize_k8s_name(name);
    let (resource_kind, exists_message, pending_message) = if kind == "secret" {
        (
            "secret",
            "matching Kubernetes Secret is present",
            "create a Kubernetes Secret to satisfy this binding",
        )
    } else {
        (
            "service",
            "matching Kubernetes Service is present",
            "create or attach a Kubernetes Service to satisfy this binding",
        )
    };
    if kubectl_exists(target_profile, namespace, resource_kind, &object_name)? {
        Ok((
            "ready".to_string(),
            provider_kind,
            Some(exists_message.to_string()),
            checked,
        ))
    } else {
        Ok((
            "pending".to_string(),
            provider_kind,
            Some(pending_message.to_string()),
            checked,
        ))
    }
}

fn sanitize_binding_id(workload_id: &str, name: &str) -> String {
    format!(
        "binding.{}.{}",
        sanitize_k8s_name(workload_id).replace('-', "_"),
        sanitize_k8s_name(name).replace('-', "_"),
    )
}

fn select_topology_profile_id(items: Option<&Vec<Value>>) -> Option<String> {
    let items = items?;
    for item in items {
        if get_str(item, &["target_kind"]).as_deref() == Some("k8s") {
            return get_str(item, &["profile_id"]);
        }
    }
    items
        .first()
        .and_then(|item| get_str(item, &["profile_id"]))
}

fn sanitize_k8s_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_dash = false;
    for ch in value.chars() {
        let lower = ch.to_ascii_lowercase();
        let is_valid = lower.is_ascii_lowercase() || lower.is_ascii_digit();
        if is_valid {
            out.push(lower);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("x07");
    }
    if out.len() > 52 {
        let digest = hex::encode(sha2::Sha256::digest(value.as_bytes()));
        out.truncate(52);
        while out.ends_with('-') {
            out.pop();
        }
        out.push('-');
        out.push_str(&digest[..10]);
    }
    out
}

fn sanitize_route_path(value: &str) -> String {
    value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(sanitize_k8s_name)
        .collect::<Vec<_>>()
        .join("/")
}

fn ensure_k8s_namespace(target_profile: &Value, namespace: &str) -> Result<()> {
    if kubectl_exists(target_profile, "", "namespace", namespace)? {
        return Ok(());
    }
    let _ = kubectl_run(target_profile, None, &["create", "namespace", namespace])?;
    Ok(())
}

fn kubectl_exists(target_profile: &Value, namespace: &str, kind: &str, name: &str) -> Result<bool> {
    match kubectl_run(
        target_profile,
        if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        },
        &["get", kind, name, "-o", "name"],
    ) {
        Ok(_) => Ok(true),
        Err(err)
            if err.to_string().contains("NotFound") || err.to_string().contains("not found") =>
        {
            Ok(false)
        }
        Err(err) if err.to_string().contains("Error from server") => Ok(false),
        Err(err) => Err(err),
    }
}

fn kubectl_apply_path(target_profile: &Value, path: &Path) -> Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("invalid manifest path: {}", path.display()))?;
    let _ = kubectl_run(target_profile, None, &["apply", "-f", path_str])?;
    Ok(())
}

fn kubectl_rollout_status(
    target_profile: &Value,
    namespace: &str,
    deployment_name: &str,
) -> Result<()> {
    let _ = kubectl_run(
        target_profile,
        Some(namespace),
        &[
            "rollout",
            "status",
            "deployment",
            deployment_name,
            "--timeout=120s",
        ],
    )?;
    Ok(())
}

fn kubectl_delete_named(
    target_profile: &Value,
    namespace: &str,
    kind: &str,
    name: &str,
) -> Result<()> {
    let _ = kubectl_run(
        target_profile,
        Some(namespace),
        &["delete", kind, name, "--ignore-not-found=true"],
    )?;
    Ok(())
}

fn kubectl_get_json(target_profile: &Value, namespace: &str, args: &[&str]) -> Result<Value> {
    let stdout = kubectl_run(
        target_profile,
        if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        },
        args,
    )?;
    serde_json::from_slice(&stdout).context("parse kubectl json")
}

fn kubectl_run(target_profile: &Value, namespace: Option<&str>, args: &[&str]) -> Result<Vec<u8>> {
    let (bin, mut prefix) = resolve_kubectl_command();
    if let Some(context) =
        get_str(target_profile, &["cluster_ref"]).filter(|value| !value.is_empty())
    {
        prefix.push("--context".to_string());
        prefix.push(context);
    }
    if let Some(namespace) = namespace.filter(|value| !value.is_empty()) {
        prefix.push("-n".to_string());
        prefix.push(namespace.to_string());
    }
    prefix.extend(args.iter().map(|value| value.to_string()));
    let output = Command::new(&bin)
        .args(&prefix)
        .output()
        .with_context(|| format!("spawn {} {}", bin, prefix.join(" ")))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    bail!(
        "kubectl command failed: {} {}: {}",
        bin,
        prefix.join(" "),
        detail
    );
}

fn resolve_kubectl_command() -> (String, Vec<String>) {
    if let Ok(raw) = std::env::var("X07LP_KUBECTL")
        && !raw.trim().is_empty()
    {
        let mut parts = raw.split_whitespace();
        if let Some(bin) = parts.next() {
            return (bin.to_string(), parts.map(ToOwned::to_owned).collect());
        }
    }
    if let Some(bin) = which("kubectl") {
        return (bin, Vec::new());
    }
    if let Some(bin) = which("k3s") {
        return (bin, vec!["kubectl".to_string()]);
    }
    ("kubectl".to_string(), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::{binding_status_doc, deployable_cells, sanitize_k8s_name, sanitize_route_path};
    use serde_json::json;

    #[test]
    fn sanitize_k8s_name_normalizes_and_truncates() {
        assert_eq!(sanitize_k8s_name("Svc/API Cell"), "svc-api-cell");
        let long = "VeryLongName/Repeated__".repeat(8);
        let normalized = sanitize_k8s_name(&long);
        assert!(normalized.len() <= 63);
        assert!(!normalized.starts_with('-'));
        assert!(!normalized.ends_with('-'));
    }

    #[test]
    fn sanitize_route_path_drops_empty_segments() {
        assert_eq!(sanitize_route_path("/Svc API//Primary/"), "svc-api/primary");
    }

    #[test]
    fn deployable_cells_extracts_http_oci_cells() {
        let runtime_pack = json!({
            "cells": [
                {
                    "cell_key": "primary",
                    "ingress_kind": "http",
                    "executable": {
                        "kind": "oci_image",
                        "image": "ghcr.io/example/api:1.0.0",
                        "container_port": 8080,
                        "health_path": "/ready"
                    }
                },
                {
                    "cell_key": "worker",
                    "ingress_kind": "none",
                    "executable": {
                        "kind": "oci_image",
                        "image": "ghcr.io/example/worker:1.0.0",
                        "container_port": 9000
                    }
                }
            ]
        });
        let cells = deployable_cells("svc.api", &runtime_pack).expect("cells");
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].cell_key, "primary");
        assert_eq!(cells[0].route_path, "/svc-api/primary");
        assert_eq!(cells[0].container_port, 8080);
    }

    #[test]
    fn binding_status_without_target_stays_pending() {
        let bindings = json!({
            "bindings": [
                {
                    "name": "db.primary",
                    "kind": "postgres"
                },
                {
                    "name": "obj.documents",
                    "kind": "s3"
                }
            ]
        });
        let status = binding_status_doc("svc.api", &bindings, None).expect("status");
        let items = status
            .get("items")
            .and_then(|value| value.as_array())
            .expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["status"], "pending");
        assert_eq!(items[0]["message"], "binding target not selected");
        assert_eq!(items[0]["binding_id"], "binding.svc_api.db_primary");
    }
}
