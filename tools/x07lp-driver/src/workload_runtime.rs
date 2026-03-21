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
    Reconcile(WorkloadReconcileArgs),
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
struct WorkloadReconcileArgs {
    #[arg(long)]
    workload: String,
    #[arg(long)]
    target: Option<String>,
    #[arg(long, default_value_t = 1)]
    cycles: u64,
    #[arg(long, default_value_t = 5)]
    interval_seconds: u64,
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
struct K8sBindingProbeHint {
    binding_ref: String,
    binding_kind: String,
}

#[derive(Debug, Clone)]
struct K8sProbe {
    probe_kind: String,
    path: Option<String>,
    port: Option<u16>,
    command: Vec<String>,
    initial_delay_seconds: Option<u64>,
    period_seconds: Option<u64>,
    timeout_seconds: Option<u64>,
    success_threshold: Option<u64>,
    failure_threshold: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct K8sProbeSet {
    readiness: Option<K8sProbe>,
    liveness: Option<K8sProbe>,
    startup: Option<K8sProbe>,
}

#[derive(Debug, Clone)]
struct K8sEventRuntime {
    binding_ref: String,
    topic: String,
    consumer_group: Option<String>,
    ack_mode: Option<String>,
    max_in_flight: Option<u64>,
    drain_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct K8sScheduleRuntime {
    cron: String,
    timezone: Option<String>,
    concurrency_policy: Option<String>,
    retry_limit: Option<u64>,
    start_deadline_seconds: Option<u64>,
    suspend: bool,
}

#[derive(Debug, Clone)]
struct K8sRollout {
    strategy: String,
    max_unavailable: Option<String>,
    max_surge: Option<String>,
    canary_percent: Option<u64>,
}

#[derive(Debug, Clone)]
struct K8sAutoscaling {
    min_replicas: u64,
    max_replicas: u64,
    target_cpu_utilization: Option<u64>,
    target_inflight: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum K8sCellResourceKind {
    Deployment,
    CronJob,
}

#[derive(Debug, Clone)]
struct K8sCellDeployment {
    cell_key: String,
    cell_kind: String,
    ingress_kind: String,
    runtime_class: String,
    scale_class: String,
    topology_group: String,
    binding_refs: Vec<String>,
    binding_probe_hints: Vec<K8sBindingProbeHint>,
    image: String,
    container_port: Option<u16>,
    deployment_name: Option<String>,
    service_name: Option<String>,
    ingress_name: Option<String>,
    cronjob_name: Option<String>,
    hpa_name: Option<String>,
    route_path: Option<String>,
    probes: K8sProbeSet,
    event: Option<K8sEventRuntime>,
    schedule: Option<K8sScheduleRuntime>,
    rollout: Option<K8sRollout>,
    autoscaling: Option<K8sAutoscaling>,
}

impl K8sCellDeployment {
    fn resource_kind(&self) -> K8sCellResourceKind {
        if self.ingress_kind == "schedule" {
            K8sCellResourceKind::CronJob
        } else {
            K8sCellResourceKind::Deployment
        }
    }

    fn desired_state(&self) -> &'static str {
        if self
            .schedule
            .as_ref()
            .map(|schedule| schedule.suspend)
            .unwrap_or(false)
        {
            "paused"
        } else {
            "running"
        }
    }
}

pub(crate) fn command_workload(args: WorkloadArgs) -> Result<Value> {
    match args.command {
        WorkloadCommand::Accept(args) => command_accept(args),
        WorkloadCommand::Run(args) => command_run(args),
        WorkloadCommand::Query(args) => command_query(args),
        WorkloadCommand::Reconcile(args) => command_reconcile(args),
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
        if let Some(deployment_name) = cell.deployment_name.as_deref() {
            kubectl_rollout_status(&target_profile, &namespace, deployment_name)?;
        }
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
        let workload_doc = render_workload_result_doc(
            accepted.get("workload").unwrap_or(&Value::Null),
            deployment.as_ref(),
            target_profile.as_ref(),
            &args.view,
        )?;
        return Ok(cli_report(
            "workload query",
            true,
            0,
            json!({
                "workload": workload_doc,
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
        let target_profile = resolve_k8s_target_for_workload(
            None,
            accepted.get("target").and_then(Value::as_object),
        )
        .ok();
        let display_name =
            get_str(&workload, &["display_name"]).unwrap_or_else(|| workload_id.clone());
        let cell_count = workload
            .get("cells")
            .and_then(Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        let deployment = current_deployment_doc(&state_dir, &workload_id)?
            .map(|doc| refresh_deployment_doc(target_profile.as_ref(), doc))
            .transpose()?;
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
        let desired_state = desired_state_for_deployment(deployment.as_ref());
        let observed_state = observed_state_for_deployment(deployment.as_ref());
        let active_target_id = active_target_id(
            deployment.as_ref().and_then(|doc| doc.get("target")),
            target_profile.as_ref(),
        );
        items.push(json!({
            "workload_id": workload_id,
            "display_name": display_name,
            "cell_count": cell_count.max(1),
            "latest_release_id": latest_release_id,
            "health": health,
            "desired_state": desired_state,
            "observed_state": observed_state,
            "active_target_id": active_target_id,
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

fn command_reconcile(args: WorkloadReconcileArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let cycles = args.cycles.max(1);
    let mut state_doc = Value::Null;
    for cycle in 0..cycles {
        state_doc = reconcile_workload_once(&state_dir, &args.workload, args.target.as_deref())?;
        if cycle + 1 < cycles {
            std::thread::sleep(std::time::Duration::from_secs(args.interval_seconds.max(1)));
        }
    }
    Ok(cli_report(
        "workload reconcile",
        true,
        0,
        state_doc,
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
            ("horizontalpodautoscaler", "hpa_name"),
            ("cronjob", "cronjob_name"),
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
        map.insert("desired_state".to_string(), json!("stopped"));
        map.insert("observed_state".to_string(), json!("stopped"));
        map.insert("observed_health".to_string(), json!("unknown"));
        map.insert("updated_unix_ms".to_string(), json!(now_ms()));
        if let Some(cells) = map.get_mut("cells").and_then(Value::as_array_mut) {
            for cell in cells {
                if let Some(cell_map) = cell.as_object_mut() {
                    cell_map.insert("status".to_string(), json!("stopped"));
                    cell_map.insert("desired_state".to_string(), json!("stopped"));
                    cell_map.insert("observed_state".to_string(), json!("stopped"));
                    cell_map.insert("observed_health".to_string(), json!("unknown"));
                    cell_map.insert("replicas".to_string(), json!(0));
                    cell_map.insert("ready_replicas".to_string(), json!(0));
                    cell_map.insert("active_jobs".to_string(), json!(0));
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

fn reconcile_workload_once(
    state_dir: &Path,
    workload_id: &str,
    target_override: Option<&str>,
) -> Result<Value> {
    let accepted = load_accepted_doc(state_dir, workload_id)?;
    let target_profile = resolve_k8s_target_for_workload(
        target_override,
        accepted.get("target").and_then(Value::as_object),
    )
    .ok();
    let refreshed = match current_deployment_doc(state_dir, workload_id)? {
        Some(deployment) => Some(reconcile_deployment_doc(
            state_dir,
            target_profile.as_ref(),
            deployment,
        )?),
        None => None,
    };
    workload_state_result_doc(workload_id, target_profile.as_ref(), refreshed.as_ref())
}

fn reconcile_deployment_doc(
    state_dir: &Path,
    target_profile: Option<&Value>,
    deployment: Value,
) -> Result<Value> {
    let Some(target_profile) = target_profile else {
        return Ok(deployment);
    };
    if get_str(&deployment, &["status"]).as_deref() == Some("stopped") {
        return Ok(deployment);
    }
    let namespace =
        get_str(&deployment, &["namespace"]).ok_or_else(|| anyhow!("missing namespace"))?;
    ensure_k8s_namespace(target_profile, &namespace)?;
    let deployment_id =
        get_str(&deployment, &["deployment_id"]).ok_or_else(|| anyhow!("missing deployment_id"))?;
    for path in manifest_paths(&manifests_dir(state_dir, &deployment_id))? {
        kubectl_apply_path(target_profile, &path)?;
    }
    for cell in deployment
        .get("cells")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(deployment_name) = cell.get("deployment_name").and_then(Value::as_str) {
            kubectl_rollout_status(target_profile, &namespace, deployment_name)?;
        }
    }
    let refreshed = refresh_deployment_doc(Some(target_profile), deployment)?;
    let _ = write_json(&deployment_path(state_dir, &deployment_id), &refreshed)?;
    Ok(refreshed)
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

fn manifest_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        bail!("missing workload manifest directory: {}", dir.display());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) == Some("json") {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        bail!("no workload manifests found in {}", dir.display());
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
        let ingress_kind = cell
            .get("ingress_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("deployable runtime pack cell missing ingress_kind"))?
            .to_string();
        if !matches!(ingress_kind.as_str(), "http" | "event" | "schedule") {
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
        let container_port = parse_optional_u16(
            executable.get("container_port"),
            "deployable runtime pack cell executable.container_port",
        )?;
        if ingress_kind == "http" && container_port.is_none() {
            bail!("http deployable runtime pack cell missing executable.container_port");
        }
        let stem = sanitize_k8s_name(&format!("{workload_id}-{cell_key}"));
        let autoscaling = parse_autoscaling(cell)?;
        cells.push(K8sCellDeployment {
            cell_key: cell_key.clone(),
            cell_kind: required_cell_string(cell, "cell_kind")?,
            ingress_kind: ingress_kind.clone(),
            runtime_class: required_cell_string(cell, "runtime_class")?,
            scale_class: required_cell_string(cell, "scale_class")?,
            topology_group: required_cell_string(cell, "topology_group")?,
            binding_refs: parse_string_array(cell.get("binding_refs")),
            binding_probe_hints: parse_binding_probe_hints(cell)?,
            image,
            container_port,
            deployment_name: if ingress_kind == "schedule" {
                None
            } else {
                Some(format!("{stem}-deploy"))
            },
            service_name: if ingress_kind == "http" {
                Some(format!("{stem}-svc"))
            } else {
                None
            },
            ingress_name: if ingress_kind == "http" {
                Some(format!("{stem}-ing"))
            } else {
                None
            },
            cronjob_name: if ingress_kind == "schedule" {
                Some(format!("{stem}-cron"))
            } else {
                None
            },
            hpa_name: if ingress_kind != "schedule"
                && autoscaling
                    .as_ref()
                    .and_then(|item| item.target_cpu_utilization)
                    .is_some()
            {
                Some(format!("{stem}-hpa"))
            } else {
                None
            },
            route_path: if ingress_kind == "http" {
                Some(format!(
                    "/{}",
                    sanitize_route_path(&format!("{}/{}", workload_id, cell_key))
                ))
            } else {
                None
            },
            probes: parse_probe_set(cell)?,
            event: parse_event_runtime(cell)?,
            schedule: parse_schedule_runtime(cell)?,
            rollout: parse_rollout(cell)?,
            autoscaling,
        });
    }
    Ok(cells)
}

fn required_cell_string(cell: &Value, key: &str) -> Result<String> {
    cell.get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("deployable runtime pack cell missing {key}"))
}

fn parse_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_optional_u16(value: Option<&Value>, label: &str) -> Result<Option<u16>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_u64()
        .ok_or_else(|| anyhow!("{label} must be an integer"))?;
    u16::try_from(raw)
        .map(Some)
        .map_err(|_| anyhow!("{label} must fit in a u16"))
}

fn parse_binding_probe_hints(cell: &Value) -> Result<Vec<K8sBindingProbeHint>> {
    cell.get("binding_probe_hints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|hint| {
            Ok(K8sBindingProbeHint {
                binding_ref: hint
                    .get("binding_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("binding_probe_hints entry missing binding_ref"))?
                    .to_string(),
                binding_kind: hint
                    .get("binding_kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("binding_probe_hints entry missing binding_kind"))?
                    .to_string(),
            })
        })
        .collect()
}

fn parse_probe_set(cell: &Value) -> Result<K8sProbeSet> {
    let Some(probes) = cell.get("probes") else {
        return Ok(K8sProbeSet::default());
    };
    Ok(K8sProbeSet {
        readiness: parse_probe(probes.get("readiness"))?,
        liveness: parse_probe(probes.get("liveness"))?,
        startup: parse_probe(probes.get("startup"))?,
    })
}

fn parse_probe(value: Option<&Value>) -> Result<Option<K8sProbe>> {
    let Some(probe) = value else {
        return Ok(None);
    };
    Ok(Some(K8sProbe {
        probe_kind: probe
            .get("probe_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("probe missing probe_kind"))?
            .to_string(),
        path: probe
            .get("path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        port: parse_optional_u16(probe.get("port"), "probe.port")?,
        command: parse_string_array(probe.get("command")),
        initial_delay_seconds: probe.get("initial_delay_seconds").and_then(Value::as_u64),
        period_seconds: probe.get("period_seconds").and_then(Value::as_u64),
        timeout_seconds: probe.get("timeout_seconds").and_then(Value::as_u64),
        success_threshold: probe.get("success_threshold").and_then(Value::as_u64),
        failure_threshold: probe.get("failure_threshold").and_then(Value::as_u64),
    }))
}

fn parse_event_runtime(cell: &Value) -> Result<Option<K8sEventRuntime>> {
    let Some(event) = cell.get("event") else {
        return Ok(None);
    };
    Ok(Some(K8sEventRuntime {
        binding_ref: event
            .get("binding_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("event runtime missing binding_ref"))?
            .to_string(),
        topic: event
            .get("topic")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("event runtime missing topic"))?
            .to_string(),
        consumer_group: event
            .get("consumer_group")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        ack_mode: event
            .get("ack_mode")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        max_in_flight: event.get("max_in_flight").and_then(Value::as_u64),
        drain_timeout_seconds: event.get("drain_timeout_seconds").and_then(Value::as_u64),
    }))
}

fn parse_schedule_runtime(cell: &Value) -> Result<Option<K8sScheduleRuntime>> {
    let Some(schedule) = cell.get("schedule") else {
        return Ok(None);
    };
    Ok(Some(K8sScheduleRuntime {
        cron: schedule
            .get("cron")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("schedule runtime missing cron"))?
            .to_string(),
        timezone: schedule
            .get("timezone")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        concurrency_policy: schedule
            .get("concurrency_policy")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        retry_limit: schedule.get("retry_limit").and_then(Value::as_u64),
        start_deadline_seconds: schedule
            .get("start_deadline_seconds")
            .and_then(Value::as_u64),
        suspend: schedule
            .get("suspend")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }))
}

fn parse_rollout(cell: &Value) -> Result<Option<K8sRollout>> {
    let Some(rollout) = cell.get("rollout") else {
        return Ok(None);
    };
    Ok(Some(K8sRollout {
        strategy: rollout
            .get("strategy")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("rollout missing strategy"))?
            .to_string(),
        max_unavailable: rollout
            .get("max_unavailable")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        max_surge: rollout
            .get("max_surge")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        canary_percent: rollout.get("canary_percent").and_then(Value::as_u64),
    }))
}

fn parse_autoscaling(cell: &Value) -> Result<Option<K8sAutoscaling>> {
    let Some(autoscaling) = cell.get("autoscaling") else {
        return Ok(None);
    };
    Ok(Some(K8sAutoscaling {
        min_replicas: autoscaling
            .get("min_replicas")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("autoscaling missing min_replicas"))?,
        max_replicas: autoscaling
            .get("max_replicas")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("autoscaling missing max_replicas"))?,
        target_cpu_utilization: autoscaling
            .get("target_cpu_utilization")
            .and_then(Value::as_u64),
        target_inflight: autoscaling.get("target_inflight").and_then(Value::as_u64),
    }))
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
        let labels = json!({
            "x07.io/workload-id": workload_id,
            "x07.io/deployment-id": deployment_id,
            "x07.io/cell-key": cell.cell_key,
            "x07.io/cell-kind": cell.cell_kind,
            "x07.io/ingress-kind": cell.ingress_kind,
        });
        match cell.resource_kind() {
            K8sCellResourceKind::Deployment => {
                let deployment_name = cell
                    .deployment_name
                    .as_deref()
                    .ok_or_else(|| anyhow!("deployment-backed cell missing deployment_name"))?;
                let deployment_doc = json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": deployment_name,
                        "namespace": namespace,
                        "labels": labels,
                        "annotations": workload_cell_annotations(cell, public_base_url),
                    },
                    "spec": {
                        "replicas": initial_replicas(cell),
                        "strategy": deployment_strategy_doc(cell),
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
                                    "x07.io/cell-kind": cell.cell_kind,
                                    "x07.io/ingress-kind": cell.ingress_kind,
                                },
                                "annotations": workload_cell_annotations(cell, public_base_url),
                            },
                            "spec": {
                                "containers": [container_doc(cell)?]
                            }
                        }
                    }
                });
                let path = manifest_dir.join(format!("deployment.{}.json", cell.cell_key));
                let _ = write_json(&path, &deployment_doc)?;
                paths.push(path);

                if let Some(hpa_doc) = hpa_doc(namespace, public_base_url, cell) {
                    let path = manifest_dir.join(format!("hpa.{}.json", cell.cell_key));
                    let _ = write_json(&path, &hpa_doc)?;
                    paths.push(path);
                }

                if cell.ingress_kind == "http" {
                    let service_name = cell
                        .service_name
                        .as_deref()
                        .ok_or_else(|| anyhow!("http cell missing service_name"))?;
                    let ingress_name = cell
                        .ingress_name
                        .as_deref()
                        .ok_or_else(|| anyhow!("http cell missing ingress_name"))?;
                    let route_path = cell
                        .route_path
                        .as_deref()
                        .ok_or_else(|| anyhow!("http cell missing route_path"))?;
                    let container_port = cell
                        .container_port
                        .ok_or_else(|| anyhow!("http cell missing container_port"))?;
                    let service_doc = json!({
                        "apiVersion": "v1",
                        "kind": "Service",
                        "metadata": {
                            "name": service_name,
                            "namespace": namespace,
                            "labels": labels,
                        },
                        "spec": {
                            "selector": {
                                "x07.io/workload-id": workload_id,
                                "x07.io/cell-key": cell.cell_key,
                            },
                            "ports": [{
                                "name": "http",
                                "port": container_port,
                                "targetPort": container_port
                            }]
                        }
                    });
                    let mut ingress_doc = json!({
                        "apiVersion": "networking.k8s.io/v1",
                        "kind": "Ingress",
                        "metadata": {
                            "name": ingress_name,
                            "namespace": namespace,
                            "labels": labels,
                            "annotations": {
                                "x07.io/public-base-url": public_base_url,
                            }
                        },
                        "spec": {
                            "rules": [{
                                "http": {
                                    "paths": [{
                                        "path": route_path,
                                        "pathType": "Prefix",
                                        "backend": {
                                            "service": {
                                                "name": service_name,
                                                "port": {
                                                    "number": container_port
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
                    for (prefix, doc) in [("service", service_doc), ("ingress", ingress_doc)] {
                        let path = manifest_dir.join(format!("{prefix}.{}.json", cell.cell_key));
                        let _ = write_json(&path, &doc)?;
                        paths.push(path);
                    }
                }
            }
            K8sCellResourceKind::CronJob => {
                let cronjob_name = cell
                    .cronjob_name
                    .as_deref()
                    .ok_or_else(|| anyhow!("scheduled cell missing cronjob_name"))?;
                let schedule = cell
                    .schedule
                    .as_ref()
                    .ok_or_else(|| anyhow!("scheduled cell missing schedule"))?;
                let mut cronjob_doc = json!({
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "metadata": {
                        "name": cronjob_name,
                        "namespace": namespace,
                        "labels": labels,
                        "annotations": workload_cell_annotations(cell, public_base_url),
                    },
                    "spec": {
                        "schedule": schedule.cron,
                        "concurrencyPolicy": cronjob_concurrency_policy(schedule.concurrency_policy.as_deref()),
                        "suspend": schedule.suspend,
                        "jobTemplate": {
                            "spec": {
                                "backoffLimit": schedule.retry_limit.unwrap_or(0),
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "x07.io/workload-id": workload_id,
                                            "x07.io/deployment-id": deployment_id,
                                            "x07.io/cell-key": cell.cell_key,
                                            "x07.io/cell-kind": cell.cell_kind,
                                            "x07.io/ingress-kind": cell.ingress_kind,
                                        },
                                        "annotations": workload_cell_annotations(cell, public_base_url),
                                    },
                                    "spec": {
                                        "restartPolicy": "OnFailure",
                                        "containers": [container_doc(cell)?]
                                    }
                                }
                            }
                        }
                    }
                });
                if let Some(timezone) = schedule.timezone.as_deref() {
                    cronjob_doc
                        .get_mut("spec")
                        .and_then(Value::as_object_mut)
                        .unwrap()
                        .insert("timeZone".to_string(), json!(timezone));
                }
                if let Some(start_deadline_seconds) = schedule.start_deadline_seconds {
                    cronjob_doc
                        .get_mut("spec")
                        .and_then(Value::as_object_mut)
                        .unwrap()
                        .insert(
                            "startingDeadlineSeconds".to_string(),
                            json!(start_deadline_seconds),
                        );
                }
                let path = manifest_dir.join(format!("cronjob.{}.json", cell.cell_key));
                let _ = write_json(&path, &cronjob_doc)?;
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn workload_cell_annotations(cell: &K8sCellDeployment, public_base_url: &str) -> Value {
    let mut annotations = serde_json::Map::new();
    annotations.insert(
        "x07.io/runtime-class".to_string(),
        json!(cell.runtime_class),
    );
    annotations.insert("x07.io/scale-class".to_string(), json!(cell.scale_class));
    annotations.insert(
        "x07.io/topology-group".to_string(),
        json!(cell.topology_group),
    );
    annotations.insert("x07.io/public-base-url".to_string(), json!(public_base_url));
    if let Some(rollout) = cell.rollout.as_ref() {
        annotations.insert(
            "x07.io/rollout-strategy".to_string(),
            json!(rollout.strategy),
        );
        if let Some(canary_percent) = rollout.canary_percent {
            annotations.insert(
                "x07.io/rollout-canary-percent".to_string(),
                json!(canary_percent.to_string()),
            );
        }
    }
    if let Some(autoscaling) = cell.autoscaling.as_ref() {
        annotations.insert(
            "x07.io/autoscaling-min-replicas".to_string(),
            json!(autoscaling.min_replicas.to_string()),
        );
        annotations.insert(
            "x07.io/autoscaling-max-replicas".to_string(),
            json!(autoscaling.max_replicas.to_string()),
        );
        if let Some(target_inflight) = autoscaling.target_inflight {
            annotations.insert(
                "x07.io/autoscaling-target-inflight".to_string(),
                json!(target_inflight.to_string()),
            );
        }
    }
    if let Some(event) = cell.event.as_ref() {
        annotations.insert(
            "x07.io/event-binding-ref".to_string(),
            json!(event.binding_ref),
        );
        annotations.insert("x07.io/event-topic".to_string(), json!(event.topic));
        if let Some(group) = event.consumer_group.as_deref() {
            annotations.insert("x07.io/event-consumer-group".to_string(), json!(group));
        }
    }
    if let Some(schedule) = cell.schedule.as_ref() {
        annotations.insert("x07.io/schedule-cron".to_string(), json!(schedule.cron));
        if let Some(timezone) = schedule.timezone.as_deref() {
            annotations.insert("x07.io/schedule-timezone".to_string(), json!(timezone));
        }
    }
    Value::Object(annotations)
}

fn initial_replicas(cell: &K8sCellDeployment) -> u64 {
    cell.autoscaling
        .as_ref()
        .map(|autoscaling| autoscaling.min_replicas.max(1))
        .unwrap_or(1)
}

fn deployment_strategy_doc(cell: &K8sCellDeployment) -> Value {
    let Some(rollout) = cell.rollout.as_ref() else {
        return json!({"type": "RollingUpdate"});
    };
    match rollout.strategy.as_str() {
        "recreate" => json!({"type": "Recreate"}),
        _ => {
            let mut doc = json!({
                "type": "RollingUpdate",
                "rollingUpdate": {}
            });
            if let Some(rolling_update) =
                doc.get_mut("rollingUpdate").and_then(Value::as_object_mut)
            {
                if let Some(max_unavailable) = rollout.max_unavailable.as_deref() {
                    rolling_update.insert("maxUnavailable".to_string(), json!(max_unavailable));
                }
                if let Some(max_surge) = rollout.max_surge.as_deref() {
                    rolling_update.insert("maxSurge".to_string(), json!(max_surge));
                }
                if rollout.strategy == "canary-lite"
                    && !rolling_update.contains_key("maxUnavailable")
                {
                    rolling_update.insert("maxUnavailable".to_string(), json!("0"));
                }
            }
            doc
        }
    }
}

fn hpa_doc(namespace: &str, public_base_url: &str, cell: &K8sCellDeployment) -> Option<Value> {
    let autoscaling = cell.autoscaling.as_ref()?;
    let target_cpu = autoscaling.target_cpu_utilization?;
    let deployment_name = cell.deployment_name.as_deref()?;
    let hpa_name = cell.hpa_name.as_deref()?;
    Some(json!({
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {
            "name": hpa_name,
            "namespace": namespace,
            "labels": {
                "x07.io/cell-key": cell.cell_key,
                "x07.io/cell-kind": cell.cell_kind,
            },
            "annotations": workload_cell_annotations(cell, public_base_url),
        },
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": deployment_name,
            },
            "minReplicas": autoscaling.min_replicas,
            "maxReplicas": autoscaling.max_replicas,
            "metrics": [{
                "type": "Resource",
                "resource": {
                    "name": "cpu",
                    "target": {
                        "type": "Utilization",
                        "averageUtilization": target_cpu
                    }
                }
            }]
        }
    }))
}

fn container_doc(cell: &K8sCellDeployment) -> Result<Value> {
    let mut container = json!({
        "name": sanitize_k8s_name(&cell.cell_key),
        "image": cell.image,
        "imagePullPolicy": "IfNotPresent",
        "env": workload_cell_env(cell),
    });
    if let Some(container_port) = cell.container_port {
        container["ports"] = json!([{
            "name": "http",
            "containerPort": container_port
        }]);
    }
    if let Some(readiness) = probe_doc(cell.probes.readiness.as_ref())? {
        container["readinessProbe"] = readiness;
    }
    if let Some(liveness) = probe_doc(cell.probes.liveness.as_ref())? {
        container["livenessProbe"] = liveness;
    }
    if let Some(startup) = probe_doc(cell.probes.startup.as_ref())? {
        container["startupProbe"] = startup;
    }
    Ok(container)
}

fn workload_cell_env(cell: &K8sCellDeployment) -> Vec<Value> {
    let mut env = Vec::new();
    env.push(json!({"name": "X07_WORKLOAD_CELL_KEY", "value": cell.cell_key}));
    env.push(json!({"name": "X07_WORKLOAD_CELL_KIND", "value": cell.cell_kind}));
    env.push(json!({"name": "X07_WORKLOAD_INGRESS_KIND", "value": cell.ingress_kind}));
    env.push(json!({"name": "X07_WORKLOAD_RUNTIME_CLASS", "value": cell.runtime_class}));
    env.push(json!({"name": "X07_WORKLOAD_SCALE_CLASS", "value": cell.scale_class}));
    env.push(json!({"name": "X07_WORKLOAD_TOPOLOGY_GROUP", "value": cell.topology_group}));
    if let Some(event) = cell.event.as_ref() {
        env.push(json!({"name": "X07_EVENT_BINDING_REF", "value": event.binding_ref}));
        env.push(json!({"name": "X07_EVENT_TOPIC", "value": event.topic}));
        if let Some(group) = event.consumer_group.as_deref() {
            env.push(json!({"name": "X07_EVENT_CONSUMER_GROUP", "value": group}));
        }
        if let Some(ack_mode) = event.ack_mode.as_deref() {
            env.push(json!({"name": "X07_EVENT_ACK_MODE", "value": ack_mode}));
        }
        if let Some(max_in_flight) = event.max_in_flight {
            env.push(
                json!({"name": "X07_EVENT_MAX_IN_FLIGHT", "value": max_in_flight.to_string()}),
            );
        }
        if let Some(drain_timeout_seconds) = event.drain_timeout_seconds {
            env.push(json!({"name": "X07_EVENT_DRAIN_TIMEOUT_SECONDS", "value": drain_timeout_seconds.to_string()}));
        }
    }
    if let Some(schedule) = cell.schedule.as_ref() {
        env.push(json!({"name": "X07_SCHEDULE_CRON", "value": schedule.cron}));
        if let Some(timezone) = schedule.timezone.as_deref() {
            env.push(json!({"name": "X07_SCHEDULE_TIMEZONE", "value": timezone}));
        }
    }
    env
}

fn probe_doc(probe: Option<&K8sProbe>) -> Result<Option<Value>> {
    let Some(probe) = probe else {
        return Ok(None);
    };
    let mut doc = serde_json::Map::new();
    match probe.probe_kind.as_str() {
        "http" => {
            let port = probe
                .port
                .ok_or_else(|| anyhow!("http probe missing port"))?;
            doc.insert(
                "httpGet".to_string(),
                json!({
                    "path": probe.path.clone().unwrap_or_else(|| "/".to_string()),
                    "port": port
                }),
            );
        }
        "exec" => {
            doc.insert(
                "exec".to_string(),
                json!({
                    "command": probe.command,
                }),
            );
        }
        other => bail!("unsupported probe_kind in runtime pack: {other}"),
    }
    insert_optional_probe_field(&mut doc, "initialDelaySeconds", probe.initial_delay_seconds);
    insert_optional_probe_field(&mut doc, "periodSeconds", probe.period_seconds);
    insert_optional_probe_field(&mut doc, "timeoutSeconds", probe.timeout_seconds);
    insert_optional_probe_field(&mut doc, "successThreshold", probe.success_threshold);
    insert_optional_probe_field(&mut doc, "failureThreshold", probe.failure_threshold);
    Ok(Some(Value::Object(doc)))
}

fn insert_optional_probe_field(
    doc: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<u64>,
) {
    if let Some(value) = value {
        doc.insert(key.to_string(), json!(value));
    }
}

fn cronjob_concurrency_policy(value: Option<&str>) -> &str {
    match value {
        Some("forbid") => "Forbid",
        Some("replace") => "Replace",
        _ => "Allow",
    }
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
    for cell in cells {
        cell_docs.push(refresh_cell_doc(
            target_profile,
            namespace,
            public_base_url,
            stored_cell_doc(cell, public_base_url),
        )?);
    }
    let desired_state = aggregate_desired_state(&cell_docs);
    let observed_state = aggregate_observed_state(&cell_docs);
    let observed_health = health_for_observed_state(&observed_state);
    Ok(json!({
        "schema_version": WORKLOAD_DEPLOYMENT_SCHEMA,
        "deployment_id": deployment_id,
        "workload_id": workload_id,
        "profile_id": profile_id,
        "namespace": namespace,
        "status": deployment_status_for_observed_state(&observed_state),
        "health": observed_health,
        "desired_state": desired_state,
        "observed_state": observed_state,
        "observed_health": observed_health,
        "public_base_url": public_base_url,
        "active_target_id": active_target_id(None, Some(target_profile)),
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
                        cell_map.insert("desired_state".to_string(), json!("stopped"));
                        cell_map.insert("observed_state".to_string(), json!("stopped"));
                        cell_map.insert("observed_health".to_string(), json!("unknown"));
                        cell_map.insert("replicas".to_string(), json!(0));
                        cell_map.insert("ready_replicas".to_string(), json!(0));
                        cell_map.insert("active_jobs".to_string(), json!(0));
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
    for cell in deployment
        .get("cells")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        cell_docs.push(refresh_cell_doc(
            target_profile,
            &namespace,
            &public_base_url,
            cell.clone(),
        )?);
    }
    let desired_state = aggregate_desired_state(&cell_docs);
    let observed_state = aggregate_observed_state(&cell_docs);
    let observed_health = health_for_observed_state(&observed_state);
    if let Some(map) = deployment.as_object_mut() {
        map.insert("cells".to_string(), Value::Array(cell_docs));
        map.insert(
            "status".to_string(),
            json!(deployment_status_for_observed_state(&observed_state)),
        );
        map.insert("health".to_string(), json!(observed_health));
        map.insert("desired_state".to_string(), json!(desired_state));
        map.insert("observed_state".to_string(), json!(observed_state));
        map.insert("observed_health".to_string(), json!(observed_health));
        map.insert("updated_unix_ms".to_string(), json!(now_ms()));
    }
    Ok(deployment)
}

fn stored_cell_doc(cell: &K8sCellDeployment, public_base_url: &str) -> Value {
    let mut doc = json!({
        "cell_key": cell.cell_key,
        "cell_kind": cell.cell_kind,
        "ingress_kind": cell.ingress_kind,
        "runtime_class": cell.runtime_class,
        "scale_class": cell.scale_class,
        "topology_group": cell.topology_group,
        "binding_refs": cell.binding_refs,
        "binding_probe_hints": cell.binding_probe_hints.iter().map(|hint| {
            json!({
                "binding_ref": hint.binding_ref,
                "binding_kind": hint.binding_kind,
            })
        }).collect::<Vec<_>>(),
        "desired_state": cell.desired_state(),
        "observed_state": "pending",
        "observed_health": "unknown",
        "status": "pending",
        "replicas": 0,
        "ready_replicas": 0,
        "active_jobs": 0,
        "image": cell.image,
        "container_port": cell.container_port,
    });
    if let Some(deployment_name) = cell.deployment_name.as_deref() {
        doc["deployment_name"] = json!(deployment_name);
    }
    if let Some(service_name) = cell.service_name.as_deref() {
        doc["service_name"] = json!(service_name);
    }
    if let Some(ingress_name) = cell.ingress_name.as_deref() {
        doc["ingress_name"] = json!(ingress_name);
    }
    if let Some(cronjob_name) = cell.cronjob_name.as_deref() {
        doc["cronjob_name"] = json!(cronjob_name);
    }
    if let Some(hpa_name) = cell.hpa_name.as_deref() {
        doc["hpa_name"] = json!(hpa_name);
    }
    if let Some(route_path) = cell.route_path.as_deref() {
        doc["route_path"] = json!(route_path);
        doc["route_url"] = json!(format!(
            "{}{}",
            public_base_url.trim_end_matches('/'),
            route_path
        ));
    }
    if let Some(event) = cell.event.as_ref() {
        doc["event"] = json!({
            "binding_ref": event.binding_ref,
            "topic": event.topic,
            "consumer_group": event.consumer_group,
            "ack_mode": event.ack_mode,
            "max_in_flight": event.max_in_flight,
            "drain_timeout_seconds": event.drain_timeout_seconds,
        });
    }
    if let Some(schedule) = cell.schedule.as_ref() {
        doc["schedule"] = json!({
            "cron": schedule.cron,
            "timezone": schedule.timezone,
            "concurrency_policy": schedule.concurrency_policy,
            "retry_limit": schedule.retry_limit,
            "start_deadline_seconds": schedule.start_deadline_seconds,
            "suspend": schedule.suspend,
        });
    }
    if let Some(rollout) = cell.rollout.as_ref() {
        doc["rollout"] = json!({
            "strategy": rollout.strategy,
            "max_unavailable": rollout.max_unavailable,
            "max_surge": rollout.max_surge,
            "canary_percent": rollout.canary_percent,
        });
    }
    if let Some(autoscaling) = cell.autoscaling.as_ref() {
        doc["autoscaling"] = json!({
            "min_replicas": autoscaling.min_replicas,
            "max_replicas": autoscaling.max_replicas,
            "target_cpu_utilization": autoscaling.target_cpu_utilization,
            "target_inflight": autoscaling.target_inflight,
        });
    }
    let probes = json!({
        "readiness": stored_probe_doc(cell.probes.readiness.as_ref()),
        "liveness": stored_probe_doc(cell.probes.liveness.as_ref()),
        "startup": stored_probe_doc(cell.probes.startup.as_ref()),
    });
    if probes
        .as_object()
        .is_some_and(|map| map.values().any(|value| !value.is_null()))
    {
        doc["probes"] = probes;
    }
    doc
}

fn stored_probe_doc(probe: Option<&K8sProbe>) -> Value {
    let Some(probe) = probe else {
        return Value::Null;
    };
    json!({
        "probe_kind": probe.probe_kind,
        "path": probe.path,
        "port": probe.port,
        "command": probe.command,
        "initial_delay_seconds": probe.initial_delay_seconds,
        "period_seconds": probe.period_seconds,
        "timeout_seconds": probe.timeout_seconds,
        "success_threshold": probe.success_threshold,
        "failure_threshold": probe.failure_threshold,
    })
}

fn refresh_cell_doc(
    target_profile: &Value,
    namespace: &str,
    public_base_url: &str,
    mut cell: Value,
) -> Result<Value> {
    if let Some(route_path) = cell.get("route_path").and_then(Value::as_str) {
        cell["route_url"] = json!(format!(
            "{}{}",
            public_base_url.trim_end_matches('/'),
            route_path
        ));
    }
    if let Some(deployment_name) = cell.get("deployment_name").and_then(Value::as_str) {
        let status = match kubectl_get_json(
            target_profile,
            namespace,
            &["get", "deployment", deployment_name, "-o", "json"],
        ) {
            Ok(status) => status,
            Err(err) if is_k8s_not_found(&err) => {
                return Ok(mark_cell_stopped(cell));
            }
            Err(err) => return Err(err),
        };
        let desired_replicas = status
            .get("spec")
            .and_then(|value| value.get("replicas"))
            .and_then(Value::as_u64)
            .unwrap_or(1);
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
        let observed_state = if ready_replicas >= desired_replicas.max(1) {
            "running"
        } else if deployment_failed(&status) {
            "failed"
        } else if ready_replicas == 0 {
            "pending"
        } else {
            "degraded"
        };
        let observed_health = health_for_observed_state(observed_state);
        if let Some(map) = cell.as_object_mut() {
            map.insert("replicas".to_string(), json!(replicas));
            map.insert("ready_replicas".to_string(), json!(ready_replicas));
            map.insert("status".to_string(), json!(observed_state));
            map.insert("observed_state".to_string(), json!(observed_state));
            map.insert("observed_health".to_string(), json!(observed_health));
        }
        return Ok(cell);
    }
    if let Some(cronjob_name) = cell.get("cronjob_name").and_then(Value::as_str) {
        let status = match kubectl_get_json(
            target_profile,
            namespace,
            &["get", "cronjob", cronjob_name, "-o", "json"],
        ) {
            Ok(status) => status,
            Err(err) if is_k8s_not_found(&err) => {
                return Ok(mark_cell_stopped(cell));
            }
            Err(err) => return Err(err),
        };
        let active_jobs = status
            .get("status")
            .and_then(|value| value.get("active"))
            .and_then(Value::as_array)
            .map(|items| items.len() as u64)
            .unwrap_or(0);
        let suspended = status
            .get("spec")
            .and_then(|value| value.get("suspend"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let observed_state = if suspended { "stopped" } else { "running" };
        let observed_health = if suspended { "unknown" } else { "healthy" };
        if let Some(map) = cell.as_object_mut() {
            map.insert("active_jobs".to_string(), json!(active_jobs));
            map.insert("status".to_string(), json!(observed_state));
            map.insert("observed_state".to_string(), json!(observed_state));
            map.insert("observed_health".to_string(), json!(observed_health));
            if let Some(last_schedule_time) = status
                .get("status")
                .and_then(|value| value.get("lastScheduleTime"))
                .cloned()
            {
                map.insert("last_schedule_time".to_string(), last_schedule_time);
            }
        }
        return Ok(cell);
    }
    Ok(cell)
}

fn mark_cell_stopped(mut cell: Value) -> Value {
    if let Some(map) = cell.as_object_mut() {
        map.insert("replicas".to_string(), json!(0));
        map.insert("ready_replicas".to_string(), json!(0));
        map.insert("active_jobs".to_string(), json!(0));
        map.insert("status".to_string(), json!("stopped"));
        map.insert("observed_state".to_string(), json!("stopped"));
        map.insert("observed_health".to_string(), json!("unknown"));
    }
    cell
}

fn aggregate_desired_state(cells: &[Value]) -> &'static str {
    let states = cells
        .iter()
        .filter_map(|cell| cell.get("desired_state").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if states.is_empty() || states.iter().all(|state| *state == "stopped") {
        "stopped"
    } else if states.iter().all(|state| *state == "paused") {
        "paused"
    } else {
        "running"
    }
}

fn aggregate_observed_state(cells: &[Value]) -> String {
    let mut any_running = false;
    let mut any_pending = false;
    let mut any_degraded = false;
    let mut any_failed = false;
    let mut all_stopped = !cells.is_empty();
    for state in cells
        .iter()
        .filter_map(|cell| cell.get("observed_state").and_then(Value::as_str))
    {
        match state {
            "running" => any_running = true,
            "pending" => any_pending = true,
            "degraded" => any_degraded = true,
            "failed" => any_failed = true,
            "stopped" => {}
            _ => all_stopped = false,
        }
        if state != "stopped" {
            all_stopped = false;
        }
    }
    if any_failed {
        "failed".to_string()
    } else if any_degraded {
        "degraded".to_string()
    } else if any_pending && !any_running {
        "pending".to_string()
    } else if any_pending {
        "degraded".to_string()
    } else if any_running {
        "running".to_string()
    } else if all_stopped || cells.is_empty() {
        "stopped".to_string()
    } else {
        "unknown".to_string()
    }
}

fn health_for_observed_state(observed_state: &str) -> &str {
    match observed_state {
        "running" => "healthy",
        "failed" => "failed",
        "pending" | "degraded" => "degraded",
        _ => "unknown",
    }
}

fn deployment_status_for_observed_state(observed_state: &str) -> &str {
    match observed_state {
        "failed" => "failed",
        "stopped" | "unknown" => "stopped",
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

fn render_workload_result_doc(
    workload: &Value,
    deployment: Option<&Value>,
    target_profile: Option<&Value>,
    view: &str,
) -> Result<Value> {
    let mut doc = workload.clone();
    let active_target_id = active_target_id(
        deployment.and_then(|item| item.get("target")),
        target_profile,
    );
    let desired_state = desired_state_for_deployment(deployment);
    let observed_state = observed_state_for_deployment(deployment);
    let observed_health = observed_health_for_deployment(deployment);
    if let Some(map) = doc.as_object_mut() {
        if matches!(view, "summary" | "full") {
            map.insert("view".to_string(), json!(view));
        }
        map.insert("active_target_id".to_string(), active_target_id);
        map.insert("desired_state".to_string(), json!(desired_state));
        map.insert("observed_state".to_string(), json!(observed_state));
        map.insert("observed_health".to_string(), json!(observed_health));
        if let Some(cells) = map.get_mut("cells").and_then(Value::as_array_mut) {
            let by_key = deployment
                .and_then(|item| item.get("cells"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|cell| {
                            cell.get("cell_key")
                                .and_then(Value::as_str)
                                .map(|key| (key.to_string(), cell))
                        })
                        .collect::<std::collections::HashMap<_, _>>()
                })
                .unwrap_or_default();
            for cell in cells {
                let desired = cell
                    .get("cell_key")
                    .and_then(Value::as_str)
                    .and_then(|key| by_key.get(key))
                    .and_then(|item| item.get("desired_state"))
                    .and_then(Value::as_str)
                    .unwrap_or("stopped");
                let observed = cell
                    .get("cell_key")
                    .and_then(Value::as_str)
                    .and_then(|key| by_key.get(key))
                    .and_then(|item| item.get("observed_state"))
                    .and_then(Value::as_str)
                    .unwrap_or("stopped");
                let health = cell
                    .get("cell_key")
                    .and_then(Value::as_str)
                    .and_then(|key| by_key.get(key))
                    .and_then(|item| item.get("observed_health"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if let Some(cell_map) = cell.as_object_mut() {
                    cell_map.insert("desired_state".to_string(), json!(desired));
                    cell_map.insert("observed_state".to_string(), json!(observed));
                    cell_map.insert("observed_health".to_string(), json!(health));
                }
            }
        }
    }
    Ok(doc)
}

fn workload_state_result_doc(
    workload_id: &str,
    target_profile: Option<&Value>,
    deployment: Option<&Value>,
) -> Result<Value> {
    let desired_state = desired_state_for_deployment(deployment);
    let observed_state = observed_state_for_deployment(deployment);
    let observed_health = observed_health_for_deployment(deployment);
    let updated_unix_ms = deployment
        .and_then(|item| item.get("updated_unix_ms"))
        .and_then(Value::as_u64)
        .unwrap_or_else(now_ms);
    let deployment_id = deployment
        .and_then(|item| item.get("deployment_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let target_id = active_target_id(
        deployment.and_then(|item| item.get("target")),
        target_profile,
    );
    let cells = deployment
        .and_then(|item| item.get("cells"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|cell| {
                    json!({
                        "cell_key": cell.get("cell_key").cloned().unwrap_or_else(|| json!("unknown")),
                        "state": cell.get("observed_state").cloned().unwrap_or_else(|| json!("unknown")),
                        "health": cell.get("observed_health").cloned().unwrap_or_else(|| json!("unknown")),
                        "desired_replicas": Value::Null,
                        "ready_replicas": cell.get("ready_replicas").cloned().unwrap_or(Value::Null),
                        "route_url": cell.get("route_url").cloned().unwrap_or(Value::Null),
                        "last_run_unix_ms": Value::Null,
                        "next_run_unix_ms": Value::Null,
                        "message": Value::Null,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "schema_version": "lp.workload.state.result@0.1.0",
        "workload_id": workload_id,
        "target_id": target_id,
        "desired": {
            "state": desired_state,
            "release_id": Value::Null,
            "deployment_id": deployment_id.clone(),
            "rollout_strategy": Value::Null,
            "updated_unix_ms": updated_unix_ms,
        },
        "observed": {
            "state": observed_state,
            "health": observed_health,
            "release_id": Value::Null,
            "deployment_id": deployment_id,
            "message": Value::Null,
            "cells": cells,
            "updated_unix_ms": updated_unix_ms,
        },
        "generated_unix_ms": now_ms(),
    }))
}

fn active_target_id(deployment_target: Option<&Value>, target_profile: Option<&Value>) -> Value {
    deployment_target
        .and_then(|target| target.get("name"))
        .and_then(Value::as_str)
        .or_else(|| {
            target_profile
                .and_then(|profile| profile.get("name"))
                .and_then(Value::as_str)
        })
        .map(|value| json!(value))
        .unwrap_or(Value::Null)
}

fn desired_state_for_deployment(deployment: Option<&Value>) -> String {
    deployment
        .and_then(|item| item.get("desired_state"))
        .and_then(Value::as_str)
        .unwrap_or("stopped")
        .to_string()
}

fn observed_state_for_deployment(deployment: Option<&Value>) -> String {
    deployment
        .and_then(|item| item.get("observed_state"))
        .or_else(|| deployment.and_then(|item| item.get("status")))
        .and_then(Value::as_str)
        .unwrap_or("stopped")
        .to_string()
}

fn observed_health_for_deployment(deployment: Option<&Value>) -> String {
    deployment
        .and_then(|item| item.get("observed_health"))
        .or_else(|| deployment.and_then(|item| item.get("health")))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

struct BindingProbeStatus {
    status: String,
    provider_kind: Option<String>,
    configured: bool,
    target_id: Option<String>,
    reason_code: Option<String>,
    message: Option<String>,
    last_checked_unix_ms: Option<u64>,
    probe_result_id: Option<String>,
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
        let probe = match (target_profile, namespace.as_deref()) {
            (Some(profile), Some(namespace))
                if get_str(profile, &["kind"]).as_deref() == Some("k8s") =>
            {
                k8s_binding_status(workload_id, profile, namespace, name, kind)?
            }
            _ => BindingProbeStatus {
                status: "pending".to_string(),
                provider_kind: None,
                configured: false,
                target_id: None,
                reason_code: Some("binding_target_missing".to_string()),
                message: Some("binding target not selected".to_string()),
                last_checked_unix_ms: None,
                probe_result_id: None,
            },
        };
        let mut item = json!({
            "binding_id": sanitize_binding_id(workload_id, name),
            "name": name,
            "kind": kind,
            "status": probe.status,
            "configured": probe.configured,
            "target_id": probe.target_id,
            "reason_code": probe.reason_code,
            "probe_result_id": probe.probe_result_id,
        });
        if let Some(provider_kind) = probe.provider_kind {
            item["provider_kind"] = json!(provider_kind);
        }
        if let Some(message) = probe.message {
            item["message"] = json!(message);
        }
        if let Some(last_checked_unix_ms) = probe.last_checked_unix_ms {
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
    workload_id: &str,
    target_profile: &Value,
    namespace: &str,
    name: &str,
    kind: &str,
) -> Result<BindingProbeStatus> {
    let provider_kind = Some("lp.impl.bindings.k8s_v1".to_string());
    let checked = Some(now_ms());
    let target_id = get_str(target_profile, &["name"]);
    let probe_result_id = checked.map(|checked| {
        format!(
            "bindprobe.{}.{}",
            sanitize_binding_id(workload_id, name),
            checked
        )
    });
    if kind == "otlp" {
        if get_str(target_profile, &["telemetry_collector_hint"]).is_some() {
            return Ok(BindingProbeStatus {
                status: "ready".to_string(),
                provider_kind,
                configured: true,
                target_id,
                reason_code: Some("telemetry_collector_hint_present".to_string()),
                message: Some("telemetry collector hint present on target profile".to_string()),
                last_checked_unix_ms: checked,
                probe_result_id,
            });
        }
        return Ok(BindingProbeStatus {
            status: "pending".to_string(),
            provider_kind,
            configured: true,
            target_id,
            reason_code: Some("telemetry_collector_hint_missing".to_string()),
            message: Some("target profile does not advertise telemetry_collector_hint".to_string()),
            last_checked_unix_ms: checked,
            probe_result_id,
        });
    }
    let object_name = sanitize_k8s_name(name);
    let (resource_kind, exists_message, pending_message, ready_reason, pending_reason) =
        if kind == "secret" {
            (
                "secret",
                "matching Kubernetes Secret is present",
                "create a Kubernetes Secret to satisfy this binding",
                "k8s_secret_present",
                "k8s_secret_missing",
            )
        } else {
            (
                "service",
                "matching Kubernetes Service is present",
                "create or attach a Kubernetes Service to satisfy this binding",
                "k8s_service_present",
                "k8s_service_missing",
            )
        };
    if kubectl_exists(target_profile, namespace, resource_kind, &object_name)? {
        Ok(BindingProbeStatus {
            status: "ready".to_string(),
            provider_kind,
            configured: true,
            target_id,
            reason_code: Some(ready_reason.to_string()),
            message: Some(exists_message.to_string()),
            last_checked_unix_ms: checked,
            probe_result_id,
        })
    } else {
        Ok(BindingProbeStatus {
            status: "pending".to_string(),
            provider_kind,
            configured: true,
            target_id,
            reason_code: Some(pending_reason.to_string()),
            message: Some(pending_message.to_string()),
            last_checked_unix_ms: checked,
            probe_result_id,
        })
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
    use super::{
        binding_status_doc, deployable_cells, sanitize_k8s_name, sanitize_route_path,
        workload_state_result_doc,
    };
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
                    "cell_kind": "api-cell",
                    "ingress_kind": "http",
                    "runtime_class": "native-http",
                    "scale_class": "replicated-http",
                    "topology_group": "frontdoor",
                    "binding_refs": ["db.primary"],
                    "binding_probe_hints": [{
                        "binding_ref": "db.primary",
                        "binding_kind": "postgres"
                    }],
                    "executable": {
                        "kind": "oci_image",
                        "image": "ghcr.io/example/api:1.0.0",
                        "container_port": 8080,
                        "health_path": "/ready"
                    }
                },
                {
                    "cell_key": "worker",
                    "cell_kind": "event-consumer",
                    "ingress_kind": "none",
                    "runtime_class": "native-worker",
                    "scale_class": "partitioned-consumer",
                    "topology_group": "async",
                    "binding_refs": ["msg.orders"],
                    "binding_probe_hints": [{
                        "binding_ref": "msg.orders",
                        "binding_kind": "amqp"
                    }],
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
        assert_eq!(cells[0].route_path.as_deref(), Some("/svc-api/primary"));
        assert_eq!(cells[0].container_port, Some(8080));
        assert_eq!(
            cells[0].deployment_name.as_deref(),
            Some("svc-api-primary-deploy")
        );
        assert_eq!(
            cells[0].service_name.as_deref(),
            Some("svc-api-primary-svc")
        );
    }

    #[test]
    fn deployable_cells_extract_event_and_schedule_shapes() {
        let runtime_pack = json!({
            "cells": [
                {
                    "cell_key": "events",
                    "cell_kind": "event-consumer",
                    "ingress_kind": "event",
                    "runtime_class": "native-worker",
                    "scale_class": "partitioned-consumer",
                    "topology_group": "async",
                    "binding_refs": ["msg.orders"],
                    "binding_probe_hints": [{
                        "binding_ref": "msg.orders",
                        "binding_kind": "amqp"
                    }],
                    "event": {
                        "binding_ref": "msg.orders",
                        "topic": "orders.created",
                        "consumer_group": "orders-workers"
                    },
                    "autoscaling": {
                        "min_replicas": 1,
                        "max_replicas": 4,
                        "target_cpu_utilization": 70
                    },
                    "executable": {
                        "kind": "oci_image",
                        "image": "ghcr.io/example/worker:1.0.0",
                        "container_port": null
                    }
                },
                {
                    "cell_key": "settlement",
                    "cell_kind": "scheduled-job",
                    "ingress_kind": "schedule",
                    "runtime_class": "native-worker",
                    "scale_class": "burst-batch",
                    "topology_group": "async",
                    "binding_refs": ["db.primary"],
                    "binding_probe_hints": [{
                        "binding_ref": "db.primary",
                        "binding_kind": "postgres"
                    }],
                    "schedule": {
                        "cron": "0 */6 * * *",
                        "timezone": "UTC",
                        "retry_limit": 3
                    },
                    "executable": {
                        "kind": "oci_image",
                        "image": "ghcr.io/example/job:1.0.0",
                        "container_port": null
                    }
                }
            ]
        });
        let cells = deployable_cells("svc.api", &runtime_pack).expect("cells");
        assert_eq!(cells.len(), 2);
        assert_eq!(
            cells[0].deployment_name.as_deref(),
            Some("svc-api-events-deploy")
        );
        assert_eq!(cells[0].hpa_name.as_deref(), Some("svc-api-events-hpa"));
        assert_eq!(
            cells[1].cronjob_name.as_deref(),
            Some("svc-api-settlement-cron")
        );
        assert!(cells[1].deployment_name.is_none());
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
        assert_eq!(items[0]["configured"], false);
        assert_eq!(items[0]["reason_code"], "binding_target_missing");
    }

    #[test]
    fn workload_state_result_rolls_up_reconciler_view() {
        let deployment = json!({
            "deployment_id": "wlrun_demo",
            "updated_unix_ms": 12345,
            "target": { "name": "k3s-local" },
            "cells": [
                {
                    "cell_key": "api",
                    "observed_state": "running",
                    "observed_health": "healthy",
                    "ready_replicas": 1,
                    "route_url": "http://127.0.0.1/demo"
                },
                {
                    "cell_key": "worker",
                    "observed_state": "running",
                    "observed_health": "healthy",
                    "ready_replicas": 1
                }
            ],
            "desired_state": "running",
            "observed_state": "running",
            "observed_health": "healthy"
        });
        let state = workload_state_result_doc("svc.demo", None, Some(&deployment)).expect("state");
        assert_eq!(state["schema_version"], "lp.workload.state.result@0.1.0");
        assert_eq!(state["workload_id"], "svc.demo");
        assert_eq!(state["target_id"], "k3s-local");
        assert_eq!(state["desired"]["state"], "running");
        assert_eq!(state["observed"]["state"], "running");
        assert_eq!(state["observed"]["health"], "healthy");
        assert_eq!(
            state["observed"]["cells"][0]["route_url"],
            "http://127.0.0.1/demo"
        );
    }
}
