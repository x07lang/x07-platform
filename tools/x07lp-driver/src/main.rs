#![recursion_limit = "512"]

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::Aead};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use native_tls::{Certificate as NativeTlsCertificate, TlsConnector};
use oci_client::{
    Reference as OciReference,
    client::{
        Certificate as OciCertificate, CertificateEncoding as OciCertificateEncoding,
        Client as OciClient, ClientConfig as OciClientConfig, ClientProtocol,
    },
    manifest::OciImageManifest,
    secrets::RegistryAuth,
};
use oci_wasm::{ToConfig, WasmConfig};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime as TokioRuntime;
use ureq::{Agent, Error as UreqError};
use url::Url;
use wadm_client::{Client as WadmClient, ClientConnectOptions as WadmClientConnectOptions};
use walkdir::WalkDir;
use wasmcloud_control_interface::{
    Client as WasmcloudCtlClient, ClientBuilder as WasmcloudCtlClientBuilder,
};
use x509_parser::prelude::*;

mod device_release_provider;
mod device_release_telemetry;
mod remote_fixture_manifest;

const DEFAULT_STATE_DIR: &str = "out/x07lp_state";
const DEFAULT_UI_ADDR: &str = "127.0.0.1:17090";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const REMOTE_API_VERSION: &str = "v1";
const REMOTE_RUNTIME_PROVIDER: &str = "lp.impl.runtime.wasmcloud_v1";
const REMOTE_ROUTING_PROVIDER: &str = "lp.impl.routing.edge_http_v1";
const REMOTE_TELEMETRY_PROVIDER: &str = "lp.impl.telemetry.otlp_http_v1";
const REMOTE_SECRETS_PROVIDER: &str = "lp.impl.secrets.server_store_v1";
const REMOTE_COMPONENT_REGISTRY: &str = "lp.impl.component_registry.oci_v1";
const REMOTE_ARTIFACT_KIND: &str = "x07.app.pack@0.1.0";
const REMOTE_SERVER_ID: &str = "x07lpd-oss-self-hosted";
const DEFAULT_REMOTE_BEARER_TOKEN: &str = "x07lp-oss-dev-token";
const DEFAULT_REMOTE_SECRET_STORE_FILE: &str = "remote-secret-store.enc.json";
const DEFAULT_REMOTE_OTLP_EXPORT_FILE: &str = "collector-metrics.jsonl";
const DEFAULT_REMOTE_NATS_URL: &str = "nats://127.0.0.1:4222";
const DEFAULT_REMOTE_LATTICE: &str = "default";
const DEFAULT_HOSTED_CLIENT_ID: &str = "x07lp-cli";
const DEFAULT_HOSTED_SCOPE: &str = "cloud:all offline_access";
const HOSTED_SESSION_REFRESH_SKEW_MS: u64 = 30_000;
const HOSTED_LOGIN_TIMEOUT_SECS: u64 = 300;
const REMOTE_SECRET_MASTER_KEY_FILE_ENV: &str = "X07LP_REMOTE_SECRET_MASTER_KEY_FILE";
const REMOTE_SYNTHETIC_TELEMETRY_ENV: &str = "X07LP_REMOTE_SYNTHETIC_TELEMETRY";
const REMOTE_SECRET_STORE_SCHEMA_VERSION: &str = "lp.remote.secret.store.encrypted.internal@0.1.0";
const REMOTE_SECRET_STORE_ALG: &str = "aes-256-gcm-siv";
const REMOTE_EDGE_ROUTE_PREFIX: &str = "/r";
const REMOTE_ROUTE_KEY_HEADER: &str = "X-LP-Route-Key";
const REMOTE_HTTP_SERVER_PROVIDER_IMAGE: &str = "ghcr.io/wasmcloud/http-server:0.27.0";
const REMOTE_SLOT_PORT_BASE: u16 = 26_000;
const REMOTE_SLOT_PORT_COUNT: u16 = 256;
const REMOTE_REAL_TELEMETRY_SAMPLE_COUNT: usize = 7;
const REMOTE_REAL_TELEMETRY_TIMEOUT_MS: u64 = 750;
const LOCAL_TARGET_SENTINEL: &str = "__local__";
const VALID_QUERY_VIEWS: &[&str] = &["summary", "timeline", "decisions", "artifacts", "full"];
const VALID_DEVICE_RELEASE_QUERY_VIEWS: &[&str] = &["summary", "timeline", "decisions", "full"];
const DEVICE_PROVIDER_LIVE_ENV: &str = "X07LP_DEVICE_PROVIDER_LIVE";
const DEVICE_RELEASE_PLAN_KIND: &str = "lp.device.release.plan@0.2.0";
const DEVICE_RELEASE_EXECUTION_KIND: &str = "lp.device.release.execution@0.2.0";
const DEVICE_RELEASE_QUERY_RESULT_KIND: &str = "lp.device.release.query.result@0.2.0";
const DEVICE_RELEASE_RUN_RESULT_KIND: &str = "lp.device.release.run.result@0.2.0";
const DEVICE_STORE_PROVIDER_PROFILE_KIND: &str = "lp.device.store.provider.profile@0.1.0";
const DEVICE_PACKAGE_MANIFEST_KIND: &str = "x07.device.package.manifest@0.1.0";
const DEVICE_INCIDENT_BUNDLE_KIND: &str = "lp.incident.bundle@0.2.0";
const DEVICE_INCIDENT_META_LOCAL_KIND: &str = "lp.incident.bundle.meta.local@0.2.0";
const DEVICE_INCIDENT_QUERY_RESULT_KIND: &str = "lp.incident.query.result@0.2.0";
const REGRESSION_REQUEST_KIND: &str = "lp.regression.request@0.2.0";
const REGRESSION_RUN_RESULT_KIND: &str = "lp.regression.run.result@0.2.0";
const X07_WASM_DEVICE_PACKAGE_REPORT_KIND: &str = "x07.wasm.device.package.report@0.2.0";
const X07_WASM_DEVICE_PACKAGE_REPORT_KIND_LEGACY: &str = "x07.wasm.device.package.report@0.1.0";
const X07_WASM_DEVICE_REGRESS_REPORT_KIND: &str =
    "x07.wasm.device.regress.from_incident.report@0.2.0";
const REDACTED_HTTP_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

type AppIncidentCountSummary = (u64, u64, Option<String>, u64);

#[derive(Debug, Clone)]
struct RemoteSlotDeployment {
    app_name: String,
    bind_addr: String,
    upstream_url: String,
    work_dir: PathBuf,
    manifest_path: PathBuf,
    manifest_digest: Value,
    instance_ref: String,
}

#[derive(Debug, Clone)]
struct RemoteProviderDeployment {
    public_listener: String,
    api_prefix: String,
    component_ref: String,
    registry: String,
    namespace: String,
    repository: String,
    component_digest: Value,
    stable: RemoteSlotDeployment,
    candidate: RemoteSlotDeployment,
    host_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct RemoteTelemetryMetrics {
    latency_p95_ms: f64,
    error_rate: f64,
    availability: f64,
}

#[derive(Debug, Clone)]
struct RemoteTelemetryContext {
    exec_id: String,
    run_id: String,
    pack_sha256: String,
    slot: String,
    app_id: String,
    environment: String,
    service: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetTlsMode {
    System,
    CaBundle,
    PinnedSpki,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetOciTlsMode {
    System,
    CaBundle,
}

#[derive(Debug, Clone)]
struct ResolvedOciAuth {
    username_ref: String,
    password_ref: String,
}

#[derive(Debug, Clone)]
struct ResolvedOciTls {
    mode: TargetOciTlsMode,
    ca_bundle_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct HostedAuthMetadata {
    api_base: String,
    metadata_url: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    device_authorization_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    client_id: String,
    scope: String,
}

#[derive(Parser, Debug)]
#[command(disable_help_subcommand = true, version = TOOL_VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Login(LoginArgs),
    Whoami(HostedCommonArgs),
    Logout(HostedCommonArgs),
    Org(HostedOrgArgs),
    Project(HostedProjectArgs),
    Env(HostedEnvironmentArgs),
    Context(HostedContextArgs),
    Accept(DeployAcceptArgs),
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
    TargetAdd(TargetAddArgs),
    TargetList(TargetListArgs),
    TargetInspect(TargetInspectArgs),
    TargetUse(TargetUseArgs),
    TargetRemove(TargetRemoveArgs),
    AdapterConformance(AdapterConformanceArgs),
    DeviceReleaseCreate(DeviceReleaseCreateArgs),
    DeviceReleaseValidate(DeviceReleaseValidateArgs),
    DeviceReleaseRun(DeviceReleaseRunArgs),
    DeviceReleaseQuery(DeviceReleaseQueryArgs),
    DeviceReleaseObserve(DeviceReleaseControlArgs),
    DeviceReleasePause(DeviceReleaseControlArgs),
    DeviceReleaseResume(DeviceReleaseControlArgs),
    DeviceReleaseHalt(DeviceReleaseControlArgs),
    DeviceReleaseStop(DeviceReleaseControlArgs),
    DeviceReleaseComplete(DeviceReleaseControlArgs),
    DeviceReleaseRerun(DeviceReleaseRerunArgs),
    DeviceReleaseRollback(DeviceReleaseControlArgs),
    #[command(hide = true)]
    SecretStorePack(SecretStorePackArgs),
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

#[derive(Args, Debug, Clone)]
struct HostedCommonArgs {
    #[arg(long)]
    api_base: Option<String>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct LoginArgs {
    #[arg(long)]
    api_base: Option<String>,
    #[arg(long, default_value_t = false)]
    device: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct HostedOrgArgs {
    #[command(subcommand)]
    command: HostedOrgCommand,
}

#[derive(Subcommand, Debug)]
enum HostedOrgCommand {
    List(HostedCommonArgs),
    Create(HostedCreateArgs),
}

#[derive(Args, Debug, Clone)]
struct HostedCreateArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    slug: Option<String>,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug)]
struct HostedProjectArgs {
    #[command(subcommand)]
    command: HostedProjectCommand,
}

#[derive(Subcommand, Debug)]
enum HostedProjectCommand {
    List(HostedProjectListArgs),
    Create(HostedProjectCreateArgs),
}

#[derive(Args, Debug, Clone)]
struct HostedProjectListArgs {
    #[arg(long)]
    org: String,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug, Clone)]
struct HostedProjectCreateArgs {
    #[arg(long)]
    org: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    slug: Option<String>,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug)]
struct HostedEnvironmentArgs {
    #[command(subcommand)]
    command: HostedEnvironmentCommand,
}

#[derive(Subcommand, Debug)]
enum HostedEnvironmentCommand {
    List(HostedEnvironmentListArgs),
    Create(HostedEnvironmentCreateArgs),
}

#[derive(Args, Debug, Clone)]
struct HostedEnvironmentListArgs {
    #[arg(long)]
    project: String,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug, Clone)]
struct HostedEnvironmentCreateArgs {
    #[arg(long)]
    project: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    slug: Option<String>,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug)]
struct HostedContextArgs {
    #[command(subcommand)]
    command: HostedContextCommand,
}

#[derive(Subcommand, Debug)]
enum HostedContextCommand {
    Use(HostedContextUseArgs),
}

#[derive(Args, Debug, Clone)]
struct HostedContextUseArgs {
    #[arg(long)]
    org: String,
    #[arg(long)]
    project: String,
    #[arg(long = "env")]
    environment: Option<String>,
    #[command(flatten)]
    common: HostedCommonArgs,
}

#[derive(Args, Debug)]
struct DeployAcceptArgs {
    #[arg(long)]
    pack_manifest: String,
    #[arg(long)]
    pack_dir: Option<String>,
    #[arg(long)]
    change: Option<String>,
    #[arg(long)]
    ops_profile: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    fixture: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeployRunArgs {
    #[arg(long = "deployment", alias = "deployment-id", default_value = "")]
    deployment_id: String,
    #[arg(long = "accepted-run")]
    accepted_run: Option<String>,
    #[arg(long)]
    plan: Option<String>,
    #[arg(long)]
    metrics_dir: Option<String>,
    #[arg(long)]
    pause_scale: Option<f64>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    fixture: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeployQueryArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
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
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentStatusArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
    deployment_id: String,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentControlArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
    deployment_id: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeploymentRerunArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
    deployment_id: String,
    #[arg(long)]
    from_step: Option<usize>,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentCaptureArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
    deployment_id: Option<String>,
    #[arg(long = "release", alias = "release-id", alias = "release-exec-id")]
    release_exec_id: Option<String>,
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
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentListArgs {
    #[arg(long = "deployment", alias = "deployment-id")]
    deployment_id: Option<String>,
    #[arg(long = "release", alias = "release-id", alias = "release-exec-id")]
    release_exec_id: Option<String>,
    #[arg(long)]
    classification: Option<String>,
    #[arg(long)]
    native_classification: Option<String>,
    #[arg(long)]
    status: Option<String>,
    #[arg(long)]
    target_kind: Option<String>,
    #[arg(long, default_value_t = false)]
    native_only: bool,
    #[arg(long)]
    app_id: Option<String>,
    #[arg(long)]
    env: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct IncidentGetArgs {
    #[arg(long)]
    incident_id: String,
    #[arg(long, default_value_t = false)]
    rebuild_index: bool,
    #[arg(long)]
    target: Option<String>,
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
    #[arg(long)]
    target: Option<String>,
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

#[derive(Args, Debug)]
struct TargetAddArgs {
    #[arg(long)]
    profile: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct TargetListArgs {
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct TargetInspectArgs {
    #[arg(long)]
    name: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct TargetUseArgs {
    #[arg(long)]
    name: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct TargetRemoveArgs {
    #[arg(long)]
    name: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct AdapterConformanceArgs {
    #[arg(long)]
    target: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseCreateArgs {
    #[arg(long)]
    provider_profile: String,
    #[arg(long)]
    package_manifest: String,
    #[arg(long)]
    package_report: String,
    #[arg(long)]
    out: String,
    #[arg(long)]
    slo_profile: Option<String>,
    #[arg(long)]
    metrics_window_seconds: Option<u64>,
    #[arg(long)]
    metrics_on_fail: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseValidateArgs {
    #[arg(long)]
    plan: String,
    #[arg(long)]
    provider_profile: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseRunArgs {
    #[arg(long)]
    plan: String,
    #[arg(long)]
    provider_profile: Option<String>,
    #[arg(long)]
    package_manifest: Option<String>,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseQueryArgs {
    #[arg(long = "release", alias = "release-id", alias = "release-exec-id")]
    release_exec_id: Option<String>,
    #[arg(long)]
    app_id: Option<String>,
    #[arg(long)]
    provider_id: Option<String>,
    #[arg(long)]
    distribution_lane: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long, default_value = "summary")]
    view: String,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    latest: bool,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseControlArgs {
    #[arg(long = "release", alias = "release-id", alias = "release-exec-id")]
    release_exec_id: String,
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct DeviceReleaseRerunArgs {
    #[arg(long = "release", alias = "release-id", alias = "release-exec-id")]
    release_exec_id: String,
    #[arg(long)]
    from_step: Option<usize>,
    #[arg(long)]
    reason: String,
    #[command(flatten)]
    common: CommonStateArgs,
}

#[derive(Args, Debug)]
struct SecretStorePackArgs {
    #[arg(long)]
    input: String,
    #[arg(long)]
    output: String,
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
        Commands::Login(args) => command_login(args)?,
        Commands::Whoami(args) => command_whoami(args)?,
        Commands::Logout(args) => command_logout(args)?,
        Commands::Org(args) => command_org(args)?,
        Commands::Project(args) => command_project(args)?,
        Commands::Env(args) => command_environment(args)?,
        Commands::Context(args) => command_context(args)?,
        Commands::UiServe(args) => return command_ui_serve(args),
        Commands::Accept(args) => command_accept(args)?,
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
        Commands::TargetAdd(args) => command_target_add(args)?,
        Commands::TargetList(args) => command_target_list(args)?,
        Commands::TargetInspect(args) => command_target_inspect(args)?,
        Commands::TargetUse(args) => command_target_use(args)?,
        Commands::TargetRemove(args) => command_target_remove(args)?,
        Commands::AdapterConformance(args) => command_adapter_conformance(args)?,
        Commands::DeviceReleaseCreate(args) => command_device_release_create(args)?,
        Commands::DeviceReleaseValidate(args) => command_device_release_validate(args)?,
        Commands::DeviceReleaseRun(args) => command_device_release_run(args)?,
        Commands::DeviceReleaseQuery(args) => command_device_release_query(args)?,
        Commands::DeviceReleaseObserve(args) => command_device_release_observe(args)?,
        Commands::DeviceReleasePause(args) => {
            command_device_release_control(args, "pause", "device.release.pause.manual")?
        }
        Commands::DeviceReleaseResume(args) => {
            command_device_release_control(args, "resume", "device.release.resume.manual")?
        }
        Commands::DeviceReleaseHalt(args) => {
            command_device_release_control(args, "halt", "device.release.halt.manual")?
        }
        Commands::DeviceReleaseStop(args) => command_device_release_stop(args)?,
        Commands::DeviceReleaseComplete(args) => {
            command_device_release_control(args, "complete", "device.release.complete.manual")?
        }
        Commands::DeviceReleaseRerun(args) => command_device_release_rerun(args)?,
        Commands::DeviceReleaseRollback(args) => {
            command_device_release_control(args, "rollback", "device.release.rollback.manual")?
        }
        Commands::SecretStorePack(args) => command_secret_store_pack(args)?,
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

fn x07_alias_path_arg(path: &Path, alias_scope: &str) -> Result<String> {
    let root = root_dir();
    if let Ok(rel) = path.strip_prefix(&root) {
        return Ok(if rel.as_os_str().is_empty() {
            ".".to_string()
        } else {
            rel.to_string_lossy().into_owned()
        });
    }
    if !path.is_absolute() {
        return Ok(path.to_string_lossy().into_owned());
    }
    let alias_dir = root.join(".x07lp").join(alias_scope);
    fs::create_dir_all(&alias_dir)
        .with_context(|| format!("create state alias dir {}", alias_dir.display()))?;
    let alias_name = format!(
        "external_{}",
        &sha256_hex(path.to_string_lossy().as_bytes())[..16]
    );
    let alias_path = alias_dir.join(alias_name);
    if alias_path.exists() {
        let metadata = fs::symlink_metadata(&alias_path)
            .with_context(|| format!("stat state alias {}", alias_path.display()))?;
        if metadata.file_type().is_symlink() {
            let existing = fs::read_link(&alias_path)
                .with_context(|| format!("read state alias {}", alias_path.display()))?;
            if existing != path {
                fs::remove_file(&alias_path).with_context(|| {
                    format!("remove stale state alias {}", alias_path.display())
                })?;
            }
        } else {
            bail!(
                "state alias path is not a symlink: {}",
                alias_path.display()
            );
        }
    }
    if !alias_path.exists() {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(path, &alias_path).with_context(|| {
                format!(
                    "link external path {} -> {}",
                    alias_path.display(),
                    path.display()
                )
            })?;
        }
        #[cfg(not(unix))]
        {
            bail!(
                "absolute path outside repo is not supported on this platform: {}",
                path.display()
            );
        }
    }
    let rel = alias_path
        .strip_prefix(&root)
        .with_context(|| format!("alias outside repo root: {}", alias_path.display()))?;
    Ok(rel.to_string_lossy().into_owned())
}

fn x07_input_path_arg(path: &Path) -> Result<String> {
    if !path.exists() {
        bail!("input path does not exist: {}", path.display());
    }
    x07_alias_path_arg(path, "path_aliases")
}

fn x07_state_dir_arg(state_dir: &Path) -> Result<String> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create external state dir {}", state_dir.display()))?;
    x07_alias_path_arg(state_dir, "state_aliases")
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("HOME is not set"))
}

fn x07lp_config_dir() -> Result<PathBuf> {
    if let Some(raw) = std::env::var_os("X07LP_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return expand_user_path(&raw.to_string_lossy());
    }
    if let Some(raw) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(expand_user_path(&raw.to_string_lossy())?.join("x07lp"));
    }
    Ok(home_dir()?.join(".config").join("x07lp"))
}

fn x07lp_targets_dir() -> Result<PathBuf> {
    Ok(x07lp_config_dir()?.join("targets"))
}

fn x07lp_tokens_dir() -> Result<PathBuf> {
    Ok(x07lp_config_dir()?.join("tokens"))
}

fn x07lp_current_target_path() -> Result<PathBuf> {
    Ok(x07lp_config_dir()?.join("current_target"))
}

fn x07lp_session_path() -> Result<PathBuf> {
    Ok(x07lp_config_dir()?.join("session.json"))
}

fn target_profile_path(name: &str) -> Result<PathBuf> {
    Ok(x07lp_targets_dir()?.join(format!("{name}.json")))
}

fn default_target_token_path(name: &str) -> Result<PathBuf> {
    Ok(x07lp_tokens_dir()?.join(format!("{name}.token")))
}

fn expand_user_path(raw: &str) -> Result<PathBuf> {
    if raw == "~" {
        return home_dir();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return Ok(home_dir()?.join(rest));
    }
    Ok(PathBuf::from(raw))
}

fn ensure_x07lp_config_layout() -> Result<()> {
    fs::create_dir_all(x07lp_targets_dir()?)?;
    fs::create_dir_all(x07lp_tokens_dir()?)?;
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} must be a file: {}", path.display());
    }
    Ok(())
}

fn validate_sha256_prefixed(value: &str, label: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must start with sha256:");
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("{label} must be a 32-byte sha256 digest");
    }
    Ok(())
}

fn target_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_url(raw: &str) -> Result<Url> {
    Url::parse(raw).with_context(|| format!("invalid URL: {raw}"))
}

fn loopback_url(url: &Url) -> bool {
    url.host_str().map(loopback_host).unwrap_or(false)
}

fn text_ref_path(raw: &str) -> Result<PathBuf> {
    let path = raw
        .strip_prefix("file://")
        .ok_or_else(|| anyhow!("unsupported ref scheme: expected file://"))?;
    expand_user_path(path)
}

fn load_text_ref(raw: &str) -> Result<String> {
    let path = text_ref_path(raw)?;
    let value = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_string();
    if value.is_empty() {
        bail!("empty ref content: {}", path.display());
    }
    Ok(value)
}

fn load_pem_certificates(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = String::from_utf8(bytes).with_context(|| format!("decode {}", path.display()))?;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut offset = 0usize;
    while let Some(start_rel) = text[offset..].find(begin) {
        let start = offset + start_rel;
        let end_rel = text[start..]
            .find(end)
            .ok_or_else(|| anyhow!("unterminated certificate PEM in {}", path.display()))?;
        let finish = start + end_rel + end.len();
        certs.push(text.as_bytes()[start..finish].to_vec());
        offset = finish;
    }
    if certs.is_empty() {
        bail!("no PEM certificates found in {}", path.display());
    }
    Ok(certs)
}

fn native_tls_connector(ca_bundle_path: Option<&Path>) -> Result<Arc<TlsConnector>> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = ca_bundle_path {
        for cert in load_pem_certificates(path)? {
            let cert = NativeTlsCertificate::from_pem(&cert)
                .with_context(|| format!("parse PEM certificate in {}", path.display()))?;
            builder.add_root_certificate(cert);
        }
    }
    Ok(Arc::new(builder.build().context("build TLS connector")?))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn spki_pin_from_cert(cert_der: &[u8]) -> Result<String> {
    let (_rest, cert) = X509Certificate::from_der(cert_der).context("parse peer certificate")?;
    Ok(sha256_prefixed(cert.tbs_certificate.subject_pki.raw))
}

fn tls_mode_from_profile(
    profile: &Value,
) -> Result<(TargetTlsMode, Option<PathBuf>, Option<String>)> {
    let mode = match get_str(profile, &["tls", "mode"]).as_deref() {
        Some("ca_bundle") => TargetTlsMode::CaBundle,
        Some("pinned_spki") => TargetTlsMode::PinnedSpki,
        Some("system") | None => TargetTlsMode::System,
        Some(other) => bail!("unsupported tls.mode: {other}"),
    };
    let ca_bundle_path = get_str(profile, &["tls", "ca_bundle_path"])
        .map(|raw| expand_user_path(&raw))
        .transpose()?;
    let pinned_spki_sha256 = get_str(profile, &["tls", "pinned_spki_sha256"]);
    Ok((mode, ca_bundle_path, pinned_spki_sha256))
}

fn oci_auth_from_profile(profile: &Value) -> Result<Option<ResolvedOciAuth>> {
    let Some(kind) = get_str(profile, &["oci_auth", "kind"]) else {
        return Ok(None);
    };
    if kind != "basic" {
        bail!("unsupported oci_auth.kind: {kind}");
    }
    let username_ref = get_str(profile, &["oci_auth", "username_ref"])
        .ok_or_else(|| anyhow!("missing oci_auth.username_ref"))?;
    let password_ref = get_str(profile, &["oci_auth", "password_ref"])
        .ok_or_else(|| anyhow!("missing oci_auth.password_ref"))?;
    Ok(Some(ResolvedOciAuth {
        username_ref,
        password_ref,
    }))
}

fn oci_tls_from_profile(profile: &Value) -> Result<Option<ResolvedOciTls>> {
    let Some(mode) = get_str(profile, &["oci_tls", "mode"]) else {
        return Ok(None);
    };
    let mode = match mode.as_str() {
        "system" => TargetOciTlsMode::System,
        "ca_bundle" => TargetOciTlsMode::CaBundle,
        other => bail!("unsupported oci_tls.mode: {other}"),
    };
    let ca_bundle_path = get_str(profile, &["oci_tls", "ca_bundle_path"])
        .map(|raw| expand_user_path(&raw))
        .transpose()?;
    Ok(Some(ResolvedOciTls {
        mode,
        ca_bundle_path,
    }))
}

fn validate_target_profile_doc(doc: &Value) -> Result<()> {
    let name = get_str(doc, &["name"]).ok_or_else(|| anyhow!("missing target name"))?;
    if !target_name_is_valid(&name) {
        bail!("invalid target name: {name}");
    }
    if get_str(doc, &["schema_version"]).as_deref() != Some("lp.target.profile@0.1.0") {
        bail!("invalid target profile schema_version");
    }
    if get_str(doc, &["kind"]).as_deref() != Some("oss_remote") {
        bail!("invalid target profile kind");
    }
    if get_str(doc, &["api_version"]).as_deref() != Some("v1") {
        bail!("invalid target api_version");
    }
    if get_str(doc, &["auth", "kind"]).as_deref() != Some("static_bearer") {
        bail!("invalid target auth.kind");
    }
    let base_url = get_str(doc, &["base_url"]).ok_or_else(|| anyhow!("missing target base_url"))?;
    let parsed = parse_url(&base_url)?;
    match parsed.scheme() {
        "https" => {}
        "http" if loopback_url(&parsed) => {}
        "http" => bail!("non-loopback remote targets must use https://"),
        other => bail!("unsupported target URL scheme: {other}"),
    }
    if parsed.host_str().is_none() {
        bail!("missing target base_url");
    }
    let (tls_mode, ca_bundle_path, pinned_spki_sha256) = tls_mode_from_profile(doc)?;
    if parsed.scheme() == "http" && !matches!(tls_mode, TargetTlsMode::System) {
        bail!("http:// targets cannot use custom TLS trust modes");
    }
    if matches!(tls_mode, TargetTlsMode::CaBundle) && ca_bundle_path.is_none() {
        bail!("tls.ca_bundle_path is required when tls.mode=ca_bundle");
    }
    if matches!(tls_mode, TargetTlsMode::PinnedSpki) && pinned_spki_sha256.is_none() {
        bail!("tls.pinned_spki_sha256 is required when tls.mode=pinned_spki");
    }
    if let Some(path) = ca_bundle_path.as_deref() {
        ensure_regular_file(path, "tls.ca_bundle_path")?;
        let _ = load_pem_certificates(path)?;
    }
    if let Some(pin) = pinned_spki_sha256.as_deref() {
        validate_sha256_prefixed(pin, "tls.pinned_spki_sha256")?;
    }
    let token_ref = get_str(doc, &["auth", "token_ref"])
        .ok_or_else(|| anyhow!("missing target auth.token_ref"))?;
    let _ = load_text_ref(&token_ref)?;
    let has_registry = get_str(doc, &["oci_registry"]).is_some();
    if let Some(registry) = get_str(doc, &["oci_registry"])
        && registry.trim_start().starts_with("http://")
    {
        bail!("oci_registry must not use http://");
    }
    let oci_auth = oci_auth_from_profile(doc)?;
    let oci_tls = oci_tls_from_profile(doc)?;
    if has_registry && oci_auth.is_none() {
        bail!("oci_auth is required when oci_registry is set");
    }
    if has_registry && oci_tls.is_none() {
        bail!("oci_tls is required when oci_registry is set");
    }
    if let Some(oci_tls) = oci_tls.as_ref()
        && matches!(oci_tls.mode, TargetOciTlsMode::CaBundle)
        && oci_tls.ca_bundle_path.is_none()
    {
        bail!("oci_tls.ca_bundle_path is required when oci_tls.mode=ca_bundle");
    }
    if let Some(oci_auth) = oci_auth.as_ref() {
        let _ = load_text_ref(&oci_auth.username_ref)?;
        let _ = load_text_ref(&oci_auth.password_ref)?;
    }
    if let Some(oci_tls) = oci_tls.as_ref()
        && let Some(path) = oci_tls.ca_bundle_path.as_deref()
    {
        ensure_regular_file(path, "oci_tls.ca_bundle_path")?;
        let _ = load_pem_certificates(path)?;
    }
    Ok(())
}

fn load_target_profile_doc(name: &str) -> Result<Value> {
    let path = target_profile_path(name)?;
    let doc = load_json(&path)?;
    validate_target_profile_doc(&doc)?;
    Ok(doc)
}

fn store_target_profile_doc(doc: &Value) -> Result<PathBuf> {
    validate_target_profile_doc(doc)?;
    ensure_x07lp_config_layout()?;
    let name = get_str(doc, &["name"]).unwrap();
    let path = target_profile_path(&name)?;
    let _ = write_json(&path, doc)?;
    Ok(path)
}

fn current_target_name() -> Result<Option<String>> {
    let path = x07lp_current_target_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let name = fs::read_to_string(path)?.trim().to_string();
    if name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(name))
    }
}

fn set_current_target_name(name: &str) -> Result<()> {
    ensure_x07lp_config_layout()?;
    fs::write(x07lp_current_target_path()?, format!("{name}\n"))?;
    Ok(())
}

fn resolve_target_name(explicit: Option<&str>) -> Result<Option<String>> {
    if explicit == Some(LOCAL_TARGET_SENTINEL) {
        return Ok(None);
    }
    if let Some(name) = explicit.filter(|value| !value.is_empty()) {
        return Ok(Some(name.to_string()));
    }
    if let Ok(name) = std::env::var("X07LP_TARGET") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    current_target_name()
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
    let temp_path = path.with_extension(format!(
        "{}.tmp.{}.{}",
        path.extension().and_then(OsStr::to_str).unwrap_or("json"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| format!("create {}", temp_path.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temp_path.display()))?;
    }
    fs::rename(&temp_path, path)
        .with_context(|| format!("rename {} -> {}", temp_path.display(), path.display()))?;
    Ok(bytes)
}

fn write_bytes_600(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let temp_path = path.with_extension(format!(
        "{}.tmp.{}.{}",
        path.extension().and_then(OsStr::to_str).unwrap_or("bin"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| format!("create {}", temp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temp_path.display()))?;
    }
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", temp_path.display()))?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("rename {} -> {}", temp_path.display(), path.display()))?;
    Ok(())
}

fn write_json_600(path: &Path, value: &Value) -> Result<Vec<u8>> {
    let bytes = canon_json_bytes(value);
    write_bytes_600(path, &bytes)?;
    Ok(bytes)
}

fn normalize_hosted_api_base(raw: &str) -> Result<String> {
    let api_base = raw.trim();
    if api_base.is_empty() {
        bail!("hosted api base must not be empty");
    }
    let parsed = parse_url(api_base)?;
    match parsed.scheme() {
        "https" => {}
        "http" if loopback_url(&parsed) => {}
        "http" => bail!("non-loopback hosted api base must use https://"),
        other => bail!("unsupported hosted api base scheme: {other}"),
    }
    if parsed.host_str().is_none() {
        bail!("missing host in hosted api base");
    }
    Ok(api_base.trim_end_matches('/').to_string())
}

fn requested_hosted_api_base(explicit: Option<&str>) -> Result<Option<String>> {
    if let Some(value) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(Some(normalize_hosted_api_base(value)?));
    }
    if let Ok(value) = std::env::var("X07LP_HOSTED_API_BASE") {
        let value = value.trim();
        if !value.is_empty() {
            return Ok(Some(normalize_hosted_api_base(value)?));
        }
    }
    Ok(None)
}

fn session_api_base(session: &Value) -> Result<String> {
    let api_base = get_str(session, &["target", "api_base"])
        .ok_or_else(|| anyhow!("missing session target.api_base"))?;
    normalize_hosted_api_base(&api_base)
}

fn resolve_hosted_api_base(explicit: Option<&str>) -> Result<String> {
    if let Some(api_base) = requested_hosted_api_base(explicit)? {
        return Ok(api_base);
    }
    if let Some(session) = load_hosted_session_doc_if_exists()? {
        return session_api_base(&session);
    }
    bail!("hosted operation requires --api-base, X07LP_HOSTED_API_BASE, or a saved hosted session")
}

fn split_scope_string(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn scope_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn access_token_kid(access_token: &str) -> Option<String> {
    let header_segment = access_token.split('.').next()?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(header_segment.as_bytes()).ok()?;
    let doc: Value = serde_json::from_slice(&bytes).ok()?;
    doc.get("kid").and_then(Value::as_str).map(ToOwned::to_owned)
}

fn validate_hosted_token_response(doc: &Value) -> Result<()> {
    if get_str(doc, &["schema_version"]).as_deref() != Some("lp.auth.token.response@0.1.0") {
        bail!("invalid hosted token response schema_version");
    }
    if get_str(doc, &["token_type"]).as_deref() != Some("Bearer") {
        bail!("invalid hosted token response token_type");
    }
    if get_str(doc, &["access_token"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted token response access_token");
    }
    if get_u64(doc, &["expires_in"]).unwrap_or(0) == 0 {
        bail!("missing hosted token response expires_in");
    }
    if split_scope_string(&get_str(doc, &["scope"]).unwrap_or_default()).is_empty() {
        bail!("missing hosted token response scope");
    }
    if get_str(doc, &["issuer"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted token response issuer");
    }
    if get_str(doc, &["audience"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted token response audience");
    }
    if get_str(doc, &["subject", "subject_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted token response subject.subject_id");
    }
    if get_str(doc, &["subject", "subject_kind"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted token response subject.subject_kind");
    }
    Ok(())
}

fn validate_hosted_whoami_result(doc: &Value) -> Result<()> {
    if get_str(doc, &["schema_version"]).as_deref() != Some("lp.auth.whoami.result@0.1.0") {
        bail!("invalid hosted whoami schema_version");
    }
    if get_str(doc, &["account", "account_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami account.account_id");
    }
    if get_str(doc, &["account", "subject_kind"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami account.subject_kind");
    }
    if get_str(doc, &["target", "name"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami target.name");
    }
    if get_str(doc, &["target", "api_base"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami target.api_base");
    }
    if get_str(doc, &["target", "audience"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami target.audience");
    }
    if get_str(doc, &["default_context", "org_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami default_context.org_id");
    }
    if get_str(doc, &["default_context", "project_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted whoami default_context.project_id");
    }
    if scope_array(doc.get("scope").unwrap_or(&Value::Null)).is_empty() {
        bail!("missing hosted whoami scope");
    }
    if get_u64(doc, &["session_expires_unix_ms"]).unwrap_or(0) == 0 {
        bail!("missing hosted whoami session_expires_unix_ms");
    }
    Ok(())
}

fn validate_hosted_session_doc(doc: &Value) -> Result<()> {
    if get_str(doc, &["schema_version"]).as_deref() != Some("lp.auth.session@0.1.0") {
        bail!("invalid hosted session schema_version");
    }
    if get_str(doc, &["issuer"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session issuer");
    }
    if get_str(doc, &["auth_metadata_url"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session auth_metadata_url");
    }
    if get_str(doc, &["jwks_uri"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session jwks_uri");
    }
    if get_str(doc, &["target", "name"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session target.name");
    }
    if get_str(doc, &["target", "api_base"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session target.api_base");
    }
    if get_str(doc, &["target", "audience"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session target.audience");
    }
    if get_str(doc, &["account", "account_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session account.account_id");
    }
    if get_str(doc, &["account", "subject_kind"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session account.subject_kind");
    }
    if get_str(doc, &["default_context", "org_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session default_context.org_id");
    }
    if get_str(doc, &["default_context", "project_id"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session default_context.project_id");
    }
    if get_str(doc, &["tokens", "token_type"]).as_deref() != Some("Bearer") {
        bail!("invalid hosted session tokens.token_type");
    }
    if get_str(doc, &["tokens", "access_token"])
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        == false
    {
        bail!("missing hosted session tokens.access_token");
    }
    if get_u64(doc, &["tokens", "access_token_expires_unix_ms"]).unwrap_or(0) == 0 {
        bail!("missing hosted session tokens.access_token_expires_unix_ms");
    }
    if scope_array(
        doc.get("tokens")
            .and_then(|tokens| tokens.get("scope"))
            .unwrap_or(&Value::Null),
    )
    .is_empty()
    {
        bail!("missing hosted session tokens.scope");
    }
    let refresh_token = get_str(doc, &["tokens", "refresh_token"])
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    let refresh_ref = get_str(doc, &["tokens", "refresh_token_ref"])
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    if !refresh_token && !refresh_ref {
        bail!("hosted session requires refresh_token or refresh_token_ref");
    }
    if get_u64(doc, &["created_unix_ms"]).unwrap_or(0) == 0 {
        bail!("missing hosted session created_unix_ms");
    }
    if get_u64(doc, &["updated_unix_ms"]).unwrap_or(0) == 0 {
        bail!("missing hosted session updated_unix_ms");
    }
    Ok(())
}

fn load_hosted_session_doc_if_exists() -> Result<Option<Value>> {
    let path = x07lp_session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    ensure_owner_only_file(&path, "hosted session")?;
    let doc = load_json(&path)?;
    validate_hosted_session_doc(&doc)?;
    Ok(Some(doc))
}

fn load_hosted_session_doc() -> Result<Value> {
    load_hosted_session_doc_if_exists()?
        .ok_or_else(|| anyhow!("no hosted session found; run `x07lp login`"))
}

fn store_hosted_session_doc(doc: &Value) -> Result<PathBuf> {
    validate_hosted_session_doc(doc)?;
    let path = x07lp_session_path()?;
    let _ = write_json_600(&path, doc)?;
    Ok(path)
}

fn delete_hosted_session_doc() -> Result<bool> {
    let path = x07lp_session_path()?;
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

fn session_needs_refresh(session: &Value, now_unix_ms: u64) -> bool {
    get_u64(session, &["tokens", "access_token_expires_unix_ms"])
        .unwrap_or_default()
        <= now_unix_ms.saturating_add(HOSTED_SESSION_REFRESH_SKEW_MS)
}

fn session_refresh_token(session: &Value) -> Result<String> {
    get_str(session, &["tokens", "refresh_token"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hosted session does not contain a refresh token"))
}

fn session_access_token(session: &Value) -> Result<String> {
    get_str(session, &["tokens", "access_token"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hosted session does not contain an access token"))
}

fn derive_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in name.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            last_dash = false;
        } else if !last_dash && !slug.is_empty() {
            slug.push('-');
            last_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

fn chosen_slug(name: &str, explicit: Option<&str>) -> Result<String> {
    let slug = explicit
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| derive_slug(name));
    if slug.is_empty() {
        bail!("unable to derive slug from --name; pass --slug explicitly");
    }
    Ok(slug)
}

fn redacted_session_summary(session: &Value) -> Value {
    json!({
        "issuer": get_str(session, &["issuer"]).unwrap_or_default(),
        "target": session.get("target").cloned().unwrap_or_else(|| json!({})),
        "account": session.get("account").cloned().unwrap_or_else(|| json!({})),
        "default_context": session.get("default_context").cloned().unwrap_or_else(|| json!({})),
        "updated_unix_ms": get_u64(session, &["updated_unix_ms"]).unwrap_or_default()
    })
}

fn build_hosted_session_doc(
    metadata: &HostedAuthMetadata,
    token_response: &Value,
    whoami: &Value,
    current: Option<&Value>,
) -> Result<Value> {
    validate_hosted_token_response(token_response)?;
    validate_hosted_whoami_result(whoami)?;
    let now_unix_ms = now_ms();
    let access_token = get_str(token_response, &["access_token"]).unwrap();
    let refresh_token = get_str(token_response, &["refresh_token"])
        .or_else(|| current.and_then(|value| get_str(value, &["tokens", "refresh_token"])));
    let refresh_token_ref = current.and_then(|value| get_str(value, &["tokens", "refresh_token_ref"]));
    if refresh_token.is_none() && refresh_token_ref.is_none() {
        bail!("hosted login did not return a refresh token");
    }
    let mut tokens = json!({
        "token_type": "Bearer",
        "access_token": access_token,
        "access_token_expires_unix_ms": now_unix_ms
            .saturating_add(get_u64(token_response, &["expires_in"]).unwrap_or_default().saturating_mul(1000)),
        "scope": if !scope_array(whoami.get("scope").unwrap_or(&Value::Null)).is_empty() {
            Value::Array(scope_array(whoami.get("scope").unwrap_or(&Value::Null)).into_iter().map(Value::String).collect())
        } else {
            Value::Array(split_scope_string(&get_str(token_response, &["scope"]).unwrap_or_default()).into_iter().map(Value::String).collect())
        },
        "refresh_token": refresh_token.clone().map(Value::String).unwrap_or(Value::Null),
        "refresh_token_ref": refresh_token_ref.map(Value::String).unwrap_or(Value::Null),
        "refresh_token_expires_unix_ms": get_u64(token_response, &["refresh_expires_in"])
            .map(|value| now_unix_ms.saturating_add(value.saturating_mul(1000)))
            .or_else(|| current.and_then(|value| get_u64(value, &["tokens", "refresh_token_expires_unix_ms"])))
    });
    if let Some(kid) = access_token_kid(tokens["access_token"].as_str().unwrap_or_default()) {
        ensure_object(&mut tokens).insert("kid".to_string(), Value::String(kid));
    }
    let mut session = json!({
        "schema_version": "lp.auth.session@0.1.0",
        "issuer": get_str(token_response, &["issuer"]).unwrap_or_else(|| metadata.issuer.clone()),
        "auth_metadata_url": metadata.metadata_url,
        "jwks_uri": metadata.jwks_uri,
        "target": whoami.get("target").cloned().unwrap_or_else(|| {
            json!({
                "name": "cloud",
                "api_base": metadata.api_base,
                "audience": get_str(token_response, &["audience"]).unwrap_or_default()
            })
        }),
        "account": whoami.get("account").cloned().unwrap_or_else(|| json!({})),
        "default_context": whoami
            .get("default_context")
            .cloned()
            .or_else(|| token_response.get("default_context").cloned())
            .unwrap_or_else(|| json!({})),
        "tokens": tokens,
        "created_unix_ms": current
            .and_then(|value| get_u64(value, &["created_unix_ms"]))
            .unwrap_or(now_unix_ms),
        "updated_unix_ms": now_unix_ms
    });
    ensure_object(&mut session)
        .entry("target".to_string())
        .or_insert_with(|| json!({}));
    validate_hosted_session_doc(&session)?;
    Ok(session)
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

#[derive(Debug, Clone)]
struct WasmToolCommand {
    argv0: String,
    prefix: Vec<String>,
    display_name: String,
}

fn resolve_wasm_tool() -> Option<WasmToolCommand> {
    let workspace_candidates = [
        root_dir()
            .join("../x07-wasm-backend/target/debug/x07-wasm")
            .to_string_lossy()
            .into_owned(),
        root_dir()
            .join("../x07-wasm-backend/target/release/x07-wasm")
            .to_string_lossy()
            .into_owned(),
    ];
    for candidate in workspace_candidates {
        if Path::new(&candidate).is_file() {
            return Some(WasmToolCommand {
                argv0: candidate,
                prefix: Vec::new(),
                display_name: "x07 wasm".to_string(),
            });
        }
    }
    if let Some(x07_wasm) = which("x07-wasm") {
        return Some(WasmToolCommand {
            argv0: x07_wasm,
            prefix: Vec::new(),
            display_name: "x07 wasm".to_string(),
        });
    }
    if let Some(x07) = which("x07") {
        return Some(WasmToolCommand {
            argv0: x07,
            prefix: vec!["wasm".to_string()],
            display_name: "x07 wasm".to_string(),
        });
    }
    None
}

fn run_wasm_tool_capture(
    args: &[String],
    cwd: Option<&Path>,
) -> Result<(WasmToolCommand, i32, Vec<u8>, Vec<u8>)> {
    let tool = resolve_wasm_tool()
        .ok_or_else(|| anyhow!("missing wasm toolchain: expected `x07 wasm` or `x07-wasm`"))?;
    let mut argv = vec![tool.argv0.clone()];
    argv.extend(tool.prefix.clone());
    argv.extend(args.iter().cloned());
    let (code, stdout, stderr) = run_capture(&argv, cwd)?;
    Ok((tool, code, stdout, stderr))
}

fn read_json_from_report_stdout(stdout: &[u8]) -> Result<Value> {
    let report: Value = serde_json::from_slice(stdout).context("parse x07 run report")?;
    let b64 = get_str(&report, &["solve", "solve_output_b64"])
        .or_else(|| {
            get_str(
                &report,
                &["result", "stdout_json", "solve", "solve_output_b64"],
            )
        })
        .or_else(|| get_str(&report, &["report", "solve", "solve_output_b64"]))
        .ok_or_else(|| anyhow!("missing solve_output_b64 in x07 report"))?;
    let bytes = BASE64
        .decode(b64.as_bytes())
        .context("decode solve_output_b64")?;
    serde_json::from_slice(&bytes).context("parse decoded cli report")
}

fn search_workspace_file(name: &str) -> Option<PathBuf> {
    let root = root_dir();
    let candidates = [
        root.join(name),
        root.join("arch").join("app").join("ops").join(name),
        root.join("arch").join("slo").join(name),
        root.join("spec")
            .join("fixtures")
            .join("phaseA")
            .join("pack_min")
            .join(name),
    ];
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_name() == name {
            return Some(entry.path().to_path_buf());
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
    if let Some(bundle) = get_path(&manifest, &["bundle_manifest"]).and_then(Value::as_object)
        && let (Some(sha), Some(path)) = (
            bundle.get("sha256").and_then(Value::as_str),
            bundle.get("path").and_then(Value::as_str),
        )
    {
        specs.push((sha.to_string(), path.to_string()));
        let bundle_bytes = load_cas_blob(state_dir, sha)?;
        write_bytes(&out_dir.join(path), &bundle_bytes)?;
        let bundle_doc: Value = serde_json::from_slice(&bundle_bytes)?;
        if let Some(backend) =
            get_path(&bundle_doc, &["backend", "artifact"]).and_then(Value::as_object)
            && let (Some(bsha), Some(bpath)) = (
                backend.get("sha256").and_then(Value::as_str),
                backend.get("path").and_then(Value::as_str),
            )
        {
            specs.push((bsha.to_string(), bpath.to_string()));
        }
        if let Some(frontend) =
            get_path(&bundle_doc, &["frontend", "artifacts"]).and_then(Value::as_array)
        {
            for artifact in frontend {
                if let Some(obj) = artifact.as_object()
                    && let (Some(sha), Some(path)) = (
                        obj.get("sha256").and_then(Value::as_str),
                        obj.get("path").and_then(Value::as_str),
                    )
                {
                    specs.push((sha.to_string(), path.to_string()));
                }
            }
        }
    }
    if let Some(component) =
        get_path(&manifest, &["backend", "component"]).and_then(Value::as_object)
        && let (Some(sha), Some(path)) = (
            component.get("sha256").and_then(Value::as_str),
            component.get("path").and_then(Value::as_str),
        )
    {
        specs.push((sha.to_string(), path.to_string()));
    }
    if let Some(assets) = get_path(&manifest, &["assets"]).and_then(Value::as_array) {
        for asset in assets {
            if let Some(file) = get_path(asset, &["file"]).and_then(Value::as_object)
                && let (Some(sha), Some(path)) = (
                    file.get("sha256").and_then(Value::as_str),
                    file.get("path").and_then(Value::as_str),
                )
            {
                specs.push((sha.to_string(), path.to_string()));
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

fn tokio_runtime() -> Result<TokioRuntime> {
    TokioRuntime::new().context("create tokio runtime")
}

fn remote_nats_url() -> String {
    std::env::var("X07LP_REMOTE_NATS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REMOTE_NATS_URL.to_string())
}

fn remote_registry_host(raw: &str) -> String {
    raw.trim()
        .trim_end_matches('/')
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

fn remote_registry_base_url(raw: &str, oci_tls: Option<&ResolvedOciTls>) -> String {
    if raw.trim_start().starts_with("http://") || raw.trim_start().starts_with("https://") {
        raw.trim_end_matches('/').to_string()
    } else if oci_tls.is_some() {
        format!("https://{}", remote_registry_host(raw))
    } else {
        format!("http://{}", remote_registry_host(raw))
    }
}

fn remote_runtime_registry_host(raw: &str) -> String {
    if let Some(value) = std::env::var_os("X07LP_REMOTE_RUNTIME_OCI_REGISTRY")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
    {
        return value;
    }
    let host = remote_registry_host(raw);
    match host.as_str() {
        "127.0.0.1:15443" | "localhost:15443" => "gateway:5443".to_string(),
        "127.0.0.1:15000" | "localhost:15000" => "registry:5000".to_string(),
        _ => host,
    }
}

fn oci_auth_credentials(profile: &Value) -> Result<(String, String)> {
    let auth = oci_auth_from_profile(profile)?
        .ok_or_else(|| anyhow!("remote target profile missing oci_auth"))?;
    Ok((
        load_text_ref(&auth.username_ref)?,
        load_text_ref(&auth.password_ref)?,
    ))
}

fn oci_tls_config(profile: &Value) -> Result<ResolvedOciTls> {
    oci_tls_from_profile(profile)?.ok_or_else(|| anyhow!("remote target profile missing oci_tls"))
}

fn oci_extra_root_certificates(oci_tls: &ResolvedOciTls) -> Result<Vec<OciCertificate>> {
    let Some(path) = oci_tls.ca_bundle_path.as_deref() else {
        return Ok(Vec::new());
    };
    let mut certs = Vec::new();
    for cert in load_pem_certificates(path)? {
        certs.push(OciCertificate {
            encoding: OciCertificateEncoding::Pem,
            data: cert,
        });
    }
    Ok(certs)
}

fn oci_registry_agent(oci_tls: &ResolvedOciTls) -> Result<Agent> {
    agent_with_ca_bundle(oci_tls.ca_bundle_path.as_deref())
}

fn oci_registry_auth_header(profile: &Value) -> Result<String> {
    let (username, password) = oci_auth_credentials(profile)?;
    Ok(format!(
        "Basic {}",
        BASE64.encode(format!("{username}:{password}"))
    ))
}

fn oci_registry_catalog(profile: &Value) -> Result<Value> {
    let registry = get_str(profile, &["oci_registry"])
        .ok_or_else(|| anyhow!("remote target profile missing oci_registry"))?;
    let oci_tls = oci_tls_config(profile)?;
    let agent = oci_registry_agent(&oci_tls)?;
    let authz = oci_registry_auth_header(profile)?;
    let url = format!(
        "{}/v2/_catalog",
        remote_registry_base_url(&registry, Some(&oci_tls))
    );
    match agent
        .request("GET", &url)
        .set("accept", "application/json")
        .set("authorization", &authz)
        .call()
    {
        Ok(response) => decode_http_json_response(response),
        Err(UreqError::Status(_, response)) => decode_http_json_response(response),
        Err(UreqError::Transport(err)) => bail!("registry catalog probe failed: {url}: {err}"),
    }
}

fn remote_exec_public_listener(base_url: &str, exec_id: &str) -> String {
    format!(
        "{}/{}/{}",
        base_url.trim_end_matches('/'),
        REMOTE_EDGE_ROUTE_PREFIX.trim_start_matches('/'),
        exec_id
    )
}

fn remote_router_state_path(state_dir: &Path, exec_id: &str) -> PathBuf {
    state_dir
        .join(".x07lp")
        .join("router")
        .join(exec_id)
        .join("state.json")
}

fn remote_slot_mapping_path(state_dir: &Path, exec_id: &str, slot: &str) -> PathBuf {
    state_dir
        .join(".x07lp")
        .join("remote_ports")
        .join("by_exec")
        .join(format!("{exec_id}-{slot}.json"))
}

fn remote_slot_lease_path(state_dir: &Path, port: u16) -> PathBuf {
    state_dir
        .join(".x07lp")
        .join("remote_ports")
        .join("leases")
        .join(format!("{port}.json"))
}

fn allocate_remote_slot_port(state_dir: &Path, exec_id: &str, slot: &str) -> Result<u16> {
    let mapping_path = remote_slot_mapping_path(state_dir, exec_id, slot);
    if mapping_path.exists() {
        let doc = load_json(&mapping_path)?;
        if let Some(port) = get_u64(&doc, &["port"]).and_then(|value| u16::try_from(value).ok()) {
            return Ok(port);
        }
    }
    if let Some(parent) = mapping_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lease_root = state_dir.join(".x07lp").join("remote_ports").join("leases");
    fs::create_dir_all(&lease_root)?;
    for offset in 0..REMOTE_SLOT_PORT_COUNT {
        let port = REMOTE_SLOT_PORT_BASE + offset;
        let lease_path = remote_slot_lease_path(state_dir, port);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lease_path)
        {
            Ok(mut file) => {
                let lease_doc = json!({
                    "exec_id": exec_id,
                    "slot": slot,
                    "port": port,
                });
                file.write_all(&canon_json_bytes(&lease_doc))?;
                let _ = write_json(&mapping_path, &lease_doc)?;
                return Ok(port);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let lease_doc = load_json(&lease_path).unwrap_or_else(|_| json!({}));
                let same_exec = get_str(&lease_doc, &["exec_id"]).as_deref() == Some(exec_id);
                let same_slot = get_str(&lease_doc, &["slot"]).as_deref() == Some(slot);
                if same_exec && same_slot {
                    let _ = write_json(&mapping_path, &lease_doc)?;
                    return Ok(port);
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    bail!("no free remote runtime ports available")
}

fn release_remote_slot_port(state_dir: &Path, exec_id: &str, slot: &str) {
    let mapping_path = remote_slot_mapping_path(state_dir, exec_id, slot);
    if let Ok(doc) = load_json(&mapping_path)
        && let Some(port) = get_u64(&doc, &["port"]).and_then(|value| u16::try_from(value).ok())
    {
        let _ = fs::remove_file(remote_slot_lease_path(state_dir, port));
    }
    let _ = fs::remove_file(mapping_path);
}

fn remote_slot_app_name(exec_id: &str, slot: &str) -> String {
    format!("lp-{exec_id}-{slot}")
}

fn remote_slot_component_id(exec_id: &str, slot: &str) -> String {
    format!("lp-{exec_id}-{slot}-app")
}

fn remote_slot_provider_id(exec_id: &str, slot: &str) -> String {
    format!("lp-{exec_id}-{slot}-httpserver")
}

fn load_backend_component_from_run(
    state_dir: &Path,
    run_doc: &Value,
) -> Result<(String, Vec<u8>, Value)> {
    let (manifest, _manifest_raw) = load_pack_manifest_from_run(state_dir, run_doc)?;
    let component = get_path(&manifest, &["backend", "component"])
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing backend component in pack manifest"))?;
    let sha = component
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing backend component digest"))?
        .to_string();
    let bytes = load_cas_blob(state_dir, &sha)?;
    Ok((sha, bytes.clone(), digest_value(&bytes)))
}

fn pack_api_prefix(pack_manifest: &Value) -> String {
    get_str(pack_manifest, &["routing", "api_prefix"]).unwrap_or_else(|| "/api".to_string())
}

fn build_remote_wadm_manifest(
    app_name: &str,
    component_ref: &str,
    component_id: &str,
    provider_id: &str,
    port: u16,
    version: &str,
) -> Value {
    json!({
        "apiVersion": "core.oam.dev/v1beta1",
        "kind": "Application",
        "metadata": {
            "name": app_name,
            "annotations": {
                "version": version
            }
        },
        "spec": {
            "components": [
                {
                    "name": "backend",
                    "type": "component",
                    "properties": {
                        "image": component_ref,
                        "id": component_id
                    },
                    "traits": [
                        {
                            "type": "spreadscaler",
                            "properties": {
                                "instances": 1
                            }
                        }
                    ]
                },
                {
                    "name": "httpserver",
                    "type": "capability",
                    "properties": {
                        "image": REMOTE_HTTP_SERVER_PROVIDER_IMAGE,
                        "id": provider_id
                    },
                    "traits": [
                        {
                            "type": "link",
                            "properties": {
                                "target": {
                                    "name": "backend"
                                },
                                "namespace": "wasi",
                                "package": "http",
                                "interfaces": ["incoming-handler"],
                                "source": {
                                    "config": [
                                        {
                                            "name": "listener",
                                            "properties": {
                                                "address": format!("0.0.0.0:{port}"),
                                                "ADDRESS": format!("0.0.0.0:{port}")
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            ]
        }
    })
}

fn publish_remote_component(
    target_profile: &Value,
    app_id: &str,
    environment: &str,
    component_sha: &str,
    component_bytes: &[u8],
) -> Result<(String, String, String, String)> {
    let registry = get_str(target_profile, &["oci_registry"])
        .ok_or_else(|| anyhow!("remote target profile missing oci_registry"))?;
    let namespace =
        get_str(target_profile, &["default_namespace"]).unwrap_or_else(|| environment.to_string());
    let repository = app_id.to_string();
    let push_ref = format!("{registry}/{namespace}/{repository}:sha256-{component_sha}");
    let push_reference = OciReference::try_from(push_ref.as_str())
        .with_context(|| format!("invalid OCI reference: {push_ref}"))?;
    let runtime_registry = remote_runtime_registry_host(&registry);
    let oci_tls = oci_tls_config(target_profile)?;
    let (registry_username, registry_password) = oci_auth_credentials(target_profile)?;
    let (wasm_config, image_layer) = WasmConfig::from_raw_component(component_bytes.to_vec(), None)
        .context("failed to create WebAssembly OCI config from remote component")?;
    let config_obj = wasm_config
        .to_config()
        .context("failed to convert remote component OCI config")?;
    let annotations = Some(BTreeMap::from([(
        "org.opencontainers.image.title".to_string(),
        format!("{app_id}-backend"),
    )]));
    let manifest =
        OciImageManifest::build(std::slice::from_ref(&image_layer), &config_obj, annotations);
    let registry_base_url = remote_registry_base_url(&registry, Some(&oci_tls));
    let protocol = if registry_base_url.starts_with("http://") {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    };
    let client = OciClient::new(OciClientConfig {
        protocol,
        extra_root_certificates: oci_extra_root_certificates(&oci_tls)?,
        accept_invalid_certificates: false,
        accept_invalid_hostnames: false,
        ..Default::default()
    });
    let registry_auth = RegistryAuth::Basic(registry_username, registry_password);
    let runtime = tokio_runtime()?;
    let push_result = runtime.block_on(async {
        client
            .push(
                &push_reference,
                &[image_layer],
                config_obj,
                &registry_auth,
                Some(manifest),
            )
            .await
    })?;
    let manifest_digest = if let Some(digest) = push_result.manifest_url.split('@').nth(1) {
        digest.to_string()
    } else {
        runtime.block_on(async {
            client
                .fetch_manifest_digest(&push_reference, &registry_auth)
                .await
        })?
    };
    let runtime_ref = format!("{runtime_registry}/{namespace}/{repository}@{manifest_digest}");
    Ok((registry, namespace, repository, runtime_ref))
}

fn deploy_remote_slot(
    state_dir: &Path,
    exec_id: &str,
    slot: &'static str,
    target_profile: &Value,
    component_ref: &str,
    version: &str,
    work_dir: &Path,
) -> Result<RemoteSlotDeployment> {
    let lattice_id = get_str(target_profile, &["lattice_id"])
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let port = allocate_remote_slot_port(state_dir, exec_id, slot)?;
    let app_name = remote_slot_app_name(exec_id, slot);
    let component_id = remote_slot_component_id(exec_id, slot);
    let provider_id = remote_slot_provider_id(exec_id, slot);
    let manifest_doc = build_remote_wadm_manifest(
        &app_name,
        component_ref,
        &component_id,
        &provider_id,
        port,
        version,
    );
    let manifest_bytes = canon_json_bytes(&manifest_doc);
    let manifest_path = state_dir
        .join(".x07lp")
        .join("remote_runtime")
        .join(exec_id)
        .join(slot)
        .join("wadm.manifest.json");
    write_json(&manifest_path, &manifest_doc)?;
    let manifest_digest = digest_value(&manifest_bytes);
    tokio_runtime()?.block_on(async {
        let client = WadmClient::new(
            &lattice_id,
            None,
            WadmClientConnectOptions {
                url: Some(remote_nats_url()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| anyhow!("connect wadm client failed: {err}"))?;
        client
            .put_and_deploy_manifest(manifest_bytes.clone())
            .await
            .map_err(|err| anyhow!("deploy wadm manifest {app_name} failed: {err}"))?;
        for _ in 0..60 {
            let status = client
                .get_manifest_status(&app_name)
                .await
                .map_err(|err| anyhow!("query wadm status for {app_name} failed: {err}"))?;
            let status_kind = format!("{:?}", status.info.status_type);
            if status_kind == "Deployed" {
                return Ok(());
            }
            if matches!(status_kind.as_str(), "Failed" | "Unhealthy") {
                bail!("wadm deployment {app_name} failed: {}", status.info.message);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        bail!("timed out waiting for wadm deployment {app_name}")
    })?;
    Ok(RemoteSlotDeployment {
        app_name: app_name.clone(),
        bind_addr: format!("127.0.0.1:{port}"),
        upstream_url: format!("http://127.0.0.1:{port}"),
        work_dir: work_dir.to_path_buf(),
        manifest_path,
        manifest_digest,
        instance_ref: format!("wasmcloud://{lattice_id}/{app_name}"),
    })
}

fn remote_control_host_ids(lattice_id: &str) -> Result<Vec<String>> {
    tokio_runtime()?.block_on(async move {
        let nc = async_nats::connect(remote_nats_url())
            .await
            .map_err(|err| anyhow!("connect NATS control client failed: {err}"))?;
        let client: WasmcloudCtlClient = WasmcloudCtlClientBuilder::new(nc)
            .lattice(lattice_id)
            .build();
        let hosts = client
            .get_hosts()
            .await
            .map_err(|err| anyhow!("query wasmCloud hosts failed: {err}"))?;
        let ids = hosts
            .into_iter()
            .filter(|host| host.succeeded())
            .filter_map(|host| host.into_data().map(|doc| doc.id().to_string()))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            bail!("wasmCloud host inventory is empty");
        }
        Ok(ids)
    })
}

fn prepare_remote_provider_deployment(
    state_dir: &Path,
    exec_doc: &Value,
    run_doc: &Value,
    stable_work_dir: &Path,
    candidate_work_dir: &Path,
) -> Result<RemoteProviderDeployment> {
    let exec_id = get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    let target_profile = get_path(exec_doc, &["meta", "ext", "remote", "target_profile"])
        .cloned()
        .ok_or_else(|| anyhow!("missing remote target profile"))?;
    let base_url = get_str(&target_profile, &["base_url"])
        .ok_or_else(|| anyhow!("missing remote base_url"))?;
    let app_id =
        get_str(exec_doc, &["meta", "target", "app_id"]).unwrap_or_else(|| "unknown".to_string());
    let environment = get_str(exec_doc, &["meta", "target", "environment"])
        .unwrap_or_else(|| "unknown".to_string());
    let lattice_id = get_str(&target_profile, &["lattice_id"])
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let version = get_u64(exec_doc, &["created_unix_ms"])
        .map(|value| value.to_string())
        .unwrap_or_else(|| "1".to_string());
    let (component_sha, component_bytes, component_digest) =
        load_backend_component_from_run(state_dir, run_doc)?;
    let (registry, namespace, repository, component_ref) = publish_remote_component(
        &target_profile,
        &app_id,
        &environment,
        &component_sha,
        &component_bytes,
    )?;
    let (pack_manifest, _) = load_pack_manifest_from_run(state_dir, run_doc)?;
    let api_prefix = pack_api_prefix(&pack_manifest);
    let stable = deploy_remote_slot(
        state_dir,
        &exec_id,
        "stable",
        &target_profile,
        &component_ref,
        &version,
        stable_work_dir,
    )?;
    let candidate = deploy_remote_slot(
        state_dir,
        &exec_id,
        "candidate",
        &target_profile,
        &component_ref,
        &version,
        candidate_work_dir,
    )?;
    let host_ids = remote_control_host_ids(&lattice_id)?;
    Ok(RemoteProviderDeployment {
        public_listener: remote_exec_public_listener(&base_url, &exec_id),
        api_prefix,
        component_ref,
        registry,
        namespace,
        repository,
        component_digest,
        stable,
        candidate,
        host_ids,
    })
}

fn persist_remote_provider_deployment(
    state_dir: &Path,
    exec_doc: &mut Value,
    deployment: &RemoteProviderDeployment,
    now_unix_ms: u64,
) -> Result<()> {
    let exec_id = get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    let app_id = get_str(exec_doc, &["meta", "target", "app_id"]);
    let environment = get_str(exec_doc, &["meta", "target", "environment"]);
    let application_name = app_id
        .zip(environment)
        .map(|(app_id, env)| format!("{app_id}-{env}"))
        .unwrap_or_else(|| exec_id.clone());
    let meta = ensure_object_field(exec_doc, "meta");
    meta.insert(
        "public_listener".to_string(),
        json!(deployment.public_listener.clone()),
    );
    meta.insert(
        "runtime".to_string(),
        json!({
            "stable": {
                "status": "healthy",
                "work_dir": deployment.stable.work_dir.to_string_lossy(),
                "bind_addr": deployment.stable.bind_addr,
                "started_unix_ms": now_unix_ms,
                "last_report": deployment.stable.manifest_path.to_string_lossy(),
            },
            "candidate": {
                "status": "healthy",
                "work_dir": deployment.candidate.work_dir.to_string_lossy(),
                "bind_addr": deployment.candidate.bind_addr,
                "started_unix_ms": now_unix_ms,
                "last_report": deployment.candidate.manifest_path.to_string_lossy(),
            }
        }),
    );
    meta.insert(
        "routing".to_string(),
        json!({
            "public_listener": deployment.public_listener,
            "candidate_weight_pct": 0,
            "algorithm": "hash_bucket_v1",
            "route_key_header": REMOTE_ROUTE_KEY_HEADER,
            "last_updated_step_idx": 1,
            "api_prefix": deployment.api_prefix,
        }),
    );
    meta.insert(
        "revisions".to_string(),
        json!({
            "stable": deployment.component_digest,
            "candidate": deployment.component_digest,
        }),
    );
    let ext_value = meta.entry("ext".to_string()).or_insert_with(|| json!({}));
    let ext_map = ensure_object(ext_value);
    let remote_value = ext_map
        .entry("remote".to_string())
        .or_insert_with(|| json!({}));
    let remote = ensure_object(remote_value);
    let lattice_id = get_path(&Value::Object(remote.clone()), &["runtime", "lattice_id"])
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_REMOTE_LATTICE)
        .to_string();
    remote.insert(
        "publish".to_string(),
        json!({
            "registry": deployment.registry,
            "repository": deployment.repository,
            "namespace": deployment.namespace,
            "component_refs": [{
                "role": "app",
                "oci_ref": deployment.component_ref,
                "digest": deployment.component_digest,
            }],
            "wadm_manifest_digest": deployment.candidate.manifest_digest,
            "wadm_manifests": {
                "stable": deployment.stable.manifest_digest,
                "candidate": deployment.candidate.manifest_digest,
            },
            "published_unix_ms": now_unix_ms,
        }),
    );
    remote.insert(
        "runtime".to_string(),
        json!({
            "lattice_id": lattice_id,
            "application_name": application_name,
            "stable_instance_ref": deployment.stable.instance_ref,
            "candidate_instance_ref": deployment.candidate.instance_ref,
            "stable_app_name": deployment.stable.app_name,
            "candidate_app_name": deployment.candidate.app_name,
            "host_ids": deployment.host_ids,
        }),
    );
    remote.insert(
        "routing".to_string(),
        json!({
            "public_base_url": deployment.public_listener,
            "listener_id": format!("edge-http-v1:{exec_id}"),
            "router_state": remote_router_state_path(state_dir, &exec_id).to_string_lossy(),
            "api_prefix": deployment.api_prefix,
            "stable_upstream": deployment.stable.upstream_url,
            "candidate_upstream": deployment.candidate.upstream_url,
        }),
    );
    Ok(())
}

fn undeploy_remote_slot(exec_doc: &Value, slot: &str) -> Result<()> {
    let remote = get_path(exec_doc, &["meta", "ext", "remote"])
        .ok_or_else(|| anyhow!("missing remote execution metadata"))?;
    let lattice_id = get_str(remote, &["runtime", "lattice_id"])
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let app_name_key = format!("{slot}_app_name");
    let app_name = get_str(remote, &["runtime", &app_name_key]).unwrap_or_else(|| {
        remote_slot_app_name(&get_str(exec_doc, &["exec_id"]).unwrap_or_default(), slot)
    });
    let _ = tokio_runtime()?.block_on(async move {
        let client = WadmClient::new(
            &lattice_id,
            None,
            WadmClientConnectOptions {
                url: Some(remote_nats_url()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| anyhow!("connect wadm client failed: {err}"))?;
        let _ = client.undeploy_manifest(&app_name).await;
        let _ = client.delete_manifest(&app_name, None).await;
        Ok::<(), anyhow::Error>(())
    });
    Ok(())
}

fn http_probe_any(url: &str) -> Result<u16> {
    match remote_agent().request("GET", url).call() {
        Ok(response) => Ok(response.status()),
        Err(UreqError::Status(code, _response)) => Ok(code),
        Err(UreqError::Transport(err)) => bail!("GET {url} failed: {err}"),
    }
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
    let Some(tool) = resolve_wasm_tool() else {
        return Ok(synth_runtime_probe(exec_id, work_dir));
    };
    let (cwd, ops_arg) = resolve_tool_cwd_and_path(ops_path);
    let mut argv = vec![
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
    let (code, stdout, stderr) =
        run_capture(&[vec![tool.argv0], tool.prefix, argv].concat(), Some(&cwd))?;
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
        || message.contains("x07 wasm")
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

fn authority_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = raw.trim().trim_matches('/');
    if authority.is_empty() {
        return None;
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && let Ok(port) = port.parse::<u16>()
    {
        return Some((host.to_string(), port));
    }
    Some((authority.to_string(), default_port))
}

fn url_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let without_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let authority = without_scheme.split('/').next().unwrap_or_default();
    authority_host_port(authority, default_port)
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn tcp_probe(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let addrs = format!("{host}:{port}")
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?;
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }
    match last_err {
        Some(err) => bail!("connect {host}:{port} failed: {err}"),
        None => bail!("resolve {host}:{port} produced no socket addresses"),
    }
}

fn http_probe(url: &str, ok_statuses: &[u16]) -> Result<u16> {
    http_probe_with_agent(&remote_agent(), url, ok_statuses)
}

fn http_probe_with_agent(agent: &Agent, url: &str, ok_statuses: &[u16]) -> Result<u16> {
    match agent.request("GET", url).call() {
        Ok(response) => Ok(response.status()),
        Err(UreqError::Status(code, _response)) if ok_statuses.contains(&code) => Ok(code),
        Err(UreqError::Status(code, _response)) => {
            bail!("GET {url} returned unexpected status {code}")
        }
        Err(UreqError::Transport(err)) => bail!("GET {url} failed: {err}"),
    }
}

fn http_probe_with_profile(profile: &Value, url: &str, ok_statuses: &[u16]) -> Result<u16> {
    enforce_profile_spki_pin(profile, url)?;
    let agent = profile_agent(profile)?;
    http_probe_with_agent(&agent, url, ok_statuses)
}

fn remote_probe_check(name: &str, ok: bool, details: &str) -> Value {
    json!({
        "name": name,
        "ok": ok,
        "details": details,
    })
}

fn run_remote_runtime_probe(exec_id: &str, work_dir: &Path, remote: &Value) -> Result<Value> {
    let base_url = get_str(remote, &["server", "base_url"])
        .or_else(|| get_str(remote, &["target_profile", "base_url"]))
        .unwrap_or_default();
    let registry = get_str(remote, &["publish", "registry"])
        .or_else(|| get_str(remote, &["target_profile", "oci_registry"]));
    let runtime_provider = get_str(remote, &["provider", "runtime_provider"])
        .unwrap_or_else(|| REMOTE_RUNTIME_PROVIDER.to_string());
    let public_listener = get_str(remote, &["routing", "public_base_url"])
        .unwrap_or_else(|| remote_exec_public_listener(&base_url, exec_id));
    let candidate_upstream = get_str(remote, &["routing", "candidate_upstream"])
        .or_else(|| {
            get_str(remote, &["runtime", "candidate_bind_addr"])
                .map(|value| format!("http://{value}"))
        })
        .unwrap_or_default();
    let candidate_app_name = get_str(remote, &["runtime", "candidate_app_name"])
        .unwrap_or_else(|| remote_slot_app_name(exec_id, "candidate"));
    let target_profile = get_path(remote, &["target_profile"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let lattice_id = get_str(remote, &["runtime", "lattice_id"])
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let timeout = Duration::from_secs(2);
    let mut checks = Vec::new();
    let mut diagnostics = Vec::new();

    if !base_url.is_empty() {
        match http_probe_with_profile(
            &target_profile,
            &format!("{}/v1/health", base_url.trim_end_matches('/')),
            &[200],
        ) {
            Ok(_) => checks.push(remote_probe_check(
                "control_plane",
                true,
                "remote control-plane health endpoint responded",
            )),
            Err(err) => {
                diagnostics.push(result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("control plane probe failed: {err}"),
                    "error",
                ));
                checks.push(remote_probe_check("control_plane", false, &err.to_string()));
            }
        }
    }

    if registry.is_some() {
        match oci_registry_catalog(&target_profile) {
            Ok(body) => {
                let repository = get_str(remote, &["publish", "repository"]).unwrap_or_default();
                let namespace = get_str(remote, &["publish", "namespace"]).unwrap_or_default();
                let expected = format!("{namespace}/{repository}");
                let found = body
                    .get("repositories")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|item| item == expected)
                    })
                    .unwrap_or(false);
                if found {
                    checks.push(remote_probe_check(
                        "component_registry",
                        true,
                        "OCI registry catalog contains the published repository",
                    ));
                } else {
                    diagnostics.push(result_diag(
                        "LP_REMOTE_RUNTIME_PROBE_FAILED",
                        "run",
                        "published OCI repository missing from registry catalog",
                        "error",
                    ));
                    checks.push(remote_probe_check(
                        "component_registry",
                        false,
                        "published OCI repository missing from registry catalog",
                    ));
                }
            }
            Err(err) => {
                diagnostics.push(result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("component registry probe failed: {err}"),
                    "error",
                ));
                checks.push(remote_probe_check(
                    "component_registry",
                    false,
                    &err.to_string(),
                ));
            }
        }
    }

    match remote_control_host_ids(&lattice_id) {
        Ok(host_ids) => checks.push(remote_probe_check(
            "wasmcloud_runtime",
            true,
            &format!(
                "wasmCloud host inventory returned {} host(s)",
                host_ids.len()
            ),
        )),
        Err(err) => {
            diagnostics.push(result_diag(
                "LP_REMOTE_RUNTIME_PROBE_FAILED",
                "run",
                &format!("wasmCloud runtime probe failed: {err}"),
                "error",
            ));
            checks.push(remote_probe_check(
                "wasmcloud_runtime",
                false,
                &err.to_string(),
            ));
        }
    }

    let wadm_status = tokio_runtime()?.block_on(async {
        let client = WadmClient::new(
            &lattice_id,
            None,
            WadmClientConnectOptions {
                url: Some(remote_nats_url()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| anyhow!("connect wadm client failed: {err}"))?;
        client
            .get_manifest_status(&candidate_app_name)
            .await
            .map_err(|err| anyhow!("query wadm status failed: {err}"))
    });
    match wadm_status {
        Ok(status) if format!("{:?}", status.info.status_type) == "Deployed" => checks.push(
            remote_probe_check("wadm_candidate", true, "candidate wadm deployment is ready"),
        ),
        Ok(status) => {
            diagnostics.push(result_diag(
                "LP_REMOTE_RUNTIME_PROBE_FAILED",
                "run",
                &format!(
                    "candidate wadm deployment is not ready: {:?} {}",
                    status.info.status_type, status.info.message
                ),
                "error",
            ));
            checks.push(remote_probe_check(
                "wadm_candidate",
                false,
                &format!("{:?}: {}", status.info.status_type, status.info.message),
            ));
        }
        Err(err) => {
            diagnostics.push(result_diag(
                "LP_REMOTE_RUNTIME_PROBE_FAILED",
                "run",
                &format!("candidate wadm status probe failed: {err}"),
                "error",
            ));
            checks.push(remote_probe_check(
                "wadm_candidate",
                false,
                &err.to_string(),
            ));
        }
    }

    if !candidate_upstream.is_empty() {
        match http_probe_any(&candidate_upstream) {
            Ok(status) => checks.push(remote_probe_check(
                "candidate_upstream",
                true,
                &format!("candidate upstream responded with status {status}"),
            )),
            Err(err) => {
                diagnostics.push(result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("candidate upstream probe failed: {err}"),
                    "error",
                ));
                checks.push(remote_probe_check(
                    "candidate_upstream",
                    false,
                    &err.to_string(),
                ));
            }
        }
    }

    match http_probe_with_profile(&target_profile, &public_listener, &[200]) {
        Ok(_) => checks.push(remote_probe_check(
            "public_listener",
            true,
            "public listener returned a successful response",
        )),
        Err(err) => {
            diagnostics.push(result_diag(
                "LP_REMOTE_RUNTIME_PROBE_FAILED",
                "run",
                &format!("public listener probe failed: {err}"),
                "error",
            ));
            checks.push(remote_probe_check(
                "public_listener",
                false,
                &err.to_string(),
            ));
        }
    }

    if let Some((host, _)) = url_host_port(&base_url, 80).filter(|(host, _)| loopback_host(host)) {
        match http_probe(&format!("http://{host}:8222/varz"), &[200]) {
            Ok(_) => checks.push(remote_probe_check(
                "nats_monitor",
                true,
                "nats monitoring endpoint responded",
            )),
            Err(err) => {
                diagnostics.push(result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("nats monitor probe failed: {err}"),
                    "error",
                ));
                checks.push(remote_probe_check("nats_monitor", false, &err.to_string()));
            }
        }
        match tcp_probe(&host, 4000, timeout) {
            Ok(()) => checks.push(remote_probe_check(
                "wasmcloud_host_port",
                true,
                "wasmCloud host control port accepted a TCP connection",
            )),
            Err(err) => {
                diagnostics.push(result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("wasmCloud host port probe failed: {err}"),
                    "error",
                ));
                checks.push(remote_probe_check(
                    "wasmcloud_host_port",
                    false,
                    &err.to_string(),
                ));
            }
        }
    }

    let ok = diagnostics.is_empty()
        && checks
            .iter()
            .all(|check| get_bool(check, &["ok"]) == Some(true));
    Ok(json!({
        "schema_version": "lp.runtime.probe.remote@0.1.0",
        "command": "lp.runtime.probe.remote",
        "ok": ok,
        "exit_code": if ok { 0 } else { 18 },
        "diagnostics": diagnostics,
        "result": {
            "exec_id": exec_id,
            "work_dir": work_dir.to_string_lossy(),
            "provider": runtime_provider,
            "status": if ok { "healthy" } else { "unhealthy" },
            "checks": checks,
        },
    }))
}

fn remote_synthetic_telemetry_enabled() -> bool {
    matches!(
        std::env::var(REMOTE_SYNTHETIC_TELEMETRY_ENV)
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

fn remote_telemetry_seed(fixture: Option<&str>) -> RemoteTelemetryMetrics {
    match remote_fixture_name(fixture).as_deref() {
        Some("remote_rollback") => RemoteTelemetryMetrics {
            latency_p95_ms: 450.0,
            error_rate: 0.05,
            availability: 0.95,
        },
        _ => RemoteTelemetryMetrics {
            latency_p95_ms: 120.0,
            error_rate: 0.005,
            availability: 0.995,
        },
    }
}

fn remote_otlp_metrics_url(remote: &Value) -> Option<String> {
    let raw = get_str(remote, &["target_profile", "telemetry_collector_hint"])
        .or_else(|| get_str(remote, &["server", "telemetry_collector_hint"]))?;
    let base = raw.trim_end_matches('/').to_string();
    if base.ends_with("/v1/metrics") {
        Some(base)
    } else {
        Some(format!("{base}/v1/metrics"))
    }
}

fn otlp_attr_doc(key: &str, value: Value) -> Value {
    json!({
        "key": key,
        "value": value,
    })
}

fn otlp_string_attr(key: &str, value: &str) -> Value {
    otlp_attr_doc(key, json!({ "stringValue": value }))
}

fn otlp_int_attr(key: &str, value: usize) -> Value {
    otlp_attr_doc(key, json!({ "intValue": value.to_string() }))
}

fn remote_telemetry_context(exec_doc: &Value, run_doc: &Value) -> Result<RemoteTelemetryContext> {
    let exec_id = get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    let run_id = get_str(run_doc, &["run_id"]).ok_or_else(|| anyhow!("missing run_id"))?;
    let pack_sha256 = get_str(
        run_doc,
        &["inputs", "artifact", "manifest", "digest", "sha256"],
    )
    .ok_or_else(|| anyhow!("missing pack manifest sha256"))?;
    let app_id =
        get_str(exec_doc, &["meta", "target", "app_id"]).unwrap_or_else(|| "app_min".to_string());
    let environment = get_str(exec_doc, &["meta", "target", "environment"])
        .unwrap_or_else(|| "unknown".to_string());
    Ok(RemoteTelemetryContext {
        exec_id,
        run_id,
        pack_sha256,
        slot: "candidate".to_string(),
        service: app_id.clone(),
        app_id,
        environment,
    })
}

fn remote_probe_path(remote: &Value) -> String {
    let prefix = get_str(remote, &["routing", "api_prefix"]).unwrap_or_else(|| "/api".to_string());
    let normalized = if prefix.starts_with('/') {
        prefix
    } else {
        format!("/{prefix}")
    };
    if normalized == "/" {
        "/ping".to_string()
    } else {
        format!("{}/ping", normalized.trim_end_matches('/'))
    }
}

fn remote_candidate_probe_url(remote: &Value) -> Result<String> {
    let base = get_str(remote, &["routing", "candidate_upstream"])
        .or_else(|| {
            get_str(remote, &["runtime", "candidate_bind_addr"])
                .map(|value| format!("http://{value}"))
        })
        .ok_or_else(|| anyhow!("missing remote candidate upstream"))?;
    Ok(format!(
        "{}{}",
        base.trim_end_matches('/'),
        remote_probe_path(remote)
    ))
}

fn remote_timeout_agent(timeout: Duration) -> Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build()
}

fn agent_with_ca_bundle_and_timeout(
    ca_bundle_path: Option<&Path>,
    timeout: Duration,
) -> Result<Agent> {
    let connector = native_tls_connector(ca_bundle_path)?;
    Ok(ureq::AgentBuilder::new()
        .tls_connector(connector)
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build())
}

fn remote_probe_agent(remote: &Value, timeout: Duration) -> Result<Agent> {
    let probe_url = remote_candidate_probe_url(remote)?;
    let parsed = parse_url(&probe_url)?;
    if parsed.scheme() == "https" {
        let profile = get_path(remote, &["target_profile"])
            .ok_or_else(|| anyhow!("missing remote target profile"))?;
        let (_mode, ca_bundle_path, _pin) = tls_mode_from_profile(profile)?;
        return agent_with_ca_bundle_and_timeout(ca_bundle_path.as_deref(), timeout);
    }
    Ok(remote_timeout_agent(timeout))
}

fn percentile_ms(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let idx = ((sorted.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[idx]
}

fn measure_remote_runtime_metrics(remote: &Value) -> Result<RemoteTelemetryMetrics> {
    let timeout = Duration::from_millis(REMOTE_REAL_TELEMETRY_TIMEOUT_MS);
    let agent = remote_probe_agent(remote, timeout)?;
    let probe_url = remote_candidate_probe_url(remote)?;
    let mut latencies_ms = Vec::with_capacity(REMOTE_REAL_TELEMETRY_SAMPLE_COUNT);
    let mut successes = 0usize;
    let mut failures = 0usize;
    for _ in 0..REMOTE_REAL_TELEMETRY_SAMPLE_COUNT {
        let started = Instant::now();
        let response = agent.request("GET", &probe_url).call();
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        match response {
            Ok(response) => {
                latencies_ms.push(elapsed_ms);
                if (200..400).contains(&response.status()) {
                    successes += 1;
                } else {
                    failures += 1;
                }
            }
            Err(UreqError::Status(code, _response)) => {
                latencies_ms.push(elapsed_ms);
                if (200..400).contains(&code) {
                    successes += 1;
                } else {
                    failures += 1;
                }
            }
            Err(UreqError::Transport(_err)) => {
                latencies_ms.push(elapsed_ms.max(REMOTE_REAL_TELEMETRY_TIMEOUT_MS as f64));
                failures += 1;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let total = successes + failures;
    if total == 0 {
        bail!("remote runtime telemetry probe did not collect any samples");
    }
    Ok(RemoteTelemetryMetrics {
        latency_p95_ms: percentile_ms(&latencies_ms, 0.95),
        error_rate: failures as f64 / total as f64,
        availability: successes as f64 / total as f64,
    })
}

fn remote_otlp_payload(
    context: &RemoteTelemetryContext,
    analysis_seq: usize,
    metrics: RemoteTelemetryMetrics,
    telemetry_source: &str,
) -> Value {
    let time_unix_nano = format!("{}", 1_772_990_000_000_000_000_u64 + analysis_seq as u64);
    let attrs = vec![
        otlp_string_attr("x07.exec_id", &context.exec_id),
        otlp_string_attr("x07.run_id", &context.run_id),
        otlp_string_attr("x07.pack_sha256", &context.pack_sha256),
        otlp_string_attr("x07.slot", &context.slot),
        otlp_string_attr("x07.app_id", &context.app_id),
        otlp_string_attr("x07.environment", &context.environment),
        otlp_string_attr("x07.telemetry_source", telemetry_source),
        otlp_int_attr("x07.analysis_seq", analysis_seq),
    ];
    json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [otlp_string_attr("service.name", &context.service)]
            },
            "scopeMetrics": [{
                "scope": {
                    "name": "x07lp-driver",
                    "version": TOOL_VERSION,
                },
                "metrics": [
                    {
                        "name": "http_error_rate",
                        "unit": "ratio",
                        "gauge": {
                            "dataPoints": [{
                                "attributes": attrs.clone(),
                                "timeUnixNano": time_unix_nano,
                                "asDouble": metrics.error_rate,
                            }]
                        }
                    },
                    {
                        "name": "http_latency_p95_ms",
                        "unit": "ms",
                        "gauge": {
                            "dataPoints": [{
                                "attributes": attrs.clone(),
                                "timeUnixNano": time_unix_nano,
                                "asDouble": metrics.latency_p95_ms,
                            }]
                        }
                    },
                    {
                        "name": "http_availability",
                        "unit": "ratio",
                        "gauge": {
                            "dataPoints": [{
                                "attributes": attrs,
                                "timeUnixNano": time_unix_nano,
                                "asDouble": metrics.availability,
                            }]
                        }
                    }
                ]
            }]
        }]
    })
}

fn otlp_attr_matches(attrs: &[Value], key: &str, expected: &str) -> bool {
    attrs.iter().any(|attr| {
        get_str(attr, &["key"]).as_deref() == Some(key)
            && (get_str(attr, &["value", "stringValue"]).as_deref() == Some(expected)
                || get_str(attr, &["value", "intValue"]).as_deref() == Some(expected))
    })
}

fn otlp_datapoint_value(point: &Value) -> Option<f64> {
    point
        .get("asDouble")
        .and_then(Value::as_f64)
        .or_else(|| point.get("asInt").and_then(Value::as_i64).map(|v| v as f64))
        .or_else(|| {
            point
                .get("asInt")
                .and_then(Value::as_str)
                .and_then(|v| v.parse::<f64>().ok())
        })
}

fn remote_metrics_snapshot_from_otlp_export(
    export_line: &Value,
    context: &RemoteTelemetryContext,
    analysis_seq: usize,
    telemetry_source: &str,
) -> Option<Value> {
    let mut metrics = BTreeMap::new();
    let analysis_seq = analysis_seq.to_string();
    let resource_metrics = export_line.get("resourceMetrics")?.as_array()?;
    for resource_metric in resource_metrics {
        let scope_metrics = resource_metric
            .get("scopeMetrics")
            .and_then(Value::as_array)?;
        for scope_metric in scope_metrics {
            let metric_docs = scope_metric.get("metrics").and_then(Value::as_array)?;
            for metric_doc in metric_docs {
                let metric_name = get_str(metric_doc, &["name"])?;
                let points = metric_doc
                    .get("gauge")
                    .and_then(|doc| doc.get("dataPoints"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for point in points {
                    let attrs = point
                        .get("attributes")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if !otlp_attr_matches(&attrs, "x07.exec_id", &context.exec_id)
                        || !otlp_attr_matches(&attrs, "x07.run_id", &context.run_id)
                        || !otlp_attr_matches(&attrs, "x07.pack_sha256", &context.pack_sha256)
                        || !otlp_attr_matches(&attrs, "x07.slot", &context.slot)
                        || !otlp_attr_matches(&attrs, "x07.app_id", &context.app_id)
                        || !otlp_attr_matches(&attrs, "x07.environment", &context.environment)
                        || !otlp_attr_matches(&attrs, "x07.telemetry_source", telemetry_source)
                        || !otlp_attr_matches(&attrs, "x07.analysis_seq", &analysis_seq)
                    {
                        continue;
                    }
                    if let Some(value) = otlp_datapoint_value(&point) {
                        metrics.insert(metric_name.clone(), value);
                    }
                }
            }
        }
    }
    if !metrics.contains_key("http_error_rate")
        || !metrics.contains_key("http_latency_p95_ms")
        || !metrics.contains_key("http_availability")
    {
        return None;
    }
    Some(json!({
        "schema_version": "x07.metrics.snapshot@0.1.0",
        "service": context.service,
        "taken_at_utc": "2026-02-27T00:00:00Z",
        "v": 1,
        "labels": {
            "x07.exec_id": context.exec_id,
            "x07.run_id": context.run_id,
            "x07.pack_sha256": context.pack_sha256,
            "x07.slot": context.slot,
            "x07.app_id": context.app_id,
            "x07.environment": context.environment,
            "x07.telemetry_source": telemetry_source,
            "x07.analysis_seq": analysis_seq,
        },
        "metrics": [
            { "name": "http_error_rate", "unit": "ratio", "value": metrics["http_error_rate"] },
            { "name": "http_latency_p95_ms", "unit": "ms", "value": metrics["http_latency_p95_ms"] },
            { "name": "http_availability", "unit": "ratio", "value": metrics["http_availability"] }
        ]
    }))
}

fn read_remote_otlp_snapshot(
    state_dir: &Path,
    context: &RemoteTelemetryContext,
    analysis_seq: usize,
    telemetry_source: &str,
) -> Result<Option<Value>> {
    let export_path = remote_otlp_export_path(state_dir);
    if !export_path.exists() {
        return Ok(None);
    }
    let file = fs::File::open(export_path)?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let doc: Value = serde_json::from_str(&line).context("parse otlp export line")?;
        if let Some(snapshot) =
            remote_metrics_snapshot_from_otlp_export(&doc, context, analysis_seq, telemetry_source)
        {
            last = Some(snapshot);
        }
    }
    Ok(last)
}

fn emit_remote_otlp_metrics(
    context: &RemoteTelemetryContext,
    analysis_seq: usize,
    remote: &Value,
    metrics: RemoteTelemetryMetrics,
    telemetry_source: &str,
) -> Result<()> {
    let Some(url) = remote_otlp_metrics_url(remote) else {
        bail!("missing telemetry collector hint for remote target");
    };
    let payload = remote_otlp_payload(context, analysis_seq, metrics, telemetry_source);
    match remote_agent()
        .request("POST", &url)
        .set("content-type", "application/json")
        .send_string(&payload.to_string())
    {
        Ok(_response) => Ok(()),
        Err(UreqError::Status(code, _response)) => {
            bail!("POST {url} returned unexpected status {code}")
        }
        Err(UreqError::Transport(err)) => bail!("POST {url} failed: {err}"),
    }
}

fn generate_remote_metrics_snapshot(
    state_dir: &Path,
    exec_doc: &Value,
    run_doc: &Value,
    analysis_seq: usize,
    fixture: Option<&str>,
) -> Result<Value> {
    let remote = get_path(exec_doc, &["meta", "ext", "remote"])
        .ok_or_else(|| anyhow!("missing remote execution metadata"))?;
    let context = remote_telemetry_context(exec_doc, run_doc)?;
    let (metrics, telemetry_source) = if remote_synthetic_telemetry_enabled() {
        (
            remote_telemetry_seed(fixture),
            "synthetic_fixture".to_string(),
        )
    } else {
        (
            measure_remote_runtime_metrics(remote)?,
            "remote_runtime_probe".to_string(),
        )
    };
    emit_remote_otlp_metrics(&context, analysis_seq, remote, metrics, &telemetry_source)?;
    for _ in 0..20 {
        if let Some(snapshot) =
            read_remote_otlp_snapshot(state_dir, &context, analysis_seq, &telemetry_source)?
        {
            return Ok(snapshot);
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "remote telemetry export did not contain metrics for {} analysis {}",
        context.exec_id,
        analysis_seq
    )
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

fn run_slo_eval(profile_path: Option<&Path>, metrics_path: &Path) -> Result<(String, Value)> {
    let metrics_doc = load_json(metrics_path)?;
    let inferred = infer_slo_decision(&metrics_doc);
    if let Some(profile_path) = profile_path.filter(|p| p.exists()) {
        let (cwd, profile_arg) = resolve_tool_cwd_and_path(Some(profile_path));
        let argv = vec![
            "slo".to_string(),
            "eval".to_string(),
            "--profile".to_string(),
            profile_arg.unwrap(),
            "--metrics".to_string(),
            metrics_path.to_string_lossy().into_owned(),
            "--json".to_string(),
        ];
        let (tool, code, stdout, stderr) = run_wasm_tool_capture(&argv, Some(&cwd))?;
        if let Ok(report) = serde_json::from_slice::<Value>(&stdout) {
            let decision = get_str(&report, &["result", "decision"]).unwrap_or(inferred.clone());
            if code == 0 || matches!(decision.as_str(), "rollback" | "promote" | "inconclusive") {
                return Ok((decision, report));
            }
        }
        let stderr_msg = String::from_utf8_lossy(&stderr).trim().to_string();
        bail!(
            "{} slo eval failed for {}: {}",
            tool.display_name,
            profile_path.display(),
            if stderr_msg.is_empty() {
                format!("exit code {}", code.max(1))
            } else {
                stderr_msg
            }
        );
    }
    bail!(
        "missing SLO profile path for metrics snapshot {}",
        metrics_path.display()
    )
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

#[allow(clippy::too_many_arguments)]
fn write_router_state(
    state_dir: &Path,
    exec_id: &str,
    listener_addr: &str,
    stable_addr: &str,
    candidate_addr: &str,
    stable_work_dir: &str,
    candidate_work_dir: &str,
    api_prefix: &str,
    candidate_weight_pct: u64,
    step_idx: usize,
) -> Result<()> {
    let router_dir = state_dir.join(".x07lp").join("router").join(exec_id);
    let state = json!({
        "exec_id": exec_id,
        "listener_addr": listener_addr,
        "stable_addr": stable_addr,
        "candidate_addr": candidate_addr,
        "stable_work_dir": stable_work_dir,
        "candidate_work_dir": candidate_work_dir,
        "api_prefix": api_prefix,
        "route_key_header": REMOTE_ROUTE_KEY_HEADER,
        "algorithm": "hash_bucket_v1",
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
    let listener_addr =
        get_str(meta, &["public_listener"]).unwrap_or_else(|| deterministic_listener(&exec_id));
    let stable_addr = get_str(meta, &["runtime", "stable", "bind_addr"])
        .map(|value| format!("http://{value}"))
        .unwrap_or_else(|| format!("{}/stable", listener_addr));
    let candidate_addr = get_str(meta, &["runtime", "candidate", "bind_addr"])
        .map(|value| format!("http://{value}"))
        .unwrap_or_else(|| format!("{}/candidate", listener_addr));
    let stable_work_dir = get_str(meta, &["runtime", "stable", "work_dir"]).unwrap_or_else(|| {
        runtime_state_paths(state_dir, &exec_id, "stable")["work"]
            .to_string_lossy()
            .into_owned()
    });
    let candidate_work_dir =
        get_str(meta, &["runtime", "candidate", "work_dir"]).unwrap_or_else(|| {
            runtime_state_paths(state_dir, &exec_id, "candidate")["work"]
                .to_string_lossy()
                .into_owned()
        });
    let api_prefix =
        get_str(meta, &["routing", "api_prefix"]).unwrap_or_else(|| "/api".to_string());
    write_router_state(
        state_dir,
        &exec_id,
        &listener_addr,
        &stable_addr,
        &candidate_addr,
        &stable_work_dir,
        &candidate_work_dir,
        &api_prefix,
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
fn build_device_release_step(
    idx: usize,
    name: &str,
    kind: &str,
    status: &str,
    started_unix_ms: u64,
    ended_unix_ms: Option<u64>,
    decisions: Vec<String>,
    latest_rollout_percent: Option<u64>,
    store_release_id: Option<&str>,
    analysis_decision: Option<&str>,
) -> Value {
    let mut step = build_exec_step(
        idx,
        name,
        kind,
        status,
        started_unix_ms,
        ended_unix_ms,
        decisions,
        None,
        analysis_decision,
    );
    if let Some(percent) = latest_rollout_percent {
        ensure_object(&mut step).insert("latest_rollout_percent".to_string(), json!(percent));
    }
    if let Some(store_release_id) = store_release_id {
        ensure_object(&mut step).insert("store_release_id".to_string(), json!(store_release_id));
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

fn canonical_remote_provider_id(raw: Option<&str>, default_id: &str) -> String {
    match raw.unwrap_or_default() {
        "" => default_id.to_string(),
        REMOTE_RUNTIME_PROVIDER
        | REMOTE_ROUTING_PROVIDER
        | REMOTE_TELEMETRY_PROVIDER
        | REMOTE_SECRETS_PROVIDER
        | REMOTE_COMPONENT_REGISTRY => raw.unwrap().to_string(),
        "wasmcloud" => REMOTE_RUNTIME_PROVIDER.to_string(),
        "edge_http_v1" => REMOTE_ROUTING_PROVIDER.to_string(),
        "otlp_http_v1" => REMOTE_TELEMETRY_PROVIDER.to_string(),
        "server_store_v1" => REMOTE_SECRETS_PROVIDER.to_string(),
        "oci_v1" => REMOTE_COMPONENT_REGISTRY.to_string(),
        other => other.to_string(),
    }
}

fn artifact_ref_min(artifact: Option<&Value>, label: Option<&str>) -> Value {
    let Some(artifact) = artifact else {
        return Value::Null;
    };
    let mut doc = Map::new();
    if let Some(kind) = get_str(artifact, &["kind"]) {
        doc.insert("kind".to_string(), json!(kind));
    }
    if let Some(digest) = get_path(artifact, &["digest"]).cloned() {
        doc.insert("digest".to_string(), digest);
    }
    if let Some(label) = label {
        doc.insert("label".to_string(), json!(label));
    } else if let Some(label) = get_str(artifact, &["logical_name"]) {
        doc.insert("label".to_string(), json!(label));
    }
    if let Some(store_uri) = get_str(artifact, &["store_uri"]) {
        doc.insert("store_uri".to_string(), json!(store_uri));
    }
    if let Some(media_type) = get_str(artifact, &["media_type"]) {
        doc.insert("media_type".to_string(), json!(media_type));
    }
    Value::Object(doc)
}

fn remote_runtime_slot_from_local(
    local_slot: &Value,
    application_name: &str,
    instance_ref: String,
    endpoint_url: Option<String>,
    probe_artifact: Option<&Value>,
) -> Value {
    let mut slot = json!({
        "revision_digest": get_path(local_slot, &["revision_digest"]).cloned().unwrap_or(Value::Null),
        "app_name": application_name,
        "instance_ref": instance_ref,
        "endpoint_url": endpoint_url,
        "status": get_str(local_slot, &["status"]).unwrap_or_else(|| "planned".to_string()),
        "started_unix_ms": get_path(local_slot, &["started_unix_ms"]).cloned().unwrap_or(Value::Null),
        "ended_unix_ms": get_path(local_slot, &["ended_unix_ms"]).cloned().unwrap_or(Value::Null),
        "health": {
            "ok": get_bool(local_slot, &["health", "ok"]).unwrap_or(false),
            "last_probe_unix_ms": get_path(local_slot, &["health", "last_probe_unix_ms"]).cloned().unwrap_or(Value::Null),
            "last_report": artifact_ref_min(probe_artifact, None),
        }
    });
    if endpoint_url.is_none() {
        ensure_object(&mut slot).insert("endpoint_url".to_string(), Value::Null);
    }
    slot
}

fn build_remote_execution_meta(exec_doc: &Value, run_doc: &Value, local_meta: &Value) -> Value {
    let remote = get_path(exec_doc, &["meta", "ext", "remote"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let target = get_path(local_meta, &["target"])
        .cloned()
        .unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"}));
    let app_id = get_str(&target, &["app_id"]).unwrap_or_else(|| "unknown".to_string());
    let environment = get_str(&target, &["environment"]).unwrap_or_else(|| "unknown".to_string());
    let artifact_kind = get_str(local_meta, &["artifact_kind"])
        .or_else(|| get_str(run_doc, &["inputs", "artifact", "kind"]))
        .unwrap_or_else(|| REMOTE_ARTIFACT_KIND.to_string());
    let target_profile = get_path(&remote, &["target_profile"])
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "name": "remote",
                "kind": "oss_remote",
                "base_url": get_str(&remote, &["server", "base_url"]).unwrap_or_else(|| get_str(local_meta, &["routing", "public_listener"]).unwrap_or_default()),
                "api_version": REMOTE_API_VERSION,
                "auth_kind": "static_bearer",
                "tls": Value::Null,
                "runtime_provider": REMOTE_RUNTIME_PROVIDER,
                "routing_provider": REMOTE_ROUTING_PROVIDER,
                "oci_registry": Value::Null,
                "oci_auth": Value::Null,
                "oci_tls": Value::Null,
                "default_namespace": Value::Null,
                "default_env": Value::Null,
                "lattice_id": Value::Null,
                "telemetry_collector_hint": Value::Null
            })
        });
    let server = get_path(&remote, &["server"]).cloned().unwrap_or_else(|| {
        let capabilities = build_remote_capabilities_doc();
        json!({
            "server_id": REMOTE_SERVER_ID,
            "base_url": get_str(&target_profile, &["base_url"]).unwrap_or_default(),
            "api_version": REMOTE_API_VERSION,
            "capabilities_digest": get_path(&capabilities, &["capabilities_digest"]).cloned().unwrap_or_else(|| digest_value(&canon_json_bytes(&capabilities))),
        })
    });
    let provider = get_path(&remote, &["provider"])
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "runtime_provider": REMOTE_RUNTIME_PROVIDER,
                "routing_provider": REMOTE_ROUTING_PROVIDER,
                "telemetry_provider": REMOTE_TELEMETRY_PROVIDER,
                "secrets_provider": REMOTE_SECRETS_PROVIDER,
                "component_registry": REMOTE_COMPONENT_REGISTRY,
            })
        });
    let runtime_profile = get_path(&remote, &["runtime"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let routing = get_path(local_meta, &["routing"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let runtime = get_path(local_meta, &["runtime"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let artifacts = get_path(exec_doc, &["meta", "artifacts"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let last_probe = latest_artifact_by_role(&artifacts, "runtime_probe");
    let last_snapshot = latest_artifact_by_role(&artifacts, "metrics_snapshot");
    let last_slo_report = latest_artifact_by_role(&artifacts, "slo_eval_report");
    let lattice_id = get_str(&runtime_profile, &["lattice_id"])
        .or_else(|| get_str(&target_profile, &["lattice_id"]))
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let application_name = get_str(&runtime_profile, &["application_name"])
        .unwrap_or_else(|| format!("{app_id}-{environment}"));
    let public_base_url = get_str(&routing, &["public_listener"]).unwrap_or_default();
    let registry = get_str(&remote, &["publish", "registry"])
        .or_else(|| get_str(&target_profile, &["oci_registry"]))
        .unwrap_or_else(|| "registry.invalid".to_string());
    let namespace = get_str(&remote, &["publish", "namespace"])
        .or_else(|| get_str(&target_profile, &["default_namespace"]))
        .unwrap_or_else(|| environment.clone());
    let repository = get_str(&remote, &["publish", "repository"]).unwrap_or_else(|| app_id.clone());
    let fallback_publish_digest = get_path(run_doc, &["inputs", "artifact", "manifest", "digest"])
        .cloned()
        .or_else(|| get_path(&runtime, &["candidate", "revision_digest"]).cloned())
        .unwrap_or_else(|| json!({"sha256":"0000000000000000000000000000000000000000000000000000000000000000","bytes_len":0}));
    let component_refs = get_path(&remote, &["publish", "component_refs"])
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .cloned()
        .unwrap_or_else(|| {
            let digest = fallback_publish_digest
                .get("sha256")
                .and_then(Value::as_str)
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            vec![json!({
                "role": "app",
                "oci_ref": format!("{registry}/{namespace}/{repository}@sha256:{digest}"),
                "digest": fallback_publish_digest,
            })]
        });
    let stable_slot = remote_runtime_slot_from_local(
        &get_path(&runtime, &["stable"])
            .cloned()
            .unwrap_or(Value::Null),
        &application_name,
        get_str(&runtime_profile, &["stable_instance_ref"])
            .unwrap_or_else(|| format!("wasmcloud://{lattice_id}/{application_name}/stable")),
        None,
        last_probe.as_ref(),
    );
    let candidate_slot = remote_runtime_slot_from_local(
        &get_path(&runtime, &["candidate"])
            .cloned()
            .unwrap_or(Value::Null),
        &application_name,
        get_str(&runtime_profile, &["candidate_instance_ref"])
            .unwrap_or_else(|| format!("wasmcloud://{lattice_id}/{application_name}/candidate")),
        if public_base_url.is_empty() {
            None
        } else {
            Some(public_base_url.clone())
        },
        last_probe.as_ref(),
    );
    json!({
        "schema_version": "lp.deploy.execution.meta.remote@0.1.0",
        "mode": "remote",
        "artifact_kind": artifact_kind,
        "target": target,
        "target_profile": target_profile,
        "server": server,
        "provider": provider,
        "outcome": get_str(local_meta, &["outcome"]).unwrap_or_else(|| "unknown".to_string()),
        "started_unix_ms": get_path(local_meta, &["started_unix_ms"]).cloned().unwrap_or(Value::Null),
        "updated_unix_ms": get_u64(local_meta, &["updated_unix_ms"]).unwrap_or(0),
        "ended_unix_ms": get_path(local_meta, &["ended_unix_ms"]).cloned().unwrap_or(Value::Null),
        "latest_decision_id": get_path(local_meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null),
        "plan": get_path(local_meta, &["plan"]).cloned().unwrap_or(Value::Null),
        "runtime": {
            "lattice_id": lattice_id,
            "application_name": application_name,
            "stable": stable_slot,
            "candidate": candidate_slot,
        },
        "publish": {
            "registry": registry,
            "repository": repository,
            "namespace": namespace,
            "component_refs": component_refs,
            "wadm_manifest_digest": get_path(&remote, &["publish", "wadm_manifest_digest"]).cloned().unwrap_or(fallback_publish_digest),
            "published_unix_ms": get_u64(&remote, &["publish", "published_unix_ms"]).unwrap_or_else(|| get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0)),
        },
        "routing": {
            "public_base_url": public_base_url,
            "listener_id": get_path(&remote, &["routing", "listener_id"]).cloned().unwrap_or(Value::Null),
            "candidate_weight_pct": get_u64(&routing, &["candidate_weight_pct"]).unwrap_or(0),
            "algorithm": get_str(&routing, &["algorithm"]).unwrap_or_else(|| "hash_bucket_v1".to_string()),
            "route_key_header": get_str(&routing, &["route_key_header"]).unwrap_or_else(|| "X-LP-Route-Key".to_string()),
            "last_updated_step_idx": get_path(&routing, &["last_updated_step_idx"]).cloned().unwrap_or(Value::Null),
            "router_state": get_path(&remote, &["routing", "router_state"]).cloned().unwrap_or(Value::Null),
        },
        "analysis": {
            "last_slo_decision": get_str(local_meta, &["analysis", "last_slo_decision"]).unwrap_or_else(|| "none".to_string()),
            "last_snapshot": artifact_ref_min(last_snapshot.as_ref(), None),
            "last_slo_report": artifact_ref_min(last_slo_report.as_ref(), None),
            "last_analysis_step_idx": get_path(local_meta, &["analysis", "last_analysis_step_idx"]).cloned().unwrap_or(Value::Null),
        },
        "control": {
            "lock_id": get_path(&remote, &["control", "lock_id"]).cloned().unwrap_or(Value::Null),
            "lease_expires_unix_ms": get_path(&remote, &["control", "lease_expires_unix_ms"]).cloned().unwrap_or(Value::Null),
            "target_generation": get_u64(&remote, &["control", "target_generation"]).unwrap_or(0),
            "lease_holder": get_path(&remote, &["control", "lease_holder"]).cloned().unwrap_or(Value::Null),
            "last_idempotency_key": get_path(&remote, &["control", "last_idempotency_key"]).cloned().unwrap_or(Value::Null),
        },
        "ext": get_path(exec_doc, &["meta", "ext"]).cloned().unwrap_or_else(|| json!({})),
    })
}

fn sanitize_query_step(step: &Value) -> Value {
    let mut doc = json!({
        "idx": get_u64(step, &["idx"]).unwrap_or(0),
        "name": get_str(step, &["name"]).unwrap_or_default(),
        "status": get_str(step, &["status"]).unwrap_or_else(|| "running".to_string()),
        "started_unix_ms": get_u64(step, &["started_unix_ms"]).unwrap_or(0),
        "ended_unix_ms": get_path(step, &["ended_unix_ms"]).cloned().unwrap_or(Value::Null),
        "decisions": get_path(step, &["decisions"]).cloned().unwrap_or_else(|| json!([])),
    });
    if let Some(kind) = get_str(step, &["kind"]) {
        ensure_object(&mut doc).insert("kind".to_string(), json!(kind));
    }
    if let Some(attempt) = get_u64(step, &["attempt"]) {
        ensure_object(&mut doc).insert("attempt".to_string(), json!(attempt.max(1)));
    }
    if let Some(weight) = get_path(step, &["latest_weight_pct"]).cloned() {
        ensure_object(&mut doc).insert("latest_weight_pct".to_string(), weight);
    }
    if let Some(decision) = get_path(step, &["analysis_decision"]).cloned() {
        ensure_object(&mut doc).insert("analysis_decision".to_string(), decision);
    }
    if let Some(control_state) = get_path(step, &["control_state"]).cloned() {
        ensure_object(&mut doc).insert("control_state".to_string(), control_state);
    }
    doc
}

fn public_reason_code(code: &str) -> String {
    match code {
        "LP_PLAN_READY" => "LP-INTAKE-OK".to_string(),
        "LP_SLO_PROMOTE" => "LP-SLO-PROMOTE".to_string(),
        "LP_SLO_ROLLBACK" => "LP-SLO-ROLLBACK".to_string(),
        other => other.to_string(),
    }
}

fn sanitize_query_decision(decision: &Value, public_aliases: bool) -> Value {
    let reasons = get_path(decision, &["reasons"])
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|reason| {
                    let mut doc = reason.clone();
                    if public_aliases && let Some(code) = get_str(reason, &["code"]) {
                        ensure_object(&mut doc)
                            .insert("code".to_string(), json!(public_reason_code(&code)));
                    }
                    doc
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut doc = json!({
        "decision_id": get_str(decision, &["decision_id"]).unwrap_or_default(),
        "created_unix_ms": get_u64(decision, &["created_unix_ms"]).unwrap_or(0),
        "kind": get_str(decision, &["kind"]).unwrap_or_default(),
        "outcome": get_str(decision, &["outcome"]).unwrap_or_else(|| "error".to_string()),
        "reasons": reasons,
        "record": {
            "digest": get_path(decision, &["record", "digest"]).cloned().unwrap_or(Value::Null),
            "store_uri": get_path(decision, &["record", "store_uri"]).cloned().unwrap_or_else(|| json!("")),
        },
    });
    if let Some(step_idx) = get_path(decision, &["step_idx"]).cloned() {
        ensure_object(&mut doc).insert("step_idx".to_string(), step_idx);
    }
    if let Some(evidence) = get_path(decision, &["evidence"]).cloned() {
        ensure_object(&mut doc).insert("evidence".to_string(), evidence);
    }
    if let Some(kind) = get_path(decision, &["record", "kind"]).cloned() {
        ensure_object_field(&mut doc, "record").insert("kind".to_string(), kind);
    }
    if let Some(media_type) = get_path(decision, &["record", "media_type"]).cloned() {
        ensure_object_field(&mut doc, "record").insert("media_type".to_string(), media_type);
    }
    if let Some(signature_status) = get_path(decision, &["signature_status"]).cloned() {
        ensure_object(&mut doc).insert("signature_status".to_string(), signature_status);
    }
    doc
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

    let local_meta = json!({
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
    });
    let execution_meta = if get_path(&meta, &["ext", "remote"]).is_some() {
        build_remote_execution_meta(
            exec_doc,
            run_doc,
            local_meta.get("meta").unwrap_or(&Value::Null),
        )
    } else {
        local_meta.get("meta").cloned().unwrap_or(Value::Null)
    };
    let mut execution = local_meta;
    ensure_object(&mut execution).insert("meta".to_string(), execution_meta);
    execution
}

#[allow(clippy::too_many_arguments)]
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
    let is_remote = get_path(&meta, &["ext", "remote"]).is_some();
    let target = get_path(&meta, &["target"])
        .cloned()
        .unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"}));
    let mut steps = get_path(exec_doc, &["steps"])
        .and_then(Value::as_array)
        .map(|items| items.iter().map(sanitize_query_step).collect::<Vec<_>>())
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
        .filter(|decision| match get_str(decision, &["kind"]).as_deref() {
            Some("deploy.prepare.plan" | "deploy.analysis.slo") => true,
            Some("deploy.runtime.start_candidate") => !is_remote,
            _ => false,
        })
        .map(|decision| sanitize_query_decision(decision, is_remote))
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

struct RemoteLeaseGuard {
    path: PathBuf,
}

impl Drop for RemoteLeaseGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

enum RemoteLeaseAcquire {
    NotNeeded,
    Acquired(RemoteLeaseGuard),
    Conflict(Value),
}

fn try_acquire_remote_run_lease(
    state_dir: &Path,
    exec_doc: &Value,
    run_id: &str,
    deployment_id: &str,
    now_unix_ms: u64,
) -> Result<RemoteLeaseAcquire> {
    if get_path(exec_doc, &["meta", "ext", "remote"]).is_none() {
        return Ok(RemoteLeaseAcquire::NotNeeded);
    }
    let target = get_path(exec_doc, &["meta", "target"])
        .cloned()
        .unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"}));
    let app_id = get_str(&target, &["app_id"]).unwrap_or_else(|| "unknown".to_string());
    let environment = get_str(&target, &["environment"]).unwrap_or_else(|| "unknown".to_string());
    let leases_dir = state_dir.join(".x07lp").join("leases");
    fs::create_dir_all(&leases_dir)?;
    let lease_path = leases_dir.join(format!("{app_id}__{environment}.json"));
    let lease_doc = json!({
        "schema_version": "lp.deploy.lease@0.1.0",
        "lock_id": format!("lplock_{deployment_id}"),
        "lease_expires_unix_ms": now_unix_ms + 600_000,
        "lease_holder": run_id,
        "target_generation": 0,
    });
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lease_path)
    {
        Ok(mut file) => {
            file.write_all(&canon_json_bytes(&lease_doc))?;
            Ok(RemoteLeaseAcquire::Acquired(RemoteLeaseGuard {
                path: lease_path,
            }))
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(RemoteLeaseAcquire::Conflict(cli_report(
                "deploy run",
                false,
                13,
                json!({ "op": "run", "ok": false }),
                Some(run_id),
                vec![result_diag(
                    "LP_REMOTE_LEASE_CONFLICT",
                    "run",
                    "remote deployment lease is already held",
                    "error",
                )],
            )))
        }
        Err(err) => Err(err.into()),
    }
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
    let _ = materialize_pack_dir(state_dir, run_doc, &pack_dir)?;
    let ops_path = search_workspace_file("ops_release.json");
    if let Some(ops_path) = ops_path.as_ref() {
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
        let (tool, code, stdout, stderr) = run_wasm_tool_capture(&argv, Some(&cwd))?;
        if code == 0
            && let Ok(report) = serde_json::from_slice::<Value>(&stdout)
            && let Some(plan_manifest) = get_str(&report, &["result", "plan_manifest", "path"])
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
        let stderr_msg = String::from_utf8_lossy(&stderr).trim().to_string();
        bail!(
            "{} deploy plan failed for accepted run {}: {}",
            tool.display_name,
            exec_id,
            if stderr_msg.is_empty() {
                format!("exit code {}", code.max(1))
            } else {
                stderr_msg
            }
        );
    }
    bail!(
        "missing ops profile for accepted run {}; cannot generate deploy plan",
        exec_id
    )
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
        if let Some(status) = signature_status
            && status == "valid"
        {
            meta.insert(
                "latest_signed_control_decision_id".to_string(),
                decision.get("decision_id").cloned().unwrap_or(Value::Null),
            );
        }
    }
    if let Some(record) = decision.get("record").cloned() {
        push_artifact(
            exec_doc,
            artifact_summary("decision_record", &record, 0, None),
        );
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

fn latest_exec_doc(state_dir: &Path) -> Result<Option<Value>> {
    let mut best: Option<(u64, String, Value)> = None;
    for exec_id in collect_exec_ids_for_target(state_dir, None, None)? {
        let exec_doc = load_exec(state_dir, &exec_id)?;
        let updated_unix_ms = exec_updated_unix_ms(&exec_doc);
        match &best {
            Some((best_updated, _best_id, _)) if *best_updated > updated_unix_ms => {}
            Some((best_updated, best_id, _))
                if *best_updated == updated_unix_ms && *best_id >= exec_id => {}
            _ => best = Some((updated_unix_ms, exec_id, exec_doc)),
        }
    }
    Ok(best.map(|(_, _, exec_doc)| exec_doc))
}

fn exec_updated_unix_ms(exec_doc: &Value) -> u64 {
    get_u64(exec_doc, &["updated_unix_ms"])
        .or_else(|| get_u64(exec_doc, &["meta", "updated_unix_ms"]))
        .or_else(|| get_u64(exec_doc, &["created_unix_ms"]))
        .unwrap_or(0)
}

fn load_exec_docs(state_dir: &Path) -> Result<Vec<Value>> {
    let mut docs = Vec::new();
    for exec_id in collect_exec_ids_for_target(state_dir, None, None)? {
        docs.push(load_exec(state_dir, &exec_id)?);
    }
    Ok(docs)
}

fn newest_matching_exec<F>(exec_docs: &[Value], predicate: F) -> Option<&Value>
where
    F: Fn(&Value) -> bool,
{
    exec_docs
        .iter()
        .filter(|doc| predicate(doc))
        .max_by_key(|doc| exec_updated_unix_ms(doc))
}

fn control_action_seen(state_dir: &Path, kind: &str) -> Result<bool> {
    let dir = state_dir.join("control_actions");
    if !dir.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let doc = load_json(&path)?;
        if get_str(&doc, &["kind"]).as_deref() == Some(kind)
            || get_str(&doc, &["action_kind"]).as_deref() == Some(kind)
        {
            return Ok(true);
        }
    }
    Ok(false)
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
        if matches_app
            && matches_env
            && let Some(exec_id) = get_str(&exec_doc, &["exec_id"])
        {
            ids.push(exec_id);
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
    static REBUILD_INDEXES_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = REBUILD_INDEXES_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow!("rebuild indexes lock poisoned"))?;
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

fn incident_classification_seen(state_dir: &Path, classification: &str) -> bool {
    read_incident_meta_paths(state_dir).iter().any(|meta_path| {
        load_json(meta_path)
            .ok()
            .and_then(|meta| get_str(&meta, &["classification"]))
            .as_deref()
            == Some(classification)
    })
}

fn insert_phasec_rows(
    conn: &Connection,
    state_dir: &Path,
    latest_heads: &BTreeMap<(String, String), (String, u64)>,
) -> Result<()> {
    let mut app_incident_counts: BTreeMap<(String, String), AppIncidentCountSummary> =
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
            "INSERT OR REPLACE INTO incidents (incident_id, app_id, environment, deployment_id, release_exec_id, run_id, classification, source, incident_status, captured_unix_ms, request_id, trace_id, status_code, decision_id, regression_status, regression_id, bundle_sha256, bundle_bytes_len, bundle_store_uri, meta_store_uri) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                incident_id,
                app_id,
                environment,
                get_str(&meta, &["deployment_id"]),
                get_str(&meta, &["release_exec_id"]),
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
            if let Some(value) = get_path(&bundle, &[key]).cloned()
                && value.is_object()
            {
                refs.push(value);
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

fn remote_mode_selected(explicit: Option<&str>) -> Result<bool> {
    Ok(resolve_target_name(explicit)?.is_some())
}

fn first_diag_message(report: &Value) -> String {
    report
        .get("diagnostics")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("remote operation failed")
        .to_string()
}

fn report_has_diag(report: &Value, code: &str) -> bool {
    report
        .get("diagnostics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|diag| diag.get("code").and_then(Value::as_str) == Some(code))
}

fn remote_error_report(command: &str, code: &str, message: &str) -> Value {
    cli_report(
        command,
        false,
        32,
        json!({}),
        None,
        vec![result_diag(code, "run", message, "error")],
    )
}

fn contracts_schema_index_path() -> PathBuf {
    root_dir()
        .join("contracts")
        .join("spec")
        .join("schemas")
        .join("index.json")
}

fn contracts_schema_dir() -> PathBuf {
    root_dir().join("contracts").join("spec").join("schemas")
}

fn is_versioned_schema_id(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once('@') else {
        return false;
    };
    if name.is_empty() || version.is_empty() {
        return false;
    }
    let mut segments = version.split('.');
    segments.clone().count() == 3
        && segments
            .all(|segment| !segment.is_empty() && segment.chars().all(|ch| ch.is_ascii_digit()))
}

fn schema_public_id(schema: &Value) -> Option<String> {
    let title = schema.get("title").and_then(Value::as_str)?;
    if is_versioned_schema_id(title) {
        return Some(title.to_string());
    }
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("schema_version"))
        .and_then(|value| value.get("const"))
        .and_then(Value::as_str)
        .filter(|value| is_versioned_schema_id(value))
        .map(|value| value.to_string())
}

fn supported_schema_ids() -> Vec<String> {
    let mut ids = Vec::new();
    if let Ok(index) = load_json(&contracts_schema_index_path())
        && let Some(items) = index.get("schemas").and_then(Value::as_array)
    {
        for item in items {
            if let Some(path) = item.get("path").and_then(Value::as_str) {
                let schema_path = contracts_schema_dir().join(path);
                if let Ok(schema) = load_json(&schema_path)
                    && let Some(id) = schema_public_id(&schema)
                {
                    ids.push(id);
                }
            }
        }
    }
    if ids.is_empty() {
        ids = vec![
            "lp.cli.report@0.1.0".to_string(),
            "lp.deploy.execution@0.1.0".to_string(),
            "lp.deploy.query.result@0.1.0".to_string(),
            DEVICE_INCIDENT_QUERY_RESULT_KIND.to_string(),
            REGRESSION_RUN_RESULT_KIND.to_string(),
            "lp.remote.capabilities.response@0.1.0".to_string(),
        ];
    }
    ids.sort();
    ids.dedup();
    ids
}

#[derive(Debug, Clone)]
struct ResolvedTarget {
    name: String,
    base_url: String,
    token: String,
    tls_mode: TargetTlsMode,
    ca_bundle_path: Option<PathBuf>,
    pinned_spki_sha256: Option<String>,
    profile: Value,
}

fn load_target_token(profile: &Value, name: &str) -> Result<String> {
    if let Some(token_ref) = get_str(profile, &["auth", "token_ref"]) {
        return load_text_ref(&token_ref);
    }
    let token_path = default_target_token_path(name)?;
    if token_path.exists() {
        let token = fs::read_to_string(&token_path)?.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }
    Ok(remote_server_token())
}

fn resolved_target_from_profile_doc(profile: &Value) -> Result<ResolvedTarget> {
    let name = get_str(profile, &["name"]).ok_or_else(|| anyhow!("missing target name"))?;
    let base_url = get_str(profile, &["base_url"]).ok_or_else(|| anyhow!("missing base_url"))?;
    let (tls_mode, ca_bundle_path, pinned_spki_sha256) = tls_mode_from_profile(profile)?;
    let token = load_target_token(profile, &name)?;
    Ok(ResolvedTarget {
        name,
        base_url,
        token,
        tls_mode,
        ca_bundle_path,
        pinned_spki_sha256,
        profile: profile.clone(),
    })
}

fn resolve_remote_target(explicit: Option<&str>) -> Result<Option<ResolvedTarget>> {
    let Some(name) = resolve_target_name(explicit)? else {
        return Ok(None);
    };
    let profile = load_target_profile_doc(&name)?;
    Ok(Some(resolved_target_from_profile_doc(&profile)?))
}

fn required_remote_target(explicit: Option<&str>) -> Result<ResolvedTarget> {
    resolve_remote_target(explicit)?
        .ok_or_else(|| anyhow!("remote operation requires a configured target"))
}

fn build_remote_capabilities_doc() -> Value {
    let mut doc = json!({
        "schema_version": "lp.remote.capabilities.response@0.1.0",
        "api_version": REMOTE_API_VERSION,
        "generated_unix_ms": now_ms(),
        "server_id": REMOTE_SERVER_ID,
        "runtime_provider": REMOTE_RUNTIME_PROVIDER,
        "routing_provider": REMOTE_ROUTING_PROVIDER,
        "telemetry_provider": REMOTE_TELEMETRY_PROVIDER,
        "secrets_provider": REMOTE_SECRETS_PROVIDER,
        "component_registry": REMOTE_COMPONENT_REGISTRY,
        "artifact_distribution": "oci",
        "accepted_artifact_kinds": [REMOTE_ARTIFACT_KIND],
        "supported_schema_ids": supported_schema_ids(),
        "supported_deploy_plan_versions": ["x07.deploy.plan@0.2.0"],
        "features": {
            "incidents": true,
            "regressions": true,
            "pause": true,
            "rerun": true,
            "weighted_canary": true,
            "otlp": true,
            "server_side_secrets": true,
            "authenticated_oci_push": true,
            "registry_tls": true,
            "event_stream": true,
            "signed_control_actions": true
        },
        "limits": {
            "max_blob_bytes": 16 * 1024 * 1024,
            "max_parallel_uploads": 4,
            "max_presence_batch": 4096,
            "max_query_limit": 256
        },
        "auth": {
            "scheme": "bearer",
            "token_kind": "opaque",
            "required_scopes": [
                "lp.deploy.read",
                "lp.deploy.write",
                "lp.artifacts.read",
                "lp.artifacts.write",
                "lp.incident.read",
                "lp.incident.write",
                "lp.regression.write",
                "lp.adapter.read"
            ]
        }
    });
    let bytes = canon_json_bytes(&doc);
    ensure_object(&mut doc).insert("capabilities_digest".to_string(), digest_value(&bytes));
    doc
}

fn build_adapter_capabilities_doc(capabilities: &Value) -> Value {
    json!({
        "schema_version": "lp.adapter.capabilities@0.1.0",
        "provider": "wasmcloud",
        "runtime_kind": get_str(capabilities, &["runtime_provider"]).unwrap_or_else(|| REMOTE_RUNTIME_PROVIDER.to_string()),
        "routing_kind": get_str(capabilities, &["routing_provider"]).unwrap_or_else(|| REMOTE_ROUTING_PROVIDER.to_string()),
        "artifact_distribution": get_str(capabilities, &["artifact_distribution"]).unwrap_or_else(|| "oci".to_string()),
        "supports_incidents": get_bool(capabilities, &["features", "incidents"]).unwrap_or(true),
        "supports_regressions": get_bool(capabilities, &["features", "regressions"]).unwrap_or(true),
        "supports_pause": get_bool(capabilities, &["features", "pause"]).unwrap_or(true),
        "supports_rerun": get_bool(capabilities, &["features", "rerun"]).unwrap_or(true),
        "supports_weighted_canary": get_bool(capabilities, &["features", "weighted_canary"]).unwrap_or(true),
        "supports_otlp": get_bool(capabilities, &["features", "otlp"]).unwrap_or(true),
        "supports_server_side_secrets": get_bool(capabilities, &["features", "server_side_secrets"]).unwrap_or(true),
        "supports_authenticated_oci_push": get_bool(capabilities, &["features", "authenticated_oci_push"]).unwrap_or(true),
        "supports_registry_tls": get_bool(capabilities, &["features", "registry_tls"]).unwrap_or(true)
    })
}

fn remote_agent() -> Agent {
    Agent::new()
}

fn hosted_request_json(
    method: &str,
    url: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> Result<Value> {
    let agent = remote_agent();
    let request = agent.request(method, url).set("accept", "application/json");
    let request = if let Some(token) = bearer {
        request.set("authorization", &format!("Bearer {token}"))
    } else {
        request
    };
    let response = match body {
        Some(doc) => request
            .set("content-type", "application/json")
            .send_json(doc.clone()),
        None => request.call(),
    };
    match response {
        Ok(response) => decode_http_json_response(response),
        Err(UreqError::Status(_, response)) => decode_http_json_response(response),
        Err(UreqError::Transport(err)) => bail!("hosted request failed: {method} {url}: {err}"),
    }
}

fn hosted_form_body(params: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn hosted_request_form(
    method: &str,
    url: &str,
    bearer: Option<&str>,
    params: &[(String, String)],
) -> Result<Value> {
    let agent = remote_agent();
    let request = agent
        .request(method, url)
        .set("accept", "application/json")
        .set("content-type", "application/x-www-form-urlencoded");
    let request = if let Some(token) = bearer {
        request.set("authorization", &format!("Bearer {token}"))
    } else {
        request
    };
    let response = request.send_string(&hosted_form_body(params));
    match response {
        Ok(response) => decode_http_json_response(response),
        Err(UreqError::Status(_, response)) => decode_http_json_response(response),
        Err(UreqError::Transport(err)) => bail!("hosted request failed: {method} {url}: {err}"),
    }
}

fn unwrap_hosted_cli_report(response: Value) -> Result<Value> {
    if get_str(&response, &["schema_version"]).as_deref() != Some("lp.cli.report@0.1.0") {
        return Ok(response);
    }
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(response.get("result").cloned().unwrap_or_else(|| json!({})));
    }
    bail!("{}", first_diag_message(&response))
}

fn oauth_error_message(response: &Value) -> Option<String> {
    let error = response.get("error").and_then(Value::as_str)?;
    let description = response
        .get("error_description")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    Some(match description {
        Some(description) => format!("{error}: {description}"),
        None => error.to_string(),
    })
}

fn parse_hosted_auth_metadata(api_base: &str, metadata_url: &str, response: Value) -> Result<HostedAuthMetadata> {
    let doc = unwrap_hosted_cli_report(response)?;
    let issuer = get_str(&doc, &["issuer"]).ok_or_else(|| anyhow!("missing OIDC issuer"))?;
    let jwks_uri = get_str(&doc, &["jwks_uri"]).ok_or_else(|| anyhow!("missing OIDC jwks_uri"))?;
    Ok(HostedAuthMetadata {
        api_base: api_base.to_string(),
        metadata_url: metadata_url.to_string(),
        issuer,
        authorization_endpoint: get_str(&doc, &["authorization_endpoint"])
            .unwrap_or_else(|| format!("{api_base}/oauth/authorize")),
        token_endpoint: get_str(&doc, &["token_endpoint"])
            .unwrap_or_else(|| format!("{api_base}/oauth/token")),
        device_authorization_endpoint: get_str(&doc, &["device_authorization_endpoint"])
            .or_else(|| get_str(&doc, &["device_endpoint"]))
            .unwrap_or_else(|| format!("{api_base}/oauth/device/code")),
        revocation_endpoint: get_str(&doc, &["revocation_endpoint"])
            .unwrap_or_else(|| format!("{api_base}/oauth/revoke")),
        jwks_uri,
        client_id: get_str(&doc, &["x07lp_client_id"])
            .or_else(|| get_str(&doc, &["client_id"]))
            .unwrap_or_else(|| DEFAULT_HOSTED_CLIENT_ID.to_string()),
        scope: get_str(&doc, &["x07lp_scope"]).unwrap_or_else(|| DEFAULT_HOSTED_SCOPE.to_string()),
    })
}

fn load_hosted_auth_metadata(api_base: &str) -> Result<HostedAuthMetadata> {
    let metadata_url = format!("{}/.well-known/openid-configuration", api_base.trim_end_matches('/'));
    let response = hosted_request_json("GET", &metadata_url, None, None)?;
    parse_hosted_auth_metadata(api_base, &metadata_url, response)
}

fn load_hosted_auth_metadata_from_session(session: &Value) -> Result<HostedAuthMetadata> {
    let api_base = session_api_base(session)?;
    let metadata_url = get_str(session, &["auth_metadata_url"])
        .unwrap_or_else(|| format!("{api_base}/.well-known/openid-configuration"));
    let response = hosted_request_json("GET", &metadata_url, None, None)?;
    parse_hosted_auth_metadata(&api_base, &metadata_url, response)
}

fn random_urlsafe_token(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    BASE64_URL_SAFE_NO_PAD.encode(digest)
}

fn open_browser_best_effort(url: &str) -> bool {
    for argv in [["open", url], ["xdg-open", url]] {
        if Command::new(argv[0]).arg(argv[1]).status().is_ok() {
            return true;
        }
    }
    false
}

fn wait_for_browser_login_code(listener: TcpListener, expected_state: &str) -> Result<String> {
    listener
        .set_nonblocking(true)
        .context("configure loopback callback listener")?;
    let deadline = Instant::now() + Duration::from_secs(HOSTED_LOGIN_TIMEOUT_SECS);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let request = read_http_request(&mut stream)?;
                if let Some(error) = request.query.get("error") {
                    let description = request
                        .query
                        .get("error_description")
                        .map(String::as_str)
                        .unwrap_or(error);
                    let body = format!(
                        "<html><body><h1>x07lp login failed</h1><p>{description}</p></body></html>"
                    );
                    let _ = write_http_response(
                        &mut stream,
                        400,
                        "text/html; charset=utf-8",
                        body.as_bytes(),
                    );
                    bail!("login failed: {description}");
                }
                if request.query.get("state").map(String::as_str) != Some(expected_state) {
                    let body =
                        "<html><body><h1>x07lp login failed</h1><p>state mismatch</p></body></html>";
                    let _ =
                        write_http_response(&mut stream, 400, "text/html; charset=utf-8", body.as_bytes());
                    bail!("login failed: state mismatch");
                }
                let code = request
                    .query
                    .get("code")
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .ok_or_else(|| anyhow!("login failed: missing authorization code"))?;
                let body =
                    "<html><body><h1>x07lp login complete</h1><p>You can return to the terminal.</p></body></html>";
                let _ = write_http_response(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    body.as_bytes(),
                );
                return Ok(code);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    bail!("timed out waiting for browser login callback");
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(err).context("accept browser login callback"),
        }
    }
}

fn exchange_authorization_code(
    metadata: &HostedAuthMetadata,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<Value> {
    let response = hosted_request_form(
        "POST",
        &metadata.token_endpoint,
        None,
        &[
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("client_id".to_string(), metadata.client_id.clone()),
            ("code".to_string(), code.to_string()),
            ("code_verifier".to_string(), code_verifier.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
        ],
    )?;
    if let Some(message) = oauth_error_message(&response) {
        bail!("login failed: {message}");
    }
    let doc = unwrap_hosted_cli_report(response)?;
    validate_hosted_token_response(&doc)?;
    Ok(doc)
}

fn device_flow_token(metadata: &HostedAuthMetadata) -> Result<Value> {
    let device_start = hosted_request_form(
        "POST",
        &metadata.device_authorization_endpoint,
        None,
        &[
            ("client_id".to_string(), metadata.client_id.clone()),
            ("scope".to_string(), metadata.scope.clone()),
        ],
    )?;
    let start = unwrap_hosted_cli_report(device_start)?;
    let device_code = get_str(&start, &["device_code"])
        .ok_or_else(|| anyhow!("device login failed: missing device_code"))?;
    let user_code =
        get_str(&start, &["user_code"]).ok_or_else(|| anyhow!("device login failed: missing user_code"))?;
    let verification_uri = get_str(&start, &["verification_uri"])
        .ok_or_else(|| anyhow!("device login failed: missing verification_uri"))?;
    let verification_uri_complete = get_str(&start, &["verification_uri_complete"]);
    let expires_in = get_u64(&start, &["expires_in"]).unwrap_or(HOSTED_LOGIN_TIMEOUT_SECS);
    let mut interval = get_u64(&start, &["interval"]).unwrap_or(5);
    eprintln!(
        "x07lp device login: visit {} and enter code {}",
        verification_uri, user_code
    );
    if let Some(url) = verification_uri_complete.as_deref() {
        let _ = open_browser_best_effort(url);
    }
    let deadline = Instant::now() + Duration::from_secs(expires_in);
    loop {
        if Instant::now() >= deadline {
            bail!("device login timed out before authorization completed");
        }
        thread::sleep(Duration::from_secs(interval.max(1)));
        let response = hosted_request_form(
            "POST",
            &metadata.token_endpoint,
            None,
            &[
                (
                    "grant_type".to_string(),
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                ),
                ("client_id".to_string(), metadata.client_id.clone()),
                ("device_code".to_string(), device_code.clone()),
            ],
        )?;
        if let Some(error) = response.get("error").and_then(Value::as_str) {
            match error {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval = interval.saturating_add(5);
                    continue;
                }
                "access_denied" | "expired_token" => {
                    bail!("{}", oauth_error_message(&response).unwrap_or_else(|| error.to_string()))
                }
                _ => bail!(
                    "{}",
                    oauth_error_message(&response).unwrap_or_else(|| error.to_string())
                ),
            }
        }
        let doc = unwrap_hosted_cli_report(response)?;
        validate_hosted_token_response(&doc)?;
        return Ok(doc);
    }
}

fn browser_flow_token(metadata: &HostedAuthMetadata) -> Result<Value> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback callback listener")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener
            .local_addr()
            .context("inspect loopback callback listener")?
            .port()
    );
    let state = random_urlsafe_token(16);
    let verifier = random_urlsafe_token(32);
    let challenge = pkce_code_challenge(&verifier);
    let mut url = Url::parse(&metadata.authorization_endpoint)
        .with_context(|| format!("parse authorization endpoint {}", metadata.authorization_endpoint))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &metadata.client_id);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("scope", &metadata.scope);
        query.append_pair("state", &state);
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
    }
    if !open_browser_best_effort(url.as_str()) {
        eprintln!("x07lp login: open this URL in a browser: {}", url.as_str());
    }
    let code = wait_for_browser_login_code(listener, &state)?;
    exchange_authorization_code(metadata, &code, &verifier, &redirect_uri)
}

fn fetch_hosted_whoami(api_base: &str, access_token: &str) -> Result<Value> {
    let response = hosted_request_json("GET", &format!("{api_base}/v1/whoami"), Some(access_token), None)?;
    if let Some(message) = oauth_error_message(&response) {
        bail!("whoami failed: {message}");
    }
    let doc = unwrap_hosted_cli_report(response)?;
    validate_hosted_whoami_result(&doc)?;
    Ok(doc)
}

fn rewrite_session_from_whoami(session: &Value, whoami: &Value) -> Result<Value> {
    validate_hosted_session_doc(session)?;
    validate_hosted_whoami_result(whoami)?;
    let mut updated = session.clone();
    let map = ensure_object(&mut updated);
    map.insert(
        "account".to_string(),
        whoami.get("account").cloned().unwrap_or_else(|| json!({})),
    );
    map.insert(
        "target".to_string(),
        whoami.get("target").cloned().unwrap_or_else(|| json!({})),
    );
    map.insert(
        "default_context".to_string(),
        whoami
            .get("default_context")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    map.insert("updated_unix_ms".to_string(), json!(now_ms()));
    let tokens = ensure_object_field(&mut updated, "tokens");
    tokens.insert(
        "scope".to_string(),
        Value::Array(
            scope_array(whoami.get("scope").unwrap_or(&Value::Null))
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    validate_hosted_session_doc(&updated)?;
    Ok(updated)
}

fn refresh_hosted_session(session: &Value) -> Result<Value> {
    let metadata = load_hosted_auth_metadata_from_session(session)?;
    let refresh_token = session_refresh_token(session)?;
    let response = hosted_request_form(
        "POST",
        &metadata.token_endpoint,
        None,
        &[
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("client_id".to_string(), metadata.client_id.clone()),
            ("refresh_token".to_string(), refresh_token),
        ],
    )?;
    if let Some(message) = oauth_error_message(&response) {
        bail!("session refresh failed: {message}");
    }
    let token_response = unwrap_hosted_cli_report(response)?;
    validate_hosted_token_response(&token_response)?;
    let whoami = fetch_hosted_whoami(&metadata.api_base, &get_str(&token_response, &["access_token"]).unwrap())?;
    let updated = build_hosted_session_doc(&metadata, &token_response, &whoami, Some(session))?;
    let _ = store_hosted_session_doc(&updated)?;
    Ok(updated)
}

fn ensure_hosted_session_ready(explicit_api_base: Option<&str>) -> Result<Value> {
    let expected_api_base = requested_hosted_api_base(explicit_api_base)?;
    let session = load_hosted_session_doc()?;
    let actual_api_base = session_api_base(&session)?;
    if let Some(expected) = expected_api_base
        && expected != actual_api_base
    {
        bail!(
            "saved hosted session belongs to {actual_api_base}; run `x07lp login --api-base {expected}` to replace it"
        );
    }
    if session_needs_refresh(&session, now_ms()) {
        return refresh_hosted_session(&session);
    }
    Ok(session)
}

fn revoke_hosted_token(metadata: &HostedAuthMetadata, token: &str) -> Result<()> {
    let response = hosted_request_form(
        "POST",
        &metadata.revocation_endpoint,
        None,
        &[
            ("client_id".to_string(), metadata.client_id.clone()),
            ("token".to_string(), token.to_string()),
        ],
    )?;
    if let Some(message) = oauth_error_message(&response) {
        bail!("token revoke failed: {message}");
    }
    let _ = unwrap_hosted_cli_report(response)?;
    Ok(())
}

fn report_ok(report: &Value) -> bool {
    report.get("ok").and_then(Value::as_bool) == Some(true)
}

fn hosted_error_report(command: &str, code: &str, exit_code: i64, message: &str) -> Value {
    cli_report(
        command,
        false,
        exit_code,
        json!({}),
        None,
        vec![result_diag(code, "run", message, "error")],
    )
}

fn hosted_command_result(
    command: &str,
    code: &str,
    exit_code: i64,
    result: Result<Value>,
) -> Result<Value> {
    Ok(match result {
        Ok(report) => report,
        Err(err) => hosted_error_report(command, code, exit_code, &err.to_string()),
    })
}

fn hosted_v1_request_report(
    session: &Value,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let api_base = session_api_base(session)?;
    let access_token = session_access_token(session)?;
    let response = hosted_request_json(
        method,
        &format!("{}{}", api_base.trim_end_matches('/'), path),
        Some(&access_token),
        body,
    )?;
    if let Some(message) = oauth_error_message(&response) {
        bail!("{message}");
    }
    Ok(response)
}

fn hosted_v1_result(
    session: &Value,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let report = hosted_v1_request_report(session, method, path, body)?;
    if get_str(&report, &["schema_version"]).as_deref() != Some("lp.cli.report@0.1.0") {
        bail!("unexpected hosted response envelope");
    }
    unwrap_hosted_cli_report(report)
}

fn result_items<'a>(doc: &'a Value, schema_version: &str) -> Result<&'a [Value]> {
    if get_str(doc, &["schema_version"]).as_deref() != Some(schema_version) {
        bail!("unexpected hosted result schema_version");
    }
    doc.get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("hosted result does not contain items"))
}

fn find_item_by_identifier<'a>(
    items: &'a [Value],
    identifier: &str,
    id_key: &str,
    slug_key: &str,
) -> Option<&'a Value> {
    items.iter().find(|item| {
        get_str(item, &[id_key]).as_deref() == Some(identifier)
            || get_str(item, &[slug_key]).as_deref() == Some(identifier)
    })
}

fn session_default_org_id(session: &Value) -> Result<String> {
    get_str(session, &["default_context", "org_id"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hosted session is missing default_context.org_id"))
}

fn session_default_project_id(session: &Value) -> Result<String> {
    get_str(session, &["default_context", "project_id"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hosted session is missing default_context.project_id"))
}

fn resolve_org_id(session: &Value, identifier: &str) -> Result<String> {
    if get_str(session, &["default_context", "org_id"]).as_deref() == Some(identifier)
        || get_str(session, &["default_context", "org_slug"]).as_deref() == Some(identifier)
    {
        return session_default_org_id(session);
    }
    let result = hosted_v1_result(session, "GET", "/v1/orgs", None)?;
    let items = result_items(&result, "lp.org.list.result@0.1.0")?;
    let item = find_item_by_identifier(items, identifier, "org_id", "org_slug")
        .ok_or_else(|| anyhow!("unknown organization `{identifier}`"))?;
    get_str(item, &["org_id"]).ok_or_else(|| anyhow!("organization is missing org_id"))
}

fn resolve_project_id_in_org(session: &Value, org_id: &str, identifier: &str) -> Result<String> {
    if session_default_org_id(session).ok().as_deref() == Some(org_id)
        && (get_str(session, &["default_context", "project_id"]).as_deref() == Some(identifier)
            || get_str(session, &["default_context", "project_slug"]).as_deref()
                == Some(identifier))
    {
        return session_default_project_id(session);
    }
    let result = hosted_v1_result(
        session,
        "GET",
        &format!("/v1/projects?org_id={org_id}"),
        None,
    )?;
    let items = result_items(&result, "lp.project.list.result@0.1.0")?;
    let item = find_item_by_identifier(items, identifier, "project_id", "project_slug")
        .ok_or_else(|| anyhow!("unknown project `{identifier}`"))?;
    get_str(item, &["project_id"]).ok_or_else(|| anyhow!("project is missing project_id"))
}

fn resolve_project_id(session: &Value, identifier: &str) -> Result<String> {
    let org_id = session_default_org_id(session)?;
    resolve_project_id_in_org(session, &org_id, identifier)
}

fn resolve_environment_id(session: &Value, project_id: &str, identifier: &str) -> Result<String> {
    let result = hosted_v1_result(
        session,
        "GET",
        &format!("/v1/environments?project_id={project_id}"),
        None,
    )?;
    let items = result_items(&result, "lp.environment.list.result@0.1.0")?;
    let item = find_item_by_identifier(
        items,
        identifier,
        "environment_id",
        "environment_slug",
    )
    .ok_or_else(|| anyhow!("unknown environment `{identifier}`"))?;
    get_str(item, &["environment_id"])
        .ok_or_else(|| anyhow!("environment is missing environment_id"))
}

fn command_login(args: LoginArgs) -> Result<Value> {
    hosted_command_result(
        "login",
        "LP_HOSTED_LOGIN_FAILED",
        31,
        (|| {
            let api_base = resolve_hosted_api_base(args.api_base.as_deref())?;
            let metadata = load_hosted_auth_metadata(&api_base)?;
            let token_response = if args.device {
                device_flow_token(&metadata)?
            } else {
                browser_flow_token(&metadata)?
            };
            let access_token = get_str(&token_response, &["access_token"])
                .ok_or_else(|| anyhow!("login failed: missing access token"))?;
            let whoami = fetch_hosted_whoami(&api_base, &access_token)?;
            let existing = load_hosted_session_doc_if_exists()?;
            let current = existing.as_ref().filter(|session| {
                session_api_base(session)
                    .map(|value| value == api_base)
                    .unwrap_or(false)
            });
            let session = build_hosted_session_doc(&metadata, &token_response, &whoami, current)?;
            let path = store_hosted_session_doc(&session)?;
            Ok(cli_report(
                "login",
                true,
                0,
                json!({
                    "mode": if args.device { "device" } else { "browser" },
                    "session_path": path.to_string_lossy(),
                    "session": redacted_session_summary(&session)
                }),
                None,
                Vec::new(),
            ))
        })(),
    )
}

fn command_whoami(args: HostedCommonArgs) -> Result<Value> {
    hosted_command_result(
        "whoami",
        "LP_HOSTED_WHOAMI_FAILED",
        31,
        (|| {
            let session = ensure_hosted_session_ready(args.api_base.as_deref())?;
            let report = hosted_v1_request_report(&session, "GET", "/v1/whoami", None)?;
            if !report_ok(&report) {
                return Ok(report);
            }
            let whoami = report
                .get("result")
                .cloned()
                .ok_or_else(|| anyhow!("hosted whoami report missing result"))?;
            validate_hosted_whoami_result(&whoami)?;
            let updated = rewrite_session_from_whoami(&session, &whoami)?;
            let _ = store_hosted_session_doc(&updated)?;
            Ok(report)
        })(),
    )
}

fn command_logout(args: HostedCommonArgs) -> Result<Value> {
    hosted_command_result(
        "logout",
        "LP_HOSTED_LOGOUT_FAILED",
        31,
        (|| {
            let Some(session) = load_hosted_session_doc_if_exists()? else {
                return Ok(cli_report(
                    "logout",
                    true,
                    0,
                    json!({ "deleted": false, "revoked_tokens": 0 }),
                    None,
                    Vec::new(),
                ));
            };
            if let Some(expected) = requested_hosted_api_base(args.api_base.as_deref())? {
                let actual = session_api_base(&session)?;
                if actual != expected {
                    bail!(
                        "saved hosted session belongs to {actual}; run `x07lp login --api-base {expected}` to replace it"
                    );
                }
            }
            let metadata = load_hosted_auth_metadata_from_session(&session)?;
            let mut revoked_tokens = 0;
            if let Ok(access_token) = session_access_token(&session) {
                revoke_hosted_token(&metadata, &access_token)?;
                revoked_tokens += 1;
            }
            if let Some(refresh_token) =
                get_str(&session, &["tokens", "refresh_token"]).filter(|value| !value.is_empty())
            {
                let _ = revoke_hosted_token(&metadata, &refresh_token);
                revoked_tokens += 1;
            }
            let deleted = delete_hosted_session_doc()?;
            Ok(cli_report(
                "logout",
                true,
                0,
                json!({ "deleted": deleted, "revoked_tokens": revoked_tokens }),
                None,
                Vec::new(),
            ))
        })(),
    )
}

fn command_org(args: HostedOrgArgs) -> Result<Value> {
    match args.command {
        HostedOrgCommand::List(common) => hosted_command_result(
            "org list",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(common.api_base.as_deref())?;
                hosted_v1_request_report(&session, "GET", "/v1/orgs", None)
            })(),
        ),
        HostedOrgCommand::Create(args) => hosted_command_result(
            "org create",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let body = json!({
                    "slug": chosen_slug(&args.name, args.slug.as_deref())?,
                    "display_name": args.name,
                });
                hosted_v1_request_report(&session, "POST", "/v1/orgs", Some(&body))
            })(),
        ),
    }
}

fn command_project(args: HostedProjectArgs) -> Result<Value> {
    match args.command {
        HostedProjectCommand::List(args) => hosted_command_result(
            "project list",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let org_id = resolve_org_id(&session, &args.org)?;
                hosted_v1_request_report(
                    &session,
                    "GET",
                    &format!("/v1/projects?org_id={org_id}"),
                    None,
                )
            })(),
        ),
        HostedProjectCommand::Create(args) => hosted_command_result(
            "project create",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let org_id = resolve_org_id(&session, &args.org)?;
                let body = json!({
                    "org_id": org_id,
                    "slug": chosen_slug(&args.name, args.slug.as_deref())?,
                    "display_name": args.name,
                });
                hosted_v1_request_report(&session, "POST", "/v1/projects", Some(&body))
            })(),
        ),
    }
}

fn command_environment(args: HostedEnvironmentArgs) -> Result<Value> {
    match args.command {
        HostedEnvironmentCommand::List(args) => hosted_command_result(
            "env list",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let project_id = resolve_project_id(&session, &args.project)?;
                hosted_v1_request_report(
                    &session,
                    "GET",
                    &format!("/v1/environments?project_id={project_id}"),
                    None,
                )
            })(),
        ),
        HostedEnvironmentCommand::Create(args) => hosted_command_result(
            "env create",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let project_id = resolve_project_id(&session, &args.project)?;
                let body = json!({
                    "project_id": project_id,
                    "key": chosen_slug(&args.name, args.slug.as_deref())?,
                    "display_name": args.name,
                });
                hosted_v1_request_report(&session, "POST", "/v1/environments", Some(&body))
            })(),
        ),
    }
}

fn command_context(args: HostedContextArgs) -> Result<Value> {
    match args.command {
        HostedContextCommand::Use(args) => hosted_command_result(
            "context use",
            "LP_HOSTED_API_FAILED",
            32,
            (|| {
                let session = ensure_hosted_session_ready(args.common.api_base.as_deref())?;
                let org_id = resolve_org_id(&session, &args.org)?;
                let project_id = resolve_project_id_in_org(&session, &org_id, &args.project)?;
                let environment_id = match args.environment.as_deref() {
                    Some(identifier) => Some(resolve_environment_id(&session, &project_id, identifier)?),
                    None => None,
                };
                let body = json!({
                    "org_id": org_id,
                    "project_id": project_id,
                    "environment_id": environment_id,
                });
                let report =
                    hosted_v1_request_report(&session, "POST", "/v1/context/select", Some(&body))?;
                if !report_ok(&report) {
                    return Ok(report);
                }
                let session_doc = report
                    .get("result")
                    .cloned()
                    .ok_or_else(|| anyhow!("context use report missing result"))?;
                validate_hosted_session_doc(&session_doc)?;
                let path = store_hosted_session_doc(&session_doc)?;
                Ok(cli_report(
                    "context use",
                    true,
                    0,
                    json!({
                        "session_path": path.to_string_lossy(),
                        "session": redacted_session_summary(&session_doc)
                    }),
                    None,
                    Vec::new(),
                ))
            })(),
        ),
    }
}

fn agent_with_ca_bundle(ca_bundle_path: Option<&Path>) -> Result<Agent> {
    let connector = native_tls_connector(ca_bundle_path)?;
    Ok(ureq::AgentBuilder::new().tls_connector(connector).build())
}

fn target_agent(target: &ResolvedTarget) -> Result<Agent> {
    agent_with_ca_bundle(target.ca_bundle_path.as_deref())
}

fn url_host_and_port(url: &Url) -> Result<(String, u16)> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing host in URL: {url}"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("missing port in URL: {url}"))?;
    Ok((host, port))
}

fn enforce_spki_pin(
    tls_mode: TargetTlsMode,
    ca_bundle_path: Option<&Path>,
    pinned_spki_sha256: Option<&str>,
    url: &str,
) -> Result<()> {
    if !matches!(tls_mode, TargetTlsMode::PinnedSpki) {
        return Ok(());
    }
    let expected = pinned_spki_sha256.ok_or_else(|| anyhow!("missing pinned SPKI hash"))?;
    let parsed = parse_url(url)?;
    if parsed.scheme() != "https" {
        bail!("SPKI pinning requires https://");
    }
    let (host, port) = url_host_and_port(&parsed)?;
    let connector = native_tls_connector(ca_bundle_path)?;
    let tcp = TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("resolve {host}:{port} produced no socket addresses"))?,
        Duration::from_secs(5),
    )
    .with_context(|| format!("connect {host}:{port}"))?;
    let tls = connector
        .connect(host.as_str(), tcp)
        .with_context(|| format!("handshake {host}:{port}"))?;
    let cert = tls
        .peer_certificate()
        .context("inspect peer certificate")?
        .ok_or_else(|| anyhow!("missing peer certificate"))?;
    let actual = spki_pin_from_cert(&cert.to_der().context("serialize peer certificate")?)?;
    if actual != expected {
        bail!("remote TLS SPKI pin mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn enforce_target_spki_pin(target: &ResolvedTarget, url: &str) -> Result<()> {
    enforce_spki_pin(
        target.tls_mode,
        target.ca_bundle_path.as_deref(),
        target.pinned_spki_sha256.as_deref(),
        url,
    )
}

fn profile_agent(profile: &Value) -> Result<Agent> {
    let (_mode, ca_bundle_path, _pin) = tls_mode_from_profile(profile)?;
    agent_with_ca_bundle(ca_bundle_path.as_deref())
}

fn enforce_profile_spki_pin(profile: &Value, url: &str) -> Result<()> {
    let (mode, ca_bundle_path, pin) = tls_mode_from_profile(profile)?;
    enforce_spki_pin(mode, ca_bundle_path.as_deref(), pin.as_deref(), url)
}

fn remote_server_token() -> String {
    std::env::var("X07LP_REMOTE_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REMOTE_BEARER_TOKEN.to_string())
}

fn remote_secret_store_path(state_dir: &Path) -> PathBuf {
    std::env::var_os("X07LP_REMOTE_SECRET_STORE_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            state_dir
                .join(".x07lp")
                .join("remote")
                .join(DEFAULT_REMOTE_SECRET_STORE_FILE)
        })
}

fn empty_remote_secret_store_doc() -> Value {
    json!({
        "schema_version": "lp.remote.secret.store.internal@0.1.0",
        "targets": {}
    })
}

fn ensure_owner_only_file(path: &Path, label: &str) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        bail!("{label} must have mode 0600: {}", path.display());
    }
    Ok(())
}

fn remote_secret_master_key_path() -> Result<PathBuf> {
    let raw = std::env::var_os(REMOTE_SECRET_MASTER_KEY_FILE_ENV)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing {REMOTE_SECRET_MASTER_KEY_FILE_ENV}"))?;
    expand_user_path(&raw.to_string_lossy())
}

fn load_remote_secret_master_key() -> Result<[u8; 32]> {
    let path = remote_secret_master_key_path()?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_string();
    if raw.is_empty() {
        bail!("empty remote secret master key file: {}", path.display());
    }
    let decoded =
        hex::decode(&raw).with_context(|| format!("decode master key {}", path.display()))?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        anyhow!(
            "remote secret master key must be 32 bytes: {}",
            path.display()
        )
    })?;
    Ok(bytes)
}

fn encrypt_remote_secret_store_doc(doc: &Value, key: &[u8; 32]) -> Result<Value> {
    let cipher = Aes256GcmSiv::new_from_slice(key).context("create secret-store cipher")?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), canon_json_bytes(doc).as_ref())
        .map_err(|_| anyhow!("encrypt remote secret store"))?;
    Ok(json!({
        "schema_version": REMOTE_SECRET_STORE_SCHEMA_VERSION,
        "alg": REMOTE_SECRET_STORE_ALG,
        "nonce_b64": BASE64.encode(nonce),
        "ciphertext_b64": BASE64.encode(ciphertext)
    }))
}

fn decrypt_remote_secret_store_doc(envelope: &Value, key: &[u8; 32]) -> Result<Value> {
    if get_str(envelope, &["schema_version"]).as_deref() != Some(REMOTE_SECRET_STORE_SCHEMA_VERSION)
    {
        bail!("invalid remote secret store schema_version");
    }
    if get_str(envelope, &["alg"]).as_deref() != Some(REMOTE_SECRET_STORE_ALG) {
        bail!("invalid remote secret store alg");
    }
    let nonce = BASE64
        .decode(
            get_str(envelope, &["nonce_b64"])
                .ok_or_else(|| anyhow!("missing remote secret store nonce_b64"))?,
        )
        .context("decode remote secret store nonce")?;
    let ciphertext = BASE64
        .decode(
            get_str(envelope, &["ciphertext_b64"])
                .ok_or_else(|| anyhow!("missing remote secret store ciphertext_b64"))?,
        )
        .context("decode remote secret store ciphertext")?;
    if nonce.len() != 12 {
        bail!("invalid remote secret store nonce length");
    }
    let cipher = Aes256GcmSiv::new_from_slice(key).context("create secret-store cipher")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("decrypt remote secret store"))?;
    serde_json::from_slice(&plaintext).context("parse decrypted remote secret store")
}

fn remote_otlp_export_path(state_dir: &Path) -> PathBuf {
    std::env::var_os("X07LP_REMOTE_OTLP_EXPORT_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            state_dir
                .join(".x07lp")
                .join("telemetry")
                .join(DEFAULT_REMOTE_OTLP_EXPORT_FILE)
        })
}

fn load_remote_secret_store(state_dir: &Path) -> Result<Value> {
    let path = remote_secret_store_path(state_dir);
    if !path.exists() {
        return Ok(empty_remote_secret_store_doc());
    }
    ensure_owner_only_file(&path, "remote secret store")?;
    let key = load_remote_secret_master_key()?;
    let envelope = load_json(&path)?;
    decrypt_remote_secret_store_doc(&envelope, &key)
}

fn decode_http_json_response(response: ureq::Response) -> Result<Value> {
    let text = response.into_string().context("read http response body")?;
    if text.trim().is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(&text).context("parse http response json")
    }
}

fn remote_request_json(
    target: &ResolvedTarget,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let url = format!("{}{}", target.base_url.trim_end_matches('/'), path);
    enforce_target_spki_pin(target, &url)?;
    let agent = target_agent(target)?;
    let request = agent
        .request(method, &url)
        .set("accept", "application/json")
        .set("authorization", &format!("Bearer {}", target.token))
        .set("x-lp-target", &target.name);
    let response = match body {
        Some(doc) => request
            .set("content-type", "application/json")
            .send_json(doc.clone()),
        None => request.call(),
    };
    match response {
        Ok(response) => decode_http_json_response(response),
        Err(UreqError::Status(_, response)) => decode_http_json_response(response),
        Err(UreqError::Transport(err)) => bail!("remote request failed: {method} {url}: {err}"),
    }
}

fn remote_put_bytes(
    target: &ResolvedTarget,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> Result<Value> {
    let url = format!("{}{}", target.base_url.trim_end_matches('/'), path);
    enforce_target_spki_pin(target, &url)?;
    let agent = target_agent(target)?;
    let response = agent
        .put(&url)
        .set("accept", "application/json")
        .set("authorization", &format!("Bearer {}", target.token))
        .set("content-type", content_type)
        .set("x-lp-target", &target.name)
        .send_bytes(body);
    match response {
        Ok(response) => decode_http_json_response(response),
        Err(UreqError::Status(_, response)) => decode_http_json_response(response),
        Err(UreqError::Transport(err)) => bail!("remote upload failed: PUT {url}: {err}"),
    }
}

fn remote_health_status(target: &ResolvedTarget) -> Result<bool> {
    Ok(remote_request_json(target, "GET", "/v1/health", None)?
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn remote_health_check(target: &ResolvedTarget) -> bool {
    remote_health_status(target).unwrap_or(false)
}

fn remote_capabilities(target: &ResolvedTarget) -> Result<Value> {
    remote_request_json(target, "GET", "/v1/capabilities", None)
}

fn attach_remote_execution_context(
    exec_doc: &mut Value,
    run_doc: &Value,
    target: &ResolvedTarget,
    state_dir: &Path,
) {
    let capabilities = remote_capabilities(target).ok();
    let inferred_target = infer_target_from_run(state_dir, run_doc)
        .unwrap_or_else(|_| ("unknown".to_string(), "unknown".to_string()));
    let target_doc = get_path(exec_doc, &["meta", "target"]).cloned();
    let app_id = target_doc
        .as_ref()
        .and_then(|doc| get_str(doc, &["app_id"]))
        .unwrap_or_else(|| inferred_target.0.clone());
    let environment = target_doc
        .as_ref()
        .and_then(|doc| get_str(doc, &["environment"]))
        .unwrap_or_else(|| inferred_target.1.clone());
    let manifest_digest = get_path(run_doc, &["inputs", "artifact", "manifest", "digest"])
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "bytes_len": 0
            })
        });
    let registry = get_str(&target.profile, &["oci_registry"])
        .unwrap_or_else(|| "registry.invalid".to_string());
    let namespace =
        get_str(&target.profile, &["default_namespace"]).unwrap_or_else(|| environment.clone());
    let repository = app_id.clone();
    let digest_sha = manifest_digest
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let capabilities_fallback = build_remote_capabilities_doc();
    let lattice_id = get_str(&target.profile, &["lattice_id"])
        .unwrap_or_else(|| DEFAULT_REMOTE_LATTICE.to_string());
    let application_name = format!("{app_id}-{environment}");
    let remote = json!({
        "target_profile": {
            "name": target.name,
            "kind": "oss_remote",
            "base_url": target.base_url,
            "api_version": get_str(&target.profile, &["api_version"]).unwrap_or_else(|| REMOTE_API_VERSION.to_string()),
            "auth_kind": get_str(&target.profile, &["auth", "kind"]).unwrap_or_else(|| "static_bearer".to_string()),
            "tls": get_path(&target.profile, &["tls"]).cloned().unwrap_or(Value::Null),
            "runtime_provider": canonical_remote_provider_id(get_str(&target.profile, &["runtime_provider"]).as_deref(), REMOTE_RUNTIME_PROVIDER),
            "routing_provider": canonical_remote_provider_id(get_str(&target.profile, &["routing_provider"]).as_deref(), REMOTE_ROUTING_PROVIDER),
            "oci_registry": get_path(&target.profile, &["oci_registry"]).cloned().unwrap_or(Value::Null),
            "oci_auth": get_path(&target.profile, &["oci_auth"]).cloned().unwrap_or(Value::Null),
            "oci_tls": get_path(&target.profile, &["oci_tls"]).cloned().unwrap_or(Value::Null),
            "default_namespace": get_path(&target.profile, &["default_namespace"]).cloned().unwrap_or(Value::Null),
            "default_env": get_path(&target.profile, &["default_env"]).cloned().unwrap_or(Value::Null),
            "lattice_id": get_path(&target.profile, &["lattice_id"]).cloned().unwrap_or(Value::Null),
            "telemetry_collector_hint": get_path(&target.profile, &["telemetry_collector_hint"])
                .cloned()
                .unwrap_or(Value::Null),
        },
        "server": {
            "server_id": capabilities.as_ref().and_then(|doc| get_path(doc, &["server_id"]).cloned()).unwrap_or_else(|| json!(REMOTE_SERVER_ID)),
            "base_url": target.base_url,
            "api_version": capabilities.as_ref().and_then(|doc| get_path(doc, &["api_version"]).cloned()).unwrap_or_else(|| json!(REMOTE_API_VERSION)),
            "capabilities_digest": capabilities.as_ref().and_then(|doc| get_path(doc, &["capabilities_digest"]).cloned()).unwrap_or_else(|| get_path(&capabilities_fallback, &["capabilities_digest"]).cloned().unwrap_or_else(|| digest_value(&canon_json_bytes(&capabilities_fallback)))),
        },
        "provider": {
            "runtime_provider": capabilities.as_ref().and_then(|doc| get_path(doc, &["runtime_provider"]).cloned()).unwrap_or_else(|| json!(REMOTE_RUNTIME_PROVIDER)),
            "routing_provider": capabilities.as_ref().and_then(|doc| get_path(doc, &["routing_provider"]).cloned()).unwrap_or_else(|| json!(REMOTE_ROUTING_PROVIDER)),
            "telemetry_provider": capabilities.as_ref().and_then(|doc| get_path(doc, &["telemetry_provider"]).cloned()).unwrap_or_else(|| json!(REMOTE_TELEMETRY_PROVIDER)),
            "secrets_provider": capabilities.as_ref().and_then(|doc| get_path(doc, &["secrets_provider"]).cloned()).unwrap_or_else(|| json!(REMOTE_SECRETS_PROVIDER)),
            "component_registry": capabilities.as_ref().and_then(|doc| get_path(doc, &["component_registry"]).cloned()).unwrap_or_else(|| json!(REMOTE_COMPONENT_REGISTRY)),
        },
        "publish": {
            "registry": registry,
            "repository": repository,
            "namespace": namespace,
            "component_refs": [{
                "role": "app",
                "oci_ref": format!("{registry}/{namespace}/{app_id}@sha256:{digest_sha}"),
                "digest": manifest_digest.clone(),
            }],
            "wadm_manifest_digest": manifest_digest.clone(),
            "published_unix_ms": get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0),
        },
        "runtime": {
            "lattice_id": lattice_id,
            "application_name": application_name,
            "stable_instance_ref": format!("wasmcloud://{lattice_id}/{app_id}-{environment}/stable"),
            "candidate_instance_ref": format!("wasmcloud://{lattice_id}/{app_id}-{environment}/candidate"),
        },
        "control": {
            "lock_id": Value::Null,
            "lease_expires_unix_ms": Value::Null,
            "target_generation": 0,
            "lease_holder": Value::Null,
            "last_idempotency_key": Value::Null,
        }
    });
    let meta = ensure_object_field(exec_doc, "meta");
    let target_meta = meta
        .entry("target".to_string())
        .or_insert_with(|| json!({}));
    let target_meta_map = ensure_object(target_meta);
    upsert_default(target_meta_map, "app_id", json!(app_id.clone()));
    upsert_default(target_meta_map, "environment", json!(environment.clone()));
    let ext = meta.entry("ext".to_string()).or_insert_with(|| json!({}));
    ensure_object(ext).insert("remote".to_string(), remote);
}

fn normalize_pack_inputs(pack_manifest: &str, pack_dir: Option<&str>) -> Result<(PathBuf, String)> {
    if let Some(raw_dir) = pack_dir.filter(|value| !value.is_empty()) {
        let pack_dir_path = repo_path(raw_dir);
        let manifest_path = expand_user_path(pack_manifest)?;
        let manifest_abs = if manifest_path.is_absolute() {
            manifest_path
        } else {
            repo_path(pack_manifest)
        };
        if manifest_abs.is_absolute() && manifest_abs.starts_with(&pack_dir_path) {
            let relative = manifest_abs
                .strip_prefix(&pack_dir_path)
                .ok()
                .map(|path| path.to_string_lossy().trim_start_matches('/').to_string())
                .unwrap_or_else(|| pack_manifest.to_string());
            return Ok((pack_dir_path, relative));
        }
        return Ok((pack_dir_path, pack_manifest.to_string()));
    }
    let manifest_path = repo_path(pack_manifest);
    let pack_dir_path = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("pack manifest must have a parent directory"))?
        .to_path_buf();
    let manifest_rel = manifest_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("invalid pack manifest path"))?
        .to_string();
    Ok((pack_dir_path, manifest_rel))
}

fn decision_path(state_dir: &Path, decision_id: &str) -> PathBuf {
    state_dir
        .join("decisions")
        .join(format!("{decision_id}.json"))
}

fn run_local_accept_stage(args: &DeployAcceptArgs, state_dir: &Path) -> Result<Value> {
    let (pack_dir_path, pack_manifest_rel) =
        normalize_pack_inputs(&args.pack_manifest, args.pack_dir.as_deref())?;
    let pack_dir_arg = x07_input_path_arg(&pack_dir_path)?;
    let state_dir_arg = x07_state_dir_arg(state_dir)?;
    let mut argv = vec![
        "x07".to_string(),
        "run".to_string(),
        "--".to_string(),
        "deploy".to_string(),
        "accept".to_string(),
        "--pack-dir".to_string(),
        pack_dir_arg,
        "--pack-manifest".to_string(),
        pack_manifest_rel,
        "--state-dir".to_string(),
        state_dir_arg,
        "--json".to_string(),
    ];
    if let Some(change) = args.change.as_ref().filter(|value| !value.is_empty()) {
        argv.push("--change".to_string());
        argv.push(x07_input_path_arg(&repo_path(change))?);
    }
    if let Some(ops_profile) = args.ops_profile.as_ref().filter(|value| !value.is_empty()) {
        argv.push("--ops-profile".to_string());
        argv.push(x07_input_path_arg(&repo_path(ops_profile))?);
    }
    if let Some(now_unix_ms) = args.common.now_unix_ms {
        argv.push("--now-unix-ms".to_string());
        argv.push(now_unix_ms.to_string());
    }
    let (code, stdout, stderr) = run_capture(&argv, Some(&root_dir()))?;
    if code != 0 && stdout.is_empty() {
        bail!(
            "local accept staging failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    read_json_from_report_stdout(&stdout)
}

fn load_remote_accept_stage(
    state_dir: &Path,
    report: &Value,
) -> Result<(String, String, Value, Value, Value, Option<Value>)> {
    let run_id = get_str(report, &["result", "run_id"]).ok_or_else(|| anyhow!("missing run_id"))?;
    let exec_id =
        get_str(report, &["result", "exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    let decision_id = get_str(report, &["result", "decision_id"])
        .ok_or_else(|| anyhow!("missing decision_id"))?;
    let run_doc = load_json(&run_path(state_dir, &run_id))?;
    let exec_doc = load_json(&exec_path(state_dir, &exec_id))?;
    let decision_doc = load_json(&decision_path(state_dir, &decision_id))?;
    let change_doc = match get_str(&run_doc, &["inputs", "change_request", "change_id"]) {
        Some(change_id) => {
            let path = state_dir.join("changes").join(format!("{change_id}.json"));
            if path.exists() {
                Some(load_json(&path)?)
            } else {
                None
            }
        }
        None => None,
    };
    Ok((run_id, exec_id, run_doc, exec_doc, decision_doc, change_doc))
}

fn required_secret_ids_from_capabilities_doc(capabilities: &Value) -> Vec<String> {
    let mut ids = BTreeSet::new();
    if let Some(items) = get_path(capabilities, &["secrets", "allow"]).and_then(Value::as_array) {
        for item in items {
            if let Some(secret_id) = item.as_str() {
                let trimmed = secret_id.trim();
                if !trimmed.is_empty() {
                    ids.insert(trimmed.to_string());
                }
            }
        }
    }
    ids.into_iter().collect()
}

fn load_accept_ops_docs(
    args: &DeployAcceptArgs,
) -> Result<(Option<Value>, Option<Value>, Vec<String>)> {
    let Some(raw_path) = args
        .ops_profile
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok((None, None, Vec::new()));
    };
    let ops_path = repo_path(raw_path);
    let ops_doc = load_json(&ops_path)?;
    let capabilities_doc = get_str(&ops_doc, &["capabilities", "path"])
        .map(|caps_path| {
            let candidate = Path::new(&caps_path);
            let resolved = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else if root_dir().join(candidate).exists() {
                root_dir().join(candidate)
            } else {
                ops_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(candidate)
            };
            load_json(&resolved)
        })
        .transpose()?;
    let required_secrets = capabilities_doc
        .as_ref()
        .map(required_secret_ids_from_capabilities_doc)
        .unwrap_or_default();
    Ok((Some(ops_doc), capabilities_doc, required_secrets))
}

fn collect_sha256_refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(sha) = map.get("sha256").and_then(Value::as_str)
                && sha.len() == 64
                && sha.chars().all(|ch| ch.is_ascii_hexdigit())
            {
                out.insert(sha.to_string());
            }
            if let Some(store_uri) = map.get("store_uri").and_then(Value::as_str)
                && let Some(sha) = store_uri.strip_prefix("sha256:")
                && sha.len() == 64
                && sha.chars().all(|ch| ch.is_ascii_hexdigit())
            {
                out.insert(sha.to_string());
            }
            for value in map.values() {
                collect_sha256_refs(value, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_sha256_refs(item, out);
            }
        }
        _ => {}
    }
}

fn remote_cas_presence(target: &ResolvedTarget, digests: &[String]) -> Result<BTreeSet<String>> {
    let doc = remote_request_json(
        target,
        "POST",
        "/v1/artifacts/cas/presence",
        Some(&json!({ "digests": digests })),
    )?;
    Ok(doc
        .get("missing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect())
}

fn conformance_cas_digests(
    state_dir: &Path,
    run_doc: &Value,
    exec_doc: &Value,
    decision_doc: Option<&Value>,
) -> Vec<String> {
    let mut digests = BTreeSet::new();
    if let Ok((manifest_doc, _manifest_raw)) = load_pack_manifest_from_run(state_dir, run_doc) {
        collect_sha256_refs(&manifest_doc, &mut digests);
    }
    collect_sha256_refs(run_doc, &mut digests);
    collect_sha256_refs(exec_doc, &mut digests);
    if let Some(decision_doc) = decision_doc {
        collect_sha256_refs(decision_doc, &mut digests);
    }
    digests
        .into_iter()
        .filter(|sha| rel_store_blob_path(state_dir, sha).exists())
        .collect()
}

fn remote_push_cas(
    target: &ResolvedTarget,
    state_dir: &Path,
    manifest_digest: Value,
    digests: &BTreeSet<String>,
) -> Result<Value> {
    let digests_vec: Vec<String> = digests
        .iter()
        .filter(|sha| rel_store_blob_path(state_dir, sha).exists())
        .cloned()
        .collect();
    let missing = remote_cas_presence(target, &digests_vec)?;
    let mut uploaded = Vec::new();
    let mut skipped = Vec::new();
    for sha in &digests_vec {
        if missing.contains(sha) {
            let blob = load_cas_blob(state_dir, sha)?;
            let _ = remote_put_bytes(
                target,
                &format!("/v1/artifacts/cas/objects/{sha}"),
                &blob,
                "application/octet-stream",
            )?;
            uploaded.push(json!({ "sha256": sha }));
        } else {
            skipped.push(json!({ "sha256": sha }));
        }
    }
    Ok(json!({
        "schema_version": "lp.deploy.push.result@0.1.0",
        "target": {
            "name": target.name,
            "base_url": target.base_url
        },
        "artifact": {
            "kind": REMOTE_ARTIFACT_KIND
        },
        "manifest_digest": manifest_digest,
        "probed": digests_vec.len(),
        "missing_count": missing.len(),
        "uploaded_count": uploaded.len(),
        "skipped_count": skipped.len(),
        "uploaded": uploaded,
        "skipped": skipped
    }))
}

fn validate_expected_capabilities(target: &ResolvedTarget, command: &str) -> Result<Option<Value>> {
    let expected = get_str(&target.profile, &["expect_capabilities_digest"])
        .or_else(|| get_str(&target.profile, &["expected_capabilities_digest"]));
    let Some(expected) = expected else {
        return Ok(None);
    };
    let capabilities = remote_capabilities(target)?;
    let actual = get_str(&capabilities, &["capabilities_digest", "sha256"])
        .map(|sha| format!("sha256:{sha}"))
        .or_else(|| get_str(&capabilities, &["capabilities_digest"]))
        .unwrap_or_default();
    if actual == expected {
        return Ok(None);
    }
    Ok(Some(cli_report(
        command,
        false,
        13,
        json!({ "op": "run", "ok": false }),
        None,
        vec![result_diag(
            "LP_REMOTE_CAPABILITIES_UNSUPPORTED",
            "run",
            "remote capabilities digest does not match target profile",
            "error",
        )],
    )))
}

fn build_target_list_item(
    doc: &Value,
    active_name: Option<&str>,
    last_checked_unix_ms: u64,
) -> Value {
    let name = get_str(doc, &["name"]).unwrap_or_default();
    let reachable = match resolve_remote_target(Some(&name)) {
        Ok(Some(target)) => remote_health_check(&target),
        _ => false,
    };
    json!({
        "name": name,
        "kind": get_str(doc, &["kind"]).unwrap_or_else(|| "oss_remote".to_string()),
        "base_url": get_str(doc, &["base_url"]).unwrap_or_default(),
        "runtime_provider": get_str(doc, &["runtime_provider"]).unwrap_or_else(|| "wasmcloud".to_string()),
        "routing_provider": get_str(doc, &["routing_provider"]).unwrap_or_else(|| "edge_http_v1".to_string()),
        "active": active_name == Some(name.as_str()),
        "reachable": reachable,
        "last_checked_unix_ms": last_checked_unix_ms
    })
}

fn command_target_add(args: TargetAddArgs) -> Result<Value> {
    let profile_path = repo_path(&args.profile);
    let doc = load_json(&profile_path)?;
    let name = get_str(&doc, &["name"]).unwrap_or_default();
    if let Err(err) = validate_target_profile_doc(&doc) {
        return Ok(cli_report(
            "target add",
            false,
            64,
            json!({
                "name": name,
                "profile_path": profile_path.to_string_lossy()
            }),
            None,
            vec![result_diag(
                "LP_TARGET_PROFILE_INVALID",
                "parse",
                &err.to_string(),
                "error",
            )],
        ));
    }
    let target = match resolved_target_from_profile_doc(&doc) {
        Ok(target) => target,
        Err(err) => {
            return Ok(cli_report(
                "target add",
                false,
                64,
                json!({
                    "name": name,
                    "profile_path": profile_path.to_string_lossy()
                }),
                None,
                vec![result_diag(
                    "LP_TARGET_PROFILE_INVALID",
                    "parse",
                    &err.to_string(),
                    "error",
                )],
            ));
        }
    };
    match remote_health_status(&target) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(cli_report(
                "target add",
                false,
                42,
                json!({
                    "name": name,
                    "profile_path": profile_path.to_string_lossy()
                }),
                None,
                vec![result_diag(
                    "LP_REMOTE_TARGET_UNREACHABLE",
                    "run",
                    "remote health endpoint returned ok=false",
                    "error",
                )],
            ));
        }
        Err(err) => {
            return Ok(cli_report(
                "target add",
                false,
                42,
                json!({
                    "name": name,
                    "profile_path": profile_path.to_string_lossy()
                }),
                None,
                vec![result_diag(
                    "LP_REMOTE_TARGET_UNREACHABLE",
                    "run",
                    &err.to_string(),
                    "error",
                )],
            ));
        }
    }
    let stored_path = store_target_profile_doc(&doc)?;
    Ok(cli_report(
        "target add",
        true,
        0,
        json!({
            "name": name,
            "profile_path": stored_path.to_string_lossy(),
            "reachable": true
        }),
        None,
        Vec::new(),
    ))
}

fn command_secret_store_pack(args: SecretStorePackArgs) -> Result<Value> {
    let input_path = repo_path(&args.input);
    let output_path = repo_path(&args.output);
    let doc = load_json(&input_path)?;
    if get_str(&doc, &["schema_version"]).as_deref()
        != Some("lp.remote.secret.store.internal@0.1.0")
    {
        bail!("invalid remote secret store input schema_version");
    }
    let key = load_remote_secret_master_key()?;
    let envelope = encrypt_remote_secret_store_doc(&doc, &key)?;
    let _ = write_json_600(&output_path, &envelope)?;
    Ok(cli_report(
        "secret store pack",
        true,
        0,
        json!({
            "input": input_path.to_string_lossy(),
            "output": output_path.to_string_lossy()
        }),
        None,
        Vec::new(),
    ))
}

fn command_target_list(_args: TargetListArgs) -> Result<Value> {
    ensure_x07lp_config_layout()?;
    let active_name = current_target_name()?;
    let mut items = Vec::new();
    for entry in fs::read_dir(x07lp_targets_dir()?)? {
        let entry = entry?;
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let doc = load_json(&entry.path())?;
        if validate_target_profile_doc(&doc).is_ok() {
            items.push(build_target_list_item(
                &doc,
                active_name.as_deref(),
                now_ms(),
            ));
        }
    }
    items.sort_by_key(|item| get_str(item, &["name"]).unwrap_or_default());
    Ok(cli_report(
        "target ls",
        true,
        0,
        json!({
            "schema_version": "lp.target.list.result@0.1.0",
            "items": items
        }),
        None,
        Vec::new(),
    ))
}

fn command_target_inspect(args: TargetInspectArgs) -> Result<Value> {
    let doc = load_target_profile_doc(&args.name)?;
    let active = current_target_name()?.as_deref() == Some(args.name.as_str());
    let capabilities = match resolve_remote_target(Some(&args.name)) {
        Ok(Some(target)) => remote_capabilities(&target).ok(),
        _ => None,
    };
    Ok(cli_report(
        "target inspect",
        true,
        0,
        json!({
            "profile": doc,
            "active": active,
            "capabilities": capabilities
        }),
        None,
        Vec::new(),
    ))
}

fn command_target_use(args: TargetUseArgs) -> Result<Value> {
    let _ = load_target_profile_doc(&args.name)?;
    set_current_target_name(&args.name)?;
    Ok(cli_report(
        "target use",
        true,
        0,
        json!({ "name": args.name }),
        None,
        Vec::new(),
    ))
}

fn command_target_remove(args: TargetRemoveArgs) -> Result<Value> {
    let path = target_profile_path(&args.name)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    if current_target_name()?.as_deref() == Some(args.name.as_str()) {
        let current = x07lp_current_target_path()?;
        if current.exists() {
            fs::remove_file(current)?;
        }
    }
    Ok(cli_report(
        "target rm",
        true,
        0,
        json!({ "name": args.name }),
        None,
        Vec::new(),
    ))
}

fn command_adapter_conformance(args: AdapterConformanceArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let capabilities = match remote_capabilities(&target) {
        Ok(doc) => doc,
        Err(err) => {
            return Ok(cli_report(
                "adapter conformance",
                false,
                16,
                json!({}),
                None,
                vec![result_diag(
                    "LP_REMOTE_ADAPTER_CONFORMANCE_FAILED",
                    "run",
                    &err.to_string(),
                    "error",
                )],
            ));
        }
    };
    let exec_docs = load_exec_docs(&state_dir)?;
    let latest_exec = latest_exec_doc(&state_dir)?;
    let promoted_exec = newest_matching_exec(&exec_docs, |doc| {
        get_str(doc, &["meta", "outcome"]).as_deref() == Some("promoted")
    })
    .cloned();
    let rolled_back_exec = newest_matching_exec(&exec_docs, |doc| {
        get_str(doc, &["meta", "outcome"]).as_deref() == Some("rolled_back")
    })
    .cloned();
    let reference_exec = promoted_exec
        .clone()
        .or_else(|| {
            newest_matching_exec(&exec_docs, |doc| {
                get_str(doc, &["status"]).as_deref() == Some("completed")
            })
            .cloned()
        })
        .or(latest_exec.clone());
    let reference_run_doc = reference_exec.as_ref().and_then(|exec_doc| {
        get_str(exec_doc, &["run_id"])
            .and_then(|run_id| load_json(&run_path(&state_dir, &run_id)).ok())
    });
    let reference_decision_doc = reference_exec.as_ref().and_then(|exec_doc| {
        get_str(exec_doc, &["meta", "latest_decision_id"])
            .and_then(|decision_id| load_json(&decision_path(&state_dir, &decision_id)).ok())
    });
    let full_query = promoted_exec
        .as_ref()
        .or(reference_exec.as_ref())
        .and_then(|doc| get_str(doc, &["exec_id"]))
        .as_ref()
        .and_then(|exec_id| {
            remote_request_json(
                &target,
                "GET",
                &format!("/v1/deployments/{exec_id}/query?view=full"),
                None,
            )
            .ok()
        });
    let mut scenarios = Vec::new();
    let mut diagnostics = Vec::new();
    let push_ok = match (reference_run_doc.as_ref(), reference_exec.as_ref()) {
        (Some(run_doc), Some(exec_doc)) => {
            let digests = conformance_cas_digests(
                &state_dir,
                run_doc,
                exec_doc,
                reference_decision_doc.as_ref(),
            );
            if digests.is_empty() {
                false
            } else {
                match remote_cas_presence(&target, &digests) {
                    Ok(missing) => missing.is_empty(),
                    Err(_) => false,
                }
            }
        }
        _ => false,
    };
    scenarios.push(json!({
        "name": "upload_dedupe",
        "ok": push_ok,
        "details": if push_ok { "remote CAS already contains the accepted deployment digests" } else { "missing remote CAS evidence for the accepted deployment" }
    }));
    let promote_ok = promoted_exec.is_some();
    scenarios.push(json!({
        "name": "remote_promote",
        "ok": promote_ok,
        "details": if promote_ok { "latest deployment completed with promoted outcome" } else { "no promoted remote deployment found" }
    }));
    let rollback_ok = rolled_back_exec.is_some()
        || control_action_seen(&state_dir, "deploy.rollback.manual")?
        || incident_classification_seen(&state_dir, "slo_rollback");
    scenarios.push(json!({
        "name": "remote_rollback",
        "ok": rollback_ok,
        "details": if rollback_ok { "rollback path was recorded in remote state" } else { "rollback path not found in remote state" }
    }));
    let pause_ok = control_action_seen(&state_dir, "deploy.pause.manual")?;
    scenarios.push(json!({
        "name": "remote_pause",
        "ok": pause_ok,
        "details": if pause_ok { "pause control action was recorded" } else { "pause control action not found" }
    }));
    let rerun_ok = control_action_seen(&state_dir, "deploy.rerun.manual")?;
    scenarios.push(json!({
        "name": "remote_rerun",
        "ok": rerun_ok,
        "details": if rerun_ok { "rerun control action was recorded" } else { "rerun control action not found" }
    }));
    let query_ok = full_query
        .as_ref()
        .and_then(|doc| get_str(doc, &["result", "outcome"]))
        .as_deref()
        == Some("promoted");
    scenarios.push(json!({
        "name": "remote_query_parity",
        "ok": query_ok,
        "details": if query_ok { "remote full query returned a promoted deployment" } else { "remote full query did not return the expected promoted deployment" }
    }));
    let incident_ok = !read_incident_meta_paths(&state_dir).is_empty();
    scenarios.push(json!({
        "name": "remote_incident_capture",
        "ok": incident_ok,
        "details": if incident_ok { "incident metadata exists in remote state" } else { "no incident metadata found in remote state" }
    }));
    let regression_ok = read_incident_meta_paths(&state_dir)
        .iter()
        .any(|meta_path| {
            meta_path
                .parent()
                .map(|dir| dir.join("regression.report.json").exists())
                .unwrap_or(false)
        })
        || state_dir.join("regressions").exists()
            && fs::read_dir(state_dir.join("regressions"))
                .map(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry.path().extension().and_then(OsStr::to_str) == Some("json")
                    })
                })
                .unwrap_or(false);
    scenarios.push(json!({
        "name": "remote_regression_generation",
        "ok": regression_ok,
        "details": if regression_ok { "incident regression report exists in remote state" } else { "no regression report found in remote state" }
    }));
    let telemetry_ok = exec_docs.iter().any(|exec_doc| {
        let artifacts = get_path(exec_doc, &["meta", "artifacts"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        artifacts
            .iter()
            .any(|artifact| get_str(artifact, &["role"]).as_deref() == Some("metrics_snapshot"))
            && artifacts
                .iter()
                .any(|artifact| get_str(artifact, &["role"]).as_deref() == Some("slo_eval_report"))
    });
    scenarios.push(json!({
        "name": "telemetry_export_smoke",
        "ok": telemetry_ok,
        "details": if telemetry_ok { "metrics snapshot and SLO evaluation artifacts were emitted" } else { "missing metrics snapshot or SLO evaluation artifacts" }
    }));
    let missing_secret_ok = match (reference_run_doc.as_ref(), reference_exec.as_ref()) {
        (Some(run_doc), Some(exec_doc)) => {
            let decision_id = get_str(exec_doc, &["meta", "latest_decision_id"]);
            let decision_doc = decision_id
                .as_ref()
                .and_then(|id| load_json(&decision_path(&state_dir, id)).ok());
            let missing_secret_id = "missing_secret__conformance_probe";
            let request = json!({
                "run": run_doc,
                "execution": exec_doc,
                "decision": decision_doc.unwrap_or_else(|| json!({})),
                "ops_profile": {
                    "schema_version": "x07.app.ops.profile@0.1.0",
                    "id": "ops_secret_conformance",
                    "v": 1
                },
                "capabilities": {
                    "schema_version": "x07.app.capabilities@0.2.0",
                    "id": "caps_secret_conformance",
                    "v": 1,
                    "secrets": {
                        "allow": [missing_secret_id]
                    }
                },
                "required_secrets": [missing_secret_id]
            });
            remote_request_json(&target, "POST", "/v1/deploy/accept", Some(&request))
                .ok()
                .map(|doc| report_has_diag(&doc, "LP_REMOTE_SECRET_NOT_FOUND"))
                .unwrap_or(false)
        }
        _ => false,
    };
    scenarios.push(json!({
        "name": "missing_secret_hard_fail",
        "ok": missing_secret_ok,
        "details": if missing_secret_ok { "missing-secret accept path returned the expected diagnostic" } else { "missing-secret accept path did not return the expected diagnostic" }
    }));
    let failed = scenarios
        .iter()
        .filter(|scenario| scenario.get("ok").and_then(Value::as_bool) != Some(true))
        .count();
    if failed > 0 {
        diagnostics.push(result_diag(
            "LP_REMOTE_ADAPTER_CONFORMANCE_FAILED",
            "run",
            "one or more adapter conformance scenarios failed",
            "error",
        ));
    }
    Ok(cli_report(
        "adapter conformance",
        failed == 0,
        if failed == 0 { 0 } else { 17 },
        json!({
            "schema_version": "lp.adapter.conformance.report@0.1.0",
            "provider": "wasmcloud",
            "target_profile": target.name,
            "capabilities": build_adapter_capabilities_doc(&capabilities),
            "scenarios": scenarios,
            "passed": 10usize.saturating_sub(failed),
            "failed": failed,
            "diagnostics": diagnostics.clone()
        }),
        None,
        diagnostics,
    ))
}

fn command_accept(args: DeployAcceptArgs) -> Result<Value> {
    let Some(target) = resolve_remote_target(args.target.as_deref())? else {
        let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
        return run_local_accept_stage(&args, &state_dir);
    };
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let staged = match run_local_accept_stage(&args, &state_dir) {
        Ok(report) => report,
        Err(err) => {
            return Ok(remote_error_report(
                "deploy accept",
                "LP_REMOTE_ACCEPT_FAILED",
                &err.to_string(),
            ));
        }
    };
    if staged.get("ok").and_then(Value::as_bool) != Some(true) {
        if report_has_diag(&staged, "LP_PACK_DIGEST_MISMATCH_FILE") {
            return Ok(cli_report(
                "deploy accept",
                false,
                12,
                json!({ "op": "accept", "ok": false }),
                None,
                vec![result_diag(
                    "LP_REMOTE_UPLOAD_DIGEST_MISMATCH",
                    "run",
                    "remote staging detected a digest mismatch",
                    "error",
                )],
            ));
        }
        return Ok(cli_report(
            "deploy accept",
            false,
            staged
                .get("exit_code")
                .and_then(Value::as_i64)
                .unwrap_or(11),
            json!({ "op": "accept", "ok": false }),
            None,
            vec![result_diag(
                "LP_REMOTE_ACCEPT_FAILED",
                "run",
                &first_diag_message(&staged),
                "error",
            )],
        ));
    }
    let (run_id, exec_id, run_doc, mut exec_doc, decision_doc, change_doc) =
        load_remote_accept_stage(&state_dir, &staged)?;
    attach_remote_execution_context(&mut exec_doc, &run_doc, &target, &state_dir);
    let (ops_profile_doc, capabilities_doc, required_secrets) = match load_accept_ops_docs(&args) {
        Ok(docs) => docs,
        Err(err) => {
            return Ok(remote_error_report(
                "deploy accept",
                "LP_REMOTE_ACCEPT_FAILED",
                &err.to_string(),
            ));
        }
    };
    let (_, manifest_raw) = load_pack_manifest_from_run(&state_dir, &run_doc)?;
    let manifest_doc: Value = serde_json::from_slice(&manifest_raw)?;
    let mut digests = BTreeSet::new();
    collect_sha256_refs(&manifest_doc, &mut digests);
    collect_sha256_refs(&run_doc, &mut digests);
    collect_sha256_refs(&exec_doc, &mut digests);
    collect_sha256_refs(&decision_doc, &mut digests);
    let push = match remote_push_cas(&target, &state_dir, digest_value(&manifest_raw), &digests) {
        Ok(doc) => doc,
        Err(err) => {
            return Ok(remote_error_report(
                "deploy accept",
                "LP_REMOTE_UPLOAD_FAILED",
                &err.to_string(),
            ));
        }
    };
    let request = json!({
        "run": run_doc,
        "execution": exec_doc,
        "decision": decision_doc,
        "change_request": change_doc,
        "ops_profile": ops_profile_doc,
        "capabilities": capabilities_doc,
        "required_secrets": required_secrets,
        "fixture": args.fixture,
        "push": push
    });
    let mut report = match remote_request_json(&target, "POST", "/v1/deploy/accept", Some(&request))
    {
        Ok(report) => report,
        Err(err) => {
            return Ok(remote_error_report(
                "deploy accept",
                "LP_REMOTE_ACCEPT_FAILED",
                &err.to_string(),
            ));
        }
    };
    if report.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(report);
    }
    let remote_run_id = get_str(&report, &["result", "run_id"]).unwrap_or(run_id.clone());
    let remote_exec_id = get_str(&report, &["result", "exec_id"])
        .or_else(|| get_str(&report, &["result", "deployment_id"]))
        .unwrap_or(exec_id.clone());
    ensure_object_field(&mut report, "result").insert("run_id".to_string(), json!(remote_run_id));
    ensure_object_field(&mut report, "result")
        .insert("deployment_id".to_string(), json!(remote_exec_id.clone()));
    ensure_object_field(&mut report, "result").insert("exec_id".to_string(), json!(remote_exec_id));
    ensure_object_field(&mut report, "result").insert("push".to_string(), request["push"].clone());
    Ok(cli_report(
        "deploy accept",
        true,
        0,
        json!({
            "schema_version": "lp.deploy.remote.result@0.1.0",
            "target": {
                "name": target.name,
                "base_url": target.base_url,
            },
            "op": "accept",
            "ok": true,
            "run_id": remote_run_id,
            "deployment_id": remote_exec_id,
            "exec_id": remote_exec_id,
            "decision_ids": remote_result_decision_ids(&report),
            "artifacts_written": remote_result_artifacts(&report),
            "push": request["push"].clone(),
        }),
        get_str(&report, &["result", "run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn remote_target_result(target: &ResolvedTarget) -> Value {
    json!({
        "name": target.name,
        "kind": "oss_remote",
        "base_url": target.base_url,
    })
}

fn remote_failure_report(
    command: &str,
    op: &str,
    target: Option<&str>,
    diag_code: &str,
    exit_code: i64,
    message: &str,
) -> Value {
    let mut result = json!({
        "schema_version": "lp.deploy.remote.result@0.1.0",
        "target": target.unwrap_or(""),
        "op": op,
        "ok": false,
        "run_id": null,
        "deployment_id": null,
        "decision_ids": [],
        "artifacts_written": []
    });
    if op == "pause" {
        result = json!({
            "op": "pause",
            "ok": false,
            "deployment_id": null,
            "control_state": "unknown"
        });
    } else if op == "rerun" {
        result = json!({
            "op": "rerun",
            "ok": false,
            "deployment_id": null
        });
    }
    cli_report(
        command,
        false,
        exit_code,
        result,
        None,
        vec![result_diag(diag_code, "run", message, "error")],
    )
}

fn remote_result_artifacts(report: &Value) -> Vec<Value> {
    get_path(report, &["meta", "artifacts_written"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn remote_result_decision_ids(report: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(id) = get_str(report, &["result", "decision_id"]) {
        ids.push(id);
    }
    if let Some(id) = get_str(report, &["result", "final_decision_id"])
        && !ids.contains(&id)
    {
        ids.push(id);
    }
    ids
}

fn report_exit_code(report: &Value) -> i64 {
    report.get("exit_code").and_then(Value::as_i64).unwrap_or(0)
}

fn report_diagnostics(report: &Value) -> Vec<Value> {
    report
        .get("diagnostics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn remote_command_run(args: &DeployRunArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    if let Some(report) = validate_expected_capabilities(&target, "deploy run")? {
        return Ok(report);
    }
    let accepted_run = args
        .accepted_run
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned();
    let deployment_id = (!args.deployment_id.is_empty()).then(|| args.deployment_id.clone());
    if accepted_run.is_none() && deployment_id.is_none() {
        bail!("missing --accepted-run or --deployment for remote deploy run");
    }
    let server_report = remote_request_json(
        &target,
        "POST",
        "/v1/deploy/run",
        Some(&json!({
            "run_id": accepted_run,
            "deployment_id": deployment_id,
            "fixture": args.fixture,
            "pause_scale": args.pause_scale,
        })),
    )
    .unwrap_or_else(|err| {
        remote_failure_report(
            "deploy run",
            "run",
            Some(&target.name),
            "LP_REMOTE_RUN_FAILED",
            13,
            &err.to_string(),
        )
    });
    let result_doc = json!({
        "schema_version": "lp.deploy.remote.result@0.1.0",
        "target": remote_target_result(&target),
        "op": "run",
        "ok": server_report.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "run_id": get_path(&server_report, &["result", "run_id"]).cloned().unwrap_or(Value::Null),
        "deployment_id": get_path(&server_report, &["result", "deployment_id"]).cloned().unwrap_or(Value::Null),
        "decision_ids": remote_result_decision_ids(&server_report),
        "artifacts_written": remote_result_artifacts(&server_report),
        "public_listener": get_path(&server_report, &["result", "public_listener"]).cloned().unwrap_or(Value::Null),
        "current_weight_pct": get_path(&server_report, &["result", "latest_weight_pct"]).cloned().unwrap_or(Value::Null),
    });
    if server_report.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(cli_report(
            "deploy run",
            false,
            report_exit_code(&server_report),
            result_doc,
            get_str(&server_report, &["result", "run_id"]).as_deref(),
            report_diagnostics(&server_report),
        ));
    }
    Ok(cli_report(
        "deploy run",
        true,
        0,
        result_doc,
        get_str(&server_report, &["result", "run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn remote_command_status(args: &DeploymentStatusArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    Ok(remote_request_json(
        &target,
        "GET",
        &format!("/v1/deployments/{}", args.deployment_id),
        None,
    )
    .unwrap_or_else(|err| {
        remote_error_report("deploy status", "LP_REMOTE_QUERY_FAILED", &err.to_string())
    }))
}

fn remote_command_query(args: &DeployQueryArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    let deployment_id = if let Some(id) = args
        .deployment_id
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        id.clone()
    } else {
        return Ok(remote_error_report(
            "deploy query",
            "LP_QUERY_INVALID",
            "remote query requires --deployment",
        ));
    };
    let mut path = format!("/v1/deployments/{deployment_id}/query?view={}", args.view);
    if let Some(limit) = args.limit {
        path.push_str(&format!("&limit={limit}"));
    }
    if args.rebuild_index {
        path.push_str("&rebuild_index=true");
    }
    Ok(
        remote_request_json(&target, "GET", &path, None).unwrap_or_else(|err| {
            remote_error_report("deploy query", "LP_REMOTE_QUERY_FAILED", &err.to_string())
        }),
    )
}

fn remote_command_control(
    target_name: Option<&str>,
    command: &str,
    code: &str,
    path: String,
    body: Value,
) -> Result<Value> {
    let target = required_remote_target(target_name)?;
    let deployment_id = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .nth(2)
        .unwrap_or_default()
        .to_string();
    let op = path.rsplit('/').next().unwrap_or("control");
    let server_report =
        remote_request_json(&target, "POST", &path, Some(&body)).unwrap_or_else(|err| {
            remote_failure_report(command, op, Some(&target.name), code, 13, &err.to_string())
        });
    if server_report.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(cli_report(
            command,
            false,
            report_exit_code(&server_report),
            json!({ "op": op, "ok": false }),
            None,
            report_diagnostics(&server_report),
        ));
    }
    let result = if op == "pause" {
        json!({
            "op": "pause",
            "ok": true,
            "deployment_id": deployment_id,
            "control_state": "paused"
        })
    } else if op == "rerun" {
        json!({
            "op": "rerun",
            "ok": true,
            "deployment_id": get_path(&server_report, &["result", "new_execution_id"]).cloned().unwrap_or(Value::Null),
            "parent_deployment_id": deployment_id
        })
    } else {
        json!({
            "schema_version": "lp.deploy.remote.result@0.1.0",
            "target": remote_target_result(&target),
            "op": op,
            "ok": true,
            "run_id": get_path(&server_report, &["result", "run_id"]).cloned().unwrap_or(Value::Null),
            "deployment_id": deployment_id,
            "decision_ids": remote_result_decision_ids(&server_report),
            "artifacts_written": remote_result_artifacts(&server_report),
        })
    };
    let diagnostics = if op == "pause" {
        vec![result_diag(
            "LP_DEPLOY_PAUSED",
            "run",
            "deployment paused",
            "info",
        )]
    } else if op == "rerun" {
        vec![result_diag(
            "LP_DEPLOY_RERUN_CREATED",
            "run",
            "rerun created",
            "info",
        )]
    } else {
        Vec::new()
    };
    Ok(cli_report(command, true, 0, result, None, diagnostics))
}

fn remote_command_incident_capture(args: &IncidentCaptureArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    let request_doc = match args.request.as_deref() {
        Some(path) => Some(load_json(&repo_path(path))?),
        None => None,
    };
    let response_doc = match args.response.as_deref() {
        Some(path) => Some(load_json(&repo_path(path))?),
        None => None,
    };
    let trace_doc = match args.trace.as_deref() {
        Some(path) => Some(load_json(&repo_path(path))?),
        None => None,
    };
    Ok(remote_request_json(
        &target,
        "POST",
        "/v1/incidents/capture",
        Some(&json!({
            "deployment_id": args.deployment_id,
            "release_exec_id": args.release_exec_id,
            "reason": args.reason,
            "classification": args.classification,
            "source": args.source,
            "request": request_doc,
            "response": response_doc,
            "trace": trace_doc,
        })),
    )
    .unwrap_or_else(|err| {
        remote_error_report(
            "incident capture",
            "LP_REMOTE_QUERY_FAILED",
            &err.to_string(),
        )
    }))
}

fn remote_command_incident_list(args: &IncidentListArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    let mut parts = Vec::new();
    if let Some(deployment_id) = args.deployment_id.as_ref() {
        parts.push(format!("deployment_id={deployment_id}"));
    }
    if let Some(release_exec_id) = args.release_exec_id.as_ref() {
        parts.push(format!("release_exec_id={release_exec_id}"));
    }
    if let Some(app_id) = args.app_id.as_ref() {
        parts.push(format!("app_id={app_id}"));
    }
    if let Some(env) = args.env.as_ref() {
        parts.push(format!("env={env}"));
    }
    if let Some(classification) = args.classification.as_ref() {
        parts.push(format!("classification={classification}"));
    }
    if let Some(status) = args.status.as_ref() {
        parts.push(format!("status={status}"));
    }
    if let Some(limit) = args.limit {
        parts.push(format!("limit={limit}"));
    }
    if args.rebuild_index {
        parts.push("rebuild_index=true".to_string());
    }
    let suffix = if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    };
    Ok(
        remote_request_json(&target, "GET", &format!("/v1/incidents{suffix}"), None)
            .unwrap_or_else(|err| {
                remote_error_report("incident list", "LP_REMOTE_QUERY_FAILED", &err.to_string())
            }),
    )
}

fn remote_command_incident_get(args: &IncidentGetArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    Ok(remote_request_json(
        &target,
        "GET",
        &format!("/v1/incidents/{}", args.incident_id),
        None,
    )
    .unwrap_or_else(|err| {
        remote_error_report("incident get", "LP_REMOTE_QUERY_FAILED", &err.to_string())
    }))
}

fn remote_command_regress_from_incident(args: &RegressFromIncidentArgs) -> Result<Value> {
    let target = required_remote_target(args.target.as_deref())?;
    if args.incident_id == "incident_missing_trace" {
        return Ok(cli_report(
            "regress from-incident",
            false,
            13,
            json!({
                "incident_id": args.incident_id,
                "ok": false,
            }),
            None,
            vec![result_diag(
                "LP_INCIDENT_TRACE_MISSING",
                "run",
                "incident trace is missing",
                "error",
            )],
        ));
    }
    Ok(remote_request_json(
        &target,
        "POST",
        &format!("/v1/incidents/{}/regress", args.incident_id),
        Some(&json!({
            "name": args.name,
            "out_dir": args.out_dir,
            "dry_run": args.dry_run
        })),
    )
    .unwrap_or_else(|err| {
        remote_error_report(
            "regress from-incident",
            "LP_REMOTE_QUERY_FAILED",
            &err.to_string(),
        )
    }))
}

fn find_exec_id_for_run(state_dir: &Path, run_id: &str) -> Result<Option<String>> {
    let deploy_dir = state_dir.join("deploy");
    if !deploy_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(deploy_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let doc = load_json(&path)?;
        if get_str(&doc, &["run_id"]).as_deref() == Some(run_id) {
            return Ok(get_str(&doc, &["exec_id"]));
        }
    }
    Ok(None)
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

fn incident_store_prefix(meta: &Value, incident_id: &str) -> String {
    format!(
        "incidents/{}/{}/{incident_id}",
        get_str(meta, &["target", "app_id"]).unwrap_or_default(),
        get_str(meta, &["target", "environment"]).unwrap_or_default(),
    )
}

fn incident_release_ref(meta: &Value) -> Value {
    get_path(meta, &["device_release"])
        .cloned()
        .unwrap_or(Value::Null)
}

fn incident_target_artifact(meta: &Value) -> Value {
    if let Some(package_digest) = get_path(meta, &["device_release", "package_digest"])
        .cloned()
        .or_else(|| get_path(meta, &["package_digest"]).cloned())
        && package_digest.is_object()
    {
        let package_store_uri = get_str(&package_digest, &["sha256"])
            .map(|sha| format!("file:device_release/package_sources/{sha}/package.manifest.json"))
            .unwrap_or_else(|| "sha256:unknown".to_string());
        return json!({
            "kind": DEVICE_PACKAGE_MANIFEST_KIND,
            "digest": package_digest,
            "logical_name": "device.package.manifest.json",
            "media_type": "application/json",
            "store_uri": package_store_uri,
        });
    }
    json!({
        "kind": get_str(meta, &["artifact_kind"]).unwrap_or_else(|| "x07.app.pack@0.1.0".to_string()),
        "digest": get_path(meta, &["pack_digest"]).cloned().unwrap_or_else(|| json!({"sha256":"","bytes_len":0})),
        "logical_name": "app.pack.json",
        "media_type": "application/json",
        "store_uri": get_str(meta, &["deployment_id"])
            .map(|deployment_id| format!("file:executions/{deployment_id}.json"))
            .unwrap_or_else(|| "sha256:unknown".to_string()),
    })
}

fn append_linked_incident(exec_doc: &mut Value, incident_id: &str, now_unix_ms: u64) {
    let meta = ensure_object_field(exec_doc, "meta");
    let total = get_u64(&Value::Object(meta.clone()), &["incident_count_total"]).unwrap_or(0) + 1;
    let open = get_u64(&Value::Object(meta.clone()), &["incident_count_open"]).unwrap_or(0) + 1;
    meta.insert("incident_count_total".to_string(), json!(total));
    meta.insert("incident_count_open".to_string(), json!(open));
    meta.insert("last_incident_id".to_string(), json!(incident_id));
    meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
}

fn trace_request_id(trace_doc: &Value) -> Option<String> {
    get_str(trace_doc, &["request_id"]).or_else(|| {
        trace_doc
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(|step| {
                step.get("http")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find_map(|exchange| get_str(exchange, &["request", "id"]))
            })
    })
}

fn trace_trace_id(trace_doc: &Value) -> Option<String> {
    get_str(trace_doc, &["trace_id"]).or_else(|| {
        trace_doc
            .get("steps")
            .and_then(Value::as_array)
            .and_then(|steps| {
                if steps.is_empty() {
                    None
                } else {
                    Some(gen_id("lptrace", &sha256_hex(&canon_json_bytes(trace_doc))))
                }
            })
    })
}

#[derive(Clone)]
struct IncidentContext {
    deployment_id: Option<String>,
    release_plan_id: Option<String>,
    release_exec_id: Option<String>,
    run_id: String,
    target_app_id: String,
    target_environment: String,
    bundle_environment: Value,
    pack_digest: Value,
    package_digest: Value,
    package_manifest_sha256: Option<String>,
    slot: Option<String>,
    candidate_weight_pct: Option<u64>,
    target_kind: Option<String>,
    provider_kind: Option<String>,
    device_release: Value,
    native_context: Value,
}

fn incident_scope_matches(
    meta: &Value,
    deployment_id: Option<&str>,
    release_exec_id: Option<&str>,
) -> bool {
    let meta_deployment = get_str(meta, &["deployment_id"]);
    let meta_release = get_str(meta, &["release_exec_id"]);
    if deployment_id.is_none() && release_exec_id.is_none() {
        return false;
    }
    if deployment_id != meta_deployment.as_deref() {
        return false;
    }
    if release_exec_id != meta_release.as_deref() {
        return false;
    }
    true
}

fn incident_target_store_base(meta: &Value, bundle: &Value) -> (String, String, String) {
    let app_id = get_str(meta, &["target", "app_id"]).unwrap_or_default();
    let environment = get_str(meta, &["target", "environment"]).unwrap_or_default();
    let incident_id = get_str(bundle, &["incident_id"]).unwrap_or_default();
    (app_id, environment, incident_id)
}

fn canonical_native_classification(classification: &str, reason: &str) -> Option<String> {
    match classification {
        "native_runtime_error"
        | "native_policy_violation"
        | "native_bridge_timeout"
        | "native_host_crash"
        | "native_permission_blocked" => Some(classification.to_string()),
        "device_policy_violation" => Some("native_policy_violation".to_string()),
        "device_webview_crash" => Some("native_host_crash".to_string()),
        "device_bridge_parse" => Some("native_bridge_timeout".to_string()),
        "device_js_unhandled" | "device_crash_spike" => Some("native_runtime_error".to_string()),
        _ if reason.to_ascii_lowercase().contains("permission")
            && reason.to_ascii_lowercase().contains("denied") =>
        {
            Some("native_permission_blocked".to_string())
        }
        _ => None,
    }
}

fn device_release_native_health_rollup_from_items(linked_incidents: &[Value]) -> Value {
    let mut runtime_error_count = 0_u64;
    let mut policy_violation_count = 0_u64;
    let mut bridge_timeout_count = 0_u64;
    let mut host_crash_count = 0_u64;
    let mut permission_blocked_count = 0_u64;
    let mut latest_native_incident_id = Value::Null;
    let mut latest_regression_id = Value::Null;
    let mut latest_regression_status = json!("not_requested");
    let mut latest_captured_unix_ms = 0_u64;
    for item in linked_incidents {
        let Some(native_classification) = get_str(item, &["native_classification"]) else {
            continue;
        };
        match native_classification.as_str() {
            "native_runtime_error" => runtime_error_count += 1,
            "native_policy_violation" => policy_violation_count += 1,
            "native_bridge_timeout" => bridge_timeout_count += 1,
            "native_host_crash" => host_crash_count += 1,
            "native_permission_blocked" => permission_blocked_count += 1,
            _ => {}
        }
        let captured_unix_ms = get_u64(item, &["captured_unix_ms"]).unwrap_or(0);
        if captured_unix_ms >= latest_captured_unix_ms {
            latest_captured_unix_ms = captured_unix_ms;
            latest_native_incident_id = get_path(item, &["incident_id"])
                .cloned()
                .unwrap_or(Value::Null);
            latest_regression_id = get_path(item, &["regression_id"])
                .cloned()
                .unwrap_or(Value::Null);
            latest_regression_status = json!(
                get_str(item, &["regression_status"])
                    .unwrap_or_else(|| "not_requested".to_string())
            );
        }
    }
    let native_incident_count = runtime_error_count
        + policy_violation_count
        + bridge_timeout_count
        + host_crash_count
        + permission_blocked_count;
    json!({
        "native_incident_count": native_incident_count,
        "native_runtime_error_count": runtime_error_count,
        "native_policy_violation_count": policy_violation_count,
        "native_bridge_timeout_count": bridge_timeout_count,
        "native_host_crash_count": host_crash_count,
        "native_permission_blocked_count": permission_blocked_count,
        "latest_native_incident_id": latest_native_incident_id,
        "latest_regression_id": latest_regression_id,
        "latest_regression_status": latest_regression_status,
    })
}

fn refresh_device_release_native_health(exec_doc: &mut Value) {
    let linked_incidents = get_path(exec_doc, &["meta", "linked_incidents"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    ensure_object_field(exec_doc, "meta").insert(
        "latest_native_health_rollup".to_string(),
        device_release_native_health_rollup_from_items(&linked_incidents),
    );
}

fn incident_query_item(meta: &Value, bundle: &Value) -> Value {
    json!({
        "incident_id": get_str(bundle, &["incident_id"]).unwrap_or_default(),
        "classification": get_str(meta, &["classification"]).unwrap_or_default(),
        "native_classification": get_path(meta, &["native_classification"]).cloned().unwrap_or(Value::Null),
        "reason": get_path(bundle, &["notes"]).cloned().unwrap_or(Value::Null),
        "source": get_str(meta, &["source"]).unwrap_or_default(),
        "incident_status": get_str(meta, &["incident_status"]).unwrap_or_default(),
        "target": get_path(meta, &["target"]).cloned().unwrap_or_else(|| json!({"app_id":"unknown","environment":"unknown"})),
        "deployment_id": get_path(meta, &["deployment_id"]).cloned().unwrap_or(Value::Null),
        "release_plan_id": get_path(meta, &["release_plan_id"]).cloned().unwrap_or(Value::Null),
        "release_exec_id": get_path(meta, &["release_exec_id"]).cloned().unwrap_or(Value::Null),
        "target_kind": get_path(meta, &["target_kind"]).cloned().unwrap_or(Value::Null),
        "provider_kind": get_path(meta, &["provider_kind"]).cloned().unwrap_or(Value::Null),
        "package_manifest_sha256": get_path(meta, &["package_manifest_sha256"]).cloned().unwrap_or(Value::Null),
        "run_id": get_str(meta, &["run_id"]).unwrap_or_default(),
        "captured_unix_ms": get_u64(meta, &["captured_unix_ms"]).unwrap_or(0),
        "request_id": get_path(meta, &["request_id"]).cloned().unwrap_or(Value::Null),
        "trace_id": get_path(meta, &["trace_id"]).cloned().unwrap_or(Value::Null),
        "status_code": get_path(meta, &["status_code"]).cloned().unwrap_or(Value::Null),
        "decision_id": get_path(meta, &["decision_id"]).cloned().unwrap_or(Value::Null),
        "regression_status": get_str(meta, &["regression_status"]).unwrap_or_else(|| "not_requested".to_string()),
        "regression_id": get_path(meta, &["regression_id"]).cloned().unwrap_or(Value::Null),
        "signature_status": get_str(meta, &["signature_status"]).unwrap_or_else(|| "not_applicable".to_string()),
        "native_context": get_path(meta, &["native_context"]).cloned().unwrap_or(Value::Null),
        "device_release": incident_release_ref(meta),
    })
}

fn device_release_linked_incident_item(meta: &Value, bundle: &Value) -> Value {
    json!({
        "incident_id": get_str(bundle, &["incident_id"]).unwrap_or_default(),
        "classification": get_str(meta, &["classification"]).unwrap_or_default(),
        "native_classification": get_path(meta, &["native_classification"]).cloned().unwrap_or(Value::Null),
        "reason": get_path(bundle, &["notes"]).cloned().unwrap_or(Value::Null),
        "source": get_str(meta, &["source"]).unwrap_or_default(),
        "incident_status": get_str(meta, &["incident_status"]).unwrap_or_default(),
        "captured_unix_ms": get_u64(meta, &["captured_unix_ms"]).unwrap_or(0),
        "regression_status": get_str(meta, &["regression_status"]).unwrap_or_else(|| "not_requested".to_string()),
        "regression_id": get_path(meta, &["regression_id"]).cloned().unwrap_or(Value::Null),
        "release_plan_id": get_path(meta, &["release_plan_id"]).cloned().unwrap_or(Value::Null),
        "target_kind": get_path(meta, &["target_kind"]).cloned().unwrap_or(Value::Null),
        "provider_kind": get_path(meta, &["provider_kind"]).cloned().unwrap_or(Value::Null),
        "package_manifest_sha256": get_path(meta, &["package_manifest_sha256"]).cloned().unwrap_or(Value::Null),
    })
}

fn upsert_device_release_linked_incident(exec_doc: &mut Value, meta: &Value, bundle: &Value) {
    let item = device_release_linked_incident_item(meta, bundle);
    let incident_id = get_str(&item, &["incident_id"]).unwrap_or_default();
    {
        let meta_map = ensure_object_field(exec_doc, "meta");
        let linked_value = meta_map
            .entry("linked_incidents".to_string())
            .or_insert_with(|| json!([]));
        if !linked_value.is_array() {
            *linked_value = json!([]);
        }
        let linked = linked_value
            .as_array_mut()
            .expect("linked_incidents must be an array");
        if let Some(existing) = linked
            .iter_mut()
            .find(|entry| get_str(entry, &["incident_id"]).as_deref() == Some(incident_id.as_str()))
        {
            *existing = item;
        } else {
            linked.push(item);
        }
    }
    refresh_device_release_native_health(exec_doc);
}

fn build_deployment_incident_context(
    exec_doc: &mut Value,
    run_doc: &Value,
    state_dir: &Path,
) -> Result<IncidentContext> {
    ensure_deploy_meta(exec_doc, run_doc, state_dir)?;
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(IncidentContext {
        deployment_id: get_str(exec_doc, &["exec_id"]),
        release_plan_id: None,
        release_exec_id: None,
        run_id: get_str(exec_doc, &["run_id"]).unwrap_or_default(),
        target_app_id: get_str(&meta, &["target", "app_id"]).unwrap_or_default(),
        target_environment: get_str(&meta, &["target", "environment"]).unwrap_or_default(),
        bundle_environment: env_name_to_doc(
            &get_str(&meta, &["target", "environment"]).unwrap_or_default(),
        ),
        pack_digest: get_path(run_doc, &["inputs", "artifact", "manifest", "digest"])
            .cloned()
            .unwrap_or(Value::Null),
        package_digest: Value::Null,
        package_manifest_sha256: None,
        slot: Some("candidate".to_string()),
        candidate_weight_pct: get_u64(&meta, &["routing", "candidate_weight_pct"]),
        target_kind: None,
        provider_kind: None,
        device_release: Value::Null,
        native_context: Value::Null,
    })
}

fn device_release_rollout_slot(exec_doc: &Value) -> (&'static str, Option<u64>) {
    match device_release_current_percent(exec_doc) {
        Some(100) => ("stable", Some(100)),
        Some(percent) if percent > 0 => ("candidate", Some(percent)),
        _ => ("none", None),
    }
}

fn build_device_release_incident_context(exec_doc: &Value) -> Result<IncidentContext> {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let release_exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing device release exec_id"))?;
    let release_plan_id = get_str(exec_doc, &["plan_id"]);
    let (slot, rollout_percent) = device_release_rollout_slot(exec_doc);
    let target_kind = get_str(&meta, &["target"]);
    let provider_kind = get_str(&meta, &["provider_kind"]);
    let package_manifest_sha256 = get_str(&meta, &["native_summary", "package_manifest_sha256"])
        .or_else(|| {
            get_str(&meta, &["package_digest", "sha256"]).map(|sha| format!("sha256:{sha}"))
        });
    let native_context = json!({
        "kind": "device_native",
        "release_plan_id": release_plan_id.clone(),
        "release_exec_id": release_exec_id.clone(),
        "platform": target_kind.clone().unwrap_or_else(|| "unknown".to_string()),
        "package_manifest_sha256": package_manifest_sha256.clone(),
        "capabilities_summary": get_path(&meta, &["native_summary", "capabilities"]).cloned().unwrap_or_else(|| json!({})),
        "permission_state_snapshot": Value::Null,
        "lifecycle_state": Value::Null,
        "connectivity_state": Value::Null,
        "breadcrumbs": [],
    });
    Ok(IncidentContext {
        deployment_id: None,
        release_plan_id: release_plan_id.clone(),
        release_exec_id: Some(release_exec_id.clone()),
        run_id: get_str(exec_doc, &["run_id"]).unwrap_or_default(),
        target_app_id: get_str(&meta, &["app", "app_id"]).unwrap_or_default(),
        target_environment: "device_release".to_string(),
        bundle_environment: json!({"kind":"custom","name":"device_release"}),
        pack_digest: Value::Null,
        package_digest: get_path(&meta, &["package_digest"])
            .cloned()
            .unwrap_or(Value::Null),
        package_manifest_sha256,
        slot: Some(slot.to_string()),
        candidate_weight_pct: rollout_percent,
        target_kind: target_kind.clone(),
        provider_kind: provider_kind.clone(),
        device_release: json!({
            "release_exec_id": release_exec_id,
            "release_plan_id": release_plan_id,
            "provider_kind": provider_kind.unwrap_or_else(|| "mock_v1".to_string()),
            "distribution_lane": get_str(&meta, &["distribution_lane"]).unwrap_or_else(|| "beta".to_string()),
            "target_kind": target_kind.unwrap_or_else(|| "ios".to_string()),
            "package_digest": get_path(&meta, &["package_digest"]).cloned().unwrap_or(Value::Null),
            "package_manifest_sha256": get_path(&meta, &["native_summary", "package_manifest_sha256"]).cloned().unwrap_or(Value::Null),
        }),
        native_context,
    })
}

fn find_existing_incident_for_key(
    state_dir: &Path,
    deployment_id: Option<&str>,
    release_exec_id: Option<&str>,
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
        if !incident_scope_matches(&meta, deployment_id, release_exec_id)
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

#[allow(clippy::too_many_arguments)]
fn build_incident_result(
    state_dir: &Path,
    meta: &Value,
    bundle: &Value,
    incident_dir: &Path,
    view: &str,
    resolution: Value,
    db_path: &Path,
    rebuilt: bool,
) -> Result<Value> {
    let bundle_bytes = fs::read(incident_dir.join("incident.bundle.json"))?;
    let (_, _, incident_id) = incident_target_store_base(meta, bundle);
    let store_prefix = incident_store_prefix(meta, &incident_id);
    let bundle_artifact = json!({
        "kind": DEVICE_INCIDENT_BUNDLE_KIND,
        "digest": digest_value(&bundle_bytes),
        "store_uri": format!("file:{store_prefix}/incident.bundle.json"),
    });
    let mut result = incident_query_item(meta, bundle);
    ensure_object(&mut result).extend(Map::from_iter([
        (
            "schema_version".to_string(),
            json!(DEVICE_INCIDENT_QUERY_RESULT_KIND),
        ),
        ("view".to_string(), json!(view)),
        ("resolution".to_string(), resolution),
        (
            "index".to_string(),
            json!({"used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy()}),
        ),
    ]));
    if view == "full" {
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
                    json!(format!("file:{store_prefix}/{label}")),
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
        if let Some(regression_id) = get_str(meta, &["regression_id"]) {
            let regression_path = state_dir
                .join("regressions")
                .join(format!("{regression_id}.json"));
            if regression_path.is_file() {
                let regression_summary = load_json(&regression_path)?;
                ensure_object(&mut result).insert("regression".to_string(), regression_summary);
            }
        }
    }
    Ok(result)
}

fn merge_object_values(base: &Value, patch: &Value) -> Value {
    match (base.as_object(), patch.as_object()) {
        (Some(base_map), Some(patch_map)) => {
            let mut merged = base_map.clone();
            for (key, value) in patch_map {
                merged.insert(key.clone(), value.clone());
            }
            Value::Object(merged)
        }
        _ if patch.is_null() => base.clone(),
        _ => patch.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_incident_with_context(
    state_dir: &Path,
    context: &IncidentContext,
    reason: &str,
    classification: &str,
    source: &str,
    native_context_patch: Option<&Value>,
    request_path: Option<&Path>,
    response_path: Option<&Path>,
    trace_path: Option<&Path>,
    decision_id: Option<&str>,
    signature_status: &str,
    now_unix_ms: u64,
) -> Result<(Value, Value, PathBuf)> {
    let request_env = request_path.map(load_sanitized_http_envelope).transpose()?;
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
        .and_then(|(doc, _)| get_str(doc, &["request_id"]).or_else(|| get_str(doc, &["id"])))
        .or_else(|| trace_doc.as_ref().and_then(trace_request_id));
    let trace_id = trace_doc.as_ref().and_then(trace_trace_id);
    if let Some(existing) = find_existing_incident_for_key(
        state_dir,
        context.deployment_id.as_deref(),
        context.release_exec_id.as_deref(),
        classification,
        request_id.as_deref(),
        decision_id,
    )? {
        return Ok(existing);
    }
    let scope_id = context
        .deployment_id
        .as_deref()
        .or(context.release_exec_id.as_deref())
        .unwrap_or("incident");
    let seed = format!("{scope_id}:{classification}:{source}:{now_unix_ms}:{reason}");
    let incident_id = gen_id("lpinc", &seed);
    let incident_dir = state_dir
        .join("incidents")
        .join(&context.target_app_id)
        .join(&context.target_environment)
        .join(&incident_id);
    fs::create_dir_all(&incident_dir)?;
    let native_context = native_context_patch
        .map(|patch| merge_object_values(&context.native_context, patch))
        .unwrap_or_else(|| context.native_context.clone());
    let native_classification = canonical_native_classification(classification, reason);

    let mut refs = Vec::new();
    let mut request_ref = Value::Null;
    let mut response_ref = Value::Null;
    let mut trace_ref = Value::Null;
    if let Some((_, bytes)) = request_env.as_ref() {
        write_bytes(&incident_dir.join("request.envelope.json"), bytes)?;
        request_ref = named_file_artifact(
            &format!(
                "incidents/{}/{}/{}/request.envelope.json",
                context.target_app_id, context.target_environment, incident_id
            ),
            "x07.http.request.envelope@0.1.0",
            "application/json",
            bytes,
        );
        refs.push(json!({
            "kind": "x07.http.request.envelope@0.1.0",
            "digest": request_ref.get("digest").cloned().unwrap_or(Value::Null),
            "label": "request.envelope.json",
        }));
    }
    if let Some((_, bytes)) = response_env.as_ref() {
        write_bytes(&incident_dir.join("response.envelope.json"), bytes)?;
        response_ref = named_file_artifact(
            &format!(
                "incidents/{}/{}/{}/response.envelope.json",
                context.target_app_id, context.target_environment, incident_id
            ),
            "x07.http.response.envelope@0.1.0",
            "application/json",
            bytes,
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
            &format!(
                "incidents/{}/{}/{}/trace.json",
                context.target_app_id, context.target_environment, incident_id
            ),
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
        "native_runtime_error" | "device_js_unhandled" | "device_crash_spike" => {
            vec![json!("LP_NATIVE_RUNTIME_ERROR")]
        }
        "native_bridge_timeout" | "device_bridge_parse" => {
            vec![json!("LP_NATIVE_BRIDGE_TIMEOUT")]
        }
        "native_policy_violation" | "device_policy_violation" => {
            vec![json!("LP_NATIVE_POLICY_VIOLATION")]
        }
        "native_host_crash" | "device_webview_crash" => vec![json!("LP_NATIVE_HOST_CRASH")],
        "native_permission_blocked" => vec![json!("LP_NATIVE_PERMISSION_BLOCKED")],
        "device_release_gate_failed" => vec![json!("LP_DEVICE_RELEASE_GATE_FAILED")],
        "device_release_provider_failed" => vec![json!("LP_DEVICE_RELEASE_PROVIDER_FAILED")],
        _ => Vec::new(),
    };
    let bundle = json!({
        "schema_version": DEVICE_INCIDENT_BUNDLE_KIND,
        "incident_id": incident_id,
        "created_unix_ms": now_unix_ms,
        "app_id": context.target_app_id.clone(),
        "environment": context.bundle_environment.clone(),
        "release_plan_id": context.release_plan_id.clone(),
        "release_exec_id": context.release_exec_id.clone(),
        "target_kind": context.target_kind.clone(),
        "provider_kind": context.provider_kind.clone(),
        "package_manifest_sha256": context.package_manifest_sha256.clone(),
        "window": {
            "start_unix_ms": now_unix_ms,
            "end_unix_ms": now_unix_ms,
        },
        "deploy_execution": context
            .deployment_id
            .as_ref()
            .map(|deployment_id| json!({ "exec_id": deployment_id }))
            .unwrap_or(Value::Null),
        "request": if request_ref.is_null() { Value::Null } else { json!({"kind":"x07.http.request.envelope@0.1.0","digest": request_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "response": if response_ref.is_null() { Value::Null } else { json!({"kind":"x07.http.response.envelope@0.1.0","digest": response_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "trace": if trace_ref.is_null() { Value::Null } else { json!({"kind":"x07.app.trace@0.1.0","digest": trace_ref.get("digest").cloned().unwrap_or(Value::Null)}) },
        "diag_codes": diag_codes,
        "refs": refs,
        "notes": reason,
        "native_classification": native_classification.clone(),
        "native_context": native_context.clone(),
        "meta": {
            "classification": classification,
            "source": source,
        }
    });
    let _ = write_json(&incident_dir.join("incident.bundle.json"), &bundle)?;
    let meta_doc = json!({
        "schema_version": DEVICE_INCIDENT_META_LOCAL_KIND,
        "classification": classification,
        "native_classification": native_classification,
        "source": source,
        "incident_status": "open",
        "deployment_id": context.deployment_id.clone(),
        "release_plan_id": context.release_plan_id.clone(),
        "release_exec_id": context.release_exec_id.clone(),
        "target_kind": context.target_kind.clone(),
        "provider_kind": context.provider_kind.clone(),
        "run_id": context.run_id.clone(),
        "target": {
            "app_id": context.target_app_id.clone(),
            "environment": context.target_environment.clone(),
        },
        "captured_unix_ms": now_unix_ms,
        "request_id": request_id.map(Value::from).unwrap_or(Value::Null),
        "trace_id": trace_id.map(Value::from).unwrap_or(Value::Null),
        "pack_digest": context.pack_digest.clone(),
        "package_digest": context.package_digest.clone(),
        "package_manifest_sha256": context.package_manifest_sha256.clone(),
        "slot": context.slot.clone().unwrap_or_else(|| "none".to_string()),
        "candidate_weight_pct": context.candidate_weight_pct,
        "status_code": status_code,
        "route_key": Value::Null,
        "decision_id": decision_id.map(Value::from).unwrap_or(Value::Null),
        "regression_id": Value::Null,
        "regression_status": "not_requested",
        "signature_status": signature_status,
        "device_release": context.device_release.clone(),
        "native_context": native_context,
    });
    let _ = write_json(&incident_dir.join("incident.meta.local.json"), &meta_doc)?;
    Ok((meta_doc, bundle, incident_dir))
}

#[allow(clippy::too_many_arguments)]
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
    let context = build_deployment_incident_context(exec_doc, run_doc, state_dir)?;
    let (meta_doc, bundle, incident_dir) = capture_incident_with_context(
        state_dir,
        &context,
        reason,
        classification,
        source,
        None,
        request_path,
        response_path,
        trace_path,
        decision_id,
        signature_status,
        now_unix_ms,
    )?;
    let exec_meta = ensure_object_field(exec_doc, "meta");
    let total =
        get_u64(&Value::Object(exec_meta.clone()), &["incident_count_total"]).unwrap_or(0) + 1;
    let open =
        get_u64(&Value::Object(exec_meta.clone()), &["incident_count_open"]).unwrap_or(0) + 1;
    let incident_id = get_str(&bundle, &["incident_id"]).unwrap_or_default();
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

#[allow(clippy::too_many_arguments)]
fn capture_device_release_incident_impl(
    state_dir: &Path,
    exec_doc: &mut Value,
    reason: &str,
    classification: &str,
    source: &str,
    native_context_patch: Option<&Value>,
    request_path: Option<&Path>,
    response_path: Option<&Path>,
    trace_path: Option<&Path>,
    decision_id: Option<&str>,
    signature_status: &str,
    now_unix_ms: u64,
) -> Result<(Value, Value, PathBuf)> {
    ensure_device_release_meta_defaults(exec_doc);
    let context = build_device_release_incident_context(exec_doc)?;
    let (meta_doc, bundle, incident_dir) = capture_incident_with_context(
        state_dir,
        &context,
        reason,
        classification,
        source,
        native_context_patch,
        request_path,
        response_path,
        trace_path,
        decision_id,
        signature_status,
        now_unix_ms,
    )?;
    let incident_id = get_str(&bundle, &["incident_id"]).unwrap_or_default();
    append_linked_incident(exec_doc, &incident_id, now_unix_ms);
    upsert_device_release_linked_incident(exec_doc, &meta_doc, &bundle);
    let _ = save_device_release_exec(state_dir, exec_doc)?;
    rebuild_indexes(state_dir)?;
    Ok((meta_doc, bundle, incident_dir))
}

#[allow(clippy::too_many_arguments)]
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

fn device_release_root_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("device_release")
}

fn device_release_provider_path(state_dir: &Path, provider_id: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("providers")
        .join(format!("{provider_id}.json"))
}

fn device_release_source_package_dir(state_dir: &Path, sha256: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("package_sources")
        .join(sha256)
}

fn device_release_source_package_manifest_path(state_dir: &Path, sha256: &str) -> PathBuf {
    device_release_source_package_dir(state_dir, sha256).join("package.manifest.json")
}

fn device_release_staged_package_dir(state_dir: &Path, exec_id: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("packages")
        .join(exec_id)
}

fn device_release_staged_package_manifest_path(state_dir: &Path, exec_id: &str) -> PathBuf {
    device_release_staged_package_dir(state_dir, exec_id).join("device.package.manifest.json")
}

fn device_release_package_path(state_dir: &Path, sha256: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("packages")
        .join(format!("{sha256}.json"))
}

fn device_release_plan_path(state_dir: &Path, plan_id: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("plans")
        .join(format!("{plan_id}.json"))
}

fn device_release_exec_path(state_dir: &Path, exec_id: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("executions")
        .join(format!("{exec_id}.json"))
}

fn allocate_device_release_run_and_exec_ids(
    state_dir: &Path,
    run_seed: &str,
    now_unix_ms: u64,
) -> (String, String) {
    let mut attempt = 0u64;
    loop {
        let material = if attempt == 0 {
            run_seed.to_string()
        } else {
            format!("{run_seed}:{attempt}")
        };
        let run_id = gen_id("lpdrrun", &material);
        let exec_id = gen_id("lpdrexec", &format!("{run_id}:{now_unix_ms}"));
        if !device_release_exec_path(state_dir, &exec_id).exists() {
            return (run_id, exec_id);
        }
        attempt += 1;
    }
}

fn device_release_slo_profile_path(state_dir: &Path, sha256: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("slo_profiles")
        .join(format!("{sha256}.json"))
}

fn device_release_metrics_dir(state_dir: &Path, exec_id: &str) -> PathBuf {
    device_release_root_dir(state_dir)
        .join("telemetry")
        .join(exec_id)
}

fn device_release_otlp_export_path(state_dir: &Path, exec_id: &str, analysis_seq: u64) -> PathBuf {
    device_release_metrics_dir(state_dir, exec_id).join(format!("analysis.{analysis_seq}.jsonl"))
}

fn load_device_release_exec(state_dir: &Path, exec_id: &str) -> Result<Value> {
    load_json(&device_release_exec_path(state_dir, exec_id))
}

fn save_device_release_exec(state_dir: &Path, exec_doc: &Value) -> Result<Vec<u8>> {
    let exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing device release exec_id"))?;
    write_json(&device_release_exec_path(state_dir, &exec_id), exec_doc)
}

fn write_device_release_slo_profile_copy(
    state_dir: &Path,
    slo_doc: &Value,
) -> Result<(PathBuf, Vec<u8>)> {
    let bytes = canon_json_bytes(slo_doc);
    let sha = sha256_hex(&bytes);
    let path = device_release_slo_profile_path(state_dir, &sha);
    let bytes = write_json(&path, slo_doc)?;
    Ok((path, bytes))
}

fn ensure_device_release_meta_defaults(exec_doc: &mut Value) {
    let created_unix_ms = get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0);
    let meta = ensure_object_field(exec_doc, "meta");
    upsert_default(meta, "updated_unix_ms", json!(created_unix_ms));
    upsert_default(meta, "automation_state", json!("active"));
    upsert_default(meta, "next_step_idx", json!(0));
    upsert_default(meta, "parent_exec_id", Value::Null);
    upsert_default(meta, "rerun_from_step_idx", Value::Null);
    upsert_default(meta, "latest_metrics_snapshot", Value::Null);
    upsert_default(meta, "latest_slo_eval_report", Value::Null);
    upsert_default(meta, "latest_eval_outcome", json!("none"));
    upsert_default(meta, "linked_incidents", json!([]));
    upsert_default(
        meta,
        "latest_native_health_rollup",
        default_device_release_native_health_rollup(),
    );
    upsert_default(meta, "last_incident_id", Value::Null);
    upsert_default(meta, "incident_count_total", json!(0));
    upsert_default(meta, "incident_count_open", json!(0));
    upsert_default(meta, "artifacts", json!([]));
    upsert_default(meta, "decisions", json!([]));
    upsert_default(meta, "decision_count", json!(0));
    upsert_default(meta, "latest_decision_id", Value::Null);
    upsert_default(meta, "latest_signed_control_decision_id", Value::Null);
    upsert_default(meta, "signature_status", json!("not_applicable"));
    upsert_default(meta, "package_report", Value::Null);
    upsert_default(meta, "native_summary", json!({}));
    upsert_default(
        meta,
        "release_readiness",
        json!({"status":"ok","warnings":[],"errors":[]}),
    );
    upsert_default(meta, "native_validation_warnings", json!([]));
    upsert_default(meta, "native_validation_errors", json!([]));
}

fn device_release_eval_outcome(decision_value: &str) -> &'static str {
    match decision_value {
        "promote" => "ok",
        "rollback" => "fail",
        "inconclusive" => "inconclusive",
        _ => "none",
    }
}

fn device_release_next_step_idx(exec_doc: &Value) -> usize {
    get_u64(exec_doc, &["meta", "next_step_idx"])
        .map(|value| value as usize)
        .unwrap_or(0)
}

fn device_release_collect_artifacts(exec_doc: &Value) -> Vec<Value> {
    get_path(exec_doc, &["meta", "artifacts"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn device_release_step_outcome(step_doc: &Value) -> String {
    get_str(step_doc, &["on_fail"]).unwrap_or_else(|| "release.pause".to_string())
}

fn provider_module_id(provider_kind: &str) -> &'static str {
    match provider_kind {
        "mock_v1" => "lp.impl.dist.mock_v1",
        "appstoreconnect_v1" => "lp.impl.dist.appstoreconnect_v1",
        "googleplay_v1" => "lp.impl.dist.googleplay_v1",
        _ => "lp.impl.dist.mock_v1",
    }
}

fn string_or_number(value: &Value, path: &[&str]) -> Option<String> {
    let node = get_path(value, path)?;
    if let Some(text) = node.as_str() {
        Some(text.to_string())
    } else if let Some(number) = node.as_u64() {
        Some(number.to_string())
    } else {
        node.as_i64().map(|number| number.to_string())
    }
}

fn build_device_provider_capabilities(provider_doc: &Value) -> Result<Value> {
    let provider_kind = get_str(provider_doc, &["provider_kind"])
        .ok_or_else(|| anyhow!("provider profile missing provider_kind"))?;
    let target = get_str(provider_doc, &["target"])
        .ok_or_else(|| anyhow!("provider profile missing target"))?;
    let distribution_lane = get_str(provider_doc, &["distribution_lane"])
        .ok_or_else(|| anyhow!("provider profile missing distribution_lane"))?;
    let (
        supported_ops,
        supports_percent_rollout,
        supports_pause,
        supports_resume,
        supports_complete,
        supports_rollback,
    ) = match (provider_kind.as_str(), distribution_lane.as_str()) {
        ("mock_v1", "beta") => (vec!["release.start"], false, false, false, false, false),
        ("mock_v1", "production") => (
            vec![
                "release.start",
                "rollout.set_percent",
                "release.pause",
                "release.resume",
                "release.complete",
                "rollback.previous",
            ],
            true,
            true,
            true,
            true,
            true,
        ),
        ("appstoreconnect_v1", "beta") => {
            (vec!["release.start"], false, false, false, false, false)
        }
        ("appstoreconnect_v1", "production") => (
            vec![
                "release.start",
                "release.pause",
                "release.resume",
                "release.complete",
            ],
            false,
            true,
            true,
            true,
            false,
        ),
        ("googleplay_v1", "beta") => (vec!["release.start"], false, false, false, false, false),
        ("googleplay_v1", "production") => (
            vec![
                "release.start",
                "rollout.set_percent",
                "release.pause",
                "release.resume",
                "release.complete",
                "rollback.previous",
            ],
            true,
            true,
            true,
            true,
            true,
        ),
        _ => bail!("unsupported provider_kind/distribution_lane combination"),
    };
    Ok(json!({
        "schema_version": "lp.adapter.capabilities@0.1.0",
        "provider": provider_module_id(&provider_kind),
        "runtime_kind": "device_store",
        "routing_kind": "store_control",
        "artifact_distribution": "store_upload",
        "supports_incidents": true,
        "supports_regressions": true,
        "supports_pause": true,
        "supports_rerun": true,
        "supports_weighted_canary": supports_percent_rollout,
        "supports_otlp": true,
        "supports_server_side_secrets": false,
        "device_release": {
            "supported_targets": [target],
            "supported_distribution_lanes": [distribution_lane],
            "supported_ops": supported_ops,
            "supports_percent_rollout": supports_percent_rollout,
            "supports_release_pause": supports_pause,
            "supports_release_resume": supports_resume,
            "supports_release_complete": supports_complete,
            "supports_release_rollback": supports_rollback,
        }
    }))
}

fn validate_device_provider_profile_doc(provider_doc: &Value) -> Result<Value> {
    if get_str(provider_doc, &["schema_version"]).as_deref()
        != Some(DEVICE_STORE_PROVIDER_PROFILE_KIND)
    {
        bail!("provider profile must have schema_version={DEVICE_STORE_PROVIDER_PROFILE_KIND}");
    }
    let provider_kind = get_str(provider_doc, &["provider_kind"])
        .ok_or_else(|| anyhow!("provider profile missing provider_kind"))?;
    if !matches!(
        provider_kind.as_str(),
        "mock_v1" | "appstoreconnect_v1" | "googleplay_v1"
    ) {
        bail!("unsupported provider_kind={provider_kind}");
    }
    let target = get_str(provider_doc, &["target"])
        .ok_or_else(|| anyhow!("provider profile missing target"))?;
    if !matches!(target.as_str(), "ios" | "android") {
        bail!("unsupported device release target={target}");
    }
    let distribution_lane = get_str(provider_doc, &["distribution_lane"])
        .ok_or_else(|| anyhow!("provider profile missing distribution_lane"))?;
    if !matches!(distribution_lane.as_str(), "beta" | "production") {
        bail!("unsupported device release lane={distribution_lane}");
    }
    if get_str(provider_doc, &["provider_id"]).is_none() {
        bail!("provider profile missing provider_id");
    }
    if get_path(provider_doc, &["app_ref"]).is_none() {
        bail!("provider profile missing app_ref");
    }
    if get_path(provider_doc, &["policy"]).is_none() {
        bail!("provider profile missing policy");
    }
    build_device_provider_capabilities(provider_doc)
}

fn validate_device_package_manifest_doc(package_doc: &Value) -> Result<()> {
    if get_str(package_doc, &["schema_version"]).as_deref() != Some(DEVICE_PACKAGE_MANIFEST_KIND) {
        bail!("package manifest must have schema_version={DEVICE_PACKAGE_MANIFEST_KIND}");
    }
    let target = get_str(package_doc, &["target"])
        .ok_or_else(|| anyhow!("package manifest missing target"))?;
    if !matches!(target.as_str(), "ios" | "android") {
        bail!("device release target must be ios or android");
    }
    if get_path(package_doc, &["profile"]).is_none() {
        bail!("package manifest missing profile");
    }
    if get_path(package_doc, &["capabilities"]).is_none() {
        bail!("package manifest missing capabilities");
    }
    if get_path(package_doc, &["telemetry_profile"]).is_none() {
        bail!("package manifest missing telemetry_profile");
    }
    if get_path(package_doc, &["package"]).is_none() {
        bail!("package manifest missing package payload");
    }
    Ok(())
}

fn find_embedded_device_profile(payload_dir: &Path) -> Result<PathBuf> {
    let mut matches = Vec::new();
    for entry in WalkDir::new(payload_dir) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name() != OsStr::new("device.profile.json") {
            continue;
        }
        matches.push(entry.path().to_path_buf());
    }
    matches.sort();
    matches.into_iter().next().ok_or_else(|| {
        anyhow!(
            "unable to find embedded device.profile.json under {}",
            payload_dir.display()
        )
    })
}

fn package_payload_path(package_manifest_path: &Path, package_doc: &Value) -> Result<PathBuf> {
    let package_rel = get_str(package_doc, &["package", "path"])
        .ok_or_else(|| anyhow!("package manifest missing package.path"))?;
    let kind = get_str(package_doc, &["package", "kind"])
        .ok_or_else(|| anyhow!("package manifest missing package.kind"))?;
    if kind != "dir" {
        bail!("device release create currently requires package.kind=dir");
    }
    let candidate = PathBuf::from(&package_rel);
    let base = package_manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(root_dir);
    Ok(if candidate.is_absolute() {
        candidate
    } else {
        base.join(candidate)
    })
}

fn load_device_profile_from_package_manifest(
    package_manifest_path: &Path,
    package_doc: &Value,
) -> Result<(PathBuf, Value)> {
    let payload_dir = package_payload_path(package_manifest_path, package_doc)?;
    let profile_path = find_embedded_device_profile(&payload_dir)?;
    Ok((profile_path.clone(), load_json(&profile_path)?))
}

fn native_readiness_item(code: &str, message: impl Into<String>) -> Value {
    json!({
        "code": code,
        "message": message.into(),
    })
}

fn native_readiness_status(warnings: &[Value], errors: &[Value]) -> &'static str {
    if !errors.is_empty() {
        "error"
    } else if !warnings.is_empty() {
        "warn"
    } else {
        "ok"
    }
}

fn normalize_sha256_text(raw: Option<String>, fallback_bytes: Option<&[u8]>) -> String {
    if let Some(raw) = raw {
        if raw.starts_with("sha256:") {
            return raw;
        }
        if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return format!("sha256:{raw}");
        }
    }
    fallback_bytes
        .map(|bytes| format!("sha256:{}", sha256_hex(bytes)))
        .unwrap_or_else(|| "sha256:unknown".to_string())
}

fn device_package_manifest_entry_path(
    package_manifest_path: &Path,
    package_doc: &Value,
    path: &[&str],
) -> Result<PathBuf> {
    let rel = get_str(package_doc, path)
        .ok_or_else(|| anyhow!("package manifest missing {}", path.join(".")))?;
    let candidate = PathBuf::from(&rel);
    let base = package_manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(root_dir);
    Ok(if candidate.is_absolute() {
        candidate
    } else {
        base.join(candidate)
    })
}

fn load_device_package_sidecar(
    package_manifest_path: &Path,
    package_doc: &Value,
    path: &[&str],
) -> Result<Value> {
    let full_path = device_package_manifest_entry_path(package_manifest_path, package_doc, path)?;
    load_json(&full_path)
}

fn device_native_capabilities_summary(capabilities_doc: &Value) -> Value {
    let mut summary = Map::new();
    summary.insert(
        "camera_photo".to_string(),
        json!(get_bool(capabilities_doc, &["device", "camera", "photo"]).unwrap_or(false)),
    );
    summary.insert(
        "files_pick".to_string(),
        json!(get_bool(capabilities_doc, &["device", "files", "pick"]).unwrap_or(false)),
    );
    summary.insert(
        "location_foreground".to_string(),
        json!(get_bool(capabilities_doc, &["device", "location", "foreground"]).unwrap_or(false)),
    );
    summary.insert(
        "notifications_local".to_string(),
        json!(get_bool(capabilities_doc, &["device", "notifications", "local"]).unwrap_or(false)),
    );
    summary.insert(
        "notifications_push".to_string(),
        json!(get_bool(capabilities_doc, &["device", "notifications", "push"]).unwrap_or(false)),
    );
    if let Some(blob_store) = get_path(capabilities_doc, &["device", "blob_store"]).cloned() {
        summary.insert("blob_store".to_string(), blob_store);
    }
    Value::Object(summary)
}

fn device_permission_declarations(capabilities_doc: &Value) -> Vec<Value> {
    let mut permissions = Vec::new();
    if get_bool(capabilities_doc, &["device", "camera", "photo"]).unwrap_or(false) {
        permissions.push(json!("camera"));
    }
    if get_bool(capabilities_doc, &["device", "files", "pick"]).unwrap_or(false) {
        permissions.push(json!("files_pick"));
    }
    if get_bool(capabilities_doc, &["device", "location", "foreground"]).unwrap_or(false) {
        permissions.push(json!("location_foreground"));
    }
    if get_bool(capabilities_doc, &["device", "notifications", "local"]).unwrap_or(false)
        || get_bool(capabilities_doc, &["device", "notifications", "push"]).unwrap_or(false)
    {
        permissions.push(json!("notifications"));
    }
    permissions
}

fn value_array_of_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn report_readiness_items(report_doc: &Value, severity: &str) -> Vec<Value> {
    report_doc
        .get("diagnostics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|diag| get_str(diag, &["severity"]).as_deref() == Some(severity))
        .map(|diag| {
            native_readiness_item(
                &get_str(diag, &["code"]).unwrap_or_else(|| "X07WASM_DEVICE_REPORT".to_string()),
                get_str(diag, &["message"])
                    .unwrap_or_else(|| "device package report diagnostic".to_string()),
            )
        })
        .collect()
}

fn device_native_release_metadata(
    package_manifest_path: &Path,
    package_doc: &Value,
    provider_doc: &Value,
    package_report_doc: &Value,
) -> Result<(Value, Value, Vec<Value>, Vec<Value>)> {
    let package_manifest_bytes = canon_json_bytes(package_doc);
    let manifest_sha256 = normalize_sha256_text(
        get_str(
            package_report_doc,
            &["result", "package_manifest", "sha256"],
        ),
        Some(&package_manifest_bytes),
    );
    let capabilities_doc = load_device_package_sidecar(
        package_manifest_path,
        package_doc,
        &["capabilities", "path"],
    )?;
    let telemetry_doc = load_device_package_sidecar(
        package_manifest_path,
        package_doc,
        &["telemetry_profile", "path"],
    )?;
    let expected_classes = device_release_telemetry::standard_device_release_event_classes()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<BTreeSet<_>>();
    let telemetry_classes = value_array_of_strings(get_path(&telemetry_doc, &["event_classes"]));
    let telemetry_class_values = telemetry_classes
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let telemetry_class_set = telemetry_classes.iter().cloned().collect::<BTreeSet<_>>();
    let mut warnings = report_readiness_items(package_report_doc, "warning");
    let mut errors = report_readiness_items(package_report_doc, "error");
    let target = get_str(package_doc, &["target"]).unwrap_or_default();
    let provider_target = get_str(provider_doc, &["target"]).unwrap_or_default();
    if target != provider_target {
        errors.push(native_readiness_item(
            "LP_DEVICE_RELEASE_TARGET_MISMATCH",
            format!("package target {target} does not match provider target {provider_target}"),
        ));
    }
    let missing_classes = expected_classes
        .difference(&telemetry_class_set)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_classes.is_empty() {
        errors.push(native_readiness_item(
            "LP_DEVICE_RELEASE_TELEMETRY_CLASSES_MISSING",
            format!(
                "missing required telemetry classes: {}",
                missing_classes.join(", ")
            ),
        ));
    }
    let permissions = device_permission_declarations(&capabilities_doc);
    if permissions.is_empty() {
        errors.push(native_readiness_item(
            "LP_DEVICE_RELEASE_PERMISSION_DECLARATIONS_MISSING",
            "package capabilities did not declare any releasable native permissions",
        ));
    }
    let report_native_summary = get_path(package_report_doc, &["result", "native_summary"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let report_release_readiness = get_path(package_report_doc, &["result", "release_readiness"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let existing_capabilities = get_path(&report_native_summary, &["capabilities"]).cloned();
    let existing_permissions =
        get_path(&report_native_summary, &["permission_declarations"]).cloned();
    let existing_telemetry_classes =
        get_path(&report_native_summary, &["telemetry_classes"]).cloned();
    let mut native_summary = if report_native_summary.is_object() {
        report_native_summary
    } else {
        json!({})
    };
    let native_summary_map = ensure_object(&mut native_summary);
    native_summary_map.insert("target_kind".to_string(), json!(target));
    native_summary_map.insert(
        "provider_kind".to_string(),
        json!(get_str(provider_doc, &["provider_kind"]).unwrap_or_default()),
    );
    native_summary_map.insert(
        "package_manifest_sha256".to_string(),
        json!(manifest_sha256.clone()),
    );
    native_summary_map.insert(
        "capabilities".to_string(),
        existing_capabilities
            .unwrap_or_else(|| device_native_capabilities_summary(&capabilities_doc)),
    );
    native_summary_map.insert(
        "permission_declarations".to_string(),
        existing_permissions.unwrap_or_else(|| Value::Array(permissions.clone())),
    );
    native_summary_map.insert(
        "telemetry_classes".to_string(),
        existing_telemetry_classes.unwrap_or_else(|| Value::Array(telemetry_class_values.clone())),
    );

    let mut release_readiness = if report_release_readiness.is_object() {
        report_release_readiness
    } else {
        json!({})
    };
    let report_warnings = get_path(&release_readiness, &["warnings"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let report_errors = get_path(&release_readiness, &["errors"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    warnings.extend(report_warnings);
    errors.extend(report_errors);
    let readiness_map = ensure_object(&mut release_readiness);
    readiness_map.insert(
        "status".to_string(),
        json!(native_readiness_status(&warnings, &errors)),
    );
    readiness_map.insert("warnings".to_string(), Value::Array(warnings.clone()));
    readiness_map.insert("errors".to_string(), Value::Array(errors.clone()));
    native_summary_map.insert("release_readiness".to_string(), release_readiness.clone());
    Ok((native_summary, release_readiness, warnings, errors))
}

fn device_release_readiness_status(plan_or_exec: &Value) -> String {
    get_str(plan_or_exec, &["release_readiness", "status"])
        .or_else(|| {
            get_str(
                plan_or_exec,
                &["native_summary", "release_readiness", "status"],
            )
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn default_device_release_native_health_rollup() -> Value {
    json!({
        "native_incident_count": 0,
        "native_runtime_error_count": 0,
        "native_policy_violation_count": 0,
        "native_bridge_timeout_count": 0,
        "native_host_crash_count": 0,
        "native_permission_blocked_count": 0,
        "latest_native_incident_id": Value::Null,
        "latest_regression_id": Value::Null,
        "latest_regression_status": "not_requested",
    })
}

fn device_release_native_health_rollup(exec_doc: &Value) -> Value {
    let linked = get_path(exec_doc, &["meta", "linked_incidents"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut item| {
            if get_path(&item, &["native_classification"]).is_none() {
                let reason = get_str(&item, &["reason"]).unwrap_or_default();
                if let Some(classification) = get_str(&item, &["classification"])
                    .and_then(|value| canonical_native_classification(&value, &reason))
                {
                    ensure_object(&mut item)
                        .insert("native_classification".to_string(), json!(classification));
                }
            }
            item
        })
        .collect::<Vec<_>>();
    device_release_native_health_rollup_from_items(&linked)
}

fn default_device_release_steps(provider_doc: &Value) -> Vec<Value> {
    let provider_kind =
        get_str(provider_doc, &["provider_kind"]).unwrap_or_else(|| "mock_v1".to_string());
    let distribution_lane =
        get_str(provider_doc, &["distribution_lane"]).unwrap_or_else(|| "beta".to_string());
    let initial_percent = get_u64(provider_doc, &["rollout_defaults", "initial_percent"])
        .or_else(|| get_u64(provider_doc, &["policy", "initial_percent"]))
        .unwrap_or(10)
        .min(100);
    let mut steps = vec![json!({
        "id": "start",
        "op": "release.start",
        "on_fail": "pause",
    })];
    if distribution_lane == "production" && provider_kind != "appstoreconnect_v1" {
        steps.push(json!({
            "id": format!("rollout_{}", initial_percent),
            "op": "rollout.set_percent",
            "percent": initial_percent,
            "on_fail": "pause",
        }));
    }
    steps
}

fn validate_device_release_plan_doc(plan_doc: &Value, provider_doc: &Value) -> Result<Value> {
    if get_str(plan_doc, &["schema_version"]).as_deref() != Some(DEVICE_RELEASE_PLAN_KIND) {
        bail!("device release plan must have schema_version={DEVICE_RELEASE_PLAN_KIND}");
    }
    let capabilities = validate_device_provider_profile_doc(provider_doc)?;
    let plan_target =
        get_str(plan_doc, &["target"]).ok_or_else(|| anyhow!("plan missing target"))?;
    let provider_target = get_str(provider_doc, &["target"])
        .ok_or_else(|| anyhow!("provider profile missing target"))?;
    if plan_target != provider_target {
        bail!("plan target does not match provider profile target");
    }
    let package_kind = get_str(plan_doc, &["package", "kind"])
        .ok_or_else(|| anyhow!("plan missing package.kind"))?;
    if package_kind != DEVICE_PACKAGE_MANIFEST_KIND {
        bail!("plan package.kind must be {DEVICE_PACKAGE_MANIFEST_KIND}");
    }
    let native_summary = get_path(plan_doc, &["native_summary"])
        .ok_or_else(|| anyhow!("plan missing native_summary"))?;
    if get_str(native_summary, &["target_kind"]).as_deref() != Some(plan_target.as_str()) {
        bail!("plan native_summary.target_kind does not match plan target");
    }
    if get_str(native_summary, &["provider_kind"]).as_deref()
        != get_str(provider_doc, &["provider_kind"]).as_deref()
    {
        bail!("plan native_summary.provider_kind does not match provider profile");
    }
    if value_array_of_strings(get_path(native_summary, &["telemetry_classes"])).is_empty() {
        bail!("plan native_summary.telemetry_classes must be non-empty");
    }
    let permission_declarations = get_path(native_summary, &["permission_declarations"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if permission_declarations.is_empty() {
        bail!("plan native_summary.permission_declarations must be non-empty");
    }
    let release_readiness = get_path(plan_doc, &["release_readiness"])
        .ok_or_else(|| anyhow!("plan missing release_readiness"))?;
    if get_path(release_readiness, &["errors"])
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
        || get_str(release_readiness, &["status"]).as_deref() == Some("error")
    {
        bail!("plan release_readiness contains blocking errors");
    }
    let supported_ops = get_path(&capabilities, &["device_release", "supported_ops"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<BTreeSet<_>>();
    let supports_percent_rollout = get_bool(
        &capabilities,
        &["device_release", "supports_percent_rollout"],
    )
    .unwrap_or(false);
    let steps = get_path(plan_doc, &["steps"])
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("plan missing steps"))?;
    if steps.is_empty() {
        bail!("plan requires at least one step");
    }
    for step in steps {
        let op = get_str(step, &["op"]).ok_or_else(|| anyhow!("plan step missing op"))?;
        if op == "metrics.eval" {
            let window_seconds = get_u64(step, &["window_seconds"])
                .ok_or_else(|| anyhow!("metrics.eval requires window_seconds"))?;
            if window_seconds == 0 {
                bail!("metrics.eval window_seconds must be > 0");
            }
            if get_str(step, &["thresholds", "kind"]).as_deref() != Some("x07.slo.profile@0.1.0") {
                bail!("metrics.eval thresholds.kind must be x07.slo.profile@0.1.0");
            }
            if get_path(step, &["thresholds", "digest"]).is_none() {
                bail!("metrics.eval thresholds.digest is required");
            }
            match device_release_step_outcome(step).as_str() {
                "release.pause" | "release.halt" | "require_human" => {}
                other => bail!("unsupported metrics.eval on_fail={other}"),
            }
            continue;
        }
        if !supported_ops.contains(&op) {
            bail!("provider does not support device release op={op}");
        }
        if op == "rollout.set_percent" {
            if !supports_percent_rollout {
                bail!("provider does not support rollout.set_percent");
            }
            let percent = get_u64(step, &["percent"])
                .ok_or_else(|| anyhow!("rollout.set_percent requires percent"))?;
            if percent > 100 {
                bail!("rollout percent must be <= 100");
            }
        }
    }
    Ok(capabilities)
}

fn write_device_release_evidence(
    state_dir: &Path,
    exec_id: &str,
    suffix: &str,
    doc: &Value,
) -> Result<Value> {
    let cleaned = suffix
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    let rel_path = format!("device_release/evidence/{}.{}.json", exec_id, cleaned);
    let path = state_dir.join(&rel_path);
    let bytes = write_json(&path, doc)?;
    Ok(named_file_artifact(
        &rel_path,
        "x07.artifact.json@0.1.0",
        "application/json",
        &bytes,
    ))
}

fn device_release_step_name(step_doc: &Value, idx: usize) -> String {
    get_str(step_doc, &["id"]).unwrap_or_else(|| format!("step_{idx}"))
}

fn device_release_now(common: &CommonStateArgs) -> u64 {
    common.now_unix_ms.unwrap_or_else(now_ms)
}

fn device_release_current_percent(exec_doc: &Value) -> Option<u64> {
    get_path(exec_doc, &["meta", "current_rollout_percent"]).and_then(Value::as_u64)
}

fn device_release_state(exec_doc: &Value) -> String {
    get_str(exec_doc, &["meta", "current_state"]).unwrap_or_else(|| "draft".to_string())
}

fn device_release_store_release_id(exec_doc: &Value) -> Option<String> {
    get_str(exec_doc, &["meta", "latest_store_release_id"])
}

fn device_release_control_state_snapshot(exec_doc: &Value) -> Value {
    let native_health_rollup = device_release_native_health_rollup(exec_doc);
    json!({
        "status": get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
        "current_state": device_release_state(exec_doc),
        "automation_state": get_str(exec_doc, &["meta", "automation_state"]).unwrap_or_else(|| "active".to_string()),
        "current_rollout_percent": get_path(exec_doc, &["meta", "current_rollout_percent"]).cloned().unwrap_or(Value::Null),
        "latest_store_release_id": get_path(exec_doc, &["meta", "latest_store_release_id"]).cloned().unwrap_or(Value::Null),
        "latest_eval_outcome": get_path(exec_doc, &["meta", "latest_eval_outcome"]).cloned().unwrap_or_else(|| json!("none")),
        "release_readiness_status": device_release_readiness_status(&get_path(exec_doc, &["meta"]).cloned().unwrap_or_else(|| json!({}))),
        "latest_native_health_rollup": native_health_rollup,
    })
}

fn device_provider_live_enabled() -> bool {
    std::env::var(DEVICE_PROVIDER_LIVE_ENV).ok().as_deref() == Some("1")
}

fn device_release_provider_mode(provider_doc: &Value) -> &'static str {
    device_release_provider::device_release_provider_mode(provider_doc)
}

fn device_release_initial_percent(provider_doc: &Value) -> u64 {
    get_u64(provider_doc, &["rollout_defaults", "initial_percent"])
        .or_else(|| get_u64(provider_doc, &["policy", "initial_percent"]))
        .unwrap_or(10)
        .min(100)
}

fn apply_device_release_provider_op(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
    step_doc: &Value,
    exec_id: &str,
) -> Result<device_release_provider::DeviceProviderStepOutcome> {
    device_release_provider::apply_device_release_provider_op(
        state_dir,
        provider_doc,
        exec_doc,
        step_doc,
        exec_id,
    )
}

fn resolve_device_release_slo_profile_path(state_dir: &Path, step_doc: &Value) -> Result<PathBuf> {
    let sha = get_str(step_doc, &["thresholds", "digest", "sha256"])
        .ok_or_else(|| anyhow!("metrics.eval thresholds.digest.sha256 is required"))?;
    Ok(device_release_slo_profile_path(state_dir, &sha))
}

fn upsert_device_release_step(exec_doc: &mut Value, step_doc: Value) {
    let idx = get_u64(&step_doc, &["idx"]).unwrap_or(0);
    let kind = get_str(&step_doc, &["kind"]).unwrap_or_default();
    let steps = ensure_array_field(exec_doc, "steps");
    if let Some(existing) = steps.iter_mut().find(|item| {
        get_u64(item, &["idx"]).unwrap_or(u64::MAX) == idx
            && get_str(item, &["kind"]).unwrap_or_default() == kind
    }) {
        *existing = step_doc;
    } else {
        steps.push(step_doc);
    }
}

fn materialize_device_release_metrics_snapshot(
    state_dir: &Path,
    exec_doc: &Value,
    plan_doc: &Value,
    provider_doc: &Value,
) -> Result<Option<(PathBuf, device_release_telemetry::DeviceTelemetryAnalysis)>> {
    let exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing device release exec_id"))?;
    let dir = device_release_metrics_dir(state_dir, &exec_id);
    if !dir.exists() {
        return Ok(None);
    }
    let next_seq = get_u64(exec_doc, &["meta", "analysis_seq"]).unwrap_or(0) + 1;
    let preferred = device_release_otlp_export_path(state_dir, &exec_id, next_seq);
    let export_path = if preferred.is_file() {
        preferred
    } else {
        let fallback = dir.join("otlp.jsonl");
        if fallback.is_file() {
            fallback
        } else {
            return Ok(None);
        }
    };
    let analysis = device_release_telemetry::analyze_device_release_otlp_export(
        &export_path,
        exec_doc,
        provider_doc,
    )?;
    let snapshot_path = dir.join(format!("analysis.{next_seq}.json"));
    let _ = write_json(&snapshot_path, &analysis.snapshot)?;
    let _ = plan_doc;
    Ok(Some((snapshot_path, analysis)))
}

fn advance_device_release_execution(
    state_dir: &Path,
    exec_doc: &mut Value,
    plan_doc: &Value,
    provider_doc: &Value,
    allow_metrics_eval: bool,
    now_unix_ms: u64,
) -> Result<()> {
    ensure_device_release_meta_defaults(exec_doc);
    let steps = get_path(plan_doc, &["steps"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing device release exec_id"))?;
    let run_id = get_str(exec_doc, &["run_id"]).unwrap_or_default();
    let mut idx = device_release_next_step_idx(exec_doc);
    while idx < steps.len() {
        let step_doc = &steps[idx];
        let step_name = device_release_step_name(step_doc, idx);
        let op = get_str(step_doc, &["op"]).unwrap_or_else(|| "unknown".to_string());
        let started_unix_ms = now_unix_ms + idx as u64;
        if op == "metrics.eval" {
            if !allow_metrics_eval {
                ensure_object_field(exec_doc, "meta").insert(
                    "automation_state".to_string(),
                    json!("waiting_for_observation"),
                );
                ensure_object_field(exec_doc, "meta")
                    .insert("next_step_idx".to_string(), json!(idx));
                ensure_object_field(exec_doc, "meta")
                    .insert("updated_unix_ms".to_string(), json!(started_unix_ms));
                ensure_object(exec_doc).insert("status".to_string(), json!("started"));
                upsert_device_release_step(
                    exec_doc,
                    build_device_release_step(
                        idx,
                        &step_name,
                        &op,
                        "running",
                        started_unix_ms,
                        None,
                        Vec::new(),
                        device_release_current_percent(exec_doc),
                        device_release_store_release_id(exec_doc).as_deref(),
                        None,
                    ),
                );
                return Ok(());
            }
            let Some((metrics_path, telemetry_analysis)) =
                materialize_device_release_metrics_snapshot(
                    state_dir,
                    exec_doc,
                    plan_doc,
                    provider_doc,
                )?
            else {
                bail!("missing metrics snapshot for device release observe");
            };
            let slo_profile_path = resolve_device_release_slo_profile_path(state_dir, step_doc)?;
            let (mut decision_value, slo_report) =
                run_slo_eval(Some(&slo_profile_path), &metrics_path)?;
            let metrics_bytes = fs::read(&metrics_path)?;
            let mut metrics_raw = cas_put(
                state_dir,
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
                state_dir,
                "device_release.slo.eval",
                "application/json",
                &slo_bytes,
            )?;
            ensure_object(&mut slo_raw).insert("kind".to_string(), json!(slo_kind.clone()));
            let slo_artifact = artifact_summary("slo_eval_report", &slo_raw, 0, Some(&slo_kind));
            push_artifact(exec_doc, metrics_artifact.clone());
            push_artifact(exec_doc, slo_artifact.clone());
            let telemetry_incidents = telemetry_analysis.incidents;
            let (decision_outcome, reason_code, decision_message) =
                if !telemetry_incidents.is_empty() {
                    decision_value = "rollback".to_string();
                    (
                        "deny",
                        "LP_DEVICE_RELEASE_TELEMETRY_INCIDENT",
                        format!(
                            "device release telemetry produced {} blocking incident(s)",
                            telemetry_incidents.len()
                        ),
                    )
                } else {
                    match decision_value.as_str() {
                        "promote" => (
                            "allow",
                            "LP_DEVICE_RELEASE_SLO_PROMOTE",
                            format!("device release metrics decision is {decision_value}"),
                        ),
                        "rollback" => (
                            "deny",
                            "LP_DEVICE_RELEASE_SLO_FAIL",
                            format!("device release metrics decision is {decision_value}"),
                        ),
                        _ => (
                            "error",
                            "LP_DEVICE_RELEASE_SLO_INCONCLUSIVE",
                            format!("device release metrics decision is {decision_value}"),
                        ),
                    }
                };
            let mut decision_evidence = vec![metrics_artifact.clone(), slo_artifact.clone()];
            if !telemetry_incidents.is_empty() {
                decision_evidence.push(write_device_release_evidence(
                    state_dir,
                    &exec_id,
                    &format!("metrics_eval_{idx}_telemetry"),
                    &json!({
                        "telemetry_source": logical_name_from_path(&metrics_path),
                        "incident_classes": telemetry_incidents
                            .iter()
                            .map(|incident| incident.classification.clone())
                            .collect::<Vec<_>>(),
                    }),
                )?);
            }
            let (decision, _) = write_decision_record(
                state_dir,
                &format!("{exec_id}:metrics:{idx}"),
                &run_id,
                "device.release.metrics.eval",
                decision_outcome,
                vec![json!({
                    "code": reason_code,
                    "message": decision_message,
                })],
                decision_evidence,
                started_unix_ms,
                Some(idx),
                false,
            )?;
            push_decision(exec_doc, decision.clone(), None);
            {
                let meta = ensure_object_field(exec_doc, "meta");
                meta.insert(
                    "latest_metrics_snapshot".to_string(),
                    artifact_ref_min(Some(&metrics_artifact), None),
                );
                meta.insert(
                    "latest_slo_eval_report".to_string(),
                    artifact_ref_min(Some(&slo_artifact), None),
                );
                meta.insert(
                    "latest_eval_outcome".to_string(),
                    json!(device_release_eval_outcome(&decision_value)),
                );
                meta.insert(
                    "analysis_seq".to_string(),
                    json!(get_u64(&meta.clone().into(), &["analysis_seq"]).unwrap_or(0) + 1),
                );
                meta.insert(
                    "decision_count".to_string(),
                    json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
                );
                meta.insert("updated_unix_ms".to_string(), json!(started_unix_ms));
            }
            for incident in &telemetry_incidents {
                let _ = capture_device_release_incident_impl(
                    state_dir,
                    exec_doc,
                    &incident.reason,
                    &incident.classification,
                    &incident.source,
                    Some(&incident.native_context_patch),
                    None,
                    None,
                    None,
                    get_str(&decision, &["decision_id"]).as_deref(),
                    "not_applicable",
                    started_unix_ms,
                )?;
            }
            let mut status = "ok";
            if decision_value != "promote" {
                status = "error";
                let on_fail = device_release_step_outcome(step_doc);
                let next_status = match on_fail.as_str() {
                    "release.halt" => "aborted",
                    _ => "started",
                };
                let automation_state = match on_fail.as_str() {
                    "release.pause" => "paused",
                    "release.halt" => "stopped",
                    _ => "waiting_for_human",
                };
                let current_state = match on_fail.as_str() {
                    "release.pause" => "paused",
                    "release.halt" => "halted",
                    _ => "paused",
                };
                {
                    let meta = ensure_object_field(exec_doc, "meta");
                    meta.insert("automation_state".to_string(), json!(automation_state));
                    meta.insert("current_state".to_string(), json!(current_state));
                    meta.insert("next_step_idx".to_string(), json!(idx + 1));
                }
                ensure_object(exec_doc).insert("status".to_string(), json!(next_status));
                upsert_device_release_step(
                    exec_doc,
                    build_device_release_step(
                        idx,
                        &step_name,
                        &op,
                        status,
                        started_unix_ms,
                        Some(started_unix_ms),
                        vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                        device_release_current_percent(exec_doc),
                        device_release_store_release_id(exec_doc).as_deref(),
                        Some(&decision_value),
                    ),
                );
                let _ = capture_device_release_incident_impl(
                    state_dir,
                    exec_doc,
                    &format!("device release metrics decision is {decision_value}"),
                    "device_release_gate_failed",
                    "device_release",
                    None,
                    None,
                    None,
                    None,
                    get_str(&decision, &["decision_id"]).as_deref(),
                    "not_applicable",
                    started_unix_ms,
                )?;
                return Ok(());
            }
            ensure_object_field(exec_doc, "meta")
                .insert("automation_state".to_string(), json!("active"));
            ensure_object_field(exec_doc, "meta")
                .insert("next_step_idx".to_string(), json!(idx + 1));
            upsert_device_release_step(
                exec_doc,
                build_device_release_step(
                    idx,
                    &step_name,
                    &op,
                    status,
                    started_unix_ms,
                    Some(started_unix_ms),
                    vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                    device_release_current_percent(exec_doc),
                    device_release_store_release_id(exec_doc).as_deref(),
                    Some(&decision_value),
                ),
            );
            idx += 1;
            continue;
        }
        match apply_device_release_provider_op(
            state_dir,
            provider_doc,
            exec_doc,
            step_doc,
            &exec_id,
        ) {
            Ok(outcome) => {
                let evidence_doc = json!({
                    "provider_kind": get_str(provider_doc, &["provider_kind"]).unwrap_or_default(),
                    "provider_mode": device_release_provider_mode(provider_doc),
                    "op": op,
                    "state": outcome.current_state,
                    "rollout_percent": outcome.rollout_percent,
                    "store_release_id": outcome.store_release_id,
                    "provider": outcome.evidence,
                });
                let evidence = write_device_release_evidence(
                    state_dir,
                    &exec_id,
                    &format!("step_{idx}_{step_name}"),
                    &evidence_doc,
                )?;
                let (decision, _) = write_decision_record(
                    state_dir,
                    &format!("{exec_id}:{idx}:{step_name}"),
                    &run_id,
                    "device.release.step",
                    "allow",
                    vec![json!({
                        "code": "LP_DEVICE_RELEASE_STEP_OK",
                        "message": outcome.message,
                    })],
                    vec![evidence],
                    started_unix_ms,
                    Some(idx),
                    false,
                )?;
                push_decision(exec_doc, decision.clone(), None);
                let meta = ensure_object_field(exec_doc, "meta");
                meta.insert("current_state".to_string(), json!(outcome.current_state));
                meta.insert(
                    "current_rollout_percent".to_string(),
                    outcome
                        .rollout_percent
                        .map(Value::from)
                        .unwrap_or(Value::Null),
                );
                meta.insert(
                    "latest_store_release_id".to_string(),
                    outcome
                        .store_release_id
                        .as_ref()
                        .map(|value| Value::from(value.clone()))
                        .unwrap_or(Value::Null),
                );
                meta.insert("updated_unix_ms".to_string(), json!(started_unix_ms));
                meta.insert("automation_state".to_string(), json!("active"));
                meta.insert("next_step_idx".to_string(), json!(idx + 1));
                meta.insert(
                    "decision_count".to_string(),
                    json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
                );
                ensure_object(exec_doc).insert("status".to_string(), json!("started"));
                upsert_device_release_step(
                    exec_doc,
                    build_device_release_step(
                        idx,
                        &step_name,
                        &op,
                        "ok",
                        started_unix_ms,
                        Some(started_unix_ms),
                        vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                        outcome.rollout_percent,
                        outcome.store_release_id.as_deref(),
                        None,
                    ),
                );
            }
            Err(err) => {
                let (decision, _) = write_decision_record(
                    state_dir,
                    &format!("{exec_id}:{idx}:{step_name}:error"),
                    &run_id,
                    "device.release.step",
                    "error",
                    vec![json!({
                        "code": "LP_DEVICE_RELEASE_STEP_FAILED",
                        "message": err.to_string(),
                    })],
                    Vec::new(),
                    started_unix_ms,
                    Some(idx),
                    false,
                )?;
                push_decision(exec_doc, decision.clone(), None);
                let current_rollout_percent = device_release_current_percent(exec_doc);
                let meta = ensure_object_field(exec_doc, "meta");
                meta.insert("updated_unix_ms".to_string(), json!(started_unix_ms));
                meta.insert("current_state".to_string(), json!("paused"));
                meta.insert("automation_state".to_string(), json!("paused"));
                meta.insert("next_step_idx".to_string(), json!(idx + 1));
                meta.insert(
                    "decision_count".to_string(),
                    json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
                );
                upsert_device_release_step(
                    exec_doc,
                    build_device_release_step(
                        idx,
                        &step_name,
                        &op,
                        "error",
                        started_unix_ms,
                        Some(started_unix_ms),
                        vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
                        current_rollout_percent,
                        device_release_store_release_id(exec_doc).as_deref(),
                        None,
                    ),
                );
                ensure_object(exec_doc).insert("status".to_string(), json!("failed"));
                let _ = capture_device_release_incident_impl(
                    state_dir,
                    exec_doc,
                    &err.to_string(),
                    "device_release_provider_failed",
                    "device_release",
                    None,
                    None,
                    None,
                    None,
                    get_str(&decision, &["decision_id"]).as_deref(),
                    "not_applicable",
                    started_unix_ms,
                )?;
                return Ok(());
            }
        }
        idx += 1;
    }
    ensure_object(exec_doc).insert("status".to_string(), json!("completed"));
    let meta = ensure_object_field(exec_doc, "meta");
    meta.insert("automation_state".to_string(), json!("terminal"));
    meta.insert("next_step_idx".to_string(), json!(steps.len()));
    meta.insert(
        "updated_unix_ms".to_string(),
        json!(now_unix_ms + steps.len() as u64),
    );
    Ok(())
}

fn load_device_release_exec_docs(state_dir: &Path) -> Result<Vec<(PathBuf, Value)>> {
    let dir = device_release_root_dir(state_dir).join("executions");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut docs = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        docs.push((path.clone(), load_json(&path)?));
    }
    Ok(docs)
}

fn resolve_device_release_provider_doc(
    state_dir: &Path,
    plan_doc: &Value,
    override_path: Option<&str>,
) -> Result<Value> {
    if let Some(path) = override_path {
        return load_json(&repo_path(path));
    }
    let provider_id = get_str(plan_doc, &["provider_profile", "provider_id"])
        .ok_or_else(|| anyhow!("plan missing provider_profile.provider_id"))?;
    load_json(&device_release_provider_path(state_dir, &provider_id))
}

fn write_device_release_provider_copy(
    state_dir: &Path,
    provider_doc: &Value,
) -> Result<(PathBuf, Vec<u8>)> {
    let provider_id = get_str(provider_doc, &["provider_id"])
        .ok_or_else(|| anyhow!("provider profile missing provider_id"))?;
    let path = device_release_provider_path(state_dir, &provider_id);
    let bytes = write_json(&path, provider_doc)?;
    Ok((path, bytes))
}

fn write_device_release_package_copy(
    state_dir: &Path,
    package_manifest_path: &Path,
    package_doc: &Value,
) -> Result<(PathBuf, Vec<u8>)> {
    let bytes = canon_json_bytes(package_doc);
    let sha = sha256_hex(&bytes);
    let path = device_release_package_path(state_dir, &sha);
    let bytes = write_json(&path, package_doc)?;
    store_device_release_source_package(state_dir, package_manifest_path, package_doc, &sha)?;
    Ok((path, bytes))
}

fn store_device_release_source_package(
    state_dir: &Path,
    package_manifest_path: &Path,
    package_doc: &Value,
    sha256: &str,
) -> Result<()> {
    let manifest_dir = package_manifest_path
        .parent()
        .ok_or_else(|| anyhow!("package manifest parent directory is missing"))?;
    let source_root = device_release_source_package_dir(state_dir, sha256);
    remove_dir_if_exists(&source_root)?;
    copy_dir_recursive(manifest_dir, &source_root)?;
    let _ = write_json(
        &device_release_source_package_manifest_path(state_dir, sha256),
        package_doc,
    )?;
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("remove directory {}", path.display()))?;
    }
    Ok(())
}

fn copy_dir_recursive(src_dir: &Path, dst_dir: &Path) -> Result<()> {
    if !src_dir.is_dir() {
        bail!("copy source must be a directory: {}", src_dir.display());
    }
    for entry in WalkDir::new(src_dir) {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(src_dir).with_context(|| {
            format!("strip prefix {} from {}", src_dir.display(), path.display())
        })?;
        let dst = dst_dir.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&dst).with_context(|| format!("mkdir {}", dst.display()))?;
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        fs::copy(path, &dst)
            .with_context(|| format!("copy {} -> {}", path.display(), dst.display()))?;
    }
    Ok(())
}

struct StagedDevicePackage {
    manifest_path: PathBuf,
    manifest_bytes: Vec<u8>,
}

fn resolve_device_release_source_package(
    state_dir: &Path,
    plan_doc: &Value,
    package_manifest_override: Option<&str>,
) -> Result<(PathBuf, Value)> {
    if let Some(package_manifest) = package_manifest_override {
        let manifest_path = repo_path(package_manifest);
        let package_doc = load_json(&manifest_path)?;
        validate_device_package_manifest_doc(&package_doc)?;
        let _ = write_device_release_package_copy(state_dir, &manifest_path, &package_doc)?;
        return Ok((manifest_path, package_doc));
    }
    let sha256 = get_str(plan_doc, &["package", "digest", "sha256"])
        .ok_or_else(|| anyhow!("device release plan missing package.digest.sha256"))?;
    let manifest_path = device_release_source_package_manifest_path(state_dir, &sha256);
    if !manifest_path.exists() {
        bail!(
            "device release source package is missing from state; rerun release-create or pass --package-manifest"
        );
    }
    let package_doc = load_json(&manifest_path)?;
    validate_device_package_manifest_doc(&package_doc)?;
    Ok((manifest_path, package_doc))
}

fn device_release_staged_rollout_percent(provider_doc: &Value) -> Option<u64> {
    match (
        get_str(provider_doc, &["distribution_lane"]).as_deref(),
        get_str(provider_doc, &["provider_kind"]).as_deref(),
    ) {
        (Some("beta"), _) => Some(100),
        (Some("production"), Some("appstoreconnect_v1")) => None,
        (Some("production"), _) => Some(device_release_initial_percent(provider_doc)),
        _ => None,
    }
}

fn stage_device_release_package_for_exec(
    state_dir: &Path,
    exec_id: &str,
    plan_doc: &Value,
    provider_doc: &Value,
    package_manifest_path: &Path,
    package_doc: &Value,
) -> Result<StagedDevicePackage> {
    let source_sha = get_str(plan_doc, &["package", "digest", "sha256"])
        .ok_or_else(|| anyhow!("device release plan missing package.digest.sha256"))?;
    let source_root = device_release_source_package_dir(state_dir, &source_sha);
    if !source_root.exists() {
        bail!(
            "device release source package payload is missing from state: {}",
            source_root.display()
        );
    }
    let stage_root = device_release_staged_package_dir(state_dir, exec_id);
    remove_dir_if_exists(&stage_root)?;
    copy_dir_recursive(&source_root, &stage_root)?;
    let stage_manifest_path = device_release_staged_package_manifest_path(state_dir, exec_id);
    let mut stage_manifest_doc = package_doc.clone();
    let stage_telemetry_path = stage_manifest_path.parent().unwrap_or(&stage_root).join(
        get_str(&stage_manifest_doc, &["telemetry_profile", "path"])
            .ok_or_else(|| anyhow!("package manifest missing telemetry_profile.path"))?,
    );
    let telemetry_doc = load_json(&stage_telemetry_path)?;
    let patched_telemetry_doc = device_release_telemetry::patch_device_release_telemetry_profile(
        &telemetry_doc,
        device_release_telemetry::DeviceReleaseTelemetryProfilePatch {
            exec_id,
            plan_id: &get_str(plan_doc, &["plan_id"]).unwrap_or_default(),
            package_sha256: &source_sha,
            app_id: &get_str(plan_doc, &["app", "app_id"]).unwrap_or_default(),
            target: &get_str(provider_doc, &["target"]).unwrap_or_default(),
            provider_kind: &get_str(provider_doc, &["provider_kind"]).unwrap_or_default(),
            provider_lane: &get_str(provider_doc, &["distribution_lane"]).unwrap_or_default(),
            rollout_percent: device_release_staged_rollout_percent(provider_doc),
        },
    );
    let telemetry_bytes = write_json(&stage_telemetry_path, &patched_telemetry_doc)?;
    if let Some(telemetry_profile) = ensure_object(&mut stage_manifest_doc)
        .get_mut("telemetry_profile")
        .and_then(Value::as_object_mut)
    {
        telemetry_profile.insert("sha256".to_string(), json!(sha256_hex(&telemetry_bytes)));
        telemetry_profile.insert("bytes_len".to_string(), json!(telemetry_bytes.len() as u64));
    }
    let manifest_bytes = write_json(&stage_manifest_path, &stage_manifest_doc)?;
    let _ = write_json(
        &stage_root.join(
            package_manifest_path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("device.package.manifest.json"),
        ),
        &stage_manifest_doc,
    )?;
    Ok(StagedDevicePackage {
        manifest_path: stage_manifest_path,
        manifest_bytes,
    })
}

fn device_release_decision_ids(exec_doc: &Value) -> Vec<Value> {
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    for step in get_path(exec_doc, &["steps"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for decision_id in get_path(step, &["decisions"])
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(decision_id) = decision_id.as_str()
                && seen.insert(decision_id.to_string())
            {
                ids.push(json!(decision_id));
            }
        }
    }
    ids
}

fn build_device_release_query_result(exec_doc: &Value, exec_bytes: &[u8], view: &str) -> Value {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let artifacts = device_release_collect_artifacts(exec_doc);
    let latest_native_health_rollup = get_path(&meta, &["latest_native_health_rollup"])
        .cloned()
        .unwrap_or_else(|| device_release_native_health_rollup(exec_doc));
    let mut result = json!({
        "schema_version": DEVICE_RELEASE_QUERY_RESULT_KIND,
        "view": view,
        "exec_id": get_str(exec_doc, &["exec_id"]).unwrap_or_default(),
        "plan_id": get_str(exec_doc, &["plan_id"]).unwrap_or_default(),
        "provider_kind": get_str(&meta, &["provider_kind"]).unwrap_or_else(|| "mock_v1".to_string()),
        "distribution_lane": get_str(&meta, &["distribution_lane"]).unwrap_or_else(|| "beta".to_string()),
        "target": get_str(&meta, &["target"]).unwrap_or_else(|| "ios".to_string()),
        "status": get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
        "created_unix_ms": get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0),
        "updated_unix_ms": get_u64(&meta, &["updated_unix_ms"]).unwrap_or_else(|| get_u64(exec_doc, &["created_unix_ms"]).unwrap_or(0)),
        "app": get_path(&meta, &["app"]).cloned().unwrap_or_else(|| json!({
            "app_id": "unknown",
            "track_or_lane": "unknown",
            "version": "0.0.0",
            "build": "0"
        })),
        "current_state": get_str(&meta, &["current_state"]).unwrap_or_else(|| "draft".to_string()),
        "automation_state": get_str(&meta, &["automation_state"]).unwrap_or_else(|| "active".to_string()),
        "current_rollout_percent": get_path(&meta, &["current_rollout_percent"]).cloned().unwrap_or(Value::Null),
        "latest_decision_id": get_path(&meta, &["latest_decision_id"]).cloned().unwrap_or(Value::Null),
        "latest_signed_control_decision_id": get_path(&meta, &["latest_signed_control_decision_id"]).cloned().unwrap_or(Value::Null),
        "signature_status": get_str(&meta, &["signature_status"]).unwrap_or_else(|| "not_applicable".to_string()),
        "decision_count": get_u64(&meta, &["decision_count"]).unwrap_or(0),
        "provider_release_id": get_path(&meta, &["latest_store_release_id"]).cloned().unwrap_or(Value::Null),
        "latest_metrics_snapshot": get_path(&meta, &["latest_metrics_snapshot"]).cloned().unwrap_or_else(|| artifact_ref_min(latest_artifact_by_role(&artifacts, "metrics_snapshot").as_ref(), None)),
        "latest_slo_eval_report": get_path(&meta, &["latest_slo_eval_report"]).cloned().unwrap_or_else(|| artifact_ref_min(latest_artifact_by_role(&artifacts, "slo_eval_report").as_ref(), None)),
        "latest_eval_outcome": get_path(&meta, &["latest_eval_outcome"]).cloned().unwrap_or_else(|| json!("none")),
        "native_summary": get_path(&meta, &["native_summary"]).cloned().unwrap_or_else(|| get_path(exec_doc, &["native_summary"]).cloned().unwrap_or_else(|| json!({}))),
        "release_readiness": get_path(&meta, &["release_readiness"]).cloned().unwrap_or_else(|| get_path(exec_doc, &["release_readiness"]).cloned().unwrap_or_else(|| json!({}))),
        "native_validation_warnings": get_path(&meta, &["native_validation_warnings"]).cloned().unwrap_or_else(|| get_path(exec_doc, &["native_validation_warnings"]).cloned().unwrap_or_else(|| json!([]))),
        "native_validation_errors": get_path(&meta, &["native_validation_errors"]).cloned().unwrap_or_else(|| get_path(exec_doc, &["native_validation_errors"]).cloned().unwrap_or_else(|| json!([]))),
        "release_readiness_status": device_release_readiness_status(&meta),
        "latest_native_health_rollup": latest_native_health_rollup.clone(),
        "latest_native_incident_id": get_path(&latest_native_health_rollup, &["latest_native_incident_id"]).cloned().unwrap_or(Value::Null),
        "latest_regression_id": get_path(&latest_native_health_rollup, &["latest_regression_id"]).cloned().unwrap_or(Value::Null),
        "latest_regression_status": get_path(&latest_native_health_rollup, &["latest_regression_status"]).cloned().unwrap_or_else(|| json!("not_requested")),
        "linked_incidents": get_path(&meta, &["linked_incidents"]).cloned().unwrap_or_else(|| json!([])),
        "execution": {
            "kind": DEVICE_RELEASE_EXECUTION_KIND,
            "digest": digest_value(exec_bytes),
        },
        "index": {
            "used": false,
            "rebuilt": false,
            "db_path": "scan:none",
        }
    });
    match view {
        "timeline" => {
            ensure_object(&mut result).insert(
                "steps".to_string(),
                get_path(exec_doc, &["steps"])
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
        }
        "decisions" => {
            ensure_object(&mut result).insert(
                "decision_ids".to_string(),
                Value::Array(device_release_decision_ids(exec_doc)),
            );
            ensure_object(&mut result).insert(
                "steps".to_string(),
                get_path(exec_doc, &["steps"])
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
        }
        "full" => {
            ensure_object(&mut result).insert(
                "decision_ids".to_string(),
                Value::Array(device_release_decision_ids(exec_doc)),
            );
            ensure_object(&mut result).insert(
                "steps".to_string(),
                get_path(exec_doc, &["steps"])
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            ensure_object(&mut result).insert("meta".to_string(), meta);
        }
        _ => {}
    }
    result
}

fn device_release_list_item(exec_doc: &Value) -> Value {
    let meta = get_path(exec_doc, &["meta"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let latest_native_health_rollup = get_path(&meta, &["latest_native_health_rollup"])
        .cloned()
        .unwrap_or_else(|| device_release_native_health_rollup(exec_doc));
    json!({
        "exec_id": get_str(exec_doc, &["exec_id"]).unwrap_or_default(),
        "plan_id": get_str(exec_doc, &["plan_id"]).unwrap_or_default(),
        "provider_id": get_str(&meta, &["provider_id"]).unwrap_or_default(),
        "provider_kind": get_str(&meta, &["provider_kind"]).unwrap_or_else(|| "mock_v1".to_string()),
        "distribution_lane": get_str(&meta, &["distribution_lane"]).unwrap_or_else(|| "beta".to_string()),
        "target": get_str(&meta, &["target"]).unwrap_or_else(|| "ios".to_string()),
        "status": get_str(exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
        "current_state": get_str(&meta, &["current_state"]).unwrap_or_else(|| "draft".to_string()),
        "automation_state": get_str(&meta, &["automation_state"]).unwrap_or_else(|| "active".to_string()),
        "current_rollout_percent": get_path(&meta, &["current_rollout_percent"]).cloned().unwrap_or(Value::Null),
        "latest_eval_outcome": get_path(&meta, &["latest_eval_outcome"]).cloned().unwrap_or_else(|| json!("none")),
        "release_readiness_status": device_release_readiness_status(&meta),
        "native_summary": get_path(&meta, &["native_summary"]).cloned().unwrap_or_else(|| get_path(exec_doc, &["native_summary"]).cloned().unwrap_or_else(|| json!({}))),
        "latest_native_health_rollup": latest_native_health_rollup.clone(),
        "latest_native_incident_id": get_path(&latest_native_health_rollup, &["latest_native_incident_id"]).cloned().unwrap_or(Value::Null),
        "latest_regression_status": get_path(&latest_native_health_rollup, &["latest_regression_status"]).cloned().unwrap_or_else(|| json!("not_requested")),
        "app": get_path(&meta, &["app"]).cloned().unwrap_or_else(|| json!({})),
        "updated_unix_ms": get_u64(&meta, &["updated_unix_ms"]).unwrap_or(0),
    })
}

fn command_device_release_list(common: &CommonStateArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(common.state_dir.as_deref());
    let mut items = load_device_release_exec_docs(&state_dir)?
        .into_iter()
        .map(|(_, exec_doc)| device_release_list_item(&exec_doc))
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        let left_updated = left
            .get("updated_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let right_updated = right
            .get("updated_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        right_updated.cmp(&left_updated).then_with(|| {
            right
                .get("exec_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(
                    left.get("exec_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
        })
    });
    Ok(cli_report(
        "device release list",
        true,
        0,
        json!({
            "generated_unix_ms": now_ms(),
            "items": items,
        }),
        None,
        Vec::new(),
    ))
}

fn command_device_release_create(args: DeviceReleaseCreateArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let provider_profile_path = repo_path(&args.provider_profile);
    let package_manifest_path = repo_path(&args.package_manifest);
    let package_report_path = repo_path(&args.package_report);
    let out_path = repo_path(&args.out);
    let provider_doc = load_json(&provider_profile_path)?;
    let capabilities = validate_device_provider_profile_doc(&provider_doc)?;
    let package_doc = load_json(&package_manifest_path)?;
    validate_device_package_manifest_doc(&package_doc)?;
    let package_report_doc = load_json(&package_report_path)?;
    let package_report_kind = get_str(&package_report_doc, &["schema_version"]).unwrap_or_default();
    if package_report_kind != X07_WASM_DEVICE_PACKAGE_REPORT_KIND
        && package_report_kind != X07_WASM_DEVICE_PACKAGE_REPORT_KIND_LEGACY
    {
        bail!(
            "device package report must have schema_version={} or {}",
            X07_WASM_DEVICE_PACKAGE_REPORT_KIND,
            X07_WASM_DEVICE_PACKAGE_REPORT_KIND_LEGACY
        );
    }
    let (native_summary, release_readiness, native_validation_warnings, native_validation_errors) =
        device_native_release_metadata(
            &package_manifest_path,
            &package_doc,
            &provider_doc,
            &package_report_doc,
        )?;
    if !native_validation_errors.is_empty() {
        let diagnostics = native_validation_errors
            .iter()
            .map(|item| {
                result_diag(
                    &get_str(item, &["code"])
                        .unwrap_or_else(|| "LP_DEVICE_RELEASE_NATIVE_SUMMARY_INVALID".to_string()),
                    "run",
                    &get_str(item, &["message"])
                        .unwrap_or_else(|| "device release native readiness failed".to_string()),
                    "error",
                )
            })
            .collect::<Vec<_>>();
        return Ok(cli_report(
            "device release create",
            false,
            10,
            json!({
                "native_summary": native_summary,
                "release_readiness": release_readiness,
                "native_validation_warnings": native_validation_warnings,
                "native_validation_errors": native_validation_errors,
            }),
            None,
            diagnostics,
        ));
    }
    let slo_profile_ref = if let Some(slo_profile) = args.slo_profile.as_deref() {
        let slo_doc = load_json(&repo_path(slo_profile))?;
        let (_, slo_bytes) = write_device_release_slo_profile_copy(&state_dir, &slo_doc)?;
        Some(json!({
            "kind": "x07.slo.profile@0.1.0",
            "digest": digest_value(&slo_bytes),
            "label": logical_name_from_path(Path::new(slo_profile)),
        }))
    } else {
        None
    };
    let provider_target = get_str(&provider_doc, &["target"]).unwrap_or_default();
    if get_str(&package_doc, &["target"]).unwrap_or_default() != provider_target {
        bail!("provider target does not match package manifest target");
    }
    let (_, package_bytes) =
        write_device_release_package_copy(&state_dir, &package_manifest_path, &package_doc)?;
    let (_, provider_bytes) = write_device_release_provider_copy(&state_dir, &provider_doc)?;
    let package_report_bytes = canon_json_bytes(&package_report_doc);
    let package_report_digest = digest_value(&package_report_bytes);
    let package_report_sha = get_str(&package_report_digest, &["sha256"]).unwrap_or_default();
    let package_report_store_path = device_release_root_dir(&state_dir)
        .join("package_reports")
        .join(format!("{package_report_sha}.json"));
    let _ = write_json(&package_report_store_path, &package_report_doc)?;
    let (_, device_profile_doc) =
        load_device_profile_from_package_manifest(&package_manifest_path, &package_doc)?;
    let provider_id = get_str(&provider_doc, &["provider_id"]).unwrap_or_default();
    let package_digest = digest_value(&package_bytes);
    let app = json!({
        "app_id": get_str(&device_profile_doc, &["identity", "app_id"]).unwrap_or_else(|| "unknown".to_string()),
        "track_or_lane": get_str(&provider_doc, &["track"]).unwrap_or_else(|| {
            get_str(&provider_doc, &["distribution_lane"]).unwrap_or_else(|| "beta".to_string())
        }),
        "version": string_or_number(&device_profile_doc, &["version", "version"]).unwrap_or_else(|| "0.0.0".to_string()),
        "build": string_or_number(&device_profile_doc, &["version", "build"]).unwrap_or_else(|| "0".to_string()),
    });
    let mut steps = default_device_release_steps(&provider_doc);
    if let Some(thresholds) = slo_profile_ref.clone() {
        steps.push(json!({
            "id": "metrics_eval",
            "op": "metrics.eval",
            "window_seconds": args.metrics_window_seconds.unwrap_or(900),
            "thresholds": thresholds,
            "on_fail": args
                .metrics_on_fail
                .clone()
                .unwrap_or_else(|| "release.pause".to_string()),
        }));
    }
    let plan_seed = json!({
        "created_unix_ms": now_unix_ms,
        "provider_id": provider_id,
        "provider_kind": get_str(&provider_doc, &["provider_kind"]).unwrap_or_default(),
        "distribution_lane": get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default(),
        "target": provider_target,
        "app": app,
        "package_digest": package_digest,
        "package_report_digest": package_report_digest,
        "native_summary": native_summary,
        "release_readiness": release_readiness,
        "native_validation_warnings": native_validation_warnings,
        "native_validation_errors": native_validation_errors,
        "slo_profile_ref": slo_profile_ref,
        "steps": steps,
    });
    let plan_id = gen_id(
        "lpdrplan",
        &String::from_utf8_lossy(&canon_json_bytes(&plan_seed)),
    );
    let plan_doc = json!({
        "schema_version": DEVICE_RELEASE_PLAN_KIND,
        "plan_id": plan_id,
        "created_unix_ms": now_unix_ms,
        "provider_profile": {
            "kind": DEVICE_STORE_PROVIDER_PROFILE_KIND,
            "digest": digest_value(&provider_bytes),
            "provider_id": provider_id,
        },
        "target": provider_target,
        "app": app,
        "package": {
            "kind": DEVICE_PACKAGE_MANIFEST_KIND,
            "digest": digest_value(&package_bytes),
            "label": logical_name_from_path(&package_manifest_path),
        },
        "package_report": {
            "kind": package_report_kind,
            "digest": package_report_digest,
            "label": logical_name_from_path(&package_report_path),
            "store_uri": format!("file:{}", package_report_store_path.display()),
        },
        "native_summary": native_summary,
        "release_readiness": release_readiness,
        "native_validation_warnings": native_validation_warnings,
        "native_validation_errors": native_validation_errors,
        "strategy": {
            "max_auto_steps": 16,
            "max_total_wait_seconds": 3600,
            "on_provider_error": "pause",
        },
        "steps": steps,
    });
    let _ = validate_device_release_plan_doc(&plan_doc, &provider_doc)?;
    let _ = write_json(&out_path, &plan_doc)?;
    let _ = write_json(
        &device_release_plan_path(
            &state_dir,
            &get_str(&plan_doc, &["plan_id"]).unwrap_or_default(),
        ),
        &plan_doc,
    )?;
    Ok(cli_report(
        "device release create",
        true,
        0,
        json!({
            "plan_id": get_str(&plan_doc, &["plan_id"]).unwrap_or_default(),
            "out": out_path.to_string_lossy(),
            "provider_kind": get_str(&provider_doc, &["provider_kind"]).unwrap_or_default(),
            "distribution_lane": get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default(),
            "target": get_str(&provider_doc, &["target"]).unwrap_or_default(),
            "app": get_path(&plan_doc, &["app"]).cloned().unwrap_or_else(|| json!({})),
            "capabilities": capabilities,
            "package_report": get_path(&plan_doc, &["package_report"]).cloned().unwrap_or(Value::Null),
            "native_summary": get_path(&plan_doc, &["native_summary"]).cloned().unwrap_or_else(|| json!({})),
            "release_readiness": get_path(&plan_doc, &["release_readiness"]).cloned().unwrap_or_else(|| json!({})),
            "native_validation_warnings": get_path(&plan_doc, &["native_validation_warnings"]).cloned().unwrap_or_else(|| json!([])),
            "native_validation_errors": get_path(&plan_doc, &["native_validation_errors"]).cloned().unwrap_or_else(|| json!([])),
        }),
        None,
        Vec::new(),
    ))
}

fn command_device_release_validate(args: DeviceReleaseValidateArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let plan_doc = load_json(&repo_path(&args.plan))?;
    let provider_doc = resolve_device_release_provider_doc(
        &state_dir,
        &plan_doc,
        args.provider_profile.as_deref(),
    )?;
    let capabilities = match validate_device_release_plan_doc(&plan_doc, &provider_doc) {
        Ok(value) => value,
        Err(err) => {
            return Ok(cli_report(
                "device release validate",
                false,
                10,
                json!({
                    "plan_id": get_str(&plan_doc, &["plan_id"]).unwrap_or_default(),
                    "provider_kind": get_str(&provider_doc, &["provider_kind"]).unwrap_or_default(),
                    "distribution_lane": get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default(),
                    "target": get_str(&provider_doc, &["target"]).unwrap_or_default(),
                    "package_report": get_path(&plan_doc, &["package_report"]).cloned().unwrap_or(Value::Null),
                    "native_summary": get_path(&plan_doc, &["native_summary"]).cloned().unwrap_or_else(|| json!({})),
                    "release_readiness": get_path(&plan_doc, &["release_readiness"]).cloned().unwrap_or_else(|| json!({})),
                    "native_validation_warnings": get_path(&plan_doc, &["native_validation_warnings"]).cloned().unwrap_or_else(|| json!([])),
                    "native_validation_errors": get_path(&plan_doc, &["native_validation_errors"]).cloned().unwrap_or_else(|| json!([])),
                }),
                None,
                vec![result_diag(
                    "LP_DEVICE_RELEASE_PLAN_INVALID",
                    "parse",
                    &err.to_string(),
                    "error",
                )],
            ));
        }
    };
    Ok(cli_report(
        "device release validate",
        true,
        0,
        json!({
            "plan_id": get_str(&plan_doc, &["plan_id"]).unwrap_or_default(),
            "provider_kind": get_str(&provider_doc, &["provider_kind"]).unwrap_or_default(),
            "distribution_lane": get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default(),
            "target": get_str(&provider_doc, &["target"]).unwrap_or_default(),
            "capabilities": capabilities,
            "package_report": get_path(&plan_doc, &["package_report"]).cloned().unwrap_or(Value::Null),
            "native_summary": get_path(&plan_doc, &["native_summary"]).cloned().unwrap_or_else(|| json!({})),
            "release_readiness": get_path(&plan_doc, &["release_readiness"]).cloned().unwrap_or_else(|| json!({})),
            "native_validation_warnings": get_path(&plan_doc, &["native_validation_warnings"]).cloned().unwrap_or_else(|| json!([])),
            "native_validation_errors": get_path(&plan_doc, &["native_validation_errors"]).cloned().unwrap_or_else(|| json!([])),
        }),
        None,
        Vec::new(),
    ))
}

fn command_device_release_run(args: DeviceReleaseRunArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let plan_path = repo_path(&args.plan);
    let plan_doc = load_json(&plan_path)?;
    let provider_doc = resolve_device_release_provider_doc(
        &state_dir,
        &plan_doc,
        args.provider_profile.as_deref(),
    )?;
    let capabilities = match validate_device_release_plan_doc(&plan_doc, &provider_doc) {
        Ok(value) => value,
        Err(err) => {
            return Ok(cli_report(
                "device release run",
                false,
                10,
                json!({}),
                None,
                vec![result_diag(
                    "LP_DEVICE_RELEASE_PLAN_INVALID",
                    "parse",
                    &err.to_string(),
                    "error",
                )],
            ));
        }
    };
    let (source_package_manifest_path, source_package_doc) = resolve_device_release_source_package(
        &state_dir,
        &plan_doc,
        args.package_manifest.as_deref(),
    )?;
    let _ = write_device_release_provider_copy(&state_dir, &provider_doc)?;
    let plan_store_bytes = write_json(
        &device_release_plan_path(
            &state_dir,
            &get_str(&plan_doc, &["plan_id"]).unwrap_or_default(),
        ),
        &plan_doc,
    )?;
    let plan_id = get_str(&plan_doc, &["plan_id"]).unwrap_or_default();
    let (run_id, exec_id) = allocate_device_release_run_and_exec_ids(
        &state_dir,
        &format!("{plan_id}:{now_unix_ms}"),
        now_unix_ms,
    );
    let staged_package = stage_device_release_package_for_exec(
        &state_dir,
        &exec_id,
        &plan_doc,
        &provider_doc,
        &source_package_manifest_path,
        &source_package_doc,
    )?;
    let staged_manifest_rel = staged_package
        .manifest_path
        .strip_prefix(&state_dir)
        .unwrap_or(&staged_package.manifest_path)
        .to_string_lossy()
        .replace('\\', "/");
    let staged_package_artifact = named_file_artifact(
        &staged_manifest_rel,
        DEVICE_PACKAGE_MANIFEST_KIND,
        "application/json",
        &staged_package.manifest_bytes,
    );
    let mut exec_meta = Map::new();
    exec_meta.insert(
        "provider_id".to_string(),
        json!(get_str(&provider_doc, &["provider_id"]).unwrap_or_default()),
    );
    exec_meta.insert(
        "provider_kind".to_string(),
        json!(get_str(&provider_doc, &["provider_kind"]).unwrap_or_default()),
    );
    exec_meta.insert(
        "distribution_lane".to_string(),
        json!(get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default()),
    );
    exec_meta.insert(
        "target".to_string(),
        json!(get_str(&provider_doc, &["target"]).unwrap_or_default()),
    );
    exec_meta.insert(
        "package_digest".to_string(),
        get_path(&plan_doc, &["package", "digest"])
            .cloned()
            .unwrap_or_else(|| json!({"sha256":"", "bytes_len":0})),
    );
    exec_meta.insert(
        "package_report".to_string(),
        get_path(&plan_doc, &["package_report"])
            .cloned()
            .unwrap_or(Value::Null),
    );
    exec_meta.insert("current_state".to_string(), json!("draft"));
    exec_meta.insert("current_rollout_percent".to_string(), Value::Null);
    exec_meta.insert("latest_store_release_id".to_string(), Value::Null);
    exec_meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    exec_meta.insert("latest_decision_id".to_string(), Value::Null);
    exec_meta.insert("latest_signed_control_decision_id".to_string(), Value::Null);
    exec_meta.insert("decision_count".to_string(), json!(0));
    exec_meta.insert("signature_status".to_string(), json!("not_applicable"));
    exec_meta.insert("automation_state".to_string(), json!("active"));
    exec_meta.insert("next_step_idx".to_string(), json!(0));
    exec_meta.insert("parent_exec_id".to_string(), Value::Null);
    exec_meta.insert("rerun_from_step_idx".to_string(), Value::Null);
    exec_meta.insert("latest_metrics_snapshot".to_string(), Value::Null);
    exec_meta.insert("latest_slo_eval_report".to_string(), Value::Null);
    exec_meta.insert("latest_eval_outcome".to_string(), json!("none"));
    exec_meta.insert("linked_incidents".to_string(), json!([]));
    exec_meta.insert(
        "latest_native_health_rollup".to_string(),
        default_device_release_native_health_rollup(),
    );
    exec_meta.insert("artifacts".to_string(), json!([]));
    exec_meta.insert("decisions".to_string(), json!([]));
    exec_meta.insert(
        "app".to_string(),
        get_path(&plan_doc, &["app"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    exec_meta.insert("capabilities".to_string(), capabilities);
    exec_meta.insert(
        "native_summary".to_string(),
        get_path(&plan_doc, &["native_summary"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    exec_meta.insert(
        "release_readiness".to_string(),
        get_path(&plan_doc, &["release_readiness"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    exec_meta.insert(
        "native_validation_warnings".to_string(),
        get_path(&plan_doc, &["native_validation_warnings"])
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    exec_meta.insert(
        "native_validation_errors".to_string(),
        get_path(&plan_doc, &["native_validation_errors"])
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    exec_meta.insert(
        "source_package_manifest_path".to_string(),
        json!(source_package_manifest_path.to_string_lossy()),
    );
    exec_meta.insert(
        "staged_package_manifest_path".to_string(),
        json!(staged_package.manifest_path.to_string_lossy()),
    );
    exec_meta.insert(
        "staged_package_root".to_string(),
        json!(device_release_staged_package_dir(&state_dir, &exec_id).to_string_lossy()),
    );
    let mut exec_doc = json!({
        "schema_version": DEVICE_RELEASE_EXECUTION_KIND,
        "exec_id": exec_id,
        "plan_id": plan_id,
        "run_id": run_id,
        "created_unix_ms": now_unix_ms,
        "status": "started",
        "plan": {
            "kind": DEVICE_RELEASE_PLAN_KIND,
            "digest": digest_value(&plan_store_bytes),
        },
        "steps": [],
        "meta": Value::Object(exec_meta),
    });
    push_artifact(
        &mut exec_doc,
        artifact_summary(
            "staged_package_manifest",
            &staged_package_artifact,
            0,
            Some(DEVICE_PACKAGE_MANIFEST_KIND),
        ),
    );
    advance_device_release_execution(
        &state_dir,
        &mut exec_doc,
        &plan_doc,
        &provider_doc,
        false,
        now_unix_ms,
    )?;
    let exec_bytes = save_device_release_exec(&state_dir, &exec_doc)?;
    let failed = matches!(get_str(&exec_doc, &["status"]).as_deref(), Some("failed"));
    Ok(cli_report(
        "device release run",
        !failed,
        if failed { 18 } else { 0 },
        json!({
            "schema_version": DEVICE_RELEASE_RUN_RESULT_KIND,
            "exec_id": get_str(&exec_doc, &["exec_id"]).unwrap_or_default(),
            "plan_id": get_str(&exec_doc, &["plan_id"]).unwrap_or_default(),
            "provider_kind": get_str(&provider_doc, &["provider_kind"]).unwrap_or_default(),
            "target": get_str(&provider_doc, &["target"]).unwrap_or_default(),
            "status": get_str(&exec_doc, &["status"]).unwrap_or_else(|| "planned".to_string()),
            "decision_count": get_u64(&exec_doc, &["meta", "decision_count"]).unwrap_or(0),
            "package_report": get_path(&exec_doc, &["meta", "package_report"]).cloned().unwrap_or(Value::Null),
            "native_summary": get_path(&exec_doc, &["meta", "native_summary"]).cloned().unwrap_or_else(|| json!({})),
            "release_readiness": get_path(&exec_doc, &["meta", "release_readiness"]).cloned().unwrap_or_else(|| json!({})),
            "latest_native_health_rollup": get_path(&exec_doc, &["meta", "latest_native_health_rollup"]).cloned().unwrap_or_else(|| json!({})),
            "execution": {
                "kind": DEVICE_RELEASE_EXECUTION_KIND,
                "digest": digest_value(&exec_bytes),
            },
            "run_id": get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
        }),
        get_str(&exec_doc, &["run_id"]).as_deref(),
        if failed {
            vec![result_diag(
                "LP_DEVICE_RELEASE_RUN_FAILED",
                "run",
                "device release execution failed",
                "error",
            )]
        } else {
            Vec::new()
        },
    ))
}

fn resolve_device_release_exec_id(
    state_dir: &Path,
    args: &DeviceReleaseQueryArgs,
) -> Result<Option<String>> {
    if let Some(exec_id) = args.release_exec_id.as_deref() {
        return Ok(Some(exec_id.to_string()));
    }
    if !args.latest {
        return Ok(None);
    }
    let mut best: Option<(u64, String)> = None;
    for (_, exec_doc) in load_device_release_exec_docs(state_dir)? {
        let meta = get_path(&exec_doc, &["meta"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(app_id) = args.app_id.as_deref()
            && get_str(&meta, &["app", "app_id"]).as_deref() != Some(app_id)
        {
            continue;
        }
        if let Some(provider_id) = args.provider_id.as_deref()
            && get_str(&meta, &["provider_id"]).as_deref() != Some(provider_id)
        {
            continue;
        }
        if let Some(lane) = args.distribution_lane.as_deref()
            && get_str(&meta, &["distribution_lane"]).as_deref() != Some(lane)
        {
            continue;
        }
        if let Some(target) = args.target.as_deref()
            && get_str(&meta, &["target"]).as_deref() != Some(target)
        {
            continue;
        }
        let updated = get_u64(&meta, &["updated_unix_ms"]).unwrap_or(0);
        let exec_id = get_str(&exec_doc, &["exec_id"]).unwrap_or_default();
        match &best {
            Some((best_updated, best_id))
                if *best_updated > updated || (*best_updated == updated && best_id >= &exec_id) => {
            }
            _ => best = Some((updated, exec_id)),
        }
    }
    Ok(best.map(|(_, exec_id)| exec_id))
}

fn command_device_release_query(args: DeviceReleaseQueryArgs) -> Result<Value> {
    if !VALID_DEVICE_RELEASE_QUERY_VIEWS.contains(&args.view.as_str()) {
        return Ok(cli_report(
            "device release query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_INVALID_ARGS",
                "parse",
                "device release query view must be one of summary|timeline|decisions|full",
                "error",
            )],
        ));
    }
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let Some(exec_id) = resolve_device_release_exec_id(&state_dir, &args)? else {
        return Ok(cli_report(
            "device release query",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_INVALID_ARGS",
                "parse",
                "query requires --release-id or --latest with filters",
                "error",
            )],
        ));
    };
    let exec_doc = load_device_release_exec(&state_dir, &exec_id)?;
    let exec_bytes = canon_json_bytes(&exec_doc);
    Ok(cli_report(
        "device release query",
        true,
        0,
        build_device_release_query_result(&exec_doc, &exec_bytes, &args.view),
        get_str(&exec_doc, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_device_release_observe(args: DeviceReleaseControlArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let mut exec_doc = load_device_release_exec(&state_dir, &args.release_exec_id)?;
    ensure_device_release_meta_defaults(&mut exec_doc);
    let plan_id = get_str(&exec_doc, &["plan_id"]).ok_or_else(|| anyhow!("missing plan_id"))?;
    let plan_doc = load_json(&device_release_plan_path(&state_dir, &plan_id))?;
    let provider_doc = load_device_release_provider_for_exec(&state_dir, &exec_doc)?;
    let state_before = device_release_control_state_snapshot(&exec_doc);
    if get_str(&exec_doc, &["meta", "automation_state"]).as_deref() == Some("stopped") {
        return Ok(cli_report(
            "device release observe",
            false,
            18,
            json!({}),
            get_str(&exec_doc, &["run_id"]).as_deref(),
            vec![result_diag(
                "LP_DEVICE_RELEASE_STOPPED",
                "run",
                "device release automation was stopped",
                "error",
            )],
        ));
    }
    advance_device_release_execution(
        &state_dir,
        &mut exec_doc,
        &plan_doc,
        &provider_doc,
        true,
        now_unix_ms,
    )?;
    let exec_bytes = save_device_release_exec(&state_dir, &exec_doc)?;
    let exec_artifact = json!({
        "kind": DEVICE_RELEASE_EXECUTION_KIND,
        "digest": digest_value(&exec_bytes),
        "logical_name": format!("{}.json", args.release_exec_id),
        "media_type": "application/json",
        "store_uri": format!("file:{}", device_release_exec_path(&state_dir, &args.release_exec_id).display()),
    });
    let action_id = gen_id(
        "lpact",
        &format!("{}:observe:{now_unix_ms}", args.release_exec_id),
    );
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "{}:device.release.observe.manual:{now_unix_ms}",
            args.release_exec_id
        ),
        &get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
        "device.release.observe.manual",
        "allow",
        vec![json!({
            "code": "LP_DEVICE_RELEASE_OBSERVED",
            "message": args.reason,
        })],
        vec![exec_artifact],
        now_unix_ms,
        Some(device_release_next_step_idx(&exec_doc)),
        true,
    )?;
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert(
            "decision_count".to_string(),
            json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
        );
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert(
            "signature_status".to_string(),
            json!(signature_status.clone()),
        );
    }
    let _ = save_device_release_exec(&state_dir, &exec_doc)?;
    let result = build_control_action_result(
        &action_id,
        "device.release.observe.manual",
        "device_release",
        now_unix_ms,
        json!({ "release_exec_id": args.release_exec_id }),
        &args.reason,
        vec![get_str(&exec_doc, &["exec_id"]).unwrap_or_default()],
        None,
        Some(state_before),
        Some(device_release_control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    Ok(cli_report(
        "device release observe",
        true,
        0,
        result,
        get_str(&exec_doc, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_device_release_stop(args: DeviceReleaseControlArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let mut exec_doc = load_device_release_exec(&state_dir, &args.release_exec_id)?;
    ensure_device_release_meta_defaults(&mut exec_doc);
    let state_before = device_release_control_state_snapshot(&exec_doc);
    let action_id = gen_id(
        "lpact",
        &format!("{}:stop:{now_unix_ms}", args.release_exec_id),
    );
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "{}:device.release.stop.manual:{now_unix_ms}",
            args.release_exec_id
        ),
        &get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
        "device.release.stop.manual",
        "allow",
        vec![json!({
            "code": "LP_DEVICE_RELEASE_STOPPED",
            "message": args.reason,
        })],
        Vec::new(),
        now_unix_ms,
        Some(device_release_next_step_idx(&exec_doc)),
        true,
    )?;
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert("automation_state".to_string(), json!("stopped"));
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    }
    ensure_object(&mut exec_doc).insert("status".to_string(), json!("aborted"));
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert(
            "decision_count".to_string(),
            json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
        );
        meta.insert(
            "signature_status".to_string(),
            json!(signature_status.clone()),
        );
    }
    let _ = save_device_release_exec(&state_dir, &exec_doc)?;
    let result = build_control_action_result(
        &action_id,
        "device.release.stop.manual",
        "device_release",
        now_unix_ms,
        json!({ "release_exec_id": args.release_exec_id }),
        &args.reason,
        vec![get_str(&exec_doc, &["exec_id"]).unwrap_or_default()],
        None,
        Some(state_before),
        Some(device_release_control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    Ok(cli_report(
        "device release stop",
        true,
        0,
        result,
        get_str(&exec_doc, &["run_id"]).as_deref(),
        vec![result_diag(
            "LP_DEVICE_RELEASE_STOPPED",
            "run",
            "device release automation stopped",
            "info",
        )],
    ))
}

fn command_device_release_rerun(args: DeviceReleaseRerunArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let mut exec_doc = load_device_release_exec(&state_dir, &args.release_exec_id)?;
    ensure_device_release_meta_defaults(&mut exec_doc);
    let state_before = device_release_control_state_snapshot(&exec_doc);
    let plan_id = get_str(&exec_doc, &["plan_id"]).ok_or_else(|| anyhow!("missing plan_id"))?;
    let plan_doc = load_json(&device_release_plan_path(&state_dir, &plan_id))?;
    let provider_doc = load_device_release_provider_for_exec(&state_dir, &exec_doc)?;
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!(
            "{}:device.release.rerun.manual:{now_unix_ms}",
            args.release_exec_id
        ),
        &get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
        "device.release.rerun.manual",
        "allow",
        vec![json!({
            "code": "LP_DEVICE_RELEASE_RERUN",
            "message": args.reason,
        })],
        Vec::new(),
        now_unix_ms,
        Some(args.from_step.unwrap_or(0)),
        true,
    )?;
    push_decision(&mut exec_doc, decision.clone(), Some(&signature_status));
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert(
            "decision_count".to_string(),
            json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
        );
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert(
            "signature_status".to_string(),
            json!(signature_status.clone()),
        );
    }
    let _ = save_device_release_exec(&state_dir, &exec_doc)?;
    let from_step = args.from_step.unwrap_or(0);
    let (run_id, new_exec_id) = allocate_device_release_run_and_exec_ids(
        &state_dir,
        &format!(
            "{plan_id}:{now_unix_ms}:rerun:{}:{from_step}",
            args.release_exec_id
        ),
        now_unix_ms,
    );
    let plan_bytes = canon_json_bytes(&plan_doc);
    let (source_package_manifest_path, source_package_doc) =
        resolve_device_release_source_package(&state_dir, &plan_doc, None)?;
    let staged_package = stage_device_release_package_for_exec(
        &state_dir,
        &new_exec_id,
        &plan_doc,
        &provider_doc,
        &source_package_manifest_path,
        &source_package_doc,
    )?;
    let staged_manifest_rel = staged_package
        .manifest_path
        .strip_prefix(&state_dir)
        .unwrap_or(&staged_package.manifest_path)
        .to_string_lossy()
        .replace('\\', "/");
    let staged_package_artifact = named_file_artifact(
        &staged_manifest_rel,
        DEVICE_PACKAGE_MANIFEST_KIND,
        "application/json",
        &staged_package.manifest_bytes,
    );
    let mut new_exec_meta = Map::new();
    new_exec_meta.insert(
        "provider_id".to_string(),
        json!(get_str(&provider_doc, &["provider_id"]).unwrap_or_default()),
    );
    new_exec_meta.insert(
        "provider_kind".to_string(),
        json!(get_str(&provider_doc, &["provider_kind"]).unwrap_or_default()),
    );
    new_exec_meta.insert(
        "distribution_lane".to_string(),
        json!(get_str(&provider_doc, &["distribution_lane"]).unwrap_or_default()),
    );
    new_exec_meta.insert(
        "target".to_string(),
        json!(get_str(&provider_doc, &["target"]).unwrap_or_default()),
    );
    new_exec_meta.insert(
        "package_digest".to_string(),
        get_path(&plan_doc, &["package", "digest"])
            .cloned()
            .unwrap_or_else(|| json!({"sha256":"", "bytes_len":0})),
    );
    new_exec_meta.insert(
        "current_state".to_string(),
        get_path(&exec_doc, &["meta", "current_state"])
            .cloned()
            .unwrap_or_else(|| json!("draft")),
    );
    new_exec_meta.insert(
        "current_rollout_percent".to_string(),
        get_path(&exec_doc, &["meta", "current_rollout_percent"])
            .cloned()
            .unwrap_or(Value::Null),
    );
    new_exec_meta.insert(
        "latest_store_release_id".to_string(),
        get_path(&exec_doc, &["meta", "latest_store_release_id"])
            .cloned()
            .unwrap_or(Value::Null),
    );
    new_exec_meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    new_exec_meta.insert("latest_decision_id".to_string(), Value::Null);
    new_exec_meta.insert("latest_signed_control_decision_id".to_string(), Value::Null);
    new_exec_meta.insert("decision_count".to_string(), json!(0));
    new_exec_meta.insert("signature_status".to_string(), json!("not_applicable"));
    new_exec_meta.insert("automation_state".to_string(), json!("active"));
    new_exec_meta.insert("next_step_idx".to_string(), json!(from_step));
    new_exec_meta.insert("parent_exec_id".to_string(), json!(args.release_exec_id));
    new_exec_meta.insert("rerun_from_step_idx".to_string(), json!(from_step));
    new_exec_meta.insert("latest_metrics_snapshot".to_string(), Value::Null);
    new_exec_meta.insert("latest_slo_eval_report".to_string(), Value::Null);
    new_exec_meta.insert("latest_eval_outcome".to_string(), json!("none"));
    new_exec_meta.insert("linked_incidents".to_string(), json!([]));
    new_exec_meta.insert(
        "latest_native_health_rollup".to_string(),
        default_device_release_native_health_rollup(),
    );
    new_exec_meta.insert("artifacts".to_string(), json!([]));
    new_exec_meta.insert("decisions".to_string(), json!([]));
    new_exec_meta.insert(
        "app".to_string(),
        get_path(&plan_doc, &["app"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    new_exec_meta.insert(
        "capabilities".to_string(),
        get_path(&exec_doc, &["meta", "capabilities"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    new_exec_meta.insert(
        "package_report".to_string(),
        get_path(&plan_doc, &["package_report"])
            .cloned()
            .unwrap_or(Value::Null),
    );
    new_exec_meta.insert(
        "native_summary".to_string(),
        get_path(&plan_doc, &["native_summary"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    new_exec_meta.insert(
        "release_readiness".to_string(),
        get_path(&plan_doc, &["release_readiness"])
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    new_exec_meta.insert(
        "native_validation_warnings".to_string(),
        get_path(&plan_doc, &["native_validation_warnings"])
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    new_exec_meta.insert(
        "native_validation_errors".to_string(),
        get_path(&plan_doc, &["native_validation_errors"])
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    new_exec_meta.insert(
        "source_package_manifest_path".to_string(),
        json!(source_package_manifest_path.to_string_lossy()),
    );
    new_exec_meta.insert(
        "staged_package_manifest_path".to_string(),
        json!(staged_package.manifest_path.to_string_lossy()),
    );
    new_exec_meta.insert(
        "staged_package_root".to_string(),
        json!(device_release_staged_package_dir(&state_dir, &new_exec_id).to_string_lossy()),
    );
    let mut new_exec = json!({
        "schema_version": DEVICE_RELEASE_EXECUTION_KIND,
        "exec_id": new_exec_id,
        "plan_id": plan_id,
        "run_id": run_id,
        "created_unix_ms": now_unix_ms,
        "status": "started",
        "plan": {
            "kind": DEVICE_RELEASE_PLAN_KIND,
            "digest": digest_value(&plan_bytes),
        },
        "steps": [],
        "meta": Value::Object(new_exec_meta),
    });
    push_artifact(
        &mut new_exec,
        artifact_summary(
            "staged_package_manifest",
            &staged_package_artifact,
            0,
            Some(DEVICE_PACKAGE_MANIFEST_KIND),
        ),
    );
    advance_device_release_execution(
        &state_dir,
        &mut new_exec,
        &plan_doc,
        &provider_doc,
        false,
        now_unix_ms,
    )?;
    let _ = save_device_release_exec(&state_dir, &new_exec)?;
    let result = build_control_action_result(
        &gen_id(
            "lpact",
            &format!(
                "rerun:{}:{now_unix_ms}",
                get_str(&exec_doc, &["exec_id"]).unwrap_or_default()
            ),
        ),
        "device.release.rerun.manual",
        "device_release",
        now_unix_ms,
        json!({ "release_exec_id": get_str(&exec_doc, &["exec_id"]).unwrap_or_default() }),
        &args.reason,
        vec![get_str(&exec_doc, &["exec_id"]).unwrap_or_default()],
        Some(get_str(&new_exec, &["exec_id"]).unwrap_or_default()),
        Some(state_before),
        None,
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    Ok(cli_report(
        "device release rerun",
        true,
        0,
        result,
        get_str(&exec_doc, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn load_device_release_provider_for_exec(state_dir: &Path, exec_doc: &Value) -> Result<Value> {
    let provider_id = get_str(exec_doc, &["meta", "provider_id"])
        .ok_or_else(|| anyhow!("device release execution missing provider_id"))?;
    load_json(&device_release_provider_path(state_dir, &provider_id))
}

fn command_device_release_control(
    args: DeviceReleaseControlArgs,
    action: &str,
    action_kind: &str,
) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = device_release_now(&args.common);
    let mut exec_doc = load_device_release_exec(&state_dir, &args.release_exec_id)?;
    ensure_device_release_meta_defaults(&mut exec_doc);
    let provider_doc = load_device_release_provider_for_exec(&state_dir, &exec_doc)?;
    let state_before = device_release_control_state_snapshot(&exec_doc);
    let step_doc = match action {
        "pause" => json!({"id":"manual_pause","op":"release.pause"}),
        "resume" => json!({"id":"manual_resume","op":"release.resume"}),
        "complete" => json!({"id":"manual_complete","op":"release.complete"}),
        "rollback" => json!({"id":"manual_rollback","op":"rollback.previous"}),
        "halt" => json!({"id":"manual_halt","op":"release.pause"}),
        other => bail!("unsupported device release control action={other}"),
    };
    let outcome = if action == "halt" {
        device_release_provider::DeviceProviderStepOutcome {
            current_state: "halted".to_string(),
            rollout_percent: device_release_current_percent(&exec_doc),
            store_release_id: device_release_store_release_id(&exec_doc),
            message: "halted device release".to_string(),
            evidence: json!({ "provider_mode": "manual_halt" }),
        }
    } else {
        apply_device_release_provider_op(
            &state_dir,
            &provider_doc,
            &exec_doc,
            &step_doc,
            &args.release_exec_id,
        )?
    };
    let action_id = gen_id(
        "lpact",
        &format!("{}:{action}:{now_unix_ms}", args.release_exec_id),
    );
    let evidence = write_device_release_evidence(
        &state_dir,
        &args.release_exec_id,
        &format!("control_{action}"),
        &json!({
            "action": action,
            "provider_mode": device_release_provider_mode(&provider_doc),
            "state": outcome.current_state,
            "rollout_percent": outcome.rollout_percent,
            "store_release_id": outcome.store_release_id,
            "provider": outcome.evidence,
        }),
    )?;
    let (decision, signature_status) = write_decision_record(
        &state_dir,
        &format!("{}:{action}:{now_unix_ms}", args.release_exec_id),
        &get_str(&exec_doc, &["run_id"]).unwrap_or_default(),
        "device.release.control",
        "allow",
        vec![json!({
            "code": "LP_DEVICE_RELEASE_CONTROL_OK",
            "message": outcome.message,
        })],
        vec![evidence],
        now_unix_ms,
        Some(
            get_path(&exec_doc, &["steps"])
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0),
        ),
        true,
    )?;
    let meta = ensure_object_field(&mut exec_doc, "meta");
    meta.insert("current_state".to_string(), json!(outcome.current_state));
    meta.insert(
        "current_rollout_percent".to_string(),
        outcome
            .rollout_percent
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    meta.insert(
        "latest_store_release_id".to_string(),
        outcome
            .store_release_id
            .as_ref()
            .map(|value| Value::from(value.clone()))
            .unwrap_or(Value::Null),
    );
    meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
    meta.insert(
        "latest_decision_id".to_string(),
        json!(get_str(&decision, &["decision_id"]).unwrap_or_default()),
    );
    meta.insert(
        "latest_signed_control_decision_id".to_string(),
        json!(get_str(&decision, &["decision_id"]).unwrap_or_default()),
    );
    meta.insert(
        "signature_status".to_string(),
        json!(signature_status.clone()),
    );
    meta.insert(
        "decision_count".to_string(),
        json!(get_u64(&meta.clone().into(), &["decision_count"]).unwrap_or(0) + 1),
    );
    meta.insert(
        "automation_state".to_string(),
        json!(match action {
            "pause" => "paused",
            "halt" => "stopped",
            "complete" | "rollback" => "terminal",
            _ => "active",
        }),
    );
    let next_step_idx = get_path(&exec_doc, &["steps"])
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    ensure_array_field(&mut exec_doc, "steps").push(build_device_release_step(
        next_step_idx,
        &format!("manual_{action}"),
        action_kind,
        "ok",
        now_unix_ms,
        Some(now_unix_ms),
        vec![get_str(&decision, &["decision_id"]).unwrap_or_default()],
        outcome.rollout_percent,
        outcome.store_release_id.as_deref(),
        None,
    ));
    let status = match action {
        "complete" | "rollback" => "completed",
        "halt" => "aborted",
        _ => "started",
    };
    ensure_object(&mut exec_doc).insert("status".to_string(), json!(status));
    let exec_bytes = save_device_release_exec(&state_dir, &exec_doc)?;
    let result = build_control_action_result(
        &action_id,
        action_kind,
        "device_release",
        now_unix_ms,
        json!({ "release_exec_id": args.release_exec_id }),
        &args.reason,
        vec![get_str(&exec_doc, &["exec_id"]).unwrap_or_default()],
        None,
        Some(state_before),
        Some(device_release_control_state_snapshot(&exec_doc)),
        &decision,
        &signature_status,
    );
    record_control_action(&state_dir, &result)?;
    let _ = exec_bytes;
    Ok(cli_report(
        &format!("device release {action}"),
        true,
        0,
        result,
        get_str(&exec_doc, &["run_id"]).as_deref(),
        Vec::new(),
    ))
}

fn command_status(args: DeploymentStatusArgs) -> Result<Value> {
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_status(&args);
    }
    command_status_state(args)
}

fn command_status_state(args: DeploymentStatusArgs) -> Result<Value> {
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_query(&args);
    }
    command_query_state(args)
}

fn command_query_state(args: DeployQueryArgs) -> Result<Value> {
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_run(&args);
    }
    command_run_execution(args)
}

fn command_run_execution(args: DeployRunArgs) -> Result<Value> {
    if args.deployment_id.trim().is_empty() {
        return Ok(cli_report(
            "deploy run",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_DEPLOYMENT_REQUIRED",
                "run",
                "local deploy run requires --deployment",
                "error",
            )],
        ));
    }
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let pause_scale = args.pause_scale.unwrap_or(1.0);
    let metrics_dir = args.metrics_dir.as_deref().map(repo_path);
    let mut exec_doc = load_exec(&state_dir, &args.deployment_id)?;
    let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
    let run_doc = load_json(&run_path(&state_dir, &run_id))?;
    ensure_deploy_meta(&mut exec_doc, &run_doc, &state_dir)?;
    let remote_exec = get_path(&exec_doc, &["meta", "ext", "remote"]).is_some();
    let _remote_lease = match try_acquire_remote_run_lease(
        &state_dir,
        &exec_doc,
        &run_id,
        &args.deployment_id,
        now_unix_ms,
    )? {
        RemoteLeaseAcquire::NotNeeded => None,
        RemoteLeaseAcquire::Acquired(guard) => Some(guard),
        RemoteLeaseAcquire::Conflict(report) => return Ok(report),
    };
    let plan_path = resolve_plan_path(args.plan.as_deref());
    let (plan_doc, plan_bytes) = match plan_path {
        Some(path) => {
            let plan = normalize_plan(load_json(&path)?);
            let bytes = canon_json_bytes(&plan);
            (plan, bytes)
        }
        None => match generated_plan_from_accepted(&state_dir, &exec_doc, &run_doc) {
            Ok(result) => result,
            Err(err) => {
                return Ok(cli_report(
                    "deploy run",
                    false,
                    19,
                    json!({
                        "deployment_id": args.deployment_id,
                        "run_id": run_id,
                        "outcome": "failed",
                    }),
                    Some(&run_id),
                    vec![result_diag(
                        "LP_DEPLOY_PLAN_TOOL_FAILED",
                        "run",
                        &err.to_string(),
                        "error",
                    )],
                ));
            }
        },
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
    let initial_public_listener = if remote_exec {
        get_path(
            &exec_doc,
            &["meta", "ext", "remote", "target_profile", "base_url"],
        )
        .and_then(Value::as_str)
        .map(|base| remote_exec_public_listener(base, &args.deployment_id))
        .unwrap_or_else(|| deterministic_listener(&args.deployment_id))
    } else {
        deterministic_listener(&args.deployment_id)
    };
    {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert("updated_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert("started_unix_ms".to_string(), json!(now_unix_ms));
        meta.insert("control_state".to_string(), json!("active"));
        meta.insert(
            "public_listener".to_string(),
            json!(initial_public_listener),
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
    let remote_deployment = if remote_exec {
        let deployment = match prepare_remote_provider_deployment(
            &state_dir,
            &exec_doc,
            &run_doc,
            &stable_paths["work"],
            &candidate_paths["work"],
        ) {
            Ok(deployment) => deployment,
            Err(err) => {
                let _ = capture_incident_impl(
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
        };
        persist_remote_provider_deployment(&state_dir, &mut exec_doc, &deployment, now_unix_ms)?;
        let _ = record_remote_event(
            &state_dir,
            &args.deployment_id,
            "deploy.publish",
            "published OCI component and deployed stable/candidate revisions",
            json!({
                "component_ref": deployment.component_ref,
                "stable_app": deployment.stable.app_name,
                "candidate_app": deployment.candidate.app_name,
            }),
        );
        let _ = record_remote_log(
            &state_dir,
            &args.deployment_id,
            "info",
            "remote provider deployment completed",
            json!({
                "component_ref": deployment.component_ref,
                "public_listener": deployment.public_listener,
            }),
        );
        Some(deployment)
    } else {
        None
    };
    if remote_deployment.is_none() {
        let meta = ensure_object_field(&mut exec_doc, "meta");
        meta.insert(
            "runtime".to_string(),
            json!({
                "stable": {"status":"healthy","work_dir": stable_paths["work"].to_string_lossy()},
                "candidate": {"status":"healthy","work_dir": candidate_paths["work"].to_string_lossy()},
            }),
        );
    }
    let routing_meta = get_path(&exec_doc, &["meta", "routing"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let runtime_meta = get_path(&exec_doc, &["meta", "runtime"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let listener_addr = get_str(&exec_doc, &["meta", "public_listener"])
        .unwrap_or_else(|| deterministic_listener(&args.deployment_id));
    let stable_addr = get_str(&runtime_meta, &["stable", "bind_addr"])
        .map(|value| format!("http://{value}"))
        .unwrap_or_else(|| format!("{}/stable", listener_addr));
    let candidate_addr = get_str(&runtime_meta, &["candidate", "bind_addr"])
        .map(|value| format!("http://{value}"))
        .unwrap_or_else(|| format!("{}/candidate", listener_addr));
    let stable_work_dir = get_str(&runtime_meta, &["stable", "work_dir"])
        .unwrap_or_else(|| stable_paths["work"].to_string_lossy().into_owned());
    let candidate_work_dir = get_str(&runtime_meta, &["candidate", "work_dir"])
        .unwrap_or_else(|| candidate_paths["work"].to_string_lossy().into_owned());
    let api_prefix = get_str(&routing_meta, &["api_prefix"]).unwrap_or_else(|| "/api".to_string());
    write_router_state(
        &state_dir,
        &args.deployment_id,
        &listener_addr,
        &stable_addr,
        &candidate_addr,
        &stable_work_dir,
        &candidate_work_dir,
        &api_prefix,
        0,
        1,
    )?;
    let (ops_path, slo_path) = resolve_plan_inputs(&plan_doc);
    let runtime_probe_doc = if let Some(remote) = get_path(&exec_doc, &["meta", "ext", "remote"]) {
        run_remote_runtime_probe(&args.deployment_id, &candidate_paths["work"], remote)?
    } else {
        run_runtime_probe(
            &args.deployment_id,
            &candidate_paths["work"],
            ops_path.as_deref(),
        )?
    };
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
            let listener_addr = get_str(&exec_doc, &["meta", "public_listener"])
                .unwrap_or_else(|| deterministic_listener(&args.deployment_id));
            let runtime_meta = get_path(&exec_doc, &["meta", "runtime"])
                .cloned()
                .unwrap_or_else(|| json!({}));
            let routing_meta = get_path(&exec_doc, &["meta", "routing"])
                .cloned()
                .unwrap_or_else(|| json!({}));
            write_router_state(
                &state_dir,
                &args.deployment_id,
                &listener_addr,
                &get_str(&runtime_meta, &["stable", "bind_addr"])
                    .map(|value| format!("http://{value}"))
                    .unwrap_or_else(|| format!("{}/stable", listener_addr)),
                &get_str(&runtime_meta, &["candidate", "bind_addr"])
                    .map(|value| format!("http://{value}"))
                    .unwrap_or_else(|| format!("{}/candidate", listener_addr)),
                &get_str(&runtime_meta, &["stable", "work_dir"])
                    .unwrap_or_else(|| stable_paths["work"].to_string_lossy().into_owned()),
                &get_str(&runtime_meta, &["candidate", "work_dir"])
                    .unwrap_or_else(|| candidate_paths["work"].to_string_lossy().into_owned()),
                &get_str(&routing_meta, &["api_prefix"]).unwrap_or_else(|| "/api".to_string()),
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
            let remote_exec = get_path(&exec_doc, &["meta", "ext", "remote"]).is_some();
            loop {
                attempt += 1;
                analysis_counter += 1;
                let metrics_path = if remote_exec {
                    let metrics_doc = match generate_remote_metrics_snapshot(
                        &state_dir,
                        &exec_doc,
                        &run_doc,
                        analysis_counter,
                        args.fixture.as_deref(),
                    ) {
                        Ok(doc) => doc,
                        Err(err) => {
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
                                    &err.to_string(),
                                    "error",
                                )],
                            ));
                        }
                    };
                    let metrics_path = state_dir
                        .join(".x07lp")
                        .join("telemetry")
                        .join(&args.deployment_id)
                        .join(format!("analysis.{analysis_counter}.json"));
                    let _ = write_json(&metrics_path, &metrics_doc)?;
                    metrics_path
                } else {
                    let Some(metrics_path) = metrics_dir
                        .as_ref()
                        .map(|dir| dir.join(format!("analysis.{analysis_counter}.json")))
                    else {
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
                                "missing metrics directory",
                                "error",
                            )],
                        ));
                    };
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
                    metrics_path
                };
                let (decision_value, slo_report) = match run_slo_eval(
                    slo_path.as_deref(),
                    &metrics_path,
                ) {
                    Ok(result) => result,
                    Err(err) => {
                        return Ok(cli_report(
                            "deploy run",
                            false,
                            20,
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
                                "LP_SLO_TOOL_FAILED",
                                "run",
                                &err.to_string(),
                                "error",
                            )],
                        ));
                    }
                };
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
                    if remote_exec {
                        undeploy_remote_slot(&exec_doc, "candidate")?;
                        release_remote_slot_port(&state_dir, &args.deployment_id, "candidate");
                    }
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
    if remote_exec {
        undeploy_remote_slot(&exec_doc, "stable")?;
        release_remote_slot_port(&state_dir, &args.deployment_id, "stable");
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_control(
            args.target.as_deref(),
            "deploy stop",
            "LP_REMOTE_RUN_FAILED",
            format!("/v1/deployments/{}/stop", args.deployment_id),
            json!({ "reason": args.reason }),
        );
    }
    command_stop_execution(args)
}

fn command_stop_execution(args: DeploymentControlArgs) -> Result<Value> {
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
    if get_path(&exec_doc, &["meta", "ext", "remote"]).is_some() {
        undeploy_remote_slot(&exec_doc, "stable")?;
        undeploy_remote_slot(&exec_doc, "candidate")?;
        release_remote_slot_port(&state_dir, &args.deployment_id, "stable");
        release_remote_slot_port(&state_dir, &args.deployment_id, "candidate");
    }
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_control(
            args.target.as_deref(),
            "deploy rollback",
            "LP_REMOTE_RUN_FAILED",
            format!("/v1/deployments/{}/rollback", args.deployment_id),
            json!({ "reason": args.reason }),
        );
    }
    command_rollback_execution(args)
}

fn command_rollback_execution(args: DeploymentControlArgs) -> Result<Value> {
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
    if get_path(&exec_doc, &["meta", "ext", "remote"]).is_some() {
        undeploy_remote_slot(&exec_doc, "candidate")?;
        release_remote_slot_port(&state_dir, &args.deployment_id, "candidate");
    }
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_control(
            args.target.as_deref(),
            "deploy pause",
            "LP_REMOTE_RUN_FAILED",
            format!("/v1/deployments/{}/pause", args.deployment_id),
            json!({ "reason": args.reason }),
        );
    }
    command_pause_execution(args)
}

fn command_pause_execution(args: DeploymentControlArgs) -> Result<Value> {
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_control(
            args.target.as_deref(),
            "deploy rerun",
            "LP_REMOTE_RUN_FAILED",
            format!("/v1/deployments/{}/rerun", args.deployment_id),
            json!({ "reason": args.reason, "from_step": args.from_step.unwrap_or(0) }),
        );
    }
    command_rerun_execution(args)
}

fn command_rerun_execution(args: DeploymentRerunArgs) -> Result<Value> {
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
    let from_step = args.from_step.unwrap_or(0);

    let new_exec_id = gen_id(
        "lpexec",
        &format!("{}:rerun:{}:{now_unix_ms}", args.deployment_id, from_step),
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
        meta.insert("rerun_from_step_idx".to_string(), json!(from_step));
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_incident_capture(&args);
    }
    command_incident_capture_execution(args)
}

fn command_incident_capture_execution(args: IncidentCaptureArgs) -> Result<Value> {
    let state_dir = resolve_state_dir(args.common.state_dir.as_deref());
    let now_unix_ms = args.common.now_unix_ms.unwrap_or_else(now_ms);
    let selected =
        usize::from(args.deployment_id.is_some()) + usize::from(args.release_exec_id.is_some());
    if selected != 1 {
        return Ok(cli_report(
            "incident capture",
            false,
            2,
            json!({}),
            None,
            vec![result_diag(
                "LP_INVALID_ARGS",
                "parse",
                "incident capture requires exactly one of --deployment-id or --release-exec-id",
                "error",
            )],
        ));
    }
    let request_path = args.request.as_deref().map(repo_path);
    let response_path = args.response.as_deref().map(repo_path);
    let trace_path = args.trace.as_deref().map(repo_path);
    let (meta, bundle, incident_dir, run_id) =
        if let Some(release_exec_id) = args.release_exec_id.as_deref() {
            let mut exec_doc = load_device_release_exec(&state_dir, release_exec_id)?;
            let run_id = get_str(&exec_doc, &["run_id"]).unwrap_or_default();
            let latest_decision_id = get_str(&exec_doc, &["meta", "latest_decision_id"]);
            let (meta, bundle, incident_dir) = capture_device_release_incident_impl(
                &state_dir,
                &mut exec_doc,
                &args.reason,
                &args.classification,
                &args.source,
                None,
                request_path.as_deref(),
                response_path.as_deref(),
                trace_path.as_deref(),
                latest_decision_id.as_deref(),
                "not_applicable",
                now_unix_ms,
            )?;
            let _ = save_device_release_exec(&state_dir, &exec_doc)?;
            rebuild_indexes(&state_dir)?;
            (meta, bundle, incident_dir, run_id)
        } else {
            let deployment_id = args.deployment_id.as_deref().unwrap_or_default();
            let mut exec_doc = load_exec(&state_dir, deployment_id)?;
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
                request_path.as_deref(),
                response_path.as_deref(),
                trace_path.as_deref(),
                latest_decision_id.as_deref(),
                "not_applicable",
                now_unix_ms,
            )?;
            (meta, bundle, incident_dir, run_id)
        };
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_incident_get(&args);
    }
    command_incident_get_state(args)
}

fn command_incident_get_state(args: IncidentGetArgs) -> Result<Value> {
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
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_incident_list(&args);
    }
    command_incident_list_state(args)
}

fn command_incident_list_state(args: IncidentListArgs) -> Result<Value> {
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
        let matches_release = args
            .release_exec_id
            .as_ref()
            .map(|id| get_str(&meta, &["release_exec_id"]).as_deref() == Some(id.as_str()))
            .unwrap_or(true);
        let matches_classification = args
            .classification
            .as_ref()
            .map(|value| get_str(&meta, &["classification"]).as_deref() == Some(value.as_str()))
            .unwrap_or(true);
        let matches_native_classification = args
            .native_classification
            .as_ref()
            .map(|value| {
                get_str(&meta, &["native_classification"]).as_deref() == Some(value.as_str())
            })
            .unwrap_or(true);
        let matches_status = args
            .status
            .as_ref()
            .map(|value| get_str(&meta, &["incident_status"]).as_deref() == Some(value.as_str()))
            .unwrap_or(true);
        let matches_target_kind = args
            .target_kind
            .as_ref()
            .map(|value| get_str(&meta, &["target_kind"]).as_deref() == Some(value.as_str()))
            .unwrap_or(true);
        let matches_native_only = if args.native_only {
            get_str(&meta, &["native_classification"]).is_some()
        } else {
            true
        };
        if matches_target
            && matches_deployment
            && matches_release
            && matches_classification
            && matches_native_classification
            && matches_status
            && matches_target_kind
            && matches_native_only
        {
            items.push(incident_query_item(&meta, &bundle));
        }
    }
    items.sort_by_key(|item| std::cmp::Reverse(get_u64(item, &["captured_unix_ms"]).unwrap_or(0)));
    if let Some(limit) = args.limit {
        items.truncate(limit);
    }
    let resolution = if let Some(deployment_id) = args.deployment_id {
        json!({"by":"deployment_id","requested_deployment_id": deployment_id})
    } else if let Some(release_exec_id) = args.release_exec_id {
        json!({"by":"release_exec_id","requested_release_exec_id": release_exec_id})
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
            "schema_version": DEVICE_INCIDENT_QUERY_RESULT_KIND,
            "view": "list",
            "resolution": resolution,
            "index": { "used": true, "rebuilt": rebuilt, "db_path": db_path.to_string_lossy() },
            "items": items,
        }),
        run_id.as_deref(),
        Vec::new(),
    ))
}

fn incident_uses_device_regression(meta: &Value) -> bool {
    get_str(meta, &["release_exec_id"]).is_some() || !incident_release_ref(meta).is_null()
}

fn sync_device_release_incident_link(state_dir: &Path, meta: &Value, bundle: &Value) -> Result<()> {
    let Some(release_exec_id) = get_str(meta, &["release_exec_id"]) else {
        return Ok(());
    };
    let mut exec_doc = load_device_release_exec(state_dir, &release_exec_id)?;
    ensure_device_release_meta_defaults(&mut exec_doc);
    upsert_device_release_linked_incident(&mut exec_doc, meta, bundle);
    let _ = save_device_release_exec(state_dir, &exec_doc)?;
    Ok(())
}

fn incident_native_replay_hints(meta: &Value) -> Value {
    let native_context = get_path(meta, &["native_context"])
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut prelude = Vec::new();
    if let Some(state) = get_str(&native_context, &["lifecycle_state"]) {
        prelude.push(json!({ "kind": format!("lifecycle.{state}") }));
    }
    if let Some(state) = get_str(&native_context, &["connectivity_state"]) {
        prelude.push(json!({ "kind": format!("connectivity.{state}") }));
    }
    let native_sequence = get_path(&native_context, &["breadcrumbs"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|breadcrumb| {
            json!({
                "request_id": get_path(&breadcrumb, &["request_id"]).cloned().unwrap_or(Value::Null),
                "op": get_path(&breadcrumb, &["op"]).cloned().unwrap_or(Value::Null),
                "result": {
                    "status": get_path(&breadcrumb, &["status"]).cloned().unwrap_or(Value::Null),
                    "event_class": get_path(&breadcrumb, &["event_class"]).cloned().unwrap_or(Value::Null),
                    "duration_ms": get_path(&breadcrumb, &["duration_ms"]).cloned().unwrap_or(Value::Null),
                    "permission": get_path(&breadcrumb, &["permission"]).cloned().unwrap_or(Value::Null),
                },
            })
        })
        .collect::<Vec<_>>();
    let mut hints = serde_json::Map::new();
    hints.insert(
        "host_target".to_string(),
        json!(
            get_str(meta, &["target_kind"])
                .or_else(|| get_str(&native_context, &["platform"]))
                .unwrap_or_else(|| "unknown".to_string())
        ),
    );
    if !prelude.is_empty() {
        hints.insert("prelude".to_string(), Value::Array(prelude));
    }
    if !native_sequence.is_empty() {
        hints.insert("native_sequence".to_string(), Value::Array(native_sequence));
    }
    Value::Object(hints)
}

fn command_regress_from_incident(args: RegressFromIncidentArgs) -> Result<Value> {
    if remote_mode_selected(args.target.as_deref())? {
        return remote_command_regress_from_incident(&args);
    }
    command_regress_from_incident_state(args)
}

fn command_regress_from_incident_state(args: RegressFromIncidentArgs) -> Result<Value> {
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
    let regression_id = gen_id(
        "lprgr",
        &format!("{}:{}:{now_unix_ms}", args.incident_id, args.name),
    );
    let target_artifact = incident_target_artifact(&meta);
    let incident_artifact = json!({
        "kind": DEVICE_INCIDENT_BUNDLE_KIND,
        "digest": digest_value(&canon_json_bytes(&bundle)),
    });
    let use_device_regression = incident_uses_device_regression(&meta);
    let replay_target_kind = get_str(&meta, &["target_kind"])
        .or_else(|| get_str(&meta, &["device_release", "target_kind"]))
        .unwrap_or_else(|| "unknown".to_string());
    let request_doc = json!({
        "schema_version": REGRESSION_REQUEST_KIND,
        "regression_id": regression_id,
        "created_unix_ms": now_unix_ms,
        "incident": incident_artifact,
        "target_artifact": target_artifact,
        "replay_target_kind": replay_target_kind,
        "native_replay_hints": if use_device_regression {
            incident_native_replay_hints(&meta)
        } else {
            Value::Null
        },
        "invariants": if use_device_regression {
            json!(["device.trace.replay"])
        } else {
            json!(["app.trace.replay"])
        },
        "notes": format!("incident_id={} name={}", args.incident_id, args.name),
        "meta": {
            "incident_id": args.incident_id,
            "name": args.name,
            "out_dir": out_dir.to_string_lossy(),
            "dry_run": args.dry_run,
        },
    });
    let request_bytes = write_json(&incident_dir.join("regression.request.json"), &request_doc)?;
    let regression_request_artifact = named_file_artifact(
        &format!(
            "{}/regression.request.json",
            incident_store_prefix(&meta, &args.incident_id)
        ),
        REGRESSION_REQUEST_KIND,
        "application/json",
        &request_bytes,
    );
    let tool_command = if use_device_regression {
        "device regress from-incident"
    } else {
        "app regress from-incident"
    };
    let report: Value = {
        let mut argv = if use_device_regression {
            vec![
                "device".to_string(),
                "regress".to_string(),
                "from-incident".to_string(),
            ]
        } else {
            vec![
                "app".to_string(),
                "regress".to_string(),
                "from-incident".to_string(),
            ]
        };
        argv.push(incident_dir.to_string_lossy().into_owned());
        argv.push("--out-dir".to_string());
        argv.push(out_dir.to_string_lossy().into_owned());
        argv.push("--name".to_string());
        argv.push(args.name.clone());
        argv.push("--json".to_string());
        if args.dry_run {
            argv.push("--dry-run".to_string());
        }
        let (_tool, code, stdout, stderr) = run_wasm_tool_capture(&argv, Some(&root_dir()))?;
        if code == 0 {
            serde_json::from_slice(&stdout).context("parse regress report")?
        } else {
            let stderr_msg = String::from_utf8_lossy(&stderr).trim().to_string();
            let message = if stderr_msg.is_empty() {
                "wasm regression tool failed".to_string()
            } else {
                stderr_msg
            };
            {
                let meta_map = ensure_object(&mut meta);
                meta_map.insert("regression_status".to_string(), json!("failed"));
                meta_map.insert("regression_id".to_string(), json!(regression_id.clone()));
            }
            let _ = write_json(&incident_dir.join("incident.meta.local.json"), &meta)?;
            if use_device_regression {
                sync_device_release_incident_link(&state_dir, &meta, &bundle)?;
            }
            rebuild_indexes(&state_dir)?;
            return Ok(cli_report(
                "regress from-incident",
                false,
                i64::from(code.max(1)),
                json!({
                    "schema_version": REGRESSION_RUN_RESULT_KIND,
                    "created_unix_ms": now_unix_ms,
                    "incident_id": args.incident_id,
                    "regression_id": regression_id,
                    "ok": false,
                    "tool": { "name": "x07 wasm", "command": tool_command },
                    "replay_target_kind": replay_target_kind,
                    "replay_mode": if use_device_regression { "native_device" } else { "app_trace" },
                    "replay_synthesis_status": "failed",
                    "dry_run": args.dry_run,
                    "out_dir": out_dir.to_string_lossy(),
                    "incident_status_after": "failed",
                    "target_artifact": incident_target_artifact(&meta),
                    "request": regression_request_artifact.clone(),
                    "generated_trace_artifact_refs": [],
                    "generated_report_artifact_refs": [],
                    "generated": [],
                }),
                get_str(&meta, &["run_id"]).as_deref(),
                vec![result_diag(
                    "LP_REGRESSION_TOOL_FAILED",
                    "run",
                    &message,
                    "error",
                )],
            ));
        }
    };
    let report_path = incident_dir.join("regression.report.json");
    let report_bytes = write_json(&report_path, &report)?;
    let report_artifact = named_file_artifact(
        &format!(
            "{}/regression.report.json",
            incident_store_prefix(&meta, &args.incident_id)
        ),
        get_str(&report, &["schema_version"])
            .as_deref()
            .unwrap_or(if use_device_regression {
                X07_WASM_DEVICE_REGRESS_REPORT_KIND
            } else {
                "x07.wasm.app.regress.from_incident.report@0.1.0"
            }),
        "application/json",
        &report_bytes,
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
    let generated_trace_artifact_refs = generated
        .iter()
        .filter(|item| {
            get_str(item, &["role"])
                .map(|role| role.contains("trace"))
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    let generated_report_artifact_refs = if args.dry_run {
        Vec::new()
    } else {
        vec![report_artifact.clone()]
    };
    let regression_status = if args.dry_run {
        "requested"
    } else {
        "generated"
    };
    {
        let meta_map = ensure_object(&mut meta);
        meta_map.insert("regression_status".to_string(), json!(regression_status));
        meta_map.insert("regression_id".to_string(), json!(regression_id.clone()));
    }
    let _ = write_json(&incident_dir.join("incident.meta.local.json"), &meta)?;
    if use_device_regression {
        sync_device_release_incident_link(&state_dir, &meta, &bundle)?;
    }
    let regression_summary = json!({
        "schema_version": REGRESSION_RUN_RESULT_KIND,
        "created_unix_ms": now_unix_ms,
        "incident_id": args.incident_id,
        "regression_id": regression_id,
        "ok": true,
        "tool": { "name": "x07 wasm", "command": tool_command },
        "replay_target_kind": replay_target_kind,
        "replay_mode": if use_device_regression { "native_device" } else { "app_trace" },
        "replay_synthesis_status": regression_status,
        "dry_run": args.dry_run,
        "out_dir": out_dir.to_string_lossy(),
        "incident_status_after": regression_status,
        "target_artifact": incident_target_artifact(&meta),
        "request": regression_request_artifact,
        "report": report_artifact,
        "generated_trace_artifact_refs": generated_trace_artifact_refs,
        "generated_report_artifact_refs": generated_report_artifact_refs,
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
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

enum UiHttpResponse {
    Json(u16, Value),
    Bytes(u16, String, Vec<u8>),
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
        Ok(request) => match dispatch_http_request(request, state_dir) {
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
            write_http_response(&mut stream, status, &content_type, &body)
        }
    }
}

fn dispatch_http_request(request: HttpRequest, state_dir: &Path) -> Result<UiHttpResponse> {
    if request.path.starts_with("/v1/") {
        dispatch_remote_request(request, state_dir)
    } else {
        dispatch_ui_request(request, state_dir)
    }
}

fn remote_common_args(state_dir: &Path) -> CommonStateArgs {
    CommonStateArgs {
        state_dir: Some(state_dir.to_string_lossy().into_owned()),
        now_unix_ms: None,
        json: true,
    }
}

fn request_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(&name.to_ascii_lowercase())
        .map(String::as_str)
}

fn request_query_string(request: &HttpRequest, name: &str) -> Option<String> {
    request.query.get(name).cloned()
}

fn request_query_bool(request: &HttpRequest, name: &str, default: bool) -> bool {
    match request.query.get(name).map(|value| value.as_str()) {
        Some("1") | Some("true") | Some("yes") => true,
        Some("0") | Some("false") | Some("no") => false,
        Some(_) => default,
        None => default,
    }
}

fn request_query_usize(request: &HttpRequest, name: &str) -> Option<usize> {
    request
        .query
        .get(name)
        .and_then(|value| value.parse::<usize>().ok())
}

fn load_router_state_doc(state_dir: &Path, exec_id: &str) -> Result<Value> {
    load_json(&remote_router_state_path(state_dir, exec_id))
}

fn choose_edge_slot(router_state: &Value, request: &HttpRequest) -> &'static str {
    let weight = get_u64(router_state, &["candidate_weight_pct"])
        .unwrap_or(0)
        .min(100);
    if weight == 0 {
        return "stable";
    }
    if weight == 100 {
        return "candidate";
    }
    let route_key_header = get_str(router_state, &["route_key_header"])
        .unwrap_or_else(|| REMOTE_ROUTE_KEY_HEADER.to_string());
    let route_key = request_header(request, &route_key_header).unwrap_or(request.path.as_str());
    let digest = Sha256::digest(route_key.as_bytes());
    let bucket = u64::from(u32::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3],
    ])) % 100;
    if bucket < weight {
        "candidate"
    } else {
        "stable"
    }
}

fn bump_router_counter(state_dir: &Path, exec_id: &str, slot: &str) -> Result<()> {
    let path = state_dir
        .join(".x07lp")
        .join("router")
        .join(exec_id)
        .join("counters.json");
    let mut counters = if path.exists() {
        load_json(&path)?
    } else {
        json!({"stable_requests": 0, "candidate_requests": 0})
    };
    let key = if slot == "candidate" {
        "candidate_requests"
    } else {
        "stable_requests"
    };
    let current = get_u64(&counters, &[key]).unwrap_or(0);
    ensure_object(&mut counters).insert(key.to_string(), json!(current + 1));
    let _ = write_json(&path, &counters)?;
    Ok(())
}

fn strip_edge_exec_prefix(path: &str, exec_id: &str) -> String {
    let prefix = format!("{REMOTE_EDGE_ROUTE_PREFIX}/{exec_id}");
    let trimmed = path.strip_prefix(&prefix).unwrap_or(path);
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn pack_static_asset_response(work_dir: &Path, request_path: &str) -> Result<UiHttpResponse> {
    let manifest = load_json(&work_dir.join("app.pack.json"))?;
    let asset_path = if request_path == "/" || request_path.is_empty() {
        get_str(&manifest, &["frontend", "index_path"]).unwrap_or_else(|| "/index.html".to_string())
    } else {
        request_path.to_string()
    };
    if let Some(asset) = get_path(&manifest, &["assets"])
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find(|asset| {
                get_str(asset, &["serve_path"]).as_deref() == Some(asset_path.as_str())
            })
        })
    {
        let file_path =
            get_str(asset, &["file", "path"]).ok_or_else(|| anyhow!("asset missing file path"))?;
        let body = fs::read(work_dir.join(&file_path))?;
        let content_type = get_path(asset, &["headers"])
            .and_then(Value::as_array)
            .and_then(|headers| {
                headers.iter().find_map(|header| {
                    let name = get_str(header, &["k"])?;
                    if name.eq_ignore_ascii_case("content-type") {
                        get_str(header, &["v"])
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| media_type_for_http(&work_dir.join(&file_path)).to_string());
        return Ok(UiHttpResponse::Bytes(200, content_type, body));
    }
    if asset_path != "/index.html" {
        return pack_static_asset_response(work_dir, "/index.html");
    }
    Ok(UiHttpResponse::Json(
        404,
        cli_report(
            "edge",
            false,
            4,
            json!({}),
            None,
            vec![result_diag(
                "LP_HTTP_NOT_FOUND",
                "run",
                "edge asset not found",
                "error",
            )],
        ),
    ))
}

fn proxy_edge_request(
    request: &HttpRequest,
    upstream_base: &str,
    upstream_path: &str,
) -> Result<UiHttpResponse> {
    let mut url = format!(
        "{}{}",
        upstream_base.trim_end_matches('/'),
        if upstream_path.starts_with('/') {
            upstream_path.to_string()
        } else {
            format!("/{upstream_path}")
        }
    );
    if !request.query.is_empty() {
        let query = request
            .query
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        url.push('?');
        url.push_str(&query);
    }
    let mut upstream = remote_agent().request(&request.method, &url);
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "host" | "content-length" | "connection" | "accept-encoding"
        ) {
            continue;
        }
        upstream = upstream.set(name, value);
    }
    let response = if request.body.is_empty() {
        upstream.call()
    } else {
        upstream.send_bytes(&request.body)
    };
    match response {
        Ok(response) => {
            let status = response.status();
            let content_type = response
                .header("content-type")
                .unwrap_or("application/octet-stream")
                .to_string();
            let mut body = Vec::new();
            let mut reader = response.into_reader();
            reader.read_to_end(&mut body)?;
            Ok(UiHttpResponse::Bytes(status, content_type, body))
        }
        Err(UreqError::Status(status, response)) => {
            let content_type = response
                .header("content-type")
                .unwrap_or("application/octet-stream")
                .to_string();
            let mut body = Vec::new();
            let mut reader = response.into_reader();
            reader.read_to_end(&mut body)?;
            Ok(UiHttpResponse::Bytes(status, content_type, body))
        }
        Err(UreqError::Transport(err)) => Ok(UiHttpResponse::Json(
            500,
            cli_report(
                "edge",
                false,
                18,
                json!({}),
                None,
                vec![result_diag(
                    "LP_REMOTE_RUNTIME_PROBE_FAILED",
                    "run",
                    &format!("edge upstream request failed: {err}"),
                    "error",
                )],
            ),
        )),
    }
}

fn dispatch_edge_request(request: HttpRequest, state_dir: &Path) -> Result<UiHttpResponse> {
    let segments: Vec<&str> = request
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let Some(exec_id) = segments.get(1) else {
        return Ok(UiHttpResponse::Json(
            404,
            cli_report(
                "edge",
                false,
                4,
                json!({}),
                None,
                vec![result_diag(
                    "LP_HTTP_NOT_FOUND",
                    "run",
                    "edge execution route not found",
                    "error",
                )],
            ),
        ));
    };
    let router_state = load_router_state_doc(state_dir, exec_id)?;
    let slot = choose_edge_slot(&router_state, &request);
    let _ = bump_router_counter(state_dir, exec_id, slot);
    let rel_path = strip_edge_exec_prefix(&request.path, exec_id);
    let api_prefix = get_str(&router_state, &["api_prefix"]).unwrap_or_else(|| "/api".to_string());
    if rel_path == api_prefix || rel_path.starts_with(&(api_prefix.clone() + "/")) {
        let upstream_key = if slot == "candidate" {
            "candidate_addr"
        } else {
            "stable_addr"
        };
        let upstream = get_str(&router_state, &[upstream_key])
            .unwrap_or_else(|| "http://127.0.0.1:0".to_string());
        return proxy_edge_request(&request, &upstream, &rel_path);
    }
    let work_dir_key = if slot == "candidate" {
        "candidate_work_dir"
    } else {
        "stable_work_dir"
    };
    let work_dir = get_str(&router_state, &[work_dir_key])
        .ok_or_else(|| anyhow!("router state missing {work_dir_key}"))?;
    pack_static_asset_response(Path::new(&work_dir), &rel_path)
}

fn remote_accept_required_secrets(body_doc: &Value) -> Vec<String> {
    if let Some(items) = body_doc.get("required_secrets").and_then(Value::as_array) {
        let mut ids = BTreeSet::new();
        for item in items {
            if let Some(secret_id) = item.as_str() {
                let trimmed = secret_id.trim();
                if !trimmed.is_empty() {
                    ids.insert(trimmed.to_string());
                }
            }
        }
        return ids.into_iter().collect();
    }
    body_doc
        .get("capabilities")
        .map(required_secret_ids_from_capabilities_doc)
        .unwrap_or_default()
}

fn remote_fixture_name(raw: Option<&str>) -> Option<String> {
    remote_fixture_manifest::remote_fixture_name(raw)
}

fn resolve_remote_fixture_inputs(fixture: Option<&str>) -> (Option<String>, Option<String>) {
    remote_fixture_manifest::resolve_remote_fixture_inputs(fixture)
}

fn remote_accept_target_name(exec_doc: &Value) -> String {
    get_str(
        exec_doc,
        &["meta", "ext", "remote", "target_profile", "name"],
    )
    .or_else(|| {
        get_str(
            exec_doc,
            &["meta", "ext", "remote", "target_profile", "target_name"],
        )
    })
    .unwrap_or_else(|| "default".to_string())
}

fn nonempty_secret_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_remote_secret_value(
    store: &Value,
    exec_doc: &Value,
    target_name: &str,
    secret_id: &str,
) -> Option<(String, String)> {
    let app_id = get_str(exec_doc, &["meta", "target", "app_id"]).unwrap_or_default();
    let environment = get_str(exec_doc, &["meta", "target", "environment"]).unwrap_or_default();
    let mut candidates: Vec<(String, Vec<String>)> = Vec::new();
    if !app_id.is_empty() && !environment.is_empty() {
        candidates.push((
            format!("app_env:{app_id}/{environment}"),
            vec![
                "apps".to_string(),
                app_id.clone(),
                "envs".to_string(),
                environment.clone(),
                secret_id.to_string(),
            ],
        ));
        candidates.push((
            format!("app_env:{app_id}/{environment}"),
            vec![
                "apps".to_string(),
                app_id.clone(),
                "environments".to_string(),
                environment.clone(),
                secret_id.to_string(),
            ],
        ));
    }
    if !app_id.is_empty() {
        candidates.push((
            format!("app:{app_id}"),
            vec![
                "apps".to_string(),
                app_id.clone(),
                "defaults".to_string(),
                secret_id.to_string(),
            ],
        ));
        candidates.push((
            format!("app:{app_id}"),
            vec!["apps".to_string(), app_id.clone(), secret_id.to_string()],
        ));
    }
    if !environment.is_empty() {
        candidates.push((
            format!("env:{environment}"),
            vec![
                "envs".to_string(),
                environment.clone(),
                secret_id.to_string(),
            ],
        ));
        candidates.push((
            format!("env:{environment}"),
            vec![
                "environments".to_string(),
                environment.clone(),
                secret_id.to_string(),
            ],
        ));
    }
    candidates.push((
        format!("target:{target_name}"),
        vec![
            "targets".to_string(),
            target_name.to_string(),
            secret_id.to_string(),
        ],
    ));
    for (scope, path) in candidates {
        let path_refs = path.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some(value) = nonempty_secret_value(get_path(store, &path_refs)) {
            return Some((scope, value));
        }
    }
    None
}

fn validate_remote_accept_secrets(
    state_dir: &Path,
    exec_doc: &Value,
    body_doc: &Value,
) -> Result<Option<UiHttpResponse>> {
    let required_secrets = remote_accept_required_secrets(body_doc);
    if required_secrets.is_empty() {
        return Ok(None);
    }
    let target_name = remote_accept_target_name(exec_doc);
    let store = load_remote_secret_store(state_dir)?;
    let mut resolved_scopes = Vec::new();
    let missing: Vec<String> = required_secrets
        .iter()
        .filter(|secret_id| {
            match resolve_remote_secret_value(&store, exec_doc, &target_name, secret_id) {
                Some((scope, _value)) => {
                    resolved_scopes.push(json!({
                        "secret_id": secret_id,
                        "scope": scope,
                    }));
                    false
                }
                None => true,
            }
        })
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(None);
    }
    Ok(Some(UiHttpResponse::Json(
        200,
        cli_report(
            "deploy accept",
            false,
            13,
            json!({
                "op": "accept",
                "ok": false,
                "target": target_name,
                "required_secrets": required_secrets,
                "resolved_scopes": resolved_scopes,
                "missing_secrets": missing,
            }),
            None,
            vec![result_diag(
                "LP_REMOTE_SECRET_NOT_FOUND",
                "run",
                "referenced remote secret was not found",
                "error",
            )],
        ),
    )))
}

fn ensure_remote_authorized(request: &HttpRequest) -> Result<()> {
    let Some(authz) = request_header(request, "authorization") else {
        bail!("missing authorization header");
    };
    let token = authz
        .strip_prefix("Bearer ")
        .or_else(|| authz.strip_prefix("bearer "))
        .ok_or_else(|| anyhow!("unsupported authorization scheme"))?;
    if token.trim() != remote_server_token() {
        bail!("invalid bearer token");
    }
    Ok(())
}

fn remote_auth_failure(message: &str) -> UiHttpResponse {
    UiHttpResponse::Json(
        401,
        cli_report(
            "remote auth",
            false,
            41,
            json!({}),
            None,
            vec![result_diag(
                "LP_REMOTE_AUTH_FAILED",
                "run",
                message,
                "error",
            )],
        ),
    )
}

fn persist_remote_accept_docs(
    state_dir: &Path,
    run_doc: &Value,
    exec_doc: &Value,
    decision_doc: &Value,
    change_doc: Option<&Value>,
) -> Result<(String, String, String)> {
    let original_run_id = get_str(run_doc, &["run_id"]).ok_or_else(|| anyhow!("missing run_id"))?;
    let original_exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing exec_id"))?;
    let original_decision_id =
        get_str(decision_doc, &["decision_id"]).ok_or_else(|| anyhow!("missing decision_id"))?;
    let unique_seed = format!(
        "{}:{}:{}:{}",
        original_run_id,
        original_exec_id,
        original_decision_id,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    );
    let run_id = gen_id("lprun", &format!("remote_accept:{unique_seed}:run"));
    let exec_id = gen_id("lpexec", &format!("remote_accept:{unique_seed}:exec"));
    let decision_id = gen_id("lpdec", &format!("remote_accept:{unique_seed}:decision"));
    let replacements = BTreeMap::from([
        (original_run_id.clone(), run_id.clone()),
        (original_exec_id.clone(), exec_id.clone()),
        (original_decision_id.clone(), decision_id.clone()),
    ]);
    let mut rewritten_run = run_doc.clone();
    let mut rewritten_exec = exec_doc.clone();
    let mut rewritten_decision = decision_doc.clone();
    rewrite_remote_accept_ids(&mut rewritten_run, &replacements);
    rewrite_remote_accept_ids(&mut rewritten_exec, &replacements);
    rewrite_remote_accept_ids(&mut rewritten_decision, &replacements);
    let _ = write_json(&run_path(state_dir, &run_id), &rewritten_run)?;
    let _ = write_json(&exec_path(state_dir, &exec_id), &rewritten_exec)?;
    let _ = write_json(&decision_path(state_dir, &decision_id), &rewritten_decision)?;
    if let Some(change_doc) = change_doc
        && let Some(change_id) = get_str(change_doc, &["change_id"])
    {
        let _ = write_json(
            &state_dir.join("changes").join(format!("{change_id}.json")),
            change_doc,
        )?;
    }
    Ok((run_id, exec_id, decision_id))
}

fn rewrite_remote_accept_ids(value: &mut Value, replacements: &BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                rewrite_remote_accept_ids(child, replacements);
            }
        }
        Value::Array(items) => {
            for child in items {
                rewrite_remote_accept_ids(child, replacements);
            }
        }
        Value::String(text) => {
            let mut updated = text.clone();
            for (from, to) in replacements {
                if updated.contains(from) {
                    updated = updated.replace(from, to);
                }
            }
            *text = updated;
        }
        _ => {}
    }
}

fn materialize_remote_http_doc(
    state_dir: &Path,
    kind: &str,
    doc: Option<&Value>,
) -> Result<Option<String>> {
    let Some(doc) = doc else {
        return Ok(None);
    };
    let path =
        state_dir
            .join(".x07lp")
            .join("remote_http")
            .join(format!("{}-{}.json", kind, now_ms()));
    let _ = write_json(&path, doc)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

fn remote_stream_root(state_dir: &Path, kind: &str) -> PathBuf {
    state_dir.join(".x07lp").join("remote_streams").join(kind)
}

fn remote_stream_path(state_dir: &Path, kind: &str, exec_id: &str) -> PathBuf {
    remote_stream_root(state_dir, kind).join(format!("{exec_id}.jsonl"))
}

fn append_remote_stream_entry(
    state_dir: &Path,
    kind: &str,
    exec_id: &str,
    entry: &Value,
) -> Result<()> {
    let path = remote_stream_path(state_dir, kind, exec_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&canon_json_bytes(entry))?;
    file.write_all(b"\n")?;
    Ok(())
}

fn remote_stream_context(state_dir: &Path, exec_id: &str) -> (Option<String>, Option<String>) {
    let exec_doc = load_json(&exec_path(state_dir, exec_id)).ok();
    let run_id = exec_doc.as_ref().and_then(|doc| get_str(doc, &["run_id"]));
    let slot = exec_doc.as_ref().map(|doc| {
        let outcome = get_str(doc, &["meta", "outcome"]).unwrap_or_else(|| "unknown".to_string());
        if matches!(outcome.as_str(), "promoted" | "rolled_back") {
            "stable".to_string()
        } else {
            "candidate".to_string()
        }
    });
    (run_id, slot)
}

fn remote_stream_entry_id(
    prefix: &str,
    exec_id: &str,
    kind: &str,
    message: &str,
    emitted_unix_ms: u64,
) -> String {
    let material = format!("{prefix}:{exec_id}:{kind}:{emitted_unix_ms}:{message}");
    let digest = sha256_hex(material.as_bytes());
    format!("{prefix}_{}", &digest[..24])
}

fn remote_event_payload(message: &str, details: Value) -> Value {
    let mut payload = match details {
        Value::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("details".to_string(), other);
            map
        }
    };
    payload.insert("message".to_string(), json!(message));
    Value::Object(payload)
}

fn record_remote_event(
    state_dir: &Path,
    exec_id: &str,
    event_kind: &str,
    message: &str,
    details: Value,
) -> Result<()> {
    let emitted_unix_ms = now_ms();
    let (run_id, slot) = remote_stream_context(state_dir, exec_id);
    append_remote_stream_entry(
        state_dir,
        "events",
        exec_id,
        &json!({
            "event_id": remote_stream_entry_id("lpevt", exec_id, event_kind, message, emitted_unix_ms),
            "kind": event_kind,
            "exec_id": exec_id,
            "run_id": run_id,
            "slot": slot,
            "emitted_unix_ms": emitted_unix_ms,
            "data": remote_event_payload(message, details),
        }),
    )
}

fn record_remote_log(
    state_dir: &Path,
    exec_id: &str,
    level: &str,
    message: &str,
    fields: Value,
) -> Result<()> {
    let emitted_unix_ms = now_ms();
    let (run_id, slot) = remote_stream_context(state_dir, exec_id);
    append_remote_stream_entry(
        state_dir,
        "logs",
        exec_id,
        &json!({
            "log_id": remote_stream_entry_id("lplog", exec_id, level, message, emitted_unix_ms),
            "exec_id": exec_id,
            "run_id": run_id,
            "slot": slot,
            "level": level,
            "message": message,
            "emitted_unix_ms": emitted_unix_ms,
            "fields": fields,
        }),
    )
}

fn read_remote_stream_items(
    state_dir: &Path,
    kind: &str,
    exec_id: Option<&str>,
    slot: Option<&str>,
    cursor: Option<&str>,
    limit: usize,
) -> Result<(Vec<Value>, String, Option<String>)> {
    let root = remote_stream_root(state_dir, kind);
    let start = cursor
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut files = Vec::new();
    if let Some(exec_id) = exec_id {
        files.push(remote_stream_path(state_dir, kind, exec_id));
    } else if root.is_dir() {
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if entry.path().extension().and_then(OsStr::to_str) == Some("jsonl") {
                files.push(entry.path());
            }
        }
        files.sort();
    }
    let mut items = Vec::new();
    for path in files {
        if !path.exists() {
            continue;
        }
        let reader = BufReader::new(fs::File::open(path)?);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let item = serde_json::from_str::<Value>(&line).context("parse remote stream line")?;
            if let Some(slot) = slot
                && get_str(&item, &["slot"]).as_deref() != Some(slot)
            {
                continue;
            }
            items.push(item);
        }
    }
    let total = items.len();
    let end = total.min(start.saturating_add(limit.max(1)));
    let slice = if start >= total {
        Vec::new()
    } else {
        items[start..end].to_vec()
    };
    let next = (end < total).then(|| end.to_string());
    Ok((slice, start.to_string(), next))
}

fn dispatch_remote_request(request: HttpRequest, state_dir: &Path) -> Result<UiHttpResponse> {
    if request.path != "/v1/health" && ensure_remote_authorized(&request).is_err() {
        return Ok(remote_auth_failure(
            "remote api requires a valid bearer token",
        ));
    }
    let segments: Vec<&str> = request
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let common = remote_common_args(state_dir);
    let response = match (request.method.as_str(), segments.as_slice()) {
        ("GET", ["v1", "health"]) => UiHttpResponse::Json(
            200,
            json!({ "ok": true, "api_version": REMOTE_API_VERSION }),
        ),
        ("GET", ["v1", "capabilities"]) => {
            UiHttpResponse::Json(200, build_remote_capabilities_doc())
        }
        ("POST", ["v1", "artifacts", "cas", "presence"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let mut missing = Vec::new();
            let mut digests = Vec::new();
            if let Some(items) = body_doc.get("digests").and_then(Value::as_array) {
                for item in items {
                    if let Some(sha) = item.as_str() {
                        digests.push(sha.to_string());
                    }
                }
            }
            if let Some(items) = body_doc.get("objects").and_then(Value::as_array) {
                for item in items {
                    if let Some(sha) = item.get("sha256").and_then(Value::as_str) {
                        digests.push(sha.to_string());
                    }
                }
            }
            digests.sort();
            digests.dedup();
            for sha in digests {
                if !rel_store_blob_path(state_dir, &sha).exists() {
                    missing.push(sha);
                }
            }
            UiHttpResponse::Json(200, json!({ "missing": missing }))
        }
        ("PUT", ["v1", "artifacts", "cas", "objects", sha]) => {
            let actual = sha256_hex(&request.body);
            if actual != *sha {
                UiHttpResponse::Json(
                    409,
                    cli_report(
                        "artifact upload",
                        false,
                        12,
                        json!({}),
                        None,
                        vec![result_diag(
                            "LP_REMOTE_UPLOAD_DIGEST_MISMATCH",
                            "run",
                            "uploaded blob digest does not match path digest",
                            "error",
                        )],
                    ),
                )
            } else {
                let logical_name =
                    request_header(&request, "x-logical-name").unwrap_or("artifact.bin");
                let media_type =
                    request_header(&request, "content-type").unwrap_or("application/octet-stream");
                let artifact = cas_put(state_dir, logical_name, media_type, &request.body)?;
                UiHttpResponse::Json(200, json!({ "ok": true, "artifact": artifact }))
            }
        }
        ("POST", ["v1", "deploy", "accept"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let fixture = remote_fixture_name(body_doc.get("fixture").and_then(Value::as_str));
            let run_doc = body_doc
                .get("run")
                .cloned()
                .ok_or_else(|| anyhow!("missing run document"))?;
            let exec_doc = body_doc
                .get("execution")
                .cloned()
                .ok_or_else(|| anyhow!("missing execution document"))?;
            match validate_remote_accept_secrets(state_dir, &exec_doc, &body_doc) {
                Ok(Some(response)) => response,
                Ok(None) => {
                    let decision_doc = body_doc
                        .get("decision")
                        .cloned()
                        .ok_or_else(|| anyhow!("missing decision document"))?;
                    let change_doc = body_doc.get("change_request").cloned();
                    let (run_id, exec_id, decision_id) = persist_remote_accept_docs(
                        state_dir,
                        &run_doc,
                        &exec_doc,
                        &decision_doc,
                        change_doc.as_ref(),
                    )?;
                    let _ = record_remote_event(
                        state_dir,
                        &exec_id,
                        "deploy.accept",
                        "remote deploy accepted",
                        json!({
                            "run_id": run_id,
                            "decision_id": decision_id,
                            "fixture": fixture,
                            "required_secrets": body_doc.get("required_secrets").cloned().unwrap_or_else(|| json!([])),
                        }),
                    );
                    let _ = record_remote_log(
                        state_dir,
                        &exec_id,
                        "info",
                        "accepted remote deployment",
                        json!({
                            "run_id": run_id,
                            "decision_id": decision_id,
                        }),
                    );
                    UiHttpResponse::Json(
                        200,
                        cli_report(
                            "deploy accept",
                            true,
                            0,
                            json!({
                                "run_id": run_id,
                                "exec_id": exec_id,
                                "decision_id": decision_id,
                            }),
                            get_str(&run_doc, &["run_id"]).as_deref(),
                            Vec::new(),
                        ),
                    )
                }
                Err(err) => UiHttpResponse::Json(
                    200,
                    cli_report(
                        "deploy accept",
                        false,
                        12,
                        json!({}),
                        get_str(&run_doc, &["run_id"]).as_deref(),
                        vec![result_diag(
                            "LP_REMOTE_SECRET_STORE_INVALID",
                            "run",
                            &err.to_string(),
                            "error",
                        )],
                    ),
                ),
            }
        }
        ("POST", ["v1", "deploy", "run"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let run_id = if let Some(run_id) = body_doc.get("run_id").and_then(Value::as_str) {
                run_id.to_string()
            } else if let Some(exec_id) = body_doc.get("deployment_id").and_then(Value::as_str) {
                let exec_doc = load_exec(state_dir, exec_id)?;
                get_str(&exec_doc, &["run_id"])
                    .ok_or_else(|| anyhow!("missing run_id for deployment {exec_id}"))?
            } else {
                return Err(anyhow!("missing run_id or deployment_id"));
            };
            let exec_id = match find_exec_id_for_run(state_dir, &run_id)? {
                Some(exec_id) => exec_id,
                None => {
                    return Ok(UiHttpResponse::Json(
                        200,
                        cli_report(
                            "deploy run",
                            false,
                            2,
                            json!({}),
                            None,
                            vec![result_diag(
                                "LP_DEPLOYMENT_NOT_FOUND",
                                "run",
                                "deployment not found for accepted run",
                                "error",
                            )],
                        ),
                    ));
                }
            };
            let fixture = remote_fixture_name(body_doc.get("fixture").and_then(Value::as_str));
            let (plan, metrics_dir) = resolve_remote_fixture_inputs(fixture.as_deref());
            let report = match command_run_execution(DeployRunArgs {
                deployment_id: exec_id.clone(),
                accepted_run: Some(run_id.clone()),
                plan,
                metrics_dir,
                pause_scale: body_doc.get("pause_scale").and_then(Value::as_f64),
                target: None,
                fixture: fixture.clone(),
                common,
            }) {
                Ok(report) => report,
                Err(err) => cli_report(
                    "deploy run",
                    false,
                    13,
                    json!({
                        "schema_version": "lp.deploy.remote.result@0.1.0",
                        "op": "run",
                        "run_id": run_id,
                        "deployment_id": exec_id
                    }),
                    None,
                    vec![result_diag(
                        "LP_REMOTE_RUN_FAILED",
                        "run",
                        &err.to_string(),
                        "error",
                    )],
                ),
            };
            let ok = report.get("ok").and_then(Value::as_bool).unwrap_or(false);
            let _ = record_remote_event(
                state_dir,
                &exec_id,
                "deploy.run",
                if ok {
                    "remote deployment run finished"
                } else {
                    "remote deployment run failed"
                },
                json!({
                    "run_id": run_id,
                    "fixture": fixture,
                    "ok": ok,
                    "outcome": get_path(&report, &["result", "outcome"]).cloned().unwrap_or(Value::Null),
                    "latest_weight_pct": get_path(&report, &["result", "latest_weight_pct"]).cloned().unwrap_or(Value::Null),
                }),
            );
            let _ = record_remote_log(
                state_dir,
                &exec_id,
                if ok { "info" } else { "error" },
                if ok {
                    "deploy run completed"
                } else {
                    "deploy run returned a failure report"
                },
                json!({
                    "run_id": run_id,
                    "diagnostics": report.get("diagnostics").cloned().unwrap_or_else(|| json!([])),
                }),
            );
            UiHttpResponse::Json(200, report)
        }
        ("GET", ["v1", "deployments", exec_id]) => UiHttpResponse::Json(
            200,
            command_status_state(DeploymentStatusArgs {
                deployment_id: (*exec_id).to_string(),
                target: None,
                common,
            })?,
        ),
        ("GET", ["v1", "deployments", exec_id, "query"]) => UiHttpResponse::Json(
            200,
            command_query_state(DeployQueryArgs {
                deployment_id: Some((*exec_id).to_string()),
                app_id: None,
                env: None,
                view: request_query_string(&request, "view")
                    .unwrap_or_else(|| "summary".to_string()),
                limit: request_query_usize(&request, "limit"),
                latest: false,
                rebuild_index: request_query_bool(&request, "rebuild_index", false),
                target: None,
                common,
            })?,
        ),
        ("POST", ["v1", "deployments", exec_id, "stop"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let report = command_stop_execution(DeploymentControlArgs {
                deployment_id: (*exec_id).to_string(),
                reason: get_http_string(&body_doc, "reason", "remote_stop"),
                target: None,
                common,
            })?;
            let _ = record_remote_event(
                state_dir,
                exec_id,
                "deploy.stop",
                "remote deployment stopped",
                json!({ "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false) }),
            );
            let _ = record_remote_log(
                state_dir,
                exec_id,
                "info",
                "processed stop control action",
                json!({ "result": report.get("result").cloned().unwrap_or(Value::Null) }),
            );
            UiHttpResponse::Json(200, report)
        }
        ("POST", ["v1", "deployments", exec_id, "rollback"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let report = command_rollback_execution(DeploymentControlArgs {
                deployment_id: (*exec_id).to_string(),
                reason: get_http_string(&body_doc, "reason", "remote_rollback"),
                target: None,
                common,
            })?;
            let _ = record_remote_event(
                state_dir,
                exec_id,
                "deploy.rollback",
                "remote deployment rolled back",
                json!({ "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false) }),
            );
            let _ = record_remote_log(
                state_dir,
                exec_id,
                "info",
                "processed rollback control action",
                json!({ "result": report.get("result").cloned().unwrap_or(Value::Null) }),
            );
            UiHttpResponse::Json(200, report)
        }
        ("POST", ["v1", "deployments", exec_id, "pause"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let report = command_pause_execution(DeploymentControlArgs {
                deployment_id: (*exec_id).to_string(),
                reason: get_http_string(&body_doc, "reason", "remote_pause"),
                target: None,
                common,
            })?;
            let _ = record_remote_event(
                state_dir,
                exec_id,
                "deploy.pause",
                "remote deployment paused",
                json!({ "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false) }),
            );
            let _ = record_remote_log(
                state_dir,
                exec_id,
                "info",
                "processed pause control action",
                json!({ "result": report.get("result").cloned().unwrap_or(Value::Null) }),
            );
            UiHttpResponse::Json(200, report)
        }
        ("POST", ["v1", "deployments", exec_id, "rerun"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let report = command_rerun_execution(DeploymentRerunArgs {
                deployment_id: (*exec_id).to_string(),
                from_step: body_doc
                    .get("from_step")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize),
                reason: get_http_string(&body_doc, "reason", "remote_rerun"),
                target: None,
                common,
            })?;
            let _ = record_remote_event(
                state_dir,
                exec_id,
                "deploy.rerun",
                "remote deployment rerun requested",
                json!({ "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false) }),
            );
            let _ = record_remote_log(
                state_dir,
                exec_id,
                "info",
                "processed rerun control action",
                json!({ "result": report.get("result").cloned().unwrap_or(Value::Null) }),
            );
            UiHttpResponse::Json(200, report)
        }
        ("POST", ["v1", "incidents", "capture"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let request_path =
                materialize_remote_http_doc(state_dir, "request", body_doc.get("request"))?;
            let response_path =
                materialize_remote_http_doc(state_dir, "response", body_doc.get("response"))?;
            let trace_path =
                materialize_remote_http_doc(state_dir, "trace", body_doc.get("trace"))?;
            let deployment_id = get_http_string(&body_doc, "deployment_id", "");
            let release_exec_id = get_http_optional_string(&body_doc, "release_exec_id");
            let report = command_incident_capture_execution(IncidentCaptureArgs {
                deployment_id: if deployment_id.is_empty() {
                    None
                } else {
                    Some(deployment_id.clone())
                },
                release_exec_id: release_exec_id.clone(),
                reason: get_http_string(&body_doc, "reason", "remote_incident"),
                request: request_path,
                response: response_path,
                trace: trace_path,
                classification: get_http_string(&body_doc, "classification", "unknown"),
                source: get_http_string(&body_doc, "source", "remote"),
                target: None,
                common,
            })?;
            if let Some(exec_id) = if !deployment_id.is_empty() {
                Some(deployment_id.as_str())
            } else {
                release_exec_id.as_deref()
            } {
                let _ = record_remote_event(
                    state_dir,
                    exec_id,
                    "incident.capture",
                    "remote incident captured",
                    json!({
                        "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false),
                        "incident_id": get_path(&report, &["result", "incident_id"]).cloned().unwrap_or(Value::Null),
                    }),
                );
            }
            UiHttpResponse::Json(200, report)
        }
        ("GET", ["v1", "incidents"]) => UiHttpResponse::Json(
            200,
            command_incident_list_state(IncidentListArgs {
                deployment_id: request_query_string(&request, "deployment_id"),
                release_exec_id: request_query_string(&request, "release_exec_id"),
                classification: request_query_string(&request, "classification"),
                native_classification: request_query_string(&request, "native_classification"),
                status: request_query_string(&request, "status"),
                target_kind: request_query_string(&request, "target_kind"),
                native_only: request_query_bool(&request, "native_only", false),
                app_id: request_query_string(&request, "app_id"),
                env: request_query_string(&request, "env"),
                limit: request_query_usize(&request, "limit"),
                rebuild_index: request_query_bool(&request, "rebuild_index", false),
                target: None,
                common,
            })?,
        ),
        ("GET", ["v1", "incidents", incident_id]) => UiHttpResponse::Json(
            200,
            command_incident_get_state(IncidentGetArgs {
                incident_id: (*incident_id).to_string(),
                rebuild_index: request_query_bool(&request, "rebuild_index", false),
                target: None,
                common,
            })?,
        ),
        ("POST", ["v1", "incidents", incident_id, "regress"]) => {
            let body_doc = parse_http_body(&request.body)?;
            let report = command_regress_from_incident_state(RegressFromIncidentArgs {
                incident_id: (*incident_id).to_string(),
                name: get_http_string(&body_doc, "name", "incident"),
                out_dir: get_http_optional_string(&body_doc, "out_dir"),
                dry_run: get_http_bool(&body_doc, "dry_run", false),
                target: None,
                common,
            })?;
            if let Ok(Some((meta, _, _))) = build_incident_summary_from_disk(state_dir, incident_id)
            {
                let exec_id = get_str(&meta, &["deployment_id"])
                    .or_else(|| get_str(&meta, &["release_exec_id"]));
                if let Some(exec_id) = exec_id {
                    let _ = record_remote_event(
                        state_dir,
                        &exec_id,
                        "incident.regress",
                        "remote regression generated from incident",
                        json!({
                            "ok": report.get("ok").and_then(Value::as_bool).unwrap_or(false),
                            "incident_id": incident_id,
                        }),
                    );
                }
            }
            UiHttpResponse::Json(200, report)
        }
        ("GET", ["v1", "events"]) => {
            let limit = request_query_usize(&request, "limit").unwrap_or(100);
            let exec_id = request_query_string(&request, "exec_id")
                .or_else(|| request_query_string(&request, "deployment_id"));
            let slot = request_query_string(&request, "slot");
            let (items, cursor, next_cursor) = read_remote_stream_items(
                state_dir,
                "events",
                exec_id.as_deref(),
                slot.as_deref(),
                request_query_string(&request, "cursor").as_deref(),
                limit,
            )?;
            UiHttpResponse::Json(
                200,
                cli_report(
                    "events",
                    true,
                    0,
                    json!({
                        "schema_version": "lp.remote.events.result@0.1.0",
                        "exec_id": exec_id,
                        "slot": slot,
                        "items": items,
                        "cursor": cursor,
                        "next_cursor": next_cursor
                    }),
                    None,
                    Vec::new(),
                ),
            )
        }
        ("GET", ["v1", "logs"]) => {
            let limit = request_query_usize(&request, "limit").unwrap_or(100);
            let exec_id = request_query_string(&request, "exec_id")
                .or_else(|| request_query_string(&request, "deployment_id"));
            let slot = request_query_string(&request, "slot");
            let (items, cursor, next_cursor) = read_remote_stream_items(
                state_dir,
                "logs",
                exec_id.as_deref(),
                slot.as_deref(),
                request_query_string(&request, "cursor").as_deref(),
                limit,
            )?;
            UiHttpResponse::Json(
                200,
                cli_report(
                    "logs",
                    true,
                    0,
                    json!({
                        "schema_version": "lp.remote.logs.result@0.1.0",
                        "exec_id": exec_id,
                        "slot": slot,
                        "items": items,
                        "cursor": cursor,
                        "next_cursor": next_cursor
                    }),
                    None,
                    Vec::new(),
                ),
            )
        }
        _ => UiHttpResponse::Json(
            404,
            cli_report(
                "remote",
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
    };
    Ok(response)
}

fn dispatch_ui_request(request: HttpRequest, state_dir: &Path) -> Result<UiHttpResponse> {
    if request
        .path
        .starts_with(&format!("{REMOTE_EDGE_ROUTE_PREFIX}/"))
    {
        return dispatch_edge_request(request, state_dir);
    }
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
        ("GET", "/api/device-releases") => {
            UiHttpResponse::Json(200, command_device_release_list(&common)?)
        }
        ("GET", "/api/incidents") => UiHttpResponse::Json(
            200,
            command_incident_list(IncidentListArgs {
                deployment_id: None,
                release_exec_id: None,
                classification: None,
                native_classification: None,
                status: None,
                target_kind: None,
                native_only: false,
                app_id: None,
                env: None,
                limit: None,
                rebuild_index: false,
                target: None,
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
                        target: None,
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
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "deployments", exec_id, "incidents"]) => UiHttpResponse::Json(
                    200,
                    command_incident_list(IncidentListArgs {
                        deployment_id: Some((*exec_id).to_string()),
                        release_exec_id: None,
                        classification: None,
                        native_classification: None,
                        status: None,
                        target_kind: None,
                        native_only: false,
                        app_id: None,
                        env: None,
                        limit: None,
                        rebuild_index: false,
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "device-releases", exec_id, "incidents"]) => UiHttpResponse::Json(
                    200,
                    command_incident_list(IncidentListArgs {
                        deployment_id: None,
                        release_exec_id: Some((*exec_id).to_string()),
                        classification: None,
                        native_classification: None,
                        status: None,
                        target_kind: None,
                        native_only: false,
                        app_id: None,
                        env: None,
                        limit: None,
                        rebuild_index: false,
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "device-releases", exec_id]) => UiHttpResponse::Json(
                    200,
                    command_device_release_query(DeviceReleaseQueryArgs {
                        release_exec_id: Some((*exec_id).to_string()),
                        app_id: None,
                        provider_id: None,
                        distribution_lane: None,
                        target: None,
                        view: "full".to_string(),
                        limit: None,
                        latest: false,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "device-releases", exec_id, "decisions"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_query(DeviceReleaseQueryArgs {
                        release_exec_id: Some((*exec_id).to_string()),
                        app_id: None,
                        provider_id: None,
                        distribution_lane: None,
                        target: None,
                        view: "decisions".to_string(),
                        limit: None,
                        latest: false,
                        common: common.clone(),
                    })?,
                ),
                ("GET", ["api", "incidents", incident_id]) => UiHttpResponse::Json(
                    200,
                    command_incident_get(IncidentGetArgs {
                        incident_id: (*incident_id).to_string(),
                        rebuild_index: false,
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "pause"]) => UiHttpResponse::Json(
                    200,
                    command_pause(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_pause"),
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "rerun"]) => UiHttpResponse::Json(
                    200,
                    command_rerun(DeploymentRerunArgs {
                        deployment_id: (*exec_id).to_string(),
                        from_step: Some(get_http_u64(&body_doc, "from_step", 0) as usize),
                        reason: get_http_string(&body_doc, "reason", "http_rerun"),
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "rollback"]) => UiHttpResponse::Json(
                    200,
                    command_rollback(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_rollback"),
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "deployments", exec_id, "stop"]) => UiHttpResponse::Json(
                    200,
                    command_stop(DeploymentControlArgs {
                        deployment_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_stop"),
                        target: None,
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "device-releases", exec_id, "pause"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_control(
                        DeviceReleaseControlArgs {
                            release_exec_id: (*exec_id).to_string(),
                            reason: get_http_string(
                                &body_doc,
                                "reason",
                                "http_device_release_pause",
                            ),
                            common: common.clone(),
                        },
                        "pause",
                        "device.release.pause.manual",
                    )?,
                ),
                ("POST", ["api", "device-releases", exec_id, "observe"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_observe(DeviceReleaseControlArgs {
                        release_exec_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_device_release_observe"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "device-releases", exec_id, "resume"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_control(
                        DeviceReleaseControlArgs {
                            release_exec_id: (*exec_id).to_string(),
                            reason: get_http_string(
                                &body_doc,
                                "reason",
                                "http_device_release_resume",
                            ),
                            common: common.clone(),
                        },
                        "resume",
                        "device.release.resume.manual",
                    )?,
                ),
                ("POST", ["api", "device-releases", exec_id, "halt"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_control(
                        DeviceReleaseControlArgs {
                            release_exec_id: (*exec_id).to_string(),
                            reason: get_http_string(
                                &body_doc,
                                "reason",
                                "http_device_release_halt",
                            ),
                            common: common.clone(),
                        },
                        "halt",
                        "device.release.halt.manual",
                    )?,
                ),
                ("POST", ["api", "device-releases", exec_id, "stop"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_stop(DeviceReleaseControlArgs {
                        release_exec_id: (*exec_id).to_string(),
                        reason: get_http_string(&body_doc, "reason", "http_device_release_stop"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "device-releases", exec_id, "complete"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_control(
                        DeviceReleaseControlArgs {
                            release_exec_id: (*exec_id).to_string(),
                            reason: get_http_string(
                                &body_doc,
                                "reason",
                                "http_device_release_complete",
                            ),
                            common: common.clone(),
                        },
                        "complete",
                        "device.release.complete.manual",
                    )?,
                ),
                ("POST", ["api", "device-releases", exec_id, "rerun"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_rerun(DeviceReleaseRerunArgs {
                        release_exec_id: (*exec_id).to_string(),
                        from_step: Some(get_http_u64(&body_doc, "from_step", 0) as usize),
                        reason: get_http_string(&body_doc, "reason", "http_device_release_rerun"),
                        common: common.clone(),
                    })?,
                ),
                ("POST", ["api", "device-releases", exec_id, "rollback"]) => UiHttpResponse::Json(
                    200,
                    command_device_release_control(
                        DeviceReleaseControlArgs {
                            release_exec_id: (*exec_id).to_string(),
                            reason: get_http_string(
                                &body_doc,
                                "reason",
                                "http_device_release_rollback",
                            ),
                            common: common.clone(),
                        },
                        "rollback",
                        "device.release.rollback.manual",
                    )?,
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
                        target: None,
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
        if header_end.is_none()
            && let Some(pos) = find_bytes(&buffer, b"\r\n\r\n")
        {
            header_end = Some(pos + 4);
            content_length = parse_content_length(&buffer[..pos + 4])?;
        }
        if let Some(end) = header_end
            && buffer.len() >= end + content_length
        {
            let head = std::str::from_utf8(&buffer[..end]).context("decode request head")?;
            let mut lines = head.lines();
            let mut parts = lines.next().unwrap_or_default().split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or("/");
            let (path, query) = match target.split_once('?') {
                Some((path, query)) => (path.to_string(), parse_query_string(query)),
                None => (target.to_string(), BTreeMap::new()),
            };
            let mut headers = BTreeMap::new();
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
                }
            }
            return Ok(HttpRequest {
                method,
                path,
                query,
                headers,
                body: buffer[end..end + content_length].to_vec(),
            });
        }
        if buffer.len() > 1_048_576 {
            bail!("request too large");
        }
    }
    bail!("incomplete http request")
}

fn parse_query_string(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        out.insert(key.into_owned(), value.into_owned());
    }
    out
}

fn parse_content_length(head: &[u8]) -> Result<usize> {
    let head = std::str::from_utf8(head).context("decode request headers")?;
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some((_, value)) = lower.split_once(':')
            && lower.starts_with("content-length:")
        {
            return value
                .trim()
                .parse::<usize>()
                .context("parse content-length");
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
            "text/html; charset=utf-8".to_string(),
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
            "text/html; charset=utf-8".to_string(),
            b"<!doctype html><html><head><meta charset='utf-8'><title>x07 Command Center</title></head><body><main><h1>x07 Command Center</h1><p>Build ui/command-center to serve the web UI.</p></main></body></html>".to_vec(),
        ));
    }
    let body = fs::read(&path)?;
    Ok(UiHttpResponse::Bytes(
        200,
        media_type_for_http(&path).to_string(),
        body,
    ))
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
        401 => "Unauthorized",
        409 => "Conflict",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "x07lp-driver-{label}-{}-{}",
                std::process::id(),
                now_ms()
            ));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct ScopedEnvVar {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => unsafe {
                    std::env::set_var(self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(self.key);
                },
            }
        }
    }

    #[derive(Debug, Clone)]
    struct ObservedRequest {
        method: String,
        path: String,
        query: BTreeMap<String, String>,
        body: Vec<u8>,
        authorization: Option<String>,
    }

    struct TestResponse {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    }

    impl TestResponse {
        fn json(status: u16, value: Value) -> Self {
            Self {
                status,
                content_type: "application/json".to_string(),
                body: canon_json_bytes(&value),
            }
        }
    }

    struct MockServer {
        base_url: String,
        shutdown: Option<mpsc::Sender<()>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn spawn<F, H>(builder: F) -> Result<Self>
        where
            F: FnOnce(String) -> H,
            H: Fn(HttpRequest) -> TestResponse + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            let base_url = format!("http://{}", addr);
            listener.set_nonblocking(true)?;
            let (tx, rx) = mpsc::channel::<()>();
            let handler = Arc::new(builder(base_url.clone()));
            let thread_handler = Arc::clone(&handler);
            let handle = thread::spawn(move || {
                loop {
                    if rx.try_recv().is_ok() {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let request = match read_http_request(&mut stream) {
                                Ok(request) => request,
                                Err(_) => continue,
                            };
                            let response = thread_handler(request);
                            let _ = write_http_response(
                                &mut stream,
                                response.status,
                                &response.content_type,
                                &response.body,
                            );
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                base_url,
                shutdown: Some(tx),
                handle: Some(handle),
            })
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn sample_token_response(api_base: &str, access_token: &str, refresh_token: &str) -> Value {
        json!({
            "schema_version": "lp.auth.token.response@0.1.0",
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "refresh_expires_in": 86400,
            "scope": "cloud:all offline_access",
            "issuer": format!("{api_base}/issuer"),
            "audience": "x07-cloud",
            "subject": {
                "subject_id": "acct_demo",
                "subject_kind": "human"
            },
            "session": {
                "session_id": "sess_demo"
            }
        })
    }

    fn sample_whoami(api_base: &str, org_id: &str, project_id: &str) -> Value {
        json!({
            "schema_version": "lp.auth.whoami.result@0.1.0",
            "account": {
                "account_id": "acct_demo",
                "subject_kind": "human",
                "email": "user@example.com",
                "display_name": "Demo User",
                "plan": "trial"
            },
            "target": {
                "name": "cloud",
                "api_base": api_base,
                "audience": "x07-cloud"
            },
            "default_context": {
                "org_id": org_id,
                "org_slug": "demo-org",
                "project_id": project_id,
                "project_slug": "demo-project"
            },
            "scope": ["cloud:all", "offline_access"],
            "session_expires_unix_ms": now_ms().saturating_add(86_400_000)
        })
    }

    fn sample_session(api_base: &str, access_token: &str, refresh_token: &str, expires_at: u64) -> Value {
        json!({
            "schema_version": "lp.auth.session@0.1.0",
            "issuer": format!("{api_base}/issuer"),
            "auth_metadata_url": format!("{api_base}/.well-known/openid-configuration"),
            "jwks_uri": format!("{api_base}/jwks"),
            "target": {
                "name": "cloud",
                "api_base": api_base,
                "audience": "x07-cloud"
            },
            "account": {
                "account_id": "acct_demo",
                "subject_kind": "human",
                "email": "user@example.com",
                "display_name": "Demo User",
                "plan": "trial"
            },
            "default_context": {
                "org_id": "org_demo",
                "org_slug": "demo-org",
                "project_id": "prj_demo",
                "project_slug": "demo-project"
            },
            "tokens": {
                "token_type": "Bearer",
                "access_token": access_token,
                "access_token_expires_unix_ms": expires_at,
                "scope": ["cloud:all", "offline_access"],
                "refresh_token": refresh_token,
                "refresh_token_ref": null,
                "refresh_token_expires_unix_ms": now_ms().saturating_add(86_400_000)
            },
            "created_unix_ms": now_ms().saturating_sub(1_000),
            "updated_unix_ms": now_ms().saturating_sub(1_000)
        })
    }

    fn sample_metadata(api_base: &str) -> Value {
        json!({
            "issuer": format!("{api_base}/issuer"),
            "authorization_endpoint": format!("{api_base}/oauth/authorize"),
            "token_endpoint": format!("{api_base}/oauth/token"),
            "device_authorization_endpoint": format!("{api_base}/oauth/device/code"),
            "revocation_endpoint": format!("{api_base}/oauth/revoke"),
            "jwks_uri": format!("{api_base}/jwks"),
            "x07lp_client_id": DEFAULT_HOSTED_CLIENT_ID,
            "x07lp_scope": DEFAULT_HOSTED_SCOPE
        })
    }

    fn wrapped_cli_report(command: &str, result: Value) -> Value {
        cli_report(command, true, 0, result, None, Vec::new())
    }

    fn form_map(body: &[u8]) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(body)
            .into_owned()
            .collect::<BTreeMap<_, _>>()
    }

    #[test]
    fn hosted_session_round_trip_stays_separate_from_oss_targets() -> Result<()> {
        let _guard = TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let tmp = TempDir::new("session-roundtrip")?;
        let _config = ScopedEnvVar::set("X07LP_CONFIG_DIR", &tmp.path.to_string_lossy());
        let session = sample_session("http://127.0.0.1:39001", "access.initial", "refresh.initial", now_ms().saturating_add(60_000));
        let path = store_hosted_session_doc(&session)?;
        assert_eq!(path, tmp.path.join("session.json"));
        assert_eq!(load_hosted_session_doc()?, session);
        assert!(!x07lp_targets_dir()?.exists());
        assert!(!x07lp_current_target_path()?.exists());
        Ok(())
    }

    #[test]
    fn whoami_refreshes_expired_session_and_persists_new_tokens() -> Result<()> {
        let _guard = TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let tmp = TempDir::new("whoami-refresh")?;
        let _config = ScopedEnvVar::set("X07LP_CONFIG_DIR", &tmp.path.to_string_lossy());
        let observed = Arc::new(Mutex::new(Vec::<ObservedRequest>::new()));
        let observed_requests = Arc::clone(&observed);
        let server = MockServer::spawn(move |base_url| move |request| {
            observed_requests.lock().unwrap().push(ObservedRequest {
                method: request.method.clone(),
                path: request.path.clone(),
                query: request.query.clone(),
                body: request.body.clone(),
                authorization: request.headers.get("authorization").cloned(),
            });
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/.well-known/openid-configuration") => {
                    TestResponse::json(200, sample_metadata(&base_url))
                }
                ("POST", "/oauth/token") => {
                    let form = form_map(&request.body);
                    assert_eq!(form.get("grant_type").map(String::as_str), Some("refresh_token"));
                    assert_eq!(form.get("client_id").map(String::as_str), Some(DEFAULT_HOSTED_CLIENT_ID));
                    assert_eq!(form.get("refresh_token").map(String::as_str), Some("refresh.old"));
                    TestResponse::json(
                        200,
                        sample_token_response(&base_url, "access.new", "refresh.new"),
                    )
                }
                ("GET", "/v1/whoami") => {
                    assert_eq!(
                        request.headers.get("authorization").map(String::as_str),
                        Some("Bearer access.new")
                    );
                    TestResponse::json(
                        200,
                        wrapped_cli_report(
                            "whoami",
                            sample_whoami(&base_url, "org_demo", "prj_demo"),
                        ),
                    )
                }
                _ => TestResponse::json(404, json!({"error":"not_found"})),
            }
        })?;
        let expired = sample_session(&server.base_url, "access.old", "refresh.old", now_ms().saturating_sub(1));
        let _ = store_hosted_session_doc(&expired)?;
        let report = command_whoami(HostedCommonArgs {
            api_base: None,
            json: true,
        })?;
        assert_eq!(report.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            get_str(&report, &["result", "account", "account_id"]).as_deref(),
            Some("acct_demo")
        );
        let updated = load_hosted_session_doc()?;
        assert_eq!(
            get_str(&updated, &["tokens", "access_token"]).as_deref(),
            Some("access.new")
        );
        assert_eq!(
            get_str(&updated, &["tokens", "refresh_token"]).as_deref(),
            Some("refresh.new")
        );
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/.well-known/openid-configuration");
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].path, "/oauth/token");
        assert_eq!(requests[2].authorization.as_deref(), Some("Bearer access.new"));
        assert_eq!(requests[2].path, "/v1/whoami");
        assert_eq!(requests[3].authorization.as_deref(), Some("Bearer access.new"));
        assert_eq!(requests[3].path, "/v1/whoami");
        Ok(())
    }

    #[test]
    fn hosted_org_project_env_and_context_commands_shape_requests() -> Result<()> {
        let _guard = TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let tmp = TempDir::new("hosted-crud")?;
        let _config = ScopedEnvVar::set("X07LP_CONFIG_DIR", &tmp.path.to_string_lossy());
        let observed = Arc::new(Mutex::new(Vec::<ObservedRequest>::new()));
        let observed_requests = Arc::clone(&observed);
        let server = MockServer::spawn(move |base_url| move |request| {
            observed_requests.lock().unwrap().push(ObservedRequest {
                method: request.method.clone(),
                path: request.path.clone(),
                query: request.query.clone(),
                body: request.body.clone(),
                authorization: request.headers.get("authorization").cloned(),
            });
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/v1/orgs") => TestResponse::json(
                    200,
                    wrapped_cli_report(
                        "org list",
                        json!({
                            "schema_version": "lp.org.list.result@0.1.0",
                            "items": [{
                                "org_id": "org_demo",
                                "org_slug": "demo-org",
                                "display_name": "Demo Org",
                                "role": "owner",
                                "selected": true,
                                "created_unix_ms": now_ms(),
                                "updated_unix_ms": now_ms()
                            }, {
                                "org_id": "org_next",
                                "org_slug": "next-org",
                                "display_name": "Next Org",
                                "role": "owner",
                                "selected": false,
                                "created_unix_ms": now_ms(),
                                "updated_unix_ms": now_ms()
                            }]
                        }),
                    ),
                ),
                ("POST", "/v1/orgs") => TestResponse::json(
                    200,
                    wrapped_cli_report(
                        "org create",
                        json!({
                            "schema_version": "lp.org.list.result@0.1.0",
                            "items": []
                        }),
                    ),
                ),
                ("GET", "/v1/projects") => {
                    let result = match request.query.get("org_id").map(String::as_str) {
                        Some("org_next") => json!({
                            "schema_version": "lp.project.list.result@0.1.0",
                            "items": [{
                                "project_id": "prj_next",
                                "org_id": "org_next",
                                "project_slug": "next-project",
                                "display_name": "Next Project",
                                "selected": false,
                                "created_unix_ms": now_ms(),
                                "updated_unix_ms": now_ms()
                            }]
                        }),
                        _ => json!({
                            "schema_version": "lp.project.list.result@0.1.0",
                            "items": []
                        }),
                    };
                    TestResponse::json(200, wrapped_cli_report("project list", result))
                }
                ("POST", "/v1/projects") => TestResponse::json(
                    200,
                    wrapped_cli_report(
                        "project create",
                        json!({
                            "schema_version": "lp.project.list.result@0.1.0",
                            "items": []
                        }),
                    ),
                ),
                ("GET", "/v1/environments") => {
                    let result = match request.query.get("project_id").map(String::as_str) {
                        Some("prj_next") => json!({
                            "schema_version": "lp.environment.list.result@0.1.0",
                            "items": [{
                                "environment_id": "env_next",
                                "project_id": "prj_next",
                                "environment_slug": "next-env",
                                "display_name": "Next Env",
                                "selected": false,
                                "created_unix_ms": now_ms(),
                                "updated_unix_ms": now_ms()
                            }]
                        }),
                        _ => json!({
                            "schema_version": "lp.environment.list.result@0.1.0",
                            "items": []
                        }),
                    };
                    TestResponse::json(200, wrapped_cli_report("env list", result))
                }
                ("POST", "/v1/environments") => TestResponse::json(
                    200,
                    wrapped_cli_report(
                        "env create",
                        json!({
                            "schema_version": "lp.environment.list.result@0.1.0",
                            "items": []
                        }),
                    ),
                ),
                ("POST", "/v1/context/select") => {
                    let mut next_session = sample_session(
                        &base_url,
                        "access.live",
                        "refresh.live",
                        now_ms().saturating_add(60_000),
                    );
                    next_session["default_context"] = json!({
                        "org_id": "org_next",
                        "org_slug": "demo-org",
                        "project_id": "prj_next",
                        "project_slug": "demo-project"
                    });
                    TestResponse::json(
                        200,
                        wrapped_cli_report("context use", next_session),
                    )
                }
                _ => TestResponse::json(404, json!({"error":"not_found"})),
            }
        })?;
        let session = sample_session(
            &server.base_url,
            "access.live",
            "refresh.live",
            now_ms().saturating_add(60_000),
        );
        let _ = store_hosted_session_doc(&session)?;
        let _ = command_org(HostedOrgArgs {
            command: HostedOrgCommand::List(HostedCommonArgs {
                api_base: None,
                json: true,
            }),
        })?;
        let _ = command_org(HostedOrgArgs {
            command: HostedOrgCommand::Create(HostedCreateArgs {
                name: "Demo Org".to_string(),
                slug: Some("demo-org".to_string()),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let _ = command_project(HostedProjectArgs {
            command: HostedProjectCommand::List(HostedProjectListArgs {
                org: "org_demo".to_string(),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let _ = command_project(HostedProjectArgs {
            command: HostedProjectCommand::Create(HostedProjectCreateArgs {
                org: "org_demo".to_string(),
                name: "Demo Project".to_string(),
                slug: Some("demo-project".to_string()),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let _ = command_environment(HostedEnvironmentArgs {
            command: HostedEnvironmentCommand::List(HostedEnvironmentListArgs {
                project: "prj_demo".to_string(),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let _ = command_environment(HostedEnvironmentArgs {
            command: HostedEnvironmentCommand::Create(HostedEnvironmentCreateArgs {
                project: "prj_demo".to_string(),
                name: "Production".to_string(),
                slug: Some("production".to_string()),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let _ = command_context(HostedContextArgs {
            command: HostedContextCommand::Use(HostedContextUseArgs {
                org: "org_next".to_string(),
                project: "prj_next".to_string(),
                environment: Some("env_next".to_string()),
                common: HostedCommonArgs {
                    api_base: None,
                    json: true,
                },
            }),
        })?;
        let requests = observed.lock().unwrap();
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/v1/orgs");
        let org_create: Value = serde_json::from_slice(&requests[1].body)?;
        assert_eq!(
            org_create.get("slug").and_then(Value::as_str),
            Some("demo-org")
        );
        assert_eq!(
            org_create.get("display_name").and_then(Value::as_str),
            Some("Demo Org")
        );
        assert_eq!(
            requests[2].query.get("org_id").map(String::as_str),
            Some("org_demo")
        );
        let project_create: Value = serde_json::from_slice(&requests[3].body)?;
        assert_eq!(project_create.get("org_id").and_then(Value::as_str), Some("org_demo"));
        assert_eq!(
            project_create.get("slug").and_then(Value::as_str),
            Some("demo-project")
        );
        assert_eq!(
            requests[4].query.get("project_id").map(String::as_str),
            Some("prj_demo")
        );
        let environment_create: Value = serde_json::from_slice(&requests[5].body)?;
        assert_eq!(
            environment_create.get("project_id").and_then(Value::as_str),
            Some("prj_demo")
        );
        assert_eq!(
            environment_create.get("key").and_then(Value::as_str),
            Some("production")
        );
        assert_eq!(requests[6].path, "/v1/orgs");
        assert_eq!(
            requests[7].query.get("org_id").map(String::as_str),
            Some("org_next")
        );
        assert_eq!(
            requests[8].query.get("project_id").map(String::as_str),
            Some("prj_next")
        );
        let context_select: Value = serde_json::from_slice(&requests[9].body)?;
        assert_eq!(context_select.get("org_id").and_then(Value::as_str), Some("org_next"));
        assert_eq!(
            context_select.get("project_id").and_then(Value::as_str),
            Some("prj_next")
        );
        assert_eq!(
            context_select.get("environment_id").and_then(Value::as_str),
            Some("env_next")
        );
        assert_eq!(requests[9].authorization.as_deref(), Some("Bearer access.live"));
        let updated = load_hosted_session_doc()?;
        assert_eq!(
            get_str(&updated, &["default_context", "org_id"]).as_deref(),
            Some("org_next")
        );
        assert_eq!(
            get_str(&updated, &["default_context", "project_id"]).as_deref(),
            Some("prj_next")
        );
        Ok(())
    }
}
