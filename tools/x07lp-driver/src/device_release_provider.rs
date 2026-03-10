use super::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use url::form_urlencoded::byte_serialize;

const APPSTORE_AUD: &str = "appstoreconnect-v1";
const APPSTORE_DEFAULT_BASE_URL: &str = "https://api.appstoreconnect.apple.com";
const GOOGLE_PLAY_DEFAULT_BASE_URL: &str =
    "https://androidpublisher.googleapis.com/androidpublisher/v3";
const GOOGLE_PLAY_DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_PLAY_SCOPE: &str = "https://www.googleapis.com/auth/androidpublisher";
const DEVICE_SECRET_PREFIX: &str = "secrets://device/";

#[derive(Debug, Clone)]
pub(super) struct DeviceProviderStepOutcome {
    pub current_state: String,
    pub rollout_percent: Option<u64>,
    pub store_release_id: Option<String>,
    pub message: String,
    pub evidence: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct AppStoreConnectCredentials {
    issuer_id: String,
    key_id: String,
    #[serde(alias = "private_key")]
    private_key_pem: String,
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GooglePlayCredentials {
    client_email: String,
    #[serde(alias = "private_key")]
    private_key_pem: String,
    #[serde(default)]
    token_uri: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AppStoreConnectClaims {
    iss: String,
    aud: String,
    exp: usize,
}

#[derive(Debug, Clone, Serialize)]
struct GooglePlayClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
struct JsonHttpResponse {
    status: u16,
    doc: Value,
}

#[derive(Debug, Clone, Copy)]
struct GooglePlayReleaseUpdate<'a> {
    status: &'a str,
    rollout_percent: Option<u64>,
    message: &'a str,
}

pub(super) fn device_release_provider_mode(provider_doc: &Value) -> &'static str {
    if get_str(provider_doc, &["provider_kind"]).as_deref() == Some("mock_v1") {
        "mock"
    } else if device_provider_live_enabled() {
        "live"
    } else {
        "live_required"
    }
}

pub(super) fn apply_device_release_provider_op(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
    step_doc: &Value,
    exec_id: &str,
) -> Result<DeviceProviderStepOutcome> {
    let provider_kind = get_str(provider_doc, &["provider_kind"])
        .ok_or_else(|| anyhow!("provider profile missing provider_kind"))?;
    if provider_kind == "mock_v1" {
        return apply_mock_device_release_provider_op(provider_doc, exec_doc, step_doc, exec_id);
    }
    if !device_provider_live_enabled() {
        bail!(
            "provider_kind={} requires {}=1 and real store credentials",
            provider_kind,
            DEVICE_PROVIDER_LIVE_ENV
        );
    }
    match provider_kind.as_str() {
        "appstoreconnect_v1" => {
            let credentials = load_appstore_credentials(state_dir, provider_doc, exec_doc)?;
            apply_appstore_device_release_op(&credentials, provider_doc, exec_doc, step_doc)
        }
        "googleplay_v1" => {
            let credentials = load_googleplay_credentials(state_dir, provider_doc, exec_doc)?;
            apply_googleplay_device_release_op(&credentials, provider_doc, exec_doc, step_doc)
        }
        other => bail!("unsupported provider_kind={other}"),
    }
}

fn apply_mock_device_release_provider_op(
    provider_doc: &Value,
    exec_doc: &Value,
    step_doc: &Value,
    exec_id: &str,
) -> Result<DeviceProviderStepOutcome> {
    let provider_kind = get_str(provider_doc, &["provider_kind"])
        .ok_or_else(|| anyhow!("provider profile missing provider_kind"))?;
    let distribution_lane = get_str(provider_doc, &["distribution_lane"])
        .ok_or_else(|| anyhow!("provider profile missing distribution_lane"))?;
    let op = get_str(step_doc, &["op"]).ok_or_else(|| anyhow!("step missing op"))?;
    let current_percent = device_release_current_percent(exec_doc);
    let current_state = device_release_state(exec_doc);
    let store_release_id =
        device_release_store_release_id(exec_doc).or_else(|| Some(format!("store-{exec_id}")));
    let outcome = match op.as_str() {
        "release.start" => {
            if distribution_lane == "beta" {
                (
                    "available".to_string(),
                    Some(100),
                    "store release started on beta lane".to_string(),
                )
            } else if provider_kind == "appstoreconnect_v1" {
                (
                    "in_progress".to_string(),
                    None,
                    "started phased production release".to_string(),
                )
            } else {
                let initial = device_release_initial_percent(provider_doc);
                (
                    "in_progress".to_string(),
                    Some(initial),
                    format!("started staged production release at {initial}%"),
                )
            }
        }
        "rollout.set_percent" => {
            let percent = get_u64(step_doc, &["percent"])
                .ok_or_else(|| anyhow!("rollout.set_percent requires percent"))?
                .min(100);
            (
                "in_progress".to_string(),
                Some(percent),
                format!("updated staged rollout to {percent}%"),
            )
        }
        "release.pause" => (
            "paused".to_string(),
            current_percent,
            "paused device release".to_string(),
        ),
        "release.resume" => (
            if current_state == "available" {
                "available".to_string()
            } else {
                "in_progress".to_string()
            },
            current_percent,
            "resumed device release".to_string(),
        ),
        "release.complete" => (
            "completed".to_string(),
            Some(100),
            "completed device release rollout".to_string(),
        ),
        "rollback.previous" => (
            "rolled_back".to_string(),
            Some(0),
            "rolled back to previous store release".to_string(),
        ),
        other => bail!("unsupported device release op={other}"),
    };
    Ok(DeviceProviderStepOutcome {
        current_state: outcome.0,
        rollout_percent: outcome.1,
        store_release_id,
        message: outcome.2,
        evidence: json!({ "provider_mode": "mock" }),
    })
}

fn load_appstore_credentials(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<AppStoreConnectCredentials> {
    let raw = load_device_provider_credentials_string(state_dir, provider_doc, exec_doc)?;
    serde_json::from_str(&raw).context("parse App Store Connect credentials JSON")
}

fn load_googleplay_credentials(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<GooglePlayCredentials> {
    let raw = load_device_provider_credentials_string(state_dir, provider_doc, exec_doc)?;
    serde_json::from_str(&raw).context("parse Google Play credentials JSON")
}

fn load_device_provider_credentials_string(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<String> {
    let credentials_ref = get_str(provider_doc, &["credentials_ref"])
        .ok_or_else(|| anyhow!("provider profile missing credentials_ref"))?;
    if let Some(secret_id) = credentials_ref.strip_prefix(DEVICE_SECRET_PREFIX) {
        return resolve_device_secret_value(state_dir, provider_doc, exec_doc, secret_id);
    }
    if credentials_ref.starts_with("file://") {
        return load_text_ref(&credentials_ref);
    }
    let path = repo_path(&credentials_ref);
    let value = fs::read_to_string(&path)
        .with_context(|| format!("read provider credentials {}", path.display()))?
        .trim()
        .to_string();
    if value.is_empty() {
        bail!("empty provider credentials ref: {}", path.display());
    }
    Ok(value)
}

fn resolve_device_secret_value(
    state_dir: &Path,
    provider_doc: &Value,
    exec_doc: &Value,
    secret_id: &str,
) -> Result<String> {
    let store = load_remote_secret_store(state_dir)?;
    let provider_id = get_str(provider_doc, &["provider_id"]).unwrap_or_default();
    let app_id = get_str(exec_doc, &["meta", "app", "app_id"]).unwrap_or_default();
    let candidates = vec![
        vec!["device".to_string(), secret_id.to_string()],
        vec!["device".to_string(), "providers".to_string(), provider_id],
        vec![
            "device".to_string(),
            "apps".to_string(),
            app_id.clone(),
            secret_id.to_string(),
        ],
        vec![
            "device".to_string(),
            "apps".to_string(),
            app_id,
            "providers".to_string(),
            secret_id.to_string(),
        ],
    ];
    for path in candidates {
        let refs = path.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some(value) = nonempty_secret_value(get_path(&store, &refs)) {
            return Ok(value);
        }
    }
    bail!("device provider credentials secret was not found: secrets://device/{secret_id}")
}

fn apply_appstore_device_release_op(
    credentials: &AppStoreConnectCredentials,
    provider_doc: &Value,
    exec_doc: &Value,
    step_doc: &Value,
) -> Result<DeviceProviderStepOutcome> {
    let token = build_appstore_bearer_token(credentials)?;
    let base_url = device_provider_base_url(
        provider_doc,
        credentials.base_url.as_deref(),
        APPSTORE_DEFAULT_BASE_URL,
    );
    let distribution_lane = get_str(provider_doc, &["distribution_lane"]).unwrap_or_default();
    let op = get_str(step_doc, &["op"]).ok_or_else(|| anyhow!("step missing op"))?;
    if distribution_lane == "beta" {
        if op != "release.start" {
            bail!("App Store Connect beta only supports release.start");
        }
        return appstore_beta_start(&base_url, &token, provider_doc, exec_doc);
    }
    let app_store_version_id =
        resolve_appstore_version_id(&base_url, &token, provider_doc, exec_doc)?;
    match op.as_str() {
        "release.start" => {
            appstore_start_phased_release(&base_url, &token, &app_store_version_id, exec_doc)
        }
        "release.pause" => appstore_patch_phased_release_state(
            &base_url,
            &token,
            provider_doc,
            exec_doc,
            &app_store_version_id,
            "PAUSED",
            "paused App Store phased release",
        ),
        "release.resume" => appstore_patch_phased_release_state(
            &base_url,
            &token,
            provider_doc,
            exec_doc,
            &app_store_version_id,
            "ACTIVE",
            "resumed App Store phased release",
        ),
        "release.complete" => appstore_patch_phased_release_state(
            &base_url,
            &token,
            provider_doc,
            exec_doc,
            &app_store_version_id,
            "COMPLETE",
            "completed App Store phased release",
        ),
        other => bail!("unsupported App Store Connect op={other}"),
    }
}

fn appstore_beta_start(
    base_url: &str,
    token: &str,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<DeviceProviderStepOutcome> {
    let app_id = resolve_appstore_app_id(base_url, token, provider_doc)?;
    let build_id = resolve_appstore_build_id(base_url, token, provider_doc, exec_doc, &app_id)?;
    let beta_group_id = provider_option_str(provider_doc, "beta_group_id")
        .ok_or_else(|| anyhow!("App Store Connect beta requires provider_options.beta_group_id"))?;
    let url = format!("{}/v1/betaGroupBuilds", base_url.trim_end_matches('/'));
    let body = json!({
        "data": {
            "type": "betaGroupBuilds",
            "relationships": {
                "betaGroup": { "data": { "id": beta_group_id, "type": "betaGroups" } },
                "build": { "data": { "id": build_id, "type": "builds" } }
            }
        }
    });
    let response = provider_request_json("POST", &url, token, Some(&body))?;
    ensure_provider_success(&response, "POST", &url)?;
    Ok(DeviceProviderStepOutcome {
        current_state: "available".to_string(),
        rollout_percent: Some(100),
        store_release_id: response
            .doc
            .get("data")
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some(format!("beta-group:{beta_group_id}"))),
        message: "started App Store TestFlight distribution".to_string(),
        evidence: json!({
            "provider_mode": "live",
            "app_id": app_id,
            "build_id": build_id,
            "beta_group_id": beta_group_id,
            "provider_response": response.doc,
        }),
    })
}

fn appstore_start_phased_release(
    base_url: &str,
    token: &str,
    app_store_version_id: &str,
    exec_doc: &Value,
) -> Result<DeviceProviderStepOutcome> {
    if let Some(existing_id) = device_release_store_release_id(exec_doc) {
        return appstore_patch_phased_release_state_by_id(
            base_url,
            token,
            &existing_id,
            "ACTIVE",
            "started App Store phased release",
        );
    }
    if let Some(existing) = find_appstore_phased_release(base_url, token, app_store_version_id)? {
        let phased_id = get_str(&existing, &["id"])
            .ok_or_else(|| anyhow!("App Store phased release missing id"))?;
        return appstore_patch_phased_release_state_by_id(
            base_url,
            token,
            &phased_id,
            "ACTIVE",
            "started App Store phased release",
        );
    }
    let url = format!(
        "{}/v1/appStoreVersionPhasedReleases",
        base_url.trim_end_matches('/')
    );
    let body = json!({
        "data": {
            "type": "appStoreVersionPhasedReleases",
            "attributes": {
                "phasedReleaseState": "ACTIVE"
            },
            "relationships": {
                "appStoreVersion": {
                    "data": {
                        "id": app_store_version_id,
                        "type": "appStoreVersions"
                    }
                }
            }
        }
    });
    let response = provider_request_json("POST", &url, token, Some(&body))?;
    ensure_provider_success(&response, "POST", &url)?;
    let phased_id = get_str(&response.doc, &["data", "id"])
        .ok_or_else(|| anyhow!("App Store phased release create response missing id"))?;
    Ok(DeviceProviderStepOutcome {
        current_state: "in_progress".to_string(),
        rollout_percent: None,
        store_release_id: Some(phased_id),
        message: "started App Store phased release".to_string(),
        evidence: json!({
            "provider_mode": "live",
            "app_store_version_id": app_store_version_id,
            "provider_response": response.doc,
        }),
    })
}

fn appstore_patch_phased_release_state(
    base_url: &str,
    token: &str,
    provider_doc: &Value,
    exec_doc: &Value,
    app_store_version_id: &str,
    phased_release_state: &str,
    message: &str,
) -> Result<DeviceProviderStepOutcome> {
    if let Some(existing_id) = device_release_store_release_id(exec_doc) {
        return appstore_patch_phased_release_state_by_id(
            base_url,
            token,
            &existing_id,
            phased_release_state,
            message,
        );
    }
    if let Some(phased_id) = provider_option_str(provider_doc, "phased_release_id") {
        return appstore_patch_phased_release_state_by_id(
            base_url,
            token,
            &phased_id,
            phased_release_state,
            message,
        );
    }
    let Some(existing) = find_appstore_phased_release(base_url, token, app_store_version_id)?
    else {
        bail!("App Store phased release was not found for appStoreVersion={app_store_version_id}");
    };
    let phased_id = get_str(&existing, &["id"])
        .ok_or_else(|| anyhow!("App Store phased release missing id"))?;
    appstore_patch_phased_release_state_by_id(
        base_url,
        token,
        &phased_id,
        phased_release_state,
        message,
    )
}

fn appstore_patch_phased_release_state_by_id(
    base_url: &str,
    token: &str,
    phased_release_id: &str,
    phased_release_state: &str,
    message: &str,
) -> Result<DeviceProviderStepOutcome> {
    let url = format!(
        "{}/v1/appStoreVersionPhasedReleases/{}",
        base_url.trim_end_matches('/'),
        percent_encode(phased_release_id)
    );
    let body = json!({
        "data": {
            "id": phased_release_id,
            "type": "appStoreVersionPhasedReleases",
            "attributes": {
                "phasedReleaseState": phased_release_state
            }
        }
    });
    let response = provider_request_json("PATCH", &url, token, Some(&body))?;
    ensure_provider_success(&response, "PATCH", &url)?;
    let current_state = match phased_release_state {
        "PAUSED" => "paused",
        "COMPLETE" => "completed",
        _ => "in_progress",
    };
    Ok(DeviceProviderStepOutcome {
        current_state: current_state.to_string(),
        rollout_percent: if current_state == "completed" {
            Some(100)
        } else {
            None
        },
        store_release_id: Some(phased_release_id.to_string()),
        message: message.to_string(),
        evidence: json!({
            "provider_mode": "live",
            "provider_response": response.doc,
        }),
    })
}

fn apply_googleplay_device_release_op(
    credentials: &GooglePlayCredentials,
    provider_doc: &Value,
    exec_doc: &Value,
    step_doc: &Value,
) -> Result<DeviceProviderStepOutcome> {
    let access_token = googleplay_access_token(credentials, provider_doc)?;
    let base_url = device_provider_base_url(
        provider_doc,
        credentials.base_url.as_deref(),
        GOOGLE_PLAY_DEFAULT_BASE_URL,
    );
    let package_name = googleplay_package_name(provider_doc)?;
    let track = googleplay_track(provider_doc);
    let op = get_str(step_doc, &["op"]).ok_or_else(|| anyhow!("step missing op"))?;
    match op.as_str() {
        "release.start" => {
            let rollout_percent =
                if get_str(provider_doc, &["distribution_lane"]).as_deref() == Some("production") {
                    Some(device_release_initial_percent(provider_doc))
                } else {
                    Some(100)
                };
            googleplay_update_release(
                &base_url,
                &access_token,
                &package_name,
                &track,
                provider_doc,
                exec_doc,
                GooglePlayReleaseUpdate {
                    status: googleplay_release_status_for_percent(provider_doc, rollout_percent),
                    rollout_percent,
                    message: "started Google Play release",
                },
            )
        }
        "rollout.set_percent" => {
            let percent = get_u64(step_doc, &["percent"])
                .ok_or_else(|| anyhow!("rollout.set_percent requires percent"))?
                .min(100);
            googleplay_update_release(
                &base_url,
                &access_token,
                &package_name,
                &track,
                provider_doc,
                exec_doc,
                GooglePlayReleaseUpdate {
                    status: googleplay_release_status_for_percent(provider_doc, Some(percent)),
                    rollout_percent: Some(percent),
                    message: &format!("updated Google Play rollout to {percent}%"),
                },
            )
        }
        "release.pause" => googleplay_update_release(
            &base_url,
            &access_token,
            &package_name,
            &track,
            provider_doc,
            exec_doc,
            GooglePlayReleaseUpdate {
                status: "halted",
                rollout_percent: device_release_current_percent(exec_doc),
                message: "paused Google Play rollout",
            },
        ),
        "release.resume" => {
            let percent = device_release_current_percent(exec_doc)
                .or_else(|| Some(device_release_initial_percent(provider_doc)));
            googleplay_update_release(
                &base_url,
                &access_token,
                &package_name,
                &track,
                provider_doc,
                exec_doc,
                GooglePlayReleaseUpdate {
                    status: googleplay_release_status_for_percent(provider_doc, percent),
                    rollout_percent: percent,
                    message: "resumed Google Play rollout",
                },
            )
        }
        "release.complete" => googleplay_update_release(
            &base_url,
            &access_token,
            &package_name,
            &track,
            provider_doc,
            exec_doc,
            GooglePlayReleaseUpdate {
                status: "completed",
                rollout_percent: Some(100),
                message: "completed Google Play rollout",
            },
        ),
        "rollback.previous" => googleplay_rollback_previous(
            &base_url,
            &access_token,
            &package_name,
            &track,
            provider_doc,
            exec_doc,
        ),
        other => bail!("unsupported Google Play op={other}"),
    }
}

fn googleplay_update_release(
    base_url: &str,
    access_token: &str,
    package_name: &str,
    track: &str,
    provider_doc: &Value,
    exec_doc: &Value,
    update: GooglePlayReleaseUpdate<'_>,
) -> Result<DeviceProviderStepOutcome> {
    let edit_id = googleplay_create_edit(base_url, access_token, package_name)?;
    let url = format!(
        "{}/applications/{}/edits/{}/tracks/{}",
        base_url.trim_end_matches('/'),
        percent_encode(package_name),
        percent_encode(&edit_id),
        percent_encode(track)
    );
    let release_name = format!(
        "{} ({})",
        get_str(exec_doc, &["meta", "app", "version"]).unwrap_or_else(|| "0.0.0".to_string()),
        get_str(exec_doc, &["meta", "app", "build"]).unwrap_or_else(|| "0".to_string())
    );
    let version_codes = googleplay_version_codes(provider_doc, exec_doc);
    let mut release = json!({
        "name": release_name,
        "status": update.status,
        "versionCodes": version_codes,
    });
    if let Some(percent) = update.rollout_percent
        && update.status == "inProgress"
        && percent < 100
    {
        ensure_object(&mut release)
            .insert("userFraction".to_string(), json!((percent as f64) / 100.0));
    }
    let body = json!({
        "track": track,
        "releases": [release]
    });
    let response = provider_request_json("PUT", &url, access_token, Some(&body))?;
    ensure_provider_success(&response, "PUT", &url)?;
    googleplay_commit_edit(base_url, access_token, package_name, &edit_id)?;
    let current_state = match update.status {
        "completed" if get_str(provider_doc, &["distribution_lane"]).as_deref() == Some("beta") => {
            "available"
        }
        "completed" => "completed",
        "halted" => "paused",
        _ => "in_progress",
    };
    Ok(DeviceProviderStepOutcome {
        current_state: current_state.to_string(),
        rollout_percent: update.rollout_percent,
        store_release_id: Some(format!("track:{track}")),
        message: update.message.to_string(),
        evidence: json!({
            "provider_mode": "live",
            "edit_id": edit_id,
            "track": track,
            "provider_response": response.doc,
        }),
    })
}

fn googleplay_rollback_previous(
    base_url: &str,
    access_token: &str,
    package_name: &str,
    track: &str,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<DeviceProviderStepOutcome> {
    let edit_id = googleplay_create_edit(base_url, access_token, package_name)?;
    let track_doc = googleplay_get_track(base_url, access_token, package_name, &edit_id, track)?;
    let current_codes = googleplay_version_codes(provider_doc, exec_doc);
    let Some(previous_release) = track_doc
        .get("releases")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find(|item| {
                let Some(version_codes) = item.get("versionCodes").and_then(Value::as_array) else {
                    return false;
                };
                !version_codes.iter().any(|value| {
                    value
                        .as_str()
                        .map(|candidate| current_codes.iter().any(|code| code == candidate))
                        .unwrap_or(false)
                })
            })
        })
        .cloned()
    else {
        bail!(
            "Google Play rollback.previous requires a previously completed release on the target track"
        );
    };
    let url = format!(
        "{}/applications/{}/edits/{}/tracks/{}",
        base_url.trim_end_matches('/'),
        percent_encode(package_name),
        percent_encode(&edit_id),
        percent_encode(track)
    );
    let mut rollback_release = previous_release;
    let rollback_map = ensure_object(&mut rollback_release);
    rollback_map.insert("status".to_string(), json!("completed"));
    rollback_map.remove("userFraction");
    let body = json!({
        "track": track,
        "releases": [rollback_release]
    });
    let response = provider_request_json("PUT", &url, access_token, Some(&body))?;
    ensure_provider_success(&response, "PUT", &url)?;
    googleplay_commit_edit(base_url, access_token, package_name, &edit_id)?;
    Ok(DeviceProviderStepOutcome {
        current_state: "rolled_back".to_string(),
        rollout_percent: Some(0),
        store_release_id: Some(format!("track:{track}")),
        message: "rolled back Google Play track to the previous release".to_string(),
        evidence: json!({
            "provider_mode": "live",
            "edit_id": edit_id,
            "track": track,
            "provider_response": response.doc,
        }),
    })
}

fn googleplay_create_edit(
    base_url: &str,
    access_token: &str,
    package_name: &str,
) -> Result<String> {
    let url = format!(
        "{}/applications/{}/edits",
        base_url.trim_end_matches('/'),
        percent_encode(package_name)
    );
    let response = provider_request_json("POST", &url, access_token, Some(&json!({})))?;
    ensure_provider_success(&response, "POST", &url)?;
    get_str(&response.doc, &["id"])
        .ok_or_else(|| anyhow!("Google Play edit create response missing id"))
}

fn googleplay_get_track(
    base_url: &str,
    access_token: &str,
    package_name: &str,
    edit_id: &str,
    track: &str,
) -> Result<Value> {
    let url = format!(
        "{}/applications/{}/edits/{}/tracks/{}",
        base_url.trim_end_matches('/'),
        percent_encode(package_name),
        percent_encode(edit_id),
        percent_encode(track)
    );
    let response = provider_request_json("GET", &url, access_token, None)?;
    ensure_provider_success(&response, "GET", &url)?;
    Ok(response.doc)
}

fn googleplay_commit_edit(
    base_url: &str,
    access_token: &str,
    package_name: &str,
    edit_id: &str,
) -> Result<()> {
    let url = format!(
        "{}/applications/{}/edits/{}:commit",
        base_url.trim_end_matches('/'),
        percent_encode(package_name),
        percent_encode(edit_id)
    );
    let response = provider_request_json("POST", &url, access_token, Some(&json!({})))?;
    ensure_provider_success(&response, "POST", &url)?;
    Ok(())
}

fn googleplay_access_token(
    credentials: &GooglePlayCredentials,
    provider_doc: &Value,
) -> Result<String> {
    let token_url = provider_option_str(provider_doc, "token_url")
        .or_else(|| credentials.token_uri.clone())
        .unwrap_or_else(|| GOOGLE_PLAY_DEFAULT_TOKEN_URL.to_string());
    let now = now_unix_seconds();
    let claims = GooglePlayClaims {
        iss: credentials.client_email.clone(),
        scope: GOOGLE_PLAY_SCOPE.to_string(),
        aud: token_url.clone(),
        exp: (now + 3600) as usize,
        iat: now as usize,
    };
    let header = Header::new(Algorithm::RS256);
    let assertion = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(credentials.private_key_pem.as_bytes())
            .context("load Google Play service-account private key")?,
    )
    .context("encode Google Play service-account JWT")?;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", &assertion)
        .finish();
    let response = provider_request_form(&token_url, &form)?;
    ensure_provider_success(&response, "POST", &token_url)?;
    get_str(&response.doc, &["access_token"])
        .ok_or_else(|| anyhow!("Google OAuth token response missing access_token"))
}

fn build_appstore_bearer_token(credentials: &AppStoreConnectCredentials) -> Result<String> {
    let now = now_unix_seconds();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(credentials.key_id.clone());
    let claims = AppStoreConnectClaims {
        iss: credentials.issuer_id.clone(),
        aud: APPSTORE_AUD.to_string(),
        exp: (now + 1_200) as usize,
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(credentials.private_key_pem.as_bytes())
            .context("load App Store Connect private key")?,
    )
    .context("encode App Store Connect JWT")
}

fn resolve_appstore_app_id(base_url: &str, token: &str, provider_doc: &Value) -> Result<String> {
    if let Some(app_id) = provider_option_str(provider_doc, "app_id") {
        return Ok(app_id);
    }
    let bundle_id = get_str(provider_doc, &["app_ref", "bundle_id"])
        .ok_or_else(|| anyhow!("provider profile missing app_ref.bundle_id"))?;
    let url = format!(
        "{}/v1/apps?filter[bundleId]={}&limit=1",
        base_url.trim_end_matches('/'),
        percent_encode(&bundle_id)
    );
    let response = provider_request_json("GET", &url, token, None)?;
    ensure_provider_success(&response, "GET", &url)?;
    response
        .doc
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("App Store Connect app lookup returned no matching app"))
}

fn resolve_appstore_version_id(
    base_url: &str,
    token: &str,
    provider_doc: &Value,
    exec_doc: &Value,
) -> Result<String> {
    if let Some(version_id) = provider_option_str(provider_doc, "app_store_version_id") {
        return Ok(version_id);
    }
    let app_id = resolve_appstore_app_id(base_url, token, provider_doc)?;
    let version = get_str(exec_doc, &["meta", "app", "version"])
        .ok_or_else(|| anyhow!("device release execution missing app.version"))?;
    let url = format!(
        "{}/v1/appStoreVersions?filter[app]={}&filter[versionString]={}&filter[platform]=IOS&limit=1",
        base_url.trim_end_matches('/'),
        percent_encode(&app_id),
        percent_encode(&version)
    );
    let response = provider_request_json("GET", &url, token, None)?;
    ensure_provider_success(&response, "GET", &url)?;
    response
        .doc
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow!("App Store Connect version lookup returned no matching appStoreVersion")
        })
}

fn resolve_appstore_build_id(
    base_url: &str,
    token: &str,
    provider_doc: &Value,
    exec_doc: &Value,
    app_id: &str,
) -> Result<String> {
    if let Some(build_id) = provider_option_str(provider_doc, "build_id") {
        return Ok(build_id);
    }
    let build = get_str(exec_doc, &["meta", "app", "build"])
        .ok_or_else(|| anyhow!("device release execution missing app.build"))?;
    let url = format!(
        "{}/v1/builds?filter[app]={}&filter[version]={}&limit=1",
        base_url.trim_end_matches('/'),
        percent_encode(app_id),
        percent_encode(&build)
    );
    let response = provider_request_json("GET", &url, token, None)?;
    ensure_provider_success(&response, "GET", &url)?;
    response
        .doc
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("App Store Connect build lookup returned no matching build"))
}

fn find_appstore_phased_release(
    base_url: &str,
    token: &str,
    app_store_version_id: &str,
) -> Result<Option<Value>> {
    let url = format!(
        "{}/v1/appStoreVersions/{}/appStoreVersionPhasedRelease",
        base_url.trim_end_matches('/'),
        percent_encode(app_store_version_id)
    );
    let response = provider_request_json("GET", &url, token, None)?;
    if response.status == 404 {
        return Ok(None);
    }
    ensure_provider_success(&response, "GET", &url)?;
    Ok(response.doc.get("data").cloned())
}

fn googleplay_package_name(provider_doc: &Value) -> Result<String> {
    get_str(provider_doc, &["app_ref", "package_name"])
        .ok_or_else(|| anyhow!("provider profile missing app_ref.package_name"))
}

fn googleplay_track(provider_doc: &Value) -> String {
    get_str(provider_doc, &["track"]).unwrap_or_else(|| {
        match get_str(provider_doc, &["distribution_lane"]).as_deref() {
            Some("beta") => "internal".to_string(),
            _ => "production".to_string(),
        }
    })
}

fn googleplay_version_codes(provider_doc: &Value, exec_doc: &Value) -> Vec<String> {
    if let Some(items) =
        get_path(provider_doc, &["provider_options", "version_codes"]).and_then(Value::as_array)
    {
        let version_codes = items
            .iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        if !version_codes.is_empty() {
            return version_codes;
        }
    }
    vec![get_str(exec_doc, &["meta", "app", "build"]).unwrap_or_else(|| "0".to_string())]
}

fn googleplay_release_status_for_percent(
    provider_doc: &Value,
    rollout_percent: Option<u64>,
) -> &'static str {
    match get_str(provider_doc, &["distribution_lane"]).as_deref() {
        Some("beta") => "completed",
        _ if rollout_percent.unwrap_or(100) >= 100 => "completed",
        _ => "inProgress",
    }
}

fn device_provider_base_url(provider_doc: &Value, fallback: Option<&str>, default: &str) -> String {
    provider_option_str(provider_doc, "base_url")
        .or_else(|| fallback.map(ToOwned::to_owned))
        .unwrap_or_else(|| default.to_string())
}

fn provider_option_str(provider_doc: &Value, key: &str) -> Option<String> {
    get_str(provider_doc, &["provider_options", key])
}

fn provider_request_form(url: &str, body: &str) -> Result<JsonHttpResponse> {
    let response = Agent::new()
        .post(url)
        .set("accept", "application/json")
        .set("content-type", "application/x-www-form-urlencoded")
        .send_string(body);
    match response {
        Ok(response) => decode_provider_json_response(response),
        Err(UreqError::Status(_, response)) => decode_provider_json_response(response),
        Err(UreqError::Transport(err)) => bail!("provider token request failed: POST {url}: {err}"),
    }
}

fn provider_request_json(
    method: &str,
    url: &str,
    bearer_token: &str,
    body: Option<&Value>,
) -> Result<JsonHttpResponse> {
    let request = Agent::new()
        .request(method, url)
        .set("accept", "application/json")
        .set("authorization", &format!("Bearer {bearer_token}"));
    let response = match body {
        Some(doc) => request
            .set("content-type", "application/json")
            .send_json(doc.clone()),
        None => request.call(),
    };
    match response {
        Ok(response) => decode_provider_json_response(response),
        Err(UreqError::Status(_, response)) => decode_provider_json_response(response),
        Err(UreqError::Transport(err)) => bail!("provider request failed: {method} {url}: {err}"),
    }
}

fn decode_provider_json_response(response: ureq::Response) -> Result<JsonHttpResponse> {
    let status = response.status();
    let text = response
        .into_string()
        .context("read provider response body")?;
    let doc = if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&text).context("parse provider response json")?
    };
    Ok(JsonHttpResponse { status, doc })
}

fn ensure_provider_success(response: &JsonHttpResponse, method: &str, url: &str) -> Result<()> {
    if (200..300).contains(&response.status) {
        return Ok(());
    }
    bail!(
        "provider request failed: {} {}: status {}: {}",
        method,
        url,
        response.status,
        provider_error_summary(&response.doc)
    )
}

fn provider_error_summary(doc: &Value) -> String {
    if let Some(message) = get_str(doc, &["error", "message"]) {
        return message;
    }
    if let Some(message) = get_str(doc, &["error_description"]) {
        return message;
    }
    if let Some(items) = doc.get("errors").and_then(Value::as_array)
        && let Some(item) = items.first()
    {
        return get_str(item, &["detail"])
            .or_else(|| get_str(item, &["title"]))
            .unwrap_or_else(|| "provider returned an error payload".to_string());
    }
    serde_json::to_string(doc).unwrap_or_else(|_| "provider returned an error payload".to_string())
}

fn percent_encode(raw: &str) -> String {
    byte_serialize(raw.as_bytes()).collect::<String>()
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
