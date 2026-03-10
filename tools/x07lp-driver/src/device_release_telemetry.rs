use super::*;

const DEVICE_RELEASE_SNAPSHOT_TAKEN_AT_UTC: &str = "2026-03-09T00:00:00Z";
const DEVICE_RELEASE_STANDARD_EVENT_CLASSES: &[&str] = &[
    "app.lifecycle",
    "app.http",
    "runtime.error",
    "bridge.timing",
    "reducer.timing",
    "policy.violation",
    "host.webview_crash",
];

#[derive(Debug, Clone)]
pub(super) struct DeviceTelemetryIncident {
    pub classification: String,
    pub reason: String,
    pub source: String,
    pub native_context_patch: Value,
}

#[derive(Debug, Clone)]
pub(super) struct DeviceTelemetryAnalysis {
    pub snapshot: Value,
    pub incidents: Vec<DeviceTelemetryIncident>,
}

#[derive(Debug, Clone)]
struct DeviceTelemetryRecord {
    class_name: String,
    event_name: String,
    body: Option<String>,
    attrs: BTreeMap<String, Value>,
}

pub(super) fn standard_device_release_event_classes() -> Vec<Value> {
    DEVICE_RELEASE_STANDARD_EVENT_CLASSES
        .iter()
        .map(|name| json!(name))
        .collect()
}

pub(super) fn patch_device_release_telemetry_profile(
    telemetry_doc: &Value,
    exec_id: &str,
    plan_id: &str,
    package_sha256: &str,
    app_id: &str,
    target: &str,
    provider_kind: &str,
    provider_lane: &str,
    rollout_percent: Option<u64>,
) -> Value {
    let mut patched = telemetry_doc.clone();
    let root = ensure_object(&mut patched);
    root.insert(
        "schema_version".to_string(),
        json!("x07.device.telemetry.profile@0.1.0"),
    );
    root.insert(
        "event_classes".to_string(),
        Value::Array(standard_device_release_event_classes()),
    );
    let resource = root
        .entry("resource".to_string())
        .or_insert_with(|| json!({}));
    if !resource.is_object() {
        *resource = json!({});
    }
    let resource_map = ensure_object(resource);
    resource_map.insert("app_id".to_string(), json!(app_id));
    resource_map.insert("target".to_string(), json!(target));
    resource_map.insert("release_exec_id".to_string(), json!(exec_id));
    resource_map.insert("release_plan_id".to_string(), json!(plan_id));
    resource_map.insert("package_sha256".to_string(), json!(package_sha256));
    resource_map.insert("provider_kind".to_string(), json!(provider_kind));
    resource_map.insert("provider_lane".to_string(), json!(provider_lane));
    resource_map.insert(
        "rollout_percent".to_string(),
        rollout_percent.map(Value::from).unwrap_or(Value::Null),
    );
    patched
}

pub(super) fn analyze_device_release_otlp_export(
    export_path: &Path,
    exec_doc: &Value,
    provider_doc: &Value,
) -> Result<DeviceTelemetryAnalysis> {
    let exec_id =
        get_str(exec_doc, &["exec_id"]).ok_or_else(|| anyhow!("missing device release exec_id"))?;
    let plan_id =
        get_str(exec_doc, &["plan_id"]).ok_or_else(|| anyhow!("missing device release plan_id"))?;
    let app_id = get_str(exec_doc, &["meta", "app", "app_id"]).unwrap_or_default();
    let package_sha256 =
        get_str(exec_doc, &["meta", "package_digest", "sha256"]).unwrap_or_default();
    let provider_kind = get_str(provider_doc, &["provider_kind"]).unwrap_or_default();
    let provider_lane = get_str(provider_doc, &["distribution_lane"]).unwrap_or_default();
    let rollout_percent = get_path(exec_doc, &["meta", "current_rollout_percent"])
        .cloned()
        .unwrap_or(Value::Null);

    let file = fs::File::open(export_path)
        .with_context(|| format!("open device telemetry export {}", export_path.display()))?;
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let doc: Value = serde_json::from_str(&line).with_context(|| {
            format!(
                "parse device telemetry export line {}",
                export_path.display()
            )
        })?;
        records.extend(extract_matching_records(
            &doc,
            &exec_id,
            &plan_id,
            &app_id,
            &package_sha256,
        ));
    }

    if records.is_empty() {
        bail!(
            "device telemetry export did not contain any release-correlated OTLP log records: {}",
            export_path.display()
        );
    }

    let mut latencies_ms = Vec::new();
    let mut total_http = 0u64;
    let mut http_failures = 0u64;
    let mut http_successes = 0u64;
    let mut incident_map = BTreeMap::<String, DeviceTelemetryIncident>::new();
    let native_context_patch = build_native_context_patch(&records);

    for record in &records {
        match record.class_name.as_str() {
            "app.http" => {
                total_http += 1;
                if let Some(duration_ms) = attr_f64(&record.attrs, "duration_ms") {
                    latencies_ms.push(duration_ms);
                }
                match attr_u64(&record.attrs, "status") {
                    Some(status) if status >= 500 => http_failures += 1,
                    Some(_) => http_successes += 1,
                    None => http_failures += 1,
                }
            }
            "runtime.error" => {
                let classification = runtime_error_classification(record);
                incident_map
                    .entry(classification.clone())
                    .or_insert_with(|| DeviceTelemetryIncident {
                        classification,
                        reason: incident_reason(record),
                        source: "device_host".to_string(),
                        native_context_patch: native_context_patch.clone(),
                    });
            }
            "policy.violation" => {
                let classification = if is_permission_block(record) {
                    "native_permission_blocked".to_string()
                } else {
                    "native_policy_violation".to_string()
                };
                incident_map
                    .entry(classification.clone())
                    .or_insert_with(|| DeviceTelemetryIncident {
                        classification,
                        reason: incident_reason(record),
                        source: "device_host".to_string(),
                        native_context_patch: native_context_patch.clone(),
                    });
            }
            "host.webview_crash" => {
                incident_map
                    .entry("native_host_crash".to_string())
                    .or_insert_with(|| DeviceTelemetryIncident {
                        classification: "native_host_crash".to_string(),
                        reason: incident_reason(record),
                        source: "device_host".to_string(),
                        native_context_patch: native_context_patch.clone(),
                    });
            }
            _ => {}
        }
    }

    let (error_rate, availability, latency_p95_ms) = if total_http == 0 {
        if incident_map.is_empty() {
            bail!(
                "device telemetry export did not contain any app.http records: {}",
                export_path.display()
            );
        }
        (1.0, 0.0, 0.0)
    } else {
        (
            http_failures as f64 / total_http as f64,
            http_successes as f64 / total_http as f64,
            percentile_ms(&latencies_ms, 0.95),
        )
    };

    let mut labels = serde_json::Map::new();
    labels.insert("app".to_string(), json!(app_id));
    labels.insert("env".to_string(), json!("device_release"));
    labels.insert("x07.release.exec_id".to_string(), json!(exec_id));
    labels.insert("x07.release.plan_id".to_string(), json!(plan_id));
    labels.insert("x07.package.sha256".to_string(), json!(package_sha256));
    labels.insert("x07.provider.kind".to_string(), json!(provider_kind));
    labels.insert("x07.provider.lane".to_string(), json!(provider_lane));
    if let Some(percent) = rollout_percent.as_u64() {
        labels.insert(
            "x07.rollout.percent".to_string(),
            json!(percent.to_string()),
        );
    }
    labels.insert(
        "x07.telemetry_source".to_string(),
        json!("device_otlp_logs"),
    );

    let snapshot = json!({
        "schema_version": "x07.metrics.snapshot@0.1.0",
        "v": 1,
        "taken_at_utc": DEVICE_RELEASE_SNAPSHOT_TAKEN_AT_UTC,
        "service": "device_release",
        "metrics": [
            { "name": "http_error_rate", "value": error_rate, "unit": "ratio" },
            { "name": "http_latency_p95_ms", "value": latency_p95_ms, "unit": "ms" },
            { "name": "http_availability", "value": availability, "unit": "ratio" }
        ],
        "labels": labels,
    });
    Ok(DeviceTelemetryAnalysis {
        snapshot,
        incidents: incident_map.into_values().collect(),
    })
}

fn extract_matching_records(
    doc: &Value,
    exec_id: &str,
    plan_id: &str,
    app_id: &str,
    package_sha256: &str,
) -> Vec<DeviceTelemetryRecord> {
    let mut out = Vec::new();
    let resource_logs = doc
        .get("resourceLogs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for resource_log in resource_logs {
        let resource_attrs = otlp_attributes_to_map(
            resource_log
                .pointer("/resource/attributes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
        );
        if !resource_matches_release(&resource_attrs, exec_id, plan_id, app_id, package_sha256) {
            continue;
        }
        let scope_logs = resource_log
            .get("scopeLogs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for scope_log in scope_logs {
            let records = scope_log
                .get("logRecords")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for record in records {
                let attrs = otlp_attributes_to_map(
                    record
                        .get("attributes")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                        .as_slice(),
                );
                let class_name = attr_string(&attrs, "x07.event.class").unwrap_or_default();
                if class_name.is_empty() {
                    continue;
                }
                let event_name = record
                    .get("eventName")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .or_else(|| attr_string(&attrs, "x07.event.name"))
                    .unwrap_or_else(|| class_name.clone());
                let body = record
                    .get("body")
                    .and_then(otlp_any_value_to_value)
                    .and_then(|value| value.as_str().map(ToOwned::to_owned));
                out.push(DeviceTelemetryRecord {
                    class_name,
                    event_name,
                    body,
                    attrs,
                });
            }
        }
    }
    out
}

fn resource_matches_release(
    attrs: &BTreeMap<String, Value>,
    exec_id: &str,
    plan_id: &str,
    app_id: &str,
    package_sha256: &str,
) -> bool {
    if let Some(value) = attr_string(attrs, "x07.release.exec_id")
        && value != exec_id
    {
        return false;
    }
    if let Some(value) = attr_string(attrs, "x07.release.plan_id")
        && value != plan_id
    {
        return false;
    }
    if let Some(value) = attr_string(attrs, "x07.app_id")
        && !app_id.is_empty()
        && value != app_id
    {
        return false;
    }
    if let Some(value) = attr_string(attrs, "x07.package.sha256")
        && !package_sha256.is_empty()
        && value != package_sha256
    {
        return false;
    }
    true
}

fn runtime_error_classification(record: &DeviceTelemetryRecord) -> String {
    let stage = attr_string(&record.attrs, "stage")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body = record.body.clone().unwrap_or_default().to_ascii_lowercase();
    if is_permission_block(record) {
        "native_permission_blocked".to_string()
    } else if stage.contains("bridge")
        || body.contains("bridge")
        || stage.contains("timeout")
        || body.contains("timeout")
    {
        "native_bridge_timeout".to_string()
    } else {
        "native_runtime_error".to_string()
    }
}

fn incident_reason(record: &DeviceTelemetryRecord) -> String {
    attr_string(&record.attrs, "message")
        .or_else(|| record.body.clone())
        .unwrap_or_else(|| format!("device telemetry incident: {}", record.event_name))
}

fn is_permission_block(record: &DeviceTelemetryRecord) -> bool {
    let status = attr_string(&record.attrs, "status")
        .or_else(|| attr_string(&record.attrs, "result"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let permission = attr_string(&record.attrs, "permission").unwrap_or_default();
    let body = record.body.clone().unwrap_or_default().to_ascii_lowercase();
    !permission.is_empty() && (status == "denied" || body.contains("permission") && body.contains("denied"))
}

fn build_native_context_patch(records: &[DeviceTelemetryRecord]) -> Value {
    let mut permission_state_snapshot = serde_json::Map::new();
    let mut lifecycle_state = Value::Null;
    let mut connectivity_state = Value::Null;
    let mut breadcrumbs = Vec::new();
    for record in records.iter().rev().take(8).collect::<Vec<_>>().into_iter().rev() {
        if let Some(permission) = attr_string(&record.attrs, "permission") {
            if let Some(status) = attr_string(&record.attrs, "status")
                .or_else(|| attr_string(&record.attrs, "result"))
            {
                permission_state_snapshot.insert(permission, json!(status));
            }
        }
        if record.class_name == "app.lifecycle" && lifecycle_state.is_null() {
            lifecycle_state = attr_string(&record.attrs, "state")
                .map(Value::String)
                .unwrap_or_else(|| json!(record.event_name.clone()));
        }
        if connectivity_state.is_null() {
            if let Some(state) = attr_string(&record.attrs, "connectivity_state")
                .or_else(|| attr_string(&record.attrs, "network_state"))
            {
                connectivity_state = json!(state);
            }
        }
        let mut breadcrumb = json!({
            "ord": breadcrumbs.len() as u64,
            "event_class": record.class_name,
            "op": attr_string(&record.attrs, "op").or_else(|| attr_string(&record.attrs, "operation")).unwrap_or_else(|| record.event_name.clone()),
            "status": attr_string(&record.attrs, "status").or_else(|| attr_string(&record.attrs, "result")).unwrap_or_default(),
            "request_id": attr_string(&record.attrs, "request_id"),
            "unix_ms": attr_u64(&record.attrs, "unix_ms").or_else(|| attr_u64(&record.attrs, "timestamp_unix_ms")),
        });
        if let Some(duration_ms) = attr_f64(&record.attrs, "duration_ms") {
            ensure_object(&mut breadcrumb).insert("duration_ms".to_string(), json!(duration_ms));
        }
        breadcrumbs.push(breadcrumb);
    }
    json!({
        "permission_state_snapshot": if permission_state_snapshot.is_empty() { Value::Null } else { Value::Object(permission_state_snapshot) },
        "lifecycle_state": lifecycle_state,
        "connectivity_state": connectivity_state,
        "breadcrumbs": breadcrumbs,
    })
}

fn attr_string(attrs: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|value| match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn attr_u64(attrs: &BTreeMap<String, Value>, key: &str) -> Option<u64> {
    attrs.get(key).and_then(|value| match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().map(|raw| raw.max(0) as u64)),
        Value::String(text) => text.parse::<u64>().ok(),
        _ => None,
    })
}

fn attr_f64(attrs: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    attrs.get(key).and_then(|value| match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse::<f64>().ok(),
        _ => None,
    })
}

fn otlp_attributes_to_map(items: &[Value]) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for item in items {
        let Some(key) = item.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = item.get("value").and_then(otlp_any_value_to_value) else {
            continue;
        };
        out.insert(key.to_string(), value);
    }
    out
}

fn otlp_any_value_to_value(doc: &Value) -> Option<Value> {
    if let Some(value) = doc.get("stringValue").and_then(Value::as_str) {
        return Some(Value::String(value.to_string()));
    }
    if let Some(value) = doc.get("intValue") {
        return match value {
            Value::String(text) => text.parse::<i64>().ok().map(Value::from),
            Value::Number(number) => number.as_i64().map(Value::from),
            _ => None,
        };
    }
    if let Some(value) = doc.get("doubleValue").and_then(Value::as_f64) {
        return Some(json!(value));
    }
    if let Some(value) = doc.get("boolValue").and_then(Value::as_bool) {
        return Some(json!(value));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_profile_sets_release_resource_fields_and_required_events() {
        let patched = patch_device_release_telemetry_profile(
            &json!({
                "schema_version": "x07.device.telemetry.profile@0.1.0",
                "transport": {
                    "protocol": "http/json",
                    "endpoint": "https://collector.example.invalid"
                },
                "event_classes": ["release.lifecycle", "release.error"]
            }),
            "lpdrexec_demo",
            "lpdrplan_demo",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "io.x07.demo.ios",
            "ios",
            "googleplay_v1",
            "production",
            Some(25),
        );
        assert_eq!(
            get_str(&patched, &["resource", "release_exec_id"]).as_deref(),
            Some("lpdrexec_demo")
        );
        assert_eq!(
            patched
                .get("event_classes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(7)
        );
    }

    #[test]
    fn analyze_otlp_export_builds_snapshot_and_incidents() {
        let tmp = std::env::temp_dir().join(format!("x07lp-telemetry-{}", now_ms()));
        let export_path = tmp.join("events.jsonl");
        fs::create_dir_all(&tmp).expect("create tmp dir");
        write_bytes(
            &export_path,
            br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"x07.release.exec_id","value":{"stringValue":"lpdrexec_demo"}},{"key":"x07.release.plan_id","value":{"stringValue":"lpdrplan_demo"}},{"key":"x07.app_id","value":{"stringValue":"io.x07.demo.ios"}},{"key":"x07.package.sha256","value":{"stringValue":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"app.http"},"attributes":[{"key":"x07.event.class","value":{"stringValue":"app.http"}},{"key":"x07.event.name","value":{"stringValue":"app.http"}},{"key":"status","value":{"intValue":"200"}},{"key":"duration_ms","value":{"doubleValue":90.0}}]},{"body":{"stringValue":"app.http"},"attributes":[{"key":"x07.event.class","value":{"stringValue":"app.http"}},{"key":"x07.event.name","value":{"stringValue":"app.http"}},{"key":"status","value":{"intValue":"200"}},{"key":"duration_ms","value":{"doubleValue":110.0}}]},{"body":{"stringValue":"runtime.error"},"attributes":[{"key":"x07.event.class","value":{"stringValue":"runtime.error"}},{"key":"x07.event.name","value":{"stringValue":"runtime.error"}},{"key":"stage","value":{"stringValue":"bridge_parse"}},{"key":"message","value":{"stringValue":"boom"}}]},{"body":{"stringValue":"policy.violation"},"attributes":[{"key":"x07.event.class","value":{"stringValue":"policy.violation"}},{"key":"x07.event.name","value":{"stringValue":"policy.violation"}},{"key":"message","value":{"stringValue":"policy blocked rollout"}}]},{"body":{"stringValue":"host.webview_crash"},"attributes":[{"key":"x07.event.class","value":{"stringValue":"host.webview_crash"}},{"key":"x07.event.name","value":{"stringValue":"host.webview_crash"}},{"key":"message","value":{"stringValue":"webview crashed"}}]}]}]}]}
"#,
        )
        .expect("write export");
        let exec_doc = json!({
            "exec_id": "lpdrexec_demo",
            "plan_id": "lpdrplan_demo",
            "meta": {
                "app": { "app_id": "io.x07.demo.ios" },
                "package_digest": {
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        });
        let provider_doc = json!({
            "provider_kind": "appstoreconnect_v1",
            "distribution_lane": "production"
        });
        let analysis = analyze_device_release_otlp_export(&export_path, &exec_doc, &provider_doc)
            .expect("analyze");
        assert_eq!(
            get_str(&analysis.snapshot, &["schema_version"]).as_deref(),
            Some("x07.metrics.snapshot@0.1.0")
        );
        let classes = analysis
            .incidents
            .iter()
            .map(|incident| incident.classification.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(classes.len(), 3);
        assert!(classes.contains("native_bridge_timeout"));
        assert!(classes.contains("native_policy_violation"));
        assert!(classes.contains("native_host_crash"));
        assert!(analysis
            .incidents
            .iter()
            .all(|incident| incident.native_context_patch.is_object()));
    }
}
