const POLL_INTERVAL_MS = 3000;

const root = document.getElementById("app");
if (!root) {
  throw new Error("missing #app");
}
document.title = "x07 Command Center";

const state = {
  route: parseRoute(window.location.pathname || "/apps"),
  loading: false,
  error: null,
  actionResult: null,
  actionPending: null,
  data: {},
  requestToken: 0,
};

installStyles();

window.addEventListener("popstate", () => {
  state.route = parseRoute(window.location.pathname || "/apps");
  void refresh();
});

function normalizePath(pathname) {
  if (!pathname || pathname === "/") {
    return "/device-releases";
  }
  return pathname.endsWith("/") && pathname.length > 1 ? pathname.slice(0, -1) : pathname;
}

function parseRoute(pathname) {
  const path = normalizePath(pathname);
  if (path === "/device-releases") {
    return { kind: "deviceReleaseList", path };
  }
  const deviceReleaseMatch = path.match(/^\/device-releases\/([^/]+)$/);
  if (deviceReleaseMatch) {
    return { kind: "deviceRelease", execId: decodeURIComponent(deviceReleaseMatch[1]), path };
  }
  const deploymentMatch = path.match(/^\/deployments\/([^/]+)$/);
  if (deploymentMatch) {
    return { kind: "deployment", execId: decodeURIComponent(deploymentMatch[1]), path };
  }
  const incidentMatch = path.match(/^\/incidents\/([^/]+)$/);
  if (incidentMatch) {
    return { kind: "incident", incidentId: decodeURIComponent(incidentMatch[1]), path };
  }
  return { kind: "apps", path: "/apps" };
}

function encodePathSegment(value) {
  return encodeURIComponent(String(value ?? ""));
}

function deploymentHref(execId) {
  return `/deployments/${encodePathSegment(execId)}`;
}

function incidentHref(incidentId) {
  return `/incidents/${encodePathSegment(incidentId)}`;
}

function deviceReleaseHref(execId) {
  return `/device-releases/${encodePathSegment(execId)}`;
}

function navigate(path, { replace = false } = {}) {
  const normalized = normalizePath(path);
  if (replace) {
    window.history.replaceState({}, "", normalized);
  } else if (window.location.pathname !== normalized) {
    window.history.pushState({}, "", normalized);
  }
  state.route = parseRoute(normalized);
  void refresh();
}

async function fetchJson(url, init) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: {
      "content-type": "application/json",
    },
    ...init,
  });
  const text = await response.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch (error) {
      const parseError = new Error(`failed to parse JSON from ${url}`);
      parseError.cause = error;
      parseError.status = response.status;
      parseError.text = text;
      throw parseError;
    }
  }
  if (!response.ok) {
    const httpError = new Error(`HTTP ${response.status} for ${url}`);
    httpError.status = response.status;
    httpError.json = json;
    httpError.text = text;
    throw httpError;
  }
  return json;
}

function unwrapResult(doc) {
  if (doc && typeof doc === "object" && doc.result && typeof doc.result === "object") {
    return doc.result;
  }
  return doc;
}

function getItems(doc) {
  const result = unwrapResult(doc);
  return Array.isArray(result?.items) ? result.items : [];
}

function getTargetApp(result) {
  return unwrapResult(result)?.target?.app_id ?? null;
}

function getTargetEnv(result) {
  return unwrapResult(result)?.target?.environment ?? null;
}

function findFirstStringByKey(node, keys) {
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findFirstStringByKey(value, keys);
      if (found) {
        return found;
      }
    }
    return null;
  }
  if (node && typeof node === "object") {
    for (const key of keys) {
      if (typeof node[key] === "string" && node[key]) {
        return node[key];
      }
    }
    for (const value of Object.values(node)) {
      const found = findFirstStringByKey(value, keys);
      if (found) {
        return found;
      }
    }
  }
  return null;
}

function formatJson(value) {
  return JSON.stringify(value, null, 2);
}

function setError(message, detail = null) {
  state.error = { message, detail };
}

function clearError() {
  state.error = null;
}

function formatError(error) {
  if (error?.json) {
    return formatJson(error.json);
  }
  if (typeof error?.text === "string" && error.text) {
    return error.text;
  }
  return String(error?.message ?? error);
}

async function refresh() {
  const token = ++state.requestToken;
  state.loading = true;
  clearError();
  render();
  try {
    if (state.route.kind === "deviceReleaseList") {
      const deviceReleases = await fetchJson("/api/device-releases");
      if (token !== state.requestToken) {
        return;
      }
      state.data = { deviceReleases };
    } else if (state.route.kind === "deviceRelease") {
      const execId = encodePathSegment(state.route.execId);
      const deviceRelease = await fetchJson(`/api/device-releases/${execId}`);
      if (token !== state.requestToken) {
        return;
      }
      state.data = { deviceRelease };
    } else if (state.route.kind === "apps") {
      const [apps, incidents] = await Promise.all([
        fetchJson("/api/apps"),
        fetchJson("/api/incidents"),
      ]);
      if (token !== state.requestToken) {
        return;
      }
      state.data = { apps, incidents };
    } else if (state.route.kind === "deployment") {
      const execId = encodePathSegment(state.route.execId);
      const [deployment, incidents] = await Promise.all([
        fetchJson(`/api/deployments/${execId}`),
        fetchJson(`/api/deployments/${execId}/incidents`),
      ]);
      if (token !== state.requestToken) {
        return;
      }
      state.data = { deployment, incidents };
    } else if (state.route.kind === "incident") {
      const incident = await fetchJson(`/api/incidents/${encodePathSegment(state.route.incidentId)}`);
      if (token !== state.requestToken) {
        return;
      }
      state.data = { incident };
    }
  } catch (error) {
    if (token !== state.requestToken) {
      return;
    }
    setError("Request failed", formatError(error));
  } finally {
    if (token === state.requestToken) {
      state.loading = false;
      render();
    }
  }
}

async function postAction(path, body, afterSuccess) {
  state.actionPending = path;
  clearError();
  render();
  try {
    const result = await fetchJson(path, {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    });
    state.actionResult = result;
    if (typeof afterSuccess === "function") {
      await afterSuccess(result);
    } else {
      await refresh();
    }
  } catch (error) {
    setError(`Action failed: ${path}`, formatError(error));
  } finally {
    state.actionPending = null;
    render();
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function append(parent, ...children) {
  for (const child of children) {
    if (child) {
      parent.appendChild(child);
    }
  }
  return parent;
}

function keyValueList(entries) {
  const dl = el("dl", "kv-list");
  for (const [key, value] of entries) {
    append(dl, el("dt", null, key), el("dd", null, value ?? "n/a"));
  }
  return dl;
}

function jsonBlock(value) {
  const pre = el("pre", "json-block");
  pre.textContent = formatJson(value);
  return pre;
}

function navButton(label, path, active = false) {
  const button = el("button", `btn ${active ? "btn-active" : ""}`, label);
  button.type = "button";
  button.disabled = !path;
  if (path) {
    button.addEventListener("click", () => navigate(path));
  }
  return button;
}

function actionButton(label, path, body, options = {}) {
  const button = el("button", `btn ${options.variant ?? ""}`.trim(), label);
  button.type = "button";
  button.disabled = !path || state.actionPending === path;
  button.addEventListener("click", () => {
    void postAction(path, body, options.afterSuccess);
  });
  return button;
}

function sectionTitle(title, subtitle) {
  const box = el("div", "section-head");
  append(box, el("h2", null, title));
  if (subtitle) {
    append(box, el("p", "muted", subtitle));
  }
  return box;
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function arrayValue(value) {
  return Array.isArray(value) ? value.filter((item) => item !== null && item !== undefined) : [];
}

function inlineValue(value, fallback = "n/a") {
  if (value === null || value === undefined) {
    return fallback;
  }
  if (typeof value === "string") {
    return value || fallback;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return fallback;
  }
}

function shortText(value, keep = 10) {
  const text = inlineValue(value, "");
  if (!text) {
    return "n/a";
  }
  return text.length > keep * 2 + 3 ? `${text.slice(0, keep)}...${text.slice(-keep)}` : text;
}

function formatPercent(value) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? `${number}%` : "n/a";
}

function formatTimestamp(value) {
  const unixMs = Number(value);
  if (!Number.isFinite(unixMs) || unixMs <= 0) {
    return "n/a";
  }
  return new Date(unixMs).toLocaleString();
}

function toneForStatus(value) {
  const status = String(value ?? "").toLowerCase();
  if (!status) {
    return "neutral";
  }
  if (
    [
      "ok",
      "healthy",
      "generated",
      "ready",
      "active",
      "complete",
      "completed",
      "released",
      "running",
      "success",
      "passed",
      "closed",
    ].includes(status)
  ) {
    return "ok";
  }
  if (
    status.includes("fail") ||
    status.includes("error") ||
    status.includes("halt") ||
    status.includes("abort") ||
    status.includes("crash") ||
    status.includes("blocked") ||
    status.includes("violation") ||
    status.includes("denied")
  ) {
    return "danger";
  }
  if (
    [
      "warning",
      "requested",
      "not_requested",
      "paused",
      "open",
      "planned",
      "draft",
      "pending",
      "in_progress",
      "manual",
    ].includes(status) ||
    status.includes("warn") ||
    status.includes("progress")
  ) {
    return "warn";
  }
  return "neutral";
}

function toneForNativeClassification(value) {
  const classification = String(value ?? "").toLowerCase();
  if (!classification) {
    return "neutral";
  }
  if (classification === "native_bridge_timeout") {
    return "warn";
  }
  return "danger";
}

function toneForRegressionStatus(value) {
  const status = String(value ?? "").toLowerCase();
  if (status === "generated") {
    return "ok";
  }
  if (status === "failed") {
    return "danger";
  }
  if (status === "requested" || status === "not_requested") {
    return "warn";
  }
  return toneForStatus(status);
}

function pill(label, tone = "neutral") {
  if (!label) {
    return null;
  }
  return el("span", `pill pill-${tone}`, label);
}

function labeledPill(label, value, tone = toneForStatus(value)) {
  const text = inlineValue(value, "");
  return text ? pill(`${label}: ${text}`, tone) : null;
}

function pillRow(items) {
  const values = items.filter(Boolean);
  if (!values.length) {
    return null;
  }
  const row = el("div", "pill-row");
  append(row, ...values);
  return row;
}

function createCard(title, subtitle) {
  const card = el("section", "card");
  append(card, sectionTitle(title, subtitle));
  return card;
}

function createSubsection(title, content) {
  const box = el("section", "subsection");
  append(box, el("h3", "mini-title", title), content);
  return box;
}

function detailsBlock(summaryText, ...children) {
  const details = el("details", "details-block");
  append(details, el("summary", null, summaryText), ...children);
  return details;
}

function textList(items, emptyText) {
  const values = arrayValue(items);
  if (!values.length) {
    return el("p", "muted", emptyText);
  }
  const list = el("ul", "bullet-list");
  for (const item of values) {
    list.appendChild(el("li", null, inlineValue(item, "")));
  }
  return list;
}

function tokenList(items, emptyText, tone = "neutral") {
  const values = arrayValue(items);
  if (!values.length) {
    return el("p", "muted", emptyText);
  }
  return pillRow(values.map((item) => pill(inlineValue(item, ""), tone)));
}

function deviceReleaseLatestIncidentId(deviceRelease) {
  return deviceRelease?.latest_native_incident_id ?? deviceRelease?.latest_native_health_rollup?.latest_native_incident_id ?? null;
}

function deviceReleaseLatestRegressionId(deviceRelease) {
  return deviceRelease?.latest_regression_id ?? deviceRelease?.latest_native_health_rollup?.latest_regression_id ?? null;
}

function deviceReleaseLatestRegressionStatus(deviceRelease) {
  return (
    deviceRelease?.latest_regression_status ??
    deviceRelease?.latest_native_health_rollup?.latest_regression_status ??
    "not_requested"
  );
}

function createHealthPills(rollup) {
  const health = objectValue(rollup) ?? {};
  const total = Number(health.native_incident_count ?? 0);
  const pills = [pill(`native incidents: ${total}`, total > 0 ? "danger" : "ok")];
  const counts = [
    ["runtime", Number(health.native_runtime_error_count ?? 0), "danger"],
    ["policy", Number(health.native_policy_violation_count ?? 0), "danger"],
    ["bridge", Number(health.native_bridge_timeout_count ?? 0), "warn"],
    ["host crash", Number(health.native_host_crash_count ?? 0), "danger"],
    ["permission", Number(health.native_permission_blocked_count ?? 0), "danger"],
  ];
  for (const [label, count, tone] of counts) {
    if (count > 0) {
      pills.push(pill(`${label}: ${count}`, tone));
    }
  }
  return pills;
}

function incidentReleaseExecId(incident) {
  return incident?.release_exec_id ?? incident?.device_release?.release_exec_id ?? incident?.native_context?.release_exec_id ?? null;
}

function incidentReleasePlanId(incident) {
  return incident?.release_plan_id ?? incident?.device_release?.release_plan_id ?? incident?.native_context?.release_plan_id ?? null;
}

function incidentTargetKind(incident) {
  return incident?.target_kind ?? incident?.device_release?.target_kind ?? incident?.native_context?.platform ?? null;
}

function incidentProviderKind(incident) {
  return incident?.provider_kind ?? incident?.device_release?.provider_kind ?? null;
}

function incidentPackageManifestSha(incident) {
  return (
    incident?.package_manifest_sha256 ??
    incident?.device_release?.package_manifest_sha256 ??
    incident?.native_context?.package_manifest_sha256 ??
    null
  );
}

function artifactLabel(ref) {
  return ref?.logical_name ?? ref?.role ?? ref?.label ?? ref?.kind ?? "artifact";
}

function renderArtifactRows(refs, emptyText) {
  const items = arrayValue(refs);
  if (!items.length) {
    return el("p", "muted", emptyText);
  }
  const box = el("div", "stack-tight");
  for (const item of items) {
    const row = el("div", "list-row");
    const copy = el("div", "list-copy");
    const subtitleBits = [
      item?.role && item.role !== artifactLabel(item) ? `role ${item.role}` : null,
      item?.store_uri ?? item?.path ?? null,
      item?.media_type ?? null,
      item?.digest?.sha256 ? shortText(item.digest.sha256, 12) : null,
    ].filter(Boolean);
    append(copy, el("div", "list-title", artifactLabel(item)));
    if (subtitleBits.length) {
      append(copy, el("div", "list-subtitle", subtitleBits.join(" · ")));
    }
    row.appendChild(copy);
    box.appendChild(row);
  }
  return box;
}

function renderIncidentRow(item, options = {}) {
  const releaseExecId = options.releaseExecId ?? incidentReleaseExecId(item);
  const row = el("div", "list-row");
  const copy = el("div", "list-copy");
  const headline = `${item?.incident_id ?? "unknown incident"} · ${item?.native_classification ?? item?.classification ?? "unknown"}`;
  const subtitleBits = [];
  if (item?.target?.app_id || item?.target?.environment) {
    subtitleBits.push(`${item.target?.app_id ?? "unknown"} / ${item.target?.environment ?? "unknown"}`);
  }
  if (item?.target_kind) {
    subtitleBits.push(`target ${item.target_kind}`);
  }
  if (releaseExecId) {
    subtitleBits.push(`release ${releaseExecId}`);
  }
  if (item?.deployment_id) {
    subtitleBits.push(`deployment ${item.deployment_id}`);
  }
  if (item?.reason) {
    subtitleBits.push(inlineValue(item.reason, ""));
  }
  append(copy, el("div", "list-title", headline));
  if (subtitleBits.length) {
    append(copy, el("div", "list-subtitle", subtitleBits.join(" · ")));
  }
  append(
    copy,
    pillRow([
      item?.native_classification
        ? pill(item.native_classification, toneForNativeClassification(item.native_classification))
        : item?.classification
          ? pill(item.classification, toneForStatus(item.classification))
          : null,
      item?.incident_status ? labeledPill("status", item.incident_status) : null,
      item?.regression_status && item.regression_status !== "not_requested"
        ? labeledPill("regression", item.regression_status, toneForRegressionStatus(item.regression_status))
        : null,
      item?.provider_kind ? labeledPill("provider", item.provider_kind, "neutral") : null,
      item?.captured_unix_ms ? labeledPill("captured", formatTimestamp(item.captured_unix_ms), "neutral") : null,
    ]),
  );
  const actions = el("div", "button-row button-row-compact");
  append(
    actions,
    item?.incident_id ? navButton("Inspect", incidentHref(item.incident_id)) : null,
    releaseExecId ? navButton("Open release", deviceReleaseHref(releaseExecId)) : null,
  );
  append(row, copy, actions);
  return row;
}

function renderNativeSummaryCard(nativeSummary) {
  const summary = objectValue(nativeSummary);
  const card = createCard("Native Summary", "Normalized package metadata returned by release query.");
  if (!summary) {
    append(card, el("p", "muted", "No native summary reported for this release."));
    return card;
  }
  append(
    card,
    keyValueList([
      ["Target", summary.target_kind ?? "n/a"],
      ["Provider", summary.provider_kind ?? "n/a"],
      ["Package manifest", shortText(summary.package_manifest_sha256, 12)],
      ["Permissions", String(arrayValue(summary.permission_declarations).length)],
      ["Telemetry classes", String(arrayValue(summary.telemetry_classes).length)],
    ]),
    createSubsection(
      "Permission Declarations",
      tokenList(summary.permission_declarations, "No native permission declarations returned."),
    ),
    createSubsection(
      "Telemetry Classes",
      tokenList(summary.telemetry_classes, "No telemetry classes returned."),
    ),
    detailsBlock(
      "Capabilities Summary",
      jsonBlock(summary.capabilities ?? {}),
    ),
  );
  return card;
}

function renderReleaseReadinessCard(deviceRelease) {
  const readiness = objectValue(deviceRelease?.release_readiness) ?? {};
  const readinessWarnings = arrayValue(readiness.warnings);
  const readinessErrors = arrayValue(readiness.errors);
  const validationWarnings = arrayValue(deviceRelease?.native_validation_warnings);
  const validationErrors = arrayValue(deviceRelease?.native_validation_errors);
  const card = createCard("Release Readiness", "Backend-derived readiness gates and validation output.");
  append(
    card,
    pillRow([
      labeledPill("status", readiness.status ?? deviceRelease?.release_readiness_status ?? "n/a"),
      pill(`warnings: ${readinessWarnings.length}`, readinessWarnings.length ? "warn" : "ok"),
      pill(`errors: ${readinessErrors.length}`, readinessErrors.length ? "danger" : "ok"),
      pill(`validation warnings: ${validationWarnings.length}`, validationWarnings.length ? "warn" : "ok"),
      pill(`validation errors: ${validationErrors.length}`, validationErrors.length ? "danger" : "ok"),
    ]),
    keyValueList([
      ["Readiness", readiness.status ?? deviceRelease?.release_readiness_status ?? "n/a"],
      ["Warnings", String(readinessWarnings.length)],
      ["Errors", String(readinessErrors.length)],
      ["Validation warnings", String(validationWarnings.length)],
      ["Validation errors", String(validationErrors.length)],
    ]),
    createSubsection("Readiness Warnings", textList(readinessWarnings, "No readiness warnings.")),
    createSubsection("Readiness Errors", textList(readinessErrors, "No readiness errors.")),
    createSubsection("Validation Warnings", textList(validationWarnings, "No validation warnings.")),
    createSubsection("Validation Errors", textList(validationErrors, "No validation errors.")),
  );
  return card;
}

function renderNativeHealthCard(deviceRelease) {
  const rollup = objectValue(deviceRelease?.latest_native_health_rollup) ?? {};
  const latestIncidentId = deviceReleaseLatestIncidentId(deviceRelease);
  const latestRegressionId = deviceReleaseLatestRegressionId(deviceRelease);
  const latestRegressionStatus = deviceReleaseLatestRegressionStatus(deviceRelease);
  const card = createCard("Native Health", "Latest normalized incident rollup for this release.");
  append(
    card,
    pillRow([
      ...createHealthPills(rollup),
      latestIncidentId ? labeledPill("latest incident", shortText(latestIncidentId, 8), "neutral") : null,
      latestRegressionId ? labeledPill("latest regression", shortText(latestRegressionId, 8), "neutral") : null,
      latestRegressionStatus ? labeledPill("regression", latestRegressionStatus, toneForRegressionStatus(latestRegressionStatus)) : null,
    ]),
    keyValueList([
      ["Native incidents", String(Number(rollup.native_incident_count ?? 0))],
      ["Runtime errors", String(Number(rollup.native_runtime_error_count ?? 0))],
      ["Policy violations", String(Number(rollup.native_policy_violation_count ?? 0))],
      ["Bridge timeouts", String(Number(rollup.native_bridge_timeout_count ?? 0))],
      ["Host crashes", String(Number(rollup.native_host_crash_count ?? 0))],
      ["Permission blocks", String(Number(rollup.native_permission_blocked_count ?? 0))],
      ["Latest native incident", latestIncidentId ?? "n/a"],
      ["Latest regression", latestRegressionId ?? "n/a"],
      ["Regression status", latestRegressionStatus],
    ]),
  );
  const actions = el("div", "button-row");
  append(actions, latestIncidentId ? navButton("Open latest incident", incidentHref(latestIncidentId)) : null);
  if (actions.childNodes.length) {
    card.appendChild(actions);
  }
  return card;
}

function renderAppsView() {
  const wrapper = el("div", "stack");
  const appsResult = unwrapResult(state.data.apps);
  const apps = getItems(state.data.apps);
  const incidents = getItems(state.data.incidents);

  const controls = el("div", "button-row");
  append(
    controls,
    actionButton("Kill platform", "/api/platform/kill", { reason: "ui_platform_kill" }, { variant: "btn-danger" }),
    actionButton("Unkill platform", "/api/platform/unkill", { reason: "ui_platform_unkill" }),
  );
  append(
    wrapper,
    sectionTitle("Applications", "Polling every 3 seconds."),
    controls,
  );

  if (!apps.length) {
    append(wrapper, el("div", "card empty", "No apps indexed."));
  }

  for (const item of apps) {
    const card = createCard(`${item.app_id ?? "unknown"} / ${item.environment ?? "unknown"}`);
    append(
      card,
      keyValueList([
        ["Latest deployment", item.latest_deployment_id ?? "n/a"],
        ["Latest incident", item.latest_incident_id ?? "n/a"],
        ["Outcome", item.outcome ?? "n/a"],
        ["Deployment status", item.deployment_status ?? "n/a"],
        ["Kill state", item.kill_state ?? "n/a"],
        ["Open incidents", String(item.incident_count_open ?? 0)],
        ["Listener", item.public_listener ?? "n/a"],
      ]),
    );
    const row = el("div", "button-row");
    append(
      row,
      navButton("Open deployment", item.latest_deployment_id ? deploymentHref(item.latest_deployment_id) : null),
      navButton("Open incident", item.latest_incident_id ? incidentHref(item.latest_incident_id) : null),
      actionButton(
        "Kill app",
        item.app_id && item.environment
          ? `/api/apps/${encodePathSegment(item.app_id)}/${encodePathSegment(item.environment)}/kill`
          : null,
        { reason: "ui_app_kill" },
        { variant: "btn-danger" },
      ),
      actionButton(
        "Unkill app",
        item.app_id && item.environment
          ? `/api/apps/${encodePathSegment(item.app_id)}/${encodePathSegment(item.environment)}/unkill`
          : null,
        { reason: "ui_app_unkill" },
      ),
    );
    append(card, row);
    append(wrapper, card);
  }

  const incidentsSection = createCard(
    "Recent Incidents",
    appsResult?.generated_unix_ms ? `Snapshot ${new Date(appsResult.generated_unix_ms).toLocaleString()}` : null,
  );
  if (!incidents.length) {
    append(incidentsSection, el("p", "muted", "No incidents recorded."));
  } else {
    for (const item of incidents) {
      incidentsSection.appendChild(renderIncidentRow(item));
    }
  }
  append(wrapper, incidentsSection);
  return wrapper;
}

function renderDeviceReleaseListView() {
  const wrapper = el("div", "stack");
  const deviceReleases = getItems(state.data.deviceReleases);
  const snapshot = unwrapResult(state.data.deviceReleases);

  append(
    wrapper,
    sectionTitle(
      "Device Releases",
      snapshot?.generated_unix_ms ? `Snapshot ${new Date(snapshot.generated_unix_ms).toLocaleString()}` : "Polling every 3 seconds.",
    ),
  );

  if (!deviceReleases.length) {
    append(wrapper, el("div", "card empty", "No device releases recorded."));
    return wrapper;
  }

  for (const item of deviceReleases) {
    const app = item.app ?? {};
    const nativeSummary = objectValue(item.native_summary) ?? {};
    const latestIncidentId = deviceReleaseLatestIncidentId(item);
    const latestRegressionStatus = deviceReleaseLatestRegressionStatus(item);
    const card = createCard(`${app.app_id ?? "unknown"} / ${nativeSummary.target_kind ?? item.target ?? "n/a"}`);
    append(
      card,
      pillRow([
        labeledPill("status", item.status),
        labeledPill("state", item.current_state),
        labeledPill("readiness", item.release_readiness_status ?? item.release_readiness?.status),
        labeledPill("eval", item.latest_eval_outcome ?? "none", toneForStatus(item.latest_eval_outcome)),
        labeledPill("regression", latestRegressionStatus, toneForRegressionStatus(latestRegressionStatus)),
        ...createHealthPills(item.latest_native_health_rollup),
      ]),
      keyValueList([
        ["Release", item.exec_id ?? "n/a"],
        ["Provider", item.provider_kind ?? nativeSummary.provider_kind ?? "n/a"],
        ["Lane", item.distribution_lane ?? "n/a"],
        ["Target", nativeSummary.target_kind ?? item.target ?? "n/a"],
        ["Rollout", formatPercent(item.current_rollout_percent)],
        ["Version", app.version ?? "n/a"],
        ["Build", app.build ?? "n/a"],
        ["Package manifest", shortText(nativeSummary.package_manifest_sha256, 12)],
        ["Latest native incident", latestIncidentId ?? "n/a"],
        ["Updated", formatTimestamp(item.updated_unix_ms)],
      ]),
    );
    const row = el("div", "button-row");
    append(
      row,
      navButton("Open release", item.exec_id ? deviceReleaseHref(item.exec_id) : null),
      latestIncidentId ? navButton("Open latest incident", incidentHref(latestIncidentId)) : null,
    );
    append(card, row);
    append(wrapper, card);
  }

  return wrapper;
}

function renderDeviceReleaseView() {
  const wrapper = el("div", "stack");
  const deviceRelease = unwrapResult(state.data.deviceRelease);
  const execId = state.route.execId;
  const app = deviceRelease?.app ?? {};
  const linkedIncidents = arrayValue(deviceRelease?.linked_incidents);
  const latestIncidentId = deviceReleaseLatestIncidentId(deviceRelease);
  const controls = el("div", "button-row");
  append(
    controls,
    navButton("Back to releases", "/device-releases"),
    latestIncidentId ? navButton("Open latest incident", incidentHref(latestIncidentId)) : null,
    actionButton("Pause", `/api/device-releases/${encodePathSegment(execId)}/pause`, { reason: "ui_device_release_pause" }),
    actionButton("Resume", `/api/device-releases/${encodePathSegment(execId)}/resume`, { reason: "ui_device_release_resume" }),
    actionButton("Complete", `/api/device-releases/${encodePathSegment(execId)}/complete`, { reason: "ui_device_release_complete" }),
    actionButton("Halt", `/api/device-releases/${encodePathSegment(execId)}/halt`, { reason: "ui_device_release_halt" }, { variant: "btn-danger" }),
    actionButton("Rollback", `/api/device-releases/${encodePathSegment(execId)}/rollback`, { reason: "ui_device_release_rollback" }, { variant: "btn-danger" }),
  );

  const summaryCard = createCard("Release Overview", "Native-aware release detail from the normalized query payload.");
  append(
    summaryCard,
    pillRow([
      labeledPill("status", deviceRelease?.status),
      labeledPill("state", deviceRelease?.current_state),
      labeledPill("readiness", deviceRelease?.release_readiness_status ?? deviceRelease?.release_readiness?.status),
      labeledPill("eval", deviceRelease?.latest_eval_outcome ?? "none", toneForStatus(deviceRelease?.latest_eval_outcome)),
      labeledPill("regression", deviceReleaseLatestRegressionStatus(deviceRelease), toneForRegressionStatus(deviceReleaseLatestRegressionStatus(deviceRelease))),
    ]),
    keyValueList([
      ["Release", deviceRelease?.exec_id ?? execId],
      ["Plan", deviceRelease?.plan_id ?? "n/a"],
      ["Provider", deviceRelease?.provider_kind ?? "n/a"],
      ["Lane", deviceRelease?.distribution_lane ?? "n/a"],
      ["Target", deviceRelease?.target ?? "n/a"],
      ["Status", deviceRelease?.status ?? "n/a"],
      ["State", deviceRelease?.current_state ?? "n/a"],
      ["Automation", deviceRelease?.automation_state ?? "n/a"],
      ["Rollout", formatPercent(deviceRelease?.current_rollout_percent)],
      ["App", app.app_id ?? "n/a"],
      ["Version", app.version ?? "n/a"],
      ["Build", app.build ?? "n/a"],
      ["Decision count", String(deviceRelease?.decision_count ?? 0)],
      ["Provider release id", inlineValue(deviceRelease?.provider_release_id, "n/a")],
      ["Latest native incident", latestIncidentId ?? "n/a"],
      ["Latest regression id", deviceReleaseLatestRegressionId(deviceRelease) ?? "n/a"],
      ["Latest regression status", deviceReleaseLatestRegressionStatus(deviceRelease)],
      ["Updated", formatTimestamp(deviceRelease?.updated_unix_ms)],
    ]),
  );

  const linkedIncidentsCard = createCard("Linked Incidents", "Incident linkage and regression state threaded through release query.");
  if (!linkedIncidents.length) {
    append(linkedIncidentsCard, el("p", "muted", "No incidents linked to this device release."));
  } else {
    for (const item of linkedIncidents) {
      linkedIncidentsCard.appendChild(renderIncidentRow(item, { releaseExecId: deviceRelease?.exec_id ?? execId }));
    }
  }

  const rawCard = createCard("Raw Payload");
  append(
    rawCard,
    detailsBlock("Full device release query JSON", jsonBlock(state.data.deviceRelease)),
  );

  const grid = el("div", "card-grid");
  append(
    grid,
    summaryCard,
    renderNativeSummaryCard(deviceRelease?.native_summary),
    renderReleaseReadinessCard(deviceRelease),
    renderNativeHealthCard(deviceRelease),
  );

  append(wrapper, sectionTitle("Device Release", execId), controls, grid, linkedIncidentsCard, rawCard);
  return wrapper;
}

function renderDeploymentView() {
  const wrapper = el("div", "stack");
  const deployment = unwrapResult(state.data.deployment);
  const incidents = getItems(state.data.incidents);
  const execId = state.route.execId;
  const controls = el("div", "button-row");
  append(
    controls,
    navButton("Back to apps", "/apps"),
    actionButton("Pause", `/api/deployments/${encodePathSegment(execId)}/pause`, { reason: "ui_pause" }),
    actionButton(
      "Rerun",
      `/api/deployments/${encodePathSegment(execId)}/rerun`,
      { reason: "ui_rerun", from_step: 0 },
      {
        afterSuccess: async (result) => {
          const newExecutionId = findFirstStringByKey(result, ["new_execution_id", "deployment_id"]);
          if (newExecutionId) {
            navigate(deploymentHref(newExecutionId));
            return;
          }
          await refresh();
        },
      },
    ),
    actionButton("Rollback", `/api/deployments/${encodePathSegment(execId)}/rollback`, { reason: "ui_rollback" }, { variant: "btn-danger" }),
    actionButton("Stop", `/api/deployments/${encodePathSegment(execId)}/stop`, { reason: "ui_stop" }, { variant: "btn-danger" }),
  );

  const summaryCard = createCard("Deployment", execId);
  append(
    summaryCard,
    keyValueList([
      ["Deployment", deployment?.deployment_id ?? execId],
      ["Status", deployment?.status ?? deployment?.execution?.status ?? "n/a"],
      ["Outcome", deployment?.outcome ?? deployment?.summary?.outcome ?? "n/a"],
      ["App", deployment?.target?.app_id ?? "n/a"],
      ["Environment", deployment?.target?.environment ?? "n/a"],
      ["Decision", deployment?.decision_id ?? "n/a"],
    ]),
    detailsBlock("Full deployment query JSON", jsonBlock(state.data.deployment)),
  );

  const incidentCard = createCard("Related Incidents");
  if (!incidents.length) {
    append(incidentCard, el("p", "muted", "No incidents linked to this deployment."));
  } else {
    for (const item of incidents) {
      incidentCard.appendChild(renderIncidentRow(item));
    }
  }

  append(wrapper, controls, summaryCard, incidentCard);
  return wrapper;
}

function renderIncidentReleaseCard(incident) {
  const releaseExecId = incidentReleaseExecId(incident);
  const releasePlanId = incidentReleasePlanId(incident);
  const targetKind = incidentTargetKind(incident);
  const providerKind = incidentProviderKind(incident);
  const packageManifestSha = incidentPackageManifestSha(incident);
  const card = createCard("Release Linkage", "Normalized release identifiers and packaging context.");
  append(
    card,
    keyValueList([
      ["Release execution", releaseExecId ?? "n/a"],
      ["Release plan", releasePlanId ?? "n/a"],
      ["Target", targetKind ?? "n/a"],
      ["Provider", providerKind ?? "n/a"],
      ["Package manifest", packageManifestSha ? shortText(packageManifestSha, 12) : "n/a"],
    ]),
  );
  const actions = el("div", "button-row");
  append(actions, releaseExecId ? navButton("Open release", deviceReleaseHref(releaseExecId)) : null);
  if (actions.childNodes.length) {
    card.appendChild(actions);
  } else {
    card.appendChild(el("p", "muted", "No device release linkage recorded."));
  }
  return card;
}

function renderNativeContextCard(incident) {
  const nativeContext = objectValue(incident?.native_context);
  const card = createCard("Native Context", "Sanitized device-native context captured with the incident.");
  if (!nativeContext) {
    append(card, el("p", "muted", "No native context recorded for this incident."));
    return card;
  }
  append(
    card,
    keyValueList([
      ["Kind", nativeContext.kind ?? "n/a"],
      ["Platform", nativeContext.platform ?? incidentTargetKind(incident) ?? "n/a"],
      ["Release execution", nativeContext.release_exec_id ?? incidentReleaseExecId(incident) ?? "n/a"],
      ["Release plan", nativeContext.release_plan_id ?? incidentReleasePlanId(incident) ?? "n/a"],
      ["Package manifest", nativeContext.package_manifest_sha256 ? shortText(nativeContext.package_manifest_sha256, 12) : "n/a"],
      ["Lifecycle state", inlineValue(nativeContext.lifecycle_state, "n/a")],
      ["Connectivity state", inlineValue(nativeContext.connectivity_state, "n/a")],
    ]),
    detailsBlock("Capabilities Summary", jsonBlock(nativeContext.capabilities_summary ?? {})),
    detailsBlock("Permission Snapshot", jsonBlock(nativeContext.permission_snapshot ?? null)),
    detailsBlock("Breadcrumbs", jsonBlock(nativeContext.breadcrumbs ?? [])),
  );
  return card;
}

function renderRegressionCard(incident) {
  const regression = objectValue(incident?.regression) ?? {};
  const generatedTraceRefs = arrayValue(
    regression.generated_trace_artifact_refs ?? incident?.generated_trace_artifact_refs,
  );
  const generatedReportRefs = arrayValue(
    regression.generated_report_artifact_refs ?? incident?.generated_report_artifact_refs,
  );
  const generatedRefs = arrayValue(regression.generated);
  const requestRefs = regression.request ? [regression.request] : [];
  const reportRefs = regression.report ? [regression.report] : [];
  const targetRefs = regression.target_artifact ? [regression.target_artifact] : [];
  const card = createCard("Regression", "Regression generation and artifact refs when present.");
  append(
    card,
    pillRow([
      labeledPill("status", incident?.regression_status ?? regression.incident_status_after ?? "not_requested", toneForRegressionStatus(incident?.regression_status ?? regression.incident_status_after ?? "not_requested")),
      labeledPill("id", shortText(incident?.regression_id ?? regression.regression_id, 8), "neutral"),
      regression.replay_mode ? labeledPill("mode", regression.replay_mode, "neutral") : null,
      regression.replay_target_kind ? labeledPill("target", regression.replay_target_kind, "neutral") : null,
      regression.replay_synthesis_status ? labeledPill("synthesis", regression.replay_synthesis_status, toneForRegressionStatus(regression.replay_synthesis_status)) : null,
    ]),
    keyValueList([
      ["Regression", incident?.regression_id ?? regression.regression_id ?? "n/a"],
      ["Status", incident?.regression_status ?? regression.incident_status_after ?? "not_requested"],
      ["Replay mode", regression.replay_mode ?? "n/a"],
      ["Replay target", regression.replay_target_kind ?? "n/a"],
      ["Synthesis", regression.replay_synthesis_status ?? "n/a"],
      ["Generated traces", String(generatedTraceRefs.length)],
      ["Generated reports", String(generatedReportRefs.length)],
      ["Generated artifacts", String(generatedRefs.length)],
    ]),
    createSubsection("Request Artifact", renderArtifactRows(requestRefs, "No regression request artifact.")),
    createSubsection("Target Artifact", renderArtifactRows(targetRefs, "No regression target artifact.")),
    createSubsection("Report Artifact", renderArtifactRows(reportRefs, "No regression report artifact.")),
    createSubsection("Generated Trace Artifacts", renderArtifactRows(generatedTraceRefs, "No generated trace artifacts.")),
    createSubsection("Generated Report Artifacts", renderArtifactRows(generatedReportRefs, "No generated report artifacts.")),
    createSubsection("Generated Artifacts", renderArtifactRows(generatedRefs, "No generated artifacts.")),
  );
  return card;
}

function renderCapturedArtifactsCard(incident) {
  const refs = arrayValue(incident?.refs);
  const fallbackRefs = [];
  if (!refs.length) {
    if (incident?.bundle) {
      fallbackRefs.push({ ...incident.bundle, label: "bundle" });
    }
    if (incident?.request) {
      fallbackRefs.push({ ...incident.request, label: "request" });
    }
    if (incident?.response) {
      fallbackRefs.push({ ...incident.response, label: "response" });
    }
    if (incident?.trace) {
      fallbackRefs.push({ ...incident.trace, label: "trace" });
    }
  }
  const card = createCard("Captured Artifacts", "Refs attached to the incident bundle.");
  append(card, renderArtifactRows(refs.length ? refs : fallbackRefs, "No captured artifact refs."));
  return card;
}

function renderIncidentView() {
  const wrapper = el("div", "stack");
  const incident = unwrapResult(state.data.incident);
  const incidentId = state.route.incidentId;
  const appId = incident?.target?.app_id ?? getTargetApp(incident);
  const environment = incident?.target?.environment ?? getTargetEnv(incident);
  const deploymentId = incident?.deployment_id ?? findFirstStringByKey(incident, ["deployment_id"]);
  const releaseExecId = incidentReleaseExecId(incident);
  const controls = el("div", "button-row");
  append(
    controls,
    navButton("Back to apps", "/apps"),
    deploymentId ? navButton("Open deployment", deploymentHref(deploymentId)) : null,
    releaseExecId ? navButton("Open release", deviceReleaseHref(releaseExecId)) : null,
    actionButton(
      "Regress",
      `/api/incidents/${encodePathSegment(incidentId)}/regress`,
      { name: `ui-${incidentId}` },
      {
        afterSuccess: async () => {
          await refresh();
        },
      },
    ),
    actionButton(
      "Kill app",
      appId && environment
        ? `/api/apps/${encodePathSegment(appId)}/${encodePathSegment(environment)}/kill`
        : null,
      { reason: "ui_incident_app_kill" },
      { variant: "btn-danger" },
    ),
    actionButton(
      "Unkill app",
      appId && environment
        ? `/api/apps/${encodePathSegment(appId)}/${encodePathSegment(environment)}/unkill`
        : null,
      { reason: "ui_incident_app_unkill" },
    ),
  );

  const overviewCard = createCard("Incident Overview", "Normalized incident detail with release and regression linkage.");
  append(
    overviewCard,
    pillRow([
      incident?.native_classification
        ? pill(incident.native_classification, toneForNativeClassification(incident.native_classification))
        : incident?.classification
          ? pill(incident.classification, toneForStatus(incident.classification))
          : null,
      labeledPill("status", incident?.incident_status),
      labeledPill("regression", incident?.regression_status ?? "not_requested", toneForRegressionStatus(incident?.regression_status ?? "not_requested")),
      incidentTargetKind(incident) ? labeledPill("target", incidentTargetKind(incident), "neutral") : null,
      incidentProviderKind(incident) ? labeledPill("provider", incidentProviderKind(incident), "neutral") : null,
    ]),
    keyValueList([
      ["Incident", incident?.incident_id ?? incidentId],
      ["Classification", incident?.classification ?? "n/a"],
      ["Native classification", incident?.native_classification ?? "n/a"],
      ["Status", incident?.incident_status ?? "n/a"],
      ["Regression", incident?.regression_status ?? "not_requested"],
      ["Regression id", incident?.regression_id ?? "n/a"],
      ["Deployment", incident?.deployment_id ?? "n/a"],
      ["Release execution", releaseExecId ?? "n/a"],
      ["Release plan", incidentReleasePlanId(incident) ?? "n/a"],
      ["App", appId ?? "n/a"],
      ["Environment", environment ?? "n/a"],
      ["Captured", formatTimestamp(incident?.captured_unix_ms)],
      ["Decision", inlineValue(incident?.decision_id, "n/a")],
    ]),
  );

  const rawCard = createCard("Raw Payload");
  append(rawCard, detailsBlock("Full incident query JSON", jsonBlock(state.data.incident)));

  const grid = el("div", "card-grid");
  append(
    grid,
    overviewCard,
    renderIncidentReleaseCard(incident),
    renderNativeContextCard(incident),
    renderRegressionCard(incident),
  );

  append(wrapper, sectionTitle("Incident", incidentId), controls, grid, renderCapturedArtifactsCard(incident), rawCard);
  return wrapper;
}

function renderBanner() {
  if (state.error) {
    const panel = el("section", "banner banner-error");
    append(panel, el("strong", null, state.error.message), el("pre", "json-block", state.error.detail ?? ""));
    return panel;
  }
  if (state.actionResult) {
    const panel = el("section", "banner banner-ok");
    append(panel, el("strong", null, "Last action result"), jsonBlock(state.actionResult));
    return panel;
  }
  return null;
}

function render() {
  root.replaceChildren();

  const page = el("main", "page");
  const header = el("header", "hero");
  append(
    header,
    el("p", "eyebrow", "x07 Platform"),
    el("h1", null, "Command Center"),
    el(
      "p",
      "muted",
      state.loading
        ? "Refreshing backend state..."
        : state.route.kind === "deviceReleaseList"
          ? "Store release orchestration, rollout state, and manual controls."
          : state.route.kind === "deviceRelease"
            ? `Device release ${state.route.execId}`
            : state.route.kind === "apps"
          ? "Applications, incidents, and control actions."
          : state.route.kind === "deployment"
            ? `Deployment ${state.route.execId}`
            : `Incident ${state.route.incidentId}`,
    ),
  );

  const routeTabs = el("div", "button-row");
  append(
    routeTabs,
    navButton("Device Releases", "/device-releases", state.route.kind === "deviceReleaseList"),
    navButton("Apps", "/apps", state.route.kind === "apps"),
  );
  if (state.route.kind === "deviceRelease") {
    append(routeTabs, navButton("Current release", state.route.path, true));
  }
  if (state.route.kind === "deployment") {
    append(routeTabs, navButton("Current deployment", state.route.path, true));
  }
  if (state.route.kind === "incident") {
    append(routeTabs, navButton("Current incident", state.route.path, true));
  }

  append(page, header, routeTabs, renderBanner());

  if (state.route.kind === "deviceReleaseList") {
    append(page, renderDeviceReleaseListView());
  } else if (state.route.kind === "deviceRelease") {
    append(page, renderDeviceReleaseView());
  } else if (state.route.kind === "apps") {
    append(page, renderAppsView());
  } else if (state.route.kind === "deployment") {
    append(page, renderDeploymentView());
  } else {
    append(page, renderIncidentView());
  }

  root.appendChild(page);
}

function installStyles() {
  if (document.getElementById("command-center-style")) {
    return;
  }
  const style = document.createElement("style");
  style.id = "command-center-style";
  style.textContent = `
    :root {
      --lp-bg: #f6f2ea;
      --lp-surface: #fffdf8;
      --lp-border: #d8cfc2;
      --lp-ink: #1c1b19;
      --lp-muted: #6c655c;
      --lp-accent: #0b6e4f;
      --lp-danger: #8f2d18;
      --lp-shadow: 0 10px 30px rgba(28, 27, 25, 0.08);
    }
    body {
      background:
        radial-gradient(circle at top left, rgba(11, 110, 79, 0.08), transparent 28rem),
        linear-gradient(180deg, #f3ede0, var(--lp-bg));
      color: var(--lp-ink);
    }
    #app {
      padding: 24px;
    }
    .page {
      max-width: 1080px;
      margin: 0 auto;
      display: grid;
      gap: 16px;
    }
    .hero {
      background: var(--lp-surface);
      border: 1px solid var(--lp-border);
      border-radius: 18px;
      box-shadow: var(--lp-shadow);
      padding: 20px;
    }
    .hero h1,
    .section-head h2,
    .card h3 {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .eyebrow {
      margin: 0 0 6px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      color: var(--lp-accent);
    }
    .muted {
      color: var(--lp-muted);
    }
    .stack {
      display: grid;
      gap: 16px;
    }
    .stack-tight {
      display: grid;
      gap: 10px;
    }
    .card-grid {
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }
    .card,
    .banner {
      background: var(--lp-surface);
      border: 1px solid var(--lp-border);
      border-radius: 18px;
      box-shadow: var(--lp-shadow);
      padding: 18px;
    }
    .section-head {
      display: grid;
      gap: 6px;
      margin-bottom: 14px;
    }
    .section-head p {
      margin: 0;
    }
    .banner-error {
      border-color: rgba(143, 45, 24, 0.35);
    }
    .banner-ok {
      border-color: rgba(11, 110, 79, 0.35);
    }
    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .button-row-compact {
      gap: 8px;
    }
    .btn {
      appearance: none;
      border: 1px solid var(--lp-border);
      background: #f7f0e5;
      border-radius: 999px;
      padding: 10px 14px;
      font: inherit;
      color: var(--lp-ink);
    }
    .btn:hover:not(:disabled) {
      border-color: var(--lp-accent);
    }
    .btn-active {
      background: #e2f0e7;
      border-color: rgba(11, 110, 79, 0.45);
    }
    .btn-danger {
      color: white;
      background: var(--lp-danger);
      border-color: var(--lp-danger);
    }
    .btn:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }
    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0 0 14px;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      border: 1px solid rgba(28, 27, 25, 0.08);
      background: rgba(28, 27, 25, 0.05);
      color: var(--lp-ink);
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.01em;
    }
    .pill-ok {
      background: rgba(11, 110, 79, 0.12);
      color: #084634;
    }
    .pill-warn {
      background: rgba(179, 119, 0, 0.14);
      color: #735000;
    }
    .pill-danger {
      background: rgba(143, 45, 24, 0.14);
      color: #7b2615;
    }
    .pill-neutral {
      background: rgba(28, 27, 25, 0.06);
      color: var(--lp-ink);
    }
    .kv-list {
      display: grid;
      grid-template-columns: minmax(160px, 220px) 1fr;
      gap: 8px 12px;
      margin: 0 0 16px;
    }
    .kv-list dt {
      font-weight: 600;
    }
    .kv-list dd {
      margin: 0;
      color: var(--lp-muted);
      overflow-wrap: anywhere;
    }
    .json-block {
      margin: 0;
      padding: 14px;
      border-radius: 14px;
      background: #1f2528;
      color: #f5f6f4;
      overflow: auto;
      font-size: 13px;
      line-height: 1.45;
    }
    .list-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 10px 0;
      border-top: 1px solid rgba(216, 207, 194, 0.65);
    }
    .list-row:first-of-type {
      border-top: 0;
    }
    .list-copy {
      flex: 1;
      overflow-wrap: anywhere;
    }
    .list-title {
      font-weight: 600;
      overflow-wrap: anywhere;
    }
    .list-subtitle,
    .list-meta {
      margin-top: 4px;
      color: var(--lp-muted);
      overflow-wrap: anywhere;
    }
    .subsection + .subsection {
      margin-top: 16px;
    }
    .mini-title {
      margin: 0 0 8px;
      font-size: 14px;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: var(--lp-muted);
    }
    .details-block {
      border: 1px solid rgba(216, 207, 194, 0.7);
      border-radius: 14px;
      background: rgba(247, 240, 229, 0.55);
      padding: 10px 12px;
    }
    .details-block summary {
      cursor: pointer;
      font-weight: 600;
      list-style: none;
    }
    .details-block summary::-webkit-details-marker {
      display: none;
    }
    .details-block > *:not(summary) {
      margin-top: 12px;
    }
    .bullet-list {
      margin: 0;
      padding-left: 18px;
      color: var(--lp-muted);
    }
    .bullet-list li + li {
      margin-top: 6px;
    }
    @media (max-width: 700px) {
      #app {
        padding: 14px;
      }
      .kv-list {
        grid-template-columns: 1fr;
      }
      .list-row {
        flex-direction: column;
        align-items: stretch;
      }
      .button-row {
        flex-direction: column;
      }
      .card-grid {
        grid-template-columns: 1fr;
      }
    }
  `;
  document.head.appendChild(style);
}

if (state.route.path !== window.location.pathname) {
  navigate(state.route.path, { replace: true });
} else {
  render();
  void refresh();
}

window.setInterval(() => {
  void refresh();
}, POLL_INTERVAL_MS);
