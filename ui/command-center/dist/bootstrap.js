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
    const card = el("section", "card");
    append(
      card,
      el("h3", null, `${item.app_id} / ${item.environment}`),
      keyValueList([
        ["Latest deployment", item.latest_deployment_id],
        ["Latest incident", item.latest_incident_id],
        ["Outcome", item.outcome],
        ["Deployment status", item.deployment_status],
        ["Kill state", item.kill_state],
        ["Open incidents", String(item.incident_count_open ?? 0)],
        ["Listener", item.public_listener],
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

  const incidentsSection = el("section", "card");
  append(
    incidentsSection,
    sectionTitle("Recent Incidents", appsResult?.generated_unix_ms ? `Snapshot ${new Date(appsResult.generated_unix_ms).toLocaleString()}` : null),
  );
  if (!incidents.length) {
    append(incidentsSection, el("p", "muted", "No incidents recorded."));
  } else {
    for (const item of incidents) {
      const row = el("div", "list-row");
      const summary = el(
        "div",
        "list-copy",
        `${item.incident_id} · ${item.classification} · ${item.target?.app_id ?? "unknown"} / ${item.target?.environment ?? "unknown"}`,
      );
      const open = navButton("Inspect", incidentHref(item.incident_id));
      append(row, summary, open);
      incidentsSection.appendChild(row);
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
    const card = el("section", "card");
    append(
      card,
      el("h3", null, `${app.app_id ?? "unknown"} / ${item.target ?? "n/a"}`),
      keyValueList([
        ["Release", item.exec_id],
        ["Provider", item.provider_kind],
        ["Lane", item.distribution_lane],
        ["Status", item.status],
        ["State", item.current_state],
        ["Rollout", item.current_rollout_percent == null ? "n/a" : `${item.current_rollout_percent}%`],
        ["Version", app.version ?? "n/a"],
        ["Build", app.build ?? "n/a"],
      ]),
    );
    const row = el("div", "button-row");
    append(row, navButton("Open release", deviceReleaseHref(item.exec_id)));
    append(card, row);
    append(wrapper, card);
  }

  return wrapper;
}

function renderDeviceReleaseView() {
  const wrapper = el("div", "stack");
  const deviceRelease = unwrapResult(state.data.deviceRelease);
  const execId = state.route.execId;
  const controls = el("div", "button-row");
  append(
    controls,
    navButton("Back to releases", "/device-releases"),
    actionButton("Pause", `/api/device-releases/${encodePathSegment(execId)}/pause`, { reason: "ui_device_release_pause" }),
    actionButton("Resume", `/api/device-releases/${encodePathSegment(execId)}/resume`, { reason: "ui_device_release_resume" }),
    actionButton("Complete", `/api/device-releases/${encodePathSegment(execId)}/complete`, { reason: "ui_device_release_complete" }),
    actionButton("Halt", `/api/device-releases/${encodePathSegment(execId)}/halt`, { reason: "ui_device_release_halt" }, { variant: "btn-danger" }),
    actionButton("Rollback", `/api/device-releases/${encodePathSegment(execId)}/rollback`, { reason: "ui_device_release_rollback" }, { variant: "btn-danger" }),
  );
  const app = deviceRelease?.app ?? {};
  const rolloutPercent =
    deviceRelease?.current_rollout_percent == null ? "n/a" : `${deviceRelease.current_rollout_percent}%`;

  const card = el("section", "card");
  append(
    card,
    keyValueList([
      ["Release", deviceRelease?.exec_id ?? execId],
      ["Plan", deviceRelease?.plan_id ?? "n/a"],
      ["Provider", deviceRelease?.provider_kind ?? "n/a"],
      ["Lane", deviceRelease?.distribution_lane ?? "n/a"],
      ["Target", deviceRelease?.target ?? "n/a"],
      ["Status", deviceRelease?.status ?? "n/a"],
      ["State", deviceRelease?.current_state ?? "n/a"],
      ["Rollout", rolloutPercent],
      ["App", app.app_id ?? "n/a"],
      ["Version", app.version ?? "n/a"],
      ["Build", app.build ?? "n/a"],
      ["Decision count", String(deviceRelease?.decision_count ?? 0)],
      ["Provider release id", deviceRelease?.provider_release_id ?? "n/a"],
    ]),
    jsonBlock(state.data.deviceRelease),
  );

  append(wrapper, sectionTitle("Device Release", execId), controls, card);
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
  append(
    wrapper,
    sectionTitle("Deployment", execId),
    controls,
    el("section", "card"),
  );
  wrapper.lastChild.appendChild(
    keyValueList([
      ["Deployment", deployment?.deployment_id ?? execId],
      ["Status", deployment?.status ?? deployment?.execution?.status ?? "n/a"],
      ["Outcome", deployment?.outcome ?? deployment?.summary?.outcome ?? "n/a"],
      ["App", deployment?.target?.app_id ?? "n/a"],
      ["Environment", deployment?.target?.environment ?? "n/a"],
      ["Decision", deployment?.decision_id ?? "n/a"],
    ]),
  );
  wrapper.lastChild.appendChild(jsonBlock(state.data.deployment));

  const incidentCard = el("section", "card");
  append(incidentCard, sectionTitle("Related Incidents"));
  if (!incidents.length) {
    append(incidentCard, el("p", "muted", "No incidents linked to this deployment."));
  } else {
    for (const item of incidents) {
      const row = el("div", "list-row");
      append(
        row,
        el("div", "list-copy", `${item.incident_id} · ${item.classification} · ${item.incident_status}`),
        navButton("Inspect", incidentHref(item.incident_id)),
      );
      incidentCard.appendChild(row);
    }
  }
  append(wrapper, incidentCard);
  return wrapper;
}

function renderIncidentView() {
  const wrapper = el("div", "stack");
  const incident = unwrapResult(state.data.incident);
  const incidentId = state.route.incidentId;
  const appId = incident?.target?.app_id ?? getTargetApp(incident);
  const environment = incident?.target?.environment ?? getTargetEnv(incident);
  const deploymentId = incident?.deployment_id ?? findFirstStringByKey(incident, ["deployment_id"]);
  const controls = el("div", "button-row");
  append(
    controls,
    navButton("Back to apps", "/apps"),
    deploymentId ? navButton("Open deployment", deploymentHref(deploymentId)) : null,
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

  const card = el("section", "card");
  append(
    card,
    keyValueList([
      ["Incident", incident?.incident_id ?? incidentId],
      ["Classification", incident?.classification ?? "n/a"],
      ["Status", incident?.incident_status ?? "n/a"],
      ["Regression", incident?.regression_status ?? "n/a"],
      ["Deployment", incident?.deployment_id ?? "n/a"],
      ["App", appId ?? "n/a"],
      ["Environment", environment ?? "n/a"],
    ]),
    jsonBlock(state.data.incident),
  );

  append(wrapper, sectionTitle("Incident", incidentId), controls, card);
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
    .card,
    .banner {
      background: var(--lp-surface);
      border: 1px solid var(--lp-border);
      border-radius: 18px;
      box-shadow: var(--lp-shadow);
      padding: 18px;
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
