const state = {
  token: null,
  mfaToken: null,
  role: null,
  dashboard: null,
};

const screens = document.querySelectorAll(".screen");
const navItems = document.querySelectorAll(".nav-item");
const loginShell = document.getElementById("login-shell");
const sidebar = document.getElementById("sidebar");
const main = document.getElementById("main");
const loginStatus = document.getElementById("login-status");
const mfaBlock = document.getElementById("mfa-block");
const mfaSetup = document.getElementById("mfa-setup");

function setStatus(message, tone = "muted") {
  loginStatus.className = tone === "error" ? "muted error" : "muted";
  loginStatus.textContent = message;
}

function activateScreen(screenId) {
  screens.forEach((screen) => screen.classList.toggle("active", screen.id === `screen-${screenId}`));
  navItems.forEach((item) => item.classList.toggle("active", item.dataset.screen === screenId));
  document.getElementById("crumb").textContent = screenId.replace("-", " ");
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }
  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(payload.detail || "Request failed");
  }
  if (response.headers.get("content-type")?.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function setupMfa() {
  const data = await api("/api/auth/mfa/setup", {
    method: "POST",
    body: JSON.stringify({ token: state.mfaToken }),
  });
  mfaSetup.classList.remove("hidden");
  mfaSetup.textContent = `Secret: ${data.secret}\nURI: ${data.otpauth_uri}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function pickTaskField(task, candidates) {
  for (const candidate of candidates) {
    const direct = task[candidate];
    if (direct !== undefined && direct !== null && String(direct).trim() !== "") {
      return direct;
    }
    const caseInsensitiveKey = Object.keys(task).find((key) => key.toLowerCase() === candidate.toLowerCase());
    if (caseInsensitiveKey) {
      const value = task[caseInsensitiveKey];
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        return value;
      }
    }
  }
  return "";
}

function parseTaskDate(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  if (typeof value === "number" || /^\d+(\.\d+)?$/.test(String(value))) {
    const serial = Number(value);
    if (Number.isFinite(serial) && serial > 20000 && serial < 70000) {
      const excelEpoch = Date.UTC(1899, 11, 30);
      return new Date(excelEpoch + serial * 86400000);
    }
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatTaskDate(value) {
  const parsed = value instanceof Date ? value : parseTaskDate(value);
  if (!parsed) {
    return String(value ?? "");
  }
  return parsed.toLocaleDateString("it-IT", { day: "2-digit", month: "2-digit", year: "numeric" });
}

function buildPlanningRows(tasks) {
  return tasks.map((task) => {
    const plannedStart = pickTaskField(task, ["Planned Start", "Start", "start"]);
    const plannedEnd = pickTaskField(task, ["Planned End", "End", "end"]);
    const effectiveStart = pickTaskField(task, ["Effective Start", "effective start"]);
    const effectiveEnd = pickTaskField(task, ["Effective End", "effective end"]);
    const start = parseTaskDate(effectiveStart || plannedStart);
    const end = parseTaskDate(effectiveEnd || plannedEnd || effectiveStart || plannedStart);
    return {
      task,
      name: pickTaskField(task, ["SCOPE", "Task", "SECTION", "Scope"]),
      owner: pickTaskField(task, ["Ownership", "Owner", "owner"]),
      status: pickTaskField(task, ["STATUS", "Status", "status"]),
      wbs: pickTaskField(task, ["WBS", "wbs"]),
      type: pickTaskField(task, ["TYPE", "Type", "type"]),
      start,
      end,
      variant: effectiveStart || effectiveEnd ? "actual" : "planned",
    };
  }).filter((item) => item.start && item.end);
}

function renderPlanningVisual(planning, tasks) {
  const rows = buildPlanningRows(tasks);
  const meta = document.getElementById("planning-meta");
  const visual = document.getElementById("planning-visual");
  const chips = [planning.headline, planning.window, planning.author_line, `${tasks.length} rows parsed`]
    .filter(Boolean)
    .map((item) => `<div class="gantt-chip">${escapeHtml(item)}</div>`)
    .join("");
  meta.innerHTML = chips;
  if (rows.length === 0) {
    visual.innerHTML = `<div class="gantt-empty">Workbook acquisito ma privo di righe con date utilizzabili.</div>`;
    return rows;
  }
  const minTime = Math.min(...rows.map((item) => item.start.getTime()));
  const maxTime = Math.max(...rows.map((item) => item.end.getTime()));
  const spanDays = Math.max(1, Math.round((maxTime - minTime) / 86400000) + 1);
  const minDate = new Date(minTime);
  const maxDate = new Date(maxTime);
  const visibleRows = rows.slice(0, 14);
  visual.innerHTML = `
    <div class="gantt-axis">
      <span>${escapeHtml(formatTaskDate(minDate))}</span>
      <span>${escapeHtml(formatTaskDate(maxDate))}</span>
    </div>
    ${visibleRows.map((item) => {
      const startOffset = Math.round((item.start.getTime() - minTime) / 86400000);
      const duration = Math.max(1, Math.round((item.end.getTime() - item.start.getTime()) / 86400000) + 1);
      const left = (startOffset / spanDays) * 100;
      const width = Math.max(3, (duration / spanDays) * 100);
      const label = [item.wbs, item.type].filter(Boolean).join(" · ");
      return `
        <div class="gantt-row">
          <div class="gantt-label">
            <strong>${escapeHtml(item.name || item.wbs || "Task")}</strong>
            <span>${escapeHtml(label || item.owner || "")}</span>
          </div>
          <div class="gantt-track">
            <div class="gantt-bar ${item.variant === "actual" ? "actual" : ""}" style="left:${left.toFixed(2)}%;width:${width.toFixed(2)}%;"></div>
          </div>
        </div>
      `;
    }).join("")}
  `;
  return rows;
}

async function loadDashboard() {
  state.dashboard = await api("/api/dashboard");
  const me = await api("/api/me");
  state.role = me.role;
  document.getElementById("admin-nav").classList.toggle("hidden", me.role !== "admin");
  if (me.role === "admin") {
    renderAdmin(state.dashboard);
  } else {
    renderClient(state.dashboard);
  }
  loginShell.classList.add("hidden");
  sidebar.classList.remove("hidden");
  main.classList.remove("hidden");
}

function renderAdmin(data) {
  document.getElementById("page-title").textContent = "Admin Console";
  document.getElementById("page-subtitle").textContent = "Workspace creation, bootstrap and oversight";
  document.getElementById("hero-copy").innerHTML = `
    <div class="eyebrow">Admin workspace</div>
    <h2>Single-pane control of clients, credentials and remote signals.</h2>
    <p>The control plane keeps tenant scope separate and publishes only engagement-bound data to each client.</p>
  `;
  document.getElementById("kpi-grid").innerHTML = `
    <div class="kpi-card"><div class="kpi-label">Engagements</div><div class="kpi-value">${data.engagements.length}</div></div>
    <div class="kpi-card"><div class="kpi-label">Mode</div><div class="kpi-value">Admin</div></div>
    <div class="kpi-card"><div class="kpi-label">Bootstrap</div><div class="kpi-value">Ready</div></div>
    <div class="kpi-card"><div class="kpi-label">Tenancy</div><div class="kpi-value">Scoped</div></div>
  `;
  document.getElementById("notifications").innerHTML = `<div class="feed-item"><div class="title">Bootstrap credentials available</div><div class="meta">${data.bootstrap_path}</div></div>`;
  document.getElementById("recent-flow").innerHTML = data.engagements.map((item) => `
    <div class="feed-item">
      <div class="title">${item.project_name}</div>
      <div class="meta">${item.start_date} - ${item.end_date} | ${item.live ? "LIVE" : "OFFLINE"}</div>
    </div>
  `).join("");
  document.getElementById("planning-snapshot").innerHTML = data.engagements.map((item) => `
    <tr><td>${item.start_date} → ${item.end_date}</td><td>${item.project_name}</td><td>${item.client_name}</td></tr>
  `).join("");
  document.getElementById("admin-engagements").innerHTML = data.engagements.map((item) => `
    <div class="stack-card"><strong>${item.project_name}</strong><p>${item.client_name} · ${item.live ? "LIVE" : "OFFLINE"}</p></div>
  `).join("");
  activateScreen("admin");
}

function renderClient(data) {
  const engagement = data.engagement;
  document.getElementById("page-title").textContent = "Digital Audit Command Center";
  document.getElementById("page-subtitle").textContent = `${engagement.client_name} · ${engagement.project_name} · ${engagement.start_date} → ${engagement.end_date}`;
  document.getElementById("hero-copy").innerHTML = `
    <div class="eyebrow">Digital Audit · single LLM</div>
    <h2>Workspace for ${engagement.project_name}</h2>
    <p>The dashboard publishes only signed deliverables, scoped planning and the parsed risk register for your engagement.</p>
  `;
  document.getElementById("kpi-grid").innerHTML = `
    <div class="kpi-card"><div class="kpi-label">Window</div><div class="kpi-value">${engagement.start_date.slice(5)} → ${engagement.end_date.slice(5)}</div></div>
    <div class="kpi-card"><div class="kpi-label">Deliverables</div><div class="kpi-value">${data.deliverables.length}</div></div>
    <div class="kpi-card"><div class="kpi-label">Register Items</div><div class="kpi-value">${data.risk_register.total_entries || 0}</div></div>
    <div class="kpi-card"><div class="kpi-label">Critical Grade</div><div class="kpi-value">${data.risk_register.critical_entries || 0}</div></div>
  `;
  const live = engagement.live;
  const dot = document.getElementById("status-dot");
  dot.classList.toggle("live", live);
  document.getElementById("status-label").textContent = live ? "LIVE" : "OFFLINE";
  document.getElementById("scope-template").textContent = engagement.scope_template;
  document.getElementById("roe-template").textContent = engagement.roe_template;
  document.getElementById("notifications").innerHTML = (data.notifications || []).map((item) => `
    <div class="feed-item"><div class="title">${item.title}</div><div class="meta">${item.created_at} | ${item.level}</div><div>${item.body}</div></div>
  `).join("");
  document.getElementById("recent-flow").innerHTML = (data.events || []).map((item) => `
    <div class="feed-item"><div class="title">${item.message}</div><div class="meta">${item.created_at} | ${item.level}</div></div>
  `).join("");
  const tasks = data.planning.tasks || [];
  const planningRows = renderPlanningVisual(data.planning || {}, tasks);
  document.getElementById("planning-snapshot").innerHTML = planningRows.slice(0, 6).map((item) => `
    <tr><td>${escapeHtml(formatTaskDate(item.start))} → ${escapeHtml(formatTaskDate(item.end))}</td><td>${escapeHtml(item.name || item.wbs || "")}</td><td>${escapeHtml(item.owner || "")}</td></tr>
  `).join("");
  document.getElementById("planning-table").innerHTML = planningRows.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || item.wbs || "")}</td>
      <td>${escapeHtml(formatTaskDate(item.start))}</td>
      <td>${escapeHtml(formatTaskDate(item.end))}</td>
      <td>${escapeHtml(item.owner || "")}</td>
      <td>${escapeHtml(item.status || "")}</td>
    </tr>
  `).join("");
  const deliverablesList = document.getElementById("deliverables-list");
  const placeholder = document.getElementById("deliverables-placeholder");
  if (data.deliverables.length === 0) {
    placeholder.classList.remove("hidden");
    placeholder.textContent = data.deliverables_placeholder;
    deliverablesList.innerHTML = "";
  } else {
    placeholder.classList.add("hidden");
    deliverablesList.innerHTML = data.deliverables.map((item) => `
      <div class="stack-card">
        <strong>${item.kind}</strong>
        <p>${item.filename}</p>
        <p class="muted">${item.created_at}</p>
        <a class="btn btn-outline" href="${item.download_url}">Download</a>
      </div>
    `).join("");
  }
  const executiveEntries = data.risk_register.executive_entries || [];
  document.getElementById("risk-executive").innerHTML = executiveEntries.map((item) => `
    <tr>
      <td>${item["Finding ID"] || ""}</td>
      <td>${item.Title || ""}</td>
      <td>${item.Grade || ""}</td>
      <td>${item.Classification || item["Classification (Red Flag / Negotiation Relevant / Integration Item / Observation)"] || ""}</td>
    </tr>
  `).join("");
  document.getElementById("risk-stats").innerHTML = `
    <div class="kpi-card"><div class="kpi-label">Sheets</div><div class="kpi-value">${(data.risk_register.sheet_names || []).length}</div></div>
    <div class="kpi-card"><div class="kpi-label">Entries</div><div class="kpi-value">${data.risk_register.total_entries || 0}</div></div>
    <div class="kpi-card"><div class="kpi-label">Critical</div><div class="kpi-value">${data.risk_register.critical_entries || 0}</div></div>
    <div class="kpi-card"><div class="kpi-label">Mode</div><div class="kpi-value">${live ? "Live" : "Standby"}</div></div>
  `;
  document.getElementById("faq-list").innerHTML = (data.faq || []).map((item) => `
    <div class="stack-card"><h3>${item.question}</h3><p>${item.answer}</p></div>
  `).join("");
  activateScreen("dashboard");
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!state.mfaToken) {
      const login = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: document.getElementById("username").value,
          password: document.getElementById("password").value,
        }),
      });
      state.mfaToken = login.token;
      mfaBlock.classList.remove("hidden");
      if (login.status === "mfa_setup_required") {
        await setupMfa();
      } else {
        mfaSetup.classList.add("hidden");
      }
      setStatus("Inserisci il codice TOTP del tuo authenticator.", "muted");
      return;
    }
    const verify = await api("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({
        token: state.mfaToken,
        code: document.getElementById("mfa-code").value,
      }),
    });
    state.token = verify.access_token;
    setStatus("");
    await loadDashboard();
  } catch (error) {
    setStatus(error.message, "error");
  }
});

document.getElementById("engagement-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const result = await api("/api/admin/engagements", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    document.getElementById("engagement-result").textContent = `Created ${result.engagement_slug} | user=${result.username} | agent=${result.agent_key}`;
  } catch (error) {
    document.getElementById("engagement-result").textContent = error.message;
  }
});

navItems.forEach((item) => {
  item.addEventListener("click", () => activateScreen(item.dataset.screen));
});

document.getElementById("live-date").textContent = new Date().toLocaleString("it-IT");
