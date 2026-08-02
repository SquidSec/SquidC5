/* SquidC5 ops console — app-shell views (loaded after auth) */
(function () {
  const api = window.__SC5_API__ || window.__SC5_api;
  const $ = window.__SC5_$;
  const showError = window.__SC5_showError;
  const showOk = window.__SC5_showOk;
  const showOutput = window.__SC5_showOutput;
  const can = window.__SC5_can;
  const state = window.__SC5_STATE__;
  const esc = window.__SC5_esc || ((s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"));
  if (!api || !$) return;

  const DOCS = window.__SC5_DOCS || "https://github.com/SquidSec/SquidC5/blob/master/docs/user-guide.md";
  function loadSel(key) {
    try { return localStorage.getItem(key) || null; } catch (_) { return null; }
  }
  function saveSel(key, val) {
    try {
      if (val) localStorage.setItem(key, val);
      else localStorage.removeItem(key);
    } catch (_) {}
  }

  let selectedId = state.selectedId || loadSel("sc5_ops_sid") || null;
  let selectedListenerId = loadSel("sc5_ops_lid") || null;
  let cache = { sessions: [], listeners: [] };
  let viewBuilt = {}; // track which views already rendered structure

  function el(id) { return document.getElementById(id); }
  function tools(html) { const t = el("viewTools"); if (t) t.innerHTML = html || ""; }
  function shortId(id) { return (id || "").length > 14 ? id.slice(0, 12) + "…" : (id || ""); }
  function metaOf(s) {
    let m = s && s.metadata;
    if (typeof m === "string") { try { m = JSON.parse(m); } catch (_) { m = {}; } }
    return m || {};
  }
  function docHref(anchor) {
    return DOCS + (anchor ? "#" + anchor : "");
  }
  /** Per-page doc menus (single button in header — no spam links in body) */
  const PAGE_DOCS = {
    dashboard: [
      { a: "status-overview", t: "Status overview" },
      { a: "connection", t: "Connection" },
      { a: "sessions", t: "Sessions" },
    ],
    sessions: [
      { a: "sessions", t: "Sessions" },
      { a: "shell", t: "Shell interact" },
      { a: "tasks", t: "Tasks / beacons" },
    ],
    listeners: [
      { a: "listeners", t: "Listeners" },
      { a: "payloads-and-implants", t: "Payloads" },
    ],
    payloads: [
      { a: "payloads-and-implants", t: "Payloads & implants" },
      { a: "c2-profiles", t: "C2 profiles" },
    ],
    postex: [
      { a: "file-ops", t: "File ops" },
      { a: "socks-pivot", t: "SOCKS pivot" },
      { a: "modules", t: "Inject / BOF" },
    ],
    collab: [
      { a: "multi-operator-collab", t: "Multi-op collab" },
      { a: "operator-chat", t: "Operator chat" },
      { a: "hitl", t: "HITL queue" },
    ],
    ai: [
      { a: "admin-ai", t: "Admin AI" },
      { a: "llm-connections", t: "LLM connections" },
    ],
    observe: [
      { a: "timeline-and-reports", t: "Timeline & reports" },
      { a: "audit-me", t: "Audit" },
    ],
    admin: [
      { a: "tokens", t: "Tokens" },
      { a: "feature-toggles", t: "Feature toggles" },
      { a: "policy", t: "Policy" },
      { a: "llm-connections", t: "LLM connections" },
      { a: "mcp-tools", t: "MCP tools" },
    ],
  };
  function setPageDocs(viewName) {
    const btn = el("viewDocsBtn");
    const menu = el("viewDocsMenu");
    if (!btn || !menu) return;
    const items = PAGE_DOCS[viewName] || [{ a: "", t: "User guide" }];
    menu.innerHTML = items.map((it) =>
      `<a href="${esc(docHref(it.a))}" target="_blank" rel="noopener noreferrer">${esc(it.t)}</a>`
    ).join("") +
      `<a href="${esc(DOCS)}" target="_blank" rel="noopener noreferrer">Full user guide</a>` +
      `<a href="https://github.com/SquidSec/SquidC5/blob/master/docs/operator-runbook.md" target="_blank" rel="noopener noreferrer">Operator runbook</a>`;
    menu.onclick = (e) => e.stopPropagation();
    btn.onclick = (e) => {
      e.stopPropagation();
      menu.classList.toggle("open");
    };
  }
  document.addEventListener("click", () => {
    const menu = el("viewDocsMenu");
    if (menu) menu.classList.remove("open");
  });
  const AI_CAPS = [
    "recon_assist", "session_triage", "task_suggest", "shell_classify", "opsec_review",
    "payload_template", "evasion_suggest", "beacon_anomaly", "report_draft", "hitl_brief",
    "anomaly_explain", "profile_mutate", "implant_build_plan", "phishing_asset", "doc_generate",
  ];

  function llmFormHtml(prefix) {
    const canSave = can("llm:manage") || can("admin");
    return `
      <p class="muted" style="font-size:0.78rem;margin:0 0 8px">API keys encrypted at rest; never returned by API. xAI / OpenAI / local Ollama.</p>
      <div class="form-grid">
        <div><label>Name</label><input id="${prefix}Name" placeholder="grok-prod" /></div>
        <div><label>Provider</label>
          <select id="${prefix}Provider">
            <option value="xai">xAI (Grok)</option>
            <option value="openai">OpenAI-compatible</option>
            <option value="ollama">Ollama (localhost)</option>
          </select>
        </div>
        <div class="full"><label>Model</label><input id="${prefix}Model" placeholder="grok-3" value="grok-3" /></div>
        <div class="full"><label>Base URL</label>
          <input id="${prefix}Base" placeholder="https://api.x.ai/v1" value="https://api.x.ai/v1" />
        </div>
        <div class="full"><label>API key</label>
          <input id="${prefix}Key" type="password" placeholder="xai-… / sk-… (never shown again)" autocomplete="off" />
        </div>
      </div>
      <div class="row">
        <button type="button" class="primary" id="${prefix}Save" ${canSave ? "" : "disabled"}>Save LLM</button>
        <button type="button" id="${prefix}List">List saved</button>
      </div>
      <div class="outbox empty" id="${prefix}Out">—</div>`;
  }
  function bindLlmForm(prefix) {
    if (el(prefix + "Provider")) el(prefix + "Provider").onchange = () => {
      const p = el(prefix + "Provider").value;
      if (p === "xai") {
        el(prefix + "Base").value = "https://api.x.ai/v1";
        if (!el(prefix + "Model").value || el(prefix + "Model").value === "gpt-4o-mini") el(prefix + "Model").value = "grok-3";
      } else if (p === "openai") {
        el(prefix + "Base").value = "https://api.openai.com/v1";
        if (!el(prefix + "Model").value || el(prefix + "Model").value === "grok-3") el(prefix + "Model").value = "gpt-4o-mini";
      } else if (p === "ollama") {
        el(prefix + "Base").value = "http://127.0.0.1:11434/v1";
        el(prefix + "Model").value = el(prefix + "Model").value || "llama3.2";
      }
    };
    if (el(prefix + "Save")) el(prefix + "Save").onclick = async () => {
      try {
        const name = (el(prefix + "Name").value || "").trim();
        const model = (el(prefix + "Model").value || "").trim();
        const base_url = (el(prefix + "Base").value || "").trim();
        const api_key = (el(prefix + "Key").value || "").trim();
        const provider = el(prefix + "Provider").value || "openai";
        if (!name || !model) return showError("Name and model required");
        if (!api_key && provider !== "ollama") return showError("API key required (except local Ollama)");
        const body = {
          name, provider, model,
          base_url: base_url || null,
          api_key: api_key || null,
          capabilities: AI_CAPS,
        };
        const r = await api("POST", "/api/v1/llm", body);
        el(prefix + "Out").textContent = JSON.stringify(r, null, 2);
        el(prefix + "Out").classList.remove("empty");
        if (el(prefix + "Key")) el(prefix + "Key").value = "";
        showOk("LLM saved (key encrypted at rest)");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el(prefix + "List")) el(prefix + "List").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/llm");
        el(prefix + "Out").textContent = JSON.stringify(r, null, 2);
        el(prefix + "Out").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  /* —— Context rail —— */
  let ctxBoundSid = null;
  function bindContextHandlers() {
    if (el("ctxClaim")) el("ctxClaim").onclick = async () => {
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/claim`, {});
        showOk("Claimed");
        if (el("ctxOut")) { el("ctxOut").textContent = JSON.stringify(r, null, 2); el("ctxOut").classList.remove("empty"); }
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxRelease")) el("ctxRelease").onclick = async () => {
      try {
        await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/release`);
        showOk("Released");
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxSpectate")) el("ctxSpectate").onclick = async () => {
      try {
        const r = await api("GET", `/api/v1/sessions/${encodeURIComponent(selectedId)}/spectator`);
        if (el("ctxOut")) { el("ctxOut").textContent = JSON.stringify(r, null, 2); el("ctxOut").classList.remove("empty"); }
        showOk("Spectator snapshot");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxRun")) el("ctxRun").onclick = async () => {
      const command = (el("ctxCmd").value || "").trim();
      if (!command) return showError("Command required");
      try {
        const r = await api("POST", "/api/v1/shell/command", { session_id: selectedId, command, wait_sec: 5 });
        const out = r.output || r.result || JSON.stringify(r, null, 2);
        showOutput(out, "$ " + command);
        if (el("ctxOut")) { el("ctxOut").textContent = out; el("ctxOut").classList.remove("empty"); }
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxTaskBtn")) el("ctxTaskBtn").onclick = async () => {
      const command = (el("ctxTask").value || "").trim();
      if (!command) return showError("Command required");
      try {
        const r = await api("POST", "/api/v1/tasks", { session_id: selectedId, command });
        showOk("Task " + (r.id || "queued"));
        if (el("ctxOut")) { el("ctxOut").textContent = JSON.stringify(r, null, 2); el("ctxOut").classList.remove("empty"); }
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  async function renderContext(force) {
    const body = el("ctxBody");
    if (!body) return;
    if (!selectedId) {
      ctxBoundSid = null;
      body.innerHTML = `<div class="ctx-empty">Select a session from <strong>Sessions</strong> to claim, shell, or task it.</div>`;
      return;
    }
    let s = cache.sessions.find((x) => x.id === selectedId);
    try { s = await api("GET", "/api/v1/sessions/" + encodeURIComponent(selectedId)); } catch (_) {}
    if (!s) {
      body.innerHTML = '<div class="ctx-empty">Session not found (may be closed).</div>';
      ctxBoundSid = null;
      return;
    }
    const m = metaOf(s);
    // Soft update: keep form fields if same session already bound
    if (!force && ctxBoundSid === selectedId && el("ctxMeta")) {
      el("ctxMeta").innerHTML = `
        <div class="mono" style="font-size:0.7rem;color:var(--muted);margin-bottom:6px">${esc(s.id)}</div>
        <div style="font-weight:700;margin-bottom:4px">${esc(s.hostname || s.remote_addr || "session")}</div>
        <div class="chips" style="margin-bottom:10px">
          <span class="chip">${esc(s.kind || "?")}</span>
          <span class="chip ${s.verified ? "ok" : ""}">${s.verified ? "verified" : esc(s.status || "")}</span>
          ${m.claimed_by ? `<span class="chip warn">🔒 ${esc(m.claimed_by)}</span>` : '<span class="chip">unlocked</span>'}
        </div>
        <div class="muted" style="font-size:0.78rem;margin-bottom:8px">
          User: ${esc(s.username || "—")}<br/>OS: ${esc(s.os_info || "—")}<br/>Addr: ${esc(s.remote_addr || "—")}
        </div>`;
      return;
    }
    const shellOk = can("shell:interact") && (s.kind === "reverse_shell" || s.interactive || s.verified);
    body.innerHTML = `
      <div id="ctxMeta"></div>
      <div class="row">
        ${can("shell:interact") || can("collab:use") ? '<button type="button" class="primary" id="ctxClaim">Claim</button>' : ""}
        ${can("shell:interact") || can("collab:use") ? '<button type="button" id="ctxRelease">Release</button>' : ""}
        ${can("sessions:read") ? '<button type="button" id="ctxSpectate">Spectate</button>' : ""}
      </div>
      ${shellOk ? `
        <label for="ctxCmd">Shell command</label>
        <textarea id="ctxCmd" rows="2" placeholder="whoami"></textarea>
        <div class="row"><button type="button" class="primary" id="ctxRun">Run</button></div>
      ` : ""}
      ${can("tasks:write") ? `
        <label for="ctxTask">Beacon task</label>
        <input id="ctxTask" placeholder="id / sysinfo / pwd" />
        <div class="row"><button type="button" class="primary" id="ctxTaskBtn">Queue task</button></div>
      ` : ""}
      <div class="outbox empty" id="ctxOut">—</div>
    `;
    ctxBoundSid = selectedId;
    // fill meta
    const metaEl = el("ctxMeta");
    if (metaEl) {
      metaEl.innerHTML = `
        <div class="mono" style="font-size:0.7rem;color:var(--muted);margin-bottom:6px">${esc(s.id)}</div>
        <div style="font-weight:700;margin-bottom:4px">${esc(s.hostname || s.remote_addr || "session")}</div>
        <div class="chips" style="margin-bottom:10px">
          <span class="chip">${esc(s.kind || "?")}</span>
          <span class="chip ${s.verified ? "ok" : ""}">${s.verified ? "verified" : esc(s.status || "")}</span>
          ${m.claimed_by ? `<span class="chip warn">🔒 ${esc(m.claimed_by)}</span>` : '<span class="chip">unlocked</span>'}
        </div>
        <div class="muted" style="font-size:0.78rem;margin-bottom:8px">
          User: ${esc(s.username || "—")}<br/>OS: ${esc(s.os_info || "—")}<br/>Addr: ${esc(s.remote_addr || "—")}
        </div>`;
    }
    bindContextHandlers();
  }

  function selectSession(id) {
    selectedId = id || null;
    state.selectedId = selectedId;
    saveSel("sc5_ops_sid", selectedId);
    document.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-sid") === selectedId);
    });
    const s = cache.sessions.find((x) => x.id === selectedId);
    const box = el("sesDetail");
    if (box) {
      if (s) {
        box.textContent = JSON.stringify(s, null, 2);
        box.classList.remove("empty");
      } else if (!selectedId) {
        box.textContent = "Select a session…";
        box.classList.add("empty");
      }
    }
    if (el("pxSid")) el("pxSid").textContent = selectedId || "(none — pick in Sessions)";
    renderContext();
    if (el("tskList")) loadTasksPanel();
  }
  window.__SC5_selectSession = selectSession;

  function fillSessionRows(tbody) {
    if (!tbody) return;
    const rows = cache.sessions || [];
    if (!rows.length) {
      tbody.innerHTML = "";
      const empty = tbody.closest(".lp-body");
      if (empty && !empty.querySelector(".empty-state")) {
        // handled by parent
      }
      return;
    }
    tbody.innerHTML = rows.map((s) => {
      const m = metaOf(s);
      return `<tr data-sid="${esc(s.id)}" class="${s.id === selectedId ? "selected" : ""}">
        <td class="mono">${esc(shortId(s.id))}${m.claimed_by ? " 🔒" : ""}</td>
        <td>${esc(s.kind || "")}</td>
        <td>${esc(s.hostname || s.remote_addr || "—")}</td>
      </tr>`;
    }).join("");
    tbody.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.onclick = () => selectSession(tr.getAttribute("data-sid"));
    });
    // restore highlight if still present
    if (selectedId && !rows.some((s) => s.id === selectedId)) {
      // keep id in state but mark missing in detail
      const box = el("sesDetail");
      if (box) {
        box.textContent = "Selected session not in active list (may be closed). id=" + selectedId;
        box.classList.remove("empty");
      }
    }
  }

  /* —— Sessions view —— */
  function renderSessionsView(force) {
    const root = el("view-sessions");
    if (!root) return;
    if (!force && viewBuilt.sessions && root.querySelector("#sesTbody")) {
      fillSessionRows(el("sesTbody"));
      const count = el("sesCount");
      if (count) count.textContent = String((cache.sessions || []).length);
      return;
    }
    const rows = cache.sessions || [];
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">Active <span id="sesCount" style="margin-left:auto" class="muted">${rows.length}</span></div>
          <div class="lp-body" id="sesListBody">
            ${rows.length
              ? `<table class="data"><thead><tr><th>Session</th><th>Kind</th><th>Host</th></tr></thead><tbody id="sesTbody"></tbody></table>`
              : '<div class="empty-state" id="sesEmpty"><strong>No sessions</strong>Land a beacon or reverse shell.</div>'}
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Session actions</div>
          <div class="wp-body">
            <div class="toolbar">
              ${can("sessions:write") ? '<button type="button" id="sesReap">Reap dead</button>' : ""}
              ${can("sessions:write") ? '<button type="button" class="danger" id="sesClose">Close selected</button>' : ""}
              <button type="button" id="sesRefresh">Refresh</button>
            </div>
            <p class="muted" style="font-size:0.85rem;margin:0">
              Click a row to load the <strong>context rail</strong>. Claim before multi-op tasking.
              Shell = verified reverse shells; Tasks = beacons.
            </p>
            <div id="sesDetail" class="outbox empty" style="margin-top:12px">Select a session…</div>
            <div class="wp-head" style="margin-top:12px;border-top:1px solid var(--border);padding-top:8px">
              Pending tasks
            </div>
            <div class="toolbar" style="margin-top:6px">
              <button type="button" id="tskReload">Reload tasks</button>
              ${can("tasks:write") ? '<button type="button" class="danger" id="tskCancel">Cancel selected</button>' : ""}
              ${can("tasks:write") ? '<button type="button" id="tskSave">Save edit</button>' : ""}
            </div>
            <div id="tskList" class="lp-body" style="max-height:180px;border:1px solid var(--border);border-radius:6px;margin-top:6px"></div>
            <label for="tskCmd">Edit command (pending only)</label>
            <input id="tskCmd" placeholder="select a pending task" />
            <p class="muted mono" id="tskHint" style="font-size:0.7rem;margin:4px 0 0">—</p>
          </div>
        </div>
      </div>
    `;
    viewBuilt.sessions = true;
    if (rows.length) {
      fillSessionRows(el("sesTbody"));
    }
    if (el("sesReap")) el("sesReap").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/sessions/reap", {});
        showOk("Reaped");
        showOutput(JSON.stringify(r, null, 2));
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("sesClose")) el("sesClose").onclick = async () => {
      if (!selectedId) return showError("Select a session");
      const sid = selectedId;
      try {
        await api("POST", "/api/v1/sessions/" + encodeURIComponent(sid) + "/close");
        showOk("Closed");
        selectSession(null);
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) {
        try {
          await api("DELETE", "/api/v1/sessions/" + encodeURIComponent(sid));
          showOk("Closed");
          selectSession(null);
          if (window.__SC5_refresh) await window.__SC5_refresh();
        } catch (e2) { showError(String(e2.message || e2)); }
      }
    };
    if (el("sesRefresh")) el("sesRefresh").onclick = () => window.__SC5_refresh && window.__SC5_refresh();
    if (el("tskReload")) el("tskReload").onclick = () => loadTasksPanel();
    if (el("tskCancel")) el("tskCancel").onclick = () => cancelSelectedTask();
    if (el("tskSave")) el("tskSave").onclick = () => saveSelectedTask();
    tools(` <button type="button" class="primary" id="toolNewShell">Focus rail</button>`);
    if (el("toolNewShell")) el("toolNewShell").onclick = () => {
      if (!selectedId) return showError("Select a session first");
      renderContext();
    };
    if (selectedId) selectSession(selectedId);
    loadTasksPanel();
  }

  let selectedTaskId = null;
  async function loadTasksPanel() {
    const box = el("tskList");
    if (!box) return;
    if (!can("tasks:read") && !can("admin")) {
      box.innerHTML = '<div class="muted" style="padding:8px">Need tasks:read</div>';
      return;
    }
    try {
      if (!selectedId) {
        box.innerHTML = '<div class="muted" style="padding:8px">Select a session to list pending tasks</div>';
        selectedTaskId = null;
        return;
      }
      const q = `/api/v1/tasks?session_id=${encodeURIComponent(selectedId)}&status=pending`;
      let tasks = await api("GET", q);
      if (!Array.isArray(tasks)) tasks = tasks.tasks || [];
      if (!tasks.length) {
        box.innerHTML = '<div class="muted" style="padding:8px">No pending tasks for this session</div>';
        selectedTaskId = null;
        return;
      }
      box.innerHTML = `<table class="data"><thead><tr><th>ID</th><th>Session</th><th>Command</th><th>Status</th></tr></thead><tbody>
        ${tasks.map((t) => `<tr data-tid="${esc(t.id)}" class="${t.id === selectedTaskId ? "selected" : ""}">
          <td class="mono">${esc(shortId(t.id))}</td>
          <td class="mono">${esc(shortId(t.session_id))}</td>
          <td>${esc(t.command || "")}</td>
          <td><span class="chip">${esc(t.status || "")}</span></td>
        </tr>`).join("")}
      </tbody></table>`;
      box.querySelectorAll("tr[data-tid]").forEach((tr) => {
        tr.onclick = () => {
          selectedTaskId = tr.getAttribute("data-tid");
          box.querySelectorAll("tr").forEach((x) => x.classList.remove("selected"));
          tr.classList.add("selected");
          const t = tasks.find((x) => x.id === selectedTaskId);
          if (t && el("tskCmd")) el("tskCmd").value = t.command || "";
          if (el("tskHint")) el("tskHint").textContent = t
            ? `Editing ${t.id} (${t.status}) · session ${t.session_id}`
            : "—";
        };
      });
    } catch (e) {
      box.innerHTML = `<div class="muted" style="padding:8px">${esc(String(e.message || e))}</div>`;
    }
  }
  async function cancelSelectedTask() {
    if (!selectedTaskId) return showError("Select a pending task");
    try {
      await api("POST", `/api/v1/tasks/${encodeURIComponent(selectedTaskId)}/cancel`);
      showOk("Task cancelled");
      selectedTaskId = null;
      await loadTasksPanel();
    } catch (e) { showError(String(e.message || e)); }
  }
  async function saveSelectedTask() {
    if (!selectedTaskId) return showError("Select a pending task");
    const command = (el("tskCmd") && el("tskCmd").value || "").trim();
    if (!command) return showError("Command required");
    try {
      await api("PATCH", `/api/v1/tasks/${encodeURIComponent(selectedTaskId)}`, { command });
      showOk("Task updated");
      await loadTasksPanel();
    } catch (e) { showError(String(e.message || e)); }
  }

  /* —— Listeners —— */
  function fillListenerRows(tbody) {
    if (!tbody) return;
    const rows = cache.listeners || [];
    tbody.innerHTML = rows.map((l) => `<tr data-lid="${esc(l.id)}" class="${l.id === selectedListenerId ? "selected" : ""}">
      <td>${esc(l.name || shortId(l.id))}</td>
      <td class="mono">${esc(l.port)}</td>
      <td>${esc(l.kind)}</td>
      <td><span class="chip ${l.status === "running" ? "ok" : ""}">${esc(l.status || "—")}</span></td>
    </tr>`).join("") || '<tr><td colspan="4" class="muted">None</td></tr>';
    tbody.querySelectorAll("tr[data-lid]").forEach((tr) => {
      tr.onclick = () => {
        selectedListenerId = tr.getAttribute("data-lid");
        saveSel("sc5_ops_lid", selectedListenerId);
        tbody.querySelectorAll("tr").forEach((x) => x.classList.remove("selected"));
        tr.classList.add("selected");
        populateListenerForm(selectedListenerId);
      };
    });
  }

  function populateListenerForm(lid) {
    const l = (cache.listeners || []).find((x) => x.id === lid);
    if (!l) return;
    if (el("lisName")) el("lisName").value = l.name || "";
    if (el("lisPort")) el("lisPort").value = l.port != null ? String(l.port) : "";
    if (el("lisKind")) el("lisKind").value = l.kind || "reverse_shell";
    const cfg = l.config || {};
    if (el("lisZone")) el("lisZone").value = cfg.zone || cfg.dns_zone || "";
    if (el("lisIdHint")) el("lisIdHint").textContent = "Selected: " + (l.id || "") + " · " + (l.status || "");
  }


  function renderListenersView(force) {
    const root = el("view-listeners");
    if (!root) return;
    if (!force && viewBuilt.listeners && el("lisTbody")) {
      fillListenerRows(el("lisTbody"));
      return;
    }
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">Listeners</div>
          <div class="lp-body">
            <table class="data"><thead><tr><th>Name</th><th>Port</th><th>Kind</th><th>Status</th></tr></thead>
            <tbody id="lisTbody"></tbody></table>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Manage</div>
          <div class="wp-body">
            ${can("listeners:write") ? `
              <p class="muted mono" id="lisIdHint" style="font-size:0.72rem;margin:0 0 6px">Select a listener to load fields</p>
              <div class="form-grid">
                <div><label>Name</label><input id="lisName" placeholder="rev443" /></div>
                <div><label>Port</label><input id="lisPort" type="number" placeholder="443" /></div>
                <div class="full"><label>Kind</label>
                  <select id="lisKind">
                    <option value="reverse_shell">reverse_shell</option>
                    <option value="http">http</option>
                    <option value="tcp">tcp</option>
                    <option value="dns">dns</option>
                  </select>
                </div>
                <div class="full"><label>DNS zone (dns only)</label><input id="lisZone" placeholder="oast.example.com" /></div>
              </div>
              <div class="row">
                <button type="button" class="primary" id="lisCreate">Create + start</button>
                <button type="button" id="lisStart">Start</button>
                <button type="button" id="lisStop">Stop</button>
                <button type="button" class="danger" id="lisDel">Delete</button>
                <button type="button" id="lisClear">Clear form</button>
              </div>
            ` : '<p class="muted">Read-only token</p>'}
            <div class="outbox empty" id="lisOut">—</div>
          </div>
        </div>
      </div>
    `;
    viewBuilt.listeners = true;
    fillListenerRows(el("lisTbody"));
    if (selectedListenerId) populateListenerForm(selectedListenerId);
    async function lisAct(fn) {
      try {
        const r = await fn();
        el("lisOut").textContent = JSON.stringify(r, null, 2);
        el("lisOut").classList.remove("empty");
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) { showError(String(e.message || e)); }
    }
    if (el("lisCreate")) el("lisCreate").onclick = () => lisAct(async () => {
      const name = (el("lisName").value || "").trim();
      const port = Number(el("lisPort").value);
      const kind = el("lisKind").value;
      const zone = (el("lisZone").value || "").trim();
      if (!name || !port) throw new Error("Name and port required");
      const config = kind === "dns" && zone ? { zone } : {};
      const created = await api("POST", "/api/v1/listeners", { name, port, kind, host: "0.0.0.0", config });
      await api("POST", `/api/v1/listeners/${created.id}/start`);
      selectedListenerId = created.id;
      saveSel("sc5_ops_lid", selectedListenerId);
      showOk("Listener running");
      return created;
    });
    if (el("lisStart")) el("lisStart").onclick = () => {
      if (!selectedListenerId) return showError("Select listener");
      lisAct(() => api("POST", `/api/v1/listeners/${selectedListenerId}/start`));
    };
    if (el("lisStop")) el("lisStop").onclick = () => {
      if (!selectedListenerId) return showError("Select listener");
      lisAct(() => api("POST", `/api/v1/listeners/${selectedListenerId}/stop`));
    };
    if (el("lisDel")) el("lisDel").onclick = () => {
      if (!selectedListenerId) return showError("Select listener");
      lisAct(async () => {
        const id = selectedListenerId;
        selectedListenerId = null;
        saveSel("sc5_ops_lid", null);
        if (el("lisName")) el("lisName").value = "";
        if (el("lisPort")) el("lisPort").value = "";
        if (el("lisIdHint")) el("lisIdHint").textContent = "Select a listener to load fields";
        return api("DELETE", `/api/v1/listeners/${id}`);
      });
    };
    if (el("lisClear")) el("lisClear").onclick = () => {
      selectedListenerId = null;
      saveSel("sc5_ops_lid", null);
      if (el("lisName")) el("lisName").value = "";
      if (el("lisPort")) el("lisPort").value = "";
      if (el("lisZone")) el("lisZone").value = "";
      if (el("lisKind")) el("lisKind").value = "reverse_shell";
      if (el("lisIdHint")) el("lisIdHint").textContent = "Select a listener to load fields";
      document.querySelectorAll("#lisTbody tr").forEach((x) => x.classList.remove("selected"));
    };
  }

  /* —— Payloads —— */
  function renderPayloadsView() {
    const root = el("view-payloads");
    if (!root) return;
    const host = (() => { try { return location.hostname || "127.0.0.1"; } catch (_) { return "127.0.0.1"; } })();
    root.innerHTML = `
      <div class="work-panel" style="min-height:360px">
        <div class="wp-head">Generate</div>
        <div class="wp-body">
          ${can("payloads:generate") ? `
            <div class="form-grid">
              <div class="full"><label>Template</label>
                <select id="payTpl">
                  <option value="http_beacon_python">http_beacon_python</option>
                  <option value="http_beacon_bash">http_beacon_bash</option>
                  <option value="reverse_shell_bash">reverse_shell_bash</option>
                  <option value="reverse_shell_python">reverse_shell_python</option>
                  <option value="ws_beacon_python">ws_beacon_python</option>
                </select>
              </div>
              <div><label>Host</label><input id="payHost" value="${esc(host)}" /></div>
              <div><label>Port</label><input id="payPort" type="number" value="${location.port || 8443}" /></div>
            </div>
            <div class="row">
              <button type="button" class="primary" id="payGen">Generate</button>
              <button type="button" id="payCopy">Copy</button>
            </div>
          ` : '<p class="muted">Need payloads:generate scope</p>'}
          <div class="outbox empty" id="payOut">—</div>
        </div>
      </div>
    `;
    if (el("payGen")) el("payGen").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/payloads/generate", {
          template: el("payTpl").value,
          host: el("payHost").value.trim(),
          port: Number(el("payPort").value),
        });
        const text = r.content || r.payload || JSON.stringify(r, null, 2);
        el("payOut").textContent = text;
        el("payOut").classList.remove("empty");
        showOk("Generated");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("payCopy")) el("payCopy").onclick = async () => {
      try {
        await navigator.clipboard.writeText(el("payOut").textContent || "");
        showOk("Copied");
      } catch (_) { showError("Copy failed"); }
    };
  }

  /* —— Post-ex —— */
  function renderPostexView() {
    const root = el("view-postex");
    if (!root) return;
    root.innerHTML = `
      <p class="muted" style="margin:0 0 10px;font-size:0.85rem">
        Target session: <strong class="mono" id="pxSid">${esc(selectedId || "(none — pick in Sessions)")}</strong>
      </p>
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Files</div>
          <div class="wp-body">
            <label>Op</label>
            <select id="pxOp"><option>list</option><option>read</option><option>write</option><option>delete</option></select>
            <label>Path</label>
            <input id="pxPath" value="." />
            <label>Content (write)</label>
            <textarea id="pxContent" rows="2"></textarea>
            <div class="row"><button type="button" class="primary" id="pxFile" ${can("shell:interact") ? "" : "disabled"}>Queue file op</button></div>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">SOCKS / modules</div>
          <div class="wp-body">
            <div class="row">
              <button type="button" id="pxSocks" ${can("shell:interact") ? "" : "disabled"}>Start SOCKS (loopback)</button>
              <button type="button" id="pxSocksList">List pivots</button>
            </div>
            <label>BOF module</label>
            <input id="pxBof" value="whoami" />
            <div class="row"><button type="button" id="pxBofRun" ${can("shell:interact") ? "" : "disabled"}>Queue bof:run</button></div>
            <div class="outbox empty" id="pxOut">—</div>
          </div>
        </div>
      </div>
    `;
    const needSid = () => {
      if (!selectedId) throw new Error("Select a session in Sessions first");
      return selectedId;
    };
    const out = (r) => {
      el("pxOut").textContent = typeof r === "string" ? r : JSON.stringify(r, null, 2);
      el("pxOut").classList.remove("empty");
    };
    if (el("pxFile")) el("pxFile").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/files/op", {
          session_id: needSid(),
          op: el("pxOp").value,
          path: el("pxPath").value,
          content: el("pxOp").value === "write" ? el("pxContent").value : undefined,
        });
        out(r); showOk("File op queued");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("pxSocks")) el("pxSocks").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/pivot/socks", {
          session_id: needSid(), listen_host: "127.0.0.1", listen_port: 0, mode: "implant",
        });
        out(r); showOk("SOCKS started");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("pxSocksList")) el("pxSocksList").onclick = async () => {
      try { out(await api("GET", "/api/v1/pivot/socks")); } catch (e) { showError(String(e.message || e)); }
    };
    if (el("pxBofRun")) el("pxBofRun").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/modules/bof/run", {
          session_id: needSid(), module_id: (el("pxBof").value || "whoami").trim(),
        });
        out(r); showOk("BOF queued");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  /* —— Collab —— */
  function renderCollabView() {
    const root = el("view-collab");
    if (!root) return;
    root.innerHTML = `
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Chat</div>
          <div class="wp-body">
            <label>Team channel (optional id)</label>
            <input id="chTeam" placeholder="leave empty for global" />
            <label>Message</label>
            <input id="chMsg" placeholder="status update…" />
            <div class="row">
              <button type="button" class="primary" id="chSend" ${can("collab:use") || can("admin") ? "" : "disabled"}>Send</button>
              <button type="button" id="chReload">Reload</button>
            </div>
            <div class="outbox empty" id="chOut">—</div>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Teams / presence / handoff</div>
          <div class="wp-body">
            <div class="row">
              <button type="button" id="tmList">List teams</button>
              <button type="button" id="tmPresence">Who's online</button>
            </div>
            <label>New team name</label>
            <input id="tmName" placeholder="red-cell" />
            <div class="row"><button type="button" class="primary" id="tmCreate">Create team</button></div>
            <label>Handoff to (actor)</label>
            <input id="tmTo" placeholder="bob" />
            <label>Note</label>
            <textarea id="tmNote" rows="2"></textarea>
            <div class="row"><button type="button" id="tmHandoff">Handoff selected session</button></div>
            <div class="outbox empty" id="tmOut">—</div>
          </div>
        </div>
      </div>
    `;
    const out = (id, r) => {
      const n = el(id);
      n.textContent = typeof r === "string" ? r : JSON.stringify(r, null, 2);
      n.classList.remove("empty");
    };
    async function loadChat() {
      const tid = (el("chTeam").value || "").trim();
      const q = tid ? "?team_id=" + encodeURIComponent(tid) : "";
      const r = await api("GET", "/api/v1/collab/chat" + q);
      const lines = (r.messages || []).map((m) => `${m.actor}: ${m.message}`);
      out("chOut", lines.join("\n") || "(empty)");
    }
    if (el("chReload")) el("chReload").onclick = () => loadChat().catch((e) => showError(String(e.message || e)));
    if (el("chSend")) el("chSend").onclick = async () => {
      try {
        const message = (el("chMsg").value || "").trim();
        if (!message) return showError("Message required");
        const team_id = (el("chTeam").value || "").trim() || null;
        await api("POST", "/api/v1/collab/chat", { message, team_id });
        el("chMsg").value = "";
        await loadChat();
        showOk("Sent");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("tmList")) el("tmList").onclick = async () => {
      try { out("tmOut", await api("GET", "/api/v1/teams")); } catch (e) { showError(String(e.message || e)); }
    };
    if (el("tmPresence")) el("tmPresence").onclick = async () => {
      try {
        await api("POST", "/api/v1/collab/presence", { status: "online", viewing_session: selectedId });
        out("tmOut", await api("GET", "/api/v1/collab/presence"));
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("tmCreate")) el("tmCreate").onclick = async () => {
      try {
        const name = (el("tmName").value || "").trim();
        if (!name) return showError("Name required");
        out("tmOut", await api("POST", "/api/v1/teams", { name }));
        showOk("Team created");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("tmHandoff")) el("tmHandoff").onclick = async () => {
      try {
        if (!selectedId) return showError("Select session first");
        const to = (el("tmTo").value || "").trim();
        if (!to) return showError("Target actor required");
        out("tmOut", await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/handoff`, {
          to, note: el("tmNote").value || "", include_pack: true, transfer_claim: true,
        }));
        showOk("Handoff sent");
      } catch (e) { showError(String(e.message || e)); }
    };
    loadChat().catch(() => {});
  }

  /* —— Observe —— */
  function renderObserveView() {
    const root = el("view-observe");
    if (!root) return;
    root.innerHTML = `
      <div class="toolbar">
        <button type="button" class="primary" id="obMetrics">Metrics</button>
        <button type="button" id="obAudit">My audit</button>
        <button type="button" id="obTimeline">Timeline</button>
        <button type="button" id="obReport">Report</button>
        <button type="button" id="obAnom">Anomalies</button>
      </div>
      <div class="outbox empty" id="obOut" style="max-height:480px">—</div>
    `;
    const out = async (path) => {
      try {
        const r = await api("GET", path);
        el("obOut").textContent = typeof r === "string" ? r : (r.markdown || JSON.stringify(r, null, 2));
        el("obOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("obMetrics")) el("obMetrics").onclick = () => out("/api/v1/metrics");
    if (el("obAudit")) el("obAudit").onclick = () => out("/api/v1/audit/me?limit=50");
    if (el("obTimeline")) el("obTimeline").onclick = () => out("/api/v1/observability/timeline?limit=40");
    if (el("obReport")) el("obReport").onclick = () => out("/api/v1/observability/report");
    if (el("obAnom")) el("obAnom").onclick = () => out("/api/v1/observability/anomalies");
  }

  /* —— Admin —— */
  /* —— AI tab —— */
  function renderAiView() {
    const root = el("view-ai");
    if (!root) return;
    if (!can("ai:use") && !can("admin")) {
      root.innerHTML = `<div class="empty-state"><strong>AI locked</strong>Need <code>ai:use</code> scope.</div>`;
      return;
    }
    root.innerHTML = `
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Run capability</div>
          <div class="wp-body">
            <label>Capability</label>
            <select id="aiCap">${AI_CAPS.map((c) => `<option value="${c}">${c}</option>`).join("")}</select>
            <label>Input (untrusted — sanitized server-side)</label>
            <textarea id="aiData" rows="4" placeholder="Describe target, paste metrics text, ask for recon assist…"></textarea>
            <div class="row">
              <button type="button" class="primary" id="aiRun">Run</button>
              <button type="button" id="aiStatus">AI status</button>
              <button type="button" id="aiOpenDrawer">Open floating chat</button>
            </div>
            <div class="outbox empty" id="aiOut">—</div>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Configure LLM (BYO)</div>
          <div class="wp-body">${llmFormHtml("llm")}</div>
        </div>
      </div>
    `;
    bindLlmForm("llm");
    if (el("aiRun")) el("aiRun").onclick = () => runAi(el("aiCap").value, el("aiData").value, "aiOut");
    if (el("aiStatus")) el("aiStatus").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/ai/status");
        el("aiOut").textContent = JSON.stringify(r, null, 2);
        el("aiOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("aiOpenDrawer")) el("aiOpenDrawer").onclick = () => openAiDrawer(true);
  }


  async function runAi(capability, user_data, outId) {
    try {
      const r = await api("POST", "/api/v1/ai/run", {
        capability: capability || "recon_assist",
        user_data: user_data || "",
      });
      const text = typeof r === "string" ? r : JSON.stringify(r, null, 2);
      if (outId && el(outId)) {
        el(outId).textContent = text;
        el(outId).classList.remove("empty");
      }
      appendAiChat("user", `[${capability}] ${user_data || "(empty)"}`);
      appendAiChat("bot", text);
      showOk("AI complete");
      return r;
    } catch (e) {
      showError(String(e.message || e));
      appendAiChat("bot", "Error: " + String(e.message || e));
    }
  }

  function appendAiChat(who, text) {
    const log = el("aiChatLog");
    if (!log) return;
    const div = document.createElement("div");
    div.className = "ai-msg " + (who === "user" ? "user" : "bot");
    const w = document.createElement("div");
    w.className = "who";
    w.textContent = who === "user" ? "You" : "Admin AI";
    const b = document.createElement("div");
    b.className = "mono";
    b.style.whiteSpace = "pre-wrap";
    b.textContent = text;
    div.appendChild(w);
    div.appendChild(b);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function openAiDrawer(open) {
    const d = el("aiDrawer");
    if (!d) return;
    if (open === false) d.classList.add("hidden");
    else d.classList.toggle("hidden", open == null ? !d.classList.contains("hidden") : !open);
  }

  function setupGlobalAi() {
    const fab = el("aiFab");
    const drawer = el("aiDrawer");
    if (!fab || !drawer) return;
    const allowed = can("ai:use") || can("admin");
    fab.classList.toggle("hidden", !allowed);
    if (!allowed) {
      drawer.classList.add("hidden");
      return;
    }
    const sel = el("aiCapGlobal");
    if (sel && !sel.options.length) {
      AI_CAPS.forEach((c) => {
        const o = document.createElement("option");
        o.value = c; o.textContent = c;
        sel.appendChild(o);
      });
      sel.value = "recon_assist";
    }
    fab.onclick = () => openAiDrawer();
    if (el("aiDrawerClose")) el("aiDrawerClose").onclick = () => openAiDrawer(false);
    if (el("aiSendGlobal")) el("aiSendGlobal").onclick = async () => {
      const cap = (el("aiCapGlobal") && el("aiCapGlobal").value) || "recon_assist";
      const prompt = (el("aiPromptGlobal") && el("aiPromptGlobal").value) || "";
      if (!prompt.trim()) return showError("Enter a prompt");
      el("aiSendGlobal").disabled = true;
      try {
        await runAi(cap, prompt, null);
        if (el("aiPromptGlobal")) el("aiPromptGlobal").value = "";
      } finally {
        el("aiSendGlobal").disabled = false;
      }
    };
  }

  function renderAdminView() {
    const root = el("view-admin");
    if (!root) return;
    if (!can("admin") && !can("tokens:manage") && !can("policy:manage")) {
      root.innerHTML = '<div class="empty-state"><strong>Admin area</strong>Requires admin or manage scopes.</div>';
      return;
    }
    const defaultScopes = new Set([
      "sessions:read", "sessions:write", "tasks:read", "tasks:write",
      "shell:interact", "listeners:read", "collab:use", "metrics:read",
    ]);
    const allScopes = [
      "sessions:read", "sessions:write", "tasks:read", "tasks:write",
      "listeners:read", "listeners:write", "payloads:generate", "shell:interact",
      "metrics:read", "audit:read", "ai:use", "collab:use", "profiles:read", "profiles:write",
      "files:read", "files:write", "oast:read", "oast:write", "mcp:connect",
      "tokens:manage", "llm:manage", "policy:manage", "plugins:manage", "admin",
    ];
    root.innerHTML = `
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Mint token</div>
          <div class="wp-body">
            <label>Name</label><input id="adName" placeholder="operator-1" />
            <label>Scopes</label>
            <div class="row" style="margin:4px 0">
              <button type="button" id="adScopeOp">Operator preset</button>
              <button type="button" id="adScopeNone">Clear</button>
              <button type="button" id="adScopeAll">All non-admin</button>
            </div>
            <div class="scope-grid" id="adScopeGrid">
              ${allScopes.map((s) => `
                <label><input type="checkbox" class="ad-scope" value="${esc(s)}"
                  ${defaultScopes.has(s) ? "checked" : ""}
                  ${s === "admin" && !can("admin") ? "disabled" : ""} /> ${esc(s)}</label>
              `).join("")}
            </div>
            <div class="row"><button type="button" class="primary" id="adMint">Mint</button></div>
            <div class="outbox empty" id="adMintOut">Token shown once</div>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Policy / features</div>
          <div class="wp-body">
            <div class="row">
              <button type="button" id="adPolGet">Get policy</button>
              <button type="button" id="adFeat">Features</button>
              <button type="button" id="adTokList">List tokens</button>
            </div>
            <div class="outbox empty" id="adOut" style="max-height:360px;flex:1">—</div>
          </div>
        </div>
        ${(can("llm:manage") || can("admin")) ? `
        <div class="work-panel full">
          <div class="wp-head">Configure LLM (BYO)</div>
          <div class="wp-body">${llmFormHtml("adLlm")}</div>
        </div>` : ""}
      </div>
    `;
    if (can("llm:manage") || can("admin")) bindLlmForm("adLlm");
    function selectedScopes() {
      return Array.from(document.querySelectorAll(".ad-scope:checked")).map((c) => c.value);
    }
    function setScopes(set) {
      document.querySelectorAll(".ad-scope").forEach((c) => {
        if (c.disabled) return;
        c.checked = set.has(c.value);
      });
    }
    if (el("adScopeOp")) el("adScopeOp").onclick = () => setScopes(defaultScopes);
    if (el("adScopeNone")) el("adScopeNone").onclick = () => setScopes(new Set());
    if (el("adScopeAll")) el("adScopeAll").onclick = () => {
      setScopes(new Set(allScopes.filter((s) => s !== "admin" || can("admin"))));
    };
    if (el("adMint")) el("adMint").onclick = async () => {
      try {
        const scopes = selectedScopes();
        if (!scopes.length) return showError("Select at least one scope");
        const r = await api("POST", "/api/v1/tokens", { name: el("adName").value.trim() || "op", scopes });
        el("adMintOut").textContent = r.token || JSON.stringify(r, null, 2);
        el("adMintOut").classList.remove("empty");
        showOk("Token minted — copy now");
      } catch (e) { showError(String(e.message || e)); }
    };
    const dump = async (path) => {
      try {
        const r = await api("GET", path);
        el("adOut").textContent = JSON.stringify(r, null, 2);
        el("adOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("adPolGet")) el("adPolGet").onclick = () => dump("/api/v1/policy");
    if (el("adFeat")) el("adFeat").onclick = () => dump("/api/v1/features");
    if (el("adTokList")) el("adTokList").onclick = () => dump("/api/v1/tokens");
  }

  /* —— View router —— */
  function renderView(name) {
    switch (name) {
      case "sessions": renderSessionsView(true); break;
      case "listeners": renderListenersView(true); break;
      case "payloads": renderPayloadsView(); break;
      case "postex": renderPostexView(); break;
      case "collab": renderCollabView(); break;
      case "ai": renderAiView(); break;
      case "observe": renderObserveView(); break;
      case "admin": renderAdminView(); break;
      default: break;
    }
    setPageDocs(name || "dashboard");
    renderContext();
  }
  window.__SC5_setPageDocs = setPageDocs;

  window.__SC5_onView = renderView;
  window.__SC5_onRefresh = (data) => {
    if (data.sessions) cache.sessions = data.sessions;
    if (data.listeners) cache.listeners = data.listeners;
    // Soft update — do not wipe selection or rebuild forms
    if (currentIs("sessions")) {
      renderSessionsView(false);
      if (el("tskList")) loadTasksPanel();
    }
    if (currentIs("listeners")) renderListenersView(false);
    if (el("pxSid")) el("pxSid").textContent = selectedId || "(none — pick in Sessions)";
    // Restore row highlights without full context rebuild if possible
    document.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-sid") === selectedId);
    });
    document.querySelectorAll("tr[data-lid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-lid") === selectedListenerId);
    });
    // Only refresh context metadata if selection still valid
    if (selectedId) renderContext(false);
  };
  function currentIs(name) {
    const v = el("view-" + name);
    return v && v.classList.contains("active");
  }

  window.__SC5_boot = function () {
    setupGlobalAi();
    const v = (() => { try { return localStorage.getItem("sc5_ops_view"); } catch (_) { return "dashboard"; } })();
    if (selectedId) state.selectedId = selectedId;
    viewBuilt = {};
    renderView(v || "dashboard");
  };
  window.__SC5_ADMIN_LOADED__ = true;
  window.__SC5_boot();
})();
