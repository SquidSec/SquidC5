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

  let selectedId = state.selectedId || null;
  let cache = { sessions: [], listeners: [] };

  function el(id) { return document.getElementById(id); }
  function setHTML(id, html) { const n = el(id); if (n) n.innerHTML = html; }
  function tools(html) { const t = el("viewTools"); if (t) t.innerHTML = html || ""; }
  function shortId(id) { return (id || "").length > 14 ? id.slice(0, 12) + "…" : (id || ""); }
  function metaOf(s) {
    let m = s && s.metadata;
    if (typeof m === "string") { try { m = JSON.parse(m); } catch (_) { m = {}; } }
    return m || {};
  }

  /* —— Context rail —— */
  async function renderContext() {
    const body = el("ctxBody");
    if (!body) return;
    if (!selectedId) {
      body.innerHTML = '<div class="ctx-empty">Select a session from <strong>Sessions</strong> to claim, shell, or task it.</div>';
      return;
    }
    let s = cache.sessions.find((x) => x.id === selectedId);
    try { s = await api("GET", "/api/v1/sessions/" + encodeURIComponent(selectedId)); } catch (_) {}
    if (!s) {
      body.innerHTML = '<div class="ctx-empty">Session not found.</div>';
      return;
    }
    const m = metaOf(s);
    body.innerHTML = `
      <div class="mono" style="font-size:0.7rem;color:var(--muted);margin-bottom:6px">${esc(s.id)}</div>
      <div style="font-weight:700;margin-bottom:4px">${esc(s.hostname || s.remote_addr || "session")}</div>
      <div class="chips" style="margin-bottom:10px">
        <span class="chip">${esc(s.kind || "?")}</span>
        <span class="chip ${s.verified ? "ok" : ""}">${s.verified ? "verified" : esc(s.status || "")}</span>
        ${m.claimed_by ? `<span class="chip warn">🔒 ${esc(m.claimed_by)}</span>` : '<span class="chip">unlocked</span>'}
      </div>
      <div class="muted" style="font-size:0.78rem;margin-bottom:8px">
        User: ${esc(s.username || "—")}<br/>
        OS: ${esc(s.os_info || "—")}<br/>
        Addr: ${esc(s.remote_addr || "—")}
      </div>
      <div class="row">
        ${can("shell:interact") || can("collab:use") ? '<button type="button" class="primary" id="ctxClaim">Claim</button>' : ""}
        ${can("shell:interact") || can("collab:use") ? '<button type="button" id="ctxRelease">Release</button>' : ""}
        ${can("sessions:read") ? '<button type="button" id="ctxSpectate">Spectate</button>' : ""}
      </div>
      ${can("shell:interact") && (s.kind === "reverse_shell" || s.interactive) ? `
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
    if (el("ctxClaim")) el("ctxClaim").onclick = async () => {
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/claim`, {});
        showOk("Claimed");
        el("ctxOut").textContent = JSON.stringify(r, null, 2);
        el("ctxOut").classList.remove("empty");
        if (window.__SC5_refresh) await window.__SC5_refresh();
        renderContext();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxRelease")) el("ctxRelease").onclick = async () => {
      try {
        await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/release`);
        showOk("Released");
        if (window.__SC5_refresh) await window.__SC5_refresh();
        renderContext();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxSpectate")) el("ctxSpectate").onclick = async () => {
      try {
        const r = await api("GET", `/api/v1/sessions/${encodeURIComponent(selectedId)}/spectator`);
        el("ctxOut").textContent = JSON.stringify(r, null, 2);
        el("ctxOut").classList.remove("empty");
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
        el("ctxOut").textContent = out;
        el("ctxOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxTaskBtn")) el("ctxTaskBtn").onclick = async () => {
      const command = (el("ctxTask").value || "").trim();
      if (!command) return showError("Command required");
      try {
        const r = await api("POST", "/api/v1/tasks", { session_id: selectedId, command });
        showOk("Task " + (r.id || "queued"));
        el("ctxOut").textContent = JSON.stringify(r, null, 2);
        el("ctxOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  function selectSession(id) {
    selectedId = id;
    state.selectedId = id;
    renderContext();
    document.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-sid") === id);
    });
  }
  window.__SC5_selectSession = selectSession;

  /* —— Sessions view —— */
  function renderSessionsView() {
    const root = el("view-sessions");
    if (!root) return;
    const rows = cache.sessions || [];
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">Active <span style="margin-left:auto" class="muted">${rows.length}</span></div>
          <div class="lp-body">
            ${rows.length ? `<table class="data"><thead><tr><th>Session</th><th>Kind</th><th>Host</th></tr></thead><tbody>
              ${rows.map((s) => {
                const m = metaOf(s);
                return `<tr data-sid="${esc(s.id)}" class="${s.id === selectedId ? "selected" : ""}">
                  <td class="mono">${esc(shortId(s.id))}${m.claimed_by ? " 🔒" : ""}</td>
                  <td>${esc(s.kind || "")}</td>
                  <td>${esc(s.hostname || s.remote_addr || "—")}</td>
                </tr>`;
              }).join("")}
            </tbody></table>` : '<div class="empty-state"><strong>No sessions</strong>Land a beacon or reverse shell.</div>'}
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
              Click a row to load the <strong>context rail</strong> (right). Claim before multi-op tasking.
              Use Shell for verified reverse shells; Tasks for beacons.
            </p>
            <div id="sesDetail" class="outbox empty" style="margin-top:12px">Select a session…</div>
          </div>
        </div>
      </div>
    `;
    root.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.onclick = () => {
        selectSession(tr.getAttribute("data-sid"));
        const s = cache.sessions.find((x) => x.id === selectedId);
        const box = el("sesDetail");
        if (box && s) {
          box.textContent = JSON.stringify(s, null, 2);
          box.classList.remove("empty");
        }
      };
    });
    if (el("sesReap")) el("sesReap").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/sessions/reap", {});
        showOk("Reaped");
        showOutput(JSON.stringify(r, null, 2));
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("sesClose") && selectedId) el("sesClose").onclick = async () => {
      if (!selectedId) return showError("Select a session");
      try {
        await api("DELETE", "/api/v1/sessions/" + encodeURIComponent(selectedId));
        showOk("Closed");
        selectedId = null;
        if (window.__SC5_refresh) await window.__SC5_refresh();
      } catch (e) {
        try {
          await api("POST", "/api/v1/sessions/" + encodeURIComponent(selectedId) + "/close");
          showOk("Closed");
          if (window.__SC5_refresh) await window.__SC5_refresh();
        } catch (e2) { showError(String(e2.message || e2)); }
      }
    };
    if (el("sesRefresh")) el("sesRefresh").onclick = () => window.__SC5_refresh && window.__SC5_refresh();
    tools(`<button type="button" class="primary" id="toolNewShell">Interact</button>`);
    if (el("toolNewShell")) el("toolNewShell").onclick = () => {
      if (!selectedId) return showError("Select a session first");
      renderContext();
    };
  }

  /* —— Listeners —— */
  function renderListenersView() {
    const root = el("view-listeners");
    if (!root) return;
    const rows = cache.listeners || [];
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">Listeners</div>
          <div class="lp-body">
            <table class="data"><thead><tr><th>Name</th><th>Port</th><th>Kind</th><th>Status</th></tr></thead><tbody>
              ${rows.map((l) => `<tr data-lid="${esc(l.id)}">
                <td>${esc(l.name || shortId(l.id))}</td>
                <td class="mono">${esc(l.port)}</td>
                <td>${esc(l.kind)}</td>
                <td><span class="chip ${l.status === "running" ? "ok" : ""}">${esc(l.status || "—")}</span></td>
              </tr>`).join("") || '<tr><td colspan="4" class="muted">None</td></tr>'}
            </tbody></table>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Manage</div>
          <div class="wp-body">
            ${can("listeners:write") ? `
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
                <button type="button" id="lisStart">Start selected</button>
                <button type="button" id="lisStop">Stop</button>
                <button type="button" class="danger" id="lisDel">Delete</button>
              </div>
            ` : '<p class="muted">Read-only token</p>'}
            <div class="outbox empty" id="lisOut">—</div>
          </div>
        </div>
      </div>
    `;
    let lid = null;
    root.querySelectorAll("tr[data-lid]").forEach((tr) => {
      tr.onclick = () => {
        lid = tr.getAttribute("data-lid");
        root.querySelectorAll("tr").forEach((x) => x.classList.remove("selected"));
        tr.classList.add("selected");
      };
    });
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
      showOk("Listener running");
      return created;
    });
    if (el("lisStart")) el("lisStart").onclick = () => {
      if (!lid) return showError("Select listener");
      lisAct(() => api("POST", `/api/v1/listeners/${lid}/start`));
    };
    if (el("lisStop")) el("lisStop").onclick = () => {
      if (!lid) return showError("Select listener");
      lisAct(() => api("POST", `/api/v1/listeners/${lid}/stop`));
    };
    if (el("lisDel")) el("lisDel").onclick = () => {
      if (!lid) return showError("Select listener");
      lisAct(() => api("DELETE", `/api/v1/listeners/${lid}`));
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
  function renderAdminView() {
    const root = el("view-admin");
    if (!root) return;
    if (!can("admin") && !can("tokens:manage") && !can("policy:manage")) {
      root.innerHTML = '<div class="empty-state"><strong>Admin area</strong>Requires admin or manage scopes.</div>';
      return;
    }
    root.innerHTML = `
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Mint token</div>
          <div class="wp-body">
            <label>Name</label><input id="adName" placeholder="operator-1" />
            <label>Scopes (comma)</label>
            <input id="adScopes" value="sessions:read,sessions:write,tasks:read,tasks:write,shell:interact,listeners:read,collab:use" />
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
            <div class="outbox empty" id="adOut" style="max-height:360px">—</div>
          </div>
        </div>
      </div>
    `;
    if (el("adMint")) el("adMint").onclick = async () => {
      try {
        const scopes = (el("adScopes").value || "").split(",").map((s) => s.trim()).filter(Boolean);
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
      case "sessions": renderSessionsView(); break;
      case "listeners": renderListenersView(); break;
      case "payloads": renderPayloadsView(); break;
      case "postex": renderPostexView(); break;
      case "collab": renderCollabView(); break;
      case "observe": renderObserveView(); break;
      case "admin": renderAdminView(); break;
      default: break;
    }
    renderContext();
  }

  window.__SC5_onView = renderView;
  window.__SC5_onRefresh = (data) => {
    if (data.sessions) cache.sessions = data.sessions;
    if (data.listeners) cache.listeners = data.listeners;
    if (currentIs("sessions")) renderSessionsView();
    if (currentIs("listeners")) renderListenersView();
    if (currentIs("postex") && el("pxSid")) el("pxSid").textContent = selectedId || "(none)";
    renderContext();
  };
  function currentIs(name) {
    const v = el("view-" + name);
    return v && v.classList.contains("active");
  }

  window.__SC5_boot = function () {
    const v = (() => { try { return localStorage.getItem("sc5_ops_view"); } catch (_) { return "dashboard"; } })();
    renderView(v || "dashboard");
  };
  window.__SC5_ADMIN_LOADED__ = true;
  window.__SC5_boot();
})();
