/* SquidC5 ops console — loaded after auth; panels gated by token scopes (API enforces too) */
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

  function panel(id, title, body, open) {
    return `<details class="panel" id="${id}"${open ? " open" : ""}>
      <summary>${title}</summary>
      ${body}
    </details>`;
  }

  const parts = [];

  // ----- Identity -----
  parts.push(`
    <div class="card" id="identityCard">
      <h2>Identity</h2>
      <p class="muted mono" id="whoLine">—</p>
      <div class="chips" id="scopeChips" style="margin-top:8px"></div>
      <div class="row" style="margin-top:8px">
        <button type="button" id="whoamiBtn">Whoami</button>
        <button type="button" id="healthBtn">Health</button>
      </div>
      <div class="outbox empty-out" id="identOut" style="margin-top:8px">—</div>
    </div>
  `);

  // ----- Shell interact -----
  if (can("shell:interact")) {
    parts.push(`
      <div class="card" id="quickRunCard">
        <h2>Shell</h2>
        <label for="shellSelect">Target shell</label>
        <select id="shellSelect"><option value="">(none)</option></select>
        <label for="shellCmd">Command</label>
        <textarea id="shellCmd" placeholder="whoami"></textarea>
        <div class="row">
          <button type="button" class="primary" id="runShellBtn">Run</button>
          ${can("shell:interact") ? '<button type="button" id="runAllBtn">All verified</button>' : ""}
          <button type="button" id="dumpOutBtn">Buffer</button>
        </div>
        <h2 style="margin-top:12px">Output</h2>
        <div class="outbox empty-out" id="shellOut">Run a command to see output here.</div>
      </div>
    `);
  }

  // ----- Sessions -----
  if (can("sessions:read") || can("sessions:write")) {
    parts.push(panel("sessionsPanel", "📡 Sessions", `
      <div class="row">
        ${can("sessions:write") ? '<button type="button" id="reapBtn">Reap dead</button>' : ""}
        ${can("sessions:write") ? '<button type="button" class="danger" id="closeShellBtn">Close selected</button>' : ""}
        <button type="button" id="listAllSesBtn">List all</button>
      </div>
      <div id="sesExtra" class="outbox empty-out" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Tasks (beacons) -----
  if (can("tasks:read") || can("tasks:write")) {
    parts.push(panel("tasksPanel", "📋 Tasks", `
      ${can("tasks:write") ? `
        <label for="taskSession">Session id</label>
        <input id="taskSession" placeholder="beacon session id" autocomplete="off" />
        <label for="taskCmd">Command</label>
        <input id="taskCmd" placeholder="id / whoami" autocomplete="off" />
        <div class="row">
          <button type="button" class="primary" id="createTaskBtn">Create task</button>
          <button type="button" id="listTasksBtn">List tasks</button>
        </div>
      ` : `<div class="row"><button type="button" id="listTasksBtn">List tasks</button></div>`}
      <div class="outbox empty-out" id="taskOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Listeners -----
  if (can("listeners:read") || can("listeners:write")) {
    parts.push(panel("listenersPanel", "🎧 Listeners", `
      <label for="listenerSelect">Listener</label>
      <select id="listenerSelect"><option value="">(none)</option></select>
      ${can("listeners:write") ? `
        <div class="row">
          <button type="button" id="startLisBtn">Start</button>
          <button type="button" id="stopLisBtn">Stop</button>
          <button type="button" class="danger" id="delLisBtn">Delete</button>
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
            <option value="dns">dns</option>
          </select>
          <input id="newLisZone" placeholder="dns zone (dns only)" style="flex:1" />
        </div>
        <div class="row">
          <button type="button" class="primary" id="createLisBtn">Create + start</button>
        </div>
      ` : ""}
    `, false));
  }

  // ----- Payloads -----
  if (can("payloads:generate")) {
    parts.push(panel("payloadsPanel", "💣 Payloads / implants", `
      <label for="payTpl">Template</label>
      <select id="payTpl">
        <option value="http_beacon_python">http_beacon_python</option>
        <option value="http_beacon_bash">http_beacon_bash</option>
        <option value="dns_beacon_python">dns_beacon_python</option>
        <option value="ws_beacon_python">ws_beacon_python</option>
        <option value="memory_beacon_python">memory_beacon_python</option>
        <option value="linux_memfd">linux_memfd</option>
        <option value="windows_ps_beacon">windows_ps_beacon</option>
        <option value="bof_c">bof_c</option>
        <option value="reverse_shell_bash">reverse_shell_bash</option>
        <option value="reverse_shell_python">reverse_shell_python</option>
      </select>
      <div class="row">
        <input id="payHost" placeholder="callback host" style="flex:1.4" />
        <input id="payPort" type="number" placeholder="port" style="flex:0.7" />
      </div>
      <div class="row">
        <select id="payScheme">
          <option value="">scheme default</option>
          <option value="http">http</option>
          <option value="https">https</option>
          <option value="ws">ws</option>
          <option value="wss">wss</option>
        </select>
        <input id="payZone" placeholder="dns zone (optional)" />
      </div>
      <div class="row">
        <button type="button" class="primary" id="genPayBtn">Generate</button>
        <button type="button" id="listTplBtn">Templates</button>
      </div>
      <label for="impFamily">Implant family</label>
      <select id="impFamily">
        <option value="http_beacon">http_beacon</option>
        <option value="dns_beacon">dns_beacon</option>
        <option value="ws_beacon">ws_beacon</option>
        <option value="memory_beacon_python">memory_beacon_python</option>
        <option value="linux_memfd">linux_memfd</option>
        <option value="linux_stager">linux_stager</option>
        <option value="bof">bof</option>
      </select>
      <div class="row">
        <button type="button" id="genImpBtn">Generate implant</button>
      </div>
      <div class="outbox empty-out" id="payOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Plugins -----
  if (can("plugins:manage") || can("admin")) {
    parts.push(panel("pluginsPanel", "🧩 Plugins", `
      <div class="row">
        <button type="button" id="plugCatBtn">Catalog</button>
        <button type="button" id="plugListBtn">Installed</button>
      </div>
      <label for="plugName">Install catalog name</label>
      <input id="plugName" placeholder="lab_recon" />
      <div class="row">
        <button type="button" class="primary" id="plugInstallBtn">Install + enable</button>
      </div>
      <div class="outbox empty-out" id="plugOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Deploy helpers -----
  if (can("admin") || can("listeners:write")) {
    parts.push(panel("deployPanel", "🛡 Redirector / certs", `
      <input id="redirName" placeholder="server_name e.g. cdn.lab" />
      <input id="redirUris" placeholder="beacon uris comma-sep" />
      <div class="row">
        <button type="button" class="primary" id="redirBtn">Nginx snippet</button>
        <button type="button" id="certPlanBtn">Cert plan</button>
      </div>
      <div class="outbox empty-out" id="deployOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Metrics / Audit -----
  if (can("metrics:read") || can("audit:read")) {
    parts.push(panel("obsPanel", "📈 Observability", `
      <div class="row">
        ${can("metrics:read") ? '<button type="button" id="metricsBtn">Metrics</button>' : ""}
        ${can("audit:read") ? '<button type="button" id="auditBtn">Audit log</button>' : ""}
      </div>
      <div class="outbox" id="adminOut" style="margin-top:8px"></div>
    `, false));
  }

  // ----- Admin AI -----
  if (can("ai:use")) {
    parts.push(`
      <div class="card" id="aiCard">
        <h2>Admin AI</h2>
        <div class="stats" style="margin-bottom:8px">
          <div class="stat"><div class="n" id="aiStatusN" style="font-size:0.95rem">—</div><div class="l">Status</div></div>
          <div class="stat"><div class="n" id="aiModeN" style="font-size:0.95rem">—</div><div class="l">Mode</div></div>
          <div class="stat"><div class="n" id="aiCallsN">—</div><div class="l">Calls</div></div>
        </div>
        <p class="muted mono" id="aiModelLine">—</p>
        <p class="muted" id="aiLastLine" style="margin-top:6px">last: —</p>
        <label for="aiCap">Capability</label>
        <select id="aiCap">
          <option value="recon_assist">recon_assist</option>
          <option value="shell_classify">shell_classify</option>
          <option value="payload_template">payload_template</option>
          <option value="phishing_asset">phishing_asset</option>
          <option value="doc_generate">doc_generate</option>
        </select>
        <label for="aiData">Input</label>
        <textarea id="aiData" placeholder="context for AI…"></textarea>
        <div class="row" style="margin-top:8px">
          <button type="button" class="primary" id="aiRunBtn">Run AI</button>
          <button type="button" id="aiRefreshBtn">Status</button>
          <button type="button" id="aiDebugBtn">Debug</button>
        </div>
        <div class="outbox empty-out" id="aiOut" style="margin-top:10px;border-color:rgba(192,38,255,0.35);color:#e9d5ff">AI result</div>
      </div>
    `);
  }

  // ----- LLM manage -----
  if (can("llm:manage")) {
    parts.push(panel("llmPanel", "🧠 LLM connections", `
      <label for="llmName">Name</label>
      <input id="llmName" placeholder="grok-prod" autocomplete="off" />
      <label for="llmModel">Model</label>
      <input id="llmModel" placeholder="grok-4.20-non-reasoning" autocomplete="off" />
      <label for="llmProvider">Provider</label>
      <select id="llmProvider">
        <option value="xai">xai</option>
        <option value="openai">openai</option>
      </select>
      <label for="llmBase">Base URL</label>
      <input id="llmBase" placeholder="https://api.x.ai/v1" autocomplete="off" />
      <label for="llmKey">API key</label>
      <input id="llmKey" type="password" placeholder="xai-…" autocomplete="off" />
      <div class="row">
        <button type="button" class="primary" id="llmAddBtn">Add / update LLM</button>
        <button type="button" id="llmListBtn">List</button>
      </div>
      <div class="outbox empty-out" id="llmOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Tokens -----
  if (can("tokens:manage") || can("admin")) {
    parts.push(panel("tokensPanel", "🔑 Tokens", `
      <p class="muted">Raw secret is shown <strong>once</strong> at create — copy it.</p>
      <label for="tokName">Name</label>
      <input id="tokName" placeholder="operator-phone" autocomplete="off" />
      <label for="tokPreset">Preset</label>
      <select id="tokPreset">
        <option value="operator">operator (sessions/tasks/shell/metrics)</option>
        <option value="readonly">read-only</option>
        <option value="listener">listener ops</option>
        <option value="ai">AI user</option>
        <option value="admin">admin (full)</option>
        <option value="custom">custom scopes…</option>
      </select>
      <div id="tokCustomScopes" class="hidden" style="margin:8px 0">
        <label>Scopes (comma-separated)</label>
        <input id="tokScopes" placeholder="sessions:read,shell:interact" autocomplete="off" />
      </div>
      <div class="row">
        <button type="button" class="primary" id="mintTokBtn">Mint token</button>
        <button type="button" id="reloadTokBtn">Refresh list</button>
      </div>
      <div class="outbox empty-out" id="tokMintOut" style="margin-top:10px;border-color:rgba(0,255,157,0.35);color:var(--ok)">Minted token appears here once</div>
      <h2 style="margin-top:12px">Active tokens</h2>
      <div id="tokList" class="empty">—</div>
    `, true));
  }

  // ----- Observability extras -----
  if (can("metrics:read") || can("audit:read") || can("admin")) {
    parts.push(panel("obsExtraPanel", "🗺 Timeline / report", `
      <div class="row">
        <button type="button" id="anomalyBtn">Anomalies</button>
        <button type="button" id="reportBtn">Export report</button>
        <button type="button" id="timelineBtn">Timeline</button>
      </div>
      <div class="outbox empty-out" id="obsExtraOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- Collab chat -----
  if (can("collab:use") || can("admin")) {
    parts.push(panel("chatPanel", "💬 Operator chat", `
      <label for="chatMsg">Message</label>
      <input id="chatMsg" placeholder="handoff note…" autocomplete="off" />
      <div class="row">
        <button type="button" class="primary" id="chatSendBtn">Send</button>
        <button type="button" id="chatReloadBtn">Reload</button>
      </div>
      <div class="outbox empty-out" id="chatOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- C2 Profiles -----
  if (can("profiles:read") || can("admin")) {
    parts.push(panel("profilesPanel", "📡 C2 profiles", `
      <p class="muted">Malleable HTTP profiles. Activate then generate beacons with that surface.</p>
      <div id="profList" class="empty">—</div>
      <div class="row" style="margin-top:8px">
        <button type="button" id="profReloadBtn">Reload</button>
        ${can("payloads:generate") || can("admin") ? '<button type="button" class="primary" id="profGenBtn">Generate beacon (active)</button>' : ""}
      </div>
      <div class="outbox empty-out" id="profOut" style="margin-top:8px">—</div>
    `, true));
  }

  // ----- Feature toggles (admin) -----
  if (can("admin") || can("policy:manage")) {
    parts.push(panel("featuresPanel", "🎛 Feature toggles", `
      <p class="muted">Server-enforced. Off = API denies the feature.</p>
      <div id="featureToggles"></div>
      <div class="row">
        <button type="button" class="primary" id="saveFeaturesBtn">Save features</button>
        <button type="button" id="reloadFeaturesBtn">Reload</button>
      </div>
    `, false));
  }

  // ----- Policy -----
  if (can("policy:manage")) {
    parts.push(panel("policyPanel", "📜 Policy", `
      <div class="row">
        <button type="button" id="policyGetBtn">Get policy</button>
      </div>
      <label for="policyJson">Set policy JSON</label>
      <textarea id="policyJson" placeholder='{"thresholds":{...}}' style="min-height:100px"></textarea>
      <div class="row">
        <button type="button" class="primary" id="policySetBtn">Save policy</button>
      </div>
      <div class="outbox empty-out" id="policyOut" style="margin-top:8px">—</div>
    `, false));
  }

  // ----- MCP -----
  if (can("mcp:connect")) {
    parts.push(panel("mcpPanel", "🔌 MCP tools", `
      <div class="row">
        <button type="button" id="mcpToolsBtn">List tools</button>
      </div>
      <label for="mcpName">Call tool</label>
      <input id="mcpName" placeholder="list_sessions" autocomplete="off" />
      <label for="mcpArgs">Args JSON</label>
      <input id="mcpArgs" placeholder="{}" autocomplete="off" />
      <div class="row">
        <button type="button" class="primary" id="mcpCallBtn">Call</button>
      </div>
      <div class="outbox empty-out" id="mcpOut" style="margin-top:8px">—</div>
    `, false));
  }

  root.innerHTML = parts.join("\n") || '<div class="card muted">No scoped actions for this token.</div>';

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setOut(id, text, empty) {
    const el = $(id);
    if (!el) return;
    el.textContent = text == null || text === "" ? "—" : String(text);
    el.classList.toggle("empty-out", !!empty);
  }

  // Identity
  async function refreshWho() {
    try {
      const who = await api("GET", "/api/v1/meta");
      const sc = who.scopes || [];
      if ($("whoLine")) {
        $("whoLine").textContent =
          `${who.actor || "?"} · ${who.actor_type || "operator"} · ${who.token_id ? who.token_id.slice(0, 10) + "…" : ""}`;
      }
      if ($("scopeChips")) {
        $("scopeChips").innerHTML = sc.length
          ? sc.map((s) => `<span class="chip">${escapeHtml(s)}</span>`).join("")
          : '<span class="chip">no scopes</span>';
      }
      return who;
    } catch (e) {
      showError(String(e.message || e));
      return null;
    }
  }
  if ($("whoamiBtn")) {
    $("whoamiBtn").onclick = async () => {
      const who = await refreshWho();
      if (who) setOut("identOut", JSON.stringify(who, null, 2), false);
    };
  }
  if ($("healthBtn")) {
    $("healthBtn").onclick = async () => {
      try {
        const h = await api("GET", "/api/v1/health");
        setOut("identOut", JSON.stringify(h, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  refreshWho();

  // Shells
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
      opt.textContent = `${l.name || l.id} :${l.port} (${l.kind}) [${l.status || "?"}]`;
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

  if ($("runShellBtn")) {
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
  }

  if ($("runAllBtn")) {
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
  }

  if ($("dumpOutBtn")) {
    $("dumpOutBtn").onclick = async () => {
      const sid = $("shellSelect").value;
      if (!sid) return showError("Select a shell");
      try {
        const res = await api("GET", `/api/v1/sessions/${sid}/output?limit=8000`);
        showOutput((res && res.output) || "(empty buffer)", `buffer · ${sid.slice(0, 12)}…`);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  if ($("reapBtn")) {
    $("reapBtn").onclick = async () => {
      try {
        const res = await api("POST", "/api/v1/sessions/reap", { probe: true });
        showOk(`Reaped ${res.closed} shell(s)`);
        refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("closeShellBtn")) {
    $("closeShellBtn").onclick = async () => {
      const sid = ($("shellSelect") && $("shellSelect").value) || "";
      if (!sid) return showError("Select a shell");
      try {
        await api("POST", `/api/v1/sessions/${sid}/close`);
        showOk("Session closed");
        refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("listAllSesBtn")) {
    $("listAllSesBtn").onclick = async () => {
      try {
        const rows = await api("GET", "/api/v1/sessions?status=all");
        setOut("sesExtra", JSON.stringify(rows, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Tasks
  if ($("createTaskBtn")) {
    $("createTaskBtn").onclick = async () => {
      const session_id = ($("taskSession").value || "").trim();
      const command = ($("taskCmd").value || "").trim();
      if (!session_id || !command) return showError("Session id and command required");
      try {
        const res = await api("POST", "/api/v1/tasks", { session_id, command });
        setOut("taskOut", JSON.stringify(res, null, 2), false);
        showOk("Task created");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("listTasksBtn")) {
    $("listTasksBtn").onclick = async () => {
      try {
        const sid = ($("taskSession") && $("taskSession").value.trim()) || "";
        const q = sid ? `?session_id=${encodeURIComponent(sid)}` : "";
        const rows = await api("GET", "/api/v1/tasks" + q);
        setOut("taskOut", JSON.stringify(rows, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Listeners
  if ($("startLisBtn")) {
    $("startLisBtn").onclick = async () => {
      const id = $("listenerSelect").value;
      if (!id) return showError("Select a listener");
      try {
        await api("POST", `/api/v1/listeners/${id}/start`);
        showOk("Listener started");
        refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("stopLisBtn")) {
    $("stopLisBtn").onclick = async () => {
      const id = $("listenerSelect").value;
      if (!id) return showError("Select a listener");
      try {
        await api("POST", `/api/v1/listeners/${id}/stop`);
        showOk("Listener stopped");
        refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("delLisBtn")) {
    $("delLisBtn").onclick = async () => {
      const id = $("listenerSelect").value;
      if (!id) return showError("Select a listener");
      if (!confirm("Delete this listener?")) return;
      try {
        await api("DELETE", `/api/v1/listeners/${id}`);
        showOk("Listener deleted");
        refresh();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("createLisBtn")) {
  if ($("createLisBtn")) $("createLisBtn").onclick = async () => {
    const name = $("newLisName").value.trim();
    const port = Number($("newLisPort").value);
    const kind = $("newLisKind").value;
    if (!name || !port) return showError("Name and port required");
    const body = { name, port, kind, host: "0.0.0.0", config: {} };
    if (kind === "dns") {
      body.config = { zone: ($("newLisZone") && $("newLisZone").value.trim()) || "c2.lab.invalid" };
    }
    try {
      const created = await api("POST", "/api/v1/listeners", body);
      await api("POST", `/api/v1/listeners/${created.id}/start`);
      showOk(`Created & started ${name} :${port}`);
      refresh();
    } catch (e) { showError(String(e.message || e)); }
  };

  }

  // Payloads
  if ($("genPayBtn")) {
    try {
      if ($("payHost") && !$("payHost").value) {
        $("payHost").value = location.hostname || "";
      }
      if ($("payPort") && !$("payPort").value) {
        $("payPort").value = location.port || "8443";
      }
    } catch (_) {}
    $("genPayBtn").onclick = async () => {
      const template = $("payTpl").value;
      const host = $("payHost").value.trim();
      const port = Number($("payPort").value);
      if (!host || !port) return showError("Host and port required");
      const body = { template, host, port, interval: 5 };
      const scheme = $("payScheme") && $("payScheme").value;
      if (scheme) body.scheme = scheme;
      const zone = $("payZone") && $("payZone").value.trim();
      if (zone) body.zone = zone;
      try {
        const res = await api("POST", "/api/v1/payloads/generate", body);
        setOut("payOut", res.content || JSON.stringify(res, null, 2), false);
        showOk("Payload generated");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("genImpBtn")) {
    $("genImpBtn").onclick = async () => {
      const host = ($("payHost") && $("payHost").value.trim()) || location.hostname;
      const port = Number(($("payPort") && $("payPort").value) || location.port || 8443);
      const family = $("impFamily").value;
      try {
        const res = await api("POST", "/api/v1/implants/generate", {
          family, platform: family === "bof" ? "windows" : "linux", arch: "x64", host, port, evasion: true,
        });
        setOut("payOut", res.content || JSON.stringify(res, null, 2), false);
        showOk("Implant generated");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("plugCatBtn")) {
    $("plugCatBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/plugins/catalog");
        setOut("plugOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("plugListBtn")) {
    $("plugListBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/plugins");
        setOut("plugOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("plugInstallBtn")) {
    $("plugInstallBtn").onclick = async () => {
      const name = ($("plugName").value || "").trim();
      if (!name) return showError("Plugin name required");
      try {
        const r = await api("POST", "/api/v1/plugins/install", { name, enable: true });
        setOut("plugOut", JSON.stringify(r, null, 2), false);
        showOk("Plugin installed");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("redirBtn")) {
    $("redirBtn").onclick = async () => {
      try {
        const server_name = ($("redirName").value || "cdn.lab").trim();
        const uris = ($("redirUris").value || "").split(",").map((s) => s.trim()).filter(Boolean);
        const r = await api("POST", "/api/v1/deploy/redirector", {
          server_name,
          beacon_uris: uris.length ? uris : undefined,
        });
        setOut("deployOut", r.config || JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("certPlanBtn")) {
    $("certPlanBtn").onclick = async () => {
      try {
        const d = ($("redirName").value || "cdn.lab").trim();
        const r = await api("POST", "/api/v1/deploy/cert-plan", { domains: [d], days: 60 });
        setOut("deployOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("listTplBtn")) {
    $("listTplBtn").onclick = async () => {
      try {
        const res = await api("GET", "/api/v1/payloads/templates");
        setOut("payOut", JSON.stringify(res, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Metrics / audit
  if ($("auditBtn")) {
    $("auditBtn").onclick = async () => {
      try {
        const rows = await api("GET", "/api/v1/audit?limit=30");
        $("adminOut").textContent = (rows || []).map((a) =>
          `${a.action}  ${a.actor}  allow=${a.allowed}`
        ).join("\n") || "(empty)";
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("metricsBtn")) {
    $("metricsBtn").onclick = async () => {
      try {
        const m = await api("GET", "/api/v1/metrics");
        $("adminOut").textContent = JSON.stringify(m.metrics || m, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Features
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
        <span>${escapeHtml(label)}<div class="muted mono" style="font-weight:400;font-size:0.7rem">${escapeHtml(key)}</div></span>
        <input type="checkbox" data-feat="${escapeHtml(key)}" ${on ? "checked" : ""} style="width:auto;transform:scale(1.2)" />
      </label>`;
    });
    box.innerHTML = html || '<div class="empty">No features</div>';
  }
  async function loadFeatures() {
    if (!$("featureToggles")) return;
    const data = await api("GET", "/api/v1/features");
    state.features = data.features || {};
    renderFeatures(data.features, data.catalog);
  }
  if ($("saveFeaturesBtn")) {
    $("saveFeaturesBtn").onclick = async () => {
      const updates = {};
      document.querySelectorAll("[data-feat]").forEach((el) => {
        updates[el.getAttribute("data-feat")] = !!el.checked;
      });
      try {
        const res = await api("PUT", "/api/v1/features", { features: updates });
        state.features = res.features || updates;
        renderFeatures(state.features, res.catalog);
        showOk("Features saved");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("reloadFeaturesBtn")) {
    $("reloadFeaturesBtn").onclick = () => loadFeatures().catch((e) => showError(String(e.message || e)));
  }

  // Tokens
  const PRESETS = {
    operator: ["sessions:read", "sessions:write", "tasks:read", "tasks:write", "shell:interact", "metrics:read", "listeners:read"],
    readonly: ["sessions:read", "tasks:read", "metrics:read", "audit:read", "listeners:read"],
    listener: ["listeners:read", "listeners:write", "payloads:generate", "sessions:read", "metrics:read"],
    ai: ["ai:use", "sessions:read", "metrics:read"],
    admin: ["admin"],
  };
  function selectedScopes() {
    const preset = ($("tokPreset") && $("tokPreset").value) || "operator";
    if (preset === "custom") {
      return ($("tokScopes").value || "").split(",").map((s) => s.trim()).filter(Boolean);
    }
    return PRESETS[preset] || PRESETS.operator;
  }
  function renderTokens(rows) {
    const box = $("tokList");
    if (!box) return;
    const active = (rows || []).filter((t) => !t.revoked);
    if (!active.length) {
      box.innerHTML = '<div class="empty">No active tokens</div>';
      return;
    }
    let html = "<table><thead><tr><th>Name</th><th>Scopes</th><th></th></tr></thead><tbody>";
    active.forEach((t) => {
      const scopes = Array.isArray(t.scopes) ? t.scopes.join(", ") : String(t.scopes || "");
      const short = (t.id || "").slice(0, 10);
      html += `<tr>
        <td><div class="mono">${escapeHtml(t.name || short)}</div>
            <div class="muted mono" style="font-size:0.65rem">${escapeHtml(short)}…</div></td>
        <td class="muted" style="font-size:0.72rem">${escapeHtml(scopes)}</td>
        <td><button type="button" class="danger tok-revoke" data-id="${escapeHtml(t.id)}" style="padding:6px 8px;font-size:0.7rem">Revoke</button></td>
      </tr>`;
    });
    html += "</tbody></table>";
    box.innerHTML = html;
    box.querySelectorAll(".tok-revoke").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute("data-id");
        if (!id || !confirm("Revoke this token?")) return;
        try {
          await api("DELETE", `/api/v1/tokens/${id}`);
          showOk("Token revoked");
          await loadTokens();
        } catch (e) { showError(String(e.message || e)); }
      };
    });
  }
  async function loadTokens() {
    if (!$("tokList")) return;
    const rows = await api("GET", "/api/v1/tokens");
    renderTokens(rows);
  }
  if ($("tokPreset")) {
    $("tokPreset").onchange = () => {
      $("tokCustomScopes").classList.toggle("hidden", $("tokPreset").value !== "custom");
    };
  }
  if ($("mintTokBtn")) {
    $("mintTokBtn").onclick = async () => {
      const name = ($("tokName").value || "").trim();
      if (!name) return showError("Token name required");
      const scopes = selectedScopes();
      if (!scopes.length) return showError("Select at least one scope");
      $("mintTokBtn").disabled = true;
      try {
        const res = await api("POST", "/api/v1/tokens", { name, scopes });
        const out = $("tokMintOut");
        out.classList.remove("empty-out");
        out.textContent =
          `name: ${res.name}\nid: ${res.id}\nscopes: ${(res.scopes || []).join(", ")}\n\n` +
          `TOKEN (copy now — shown once):\n${res.token}`;
        showOk("Token minted — copy the secret now");
        $("tokName").value = "";
        await loadTokens();
      } catch (e) { showError(String(e.message || e)); }
      finally { $("mintTokBtn").disabled = false; }
    };
  }
  if ($("reloadTokBtn")) {
    $("reloadTokBtn").onclick = () => loadTokens().catch((e) => showError(String(e.message || e)));
  }

  // AI
  if ($("aiRunBtn")) {
    $("aiRunBtn").onclick = async () => {
      $("aiRunBtn").disabled = true;
      setOut("aiOut", "… calling Admin AI …", false);
      try {
        const res = await api("POST", "/api/v1/ai/run", {
          capability: $("aiCap").value,
          user_data: ($("aiData").value || "").trim(),
        });
        setOut("aiOut", JSON.stringify(res, null, 2), false);
        showOk(`AI ${res.mode || "ok"}`);
        const st = await api("GET", "/api/v1/ai/status");
        window.__SC5_renderAi(st);
      } catch (e) {
        setOut("aiOut", String(e.message || e), false);
        showError(String(e.message || e));
      } finally {
        $("aiRunBtn").disabled = false;
      }
    };
  }
  if ($("aiRefreshBtn")) {
    $("aiRefreshBtn").onclick = async () => {
      try {
        const st = await api("GET", "/api/v1/ai/status");
        window.__SC5_renderAi(st);
        setOut("aiOut", JSON.stringify({
          status: st.status, active_mode: st.active_mode, busy: st.busy,
          llm_count: st.llm_count, llms: st.llms, last: st.last, metrics: st.metrics,
        }, null, 2), false);
        showOk("AI status refreshed");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("aiDebugBtn")) {
    $("aiDebugBtn").onclick = async () => {
      try {
        const st = await api("GET", "/api/v1/ai/status?debug=true");
        window.__SC5_renderAi(st);
        setOut("aiOut", JSON.stringify(st, null, 2), false);
        showOk("AI debug loaded");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // LLM
  if ($("llmAddBtn")) {
    $("llmAddBtn").onclick = async () => {
      const name = ($("llmName").value || "").trim();
      const model = ($("llmModel").value || "").trim();
      if (!name || !model) return showError("Name and model required");
      try {
        const body = {
          name,
          model,
          provider: $("llmProvider").value,
          base_url: ($("llmBase").value || "").trim() || null,
          api_key: ($("llmKey").value || "").trim() || null,
        };
        const res = await api("POST", "/api/v1/llm", body);
        setOut("llmOut", JSON.stringify(res, null, 2), false);
        showOk("LLM saved");
        $("llmKey").value = "";
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("llmListBtn")) {
    $("llmListBtn").onclick = async () => {
      try {
        const rows = await api("GET", "/api/v1/llm");
        setOut("llmOut", JSON.stringify(rows, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Policy
  if ($("policyGetBtn")) {
    $("policyGetBtn").onclick = async () => {
      try {
        const p = await api("GET", "/api/v1/policy");
        setOut("policyOut", JSON.stringify(p, null, 2), false);
        if ($("policyJson")) $("policyJson").value = JSON.stringify(p, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("policySetBtn")) {
    $("policySetBtn").onclick = async () => {
      try {
        const raw = ($("policyJson").value || "").trim();
        const parsed = JSON.parse(raw);
        const body = parsed.rules != null ? parsed : { rules: parsed };
        const res = await api("PUT", "/api/v1/policy", body);
        setOut("policyOut", JSON.stringify(res, null, 2), false);
        showOk("Policy saved");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // MCP
  if ($("mcpToolsBtn")) {
    $("mcpToolsBtn").onclick = async () => {
      try {
        const res = await api("GET", "/mcp/tools");
        setOut("mcpOut", JSON.stringify(res, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("mcpCallBtn")) {
    $("mcpCallBtn").onclick = async () => {
      const name = ($("mcpName").value || "").trim();
      if (!name) return showError("Tool name required");
      let args = {};
      try {
        const raw = ($("mcpArgs").value || "").trim();
        if (raw) args = JSON.parse(raw);
      } catch (_) { return showError("Args must be valid JSON"); }
      try {
        const res = await api("POST", "/mcp/call", { name, arguments: args });
        setOut("mcpOut", JSON.stringify(res, null, 2), false);
        showOk("MCP call done");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Profiles UI
  async function loadProfiles() {
    if (!$("profList")) return;
    const data = await api("GET", "/api/v1/profiles");
    const active = data.active_id;
    const rows = data.profiles || [];
    if (!rows.length) {
      $("profList").innerHTML = '<div class="empty">No profiles</div>';
      return;
    }
    let html = "<table><thead><tr><th>Name</th><th>Channel</th><th></th></tr></thead><tbody>";
    rows.forEach((p) => {
      const isAct = p.id === active || p.active;
      html += `<tr>
        <td><div>${escapeHtml(p.name)}</div>
            <div class="muted mono" style="font-size:0.65rem">${escapeHtml(p.id)}${isAct ? " · ACTIVE" : ""}</div></td>
        <td class="muted">${escapeHtml(p.channel || "http")}</td>
        <td>${can("profiles:write") || can("admin")
          ? `<button type="button" class="prof-act" data-id="${escapeHtml(p.id)}" style="padding:6px 8px;font-size:0.7rem">${isAct ? "Active" : "Activate"}</button>`
          : ""}</td>
      </tr>`;
    });
    html += "</tbody></table>";
    $("profList").innerHTML = html;
    $("profList").querySelectorAll(".prof-act").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api("POST", `/api/v1/profiles/${btn.getAttribute("data-id")}/activate`);
          showOk("Profile activated");
          await loadProfiles();
        } catch (e) { showError(String(e.message || e)); }
      };
    });
  }
  if ($("profReloadBtn")) {
    $("profReloadBtn").onclick = () => loadProfiles().catch((e) => showError(String(e.message || e)));
  }
  if ($("profGenBtn")) {
    $("profGenBtn").onclick = async () => {
      try {
        const host = location.hostname || "127.0.0.1";
        const port = Number(location.port || 8443);
        const res = await api("POST", "/api/v1/payloads/generate", {
          template: "http_beacon_python",
          host,
          port,
        });
        setOut("profOut", res.content || JSON.stringify(res, null, 2), false);
        showOk("Beacon generated for active profile");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  if ($("anomalyBtn")) {
    $("anomalyBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/observability/anomalies");
        setOut("obsExtraOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("reportBtn")) {
    $("reportBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/observability/report");
        setOut("obsExtraOut", r.markdown || JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("timelineBtn")) {
    $("timelineBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/observability/timeline?limit=30");
        setOut("obsExtraOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  async function loadChat() {
    if (!$("chatOut")) return;
    const r = await api("GET", "/api/v1/collab/chat?limit=30");
    const lines = (r.messages || []).map((m) => `${m.actor}: ${m.message}`);
    setOut("chatOut", lines.join("\n") || "(empty)", !lines.length);
  }
  if ($("chatSendBtn")) {
    $("chatSendBtn").onclick = async () => {
      const message = ($("chatMsg").value || "").trim();
      if (!message) return showError("Message required");
      try {
        await api("POST", "/api/v1/collab/chat", { message });
        $("chatMsg").value = "";
        await loadChat();
        showOk("Sent");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("chatReloadBtn")) {
    $("chatReloadBtn").onclick = () => loadChat().catch((e) => showError(String(e.message || e)));
  }

  // Bootstrap data for panels present
  if ($("featureToggles")) loadFeatures().catch((e) => showError(String(e.message || e)));
  if ($("tokList")) loadTokens().catch((e) => showError(String(e.message || e)));
  if ($("profList")) loadProfiles().catch((e) => showError(String(e.message || e)));
  if ($("chatOut")) loadChat().catch(() => {});
  window.__SC5_ADMIN_LOADED__ = true;
})();
