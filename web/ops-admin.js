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

  function isDesktopLayout() {
    try {
      return window.matchMedia && window.matchMedia("(min-width: 768px)").matches;
    } catch (_) {
      return false;
    }
  }

  const DOCS_BASE = "https://github.com/DotNetRussell/SquidC5/blob/master/docs/user-guide.md";

  function docLink(anchor, label) {
    const href = DOCS_BASE + "#" + anchor;
    return `<a class="doc-link" href="${href}" target="_blank" rel="noopener noreferrer" title="Open GitHub documentation">${label || "Docs"}</a>`;
  }

  function panel(id, title, body, open, docAnchor) {
    // Desktop: expanded by default; mobile: always start collapsed
    const isOpen = isDesktopLayout() && open !== false;
    const docs = docAnchor
      ? `<a class="doc-link summary-doc" href="${DOCS_BASE}#${docAnchor}" target="_blank" rel="noopener noreferrer" title="Documentation on GitHub" onclick="event.stopPropagation()">Docs</a>`
      : "";
    return `<details class="panel" id="${id}"${isOpen ? " open" : ""}>
      <summary>
        <span class="drag-handle" draggable="true" title="Drag to reorder">⋮⋮</span>
        <span class="panel-title">${title}</span>
        ${docs}
        <button type="button" class="wide-btn" title="Toggle full-width row">⟷</button>
      </summary>
      <div class="panel-body">${body}</div>
    </details>`;
  }

  function hint(text, docAnchor) {
    const more = docAnchor
      ? ` ${docLink(docAnchor, "Full docs →")}`
      : "";
    return `<p class="hint">${text}${more}</p>`;
  }

  const parts = [];

  // Multi-page nav (competitor-style: Dashboard / Sessions / Listeners / Post-Ex / Collab / Admin)
  const uiRole = window.__SC5_UI_ROLE__ || (can("admin") ? "admin" : "operator");
  parts.push(`
    <div id="opsNavBar" class="ops-nav" style="grid-column:1/-1;display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:8px 4px;margin-bottom:8px;border-bottom:1px solid rgba(255,255,255,0.08)">
      <strong style="margin-right:8px">SquidC5</strong>
      <button type="button" class="ops-page-btn primary" data-page="dashboard">Dashboard</button>
      <button type="button" class="ops-page-btn" data-page="sessions">Sessions</button>
      <button type="button" class="ops-page-btn" data-page="listeners">Listeners</button>
      <button type="button" class="ops-page-btn" data-page="postex">Post-Ex</button>
      <button type="button" class="ops-page-btn" data-page="collab">Collab</button>
      ${can("admin") || uiRole === "admin" ? '<button type="button" class="ops-page-btn" data-page="admin">Admin</button>' : ""}
      <span style="flex:1"></span>
      <label for="layoutPreset" class="muted" style="font-size:0.75rem">Role layout</label>
      <select id="layoutPreset" style="max-width:140px">
        <option value="operator">Operator</option>
        <option value="lead">Lead</option>
        ${can("admin") ? '<option value="admin">Admin</option>' : ""}
      </select>
    </div>
  `);

  // ----- Identity -----
  parts.push(panel("identityCard", "🪪 Identity", `
    ${hint("Who you are on this C2. Scopes gate panels; admin unlocks Admin page.", "identity")}
    <p class="muted mono" id="whoLine">—</p>
    <div class="chips" id="scopeChips" style="margin-top:8px"></div>
    <div class="row" style="margin-top:8px">
      <button type="button" id="whoamiBtn">Whoami</button>
      <button type="button" id="healthBtn">Health</button>
    </div>
    <div class="outbox empty-out" id="identOut" style="margin-top:8px">—</div>
  `, true, "identity"));

  // ----- U1 Session workbench -----
  if (can("sessions:read") || can("shell:interact") || can("tasks:write")) {
    parts.push(panel("workbenchPanel", "🎯 Session workbench", `
      ${hint("One selected session drives Shell, Tasks, Files, SOCKS, and Modules. Claim lock (M1) before multi-op tasking. Spectate for read-only.", "session-workbench")}
      <label for="wbSession">Active session</label>
      <select id="wbSession"><option value="">(none)</option></select>
      <div class="row" style="margin-top:6px">
        <button type="button" id="wbRefreshBtn">Refresh list</button>
        ${can("collab:use") || can("shell:interact") || can("admin") ? '<button type="button" class="primary" id="wbClaimBtn">Claim</button>' : ""}
        ${can("collab:use") || can("shell:interact") || can("admin") ? '<button type="button" id="wbReleaseBtn">Release</button>' : ""}
        ${can("sessions:read") ? '<button type="button" id="wbSpectateBtn">Spectate</button>' : ""}
      </div>
      <p class="muted mono" id="wbClaimLine" style="margin-top:8px">claim: —</p>
      <div class="outbox empty-out" id="wbOut" style="margin-top:8px">Select a session to operate.</div>
    `, true, "session-workbench"));
  }

  // ----- U2 Live events rail -----
  if (can("metrics:read") || can("sessions:read") || can("collab:use") || can("admin")) {
    parts.push(panel("eventsRailPanel", "📡 Live events", `
      ${hint("SSE stream: shell.output, tasks, HITL, chat, presence. Sticky rail for ops awareness.", "live-events")}
      <div class="row">
        <button type="button" class="primary" id="eventsConnectBtn">Connect</button>
        <button type="button" id="eventsClearBtn">Clear</button>
        <span class="chip" id="eventsStatus">off</span>
      </div>
      <div class="outbox empty-out" id="eventsRail" style="margin-top:8px;min-height:120px;max-height:220px;overflow:auto">—</div>
    `, true, "live-events"));
  }

  // ----- Shell interact -----
  if (can("shell:interact")) {
    parts.push(panel("quickRunCard", "⌨ Shell", `
      ${hint("Interactive command runner for <strong>verified reverse shells</strong> only (exec-probe passed). Uses workbench session when set. Buffer shows recent session output — not a live PTY.", "shell")}
      <label for="shellSelect">Target shell</label>
      <select id="shellSelect"><option value="">(none)</option></select>
      <label for="shellCmd">Command</label>
      <textarea id="shellCmd" placeholder="whoami" class="touch-lg"></textarea>
      <div class="row">
        <button type="button" class="primary touch-lg" id="runShellBtn">Run</button>
        ${can("shell:interact") ? '<button type="button" id="runAllBtn">All verified</button>' : ""}
        <button type="button" id="dumpOutBtn">Buffer</button>
      </div>
      <h2 style="margin-top:12px">Output</h2>
      <div class="outbox empty-out" id="shellOut">Run a command to see output here.</div>
    `, true, "shell"));
  }

  // ----- Sessions -----
  if (can("sessions:read") || can("sessions:write")) {
    parts.push(panel("sessionsPanel", "📡 Sessions", `
      ${hint("Every implant or reverse-shell connection the server tracks (beacons, shells, closed). <strong>Reap dead</strong> probes and drops mute/zombie shells. <strong>Close selected</strong> uses the Shell dropdown target. List all dumps the full session table for forensics.", "sessions")}
      <div class="row">
        ${can("sessions:write") ? '<button type="button" id="reapBtn">Reap dead</button>' : ""}
        ${can("sessions:write") ? '<button type="button" class="danger" id="clearUnverifiedBtn" title="Delete unverified reverse shells (internet scanner noise)">Clear unverified</button>' : ""}
        ${can("sessions:write") ? '<button type="button" class="danger" id="clearClosedBtn" title="Purge closed shell rows from DB">Purge closed shells</button>' : ""}
        ${can("sessions:write") ? '<button type="button" class="danger" id="closeShellBtn">Close selected</button>' : ""}
        <button type="button" id="listAllSesBtn">List all</button>
      </div>
      <div id="sesExtra" class="outbox empty-out" style="margin-top:8px">—</div>
    `, true, "sessions"));
  }

  // ----- Tasks (beacons) -----
  if (can("tasks:read") || can("tasks:write")) {
    parts.push(panel("tasksPanel", "📋 Tasks", `
      ${hint("Async work queue for <strong>beacon</strong> implants. Session defaults from workbench.", "tasks")}
      ${can("tasks:write") ? `
        <label for="taskSession">Session id</label>
        <input id="taskSession" class="wb-bound" placeholder="from workbench" autocomplete="off" />
        <label for="taskCmd">Command</label>
        <input id="taskCmd" placeholder="id / whoami" autocomplete="off" class="touch-lg" />
        <div class="row">
          <button type="button" class="primary touch-lg" id="createTaskBtn">Create task</button>
          <button type="button" id="listTasksBtn">List tasks</button>
        </div>
      ` : `<div class="row"><button type="button" id="listTasksBtn">List tasks</button></div>`}
      <div class="outbox empty-out" id="taskOut" style="margin-top:8px">—</div>
    `, true, "tasks"));
  }

  // ----- Listeners -----
  if (can("listeners:read") || can("listeners:write")) {
    parts.push(panel("listenersPanel", "🎧 Listeners", `
      ${hint("Server-side sockets that accept implant traffic. <strong>How to set up:</strong> (1) Create with a name + port + kind, (2) ensure Start shows running, (3) open the host firewall for that port, (4) point payloads/shells at this host:port. <strong>Kinds:</strong> <code>reverse_shell</code> = raw TCP shells; <code>http</code> = HTTP beacons; <code>tcp</code> = generic TCP; <code>dns</code> = DNS TXT C2 (set zone). Privileged ports (&lt;1024) need host sysctl if non-root. Background: <a class=\"doc-link\" href=\"https://grok.com/pedia/reverse-shell\" target=\"_blank\" rel=\"noopener noreferrer\">reverse shell</a> · <a class=\"doc-link\" href=\"https://grok.com/pedia/dns-tunneling\" target=\"_blank\" rel=\"noopener noreferrer\">DNS tunneling</a>.", "listeners")}
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
    `, true, "listeners"));
  }

  // ----- Payloads -----
  if (can("payloads:generate")) {
    parts.push(panel("payloadsPanel", "💣 Payloads / implants", `
      ${hint("Deterministic stagers/agents that call back to your listeners. Pick a template (or implant family), set callback host/port (and scheme/zone if needed), Generate, then run only on authorized targets. Reverse-shell templates need a <code>reverse_shell</code> listener; HTTP/DNS/WS beacons need matching listener kinds and usually an active C2 profile for HTTP surface shape. Background: <a class=\"doc-link\" href=\"https://grok.com/pedia/payload\" target=\"_blank\" rel=\"noopener noreferrer\">payload</a> · <a class=\"doc-link\" href=\"https://grok.com/pedia/implant\" target=\"_blank\" rel=\"noopener noreferrer\">implant</a> · <a class=\"doc-link\" href=\"https://grok.com/pedia/beacon\" target=\"_blank\" rel=\"noopener noreferrer\">beacon</a>.", "payloads-and-implants")}
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
    `, true, "payloads-and-implants"));
  }

  // ----- Plugins -----
  if (can("plugins:manage") || can("admin")) {
    parts.push(panel("pluginsPanel", "🧩 Plugins", `
      ${hint("Optional server extensions (signed catalog modules) that add curated capabilities — e.g. lab recon helpers — without shipping them in the core binary. Catalog lists available modules; Install + enable loads one by name and turns it on under policy. Plugins stay allow-listed; they are not arbitrary remote code from the internet.", "plugins")}
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
    `, true, "plugins"));
  }

  // ----- Deploy helpers -----
  if (can("admin") || can("listeners:write")) {
    parts.push(panel("deployPanel", "🛡 Redirector / certs", `
      ${hint("OpSec helpers for fronting the C2. Nginx snippet builds a sample reverse-proxy config (server_name + beacon URI paths) for a redirector/CDN hop. Cert plan outlines TLS issuance steps for that hostname — it does not auto-issue certificates on the droplet.", "redirector-and-certificates")}
      <input id="redirName" placeholder="server_name e.g. cdn.lab" />
      <input id="redirUris" placeholder="beacon uris comma-sep" />
      <div class="row">
        <button type="button" class="primary" id="redirBtn">Nginx snippet</button>
        <button type="button" id="certPlanBtn">Cert plan</button>
      </div>
      <div class="outbox empty-out" id="deployOut" style="margin-top:8px">—</div>
    `, true, "redirector-and-certificates"));
  }

  // ----- Metrics / Audit -----
  if (can("metrics:read") || can("audit:read")) {
    parts.push(panel("obsPanel", "📈 Observability", `
      ${hint("Live counters (sessions, tasks, AI calls, etc.) and the append-only audit trail of operator/API actions. Use this to verify what happened and when — not a full SIEM, but the authoritative in-product log.", "observability")}
      <div class="row">
        ${can("metrics:read") ? '<button type="button" id="metricsBtn">Metrics</button>' : ""}
        ${can("audit:read") ? '<button type="button" id="auditBtn">Audit log</button>' : ""}
      </div>
      <div class="outbox" id="adminOut" style="margin-top:8px"></div>
    `, true, "observability"));
  }

  // ----- Admin AI -----
  if (can("ai:use")) {
    parts.push(panel("aiCard", "✨ Admin AI", `
      ${hint("Sandboxed, allow-listed AI capabilities on the server (not free-form agents). Uses your configured LLM if present, otherwise offline/deterministic fallbacks. Untrusted session text is sanitized before prompts. Pick a capability, pass structured input, Run AI — results are auditable. Phishing-related caps are for <strong>authorized</strong> sims only — <a class=\"doc-link\" href=\"https://grok.com/pedia/phishing\" target=\"_blank\" rel=\"noopener noreferrer\">phishing</a>.", "admin-ai")}
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
    `, true, "admin-ai"));
  }

  // ----- LLM manage -----
  if (can("llm:manage")) {
    parts.push(panel("llmPanel", "🧠 LLM connections", `
      ${hint("BYO model endpoints for Admin AI (OpenAI-compatible, including xAI Grok). Keys are stored server-side in data/ and never returned by status APIs. Add a named connection, then Admin AI can use it; without an LLM the AI stays offline-fallback only.", "llm-connections")}
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
    `, true, "llm-connections"));
  }

  // ----- Tokens -----
  if (can("tokens:manage") || can("admin")) {
    parts.push(panel("tokensPanel", "🔑 Tokens", `
      ${hint("Mint scoped API tokens for operators, automation, or MCP. The raw <code>sc5_…</code> secret is shown <strong>once</strong> at create — copy it immediately. Presets map to common scope bundles; custom lets you pick exact scopes. Revoke compromised tokens from the list.", "tokens")}
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
    `, true, "tokens"));
  }

  // ----- Observability extras -----
  if (can("metrics:read") || can("audit:read") || can("admin")) {
    parts.push(panel("obsExtraPanel", "🗺 Timeline / report", `
      ${hint("Higher-level ops forensics: anomaly hints, a chronological event timeline, and exportable engagement reports. Complements raw metrics/audit with operator-facing summaries for handoff and after-action.", "timeline-and-reports")}
      <div class="row">
        <button type="button" id="anomalyBtn">Anomalies</button>
        <button type="button" id="reportBtn">Export report</button>
        <button type="button" id="timelineBtn">Timeline</button>
      </div>
      <div class="outbox empty-out" id="obsExtraOut" style="margin-top:8px">—</div>
    `, true, "timeline-and-reports"));
  }

  // ----- Collab chat (M5 team-scoped) -----
  if (can("collab:use") || can("admin")) {
    parts.push(panel("chatPanel", "💬 Operator chat", `
      ${hint("Team-scoped or global operator chat (M5). Pick a team channel or leave blank for global.", "operator-chat")}
      <label for="chatTeam">Team channel</label>
      <select id="chatTeam"><option value="">(global)</option></select>
      <label for="chatMsg">Message</label>
      <input id="chatMsg" placeholder="handoff note…" autocomplete="off" class="touch-lg" />
      <div class="row">
        <button type="button" class="primary touch-lg" id="chatSendBtn">Send</button>
        <button type="button" id="chatReloadBtn">Reload</button>
      </div>
      <div class="outbox empty-out" id="chatOut" style="margin-top:8px">—</div>
    `, true, "operator-chat"));
  }

  // ----- U3 Teams + handoff + M4 presence -----
  if (can("collab:use") || can("admin")) {
    parts.push(panel("teamsPanel", "👥 Teams / handoff", `
      ${hint("Multi-op teams, members, claim handoff packs, and online presence.", "teams-handoff")}
      <div class="row">
        <button type="button" id="teamsReloadBtn">List teams</button>
        <button type="button" id="presenceBtn">Who's online</button>
      </div>
      <label for="newTeamName">Create team</label>
      <div class="row">
        <input id="newTeamName" placeholder="red-cell" autocomplete="off" />
        <button type="button" class="primary" id="teamCreateBtn">Create</button>
      </div>
      <label for="teamMemberTeam">Add member — team id</label>
      <input id="teamMemberTeam" placeholder="team_…" autocomplete="off" />
      <label for="teamMemberActor">Actor name</label>
      <input id="teamMemberActor" placeholder="alice" autocomplete="off" />
      <div class="row">
        <button type="button" id="teamAddMemberBtn">Add member</button>
        <button type="button" id="teamListMembersBtn">List members</button>
      </div>
      <hr style="border-color:rgba(255,255,255,0.08);margin:10px 0" />
      <label for="handoffTo">Handoff to (actor)</label>
      <input id="handoffTo" placeholder="bob" autocomplete="off" />
      <label for="handoffNote">Note</label>
      <textarea id="handoffNote" placeholder="status + next steps" style="min-height:50px"></textarea>
      <div class="row">
        <button type="button" class="primary" id="handoffBtn">Handoff active session</button>
        <button type="button" id="handoffListBtn">List handoffs</button>
      </div>
      <div class="outbox empty-out" id="teamsOut" style="margin-top:8px">—</div>
    `, true, "teams-handoff"));
  }

  // ----- M6 My audit -----
  if (can("audit:read") || can("admin")) {
    parts.push(panel("auditMePanel", "🧾 My actions", `
      ${hint("Per-operator audit filter (M6). Load your actions or filter by actor.", "audit-me")}
      <div class="row">
        <button type="button" class="primary" id="auditMeBtn">My actions</button>
        <button type="button" id="auditMineTimelineBtn">My timeline</button>
      </div>
      <label for="auditActor">Filter actor</label>
      <input id="auditActor" placeholder="operator name" autocomplete="off" />
      <div class="row">
        <button type="button" id="auditActorBtn">Load actor audit</button>
      </div>
      <div class="outbox empty-out" id="auditMeOut" style="margin-top:8px">—</div>
    `, false, "audit-me"));
  }

  // ----- U6 Pivot map -----
  if (can("shell:interact") || can("admin")) {
    parts.push(panel("pivotMapPanel", "🗺 Pivot map", `
      ${hint("Simple session → SOCKS listen graph.", "pivot-map")}
      <div class="row">
        <button type="button" class="primary" id="pivotMapBtn">Refresh map</button>
      </div>
      <div class="outbox empty-out" id="pivotMapOut" style="margin-top:8px">—</div>
    `, false, "pivot-map"));
  }

  // ----- C2 Profiles -----
  if (can("profiles:read") || can("admin")) {
    parts.push(panel("profilesPanel", "📡 C2 profiles", `
      ${hint("<strong>What they are:</strong> malleable traffic profiles that define how HTTP (and related) beacons look on the wire — paths, headers, jitter, decoy behavior — so C2 blends with legitimate traffic. <strong>What they do:</strong> the active profile is the surface generators and the server expect for implant check-ins. Activate a profile, then Generate beacon (active) so payloads match that profile. Switching profiles mid-op changes the expected beacon shape; regenerate implants after a switch. Background: <a class=\"doc-link\" href=\"https://grok.com/pedia/command-and-control\" target=\"_blank\" rel=\"noopener noreferrer\">C2</a> · <a class=\"doc-link\" href=\"https://grok.com/pedia/beacon\" target=\"_blank\" rel=\"noopener noreferrer\">beacon</a>.", "c2-profiles")}
      <div id="profList" class="empty">—</div>
      <div class="row" style="margin-top:8px">
        <button type="button" id="profReloadBtn">Reload</button>
        ${can("payloads:generate") || can("admin") ? '<button type="button" class="primary" id="profGenBtn">Generate beacon (active)</button>' : ""}
      </div>
      <div class="outbox empty-out" id="profOut" style="margin-top:8px">—</div>
    `, true, "c2-profiles"));
  }

  // ----- File ops -----
  if (can("shell:interact")) {
    parts.push(panel("filesPanel", "📁 File ops", `
      ${hint("Structured file list/read/write/delete tasks on a beacon session. Write may require HITL. Implant executes <code>file:*</code> commands.", "file-ops")}
      <label for="fileSession">Session id</label>
      <input id="fileSession" class="wb-bound" placeholder="from workbench" autocomplete="off" />
      <label for="fileOp">Op</label>
      <select id="fileOp">
        <option value="list">list</option>
        <option value="read">read</option>
        <option value="write">write</option>
        <option value="delete">delete</option>
      </select>
      <div class="row" id="fileCrumbs" style="flex-wrap:wrap;gap:4px;margin:6px 0"></div>
      <label for="filePath">Path</label>
      <input id="filePath" placeholder="/tmp or ." autocomplete="off" class="touch-lg" />
      <label for="fileContent">Content (write)</label>
      <textarea id="fileContent" placeholder="optional text" style="min-height:60px"></textarea>
      <div class="row">
        <button type="button" class="primary touch-lg" id="fileOpBtn">Queue / browse</button>
      </div>
      <div id="fileTable" style="margin-top:8px;overflow:auto"></div>
      <div class="outbox empty-out" id="fileOut" style="margin-top:8px">—</div>
    `, false, "file-ops"));
  }

  // ----- SOCKS pivot -----
  if (can("shell:interact")) {
    parts.push(panel("socksPanel", "🕸 SOCKS pivot", `
      ${hint("Start a SOCKS5 listener bridged through an implant (reverse-dial) or direct mode. List/stop existing pivots.", "socks-pivot")}
      <label for="socksSession">Session id</label>
      <input id="socksSession" class="wb-bound" placeholder="from workbench" autocomplete="off" />
      <label for="socksHost">Listen host</label>
      <input id="socksHost" value="127.0.0.1" autocomplete="off" />
      <label for="socksPort">Listen port (0=ephemeral)</label>
      <input id="socksPort" type="number" value="0" autocomplete="off" />
      <label for="socksMode">Mode</label>
      <select id="socksMode">
        <option value="implant">implant (reverse-dial)</option>
        <option value="direct">direct</option>
      </select>
      <div class="row">
        <button type="button" class="primary" id="socksStartBtn">Start</button>
        <button type="button" id="socksListBtn">List</button>
      </div>
      <label for="socksStopId">Stop pivot id</label>
      <input id="socksStopId" placeholder="pivot id" autocomplete="off" />
      <div class="row">
        <button type="button" class="danger" id="socksStopBtn">Stop</button>
      </div>
      <div class="outbox empty-out" id="socksOut" style="margin-top:8px">—</div>
    `, false, "socks-pivot"));
  }

  // ----- Modules inject / BOF -----
  if (can("shell:interact") || can("tasks:read")) {
    parts.push(panel("modulesPanel", "🧬 Inject / BOF / sleep", `
      ${hint("Lab catalog for inject techniques, BOF modules, sleep-mask modes. Queue inject/BOF only on authorized targets; implant requires <code>SC5_ALLOW_INJECT=1</code> / <code>SC5_ALLOW_BOF=1</code>.", "modules")}
      <div class="row">
        <button type="button" id="modCatalogBtn">Load catalog</button>
      </div>
      <label for="modSession">Session id</label>
      <input id="modSession" class="wb-bound" placeholder="from workbench" autocomplete="off" />
      <label for="modTech">Inject technique</label>
      <input id="modTech" placeholder="create_remote_thread" autocomplete="off" />
      <label for="modPid">PID</label>
      <input id="modPid" type="number" value="0" autocomplete="off" />
      <div class="row">
        ${can("shell:interact") ? '<button type="button" class="primary" id="modInjectBtn">Queue inject</button>' : ""}
      </div>
      <label for="modBofId">BOF module id</label>
      <input id="modBofId" placeholder="whoami" autocomplete="off" />
      <div class="row">
        ${can("shell:interact") ? '<button type="button" id="modBofBtn">Queue bof:run</button>' : ""}
      </div>
      <div class="outbox empty-out" id="modOut" style="margin-top:8px">—</div>
    `, false, "modules"));
  }

  // ----- HITL queue -----
  if (can("policy:manage") || can("admin")) {
    parts.push(panel("hitlPanel", "✋ HITL queue", `
      ${hint("Human-in-the-loop approvals for high-risk actions. List pending requests; approve or deny as admin.", "hitl")}
      <div class="row">
        <button type="button" id="hitlListBtn">List pending</button>
      </div>
      <label for="hitlId">Request id</label>
      <input id="hitlId" placeholder="hitl request id" autocomplete="off" />
      <div class="row">
        ${can("admin") ? '<button type="button" class="primary" id="hitlApproveBtn">Approve</button>' : ""}
        ${can("admin") ? '<button type="button" class="danger" id="hitlDenyBtn">Deny</button>' : ""}
      </div>
      <div class="outbox empty-out" id="hitlOut" style="margin-top:8px">—</div>
    `, false, "hitl"));
  }

  // ----- Engagement ROE -----
  if (can("policy:manage") || can("admin")) {
    parts.push(panel("engagementPanel", "🎯 Engagement ROE", `
      ${hint("Rules of engagement: allowed hosts/CIDRs, kill date, working hours. Get current policy; admins can PATCH JSON fields.", "engagement")}
      <div class="row">
        <button type="button" id="engGetBtn">Get engagement</button>
      </div>
      <label for="engJson">Update JSON (admin)</label>
      <textarea id="engJson" placeholder='{"allowed_cidrs":["10.0.0.0/8"]}' style="min-height:80px"></textarea>
      <div class="row">
        ${can("admin") ? '<button type="button" class="primary" id="engSetBtn">Save engagement</button>' : ""}
      </div>
      <div class="outbox empty-out" id="engOut" style="margin-top:8px">—</div>
    `, false, "engagement"));
  }

  // ----- Feature toggles (admin) -----
  if (can("admin") || can("policy:manage")) {
    parts.push(panel("featuresPanel", "🎛 Feature toggles", `
      ${hint("Runtime kill-switches enforced by the server. Off means the API denies that capability (MCP, AI paths, etc.). Defaults are secure; <code>public_docs</code> stays locked off. Save writes the flag set; Reload refreshes from the server.", "feature-toggles")}
      <div id="featureToggles"></div>
      <div class="row">
        <button type="button" class="primary" id="saveFeaturesBtn">Save features</button>
        <button type="button" id="reloadFeaturesBtn">Reload</button>
      </div>
    `, true, "feature-toggles"));
  }

  // ----- Policy -----
  if (can("policy:manage")) {
    parts.push(panel("policyPanel", "📜 Policy", `
      ${hint("Risk / allow-deny engine rules: thresholds for high-risk actions, HITL gates, and chain limits. Get policy loads current JSON; edit carefully and Save. Bad policy can block operators or weaken guardrails — treat as production config.", "policy")}
      <div class="row">
        <button type="button" id="policyGetBtn">Get policy</button>
      </div>
      <label for="policyJson">Set policy JSON</label>
      <textarea id="policyJson" placeholder='{"thresholds":{...}}' style="min-height:100px"></textarea>
      <div class="row">
        <button type="button" class="primary" id="policySetBtn">Save policy</button>
      </div>
      <div class="outbox empty-out" id="policyOut" style="margin-top:8px">—</div>
    `, true, "policy"));
  }

  // ----- MCP -----
  if (can("mcp:connect")) {
    parts.push(panel("mcpPanel", "🔌 MCP tools", `
      ${hint("External AI / MCP bridge: tools exposed to models under a per-token allow-list (not open-ended autonomy). List tools shows what this token may call; Call runs one tool with JSON args. MCP is off by default until features/settings enable it. Background: <a class=\"doc-link\" href=\"https://grok.com/pedia/model-context-protocol\" target=\"_blank\" rel=\"noopener noreferrer\">Model Context Protocol</a>.", "mcp-tools")}
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
    `, true, "mcp-tools"));
  }

  root.innerHTML = parts.join("\n") || '<details class="panel" open><summary>Console</summary><p class="muted">No scoped actions for this token.</p></details>';

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

  if ($("clearUnverifiedBtn")) {
    $("clearUnverifiedBtn").onclick = async () => {
      if (!confirm("Delete all unverified reverse shells? (keeps verified)")) return;
      try {
        const res = await api("POST", "/api/v1/sessions/clear", { unverified_only: true, delete: true });
        showOk(`Cleared ${res.removed || 0} unverified shell(s)`);
        if (typeof refresh === "function") refresh();
      } catch (e) { showError(e.message || String(e)); }
    };
  }
  if ($("clearClosedBtn")) {
    $("clearClosedBtn").onclick = async () => {
      if (!confirm("Hard-delete all closed reverse-shell rows?")) return;
      try {
        const res = await api("POST", "/api/v1/sessions/clear", { closed_only: true, unverified_only: false, delete: true });
        showOk(`Purged ${res.removed || 0} closed shell(s)`);
        if (typeof refresh === "function") refresh();
      } catch (e) { showError(e.message || String(e)); }
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
    const tid = ($("chatTeam") && $("chatTeam").value) || "";
    const q = tid ? `?limit=30&team_id=${encodeURIComponent(tid)}` : "?limit=30";
    const r = await api("GET", "/api/v1/collab/chat" + q);
    const lines = (r.messages || []).map((m) => {
      const ch = m.team_id ? `[${String(m.team_id).slice(0, 8)}] ` : "";
      // setOut uses textContent; still strip control chars defensively
      const actor = String(m.actor || "?").replace(/[\r\n\t]/g, " ").slice(0, 64);
      const msg = String(m.message || "").replace(/[\r\n]+/g, " ").slice(0, 2000);
      return `${ch}${actor}: ${msg}`;
    });
    setOut("chatOut", lines.join("\n") || "(empty)", !lines.length);
  }
  if ($("chatSendBtn")) {
    $("chatSendBtn").onclick = async () => {
      const message = ($("chatMsg").value || "").trim();
      if (!message) return showError("Message required");
      const team_id = ($("chatTeam") && $("chatTeam").value) || null;
      try {
        await api("POST", "/api/v1/collab/chat", { message, team_id: team_id || null });
        $("chatMsg").value = "";
        await loadChat();
        showOk("Sent");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("chatReloadBtn")) {
    $("chatReloadBtn").onclick = () => loadChat().catch((e) => showError(String(e.message || e)));
  }
  if ($("chatTeam")) {
    $("chatTeam").onchange = () => loadChat().catch(() => {});
  }

  // ----- U1 Workbench + claim -----
  function activeSessionId() {
    const wb = $("wbSession") && $("wbSession").value;
    if (wb) return wb.trim();
    const sh = $("shellSelect") && $("shellSelect").value;
    return (sh || "").trim();
  }
  function syncWorkbenchBindings(sid) {
    document.querySelectorAll(".wb-bound").forEach((el) => {
      if (sid) el.value = sid;
    });
    if ($("shellSelect") && sid) {
      const opt = Array.from($("shellSelect").options).find((o) => o.value === sid);
      if (opt) $("shellSelect").value = sid;
    }
    if ($("taskSession") && sid) $("taskSession").value = sid;
  }
  async function loadWorkbenchSessions() {
    if (!$("wbSession")) return;
    try {
      const rows = await api("GET", "/api/v1/sessions?status=active");
      const list = Array.isArray(rows) ? rows : (rows.sessions || []);
      const cur = $("wbSession").value;
      $("wbSession").innerHTML = '<option value="">(none)</option>' +
        list.map((s) => {
          const meta = s.metadata || {};
          const claim = meta.claimed_by ? ` · 🔒${meta.claimed_by}` : "";
          const label = `${s.id.slice(0, 12)}… ${s.kind || ""} ${s.hostname || s.remote_addr || ""}${claim}`;
          return `<option value="${escapeHtml(s.id)}">${escapeHtml(label)}</option>`;
        }).join("");
      if (cur) $("wbSession").value = cur;
    } catch (e) {
      setOut("wbOut", String(e.message || e), false);
    }
  }
  if ($("wbRefreshBtn")) {
    $("wbRefreshBtn").onclick = () => loadWorkbenchSessions().then(() => showOk("Sessions refreshed")).catch((e) => showError(String(e.message || e)));
  }
  if ($("wbSession")) {
    $("wbSession").onchange = async () => {
      const sid = activeSessionId();
      syncWorkbenchBindings(sid);
      if (!sid) {
        if ($("wbClaimLine")) $("wbClaimLine").textContent = "claim: —";
        setOut("wbOut", "Select a session to operate.", true);
        return;
      }
      try {
        const s = await api("GET", `/api/v1/sessions/${encodeURIComponent(sid)}`);
        const meta = s.metadata || {};
        if ($("wbClaimLine")) {
          $("wbClaimLine").textContent = meta.claimed_by
            ? `claim: ${meta.claimed_by}${meta.claimed_at ? " @ " + new Date(meta.claimed_at * 1000).toISOString() : ""}`
            : "claim: (unlocked)";
        }
        setOut("wbOut", JSON.stringify({ id: s.id, kind: s.kind, hostname: s.hostname, status: s.status, claimed_by: meta.claimed_by }, null, 2), false);
        // presence viewing
        try {
          await api("POST", "/api/v1/collab/presence", { status: "online", viewing_session: sid });
        } catch (_) {}
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("wbClaimBtn")) {
    $("wbClaimBtn").onclick = async () => {
      const sid = activeSessionId();
      if (!sid) return showError("Select a session");
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(sid)}/claim`, {});
        setOut("wbOut", JSON.stringify(r, null, 2), false);
        showOk("Claimed");
        if ($("wbClaimLine")) $("wbClaimLine").textContent = `claim: ${r.claimed_by || "you"}`;
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("wbReleaseBtn")) {
    $("wbReleaseBtn").onclick = async () => {
      const sid = activeSessionId();
      if (!sid) return showError("Select a session");
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(sid)}/release`);
        setOut("wbOut", JSON.stringify(r, null, 2), false);
        showOk("Released");
        if ($("wbClaimLine")) $("wbClaimLine").textContent = "claim: (unlocked)";
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("wbSpectateBtn")) {
    $("wbSpectateBtn").onclick = async () => {
      const sid = activeSessionId();
      if (!sid) return showError("Select a session");
      try {
        const r = await api("GET", `/api/v1/sessions/${encodeURIComponent(sid)}/spectator`);
        setOut("wbOut", "👁 WATCHING\n" + JSON.stringify(r, null, 2), false);
        showOk("Spectator mode");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // ----- U2 Events rail -----
  let _evtSrc = null;
  function appendEventLine(text) {
    const el = $("eventsRail");
    if (!el) return;
    const line = document.createElement("div");
    line.className = "mono";
    line.style.fontSize = "0.7rem";
    line.textContent = text;
    if (el.classList.contains("empty-out")) {
      el.textContent = "";
      el.classList.remove("empty-out");
    }
    el.appendChild(line);
    while (el.childNodes.length > 80) el.removeChild(el.firstChild);
    el.scrollTop = el.scrollHeight;
  }
  if ($("eventsConnectBtn")) {
    $("eventsConnectBtn").onclick = () => {
      if (_evtSrc) {
        try { _evtSrc.close(); } catch (_) {}
        _evtSrc = null;
      }
      const base = (window.__SC5_API_BASE__ || location.origin || "").replace(/\/$/, "");
      const tok = (window.__SC5_STATE__ && window.__SC5_STATE__.token) || localStorage.getItem("sc5_token") || "";
      // EventSource cannot set Authorization — use query if server supports; else poll metrics
      // Prefer fetch stream via cookie-less: use polling fallback on recent events
      if ($("eventsStatus")) $("eventsStatus").textContent = "polling";
      showOk("Events rail connected (poll)");
      const poll = async () => {
        if (!$("eventsRail")) return;
        try {
          const snap = await api("GET", "/api/v1/metrics");
          const ev = (snap.recent_events || []).slice(-15);
          ev.forEach((e) => {
            const t = e.type || "?";
            const p = e.payload ? JSON.stringify(e.payload).slice(0, 120) : "";
            appendEventLine(`${new Date((e.ts || 0) * 1000).toISOString().slice(11, 19)} ${t} ${p}`);
          });
          if ($("eventsStatus")) $("eventsStatus").textContent = "live";
        } catch (e) {
          if ($("eventsStatus")) $("eventsStatus").textContent = "err";
        }
      };
      poll();
      if (window.__SC5_EVT_TIMER) clearInterval(window.__SC5_EVT_TIMER);
      window.__SC5_EVT_TIMER = setInterval(poll, 4000);
      // presence beat
      api("POST", "/api/v1/collab/presence", { status: "online" }).catch(() => {});
    };
  }
  if ($("eventsClearBtn")) {
    $("eventsClearBtn").onclick = () => {
      if ($("eventsRail")) {
        $("eventsRail").textContent = "—";
        $("eventsRail").classList.add("empty-out");
      }
    };
  }

  // ----- Multi-page + role layouts (admin can switch) -----
  const PAGE_PANELS = {
    dashboard: ["identityCard", "workbenchPanel", "eventsRailPanel", "sessionsPanel", "obsPanel", "obsExtraPanel"],
    sessions: ["workbenchPanel", "sessionsPanel", "quickRunCard", "tasksPanel", "eventsRailPanel"],
    listeners: ["listenersPanel", "payloadsPanel", "profilesPanel", "deployPanel"],
    postex: ["workbenchPanel", "filesPanel", "socksPanel", "modulesPanel", "pivotMapPanel", "pluginsPanel"],
    collab: ["chatPanel", "teamsPanel", "hitlPanel", "engagementPanel", "auditMePanel"],
    admin: ["tokensPanel", "featuresPanel", "policyPanel", "llmPanel", "mcpPanel", "aiCard", "deployPanel"],
  };
  const PRESET_HIDE = {
    operator: ["llmPanel", "tokensPanel", "featuresPanel", "policyPanel", "mcpPanel", "pluginsPanel", "deployPanel", "aiCard"],
    lead: ["llmPanel", "tokensPanel", "featuresPanel", "policyPanel", "mcpPanel", "payloadsPanel", "modulesPanel", "aiCard"],
    admin: [],
  };
  let _currentPage = "dashboard";
  function applyPage(page) {
    _currentPage = page || "dashboard";
    const show = PAGE_PANELS[_currentPage] || PAGE_PANELS.dashboard;
    const preset = ($("layoutPreset") && $("layoutPreset").value) || "operator";
    const hideExtra = PRESET_HIDE[preset] || [];
    // Non-admin cannot open admin page
    if (_currentPage === "admin" && !can("admin")) {
      _currentPage = "dashboard";
    }
    document.querySelectorAll("details.panel").forEach((p) => {
      if (!p.id) return;
      const onPage = show.indexOf(p.id) >= 0;
      const roleHide = hideExtra.indexOf(p.id) >= 0;
      p.style.display = onPage && !roleHide ? "" : "none";
      if (onPage && !roleHide && isDesktopLayout()) p.open = true;
    });
    document.querySelectorAll(".ops-page-btn").forEach((b) => {
      b.classList.toggle("primary", b.getAttribute("data-page") === _currentPage);
    });
    try {
      localStorage.setItem("sc5_ops_page", _currentPage);
      localStorage.setItem("sc5_layout_preset", preset);
    } catch (_) {}
  }
  function applyLayoutPreset(name) {
    if ($("layoutPreset")) $("layoutPreset").value = name;
    applyPage(_currentPage);
    showOk("Layout: " + name + " / " + _currentPage);
  }
  document.querySelectorAll(".ops-page-btn").forEach((b) => {
    b.onclick = () => applyPage(b.getAttribute("data-page"));
  });
  if ($("layoutPreset")) {
    try {
      const saved = localStorage.getItem("sc5_layout_preset");
      if (saved && (saved !== "admin" || can("admin"))) $("layoutPreset").value = saved;
      else if (!can("admin")) $("layoutPreset").value = "operator";
      else $("layoutPreset").value = "admin";
      const sp = localStorage.getItem("sc5_ops_page");
      if (sp) _currentPage = sp;
    } catch (_) {}
    $("layoutPreset").onchange = () => applyLayoutPreset($("layoutPreset").value);
    applyPage(_currentPage);
  }

  // ----- Teams / handoff / presence -----
  async function loadTeamsIntoSelects() {
    if (!$("chatTeam") && !$("teamsOut")) return;
    try {
      const teams = await api("GET", "/api/v1/teams");
      const list = Array.isArray(teams) ? teams : [];
      if ($("chatTeam")) {
        const cur = $("chatTeam").value;
        $("chatTeam").innerHTML = '<option value="">(global)</option>' +
          list.map((t) => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name || t.id)}</option>`).join("");
        if (cur) $("chatTeam").value = cur;
      }
      if ($("teamsOut") && list.length) {
        setOut("teamsOut", list.map((t) => `${t.id}  ${t.name}`).join("\n"), false);
      }
    } catch (_) {}
  }
  if ($("teamsReloadBtn")) {
    $("teamsReloadBtn").onclick = () => loadTeamsIntoSelects().then(() => showOk("Teams loaded")).catch((e) => showError(String(e.message || e)));
  }
  if ($("teamCreateBtn")) {
    $("teamCreateBtn").onclick = async () => {
      const name = ($("newTeamName").value || "").trim();
      if (!name) return showError("Team name required");
      try {
        const r = await api("POST", "/api/v1/teams", { name });
        setOut("teamsOut", JSON.stringify(r, null, 2), false);
        showOk("Team created");
        await loadTeamsIntoSelects();
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("teamAddMemberBtn")) {
    $("teamAddMemberBtn").onclick = async () => {
      const tid = ($("teamMemberTeam").value || "").trim();
      const actor = ($("teamMemberActor").value || "").trim();
      if (!tid || !actor) return showError("Team id and actor required");
      try {
        const r = await api("POST", `/api/v1/teams/${encodeURIComponent(tid)}/members`, { actor, role: "operator" });
        setOut("teamsOut", JSON.stringify(r, null, 2), false);
        showOk("Member added");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("teamListMembersBtn")) {
    $("teamListMembersBtn").onclick = async () => {
      const tid = ($("teamMemberTeam").value || "").trim();
      if (!tid) return showError("Team id required");
      try {
        const r = await api("GET", `/api/v1/teams/${encodeURIComponent(tid)}/members`);
        setOut("teamsOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("presenceBtn")) {
    $("presenceBtn").onclick = async () => {
      try {
        await api("POST", "/api/v1/collab/presence", { status: "online", viewing_session: activeSessionId() || null });
        const r = await api("GET", "/api/v1/collab/presence");
        const lines = (r.operators || []).map((o) => `${o.actor}  ${o.status}  ${o.viewing_session || ""}`);
        setOut("teamsOut", lines.join("\n") || "(nobody online)", !lines.length);
        showOk(`${r.count || 0} online`);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("handoffBtn")) {
    $("handoffBtn").onclick = async () => {
      const sid = activeSessionId();
      const to = ($("handoffTo").value || "").trim();
      if (!sid) return showError("Select workbench session");
      if (!to) return showError("Handoff target required");
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(sid)}/handoff`, {
          to,
          note: ($("handoffNote").value || "").trim(),
          transfer_claim: true,
          include_pack: true,
        });
        setOut("teamsOut", JSON.stringify(r, null, 2), false);
        showOk("Handoff sent");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("handoffListBtn")) {
    $("handoffListBtn").onclick = async () => {
      const sid = activeSessionId();
      if (!sid) return showError("Select workbench session");
      try {
        const r = await api("GET", `/api/v1/sessions/${encodeURIComponent(sid)}/handoffs`);
        setOut("teamsOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // ----- M6 audit me -----
  if ($("auditMeBtn")) {
    $("auditMeBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/audit/me?limit=50");
        setOut("auditMeOut", JSON.stringify(r, null, 2), false);
        showOk("My actions loaded");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("auditMineTimelineBtn")) {
    $("auditMineTimelineBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/observability/timeline?mine=true&limit=40");
        setOut("auditMeOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("auditActorBtn")) {
    $("auditActorBtn").onclick = async () => {
      const actor = ($("auditActor").value || "").trim();
      if (!actor) return showError("Actor required");
      try {
        const r = await api("GET", `/api/v1/audit?actor=${encodeURIComponent(actor)}&limit=50`);
        setOut("auditMeOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // ----- U6 pivot map -----
  if ($("pivotMapBtn")) {
    $("pivotMapBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/pivot/socks");
        const pivots = r.pivots || r || [];
        const lines = (Array.isArray(pivots) ? pivots : []).map((p) => {
          return `${p.session_id || "?"}  →  socks5://${p.listen_host || "127.0.0.1"}:${p.listen_port || "?"}  (${p.mode || p.status || "up"})`;
        });
        setOut("pivotMapOut", lines.join("\n") || "(no pivots)", !lines.length);
        showOk("Pivot map");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // File ops (U5 browser-ish)
  function renderFileCrumbs(path) {
    const el = $("fileCrumbs");
    if (!el) return;
    const parts = (path || ".").split(/[/\\]/).filter(Boolean);
    let acc = path && path.startsWith("/") ? "" : "";
    const crumbs = ['<button type="button" class="chip file-crumb" data-path=".">root</button>'];
    parts.forEach((p) => {
      acc = (acc ? acc + "/" : (path.startsWith("/") ? "/" : "")) + p;
      if (path.startsWith("/") && !acc.startsWith("/")) acc = "/" + acc;
      crumbs.push(`<button type="button" class="chip file-crumb" data-path="${escapeHtml(acc)}">${escapeHtml(p)}</button>`);
    });
    el.innerHTML = crumbs.join(" / ");
    el.querySelectorAll(".file-crumb").forEach((b) => {
      b.onclick = () => {
        if ($("filePath")) $("filePath").value = b.getAttribute("data-path") || ".";
        if ($("fileOp")) $("fileOp").value = "list";
        if ($("fileOpBtn")) $("fileOpBtn").click();
      };
    });
  }
  function renderFileTable(text) {
    const el = $("fileTable");
    if (!el) return;
    const lines = String(text || "").trim().split("\n").filter(Boolean);
    if (!lines.length || lines[0].startsWith("error")) {
      el.innerHTML = "";
      return;
    }
    // agent format: mode\tsize\tname
    let html = "<table><thead><tr><th></th><th>size</th><th>name</th></tr></thead><tbody>";
    let any = false;
    lines.forEach((ln) => {
      const parts = ln.split("\t");
      if (parts.length < 3) return;
      any = true;
      const mode = parts[0];
      const sz = parts[1];
      const name = parts.slice(2).join("\t");
      const base = ($("filePath").value || ".").replace(/\/$/, "");
      const next = base === "." ? name : base + "/" + name;
      html += `<tr><td>${escapeHtml(mode)}</td><td class="muted">${escapeHtml(sz)}</td>` +
        `<td><button type="button" class="file-row" data-path="${escapeHtml(next)}" data-mode="${escapeHtml(mode)}" style="background:none;border:0;color:inherit;cursor:pointer;text-align:left">${escapeHtml(name)}</button></td></tr>`;
    });
    html += "</tbody></table>";
    el.innerHTML = any ? html : "";
    el.querySelectorAll(".file-row").forEach((b) => {
      b.onclick = () => {
        const mode = b.getAttribute("data-mode");
        const p = b.getAttribute("data-path") || "";
        if ($("filePath")) $("filePath").value = p;
        if (mode === "d") {
          if ($("fileOp")) $("fileOp").value = "list";
          if ($("fileOpBtn")) $("fileOpBtn").click();
        } else {
          if ($("fileOp")) $("fileOp").value = "read";
        }
      };
    });
  }
  if ($("fileOpBtn")) {
    $("fileOpBtn").onclick = async () => {
      let session_id = ($("fileSession").value || "").trim() || activeSessionId();
      const op = ($("fileOp").value || "list").trim();
      const path = ($("filePath").value || "").trim() || ".";
      if (!session_id) return showError("Session id required (use workbench)");
      const body = { session_id, op, path };
      if (op === "write") body.content = $("fileContent").value || "";
      try {
        const r = await api("POST", "/api/v1/files/op", body);
        setOut("fileOut", JSON.stringify(r, null, 2), false);
        renderFileCrumbs(path);
        // if task already has result inline (rare), render table
        if (r.result) renderFileTable(r.result);
        showOk("File op queued — poll task for listing");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // SOCKS
  if ($("socksStartBtn")) {
    $("socksStartBtn").onclick = async () => {
      const session_id = ($("socksSession").value || "").trim();
      if (!session_id) return showError("Session id required");
      try {
        const r = await api("POST", "/api/v1/pivot/socks", {
          session_id,
          listen_host: ($("socksHost").value || "127.0.0.1").trim(),
          listen_port: Number($("socksPort").value || 0),
          mode: ($("socksMode").value || "implant"),
        });
        setOut("socksOut", JSON.stringify(r, null, 2), false);
        showOk("SOCKS started");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("socksListBtn")) {
    $("socksListBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/pivot/socks");
        setOut("socksOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("socksStopBtn")) {
    $("socksStopBtn").onclick = async () => {
      const id = ($("socksStopId").value || "").trim();
      if (!id) return showError("Pivot id required");
      try {
        const r = await api("DELETE", `/api/v1/pivot/socks/${encodeURIComponent(id)}`);
        setOut("socksOut", JSON.stringify(r, null, 2), false);
        showOk("Stopped");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Modules
  if ($("modCatalogBtn")) {
    $("modCatalogBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/modules");
        setOut("modOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("modInjectBtn")) {
    $("modInjectBtn").onclick = async () => {
      const session_id = ($("modSession").value || "").trim();
      if (!session_id) return showError("Session id required");
      try {
        const r = await api("POST", "/api/v1/modules/inject", {
          session_id,
          technique: ($("modTech").value || "create_remote_thread").trim(),
          pid: Number($("modPid").value || 0),
        });
        setOut("modOut", JSON.stringify(r, null, 2), false);
        showOk("Inject task queued");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("modBofBtn")) {
    $("modBofBtn").onclick = async () => {
      const session_id = ($("modSession").value || "").trim();
      const module_id = ($("modBofId").value || "").trim();
      if (!session_id || !module_id) return showError("Session and module id required");
      try {
        const r = await api("POST", "/api/v1/modules/bof/run", { session_id, module_id });
        setOut("modOut", JSON.stringify(r, null, 2), false);
        showOk("BOF task queued");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // HITL
  if ($("hitlListBtn")) {
    $("hitlListBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/policy/hitl?status=pending");
        setOut("hitlOut", JSON.stringify(r, null, 2), false);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("hitlApproveBtn")) {
    $("hitlApproveBtn").onclick = async () => {
      const id = ($("hitlId").value || "").trim();
      if (!id) return showError("Request id required");
      try {
        const r = await api("POST", `/api/v1/policy/hitl/${encodeURIComponent(id)}/approve`);
        setOut("hitlOut", JSON.stringify(r, null, 2), false);
        showOk("Approved");
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("hitlDenyBtn")) {
    $("hitlDenyBtn").onclick = async () => {
      const id = ($("hitlId").value || "").trim();
      if (!id) return showError("Request id required");
      try {
        const r = await api("POST", `/api/v1/policy/hitl/${encodeURIComponent(id)}/deny`);
        setOut("hitlOut", JSON.stringify(r, null, 2), false);
        showOk("Denied");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Engagement
  if ($("engGetBtn")) {
    $("engGetBtn").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/engagement");
        setOut("engOut", JSON.stringify(r, null, 2), false);
        if ($("engJson") && !$("engJson").value) $("engJson").value = JSON.stringify(r, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
  }
  if ($("engSetBtn")) {
    $("engSetBtn").onclick = async () => {
      let body = {};
      try { body = JSON.parse($("engJson").value || "{}"); }
      catch (_) { return showError("Invalid JSON"); }
      try {
        const r = await api("PUT", "/api/v1/engagement", body);
        setOut("engOut", JSON.stringify(r, null, 2), false);
        showOk("Engagement saved");
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  // Bootstrap data for panels present
  if ($("featureToggles")) loadFeatures().catch((e) => showError(String(e.message || e)));
  if ($("tokList")) loadTokens().catch((e) => showError(String(e.message || e)));
  if ($("profList")) loadProfiles().catch((e) => showError(String(e.message || e)));
  if ($("chatOut")) loadChat().catch(() => {});
  if ($("wbSession")) loadWorkbenchSessions().catch(() => {});
  if ($("chatTeam") || $("teamsOut")) loadTeamsIntoSelects().catch(() => {});
  // presence on load
  api("POST", "/api/v1/collab/presence", { status: "online" }).catch(() => {});
  window.__SC5_ADMIN_LOADED__ = true;
})();
