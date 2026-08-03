/* SquidC5 ops console - app-shell views (loaded after auth) */
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
  function shortId(id) { return (id || "").length > 14 ? id.slice(0, 12) + "..." : (id || ""); }
  function metaOf(s) {
    let m = s && s.metadata;
    if (typeof m === "string") { try { m = JSON.parse(m); } catch (_) { m = {}; } }
    return m || {};
  }
  function docHref(anchor) {
    return DOCS + (anchor ? "#" + anchor : "");
  }
  /** Per-page doc menus (single button in header - no spam links in body) */
  const PAGE_DOCS = {
    dashboard: [
      { a: "status-overview", t: "Status overview" },
      { a: "ops-console-layout", t: "Ops layout" },
      { a: "connection", t: "Connection" },
      { a: "sessions", t: "Sessions" },
    ],
    sessions: [
      { a: "sessions", t: "Sessions" },
      { a: "shell", t: "Shell interact" },
      { a: "tasks", t: "Tasks / beacons" },
      { a: "verified-reverse-shells", t: "Verified shells" },
    ],
    hosts: [
      { a: "sessions", t: "Sessions / hosts" },
      { a: "multi-operator-collab", t: "Session locks" },
    ],
    listeners: [
      { a: "listeners", t: "Listeners" },
      { a: "oast-collaborator", t: "OAST" },
      { a: "payloads-and-implants", t: "Payloads" },
    ],
    payloads: [
      { a: "payloads-and-implants", t: "Payloads & implants" },
      { a: "c2-profiles-profiles", t: "C2 profiles" },
      { a: "artifacts", t: "Artifacts" },
    ],
    profiles: [
      { a: "c2-profiles-profiles", t: "C2 profiles" },
      { a: "payloads-and-implants", t: "Payloads" },
      { a: "redirector-and-certificates", t: "Redirector" },
    ],
    artifacts: [
      { a: "artifacts", t: "Artifacts" },
      { a: "payloads-and-implants", t: "Payloads & implants" },
    ],
    postex: [
      { a: "post-ex", t: "Post-Ex" },
      { a: "sessions", t: "Sessions" },
    ],
    collab: [
      { a: "multi-operator-collab", t: "Multi-op collab" },
      { a: "policy", t: "Policy / HITL" },
      { a: "identity", t: "Identity" },
    ],
    ai: [
      { a: "inko-intelligent-neural-kinetic-operator", t: "INKO" },
      { a: "llm-connections", t: "LLM connections" },
      { a: "mcp-tools", t: "MCP tools" },
    ],
    observe: [
      { a: "observability", t: "Observability" },
      { a: "timeline-and-reports", t: "Timeline & reports" },
      { a: "event-stream", t: "Event stream" },
    ],
    admin: [
      { a: "tokens", t: "Tokens" },
      { a: "llm-connections", t: "LLM connections" },
      { a: "tls-certificate-library", t: "TLS certificates" },
      { a: "feature-toggles", t: "Feature toggles" },
      { a: "policy", t: "Policy" },
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

  /** OpenAI-compatible providers (chat/completions + /models) */
  const LLM_PROVIDERS = [
    { id: "xai", label: "xAI (Grok)", base: "https://api.x.ai/v1", model: "grok-3", needKey: true, keyUrl: "https://console.x.ai/" },
    { id: "openai", label: "OpenAI", base: "https://api.openai.com/v1", model: "gpt-4o-mini", needKey: true, keyUrl: "https://platform.openai.com/api-keys" },
    { id: "groq", label: "Groq", base: "https://api.groq.com/openai/v1", model: "llama-3.3-70b-versatile", needKey: true, keyUrl: "https://console.groq.com/keys" },
    { id: "openrouter", label: "OpenRouter", base: "https://openrouter.ai/api/v1", model: "openai/gpt-4o-mini", needKey: true, keyUrl: "https://openrouter.ai/keys" },
    { id: "together", label: "Together AI", base: "https://api.together.xyz/v1", model: "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", needKey: true, keyUrl: "https://api.together.xyz/settings/api-keys" },
    { id: "deepseek", label: "DeepSeek", base: "https://api.deepseek.com/v1", model: "deepseek-chat", needKey: true, keyUrl: "https://platform.deepseek.com/api_keys" },
    { id: "mistral", label: "Mistral", base: "https://api.mistral.ai/v1", model: "mistral-small-latest", needKey: true, keyUrl: "https://console.mistral.ai/api-keys/" },
    { id: "fireworks", label: "Fireworks", base: "https://api.fireworks.ai/inference/v1", model: "accounts/fireworks/models/llama-v3p1-8b-instruct", needKey: true, keyUrl: "https://fireworks.ai/account/api-keys" },
    { id: "perplexity", label: "Perplexity", base: "https://api.perplexity.ai", model: "sonar", needKey: true, keyUrl: "https://www.perplexity.ai/settings/api" },
    { id: "gemini", label: "Google Gemini (OpenAI compat)", base: "https://generativelanguage.googleapis.com/v1beta/openai", model: "gemini-2.0-flash", needKey: true, keyUrl: "https://aistudio.google.com/apikey" },
    { id: "ollama", label: "Ollama (localhost)", base: "http://127.0.0.1:11434/v1", model: "llama3.2", needKey: false, keyUrl: "" },
    { id: "lmstudio", label: "LM Studio (localhost)", base: "http://127.0.0.1:1234/v1", model: "local-model", needKey: false, keyUrl: "" },
    { id: "custom", label: "Custom OpenAI-compatible", base: "", model: "", needKey: true, keyUrl: "" },
  ];
  const LLM_PROVIDER_MAP = Object.fromEntries(LLM_PROVIDERS.map((p) => [p.id, p]));

  function llmFormHtml(prefix) {
    const canSave = can("llm:manage") || can("admin");
    const opts = LLM_PROVIDERS.map((p) =>
      `<option value="${esc(p.id)}">${esc(p.label)}</option>`
    ).join("");
    return `
      <p class="muted" style="font-size:0.78rem;margin:0 0 10px">
        OpenAI-compatible providers. Keys encrypted at rest and never returned by the API.
        Paste a key to load live models from the provider.
      </p>
      <div class="form-grid llm-form-grid">
        <div><label>Connection name</label><input id="${prefix}Name" placeholder="grok-prod" /></div>
        <div><label>Provider</label>
          <select id="${prefix}Provider">${opts}</select>
        </div>
        <div class="full"><label>Base URL</label>
          <input id="${prefix}Base" placeholder="https://api.x.ai/v1" value="https://api.x.ai/v1" />
        </div>
        <div class="full"><label>API key</label>
          <input id="${prefix}Key" type="password" placeholder="xai-... / sk-... (never shown again)" autocomplete="off" />
          <div class="row" style="margin-top:6px">
            <button type="button" id="${prefix}KeyLink" title="Open provider API keys page">Get API key -></button>
          </div>
        </div>
        <div class="full" id="${prefix}ModelWrap">
          <label>Model</label>
          <select id="${prefix}ModelSel" disabled>
            <option value="">Paste API key to load models...</option>
          </select>
          <input id="${prefix}Model" class="hidden" placeholder="custom-model-id" />
          <label class="chk-inline" style="margin-top:8px;text-transform:none;letter-spacing:0;font-size:0.78rem;color:var(--text);font-weight:500">
            <input type="checkbox" id="${prefix}ModelOverride" /> Override - type model name manually
          </label>
          <div class="row" style="margin-top:6px">
            <button type="button" id="${prefix}FetchModels" disabled>Refresh models</button>
            <span class="muted" id="${prefix}ModelHint" style="font-size:0.72rem"></span>
          </div>
        </div>
      </div>
      <div class="row">
        <button type="button" class="primary" id="${prefix}Save" ${canSave ? "" : "disabled"}>Save LLM</button>
        <button type="button" id="${prefix}List">List saved</button>
      </div>
      <div class="outbox empty" id="${prefix}Out">-</div>`;
  }
  function bindLlmForm(prefix) {
    const applyProvider = () => {
      const id = el(prefix + "Provider")?.value || "xai";
      const p = LLM_PROVIDER_MAP[id] || LLM_PROVIDER_MAP.custom;
      if (p.base) el(prefix + "Base").value = p.base;
      if (p.model && !el(prefix + "ModelOverride")?.checked) {
        const sel = el(prefix + "ModelSel");
        const custom = el(prefix + "Model");
        if (sel && !sel.disabled && [...sel.options].some((o) => o.value === p.model)) {
          sel.value = p.model;
        } else if (custom) {
          custom.value = p.model;
        } else if (sel) {
          // seed single default option until fetch
          sel.innerHTML = `<option value="${esc(p.model)}">${esc(p.model)}</option>`;
          sel.value = p.model;
        }
      }
      updateModelUi();
    };
    const updateModelUi = () => {
      const override = !!(el(prefix + "ModelOverride") && el(prefix + "ModelOverride").checked);
      const sel = el(prefix + "ModelSel");
      const inp = el(prefix + "Model");
      const key = (el(prefix + "Key")?.value || "").trim();
      const prov = el(prefix + "Provider")?.value || "";
      const needKey = (LLM_PROVIDER_MAP[prov] || {}).needKey !== false;
      const canFetch = !needKey || key.length > 0;
      if (sel) {
        sel.classList.toggle("hidden", override);
        sel.disabled = override || (!canFetch && sel.options.length <= 1 && !sel.value);
      }
      if (inp) {
        inp.classList.toggle("hidden", !override);
        if (override && sel && sel.value && !inp.value) inp.value = sel.value;
      }
      if (el(prefix + "FetchModels")) el(prefix + "FetchModels").disabled = !canFetch;
    };
    const currentModel = () => {
      if (el(prefix + "ModelOverride")?.checked) return (el(prefix + "Model")?.value || "").trim();
      return (el(prefix + "ModelSel")?.value || el(prefix + "Model")?.value || "").trim();
    };
    const fetchModels = async () => {
      const hint = el(prefix + "ModelHint");
      const sel = el(prefix + "ModelSel");
      try {
        if (hint) hint.textContent = "Loading models...";
        const body = {
          base_url: (el(prefix + "Base")?.value || "").trim() || null,
          api_key: (el(prefix + "Key")?.value || "").trim() || null,
          provider: el(prefix + "Provider")?.value || null,
        };
        const r = await api("POST", "/api/v1/llm/models", body);
        const models = r.models || [];
        if (!sel) return;
        const prev = currentModel();
        if (!models.length) {
          sel.innerHTML = `<option value="">(no models returned)</option>`;
          sel.disabled = true;
          if (hint) hint.textContent = "No models - use override";
          return;
        }
        sel.innerHTML = models.map((m) =>
          `<option value="${esc(m)}">${esc(m)}</option>`
        ).join("");
        sel.disabled = false;
        if (prev && models.includes(prev)) sel.value = prev;
        else {
          const def = (LLM_PROVIDER_MAP[el(prefix + "Provider")?.value] || {}).model;
          if (def && models.includes(def)) sel.value = def;
        }
        if (hint) hint.textContent = models.length + " model(s)";
        updateModelUi();
      } catch (e) {
        if (hint) hint.textContent = "Fetch failed - use override";
        showError(String(e.message || e));
        // enable override path
        if (el(prefix + "ModelOverride")) {
          el(prefix + "ModelOverride").checked = true;
          updateModelUi();
          const p = LLM_PROVIDER_MAP[el(prefix + "Provider")?.value] || {};
          if (el(prefix + "Model") && !el(prefix + "Model").value) el(prefix + "Model").value = p.model || "";
        }
      }
    };
    if (el(prefix + "Provider")) {
      el(prefix + "Provider").onchange = () => {
        applyProvider();
        const key = (el(prefix + "Key")?.value || "").trim();
        const prov = el(prefix + "Provider").value;
        if (key || (LLM_PROVIDER_MAP[prov] || {}).needKey === false) fetchModels();
      };
    }
    if (el(prefix + "KeyLink")) {
      const go = () => {
        const id = el(prefix + "Provider")?.value || "";
        const u = (LLM_PROVIDER_MAP[id] || {}).keyUrl;
        if (!u) return showError("No key page for this provider - use their console");
        window.open(u, "_blank", "noopener,noreferrer");
      };
      el(prefix + "KeyLink").onclick = go;
    }
    if (el(prefix + "Key")) {
      let t = null;
      el(prefix + "Key").oninput = () => {
        updateModelUi();
        clearTimeout(t);
        t = setTimeout(() => {
          const key = (el(prefix + "Key")?.value || "").trim();
          if (key.length >= 8) fetchModels();
        }, 600);
      };
    }
    if (el(prefix + "ModelOverride")) el(prefix + "ModelOverride").onchange = updateModelUi;
    if (el(prefix + "FetchModels")) el(prefix + "FetchModels").onclick = () => fetchModels();
    if (el(prefix + "Save")) el(prefix + "Save").onclick = async () => {
      try {
        const name = (el(prefix + "Name").value || "").trim();
        const model = currentModel();
        const base_url = (el(prefix + "Base").value || "").trim();
        const api_key = (el(prefix + "Key").value || "").trim();
        const provider = el(prefix + "Provider").value || "openai";
        const needKey = (LLM_PROVIDER_MAP[provider] || {}).needKey !== false;
        if (!name || !model) return showError("Name and model required");
        if (!api_key && needKey) return showError("API key required for this provider");
        if (!base_url) return showError("Base URL required");
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
        updateModelUi();
        showOk("LLM saved (key encrypted at rest)");
        if (window.__SC5_refreshLlms) window.__SC5_refreshLlms();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el(prefix + "List")) el(prefix + "List").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/llm");
        el(prefix + "Out").textContent = JSON.stringify(r, null, 2);
        el(prefix + "Out").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    // defaults
    if (el(prefix + "Provider") && !el(prefix + "Provider").dataset.bound) {
      el(prefix + "Provider").value = "xai";
      applyProvider();
      el(prefix + "Provider").dataset.bound = "1";
    }
    updateModelUi();
  }


  async function loadModelsForLlm(llmId, modelSelectId, preferred) {
    const sel = el(modelSelectId);
    if (!sel) return;
    if (!llmId) {
      sel.innerHTML = '<option value="">Select a connection first</option>';
      sel.disabled = true;
      return;
    }
    sel.disabled = true;
    sel.innerHTML = '<option value="">Loading models...</option>';
    try {
      const r = await api("POST", "/api/v1/llm/models", { llm_id: llmId });
      const models = r.models || [];
      const pref = preferred || "";
      if (!models.length) {
        sel.innerHTML = pref
          ? `<option value="${esc(pref)}">${esc(pref)}</option>`
          : '<option value="">(no models - type via override in Admin)</option>';
        sel.disabled = !pref;
        if (pref) sel.value = pref;
        return;
      }
      const set = new Set(models);
      if (pref) set.add(pref);
      const list = Array.from(set).sort((a, b) => a.localeCompare(b));
      sel.innerHTML = list.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
      sel.disabled = false;
      sel.value = pref && list.includes(pref) ? pref : list[0];
    } catch (e) {
      const pref = preferred || "";
      sel.innerHTML = pref
        ? `<option value="${esc(pref)}">${esc(pref)} (offline)</option>`
        : `<option value="">Model list failed</option>`;
      sel.disabled = !pref;
      if (pref) sel.value = pref;
    }
  }

  function bindLlmModelPair(connId, modelId) {
    const conn = el(connId);
    const mod = el(modelId);
    if (!conn || !mod) return;
    const sync = async () => {
      const id = conn.value || "";
      saveSel("sc5_ops_llm", id || "");
      let pref = "";
      try {
        const llms = await loadSavedLlms();
        const row = (llms || []).find((L) => (L.id || L.name) === id);
        pref = (row && row.model) || loadSel("sc5_ops_model") || "";
      } catch (_) { pref = loadSel("sc5_ops_model") || ""; }
      await loadModelsForLlm(id, modelId, pref);
      if (mod.value) saveSel("sc5_ops_model", mod.value);
    };
    conn.onchange = () => { sync(); };
    mod.onchange = () => {
      if (mod.value) saveSel("sc5_ops_model", mod.value);
      // persist model on connection for next chat default
      const id = conn.value;
      if (id && mod.value) {
        api("PATCH", "/api/v1/llm/" + encodeURIComponent(id), { model: mod.value }).catch(() => {});
      }
    };
    sync();
  }

  async function loadSavedLlms() {
    try {
      return await api("GET", "/api/v1/llm") || [];
    } catch (_) {
      return [];
    }
  }
  function fillLlmSelect(sel, llms, selected) {
    if (!sel) return;
    const list = Array.isArray(llms) ? llms : [];
    if (!list.length) {
      sel.innerHTML = `<option value="">(no LLM configured - use Configure panel)</option>`;
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    sel.innerHTML = list.map((L) => {
      const id = L.id || L.name;
      const label = `${L.name || id}  /  ${L.model || "?"}  /  ${L.provider || "?"}`;
      return `<option value="${esc(id)}">${esc(label)}</option>`;
    }).join("");
    if (selected && list.some((L) => (L.id || L.name) === selected)) sel.value = selected;
  }

  /* -- Context rail -- */
  let ctxBoundSid = null;
  function bindCtxChrome() {
    if (el("ctxClose")) el("ctxClose").onclick = () => openCtxSheet(false);
    if (el("ctxBackdrop")) el("ctxBackdrop").onclick = () => openCtxSheet(false);
  }
  bindCtxChrome();

  function bindContextHandlers() {
    if (el("ctxClaim")) el("ctxClaim").onclick = async () => {
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/claim`, {});
        showOk("Lock claimed");
        if (el("ctxOut")) { el("ctxOut").textContent = JSON.stringify(r, null, 2); el("ctxOut").classList.remove("empty"); }
        if (window.__SC5_refresh) await window.__SC5_refresh();
        renderContext(true);
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxForceClaim")) el("ctxForceClaim").onclick = async () => {
      if (!confirm("Force-steal lock from current holder?")) return;
      try {
        const r = await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/claim`, { force: true });
        showOk("Force claimed");
        if (el("ctxOut")) { el("ctxOut").textContent = JSON.stringify(r, null, 2); el("ctxOut").classList.remove("empty"); }
        if (window.__SC5_refresh) await window.__SC5_refresh();
        renderContext(true);
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("ctxRelease")) el("ctxRelease").onclick = async () => {
      try {
        await api("POST", `/api/v1/sessions/${encodeURIComponent(selectedId)}/release`);
        showOk("Lock released");
        if (window.__SC5_refresh) await window.__SC5_refresh();
        renderContext(true);
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
    const claim = s.claim || {
      claimed_by: m.claimed_by,
      claim_expires_at: m.claim_expires_at,
      claim_remaining_sec: m.claim_remaining_sec,
      locked: !!m.claimed_by,
    };
    function claimChipHtml(c) {
      if (!c || !c.claimed_by) return '<span class="chip">unlocked</span>';
      let extra = "";
      if (c.claim_remaining_sec != null && c.claim_expires_at) {
        const mleft = Math.max(0, Math.ceil(Number(c.claim_remaining_sec) / 60));
        extra = " · " + mleft + "m left";
      } else if (c.claim_expires_at == null && c.claimed_by) {
        extra = " · no timeout";
      }
      return `<span class="chip warn">locked: ${esc(c.claimed_by)}${esc(extra)}</span>`;
    }
    // Soft update: keep form fields if same session already bound
    if (!force && ctxBoundSid === selectedId && el("ctxMeta")) {
      el("ctxMeta").innerHTML = `
        <div class="mono" style="font-size:0.7rem;color:var(--muted);margin-bottom:6px">${esc(s.id)}</div>
        <div style="font-weight:700;margin-bottom:4px">${esc(s.hostname || s.remote_addr || "session")}</div>
        <div class="chips" style="margin-bottom:10px">
          <span class="chip">${esc(s.kind || "?")}</span>
          <span class="chip ${s.verified ? "ok" : ""}">${s.verified ? "verified" : esc(s.status || "")}</span>
          ${claimChipHtml(claim)}
        </div>
        <div class="muted" style="font-size:0.78rem;margin-bottom:8px">
          User: ${esc(s.username || "-")}<br/>OS: ${esc(s.os_info || "-")}<br/>Addr: ${esc(s.remote_addr || "-")}
        </div>`;
      return;
    }
    const shellOk = can("shell:interact") && (s.kind === "reverse_shell" || s.interactive || s.verified);
    const canLock = can("shell:interact") || can("collab:use") || can("admin");
    body.innerHTML = `
      <div id="ctxMeta"></div>
      <div class="row">
        ${canLock ? '<button type="button" class="primary" id="ctxClaim">Claim lock</button>' : ""}
        ${canLock ? '<button type="button" class="ghost" id="ctxRelease">Release</button>' : ""}
        ${can("admin") ? '<button type="button" class="danger sm" id="ctxForceClaim">Force claim</button>' : ""}
        ${can("sessions:read") ? '<button type="button" class="ghost" id="ctxSpectate">Spectate</button>' : ""}
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
      <div class="outbox empty" id="ctxOut">-</div>
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
          ${claimChipHtml(claim)}
        </div>
        <div class="muted" style="font-size:0.78rem;margin-bottom:8px">
          User: ${esc(s.username || "-")}<br/>OS: ${esc(s.os_info || "-")}<br/>Addr: ${esc(s.remote_addr || "-")}
        </div>`;
    }
    bindContextHandlers();
  }

  function isMobileShell() {
    try { return window.matchMedia && window.matchMedia("(max-width: 900px)").matches; } catch (_) { return false; }
  }
  function openCtxSheet(open) {
    const rail = el("ctxRail");
    const bd = el("ctxBackdrop");
    if (!rail) return;
    if (!isMobileShell()) {
      rail.classList.remove("open");
      if (bd) bd.classList.add("hidden");
      return;
    }
    const show = open !== false && !!selectedId;
    rail.classList.toggle("open", show);
    if (bd) bd.classList.toggle("hidden", !show);
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
        box.textContent = "Select a session...";
        box.classList.add("empty");
      }
    }
    if (el("pxSid")) el("pxSid").textContent = selectedId || "(none - pick in Sessions)";
    renderContext();
    openCtxSheet(!!selectedId);
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
        <td class="mono">${esc(shortId(s.id))}${m.claimed_by ? " [locked]" : ""}</td>
        <td>${esc(s.kind || "")}</td>
        <td>${esc(s.hostname || s.remote_addr || "-")}</td>
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

  /* -- Sessions view -- */
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
            <div id="sesDetail" class="outbox empty" style="margin-top:12px">Select a session...</div>
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
            <p class="muted mono" id="tskHint" style="font-size:0.7rem;margin:4px 0 0">-</p>
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
    tools(`<button type="button" class="primary" id="toolNewShell">Context</button>`);
    if (el("toolNewShell")) el("toolNewShell").onclick = () => {
      if (!selectedId) return showError("Select a session first");
      renderContext(true);
      openCtxSheet(true);
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
            ? `Editing ${t.id} (${t.status})  /  session ${t.session_id}`
            : "-";
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

  /* -- Listeners -- */
  function fillListenerRows(tbody) {
    if (!tbody) return;
    const rows = cache.listeners || [];
    tbody.innerHTML = rows.map((l) => `<tr data-lid="${esc(l.id)}" class="${l.id === selectedListenerId ? "selected" : ""}">
      <td>${esc(l.name || shortId(l.id))}</td>
      <td class="mono">${esc(l.port)}</td>
      <td>${esc(l.kind)}</td>
      <td><span class="chip ${l.status === "running" ? "ok" : ""}">${esc(l.status || "-")}</span></td>
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
    if (el("lisIdHint")) el("lisIdHint").textContent = "Selected: " + (l.id || "") + "  /  " + (l.status || "");
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
                    <option value="https">https (TLS)</option>
                    <option value="tcp">tcp</option>
                    <option value="dns">dns</option>
                    <option value="smtp">smtp</option>
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
            <div class="outbox empty" id="lisOut">-</div>
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
      if (!name) throw new Error("Name required");
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be an integer 1-65535");
      const taken = (cache.listeners || []).find((L) => Number(L.port) === port && (L.host || "0.0.0.0") === "0.0.0.0");
      if (taken) throw new Error("Port " + port + " already used by " + (taken.name || taken.id));
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

  /* -- Payloads -- */
  function renderPayloadsView(force) {
    const root = el("view-payloads");
    if (!root) return;
    if (!force && viewBuilt.payloads && root.querySelector("#payTpl")) return;
    const host = (() => { try { return location.hostname || "127.0.0.1"; } catch (_) { return "127.0.0.1"; } })();
    root.innerHTML = `
      <div class="work-panel" style="min-height:360px">
        <div class="wp-head">Generate</div>
        <div class="wp-body">
          ${can("payloads:generate") ? `
            <div class="form-grid">
              <div class="full"><label>Template</label>
                <select id="payTpl"><option value="">Loading...</option></select>
              </div>
              <div class="full"><label>C2 profile (optional)</label>
                <select id="payProfile"><option value="">(active profile)</option></select>
              </div>
              <div><label>Host</label><input id="payHost" value="${esc(host)}" /></div>
              <div><label>Port</label><input id="payPort" type="number" value="${location.port || 8443}" /></div>
              <div><label>Interval</label><input id="payInterval" type="number" value="5" /></div>
              <div><label>Scheme</label>
                <select id="payScheme"><option value="">auto</option><option value="https">https</option><option value="http">http</option></select>
              </div>
            </div>
            <div class="row">
              <button type="button" class="primary" id="payGen">Generate</button>
              <button type="button" id="payCopy">Copy</button>
              <button type="button" id="paySave">Save artifact</button>
            </div>
            <details style="margin-top:12px">
              <summary class="muted" style="cursor:pointer;font-size:0.78rem">Register custom template</summary>
              <label>Name</label><input id="payTplName" placeholder="my_custom_beacon" />
              <label>Body (use {host} {port} {path} {interval})</label>
              <textarea id="payTplBody" rows="5" class="mono" style="font-size:0.75rem" placeholder="connect {host}:{port}"></textarea>
              <div class="row"><button type="button" id="payTplReg">Register template</button></div>
            </details>
          ` : '<p class="muted">Need payloads:generate scope</p>'}
          <div class="outbox empty" id="payOut">-</div>
        </div>
      </div>
    `;
    viewBuilt.payloads = true;
    (async () => {
      try {
        const [tpl, prof] = await Promise.all([
          api("GET", "/api/v1/payloads/templates").catch(() => ({ templates: [] })),
          can("profiles:read") || can("admin")
            ? api("GET", "/api/v1/profiles").catch(() => ({ profiles: [] }))
            : Promise.resolve({ profiles: [] }),
        ]);
        const names = tpl.templates || [];
        if (el("payTpl")) {
          el("payTpl").innerHTML = names.map((n) => {
            const custom = (tpl.custom || []).includes(n);
            return `<option value="${esc(n)}">${esc(n)}${custom ? " (custom)" : ""}</option>`;
          }).join("") || '<option value="">(none)</option>';
        }
        if (el("payProfile")) {
          const rows = prof.profiles || [];
          const act = prof.active_id || "";
          el("payProfile").innerHTML = `<option value="">(active${act ? ": " + esc(act) : ""})</option>` +
            rows.map((p) => `<option value="${esc(p.id)}">${esc(p.name || p.id)}${p.id === act ? " *" : ""}</option>`).join("");
        }
      } catch (e) { /* ignore */ }
    })();
    if (el("payGen")) el("payGen").onclick = async () => {
      try {
        const body = {
          template: el("payTpl").value,
          host: el("payHost").value.trim(),
          port: Number(el("payPort").value),
          interval: Number(el("payInterval")?.value || 5),
        };
        if (el("payProfile")?.value) body.profile_id = el("payProfile").value;
        if (el("payScheme")?.value) body.scheme = el("payScheme").value;
        const r = await api("POST", "/api/v1/payloads/generate", body);
        const text = r.content || r.payload || JSON.stringify(r, null, 2);
        el("payOut").textContent = text;
        el("payOut").classList.remove("empty");
        el("payOut").dataset.raw = text;
        showOk("Generated");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("payCopy")) el("payCopy").onclick = async () => {
      const text = el("payOut")?.dataset?.raw || el("payOut")?.textContent || "";
      try { await navigator.clipboard.writeText(text); showOk("Copied"); }
      catch (_) { showError("Clipboard unavailable"); }
    };
    if (el("paySave")) el("paySave").onclick = async () => {
      try {
        const text = el("payOut")?.dataset?.raw || el("payOut")?.textContent || "";
        if (!text || text === "-") return showError("Generate first");
        const name = (el("payTpl").value || "payload") + "-" + Date.now().toString(36);
        await api("POST", "/api/v1/assets", {
          kind: "payload",
          name,
          content: text,
          meta: { template: el("payTpl").value, host: el("payHost").value, port: el("payPort").value },
        });
        showOk("Saved to Artifacts");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("payTplReg")) el("payTplReg").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/payloads/templates", {
          name: (el("payTplName").value || "").trim(),
          content: el("payTplBody").value || "",
        });
        showOk("Template registered: " + (r.name || ""));
        viewBuilt.payloads = false;
        renderPayloadsView(true);
      } catch (e) { showError(String(e.message || e)); }
    };
  }

  /* -- Post-ex -- */
  function renderPostexView(force) {
    const root = el("view-postex");
    if (!root) return;
    if (!force && viewBuilt.postex && root.children.length) return;
    root.innerHTML = `
      <p class="muted" style="margin:0 0 10px;font-size:0.85rem">
        Target session: <strong class="mono" id="pxSid">${esc(selectedId || "(none - pick in Sessions)")}</strong>
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
            <div class="outbox empty" id="pxOut">-</div>
          </div>
        </div>
      </div>
    `;
    viewBuilt.postex = true;
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

  /* -- Collab -- */
  function renderCollabView(force) {
    const root = el("view-collab");
    if (!root) return;
    if (!force && viewBuilt.collab && root.children.length) return;
    root.innerHTML = `
      <div class="form-grid">
        <div class="work-panel">
          <div class="wp-head">Chat</div>
          <div class="wp-body">
            <label>Team channel (optional id)</label>
            <input id="chTeam" placeholder="leave empty for global" />
            <label>Message</label>
            <input id="chMsg" placeholder="status update..." />
            <div class="row">
              <button type="button" class="primary" id="chSend" ${can("collab:use") || can("admin") ? "" : "disabled"}>Send</button>
              <button type="button" id="chReload">Reload</button>
            </div>
            <div class="outbox empty" id="chOut">-</div>
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
            <div class="outbox empty" id="tmOut">-</div>
          </div>
        </div>
      </div>
    `;
    viewBuilt.collab = true;
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

  /* -- Observe -- */
  function renderObserveView(force) {
    const root = el("view-observe");
    if (!root) return;
    if (!force && viewBuilt.observe && root.children.length) return;
    root.innerHTML = `
      <div class="toolbar">
        <button type="button" class="primary" id="obMetrics">Metrics</button>
        <button type="button" id="obAudit">My audit</button>
        <button type="button" id="obTimeline">Timeline</button>
        <button type="button" id="obReport">Report</button>
        <button type="button" id="obAnom">Anomalies</button>
      </div>
      <div class="outbox empty" id="obOut" style="max-height:480px">-</div>
    `;
    viewBuilt.observe = true;
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

  /* -- Admin -- */
  /* -- AI / INKO tab -- */
  const AI_HIST_KEY = "sc5_inko_chat_v1";
  const AI_HIST_MAX = 40;
  let aiBusy = false;

  function loadAiHistory() {
    try {
      const raw = localStorage.getItem(AI_HIST_KEY);
      if (!raw) return [];
      const arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return [];
      return arr
        .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
        .slice(-AI_HIST_MAX);
    } catch (_) {
      return [];
    }
  }

  function persistAiHistory() {
    try {
      localStorage.setItem(AI_HIST_KEY, JSON.stringify(aiChatHistory.slice(-AI_HIST_MAX)));
    } catch (_) {}
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /** Minimal safe markdown -> HTML (escape first; no raw HTML passthrough). */
  function renderMarkdownSafe(src) {
    let s = String(src ?? "").replace(/\r\n/g, "\n");
    const fences = [];
    const tables = [];
    s = s.replace(/```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g, (_, lang, code) => {
      const i = fences.length;
      fences.push(
        `<pre><code${lang ? ` class="language-${escapeHtml(lang)}"` : ""}>${escapeHtml(code.replace(/\n$/, ""))}</code></pre>`
      );
      return `\u0000FENCE${i}\u0000`;
    });
    // GFM tables on raw text - escape each cell at HTML build time (XSS-safe)
    s = s.replace(/(?:^[ \t]*\|.+\|[ \t]*\n){2,}/gm, (block) => {
      const lines = block.trim().split("\n").map((l) => l.trim()).filter(Boolean);
      if (lines.length < 2) return block;
      const splitRow = (line) => {
        let t = line.trim();
        if (t.startsWith("|")) t = t.slice(1);
        if (t.endsWith("|")) t = t.slice(0, -1);
        return t.split("|").map((c) => c.trim());
      };
      const isSep = (line) => {
        const cells = splitRow(line);
        return cells.length > 0 && cells.every((c) => /^:?-{1,}:?$/.test(c));
      };
      const header = splitRow(lines[0]);
      let bodyStart = 1;
      if (isSep(lines[1])) bodyStart = 2;
      else if (isSep(lines[0])) return block;
      const rows = lines.slice(bodyStart).filter((l) => !isSep(l)).map(splitRow);
      if (!header.length || !rows.length) return block;
      const coln = header.length;
      const norm = (row) => {
        const r = row.slice(0, coln);
        while (r.length < coln) r.push("");
        return r;
      };
      // Inline md in cells (bold/code only) after escape
      const cellHtml = (raw) => {
        let c = escapeHtml(raw);
        c = c.replace(/`([^`\n]+)`/g, "<code>$1</code>");
        c = c.replace(/(\*\*|__)(?=\S)([\s\S]*?\S)\1/g, "<strong>$2</strong>");
        return c;
      };
      const th = norm(header).map((c) => `<th>${cellHtml(c)}</th>`).join("");
      const trs = rows.map((r) => `<tr>${norm(r).map((c) => `<td>${cellHtml(c)}</td>`).join("")}</tr>`).join("");
      const i = tables.length;
      tables.push(`<div class="md-table-wrap"><table class="md-table"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table></div>`);
      return `\u0000TABLE${i}\u0000\n\n`;
    });
    // Lists from raw text with per-item escapeHtml (greedy + -> one <ol>/<ul>).
    // Non-greedy +? previously made each line its own <ol> (displayed 1. 1. 1.).
    const lists = [];
    const stashList = (html) => {
      const i = lists.length;
      lists.push(html);
      return `\u0000LIST${i}\u0000\n\n`;
    };
    s = s.replace(/(?:^(?:[-*+])\s+.+(?:\n|$))+/gm, (block) => {
      const items = block
        .trim()
        .split("\n")
        .map((line) => line.replace(/^[-*+]\s+/, "").trim())
        .filter(Boolean)
        .map((t) => `<li>${escapeHtml(t)}</li>`);
      return stashList(`<ul>${items.join("")}</ul>`);
    });
    s = s.replace(/(?:^\d+\.\s+.+(?:\n|$))+/gm, (block) => {
      const items = block
        .trim()
        .split("\n")
        .map((line) => line.replace(/^\d+\.\s+/, "").trim())
        .filter(Boolean)
        .map((t) => `<li>${escapeHtml(t)}</li>`);
      return stashList(`<ol>${items.join("")}</ol>`);
    });
    // Escape remaining prose; list/table/fence bodies restored after.
    s = escapeHtml(s);
    // Inline / block markdown on escaped text only (allow-listed tags)
    s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    s = s.replace(/^(#{1,4})\s+(.+)$/gm, (_, h, t) => `<h${h.length}>${t}</h${h.length}>`);
    s = s.replace(/(\*\*|__)(?=\S)([\s\S]*?\S)\1/g, "<strong>$2</strong>");
    s = s.replace(/(\*|_)(?=\S)([\s\S]*?\S)\1/g, "<em>$2</em>");
    s = s.replace(/^&gt;\s?(.+)$/gm, "<blockquote>$1</blockquote>");
    s = s
      .split(/\n{2,}/)
      .map((para) => {
        const t = para.trim();
        if (!t) return "";
        if (/^<(?:ul|ol|pre|h[1-4]|blockquote|div)/.test(t)) return t;
        if (/^\u0000(?:TABLE|LIST)\d+\u0000$/.test(t)) return t;
        return `<p>${para.replace(/\n/g, "<br>")}</p>`;
      })
      .join("");
    s = s.replace(/\u0000LIST(\d+)\u0000/g, (_, i) => lists[Number(i)] || "");
    s = s.replace(/\u0000TABLE(\d+)\u0000/g, (_, i) => tables[Number(i)] || "");
    s = s.replace(/\u0000FENCE(\d+)\u0000/g, (_, i) => fences[Number(i)] || "");
    // Bold/em inside list items (restored after escape)
    s = s.replace(/(\*\*|__)(?=\S)([\s\S]*?\S)\1/g, "<strong>$2</strong>");
    s = s.replace(/(\*|_)(?=\S)([\s\S]*?\S)\1/g, "<em>$2</em>");
    s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    return s;
  }

  // Expose for light automated checks / console
  window.__SC5_renderMarkdownSafe = renderMarkdownSafe;

  let aiChatHistory = loadAiHistory();

  function setAiBusy(busy) {
    aiBusy = !!busy;
    document.body.classList.toggle("ai-busy", aiBusy);
    ["aiRun", "aiSendGlobal"].forEach((id) => {
      const n = el(id);
      if (!n) return;
      n.disabled = aiBusy;
      n.classList.toggle("ai-send-busy", aiBusy);
    });
  }

  function scrollAiChatLog() {
    const parent = el("aiChatLog");
    if (!parent) return;
    // Instant only - smooth + keyboard resize causes mobile jitter
    parent.scrollTop = parent.scrollHeight;
  }

  function showAiPending() {
    removeAiPending();
    const parent = el("aiChatLog");
    if (!parent) return null;
    const div = document.createElement("div");
    div.className = "ai-msg bot pending";
    div.dataset.aiPending = "1";
    div.innerHTML =
      '<div class="who">INKO</div><div class="ai-typing"><span class="ai-typing-dots" aria-hidden="true"><span></span><span></span><span></span></span><span>Thinking...</span></div>';
    parent.appendChild(div);
    scrollAiChatLog();
    return div;
  }

  function removeAiPending() {
    document.querySelectorAll('[data-ai-pending="1"]').forEach((n) => n.remove());
  }

  function appendAiChat(who, text, toolTrace) {
    const parent = el("aiChatLog");
    if (!parent) return;
    const div = document.createElement("div");
    div.className = "ai-msg " + (who === "user" ? "user" : "bot");
    const w = document.createElement("div");
    w.className = "who";
    w.textContent = who === "user" ? "You" : "INKO";
    const b = document.createElement("div");
    b.className = "body";
    if (who === "user") {
      b.style.whiteSpace = "pre-wrap";
      b.textContent = text;
    } else {
      b.innerHTML = renderMarkdownSafe(text);
    }
    div.appendChild(w);
    div.appendChild(b);
    if (toolTrace && toolTrace.length) {
      const row = document.createElement("div");
      row.className = "tools-used";
      toolTrace.forEach((t) => {
        const chip = document.createElement("span");
        chip.className = "tool-chip " + (t.ok ? "ok" : "bad");
        chip.textContent = (t.ok ? "ok: " : "err: ") + (t.tool || "?") + (t.summary ? "  /  " + t.summary : "");
        row.appendChild(chip);
      });
      div.appendChild(row);
    }
    if (who !== "user") {
      const actions = document.createElement("div");
      actions.className = "ai-msg-actions";
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "ai-copy-btn";
      copyBtn.textContent = "Copy";
      copyBtn.title = "Copy response to clipboard";
      copyBtn.onclick = async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(String(text || ""));
          copyBtn.textContent = "Copied";
          copyBtn.classList.add("copied");
          setTimeout(() => {
            copyBtn.textContent = "Copy";
            copyBtn.classList.remove("copied");
          }, 1600);
        } catch (_) {
          showError("Clipboard unavailable");
        }
      };
      actions.appendChild(copyBtn);
      div.appendChild(actions);
    }
    parent.appendChild(div);
    if (!parent.dataset.skipScroll) scrollAiChatLog();
  }

  function rebuildAiChatDom() {
    const log = el("aiChatLog");
    if (log) log.innerHTML = "";
    if (!aiChatHistory.length) {
      renderInkoStarters();
      return;
    }
    if (log) log.dataset.skipScroll = "1";
    try {
      aiChatHistory.forEach((m) => {
        const who = m.role === "user" ? "user" : "bot";
        appendAiChat(who, m.content, m.tools || null);
      });
    } finally {
      if (log) delete log.dataset.skipScroll;
    }
    scrollAiChatLog();
  }


  const INKO_STARTERS = [
    { t: "Sessions", q: "List my active sessions and summarize kind, host, and verified status." },
    { t: "Listeners", q: "List all listeners with port, kind, and running status." },
    { t: "Setup rev shell", q: "Setup a reverse shell listener on port 4444 and start it." },
    { t: "Events", q: "Show recent events from the live buffer." },
    { t: "Metrics", q: "Give me a quick metrics snapshot of this teamserver." },
    { t: "Payloads", q: "List payload templates I can generate." },
    { t: "Audit", q: "Show the latest audit log entries." },
    { t: "Save tip", q: "When you generate a payload, save it to the asset library with save=true so I can reuse it." },
  ];

  function renderInkoStarters() {
    const log = el("aiChatLog");
    if (!log) return;
    if (aiChatHistory.length) return;
    const wrap = document.createElement("div");
    wrap.className = "inko-starters";
    wrap.id = "inkoStarters";
    INKO_STARTERS.forEach((s) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "inko-starter";
      b.innerHTML = "<strong></strong><span></span>";
      b.querySelector("strong").textContent = s.t;
      b.querySelector("span").textContent = s.q;
      b.onclick = async () => {
        if (aiBusy) return;
        await runAiChat(s.q);
      };
      wrap.appendChild(b);
    });
    log.appendChild(wrap);
  }

  function clearAiChat() {
    if (aiBusy) return showError("Wait for INKO to finish");
    aiChatHistory = [];
    persistAiHistory();
    removeAiPending();
    if (el("aiChatLog")) el("aiChatLog").innerHTML = "";
    renderInkoStarters();
    showOk("New chat");
  }

  function takeInputValue(textareaId) {
    const node = el(textareaId);
    if (!node) return "";
    const v = node.value || "";
    node.value = "";
    return v;
  }

  async function runAiChat(message) {
    const text = (message || "").trim();
    if (!text) return;
    if (aiBusy) return showError("INKO is still responding");
    setAiBusy(true);
    appendAiChat("user", text);
    aiChatHistory.push({ role: "user", content: text });
    if (aiChatHistory.length > AI_HIST_MAX) aiChatHistory = aiChatHistory.slice(-AI_HIST_MAX);
    persistAiHistory();
    showAiPending();
    try {
      const body = {
        message: text,
        history: aiChatHistory.slice(0, -1),
      };
      const llm_id = selectedLlmId();
      if (llm_id) body.llm_id = llm_id;
      const model = selectedModel();
      if (model) body.model = model;
      const r = await api("POST", "/api/v1/ai/chat", body);
      const reply = (r && r.reply) || JSON.stringify(r, null, 2);
      const tools = (r && r.tool_trace) || [];
      removeAiPending();
      appendAiChat("bot", reply, tools);
      aiChatHistory.push({ role: "assistant", content: reply, tools: tools.length ? tools : undefined });
      if (aiChatHistory.length > AI_HIST_MAX) aiChatHistory = aiChatHistory.slice(-AI_HIST_MAX);
      persistAiHistory();
      if (tools.some((t) => t.ok && /listener|session|task|payload/i.test(t.tool || ""))) {
        if (window.__SC5_refresh) try { await window.__SC5_refresh(); } catch (_) {}
      }
      showOk(r.mode === "offline" ? "INKO (offline)" : "INKO replied");
      return r;
    } catch (e) {
      const err = String(e.message || e);
      showError(err);
      removeAiPending();
      appendAiChat("bot", "Error: " + err);
      aiChatHistory.push({ role: "assistant", content: "Error: " + err });
      persistAiHistory();
    } finally {
      setAiBusy(false);
    }
  }

  function renderAiView(force) {
    const root = el("view-ai");
    if (!root) return;
    if (!force && viewBuilt.ai && root.children.length) return;
    if (!can("ai:use") && !can("admin")) {
      root.innerHTML = `<div class="empty-state"><strong>INKO locked</strong>Need <code>ai:use</code> scope.</div>`;
      viewBuilt.ai = true;
      return;
    }
    const CAP_CARDS = [
      { t: "Sessions", d: "List / get beacons & reverse shells; triage live inventory." },
      { t: "Listeners", d: "Create, start, stop reverse_shell / http / dns / smtp acceptors." },
      { t: "Tasks", d: "Queue commands on beacons; inspect pending work." },
      { t: "Payloads", d: "List templates and generate implants for authorized targets." },
      { t: "Metrics & events", d: "Snapshot counters and recent live event buffer." },
      { t: "Audit", d: "Pull recent audit trail entries for the engagement." },
      { t: "Shell (HITL)", d: "Send to verified reverse shells when policy allows." },
      { t: "General ops Q&A", d: "Explain C5 concepts, ROE-safe guidance, and results." },
    ];
    root.innerHTML = `
      <div class="form-grid" style="align-items:stretch">
        <div class="work-panel">
          <div class="wp-head" style="flex-wrap:wrap;gap:6px">
            <span class="inko-brand">INKO</span>
            <span class="muted" style="margin-left:4px;font-size:0.75rem;font-weight:600;text-transform:none;letter-spacing:0">Intelligent Neural Kinetic Operator</span>
          </div>
          <div class="wp-body">
            <p class="muted" style="font-size:0.82rem;margin:0 0 10px;line-height:1.45">
              Chat lives in the top-bar <strong>INKO</strong> flyout - not on this page.
              Here you pick the default LLM, review what INKO can do, and inspect status / tool catalog.
              Configure providers under <strong>Admin</strong>.
            </p>
            <div class="row" style="margin-bottom:12px">
              <button type="button" class="primary" id="aiOpenDrawer">Open INKO chat</button>
              <button type="button" id="aiClearPage">Clear chat history</button>
            </div>
            <label>LLM connection</label>
            <select id="aiLlmPick"><option value="">Loading...</option></select>
            <label>Model</label>
            <select id="aiModelPick" disabled><option value="">Select connection...</option></select>
            <p class="muted" style="font-size:0.72rem;margin:4px 0 0">Models load from the provider for the selected connection. Switching model updates the connection default.</p>
            <h3 style="margin:16px 0 6px;font-size:0.85rem;color:var(--text)">What INKO can do</h3>
            <div class="inko-cap-grid">
              ${CAP_CARDS.map((c) => `
                <div class="inko-cap-card"><h4>${esc(c.t)}</h4><p>${esc(c.d)}</p></div>
              `).join("")}
            </div>
            <p class="muted" style="font-size:0.75rem;margin:8px 0 0">
              Example: <em>"setup reverse shell on 4444"</em>  /  <em>"list active sessions"</em>  /  <em>"show recent events"</em>
            </p>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Status &amp; tools</div>
          <div class="wp-body" style="display:flex;flex-direction:column;min-height:0;flex:1">
            <div class="row">
              <button type="button" class="primary" id="aiStatus">AI status</button>
              <button type="button" id="aiTools">Tool catalog</button>
            </div>
            <div class="outbox empty inko-outbox" id="aiOut">Run Status or Tools - output appears here (scrollable).</div>
          </div>
        </div>
      </div>
    `;
    const refreshPick = async () => {
      const llms = await loadSavedLlms();
      const prev = el("aiLlmPick")?.value || loadSel("sc5_ops_llm") || "";
      fillLlmSelect(el("aiLlmPick"), llms, prev);
      fillLlmSelect(el("aiLlmGlobal"), llms, prev);
      bindLlmModelPair("aiLlmPick", "aiModelPick");
      bindLlmModelPair("aiLlmGlobal", "aiModelGlobal");
    };
    window.__SC5_refreshLlms = refreshPick;
    refreshPick();
    if (el("aiClearPage")) el("aiClearPage").onclick = () => clearAiChat();
    if (el("aiStatus")) el("aiStatus").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/ai/status");
        el("aiOut").classList.remove("empty");
        el("aiOut").textContent = JSON.stringify(r, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("aiTools")) el("aiTools").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/ai/tools");
        el("aiOut").classList.remove("empty");
        const tools = (r && r.tools) || [];
        if (tools.length) {
          el("aiOut").textContent = tools.map((t) =>
            `${t.name}\n  ${t.description || ""}\n  scopes: ${(t.scopes || []).join(", ") || "-"}\n  policy: ${t.policy_action || "-"}`
          ).join("\n\n") + (r.note ? `\n\n-\n${r.note}` : "");
        } else {
          el("aiOut").textContent = JSON.stringify(r, null, 2);
        }
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("aiOpenDrawer")) el("aiOpenDrawer").onclick = () => openAiDrawer(true);
  }

  function selectedLlmId() {
    return (el("aiLlmPick") && el("aiLlmPick").value)
      || (el("aiLlmGlobal") && el("aiLlmGlobal").value)
      || loadSel("sc5_ops_llm")
      || null;
  }
  function selectedModel() {
    return (el("aiModelPick") && el("aiModelPick").value)
      || (el("aiModelGlobal") && el("aiModelGlobal").value)
      || loadSel("sc5_ops_model")
      || null;
  }

  function openAiDrawer(open) {
    const d = el("aiDrawer");
    const backdrop = el("aiBackdrop");
    const btn = el("btnInko");
    if (!d) return;
    let show;
    if (open === false) show = false;
    else if (open === true) show = true;
    else show = d.classList.contains("hidden") || !d.classList.contains("open");
    d.classList.toggle("hidden", !show);
    d.classList.toggle("open", show);
    d.setAttribute("aria-hidden", show ? "false" : "true");
    if (!show) {
      // Drop visualViewport pin so next open starts full-screen again
      d.classList.remove("kb-pinned");
      d.style.top = "";
      d.style.height = "";
      d.style.bottom = "";
    }
    if (backdrop) {
      backdrop.hidden = !show;
      backdrop.classList.toggle("show", show);
      backdrop.setAttribute("aria-hidden", show ? "false" : "true");
    }
    if (btn) btn.setAttribute("aria-expanded", show ? "true" : "false");
    if (show) {
      rebuildAiChatDom();
      const ta = el("aiPromptGlobal");
      if (ta) setTimeout(() => { try { ta.focus(); } catch (_) {} }, 50);
    }
  }

  function setupGlobalAi() {
    const btn = el("btnInko");
    const drawer = el("aiDrawer");
    const backdrop = el("aiBackdrop");
    if (!btn || !drawer) return;
    const allowed = can("ai:use") || can("admin");
    btn.classList.toggle("hidden", !allowed);
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", "aiDrawer");
    if (!allowed) {
      openAiDrawer(false);
      return;
    }
    if (!aiChatHistory.length) aiChatHistory = loadAiHistory();
    rebuildAiChatDom();
    loadSavedLlms().then((llms) => {
      fillLlmSelect(el("aiLlmGlobal"), llms, loadSel("sc5_ops_llm") || "");
      fillLlmSelect(el("aiLlmPick"), llms, loadSel("sc5_ops_llm") || "");
      bindLlmModelPair("aiLlmGlobal", "aiModelGlobal");
      bindLlmModelPair("aiLlmPick", "aiModelPick");
    });
    btn.onclick = () => openAiDrawer();
    if (el("aiDrawerClose")) el("aiDrawerClose").onclick = () => openAiDrawer(false);
    if (backdrop) backdrop.onclick = () => openAiDrawer(false);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && drawer.classList.contains("open")) openAiDrawer(false);
    });
    if (el("aiClearGlobal")) el("aiClearGlobal").onclick = () => clearAiChat();
    if (el("aiNewChat")) el("aiNewChat").onclick = () => clearAiChat();
    // Resize INKO drawer width
    (function bindInkoResize() {
      const handle = el("aiDrawerResize");
      const drawer = el("aiDrawer");
      if (!handle || !drawer || handle.dataset.bound) return;
      handle.dataset.bound = "1";
      try {
        const w = parseInt(localStorage.getItem("sc5_inko_w") || "", 10);
        if (w >= 320 && w <= Math.min(900, window.innerWidth)) {
          document.documentElement.style.setProperty("--inko-w", w + "px");
        }
      } catch (_) {}
      let active = false;
      const start = (e) => {
        if (window.matchMedia("(max-width: 900px)").matches) return;
        active = true;
        handle.classList.add("dragging");
        e.preventDefault();
        const move = (ev) => {
          if (!active) return;
          const pt = ev.touches ? ev.touches[0] : ev;
          const w = Math.max(320, Math.min(window.innerWidth - 80, window.innerWidth - pt.clientX));
          document.documentElement.style.setProperty("--inko-w", Math.round(w) + "px");
        };
        const end = () => {
          active = false;
          handle.classList.remove("dragging");
          window.removeEventListener("mousemove", move);
          window.removeEventListener("mouseup", end);
          window.removeEventListener("touchmove", move);
          window.removeEventListener("touchend", end);
          try {
            const cur = getComputedStyle(document.documentElement).getPropertyValue("--inko-w").trim();
            const n = parseInt(cur, 10);
            if (n) localStorage.setItem("sc5_inko_w", String(n));
          } catch (_) {}
        };
        window.addEventListener("mousemove", move);
        window.addEventListener("mouseup", end);
        window.addEventListener("touchmove", move, { passive: false });
        window.addEventListener("touchend", end);
      };
      handle.addEventListener("mousedown", start);
      handle.addEventListener("touchstart", start, { passive: false });
    })();

    const sendGlobal = async () => {
      if (aiBusy) return;
      const prompt = takeInputValue("aiPromptGlobal");
      if (!prompt.trim()) return showError("Enter a message");
      await runAiChat(prompt);
    };
    if (el("aiSendGlobal")) el("aiSendGlobal").onclick = sendGlobal;
    // Enter to send (Shift+Enter newline); input clears immediately via takeInputValue
    if (el("aiPromptGlobal")) {
      el("aiPromptGlobal").onkeydown = (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          if (!aiBusy) sendGlobal();
        }
      };
    }
  }

  function renderAdminView(force) {
    const root = el("view-admin");
    if (!root) return;
    if (!force && viewBuilt.admin && root.children.length) return;
    if (!can("admin") && !can("tokens:manage") && !can("policy:manage") && !can("llm:manage")) {
      root.innerHTML = '<div class="empty-state"><strong>Admin area</strong>Requires admin or manage scopes.</div>';
      return;
    }
    const meta = state.meta || {};
    const catalog = meta.scope_catalog || [];
    const presets = (meta.scope_presets || []).filter((p) => !p.admin_only || can("admin"));
    const privileged = new Set(meta.privileged_scopes || ["admin", "tokens:manage", "policy:manage", "llm:manage", "plugins:manage"]);
    const allScopes = catalog.length
      ? catalog.map((c) => c.id)
      : [
          "sessions:read", "sessions:write", "tasks:read", "tasks:write",
          "listeners:read", "listeners:write", "payloads:generate", "shell:interact",
          "metrics:read", "audit:read", "ai:use", "collab:use", "profiles:read", "profiles:write",
          "files:read", "files:write", "oast:read", "oast:write", "mcp:connect", "phone:operator",
          "tokens:manage", "llm:manage", "policy:manage", "plugins:manage", "admin",
        ];
    const descMap = {};
    catalog.forEach((c) => { descMap[c.id] = c.description || ""; });
    const defaultPreset = presets.find((p) => p.id === "full_operator")
      || presets.find((p) => p.id === "operator")
      || presets[0];
    const defaultScopes = new Set((defaultPreset && defaultPreset.scopes) || [
      "sessions:read", "sessions:write", "tasks:read", "tasks:write",
      "shell:interact", "listeners:read", "collab:use", "metrics:read",
    ]);
    const nonAdminScopes = (meta.non_admin_scopes || allScopes.filter((s) => !privileged.has(s)));
    const scopeLabel = (s) => {
      const d = descMap[s] || "";
      return d
        ? `<span class="mono" style="font-size:0.72rem">${esc(s)}</span><span class="muted" style="display:block;font-size:0.65rem;line-height:1.25;margin-top:2px;text-transform:none;letter-spacing:0;font-weight:400">${esc(d)}</span>`
        : `<span class="mono" style="font-size:0.72rem">${esc(s)}</span>`;
    };
    const presetBtns = presets.map((p) =>
      `<button type="button" class="ad-preset" data-preset="${esc(p.id)}" title="${esc(p.description || "")}">${esc(p.label || p.id)}</button>`
    ).join("") +
      `<button type="button" id="adScopeNone">Clear</button>` +
      `<button type="button" id="adScopeAll" title="Every non-privileged scope (never includes admin)">All non-admin</button>`;
    root.innerHTML = `
      <div class="admin-stack">
        <div class="admin-row">
          <div class="work-panel">
            <div class="wp-head">Tokens</div>
            <div class="wp-body">
              <p class="muted" style="font-size:0.75rem;margin:0 0 8px">Mint or edit scopes below. <strong>Link</strong> makes a one-time URL to send an existing operator (no secret shown). <strong>Roll</strong> rotates the secret now. Redeeming a link also rolls their secret once.</p>
              <div id="adSecretBanner" class="hidden" style="margin-bottom:12px;padding:12px;border-radius:10px;border:1px solid rgba(52,211,153,0.4);background:rgba(15,46,34,0.55)">
                <div class="row" style="margin:0 0 8px;justify-content:space-between;align-items:flex-start">
                  <div>
                    <strong id="adSecretTitle" style="color:var(--ok)">New token secret</strong>
                    <p class="muted" style="margin:4px 0 0;font-size:0.72rem">Shown until you dismiss. Copy the token and/or connection link.</p>
                  </div>
                  <button type="button" id="adSecretDismiss" title="Dismiss">Close</button>
                </div>
                <label style="margin-top:0">Token</label>
                <div class="row" style="margin:4px 0 8px;gap:6px;align-items:stretch">
                  <input id="adSecretToken" class="mono" readonly style="flex:1;font-size:0.75rem" />
                  <button type="button" id="adSecretCopyTok">Copy token</button>
                </div>
                <label>Connection link</label>
                <div class="row" style="margin:4px 0 0;gap:6px;align-items:stretch">
                  <input id="adSecretLink" class="mono" readonly style="flex:1;font-size:0.68rem" />
                  <button type="button" id="adSecretCopyLink">Copy link</button>
                </div>
                <p class="muted" id="adSecretMeta" style="margin:8px 0 0;font-size:0.68rem"></p>
              </div>
              <label>Name</label><input id="adName" placeholder="operator-1" />
              <input type="hidden" id="adEditId" value="" />
              <label>Presets</label>
              <div class="row" style="margin:4px 0;gap:6px" id="adPresetRow">${presetBtns}</div>
              <p class="muted" id="adPresetDesc" style="font-size:0.72rem;margin:4px 0 8px;min-height:2.2em">${esc((defaultPreset && defaultPreset.description) || "Pick a preset or tick scopes manually.")}</p>
              <label>Scopes</label>
              <div class="scope-grid" id="adScopeGrid" style="max-height:320px">
                ${allScopes.map((s) => {
                  const priv = privileged.has(s);
                  const dis = priv && !can("admin");
                  return `<label style="align-items:flex-start">
                    <input type="checkbox" class="ad-scope" value="${esc(s)}"
                      ${defaultScopes.has(s) ? "checked" : ""}
                      ${dis ? "disabled" : ""} style="margin-top:3px" />
                    <span>${scopeLabel(s)}</span>
                  </label>`;
                }).join("")}
              </div>
              <label class="chk-inline" style="margin-top:10px">
                <input type="checkbox" id="adMcpShow" /> Show MCP tool allow-list (when mcp:connect)
              </label>
              <div id="adMcpBox" class="hidden" style="margin-top:8px">
                <label>MCP tools</label>
                <div class="scope-grid" id="adMcpGrid" style="max-height:140px">
                  ${(meta.all_mcp_tools || []).map((t) =>
                    `<label><input type="checkbox" class="ad-mcp" value="${esc(t)}" /> <span class="mono" style="font-size:0.72rem">${esc(t)}</span></label>`
                  ).join("") || '<span class="muted">No MCP catalog</span>'}
                </div>
              </div>
              <div class="row" style="margin-top:10px">
                <button type="button" class="primary" id="adMint">Mint new</button>
                <button type="button" id="adSaveEdit" disabled>Save changes</button>
                <button type="button" id="adCancelEdit" class="hidden">Cancel edit</button>
              </div>
              <div class="row" style="margin-top:12px">
                <button type="button" id="adTokRefresh">Refresh list</button>
              </div>
              <div id="adTokTable" style="margin-top:8px;overflow:auto;max-height:280px"></div>
            </div>
          </div>
          <div class="work-panel">
            <div class="wp-head">Policy / features</div>
            <div class="wp-body">
              <div class="row">
                <button type="button" id="adPolGet">Get policy</button>
                <button type="button" id="adFeat">Features</button>
              </div>
              <div class="outbox empty" id="adOut" style="max-height:min(420px,50vh);flex:1">-</div>
            </div>
          </div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Your actor name</div>
          <div class="wp-body">
            <p class="muted" style="font-size:0.78rem;margin:0 0 8px">Shown in collab, audit, and the ops chrome. Renames this API token.</p>
            <label>Actor / display name</label>
            <input id="adActorName" placeholder="operator-1" value="${esc(state.actor || "")}" />
            <div class="row"><button type="button" class="primary" id="adActorSave">Save name</button></div>
          </div>
        </div>
        ${can("admin") ? `
        <div class="work-panel">
          <div class="wp-head">TLS certificates</div>
          <div class="wp-body">
            <p class="muted" style="font-size:0.78rem;margin:0 0 8px">Upload PEM fullchain + private key. Activate copies to server TLS material (restart required).</p>
            <label>Label</label><input id="tlsLabel" placeholder="letsencrypt-prod" />
            <label>Certificate PEM (fullchain)</label>
            <textarea id="tlsCert" rows="4" placeholder="-----BEGIN CERTIFICATE-----" class="mono" style="font-size:0.72rem"></textarea>
            <label>Private key PEM</label>
            <textarea id="tlsKey" rows="4" placeholder="-----BEGIN PRIVATE KEY-----" class="mono" style="font-size:0.72rem"></textarea>
            <div class="row">
              <button type="button" class="primary" id="tlsUpload">Upload</button>
              <button type="button" id="tlsRefresh">Refresh list</button>
            </div>
            <div class="outbox empty" id="tlsOut" style="max-height:240px">-</div>
          </div>
        </div>` : ""}
        ${(can("llm:manage") || can("admin")) ? `
        <div class="work-panel admin-llm">
          <div class="wp-head">Configure LLM (BYO)</div>
          <div class="wp-body">${llmFormHtml("adLlm")}</div>
        </div>` : ""}
        ${(can("payloads:generate") || can("admin")) ? `
        <div class="work-panel">
          <div class="wp-head">Saved assets (INKO / payloads)</div>
          <div class="wp-body">
            <div class="row"><button type="button" id="astRefresh">List assets</button></div>
            <div class="outbox empty" id="astOut" style="max-height:280px">-</div>
          </div>
        </div>` : ""}
      </div>
    `;
    viewBuilt.admin = true;
    if (can("llm:manage") || can("admin")) {
      bindLlmForm("adLlm");
      window.__SC5_refreshLlms = async () => {
        const llms = await loadSavedLlms();
        fillLlmSelect(el("aiLlmGlobal"), llms, loadSel("sc5_ops_llm") || "");
        fillLlmSelect(el("aiLlmPick"), llms, loadSel("sc5_ops_llm") || "");
      };
    }
    if (el("adActorSave")) el("adActorSave").onclick = async () => {
      try {
        const name = (el("adActorName").value || "").trim();
        if (!name) return showError("Name required");
        const r = await api("PUT", "/api/v1/me", { name });
        state.actor = r.actor || name;
        if (el("roleBadge")) el("roleBadge").textContent = can("admin") ? "admin" : state.actor;
        showOk("Actor name updated");
      } catch (e) { showError(String(e.message || e)); }
    };
    async function loadTls() {
      if (!el("tlsOut")) return;
      try {
        const r = await api("GET", "/api/v1/tls/certs");
        const certs = r.certs || [];
        el("tlsOut").classList.remove("empty");
        if (!certs.length) {
          el("tlsOut").textContent = "No uploaded certificates yet.";
          return;
        }
        el("tlsOut").innerHTML = certs.map((c) => `
          <div style="margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid var(--border)">
            <strong>${esc(c.label || c.id)}</strong> ${c.active ? '<span class="pill ok">active</span>' : ""}
            <span class="mono muted" style="font-size:0.7rem"> ${esc(c.id)}</span>
            <div class="row" style="margin-top:4px">
              ${!c.active ? `<button type="button" data-tls-act="${esc(c.id)}" class="primary">Activate</button>` : ""}
              ${!c.active ? `<button type="button" data-tls-del="${esc(c.id)}" class="danger">Delete</button>` : ""}
            </div>
          </div>`).join("");
        el("tlsOut").querySelectorAll("[data-tls-act]").forEach((b) => {
          b.onclick = async () => {
            try {
              const r2 = await api("POST", `/api/v1/tls/certs/${b.getAttribute("data-tls-act")}/activate`);
              el("tlsOut").textContent = JSON.stringify(r2, null, 2);
              showOk("Activated - restart squidc5 to serve new TLS");
              loadTls();
            } catch (e) { showError(String(e.message || e)); }
          };
        });
        el("tlsOut").querySelectorAll("[data-tls-del]").forEach((b) => {
          b.onclick = async () => {
            try {
              await api("DELETE", `/api/v1/tls/certs/${b.getAttribute("data-tls-del")}`);
              showOk("Deleted");
              loadTls();
            } catch (e) { showError(String(e.message || e)); }
          };
        });
      } catch (e) { showError(String(e.message || e)); }
    }
    if (el("tlsUpload")) el("tlsUpload").onclick = async () => {
      try {
        const r = await api("POST", "/api/v1/tls/certs", {
          label: (el("tlsLabel").value || "uploaded").trim(),
          cert_pem: el("tlsCert").value || "",
          key_pem: el("tlsKey").value || "",
        });
        showOk("Certificate uploaded: " + (r.id || ""));
        if (el("tlsCert")) el("tlsCert").value = "";
        if (el("tlsKey")) el("tlsKey").value = "";
        loadTls();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("tlsRefresh")) el("tlsRefresh").onclick = () => loadTls();
    if (can("admin")) loadTls();
    if (el("astRefresh")) el("astRefresh").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/assets?limit=50");
        el("astOut").classList.remove("empty");
        el("astOut").textContent = JSON.stringify(r.assets || r, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
    function selectedScopes() {
      return Array.from(document.querySelectorAll(".ad-scope:checked")).map((c) => c.value);
    }
    function selectedMcp() {
      return Array.from(document.querySelectorAll(".ad-mcp:checked")).map((c) => c.value);
    }
    function setScopes(set) {
      document.querySelectorAll(".ad-scope").forEach((c) => {
        if (c.disabled) return;
        c.checked = set.has(c.value);
      });
      syncMcpVisibility();
    }
    function setMcp(list) {
      const want = new Set(list || []);
      document.querySelectorAll(".ad-mcp").forEach((c) => {
        c.checked = want.has(c.value);
      });
    }
    function syncMcpVisibility() {
      const show = !!(el("adMcpShow") && el("adMcpShow").checked) || selectedScopes().includes("mcp:connect");
      if (el("adMcpBox")) el("adMcpBox").classList.toggle("hidden", !show);
      if (el("adMcpShow") && selectedScopes().includes("mcp:connect")) el("adMcpShow").checked = true;
    }
    function b64urlEncodeObj(obj) {
      const s = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
      return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function buildTokenConnectLink(rawToken) {
      let apiUrl = "";
      try {
        if (window.__SC5_API_BASE__) apiUrl = String(window.__SC5_API_BASE__);
        else if (typeof localStorage !== "undefined") {
          const raw = localStorage.getItem("sc5_ops_cfg");
          if (raw) apiUrl = (JSON.parse(raw).url || "");
        }
      } catch (_) {}
      if (!apiUrl && typeof location !== "undefined") apiUrl = location.origin;
      apiUrl = (apiUrl || "").replace(/\/$/, "");
      let opsOrigin = apiUrl;
      try { opsOrigin = new URL(apiUrl).origin; } catch (_) {}
      const payload = { url: apiUrl, token: rawToken, refresh: 10 };
      return opsOrigin + "/ops#sc5=" + b64urlEncodeObj(payload);
    }
    function hideSecretBanner() {
      const b = el("adSecretBanner");
      if (b) b.classList.add("hidden");
      if (el("adSecretToken")) el("adSecretToken").value = "";
      if (el("adSecretLink")) el("adSecretLink").value = "";
    }
    function showSecretBanner({ title, token, name, id, scopes, linkOnly }) {
      const b = el("adSecretBanner");
      if (!b) return;
      b.classList.remove("hidden");
      if (el("adSecretTitle")) el("adSecretTitle").textContent = title || "Token secret";
      if (el("adSecretToken")) {
        el("adSecretToken").value = linkOnly
          ? "(secret not shown - recipient redeems the link once)"
          : (token || "");
      }
      if (el("adSecretLink")) {
        el("adSecretLink").value = linkOnly
          ? (token || "") // when linkOnly, `token` arg carries the URL
          : buildTokenConnectLink(token || "");
      }
      if (el("adSecretMeta")) {
        const sc = (scopes || []).slice(0, 8).join(", ");
        el("adSecretMeta").textContent =
          (name ? name + " - " : "") + (id || "") + (sc ? " - " + sc : "");
      }
      try { b.scrollIntoView({ block: "nearest", behavior: "smooth" }); } catch (_) {}
    }
    async function copyField(inputId, okMsg) {
      const n = el(inputId);
      if (!n || !n.value) return showError("Nothing to copy");
      try {
        await navigator.clipboard.writeText(n.value);
        showOk(okMsg || "Copied");
      } catch (_) {
        try {
          n.focus();
          n.select();
          document.execCommand("copy");
          showOk(okMsg || "Copied");
        } catch (e2) {
          showError("Clipboard unavailable - select and copy manually");
        }
      }
    }
    function clearEditMode() {
      if (el("adEditId")) el("adEditId").value = "";
      if (el("adSaveEdit")) el("adSaveEdit").disabled = true;
      if (el("adCancelEdit")) el("adCancelEdit").classList.add("hidden");
      if (el("adMint")) el("adMint").disabled = false;
      if (el("adName")) el("adName").value = "";
      setScopes(defaultScopes);
      setMcp([]);
    }
    function enterEditMode(tok) {
      if (!tok || tok.revoked) return;
      if (el("adEditId")) el("adEditId").value = tok.id || "";
      if (el("adName")) el("adName").value = tok.name || "";
      setScopes(new Set(tok.scopes || []));
      setMcp(tok.mcp_tools || []);
      if (el("adSaveEdit")) el("adSaveEdit").disabled = false;
      if (el("adCancelEdit")) el("adCancelEdit").classList.remove("hidden");
      if (el("adMint")) el("adMint").disabled = true;
    }
    async function loadTokenTable() {
      const box = el("adTokTable");
      if (!box || !can("tokens:manage") && !can("admin")) {
        if (box) box.innerHTML = '<p class="muted">tokens:manage required to list tokens</p>';
        return;
      }
      try {
        const rows = await api("GET", "/api/v1/tokens");
        const list = Array.isArray(rows) ? rows : [];
        if (!list.length) {
          box.innerHTML = '<p class="muted">No tokens yet.</p>';
          return;
        }
        box.innerHTML = `<table class="data"><thead><tr>
          <th>Name</th><th>Scopes</th><th>Status</th><th></th>
        </tr></thead><tbody>
        ${list.map((t) => {
          const sc = (t.scopes || []).slice(0, 6).map((s) => esc(s)).join(", ");
          const more = (t.scopes || []).length > 6 ? " +" + ((t.scopes || []).length - 6) : "";
          const st = t.revoked ? '<span class="chip">revoked</span>' : '<span class="chip ok">active</span>';
          return `<tr data-tid="${esc(t.id)}">
            <td><strong>${esc(t.name || "")}</strong><div class="mono muted" style="font-size:0.65rem">${esc(t.id || "")}</div></td>
            <td style="font-size:0.72rem;max-width:220px">${sc}${more}</td>
            <td>${st}</td>
            <td class="row" style="margin:0;flex-wrap:wrap">
              ${!t.revoked ? `<button type="button" data-tok-edit="${esc(t.id)}">Edit</button>` : ""}
              ${!t.revoked ? `<button type="button" data-tok-link="${esc(t.id)}" title="One-time connection URL (no secret shown)">Link</button>` : ""}
              ${!t.revoked ? `<button type="button" data-tok-roll="${esc(t.id)}">Roll</button>` : ""}
              ${!t.revoked ? `<button type="button" class="danger" data-tok-rev="${esc(t.id)}">Revoke</button>` : ""}
            </td>
          </tr>`;
        }).join("")}
        </tbody></table>`;
        box.querySelectorAll("[data-tok-edit]").forEach((b) => {
          b.onclick = () => {
            const id = b.getAttribute("data-tok-edit");
            const tok = list.find((x) => x.id === id);
            if (tok) enterEditMode(tok);
          };
        });
        box.querySelectorAll("[data-tok-link]").forEach((b) => {
          b.onclick = async () => {
            const id = b.getAttribute("data-tok-link");
            const tok = list.find((x) => x.id === id);
            if (!id) return;
            try {
              // Use the same origin the ops header shows (not implant PUBLIC_HOST)
              let baseUrl = "";
              try {
                if (window.__SC5_API_BASE__) baseUrl = String(window.__SC5_API_BASE__);
                else if (typeof localStorage !== "undefined") {
                  const raw = localStorage.getItem("sc5_ops_cfg");
                  if (raw) baseUrl = (JSON.parse(raw).url || "");
                }
              } catch (_) {}
              if (!baseUrl && typeof location !== "undefined") baseUrl = location.origin;
              baseUrl = (baseUrl || "").replace(/\/$/, "");
              const r = await api("POST", "/api/v1/tokens/" + encodeURIComponent(id) + "/connection-link", {
                ttl_sec: 3600,
                note: "admin handoff",
                base_url: baseUrl || undefined,
              });
              const exp = r.expires_at ? new Date(r.expires_at * 1000).toISOString() : "";
              showSecretBanner({
                title: "Connection link (one-time)",
                token: r.url || "",
                name: r.name || (tok && tok.name),
                id: r.token_id || id,
                scopes: r.scopes || (tok && tok.scopes),
                linkOnly: true,
              });
              if (el("adSecretMeta")) {
                el("adSecretMeta").textContent =
                  (r.name || (tok && tok.name) || "") +
                  " - " + (r.token_id || id) +
                  (exp ? " - expires " + exp : "") +
                  " - redeem rolls their secret once";
              }
              showOk("Connection link ready - send to operator");
            } catch (e) { showError(String(e.message || e)); }
          };
        });
        box.querySelectorAll("[data-tok-roll]").forEach((b) => {
          b.onclick = async () => {
            const id = b.getAttribute("data-tok-roll");
            const tok = list.find((x) => x.id === id);
            if (!id || !confirm("Roll secret for " + (tok && tok.name ? tok.name : id) + "? The old secret stops working immediately.")) return;
            try {
              const r = await api("POST", "/api/v1/tokens/" + encodeURIComponent(id) + "/roll");
              showSecretBanner({
                title: "Rolled token secret",
                token: r.token,
                name: r.name || (tok && tok.name),
                id: r.id || id,
                scopes: r.scopes || (tok && tok.scopes),
              });
              showOk("Token rolled - copy new secret");
              clearEditMode();
              loadTokenTable();
            } catch (e) { showError(String(e.message || e)); }
          };
        });
        box.querySelectorAll("[data-tok-rev]").forEach((b) => {
          b.onclick = async () => {
            const id = b.getAttribute("data-tok-rev");
            if (!id || !confirm("Revoke token " + id + "?")) return;
            try {
              await api("DELETE", "/api/v1/tokens/" + encodeURIComponent(id));
              showOk("Revoked");
              if (el("adEditId") && el("adEditId").value === id) clearEditMode();
              loadTokenTable();
            } catch (e) { showError(String(e.message || e)); }
          };
        });
      } catch (e) {
        box.innerHTML = '<p class="muted">Failed to load tokens</p>';
        showError(String(e.message || e));
      }
    }
    document.querySelectorAll(".ad-preset").forEach((b) => {
      b.onclick = () => {
        const id = b.getAttribute("data-preset");
        const p = presets.find((x) => x.id === id);
        if (!p) return;
        if (el("adPresetDesc")) el("adPresetDesc").textContent = p.description || "";
        setScopes(new Set(p.scopes || []));
        if (p.mcp_tools) {
          setMcp(p.mcp_tools);
          if (el("adMcpShow")) el("adMcpShow").checked = true;
          syncMcpVisibility();
        }
      };
    });
    if (el("adScopeNone")) el("adScopeNone").onclick = () => {
      if (el("adPresetDesc")) el("adPresetDesc").textContent = "No scopes selected.";
      setScopes(new Set());
    };
    if (el("adScopeAll")) el("adScopeAll").onclick = () => {
      if (el("adPresetDesc")) {
        el("adPresetDesc").textContent =
          "All non-privileged scopes (never admin, tokens:manage, policy, llm, plugins).";
      }
      // Never include privileged scopes - even when the granter is admin
      setScopes(new Set(nonAdminScopes));
    };
    if (el("adMcpShow")) el("adMcpShow").onchange = () => syncMcpVisibility();
    document.querySelectorAll(".ad-scope").forEach((c) => {
      c.addEventListener("change", () => syncMcpVisibility());
    });
    if (el("adCancelEdit")) el("adCancelEdit").onclick = () => clearEditMode();
    if (el("adSecretDismiss")) el("adSecretDismiss").onclick = () => hideSecretBanner();
    if (el("adSecretCopyTok")) el("adSecretCopyTok").onclick = () => copyField("adSecretToken", "Token copied");
    if (el("adSecretCopyLink")) el("adSecretCopyLink").onclick = () => copyField("adSecretLink", "Connection link copied");
    if (el("adMint")) el("adMint").onclick = async () => {
      try {
        const scopes = selectedScopes();
        if (!scopes.length) return showError("Select at least one scope");
        const name = (el("adName").value || "").trim() || "op";
        const body = { name, scopes };
        if (scopes.includes("mcp:connect")) {
          const tools = selectedMcp();
          if (tools.length) body.mcp_tools = tools;
        }
        const r = await api("POST", "/api/v1/tokens", body);
        showSecretBanner({
          title: "Minted token secret",
          token: r.token,
          name: r.name || name,
          id: r.id,
          scopes: r.scopes || scopes,
        });
        showOk("Token minted - copy secret or connection link");
        loadTokenTable();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("adSaveEdit")) el("adSaveEdit").onclick = async () => {
      try {
        const id = (el("adEditId") && el("adEditId").value) || "";
        if (!id) return showError("No token selected");
        const scopes = selectedScopes();
        if (!scopes.length) return showError("Select at least one scope");
        const body = {
          name: (el("adName").value || "").trim() || undefined,
          scopes,
        };
        if (scopes.includes("mcp:connect")) body.mcp_tools = selectedMcp();
        else body.mcp_tools = [];
        await api("PATCH", "/api/v1/tokens/" + encodeURIComponent(id), body);
        showOk("Token updated (secret unchanged)");
        clearEditMode();
        loadTokenTable();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("adTokRefresh")) el("adTokRefresh").onclick = () => loadTokenTable();
    syncMcpVisibility();
    if (can("tokens:manage") || can("admin")) loadTokenTable();
    const dump = async (path) => {
      try {
        const r = await api("GET", path);
        el("adOut").textContent = JSON.stringify(r, null, 2);
        el("adOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("adPolGet")) el("adPolGet").onclick = () => dump("/api/v1/policy");
    if (el("adFeat")) el("adFeat").onclick = () => dump("/api/v1/features");
  }


  /* -- Profiles -- */
  function renderProfilesView(force) {
    const root = el("view-profiles");
    if (!root) return;
    if (!force && viewBuilt.profiles && root.querySelector("#profTbody")) return;
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">C2 profiles <button type="button" id="profReload" style="margin-left:auto">Reload</button></div>
          <div class="lp-body"><table class="data"><thead><tr><th>Name</th><th>Channel</th><th>Active</th></tr></thead>
          <tbody id="profTbody"></tbody></table></div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Manage</div>
          <div class="wp-body">
            ${(can("profiles:write") || can("admin")) ? `
              <label>Name</label><input id="profName" placeholder="stealth-http" />
              <label>URIs (comma-separated)</label><input id="profUris" placeholder="/api/v1/implant/beacon,/cdn/a" />
              <label>User-Agent</label><input id="profUa" value="Mozilla/5.0" />
              <div class="form-grid">
                <div><label>Sleep sec</label><input id="profSleep" type="number" value="5" /></div>
                <div><label>Jitter %</label><input id="profJitter" type="number" value="20" /></div>
              </div>
              <div class="row">
                <button type="button" class="primary" id="profSave">Save profile</button>
                <button type="button" id="profAct">Activate selected</button>
                <button type="button" id="profPush">Push active</button>
              </div>
            ` : '<p class="muted">Need profiles:write</p>'}
            <div class="outbox empty" id="profOut">-</div>
          </div>
        </div>
      </div>
    `;
    viewBuilt.profiles = true;
    let selectedProf = null;
    async function loadProfs() {
      try {
        const r = await api("GET", "/api/v1/profiles");
        const rows = r.profiles || [];
        const act = r.active_id || "";
        const tb = el("profTbody");
        if (!tb) return;
        tb.innerHTML = rows.map((p) => `
          <tr data-pid="${esc(p.id)}" class="${p.id === act ? "selected" : ""}">
            <td>${esc(p.name || p.id)}</td>
            <td>${esc(p.channel || "http")}</td>
            <td>${p.id === act || p.active ? "*" : ""}</td>
          </tr>`).join("") || '<tr><td colspan="3" class="muted">No profiles</td></tr>';
        tb.querySelectorAll("tr[data-pid]").forEach((tr) => {
          tr.onclick = () => {
            selectedProf = tr.getAttribute("data-pid");
            tb.querySelectorAll("tr").forEach((x) => x.classList.toggle("selected", x === tr));
            const row = rows.find((x) => x.id === selectedProf);
            if (row && el("profName")) {
              el("profName").value = row.name || "";
              const uris = (row.http && row.http.uris) || [];
              if (el("profUris")) el("profUris").value = uris.join(",");
              if (el("profUa") && row.http) el("profUa").value = row.http.user_agent || "";
              if (el("profSleep") && row.http) el("profSleep").value = row.http.sleep_sec ?? 5;
              if (el("profJitter") && row.http) el("profJitter").value = row.http.jitter_pct ?? 20;
            }
          };
        });
        el("profOut").textContent = "active: " + (act || "none") + "  /  " + rows.length + " profiles";
        el("profOut").classList.remove("empty");
      } catch (e) { showError(String(e.message || e)); }
    }
    if (el("profReload")) el("profReload").onclick = () => loadProfs();
    if (el("profSave")) el("profSave").onclick = async () => {
      try {
        const name = (el("profName").value || "").trim();
        const uris = (el("profUris").value || "").split(",").map((s) => s.trim()).filter(Boolean);
        const body = {
          id: selectedProf || undefined,
          name,
          channel: "http",
          http: {
            uris: uris.length ? uris : ["/api/v1/implant/beacon"],
            user_agent: el("profUa").value || "Mozilla/5.0",
            sleep_sec: Number(el("profSleep").value || 5),
            jitter_pct: Number(el("profJitter").value || 20),
          },
        };
        const r = await api("POST", "/api/v1/profiles", body);
        showOk("Profile saved");
        el("profOut").textContent = JSON.stringify(r, null, 2);
        loadProfs();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("profAct")) el("profAct").onclick = async () => {
      if (!selectedProf) return showError("Select a profile");
      try {
        const r = await api("POST", `/api/v1/profiles/${encodeURIComponent(selectedProf)}/activate`);
        showOk("Activated");
        el("profOut").textContent = JSON.stringify(r, null, 2);
        loadProfs();
      } catch (e) { showError(String(e.message || e)); }
    };
    if (el("profPush")) el("profPush").onclick = async () => {
      try {
        const r = await api("GET", "/api/v1/profiles/active");
        const id = r.id;
        const out = await api("POST", `/api/v1/profiles/${encodeURIComponent(id)}/push`, {});
        showOk("Push queued");
        el("profOut").textContent = JSON.stringify(out, null, 2);
      } catch (e) { showError(String(e.message || e)); }
    };
    loadProfs();
  }

  /* -- Artifacts -- */
  function renderArtifactsView(force) {
    const root = el("view-artifacts");
    if (!root) return;
    if (!force && viewBuilt.artifacts && root.querySelector("#astTbody")) return;
    root.innerHTML = `
      <div class="split">
        <div class="list-panel">
          <div class="lp-head">Artifacts
            <select id="astKind" style="margin-left:auto;width:auto;min-height:32px;font-size:0.75rem">
              <option value="">all</option>
              <option value="payload">payload</option>
              <option value="template">template</option>
              <option value="profile">profile</option>
              <option value="implant">implant</option>
              <option value="other">other</option>
            </select>
            <button type="button" id="astReload">Reload</button>
          </div>
          <div class="lp-body"><table class="data"><thead><tr><th>Name</th><th>Kind</th><th>By</th></tr></thead>
          <tbody id="astTbody"></tbody></table></div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Preview</div>
          <div class="wp-body">
            <div class="row">
              <button type="button" id="astCopy">Copy</button>
              <button type="button" class="danger" id="astDel">Delete</button>
            </div>
            <div class="outbox empty" id="astPreview" style="max-height:min(60vh,520px);min-height:200px">Select an artifact...</div>
          </div>
        </div>
      </div>
    `;
    viewBuilt.artifacts = true;
    let selectedAst = null;
    let selectedContent = "";
    async function loadAst() {
      try {
        const kind = el("astKind")?.value || "";
        const q = kind ? `?kind=${encodeURIComponent(kind)}&limit=100` : "?limit=100";
        const r = await api("GET", "/api/v1/assets" + q);
        const rows = r.assets || [];
        const tb = el("astTbody");
        tb.innerHTML = rows.map((a) => `
          <tr data-aid="${esc(a.id)}">
            <td>${esc(a.name)}</td>
            <td>${esc(a.kind)}</td>
            <td class="mono">${esc(a.created_by || "-")}</td>
          </tr>`).join("") || '<tr><td colspan="3" class="muted">No artifacts yet - generate from Payloads or INKO</td></tr>';
        tb.querySelectorAll("tr[data-aid]").forEach((tr) => {
          tr.onclick = async () => {
            selectedAst = tr.getAttribute("data-aid");
            tb.querySelectorAll("tr").forEach((x) => x.classList.toggle("selected", x === tr));
            try {
              const full = await api("GET", `/api/v1/assets/${encodeURIComponent(selectedAst)}`);
              selectedContent = full.content || "";
              el("astPreview").textContent = selectedContent || JSON.stringify(full, null, 2);
              el("astPreview").classList.remove("empty");
            } catch (e) { showError(String(e.message || e)); }
          };
        });
      } catch (e) { showError(String(e.message || e)); }
    }
    if (el("astReload")) el("astReload").onclick = () => loadAst();
    if (el("astKind")) el("astKind").onchange = () => loadAst();
    if (el("astCopy")) el("astCopy").onclick = async () => {
      try { await navigator.clipboard.writeText(selectedContent || ""); showOk("Copied"); }
      catch (_) { showError("Clipboard unavailable"); }
    };
    if (el("astDel")) el("astDel").onclick = async () => {
      if (!selectedAst) return showError("Select artifact");
      try {
        await api("DELETE", `/api/v1/assets/${encodeURIComponent(selectedAst)}`);
        selectedAst = null;
        selectedContent = "";
        el("astPreview").textContent = "Select an artifact...";
        el("astPreview").classList.add("empty");
        showOk("Deleted");
        loadAst();
      } catch (e) { showError(String(e.message || e)); }
    };
    loadAst();
  }


  /* -- Assets / hosts graph -- */
  let _hostsCache = { hosts: [], edges: [], claim_ttl_sec: 0, selected: null };

  function renderHostsView(force) {
    const root = el("view-hosts");
    if (!root) return;
    if (!force && viewBuilt.hosts && root.querySelector("#hostGraph")) {
      loadHostsGraph();
      return;
    }
    root.innerHTML = `
      <div class="split" style="grid-template-columns: minmax(260px, 340px) 1fr">
        <div class="list-panel">
          <div class="lp-head">Hosts
            <button type="button" class="ghost sm" id="hostReload" style="margin-left:auto">Reload</button>
          </div>
          <div class="lp-body"><table class="data"><thead><tr>
            <th>Host</th><th>Sessions</th><th>Lock</th>
          </tr></thead><tbody id="hostTbody"></tbody></table></div>
        </div>
        <div class="work-panel">
          <div class="wp-head">Asset graph <span class="muted" id="hostGraphMeta" style="font-weight:400;margin-left:8px;font-size:0.72rem"></span></div>
          <div class="wp-body" style="display:flex;flex-direction:column;min-height:0;height:100%">
            <p class="muted" style="font-size:0.75rem;margin:0 0 8px">Compromised hosts as nodes. Pink = active access; amber = session lock held. Click host for implants; click a session row to open the lock rail.</p>
            <div class="chips" style="margin-bottom:8px">
              <span class="chip ok">active</span>
              <span class="chip warn">locked</span>
              <span class="chip">idle / closed only</span>
            </div>
            <div id="hostGraph" style="flex:1;min-height:300px;border:1px solid var(--border);border-radius:10px;background:#0a0a10;position:relative;overflow:hidden"></div>
            <div id="hostDetail" class="outbox empty" style="margin-top:10px;max-height:240px;overflow:auto">Select a host</div>
          </div>
        </div>
      </div>`;
    viewBuilt.hosts = true;
    if (el("hostReload")) el("hostReload").onclick = () => loadHostsGraph();
    loadHostsGraph();
  }

  async function loadHostsGraph() {
    const tbody = el("hostTbody");
    const graph = el("hostGraph");
    const detail = el("hostDetail");
    if (!tbody || !graph) return;
    try {
      const data = await api("GET", "/api/v1/hosts");
      const hosts = data.hosts || [];
      _hostsCache = {
        hosts,
        edges: data.edges || [],
        claim_ttl_sec: data.claim_ttl_sec || 0,
        selected: _hostsCache.selected,
      };
      if (el("hostGraphMeta")) {
        const ttl = _hostsCache.claim_ttl_sec;
        el("hostGraphMeta").textContent =
          hosts.length + " host(s) · claim TTL " + (ttl > 0 ? Math.round(ttl / 60) + "m" : "off");
      }
      tbody.innerHTML = hosts.map((h) => {
        const lock = h.claimed_by
          ? `<span class="chip warn">${esc(h.claimed_by)}</span>`
          : `<span class="chip">-</span>`;
        return `<tr data-host="${esc(h.id)}">
          <td><strong>${esc(h.label)}</strong>
            <div class="muted mono" style="font-size:0.65rem">${esc((h.addrs || []).join(", ") || "")}</div>
          </td>
          <td>${esc(String(h.active_sessions || 0))}/${esc(String(h.session_count || 0))}</td>
          <td>${lock}</td>
        </tr>`;
      }).join("") || '<tr><td colspan="3" class="muted">No hosts yet — catch a beacon or shell</td></tr>';
      const pick = (id) => {
        tbody.querySelectorAll("tr").forEach((x) => {
          x.classList.toggle("selected", x.getAttribute("data-host") === id);
        });
        const h = hosts.find((x) => x.id === id);
        _hostsCache.selected = id;
        if (h) showHostDetail(h, detail);
        drawHostGraph(graph, hosts, pick, id);
      };
      tbody.querySelectorAll("tr[data-host]").forEach((tr) => {
        tr.onclick = () => pick(tr.getAttribute("data-host"));
      });
      const sel = _hostsCache.selected && hosts.some((h) => h.id === _hostsCache.selected)
        ? _hostsCache.selected
        : null;
      drawHostGraph(graph, hosts, pick, sel);
      if (sel) {
        const h = hosts.find((x) => x.id === sel);
        if (h) showHostDetail(h, detail);
      }
    } catch (e) {
      showError(String(e.message || e));
      tbody.innerHTML = '<tr><td colspan="3" class="muted">Failed to load hosts</td></tr>';
    }
  }

  function showHostDetail(h, detail) {
    if (!detail || !h) return;
    detail.classList.remove("empty");
    const sess = (h.sessions || []).map((s) => {
      const c = s.claim || {};
      const lock = c.claimed_by ? c.claimed_by : "-";
      const left = (c.claim_remaining_sec != null)
        ? ` · ${Math.ceil(c.claim_remaining_sec / 60)}m`
        : "";
      return `<tr data-sid="${esc(s.id)}" style="cursor:pointer">
        <td class="mono">${esc(String(s.id || "").slice(0, 12))}</td>
        <td>${esc(s.kind || "")}</td>
        <td>${esc(s.status || "")}${s.verified ? " ✓" : ""}</td>
        <td>${esc(s.username || "-")}</td>
        <td>${c.claimed_by ? `<span class="chip warn">${esc(lock)}${esc(left)}</span>` : '<span class="chip">unlocked</span>'}</td>
      </tr>`;
    }).join("");
    detail.innerHTML = `
      <div style="margin-bottom:8px">
        <strong style="font-size:1rem">${esc(h.label)}</strong>
        <div class="muted" style="font-size:0.78rem;margin-top:4px">
          OS: ${esc(h.os_info || "-")} · Addrs: ${esc((h.addrs || []).join(", ") || "-")}<br/>
          Users: ${esc((h.usernames || []).join(", ") || "-")} · Kinds: ${esc((h.kinds || []).join(", "))}
        </div>
      </div>
      <table class="data"><thead><tr>
        <th>Session</th><th>Kind</th><th>Status</th><th>User</th><th>Lock</th>
      </tr></thead><tbody>${sess || '<tr><td colspan="5" class="muted">No sessions</td></tr>'}</tbody></table>`;
    detail.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.onclick = () => {
        const sid = tr.getAttribute("data-sid");
        if (sid) selectSession(sid);
      };
    });
  }

  function drawHostGraph(container, hosts, onClick, selectedId) {
    if (!container) return;
    const w = Math.max(320, container.clientWidth || 480);
    const hgt = Math.max(280, container.clientHeight || 320);
    if (!hosts.length) {
      container.innerHTML = `<div class="empty-state" style="height:100%;display:flex;align-items:center;justify-content:center;margin:0">
        <div><strong>No host nodes</strong><div class="muted" style="margin-top:6px">Beacons and shells appear here grouped by hostname / remote address.</div></div>
      </div>`;
      return;
    }
    const n = hosts.length;
    const cx = w / 2;
    const cy = hgt / 2;
    const R = Math.min(w, hgt) * (n === 1 ? 0 : 0.34);
    const nodes = hosts.map((host, i) => {
      const ang = (i / n) * Math.PI * 2 - Math.PI / 2;
      return {
        host,
        x: n === 1 ? cx : cx + Math.cos(ang) * R,
        y: n === 1 ? cy : cy + Math.sin(ang) * R,
      };
    });
    const byId = Object.fromEntries(nodes.map((nd) => [nd.host.id, nd]));
    let svg = `<svg width="100%" height="100%" viewBox="0 0 ${w} ${hgt}" xmlns="http://www.w3.org/2000/svg">`;
    // Hub spokes + ring for multi-host engagement topology
    if (n > 1) {
      nodes.forEach((nd) => {
        svg += `<line x1="${cx}" y1="${cy}" x2="${nd.x}" y2="${nd.y}" stroke="rgba(233,30,140,0.12)" stroke-width="1" stroke-dasharray="4 4"/>`;
      });
      for (let i = 0; i < n; i++) {
        const a = nodes[i];
        const b = nodes[(i + 1) % n];
        svg += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="rgba(233,30,140,0.18)" stroke-width="1.5"/>`;
      }
    }
    // Co-host session edges collapsed to host pairs (thicker when many sessions share host - already same node)
    // Cross-host: none from API; keep topology visual only
    void byId;
    nodes.forEach((node, idx) => {
      const host = node.host;
      const active = (host.active_sessions || 0) > 0;
      const locked = !!host.claimed_by;
      const sel = selectedId && host.id === selectedId;
      const fill = locked ? "rgba(251,191,36,0.28)" : active ? "rgba(233,30,140,0.38)" : "rgba(255,255,255,0.07)";
      const stroke = sel ? "#fff" : locked ? "rgba(251,191,36,0.9)" : "rgba(233,30,140,0.7)";
      const sw = sel ? 3 : 2;
      const r = 20 + Math.min(16, (host.session_count || 1) * 3);
      const label = (host.label || host.id || "?").slice(0, 20);
      const sub = (host.active_sessions || 0) + "/" + (host.session_count || 0);
      svg += `<g class="host-node" data-idx="${idx}" style="cursor:pointer">
        <circle cx="${node.x}" cy="${node.y}" r="${r + 4}" fill="none" stroke="${sel ? "rgba(233,30,140,0.35)" : "transparent"}" stroke-width="6"/>
        <circle cx="${node.x}" cy="${node.y}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"/>
        <text x="${node.x}" y="${node.y + 4}" text-anchor="middle" fill="#fff" font-size="11" font-weight="700">${esc(sub)}</text>
        <text x="${node.x}" y="${node.y + r + 16}" text-anchor="middle" fill="#c8c8d4" font-size="11" font-family="ui-monospace,monospace">${esc(label)}</text>
      </g>`;
    });
    svg += "</svg>";
    container.innerHTML = svg;
    container.querySelectorAll(".host-node").forEach((g) => {
      g.onclick = () => {
        const i = Number(g.getAttribute("data-idx"));
        if (nodes[i] && onClick) onClick(nodes[i].host.id);
      };
    });
  }

  /* -- View router -- */
  function renderView(name) {
    // Soft by default - preserve form focus/values; only build once per view
    switch (name) {
      case "sessions": renderSessionsView(false); break;
      case "hosts": renderHostsView(false); break;
      case "listeners": renderListenersView(false); break;
      case "payloads": renderPayloadsView(false); break;
      case "profiles": renderProfilesView(false); break;
      case "artifacts": renderArtifactsView(false); break;
      case "postex": renderPostexView(false); break;
      case "collab": renderCollabView(false); break;
      case "ai": renderAiView(false); break;
      case "observe": renderObserveView(false); break;
      case "admin": renderAdminView(false); break;
      default: break;
    }
    setPageDocs(name || "dashboard");
    renderContext();
    // Admin/AI hide ctx on desktop; on mobile keep sheet available when a session is selected
    if (name === "admin" || name === "ai") {
      if (!isMobileShell()) openCtxSheet(false);
    } else if (selectedId && isMobileShell()) {
      /* leave sheet closed until user re-selects unless already open */
    }
  }
  window.__SC5_setPageDocs = setPageDocs;
  window.__SC5_openCtx = openCtxSheet;

  window.__SC5_onView = renderView;
  window.__SC5_onRefresh = (data) => {
    if (data.sessions) cache.sessions = data.sessions;
    if (data.listeners) cache.listeners = data.listeners;
    const ae = document.activeElement;
    const typing = ae && (
      ae.tagName === "INPUT" || ae.tagName === "TEXTAREA" || ae.tagName === "SELECT" || ae.isContentEditable
    );
    // Soft update - never rebuild forms; skip panels while user is typing
    if (currentIs("sessions")) {
      renderSessionsView(false);
      if (el("tskList") && !typing) loadTasksPanel();
    }
    if (currentIs("hosts") && !typing) renderHostsView(false);
    if (currentIs("listeners")) renderListenersView(false);
    if (el("pxSid") && !typing) el("pxSid").textContent = selectedId || "(none - pick in Sessions)";
    document.querySelectorAll("tr[data-sid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-sid") === selectedId);
    });
    document.querySelectorAll("tr[data-lid]").forEach((tr) => {
      tr.classList.toggle("selected", tr.getAttribute("data-lid") === selectedListenerId);
    });
    // Context metadata only when not focused inside context form
    if (selectedId) {
      const inCtx = ae && el("ctxBody") && el("ctxBody").contains(ae);
      if (!inCtx && !typing) renderContext(false);
    }
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
