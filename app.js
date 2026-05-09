/* LB Woo Tracker — encrypted leads dashboard.
 *
 * Data flow:
 *   1. Fetch leads.encrypted.json (envelope w/ AES-GCM ciphertext)
 *   2. Show plaintext "last updated" timestamp
 *   3. Prompt for passphrase (or use cached one from localStorage)
 *   4. Derive PBKDF2 key, AES-GCM decrypt → JSON.parse → render
 *   5. Personal state (contacted flags, notes, settings) lives in localStorage
 *      per-browser. Backups via Settings → Export.
 */
(() => {
"use strict";

// ──────────────────────────────────────────────────────────────────────────
// Constants & state
// ──────────────────────────────────────────────────────────────────────────

const DATA_URL = "leads.encrypted.json";
const LS_KEYS = {
  passphrase: "lbwt:passphrase",
  contacted: "lbwt:contacted",          // { domain: { at: iso, status: "contacted"|"not_interested" } }
  notes: "lbwt:notes",                  // { domain: "free text" }
  theme: "lbwt:theme",                  // "light" | "dark"
  templateNoApp: "lbwt:tpl:noApp",
  templateHasApp: "lbwt:tpl:hasApp",
  templateSig: "lbwt:tpl:sig",
  templatePortfolio: "lbwt:tpl:portfolio",
  filters: "lbwt:filters",
  sort: "lbwt:sort",
};

const DEFAULT_TEMPLATES = {
  noApp:
`Subject: A mobile app for {{store_name}}

Hi,

I came across {{store_name}} ({{domain}}) and noticed you don't yet have a mobile app on the App Store or Play Store.

Because you're on WooCommerce, your existing store can power a native mobile app via the Woo REST API — no rebuild, no new backend. The catalog, cart, and checkout you already maintain become the data layer for the app. A working iOS + Android app on top of an existing Woo store typically takes 3-4 weeks to ship instead of the 4-6 months a from-scratch build would take.

A native app on the stores would let you:
  • Send push notifications for restocks, sales, and new arrivals (5-10× the open-rate of email)
  • Skip the mobile-web checkout friction (often a 20-40% lift in completion)
  • Build a direct channel that doesn't depend on Meta or Google ads

I'm based in Lebanon and would love to put together a quick proposal — including a clickable prototype matching your branding — at no cost. Would Tuesday or Wednesday work for a 20-minute call?

{{signature}}
{{portfolio_url}}`,
  hasApp:
`Subject: Refreshing the {{store_name}} mobile app

Hi,

I'm a Lebanon-based mobile developer. I came across the {{store_name}} app on the stores and noticed it was last updated {{app_age}}.

Both Apple and Google have shipped major guideline changes since {{app_age_year}}, and modern shoppers expect things that weren't standard back then — fast checkout, dark mode, modern push notifications, accessibility improvements. Stale apps tend to drop in store ranking too, so the cost of leaving an aging build untouched grows over time.

Because {{store_name}} runs on WooCommerce, I can rebuild on top of your existing store via the Woo REST API — no migration, no data copy. Most refreshes I do ship in 3-4 weeks.

Would Tuesday or Wednesday work for a 20-minute call? I'll come prepared with a concrete walkthrough of what would change for {{store_name}} specifically.

{{signature}}
{{portfolio_url}}
{{ios_url}}
{{android_url}}`,
  sig: "Pierre Sabbagh",
  portfolio: "https://sabbaghpierre.github.io",
};

const state = {
  envelope: null,        // raw envelope from leads.encrypted.json
  data: null,            // decrypted: { schema_version, generated_at, counts, leads }
  filtered: [],          // current filter+sort view
  filters: { tier: "all", status: "all", contact: "all", search: "" },
  sort: { key: "lead_score", dir: "desc" },
  selectedIndex: -1,
  expandedDomain: null,
};

// ──────────────────────────────────────────────────────────────────────────
// LocalStorage helpers
// ──────────────────────────────────────────────────────────────────────────

const ls = {
  get(key, fallback = null) {
    try { const v = localStorage.getItem(key); return v == null ? fallback : JSON.parse(v); }
    catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
  },
  del(key) { try { localStorage.removeItem(key); } catch {} },
};

// ──────────────────────────────────────────────────────────────────────────
// Crypto: PBKDF2 + AES-GCM, mirroring src/encrypt_dashboard.py
// ──────────────────────────────────────────────────────────────────────────

function b64decode(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

async function deriveKey(passphrase, saltBytes, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptEnvelope(envelope, passphrase) {
  if (!envelope || envelope.alg !== "AES-GCM") {
    throw new Error("Unsupported envelope format");
  }
  const salt = b64decode(envelope.salt);
  const iv = b64decode(envelope.iv);
  const ciphertext = b64decode(envelope.ciphertext);
  const key = await deriveKey(passphrase, salt, envelope.iterations || 200000);
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(plaintextBuf));
}

// ──────────────────────────────────────────────────────────────────────────
// Bootstrap
// ──────────────────────────────────────────────────────────────────────────

async function init() {
  applyTheme(ls.get(LS_KEYS.theme, prefersDark() ? "dark" : "light"));
  hookGlobalUI();
  hookSettingsUI();
  restoreFiltersAndSort();
  await loadEnvelope();
  setUpdatedTimestamp();
  hideLoading();
  await tryAutoUnlock();
}

async function loadEnvelope() {
  try {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.envelope = await res.json();
  } catch (e) {
    document.getElementById("auth-error").hidden = false;
    document.getElementById("auth-error").textContent =
      `Could not load ${DATA_URL}: ${e.message}. ` +
      `If the dashboard repo was just created, the workflow may not have run yet.`;
    showAuth();
  }
}

function setUpdatedTimestamp() {
  if (!state.envelope?.updated_at) return;
  const fmt = formatRelativeAndAbsolute(state.envelope.updated_at);
  document.getElementById("updated").textContent = `· data updated ${fmt}`;
  document.getElementById("auth-updated").textContent = fmt;
}

async function tryAutoUnlock() {
  const cached = ls.get(LS_KEYS.passphrase);
  if (cached && state.envelope) {
    try {
      state.data = await decryptEnvelope(state.envelope, cached);
      onUnlocked();
      return;
    } catch {
      ls.del(LS_KEYS.passphrase);
    }
  }
  showAuth();
}

function showAuth() {
  document.getElementById("auth-overlay").style.display = "flex";
  document.getElementById("auth-passphrase").focus();
}

function hideAuth() {
  document.getElementById("auth-overlay").style.display = "none";
}

function showLoading() { document.getElementById("loading-overlay").style.display = "flex"; }
function hideLoading() { document.getElementById("loading-overlay").style.display = "none"; }

function onUnlocked() {
  hideAuth();
  document.getElementById("main").hidden = false;
  renderStats();
  renderTable();
}

document.getElementById("auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = document.getElementById("auth-passphrase").value;
  const remember = document.getElementById("auth-remember").checked;
  const errEl = document.getElementById("auth-error");
  errEl.hidden = true;
  const submitBtn = document.getElementById("auth-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "Unlocking…";
  try {
    if (!state.envelope) throw new Error("no data loaded");
    state.data = await decryptEnvelope(state.envelope, pass);
    if (remember) ls.set(LS_KEYS.passphrase, pass);
    onUnlocked();
  } catch (err) {
    errEl.textContent = "Wrong passphrase, or the file is corrupted.";
    errEl.hidden = false;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Unlock";
  }
});

// ──────────────────────────────────────────────────────────────────────────
// Stats
// ──────────────────────────────────────────────────────────────────────────

function renderStats() {
  const c = state.data.counts || {};
  const cards = [
    ["Total", c.total || 0],
    ["A-tier", c.A || 0, "tier-A"],
    ["B-tier", c.B || 0, "tier-B"],
    ["C-tier", c.C || 0, "tier-C"],
    ["No app", c.no_app || 0, "status-no_app"],
    ["Has app", c.has_app || 0, "status-has_app"],
    ["Unknown", c.app_unknown || 0, "status-app_unknown"],
    ["Contacted", Object.keys(ls.get(LS_KEYS.contacted, {})).length],
  ];
  const html = cards.map(([label, value, badge]) => `
    <div class="stat-card">
      <div class="label">${label}</div>
      <div class="value">${value}</div>
    </div>
  `).join("");
  document.getElementById("stats").innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────────────
// Table render
// ──────────────────────────────────────────────────────────────────────────

function applyFiltersAndSort() {
  const contacted = ls.get(LS_KEYS.contacted, {});
  const q = state.filters.search.trim().toLowerCase();
  let rows = (state.data.leads || []).slice();

  rows = rows.filter(L => {
    if (state.filters.tier !== "all" && L.lead_tier !== state.filters.tier) return false;
    if (state.filters.status !== "all" && L.status !== state.filters.status) return false;
    const c = contacted[L.domain]?.status || "uncontacted";
    if (state.filters.contact === "contacted" && c !== "contacted") return false;
    if (state.filters.contact === "uncontacted" && c !== "uncontacted") return false;
    if (state.filters.contact === "not_interested" && c !== "not_interested") return false;
    if (q) {
      const hay = (L.domain + " " + (L.store_name || "")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const { key, dir } = state.sort;
  const mul = dir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    let av, bv;
    if (key === "app_age") {
      av = appAgeDays(a) ?? Infinity;
      bv = appAgeDays(b) ?? Infinity;
    } else if (key === "contacted") {
      av = contacted[a.domain]?.at || "";
      bv = contacted[b.domain]?.at || "";
    } else {
      av = a[key]; bv = b[key];
    }
    if (av == null) av = "";
    if (bv == null) bv = "";
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * mul;
    return String(av).localeCompare(String(bv)) * mul;
  });

  state.filtered = rows;
}

function renderTable() {
  applyFiltersAndSort();
  const contacted = ls.get(LS_KEYS.contacted, {});
  const tbody = document.getElementById("leads-body");
  const empty = document.getElementById("empty-state");

  if (state.filtered.length === 0) {
    tbody.innerHTML = "";
    empty.hidden = false;
  } else {
    empty.hidden = true;
    tbody.innerHTML = state.filtered.map((L, i) => renderRow(L, i, contacted[L.domain])).join("");
  }

  document.getElementById("footer-counts").textContent =
    `${state.filtered.length} of ${state.data.counts?.total || 0} leads shown`;

  // Re-attach handlers
  tbody.querySelectorAll("tr.lead-row").forEach(tr => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button, a, textarea, input")) return;
      toggleExpand(tr.dataset.domain);
    });
  });

  // Re-expand the previously expanded row, if still in the filtered list.
  if (state.expandedDomain) {
    const row = tbody.querySelector(`tr.lead-row[data-domain="${cssEscape(state.expandedDomain)}"]`);
    if (row) injectExpanded(row);
    else state.expandedDomain = null;
  }

  // Update sort indicators
  document.querySelectorAll("th.sortable").forEach(th => {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.sort === state.sort.key) {
      th.classList.add(state.sort.dir === "asc" ? "sorted-asc" : "sorted-desc");
    }
  });
}

function renderRow(L, idx, contact) {
  const tier = L.lead_tier || "?";
  const score = L.lead_score ?? "?";
  const status = L.status || "?";
  const ageDays = appAgeDays(L);
  const ageStr = ageDays != null ? humanAge(ageDays) : "—";
  const reasons = (L.score_reasons || []).slice(0, 3).map(r =>
    `<span class="reason-tag">${escapeHtml(r)}</span>`
  ).join("");
  const contactStatus = contact?.status || "";
  const contactLabel = contactStatus === "contacted" ? "Contacted"
                     : contactStatus === "not_interested" ? "Not interested"
                     : "—";

  const rowClass = ["lead-row"];
  if (idx === state.selectedIndex) rowClass.push("selected");
  if (contactStatus) rowClass.push(contactStatus);

  return `
    <tr class="${rowClass.join(" ")}" data-domain="${escapeHtml(L.domain)}" data-idx="${idx}">
      <td class="score">${score}</td>
      <td><span class="tier-badge tier-${tier}">${tier}</span></td>
      <td><span class="status-badge status-${status}">${humanStatus(status)}</span></td>
      <td><a href="https://${escapeHtml(L.domain)}" target="_blank" rel="noopener noreferrer">${escapeHtml(L.domain)}</a></td>
      <td>${escapeHtml(L.store_name || "")}</td>
      <td>${ageStr}</td>
      <td><div class="reasons">${reasons}</div></td>
      <td>${escapeHtml(L.last_checked || "")}</td>
      <td><span class="contact-tag ${contactStatus}">${contactLabel}</span></td>
    </tr>
  `;
}

function injectExpanded(rowEl) {
  // Remove any existing expanded row first
  const existing = document.querySelector("tr.expanded-row");
  if (existing) existing.remove();

  const domain = rowEl.dataset.domain;
  const lead = state.data.leads.find(L => L.domain === domain);
  if (!lead) return;

  const expandedTr = document.createElement("tr");
  expandedTr.className = "expanded-row";
  expandedTr.dataset.expandedFor = domain;
  const td = document.createElement("td");
  td.colSpan = 9;
  td.innerHTML = renderExpandedContent(lead);
  expandedTr.appendChild(td);
  rowEl.parentNode.insertBefore(expandedTr, rowEl.nextSibling);

  // Wire up actions inside the expanded view
  const root = expandedTr;
  root.querySelector("[data-action=copy-email]")?.addEventListener("click", () => {
    const draft = root.querySelector(".email-draft").textContent;
    copyToClipboard(draft);
  });
  root.querySelector("[data-action=mark-contacted]")?.addEventListener("click", () => {
    setContactStatus(domain, "contacted");
  });
  root.querySelector("[data-action=mark-not-interested]")?.addEventListener("click", () => {
    setContactStatus(domain, "not_interested");
  });
  root.querySelector("[data-action=clear-contact]")?.addEventListener("click", () => {
    setContactStatus(domain, null);
  });
  root.querySelector("[data-action=regen-template]")?.addEventListener("change", (e) => {
    const which = e.target.value;
    root.querySelector(".email-draft").textContent = buildEmail(lead, which);
  });
  const notesEl = root.querySelector(".notes-area");
  if (notesEl) {
    notesEl.value = (ls.get(LS_KEYS.notes, {})[domain]) || "";
    let timer;
    notesEl.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        const all = ls.get(LS_KEYS.notes, {});
        if (notesEl.value.trim()) all[domain] = notesEl.value;
        else delete all[domain];
        ls.set(LS_KEYS.notes, all);
      }, 400);
    });
  }
}

function renderExpandedContent(L) {
  const ageDays = appAgeDays(L);
  const components = Object.entries(L.score_components || {})
    .filter(([, v]) => v !== 0)
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>+${v}</dd>`).join("");
  const wooSignals = (L.woo_signals || []).map(s =>
    `<span class="reason-tag">${escapeHtml(s)}</span>`).join(" ");
  const lbSignals = (L.lb_signals || []).map(s =>
    `<span class="reason-tag">${escapeHtml(s)}</span>`).join(" ");

  const apps = (L.app_matches || []).map(m => `
    <div class="app-card">
      <div class="app-platform">${escapeHtml(m.platform || "?").toUpperCase()}</div>
      <div class="app-name">${escapeHtml(m.name || "")}
        ${m.url ? `· <a href="${escapeHtml(m.url)}" target="_blank" rel="noopener noreferrer">open</a>` : ""}
      </div>
      <div class="muted small">
        ${m.developer ? `dev: ${escapeHtml(m.developer)} · ` : ""}
        ${m.last_updated ? `updated ${m.last_updated}` : ""}
        ${(m.rating || 0) > 0 ? ` · ★ ${m.rating} (${m.review_count || 0})` : ""}
        ${m.confidence ? ` · ${m.confidence} confidence` : ""}
      </div>
    </div>
  `).join("") || `<p class="muted small">No app matches.</p>`;

  const which = L.status === "has_app" ? "hasApp" : "noApp";
  const draft = buildEmail(L, which);

  return `
    <div class="expanded-content">
      <div class="expanded-grid">
        <div>
          <div class="detail-section">
            <h4>Detection</h4>
            <dl>
              <dt>Domain</dt><dd>${escapeHtml(L.domain)}</dd>
              <dt>Store</dt><dd>${escapeHtml(L.store_name || "—")}</dd>
              <dt>Status</dt><dd>${humanStatus(L.status)}</dd>
              <dt>Score</dt><dd>${L.lead_score ?? "?"} (${L.lead_tier ?? "?"})</dd>
              <dt>First seen</dt><dd>${escapeHtml(L.first_seen || "—")}</dd>
              <dt>Last checked</dt><dd>${escapeHtml(L.last_checked || "—")}</dd>
              <dt>App age</dt><dd>${ageDays != null ? humanAge(ageDays) : "—"}</dd>
            </dl>
          </div>
          <div class="detail-section">
            <h4>Score components</h4>
            <dl>${components || "<dd>—</dd>"}</dl>
          </div>
          <div class="detail-section">
            <h4>Woo signals (${L.woo_score ?? 0})</h4>
            <div class="reasons">${wooSignals || "<span class=\"muted small\">—</span>"}</div>
          </div>
          <div class="detail-section">
            <h4>Lebanon signals (${L.lb_score ?? 0})</h4>
            <div class="reasons">${lbSignals || "<span class=\"muted small\">—</span>"}</div>
          </div>
          <div class="detail-section">
            <h4>Apps</h4>
            ${apps}
          </div>
        </div>

        <div>
          <div class="detail-section">
            <h4>Email draft
              <select data-action="regen-template" class="ghost-btn" style="float:right; font-size:11px;">
                <option value="${which}" selected>${which === "hasApp" ? "Revamp" : "Cold"}</option>
                <option value="${which === "hasApp" ? "noApp" : "hasApp"}">${which === "hasApp" ? "Cold" : "Revamp"}</option>
              </select>
            </h4>
            <pre class="email-draft">${escapeHtml(draft)}</pre>
            <div class="btn-row">
              <button data-action="copy-email" class="primary-btn">📋 Copy email</button>
              <a href="https://${escapeHtml(L.domain)}" target="_blank" rel="noopener noreferrer" class="ghost-btn">↗ Open shop</a>
            </div>
          </div>
          <div class="detail-section">
            <h4>Mark</h4>
            <div class="btn-row">
              <button data-action="mark-contacted" class="ghost-btn">✓ Contacted</button>
              <button data-action="mark-not-interested" class="ghost-btn">✗ Not interested</button>
              <button data-action="clear-contact" class="ghost-btn">↺ Reset</button>
            </div>
          </div>
          <div class="detail-section">
            <h4>Notes</h4>
            <textarea class="notes-area" placeholder="Personal notes about this lead — saved locally"></textarea>
          </div>
        </div>
      </div>
    </div>
  `;
}

function toggleExpand(domain) {
  if (state.expandedDomain === domain) {
    document.querySelector("tr.expanded-row")?.remove();
    state.expandedDomain = null;
    return;
  }
  state.expandedDomain = domain;
  const row = document.querySelector(`tr.lead-row[data-domain="${cssEscape(domain)}"]`);
  if (row) injectExpanded(row);
}

// ──────────────────────────────────────────────────────────────────────────
// Email template
// ──────────────────────────────────────────────────────────────────────────

function buildEmail(lead, which /* "noApp" | "hasApp" */) {
  const tpl = which === "hasApp"
    ? ls.get(LS_KEYS.templateHasApp, DEFAULT_TEMPLATES.hasApp)
    : ls.get(LS_KEYS.templateNoApp, DEFAULT_TEMPLATES.noApp);
  const sig = ls.get(LS_KEYS.templateSig, DEFAULT_TEMPLATES.sig);
  const portfolio = ls.get(LS_KEYS.templatePortfolio, DEFAULT_TEMPLATES.portfolio);

  const ageDays = appAgeDays(lead);
  const ageStr = ageDays != null ? humanAge(ageDays) : "some time ago";
  const ageYear = ageDays != null
    ? new Date(Date.now() - ageDays * 86400000).getFullYear().toString()
    : "";
  const ios = (lead.app_matches || []).find(m => m.platform === "ios")?.url || "";
  const android = (lead.app_matches || []).find(m => m.platform === "android")?.url || "";

  return tpl
    .replaceAll("{{store_name}}", lead.store_name || lead.domain)
    .replaceAll("{{domain}}", lead.domain)
    .replaceAll("{{app_age}}", ageStr)
    .replaceAll("{{app_age_year}}", ageYear)
    .replaceAll("{{signature}}", sig)
    .replaceAll("{{portfolio_url}}", portfolio)
    .replaceAll("{{ios_url}}", ios)
    .replaceAll("{{android_url}}", android);
}

// ──────────────────────────────────────────────────────────────────────────
// Personal state mutations
// ──────────────────────────────────────────────────────────────────────────

function setContactStatus(domain, status /* "contacted" | "not_interested" | null */) {
  const all = ls.get(LS_KEYS.contacted, {});
  if (status == null) delete all[domain];
  else all[domain] = { status, at: new Date().toISOString().slice(0, 10) };
  ls.set(LS_KEYS.contacted, all);
  toast(status ? `Marked ${status.replace("_", " ")}` : "Reset contact status");
  renderStats();
  renderTable();
}

// ──────────────────────────────────────────────────────────────────────────
// Filters & sort UI
// ──────────────────────────────────────────────────────────────────────────

function hookGlobalUI() {
  // Filter chips
  document.querySelectorAll(".filter-group").forEach(group => {
    const filter = group.dataset.filter;
    group.addEventListener("click", (e) => {
      const btn = e.target.closest(".chip");
      if (!btn) return;
      group.querySelectorAll(".chip").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.filters[filter] = btn.dataset.value;
      saveFilters();
      renderTable();
    });
  });

  // Search
  const search = document.getElementById("search");
  let searchTimer;
  search.addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = e.target.value;
      saveFilters();
      renderTable();
    }, 150);
  });

  // Sortable headers
  document.querySelectorAll("th.sortable").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) {
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort.key = key;
        state.sort.dir = (key === "domain" || key === "store_name") ? "asc" : "desc";
      }
      saveSort();
      renderTable();
    });
  });

  // Topbar buttons
  document.getElementById("btn-theme").addEventListener("click", () => {
    const next = (document.documentElement.dataset.theme === "dark") ? "light" : "dark";
    applyTheme(next);
  });
  document.getElementById("btn-lock").addEventListener("click", lockDashboard);
  document.getElementById("btn-settings").addEventListener("click", openSettings);

  // Export filtered as CSV
  document.getElementById("btn-export").addEventListener("click", exportFilteredCsv);

  // Keyboard shortcuts
  document.addEventListener("keydown", onKey);
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  ls.set(LS_KEYS.theme, theme);
}

function prefersDark() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function lockDashboard() {
  ls.del(LS_KEYS.passphrase);
  state.data = null;
  document.getElementById("main").hidden = true;
  document.getElementById("auth-passphrase").value = "";
  showAuth();
}

function saveFilters() { ls.set(LS_KEYS.filters, state.filters); }
function saveSort() { ls.set(LS_KEYS.sort, state.sort); }

function restoreFiltersAndSort() {
  const f = ls.get(LS_KEYS.filters);
  if (f) state.filters = { ...state.filters, ...f };
  const s = ls.get(LS_KEYS.sort);
  if (s) state.sort = { ...state.sort, ...s };

  // Reflect in UI
  document.querySelectorAll(".filter-group").forEach(group => {
    const filter = group.dataset.filter;
    group.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
    const target = group.querySelector(`.chip[data-value="${state.filters[filter] || "all"}"]`);
    (target || group.querySelector(".chip[data-value=all]")).classList.add("active");
  });
  document.getElementById("search").value = state.filters.search || "";
}

// ──────────────────────────────────────────────────────────────────────────
// Settings modal
// ──────────────────────────────────────────────────────────────────────────

function hookSettingsUI() {
  document.querySelectorAll("[data-close]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.getElementById(btn.dataset.close).hidden = true;
    });
  });
  document.getElementById("btn-save-settings").addEventListener("click", saveSettings);
  document.getElementById("btn-export-personal").addEventListener("click", exportPersonal);
  document.getElementById("import-personal").addEventListener("change", importPersonal);
  document.getElementById("btn-clear-personal").addEventListener("click", () => {
    if (!confirm("Erase all contacted flags and notes? This can't be undone.")) return;
    ls.del(LS_KEYS.contacted);
    ls.del(LS_KEYS.notes);
    renderStats();
    renderTable();
    toast("Personal data cleared");
  });
  document.getElementById("btn-clear-cache").addEventListener("click", () => {
    if (!confirm("Forget the passphrase and reload?")) return;
    ls.del(LS_KEYS.passphrase);
    location.reload();
  });
}

function openSettings() {
  document.getElementById("tpl-no-app").value =
    ls.get(LS_KEYS.templateNoApp, DEFAULT_TEMPLATES.noApp);
  document.getElementById("tpl-has-app").value =
    ls.get(LS_KEYS.templateHasApp, DEFAULT_TEMPLATES.hasApp);
  document.getElementById("tpl-signature").value =
    ls.get(LS_KEYS.templateSig, DEFAULT_TEMPLATES.sig);
  document.getElementById("tpl-portfolio").value =
    ls.get(LS_KEYS.templatePortfolio, DEFAULT_TEMPLATES.portfolio);
  document.getElementById("settings-modal").hidden = false;
}

function saveSettings() {
  ls.set(LS_KEYS.templateNoApp, document.getElementById("tpl-no-app").value);
  ls.set(LS_KEYS.templateHasApp, document.getElementById("tpl-has-app").value);
  ls.set(LS_KEYS.templateSig, document.getElementById("tpl-signature").value);
  ls.set(LS_KEYS.templatePortfolio, document.getElementById("tpl-portfolio").value);
  document.getElementById("settings-modal").hidden = true;
  if (state.expandedDomain) {
    // Re-render expanded row so the email draft picks up new template
    const row = document.querySelector(`tr.lead-row[data-domain="${cssEscape(state.expandedDomain)}"]`);
    if (row) injectExpanded(row);
  }
  toast("Settings saved");
}

function exportPersonal() {
  const blob = {
    schema: 1,
    exported_at: new Date().toISOString(),
    contacted: ls.get(LS_KEYS.contacted, {}),
    notes: ls.get(LS_KEYS.notes, {}),
    templates: {
      noApp: ls.get(LS_KEYS.templateNoApp),
      hasApp: ls.get(LS_KEYS.templateHasApp),
      sig: ls.get(LS_KEYS.templateSig),
      portfolio: ls.get(LS_KEYS.templatePortfolio),
    },
  };
  download(`lbwt-personal-${new Date().toISOString().slice(0, 10)}.json`,
           JSON.stringify(blob, null, 2), "application/json");
}

async function importPersonal(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const blob = JSON.parse(text);
    if (blob.contacted) ls.set(LS_KEYS.contacted, blob.contacted);
    if (blob.notes) ls.set(LS_KEYS.notes, blob.notes);
    if (blob.templates?.noApp) ls.set(LS_KEYS.templateNoApp, blob.templates.noApp);
    if (blob.templates?.hasApp) ls.set(LS_KEYS.templateHasApp, blob.templates.hasApp);
    if (blob.templates?.sig) ls.set(LS_KEYS.templateSig, blob.templates.sig);
    if (blob.templates?.portfolio) ls.set(LS_KEYS.templatePortfolio, blob.templates.portfolio);
    renderStats();
    renderTable();
    toast("Personal data imported");
  } catch (err) {
    alert("Import failed: " + err.message);
  } finally {
    e.target.value = "";
  }
}

// ──────────────────────────────────────────────────────────────────────────
// CSV export of currently filtered list
// ──────────────────────────────────────────────────────────────────────────

function exportFilteredCsv() {
  if (!state.filtered.length) { toast("Nothing to export"); return; }
  const cols = ["lead_score", "lead_tier", "status", "domain", "store_name",
                "woo_score", "lb_score", "first_seen", "last_checked",
                "ios_url", "android_url", "ios_updated", "android_updated"];
  const head = cols.join(",");
  const rows = state.filtered.map(L => {
    const ios = (L.app_matches || []).find(m => m.platform === "ios") || {};
    const and = (L.app_matches || []).find(m => m.platform === "android") || {};
    const flat = {
      ...L,
      ios_url: ios.url || "", android_url: and.url || "",
      ios_updated: ios.last_updated || "", android_updated: and.last_updated || "",
    };
    return cols.map(c => csvCell(flat[c])).join(",");
  });
  const csv = [head, ...rows].join("\n");
  download(`leads-${new Date().toISOString().slice(0, 10)}.csv`, csv, "text/csv");
}

function csvCell(v) {
  if (v == null) return "";
  const s = String(v);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

// ──────────────────────────────────────────────────────────────────────────
// Keyboard
// ──────────────────────────────────────────────────────────────────────────

function onKey(e) {
  // Don't hijack typing in inputs/textareas
  const tag = (e.target.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  // Don't fire if a modal is open and visible
  const settingsOpen = !document.getElementById("settings-modal").hidden;
  if (settingsOpen) {
    if (e.key === "Escape") document.getElementById("settings-modal").hidden = true;
    return;
  }

  if (e.key === "/") {
    e.preventDefault();
    document.getElementById("search").focus();
    return;
  }
  if (e.key === "t" || e.key === "T") {
    document.getElementById("btn-theme").click(); return;
  }
  if (e.key === "l" || e.key === "L") {
    lockDashboard(); return;
  }
  if (e.key === ",") {
    openSettings(); return;
  }
  if (e.key === "Escape") {
    if (state.expandedDomain) toggleExpand(state.expandedDomain);
    return;
  }

  if (state.filtered.length === 0) return;

  if (e.key === "j") {
    state.selectedIndex = Math.min(state.filtered.length - 1, state.selectedIndex + 1);
    updateSelection(); return;
  }
  if (e.key === "k") {
    state.selectedIndex = Math.max(0, state.selectedIndex - 1);
    updateSelection(); return;
  }
  if (e.key === "Enter" && state.selectedIndex >= 0) {
    toggleExpand(state.filtered[state.selectedIndex].domain); return;
  }

  // Actions on selected lead
  if (state.selectedIndex < 0) return;
  const lead = state.filtered[state.selectedIndex];
  if (e.key === "c") {
    setContactStatus(lead.domain, "contacted");
  } else if (e.key === "n") {
    setContactStatus(lead.domain, "not_interested");
  } else if (e.key === "e") {
    copyToClipboard(buildEmail(lead, lead.status === "has_app" ? "hasApp" : "noApp"));
  }
}

function updateSelection() {
  document.querySelectorAll("tbody tr.lead-row").forEach((tr, i) => {
    tr.classList.toggle("selected", i === state.selectedIndex);
  });
  const row = document.querySelector(`tbody tr.lead-row.selected`);
  if (row) row.scrollIntoView({ block: "nearest" });
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

function appAgeDays(lead) {
  const dates = (lead.app_matches || [])
    .map(m => m.last_updated)
    .filter(Boolean);
  if (!dates.length) return null;
  const newest = dates.sort().slice(-1)[0];
  const t = Date.parse(newest);
  if (isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

function humanAge(days) {
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.round(days / 30)} mo`;
  const y = Math.floor(days / 365);
  const m = Math.round((days % 365) / 30);
  return m ? `${y}y ${m}mo` : `${y}y`;
}

function humanStatus(s) {
  return ({
    no_app: "no app", has_app: "has app", app_unknown: "unknown",
  })[s] || s || "?";
}

function formatRelativeAndAbsolute(iso) {
  const t = Date.parse(iso);
  if (isNaN(t)) return iso;
  const diffMin = Math.round((Date.now() - t) / 60000);
  let rel;
  if (diffMin < 60) rel = `${diffMin} min ago`;
  else if (diffMin < 60 * 24) rel = `${Math.round(diffMin / 60)} h ago`;
  else rel = `${Math.round(diffMin / (60 * 24))} d ago`;
  const d = new Date(t);
  return `${rel} (${d.toISOString().slice(0, 16).replace("T", " ")} UTC)`;
}

function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard"));
    return;
  }
  // Fallback
  const ta = document.createElement("textarea");
  ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); toast("Copied to clipboard"); }
  finally { ta.remove(); }
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

let toastTimer;
function toast(msg) {
  clearTimeout(toastTimer);
  document.querySelector(".toast")?.remove();
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg;
  document.body.appendChild(t);
  toastTimer = setTimeout(() => t.remove(), 2400);
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function cssEscape(s) {
  if (window.CSS && CSS.escape) return CSS.escape(s);
  return String(s).replace(/[^a-zA-Z0-9_-]/g, ch => `\\${ch}`);
}

// ──────────────────────────────────────────────────────────────────────────
// Go
// ──────────────────────────────────────────────────────────────────────────

init().catch(err => {
  console.error(err);
  alert("Dashboard failed to start: " + err.message);
});

})();
