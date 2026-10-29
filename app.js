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
  contacted: "lbwt:contacted",            // legacy, migrated into pipeline on load
  pipeline: "lbwt:pipeline",              // { domain: { stage, at: iso-date, followup: iso-date|"" } }
  hidden: "lbwt:hidden",                  // { domain: true } dismissed leads
  overrides: "lbwt:overrides",
  notes: "lbwt:notes",                  // { domain: "free text" }
  theme: "lbwt:theme",                  // "light" | "dark"
  templateNoApp: "lbwt:tpl:noApp",
  templateHasApp: "lbwt:tpl:hasApp",
  templateWa: "lbwt:tpl:wa",
  templateSig: "lbwt:tpl:sig",
  templatePortfolio: "lbwt:tpl:portfolio",
  filters: "lbwt:filters",
  sort: "lbwt:sort",
};

const DEFAULT_TEMPLATES = {
  noApp:
`Subject: A mobile app for {{store_name}}

Hi,

I came across {{store_name}} ({{domain}}). {{app_observation}}

I'm a Lebanon-based mobile developer. I'd like to explore whether an app connected to your {{platform}} store could make repeat shopping easier, with features such as restock notifications.

Would a short conversation about your store's needs be useful?

{{signature}}
{{portfolio_url}}`,
  hasApp:
`Subject: Refreshing the {{store_name}} mobile app

Hi,

I'm a Lebanon-based mobile developer. {{app_observation}}

I work on apps connected to {{platform}} stores and would be interested in understanding whether there are improvements your customers need. An older release alone doesn't tell me how well your app works.

Would you be open to a short conversation about your mobile shopping experience?

{{signature}}
{{portfolio_url}}
{{ios_url}}
{{android_url}}`,
  sig: "Pierre Sabbagh",
  portfolio: "https://sabbaghpierre.github.io",
  whatsapp:
`Hi {{store_name}} — I'm a Lebanon-based mobile developer. Would you be the right person to discuss a mobile shopping app for {{domain}}? {{signature}}`,
};

const state = {
  envelope: null,        // raw envelope from leads.encrypted.json
  data: null,            // decrypted: { schema_version, generated_at, counts, leads }
  filtered: [],          // current filter+sort view
  filters: { view: "active", tier: "all", status: "all", contact: "all", platform: "all", reach: "all", focus: false, search: "" },
  sort: { key: "priority", dir: "desc" },
  selectedIndex: -1,
  expandedDomain: null,
};

const STAGE_LABELS = {
  contacted: "Contacted", replied: "Replied", meeting: "Meeting",
  won: "Won", lost: "Lost",
};
const ACTIVE_STAGES = new Set(["contacted", "replied", "meeting"]);

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
// Pipeline (per-browser outreach state), reachability & priority
// ──────────────────────────────────────────────────────────────────────────

// stage: "contacted" | "replied" | "meeting" | "won" | "lost"
// entry: { stage, at: "YYYY-MM-DD", followup: "YYYY-MM-DD" | "" }
function migratePersonal() {
  if (ls.get(LS_KEYS.pipeline) || !ls.get(LS_KEYS.contacted)) return;
  const old = ls.get(LS_KEYS.contacted, {});
  const next = {};
  for (const [domain, v] of Object.entries(old)) {
    next[domain] = {
      stage: v?.status === "not_interested" ? "lost" : "contacted",
      at: v?.at || "",
      followup: "",
    };
  }
  ls.set(LS_KEYS.pipeline, next);
  ls.del(LS_KEYS.contacted);
}

function pipeOf(domain) {
  return ls.get(LS_KEYS.pipeline, {})[domain] || null;
}
function stageOf(domain) {
  return pipeOf(domain)?.stage || "";
}
function isHidden(domain) {
  return !!ls.get(LS_KEYS.hidden, {})[domain];
}
function hasPersonal(L) { return (L.emails || []).some(e => e.role === "personal"); }
function hasWa(L) { return (L.phones || []).some(p => p.channel === "whatsapp"); }
function hasAnyContact(L) { return (L.emails || []).length > 0 || (L.phones || []).length > 0; }
function isArchived(L) { return L.lifecycle === "archived" || isHidden(L.domain); }
function effectiveLeads() {
  const overrides = ls.get(LS_KEYS.overrides, {});
  return (state.data?.leads || []).map(L => ({ ...L, ...overrides[L.domain] }));
}
function leadOf(domain) { return effectiveLeads().find(L => L.domain === domain); }

// Priority: lead score + catalog value + reachability. Decides the daily order.
function priorityOf(L) {
  return L.lead_score || 0;
}

function fmtCount(n) {
  if (typeof n !== "number" || n < 0) return "—";
  return n.toLocaleString("en-US");
}

function productCountStr(L) {
  const pc = L.product_count;
  return (typeof pc === "number" && pc >= 0) ? String(pc) : "your online catalog";
}

// One plain-English line explaining why this lead matters.
function whyLine(L) {
  const bits = [];
  if (L.status === "no_app") bits.push("No app found");
  else if (L.status === "has_app") {
    const age = appAgeDays(L);
    bits.push(age != null ? `App ${humanAge(age)} old` : "Has app");
  } else bits.push("App status unknown");
  if (typeof L.product_count === "number" && L.product_count >= 0)
    bits.push(`${fmtCount(L.product_count)} products`);
  const reach = [];
  if (hasPersonal(L)) reach.push("personal email");
  else if ((L.emails || []).length) reach.push("email");
  if (hasWa(L)) reach.push("WhatsApp");
  else if ((L.phones || []).length) reach.push("phone");
  if (reach.length) bits.push(reach.join(" + "));
  return bits.join(" · ");
}

function followupState(domain) {
  const e = pipeOf(domain);
  if (!e?.followup) return "";
  const today = new Date().toISOString().slice(0, 10);
  return e.followup < today ? "overdue" : e.followup === today ? "due" : "future";
}

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
  migratePersonal();
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
  const stages = Object.values(ls.get(LS_KEYS.pipeline, {})).map(e => e.stage);
  const leads = effectiveLeads();
  const ready = leads.filter(L => !isArchived(L) && !L.review_required);
  const fresh = leads.filter(L => !stageOf(L.domain) && !isArchived(L) && !L.review_required).length;
  const cards = [
    ["Total", leads.length],
    ["A-tier", ready.filter(L => L.lead_tier === "A").length],
    ["No app found", ready.filter(L => L.status === "no_app").length],
    ["Has app", ready.filter(L => L.status === "has_app").length],
    ["New", fresh],
    ["Active", stages.filter(s => ACTIVE_STAGES.has(s)).length],
    ["Won", stages.filter(s => s === "won").length],
    ["Review", leads.filter(L => L.review_required && !isArchived(L)).length],
    ["Archived", leads.filter(isArchived).length],
  ];
  const html = cards.map(([label, value]) => `
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
  const pipe = ls.get(LS_KEYS.pipeline, {});
  const q = state.filters.search.trim().toLowerCase();
  let rows = effectiveLeads();

  rows = rows.filter(L => {
    if (state.filters.view === "archived") {
      if (!isArchived(L)) return false;
    } else {
      if (isArchived(L)) return false;
      if (state.filters.view === "review" && !L.review_required) return false;
      if (state.filters.view === "active" && L.review_required) return false;
    }
    if (state.filters.platform !== "all" && L.platform !== state.filters.platform) return false;
    if (state.filters.tier !== "all" && L.lead_tier !== state.filters.tier) return false;
    if (state.filters.status !== "all" && L.status !== state.filters.status) return false;
    const stage = pipe[L.domain]?.stage || "";
    const cf = state.filters.contact;
    if (cf === "uncontacted" && stage) return false;
    if (cf === "active" && !ACTIVE_STAGES.has(stage)) return false;
    if (cf === "won" && stage !== "won") return false;
    if (cf === "lost" && stage !== "lost") return false;
    if (cf === "due" && (!ACTIVE_STAGES.has(stage) || !["due", "overdue"].includes(followupState(L.domain)))) return false;
    const rf = state.filters.reach || "all";
    if (rf === "personal" && !hasPersonal(L)) return false;
    if (rf === "whatsapp" && !hasWa(L)) return false;
    if (rf === "any" && !hasAnyContact(L)) return false;
    if (rf === "none" && hasAnyContact(L)) return false;
    if (q) {
      const hay = (L.domain + " " + (L.store_name || "") + " " +
        (L.emails || []).map(e => e.address).join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const { key, dir } = state.sort;
  const mul = dir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    let av, bv;
    if (key === "priority") {
      av = priorityOf(a);
      bv = priorityOf(b);
    } else if (key === "product_count") {
      av = (typeof a.product_count === "number" && a.product_count >= 0) ? a.product_count : -1;
      bv = (typeof b.product_count === "number" && b.product_count >= 0) ? b.product_count : -1;
    } else if (key === "app_age") {
      av = appAgeDays(a) ?? -1;
      bv = appAgeDays(b) ?? -1;
    } else if (key === "contacted") {
      av = pipe[a.domain]?.at || "";
      bv = pipe[b.domain]?.at || "";
    } else {
      av = a[key]; bv = b[key];
    }
    if (av == null) av = "";
    if (bv == null) bv = "";
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * mul;
    return String(av).localeCompare(String(bv)) * mul;
  });

  if (state.filters.focus) {
    rows = rows.filter(L => !pipe[L.domain]?.stage && !isArchived(L) && !L.review_required && hasAnyContact(L)).slice(0, 10);
  }

  state.filtered = rows;
}

function renderTable() {
  applyFiltersAndSort();
  const pipe = ls.get(LS_KEYS.pipeline, {});
  const tbody = document.getElementById("leads-body");
  const empty = document.getElementById("empty-state");

  if (state.filtered.length === 0) {
    tbody.innerHTML = "";
    empty.hidden = false;
  } else {
    empty.hidden = true;
    tbody.innerHTML = state.filtered.map((L, i) => renderRow(L, i, pipe[L.domain])).join("");
  }

  const hiddenN = Object.keys(ls.get(LS_KEYS.hidden, {})).length;
  document.getElementById("footer-counts").textContent =
    `${state.filtered.length} of ${state.data.counts?.total || 0} leads shown` +
    (state.filters.focus ? " · ★ focus top 10" : "") +
    (hiddenN ? ` · ${hiddenN} dismissed` : "");

  // Re-attach handlers
  tbody.querySelectorAll("tr.lead-row").forEach(tr => {
    tr.addEventListener("click", (e) => {
      // Reach-email click-to-copy (handled before row-expand)
      const reachEmail = e.target.closest(".reach-email");
      if (reachEmail) {
        e.preventDefault();
        e.stopPropagation();
        copyToClipboard(reachEmail.dataset.copy, `Copied ${reachEmail.dataset.copy}`);
        return;
      }
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

function renderRow(L, idx, pipeEntry) {
  const tier = L.lead_tier || "?";
  const score = L.lead_score ?? "?";
  const status = L.status || "?";
  const ageDays = appAgeDays(L);
  const ageStr = ageDays != null ? humanAge(ageDays) : "—";
  const reasons = (L.score_reasons || []).slice(0, 3).map(r =>
    `<span class="reason-tag">${escapeHtml(r)}</span>`
  ).join("");
  const stage = pipeEntry?.stage || "";
  const fu = pipeEntry?.followup || "";
  const fuCls = followupState(L.domain);
  const pipeCell = stage || fu
    ? (stage ? `<span class="stage-tag stage-${stage}">${STAGE_LABELS[stage]}</span>` : "") +
      (fu ? ` <span class="due ${fuCls}" title="Follow up ${escapeHtml(fu)}">↺ ${escapeHtml(fu.slice(5))}</span>` : "")
    : "—";

  const rowClass = ["lead-row"];
  if (idx === state.selectedIndex) rowClass.push("selected");
  if (stage) rowClass.push("stage-" + stage);

  // Reach: top extracted email + whatsapp/phone
  const emails = L.emails || [];
  const phones = L.phones || [];
  const wa = phones.find(p => p.channel === "whatsapp");
  const reachParts = [];
  if (emails[0]) {
    reachParts.push(`<a href="#" class="reach-email" data-copy="${escapeHtml(emails[0].address)}" title="Copy ${escapeHtml(emails[0].address)}">${escapeHtml(emails[0].address)}</a>`);
  }
  if (wa) {
    const num = wa.number.replace("+", "");
    reachParts.push(`<a href="https://wa.me/${escapeHtml(num)}" target="_blank" rel="noopener" class="reach-wa" title="WhatsApp">📱</a>`);
  } else if (phones[0]) {
    reachParts.push(`<a href="tel:${escapeHtml(phones[0].number)}" class="reach-phone">${escapeHtml(phones[0].number)}</a>`);
  }
  const reachCell = reachParts.length
    ? reachParts.join('<span class="reach-sep"> · </span>')
    : '<span class="reach-missing">—</span>';

  return `
    <tr class="${rowClass.join(" ")}" data-domain="${escapeHtml(L.domain)}" data-idx="${idx}">
      <td class="score" data-label="Score">${score}</td>
      <td data-label="Tier"><span class="tier-badge tier-${tier}">${tier}</span></td>
      <td data-label="Status"><span class="status-badge status-${status}">${humanStatus(status)}</span></td>
      <td data-label="Domain"><a href="https://${escapeHtml(L.domain)}" target="_blank" rel="noopener noreferrer">${escapeHtml(L.domain)}</a></td>
      <td data-label="Store">${escapeHtml(L.store_name || "")}</td>
      <td class="col-value" data-label="Value">${fmtCount(L.product_count)}${L.product_count_kind === "lower_bound" ? "+" : ""}</td>
      <td class="col-reach" data-label="Reach">${reachCell}</td>
      <td data-label="App age">${ageStr}</td>
      <td data-label="Reasons"><div class="reasons">${reasons}</div></td>
      <td data-label="Last check">${escapeHtml(L.last_checked || "")}</td>
      <td data-label="Pipeline">${pipeCell}</td>
    </tr>
  `;
}

function injectExpanded(rowEl) {
  // Remove any existing expanded row first
  const existing = document.querySelector("tr.expanded-row");
  if (existing) existing.remove();

  const domain = rowEl.dataset.domain;
  const lead = leadOf(domain);
  if (!lead) return;

  const expandedTr = document.createElement("tr");
  expandedTr.className = "expanded-row";
  expandedTr.dataset.expandedFor = domain;
  const td = document.createElement("td");
  td.colSpan = 11;
  td.innerHTML = renderExpandedContent(lead);
  expandedTr.appendChild(td);
  rowEl.parentNode.insertBefore(expandedTr, rowEl.nextSibling);

  // Wire up actions inside the expanded view
  const root = expandedTr;
  root.querySelector("[data-action=copy-email]")?.addEventListener("click", () => {
    const draft = root.querySelector(".email-draft").textContent;
    copyToClipboard(draft);
  });
  root.querySelector("[data-action=copy-wa]")?.addEventListener("click", () => {
    copyToClipboard(buildWhatsApp(lead));
  });
  root.querySelectorAll("[data-action=stage]").forEach(btn => {
    btn.addEventListener("click", () => setStage(domain, btn.dataset.stage));
  });
  root.querySelector("[data-action=clear-stage]")?.addEventListener("click", () => {
    setStage(domain, null);
  });
  root.querySelector("[data-action=dismiss]")?.addEventListener("click", () => {
    toggleHidden(domain);
  });
  root.querySelector("[data-action=restore]")?.addEventListener("click", () => {
    const overrides = ls.get(LS_KEYS.overrides, {});
    overrides[domain] = { ...overrides[domain], lifecycle: "active", archive_reason: "", review_required: true, reviewed_at: new Date().toISOString() };
    ls.set(LS_KEYS.overrides, overrides);
    const hidden = ls.get(LS_KEYS.hidden, {});
    delete hidden[domain];
    ls.set(LS_KEYS.hidden, hidden);
    renderStats(); renderTable();
  });
  root.querySelector("[data-action=save-review]")?.addEventListener("click", () => saveReview(domain, root));
  root.querySelector("[data-action=reset-review]")?.addEventListener("click", () => {
    const overrides = ls.get(LS_KEYS.overrides, {});
    delete overrides[domain];
    ls.set(LS_KEYS.overrides, overrides);
    renderStats(); renderTable();
  });
  const fuInput = root.querySelector("[data-action=followup]");
  if (fuInput) {
    fuInput.value = pipeOf(domain)?.followup || "";
    fuInput.addEventListener("change", () => setFollowup(domain, fuInput.value));
  }
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
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v >= 0 ? "+" : ""}${v}</dd>`).join("");
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
  const waDraft = buildWhatsApp(L);
  const wa = (L.phones || []).find(p => p.channel === "whatsapp");
  const waNum = wa ? wa.number.replace("+", "") : "";
  const waLink = waNum ? `https://wa.me/${encodeURIComponent(waNum)}?text=${encodeURIComponent(waDraft)}` : "";
  const email0 = (L.emails || [])[0]?.address || "";
  const options = (values, selected) => values.map(([value, label]) =>
    `<option value="${escapeHtml(value)}"${value === selected ? " selected" : ""}>${escapeHtml(label)}</option>`).join("");
  const evidence = (L.location_evidence || []).map(e =>
    `<p class="small"><a href="${escapeHtml(safeUrl(e.source_url))}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.signal)}</a>: ${escapeHtml(e.excerpt)} (${escapeHtml(e.observed_at || "")})</p>`).join("");
  const coverage = Object.entries(L.app_coverage || {}).map(([p, result]) => `${p}: ${result}`).join(" · ") || "Not verified with current detector";
  const candidates = (L.app_candidates || []).map(m => `<p class="small">Review ownership: <a href="${escapeHtml(safeUrl(m.url))}" target="_blank" rel="noopener noreferrer">${escapeHtml(m.name)}</a> · ${escapeHtml(m.developer)}</p>`).join("");

  // Build contact-info block (emails + phones with role/channel badges).
  const emailsHtml = (L.emails || []).map(e =>
    `<div class="expand-contact-row"><span class="role-badge role-${escapeHtml(e.role)}">${escapeHtml(e.role)}</span> <span class="contact-val">${escapeHtml(e.address)}</span></div>`
  ).join("");
  const phonesHtml = (L.phones || []).map(p =>
    `<div class="expand-contact-row"><span class="role-badge role-${escapeHtml(p.channel)}">${escapeHtml(p.channel)}</span> <span class="contact-val">${escapeHtml(p.number)}</span></div>`
  ).join("");
  const reachBlock = (emailsHtml || phonesHtml)
    ? `<section class="expand-section"><h4>Reach</h4>${emailsHtml}${phonesHtml}</section>`
    : "";

  return `
    <div class="expanded-content">
      <div class="why-line">${escapeHtml(whyLine(L))}</div>
      <div class="expanded-grid">
        <div>
          <div class="detail-section">
            <h4>Detection</h4>
            <dl>
              <dt>Domain</dt><dd>${escapeHtml(L.domain)}</dd>
              <dt>Store</dt><dd>${escapeHtml(L.store_name || "—")}</dd>
              <dt>Status</dt><dd>${humanStatus(L.status)}</dd>
              <dt>Score</dt><dd>${L.lead_score ?? "?"} (${L.lead_tier ?? "?"}) · priority ${priorityOf(L)}</dd>
              <dt>First seen</dt><dd>${escapeHtml(L.first_seen || "—")}</dd>
              <dt>Last checked</dt><dd>${escapeHtml(L.last_checked || "—")}</dd>
              <dt>Last qualified</dt><dd>${escapeHtml(L.last_qualified || "—")}</dd>
              <dt>Confidence</dt><dd>${escapeHtml(L.qualification_confidence || "low")}</dd>
              <dt>Lifecycle</dt><dd>${escapeHtml(isHidden(L.domain) ? "manually dismissed" : L.lifecycle || "active")} ${escapeHtml(L.archive_reason || "")}</dd>
              <dt>Location</dt><dd>${escapeHtml(L.location_relationship || "unknown")}</dd>
              <dt>App coverage</dt><dd>${escapeHtml(coverage)} · ${escapeHtml(L.last_app_checked || "never")}</dd>
              <dt>Observed hosts</dt><dd>${escapeHtml((L.observed_hosts || []).join(", "))}</dd>
              ${L.duplicate_of ? `<dt>Shared destination</dt><dd>${escapeHtml(L.duplicate_of)} — review before contacting twice</dd>` : ""}
              ${L.identity_note ? `<dt>Business identity</dt><dd>${escapeHtml(L.identity_note)}</dd>` : ""}
              <dt>Sources</dt><dd>${escapeHtml((L.discovery_sources || []).join(", "))}</dd>
              <dt>Search queries</dt><dd>${escapeHtml((L.discovery_queries || []).join("; "))}</dd>
              <dt>App age</dt><dd>${ageDays != null ? humanAge(ageDays) : "—"}</dd>
            </dl>
          </div>
          <div class="detail-section">
            <h4>Score components</h4>
            <dl>${components || "<dd>—</dd>"}</dl>
          </div>
          <div class="detail-section">
            <h4>Platform signals (${escapeHtml(L.platform || "unknown")})</h4>
            <div class="reasons">${escapeHtml((L.platform_signals || L.woo_signals || []).join(", "))}</div>
          </div>
          <div class="detail-section">
            <h4>Lebanon signals (${L.lb_score ?? 0})</h4>
            <div class="reasons">${lbSignals || "<span class=\"muted small\">—</span>"}</div>
          </div>
          <div class="detail-section">
            <h4>Apps</h4>
            ${apps}
            ${candidates}
            ${evidence}
            ${L.business_evidence ? `<p class="small">Storefront observed ${escapeHtml(L.business_evidence.observed_at)}: ${escapeHtml(Object.keys(L.business_evidence.signals || {}).join(", "))}</p>` : ""}
            ${L.closure_evidence ? `<p class="small">Closure evidence: ${escapeHtml(L.closure_evidence.excerpt)}</p>` : ""}
            ${L.error ? `<p class="small">Last fetch: ${escapeHtml(L.error)}</p>` : ""}
          </div>
          ${reachBlock}
        </div>

        <div>
          <div class="detail-section">
            <h4>Manual review</h4>
            <p class="muted small">Corrections stay in this browser and survive data refreshes. Export personal data to back them up. Changed facts clear the score; use automatic facts again to accept a refreshed score.</p>
            <label>Platform <select data-review="platform">${options([["woo", "WooCommerce"], ["shopify", "Shopify"], ["", "Unknown"]], L.platform || "")}</select></label>
            <label>App status <select data-review="status">${options([["app_unknown", "Unknown"], ["no_app", "No app found (reviewed)"], ["has_app", "Owned app (reviewed)"]], ["no_app", "has_app"].includes(L.status) ? L.status : "app_unknown")}</select></label>
            <label>Location <select data-review="location">${options([["unknown", "Unknown"], ["local_contact", "Lebanon business/contact"], ["serves_lebanon", "Ships to Lebanon only"]], L.location_relationship === "likely_local" ? "local_contact" : L.location_relationship || "unknown")}</select></label>
            <label>Emails <input data-review="emails" value="${escapeHtml((L.emails || []).map(e => e.address).join(", "))}"></label>
            <label>Phones (+country code) <input data-review="phones" value="${escapeHtml((L.phones || []).map(p => p.number).join(", "))}"></label>
            <label>Owned iOS app <input data-review="ios" value="${escapeHtml((L.app_matches || []).find(m => m.platform === "ios")?.url || "")}"></label>
            <label>Owned Android app <input data-review="android" value="${escapeHtml((L.app_matches || []).find(m => m.platform === "android")?.url || "")}"></label>
            <label>Reason / evidence <input data-review="reason" value="${escapeHtml(L.review_reason || "")}" placeholder="Required: what did you verify?"></label>
            <div class="btn-row"><button data-action="save-review" class="ghost-btn">Save reviewed facts</button><button data-action="reset-review" class="ghost-btn">Use automatic facts</button></div>
          </div>
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
              ${email0 ? `<a href="${escapeHtml(mailtoHref(L))}" class="ghost-btn">✉️ Open mail</a>` : ""}
              <a href="https://${escapeHtml(L.domain)}" target="_blank" rel="noopener noreferrer" class="ghost-btn">↗ Open shop</a>
            </div>
          </div>
          <div class="detail-section">
            <h4>WhatsApp</h4>
            <pre class="wa-draft">${escapeHtml(waDraft)}</pre>
            <div class="btn-row">
              <button data-action="copy-wa" class="primary-btn">📋 Copy WhatsApp</button>
              ${waLink ? `<a href="${escapeHtml(waLink)}" target="_blank" rel="noopener noreferrer" class="ghost-btn">↗ Open chat</a>` : ""}
            </div>
          </div>
          <div class="detail-section">
            <h4>Pipeline</h4>
            <div class="btn-row">
              ${Object.entries(STAGE_LABELS).map(([s, label]) =>
                `<button data-action="stage" data-stage="${s}" class="ghost-btn${stageOf(L.domain) === s ? " active-stage" : ""}">${label}</button>`).join("")}
              <button data-action="clear-stage" class="ghost-btn">↺ Reset</button>
            </div>
            <div class="followup-row">
              <label class="muted small">Follow up <input type="date" data-action="followup"></label>
              <button data-action="dismiss" class="ghost-btn">${isHidden(L.domain) ? "Undo dismissal" : "Archive / dismiss"}</button>
              ${isArchived(L) ? '<button data-action="restore" class="ghost-btn">Restore store</button>' : ""}
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
  const tpl = lead.status === "app_unknown" ? DEFAULT_TEMPLATES.noApp : which === "hasApp"
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
  const observation = lead.status === "no_app"
    ? "I couldn't find a confirmed iOS or Android app in my checks. Do you currently have one?"
    : lead.status === "has_app"
      ? "I found your store's app listing. " + (lead.app_matches || []).map(m => `${m.platform === "ios" ? "iOS" : "Android"}${m.last_updated ? `: listing updated ${m.last_updated}` : ": update date not confirmed"}`).join("; ") + "."
      : "Do you currently offer a mobile app for your store?";

  return tpl
    .replaceAll("{{store_name}}", lead.store_name || lead.domain)
    .replaceAll("{{domain}}", lead.domain)
    .replaceAll("{{platform}}", lead.platform === "woo" ? "WooCommerce" : lead.platform === "shopify" ? "Shopify" : "online")
    .replaceAll("{{app_observation}}", observation)
    .replaceAll("{{app_age}}", ageStr)
    .replaceAll("{{app_age_year}}", ageYear)
    .replaceAll("{{product_count}}", productCountStr(lead))
    .replaceAll("{{app_name}}", ((lead.app_matches || [])[0]?.name) || lead.store_name || lead.domain)
    .replaceAll("{{signature}}", sig)
    .replaceAll("{{portfolio_url}}", portfolio)
    .replaceAll("{{ios_url}}", ios)
    .replaceAll("{{android_url}}", android);
}

function buildWhatsApp(lead) {
  const tpl = ls.get(LS_KEYS.templateWa, DEFAULT_TEMPLATES.whatsapp);
  const sig = ls.get(LS_KEYS.templateSig, DEFAULT_TEMPLATES.sig);
  const ageDays = appAgeDays(lead);
  const ageStr = ageDays != null ? humanAge(ageDays) : "some time ago";
  return tpl
    .replaceAll("{{store_name}}", lead.store_name || lead.domain)
    .replaceAll("{{domain}}", lead.domain)
    .replaceAll("{{app_age}}", ageStr)
    .replaceAll("{{product_count}}", productCountStr(lead))
    .replaceAll("{{app_name}}", ((lead.app_matches || [])[0]?.name) || lead.store_name || lead.domain)
    .replaceAll("{{signature}}", sig);
}

function mailtoHref(lead) {
  const email0 = (lead.emails || [])[0]?.address || "";
  const full = buildEmail(lead, lead.status === "has_app" ? "hasApp" : "noApp");
  const m = full.match(/^Subject:\s*(.*)$/m);
  const subject = m ? m[1] : `A mobile app for ${lead.store_name || lead.domain}`;
  const body = full.replace(/^Subject:.*\n/, "");
  return `mailto:${encodeURIComponent(email0)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

// ──────────────────────────────────────────────────────────────────────────
// Personal state mutations
// ──────────────────────────────────────────────────────────────────────────

function setStage(domain, stage /* "contacted"|"replied"|"meeting"|"won"|"lost"|null */) {
  const all = ls.get(LS_KEYS.pipeline, {});
  if (stage == null) delete all[domain];
  else {
    const at = new Date().toISOString().slice(0, 10);
    const reason = stage === "lost" ? prompt("Reason (optional)", all[domain]?.reason || "") : all[domain]?.reason || "";
    all[domain] = { ...all[domain], stage, at, followup: all[domain]?.followup || "", reason: reason || "",
      history: [...(all[domain]?.history || []), { stage, at, reason: reason || "" }] };
  }
  ls.set(LS_KEYS.pipeline, all);
  toast(stage ? `Marked ${STAGE_LABELS[stage].toLowerCase()}` : "Reset pipeline stage");
  renderStats();
  renderTable();
}

function setFollowup(domain, dateStr) {
  const all = ls.get(LS_KEYS.pipeline, {});
  const cur = all[domain] || { stage: "", at: "" };
  cur.followup = dateStr || "";
  all[domain] = cur;
  ls.set(LS_KEYS.pipeline, all);
  toast(dateStr ? `Follow-up ${dateStr}` : "Follow-up cleared");
  renderStats();
  renderTable();
}

function toggleHidden(domain) {
  const all = ls.get(LS_KEYS.hidden, {});
  if (all[domain]) delete all[domain];
  else {
    const reason = prompt("Why archive this store?", "Not a fit");
    if (reason == null) return;
    all[domain] = { reason: reason.trim() || "Manually dismissed", at: new Date().toISOString() };
  }
  ls.set(LS_KEYS.hidden, all);
  if (state.expandedDomain === domain) {
    document.querySelector("tr.expanded-row")?.remove();
    state.expandedDomain = null;
  }
  toast(all[domain] ? "Lead dismissed" : "Lead restored");
  renderStats();
  renderTable();
}

function saveReview(domain, root) {
  const lead = leadOf(domain);
  const value = key => root.querySelector(`[data-review="${key}"]`).value.trim();
  const reason = value("reason");
  if (!reason) { toast("Add a review reason or evidence first"); return; }
  const status = value("status");
  const addresses = value("emails").split(",").map(s => s.trim()).filter(Boolean);
  const numbers = value("phones").split(",").map(s => s.trim()).filter(Boolean);
  if (addresses.some(s => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) || numbers.some(s => !/^\+\d{7,15}$/.test(s))) {
    toast("Check email addresses and international phone numbers"); return;
  }
  const apps = [];
  for (const platform of ["ios", "android"]) {
    const url = value(platform);
    if (!url) continue;
    let host;
    try { host = new URL(url).hostname; } catch { toast("Use a valid app-store URL"); return; }
    if ((platform === "ios" && !["apps.apple.com", "itunes.apple.com"].includes(host)) || (platform === "android" && host !== "play.google.com") || !url.startsWith("https://")) {
      toast("Use an official HTTPS app-store URL"); return;
    }
    const previous = (lead.app_matches || []).find(m => m.platform === platform && m.url === url);
    apps.push(previous || { platform, url, name: lead.store_name || domain, confidence: "reviewed", evidence: reason });
  }
  if (status === "has_app" && !apps.length) { toast("Add an owned app link"); return; }
  if (status !== "has_app" && apps.length) { toast("Clear owned app links or select owned app"); return; }
  const overrides = ls.get(LS_KEYS.overrides, {});
  overrides[domain] = { ...overrides[domain], platform: value("platform"), status,
    has_app: status === "has_app" ? true : status === "no_app" ? false : null,
    location_relationship: value("location"),
    emails: addresses.map(address => (lead.emails || []).find(e => e.address === address) || { address, role: "unknown", source_url: "manual review" }),
    phones: numbers.map(number => (lead.phones || []).find(p => p.number === number) || { number, channel: "phone", source_url: "manual review" }),
    app_matches: apps, review_required: status === "app_unknown" || value("location") !== "local_contact" || !value("platform"),
    review_reason: reason, reviewed_at: new Date().toISOString(), qualification_confidence: "reviewed",
    lead_score: null, lead_tier: "?", score_components: {}, score_reasons: ["Manually corrected — automated score cleared"] };
  ls.set(LS_KEYS.overrides, overrides);
  toast("Reviewed facts saved locally"); renderStats(); renderTable();
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

  // Focus: top-10 queue
  document.getElementById("btn-focus").addEventListener("click", (e) => {
    state.filters.focus = !state.filters.focus;
    e.currentTarget.classList.toggle("on", state.filters.focus);
    saveFilters();
    renderTable();
  });

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
  document.getElementById("btn-focus").classList.toggle("on", !!state.filters.focus);
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
    if (!confirm("Erase all pipeline stages, dismissed leads, and notes? This can't be undone.")) return;
    ls.del(LS_KEYS.pipeline);
    ls.del(LS_KEYS.contacted);
    ls.del(LS_KEYS.hidden);
    ls.del(LS_KEYS.notes);
    ls.del(LS_KEYS.overrides);
    renderStats();
    renderTable();
    toast("Personal data cleared");
  });
  document.getElementById("btn-restore-hidden").addEventListener("click", () => {
    ls.del(LS_KEYS.hidden);
    renderStats();
    renderTable();
    openSettings();
    toast("Dismissed leads restored");
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
  document.getElementById("tpl-whatsapp").value =
    ls.get(LS_KEYS.templateWa, DEFAULT_TEMPLATES.whatsapp);
  document.getElementById("tpl-signature").value =
    ls.get(LS_KEYS.templateSig, DEFAULT_TEMPLATES.sig);
  document.getElementById("tpl-portfolio").value =
    ls.get(LS_KEYS.templatePortfolio, DEFAULT_TEMPLATES.portfolio);
  const hiddenN = Object.keys(ls.get(LS_KEYS.hidden, {})).length;
  document.getElementById("btn-restore-hidden").textContent = `Restore dismissed (${hiddenN})`;
  document.getElementById("settings-modal").hidden = false;
}

function saveSettings() {
  ls.set(LS_KEYS.templateNoApp, document.getElementById("tpl-no-app").value);
  ls.set(LS_KEYS.templateHasApp, document.getElementById("tpl-has-app").value);
  ls.set(LS_KEYS.templateWa, document.getElementById("tpl-whatsapp").value);
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
    schema: 2,
    exported_at: new Date().toISOString(),
    pipeline: ls.get(LS_KEYS.pipeline, {}),
    contacted: ls.get(LS_KEYS.contacted, {}),
    hidden: ls.get(LS_KEYS.hidden, {}),
    overrides: ls.get(LS_KEYS.overrides, {}),
    notes: ls.get(LS_KEYS.notes, {}),
    templates: {
      noApp: ls.get(LS_KEYS.templateNoApp),
      hasApp: ls.get(LS_KEYS.templateHasApp),
      whatsapp: ls.get(LS_KEYS.templateWa),
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
    if (blob.pipeline) ls.set(LS_KEYS.pipeline, blob.pipeline);
    else if (blob.contacted) ls.set(LS_KEYS.contacted, blob.contacted);
    if (blob.hidden) ls.set(LS_KEYS.hidden, blob.hidden);
    if (blob.overrides) ls.set(LS_KEYS.overrides, blob.overrides);
    if (blob.notes) ls.set(LS_KEYS.notes, blob.notes);
    if (blob.templates?.noApp) ls.set(LS_KEYS.templateNoApp, blob.templates.noApp);
    if (blob.templates?.hasApp) ls.set(LS_KEYS.templateHasApp, blob.templates.hasApp);
    if (blob.templates?.whatsapp) ls.set(LS_KEYS.templateWa, blob.templates.whatsapp);
    if (blob.templates?.sig) ls.set(LS_KEYS.templateSig, blob.templates.sig);
    if (blob.templates?.portfolio) ls.set(LS_KEYS.templatePortfolio, blob.templates.portfolio);
    migratePersonal();
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
  const pipe = ls.get(LS_KEYS.pipeline, {});
  const cols = ["priority", "lead_score", "lead_tier", "status", "domain", "store_name", "platform", "qualification_confidence", "lifecycle", "archive_reason", "review_reason", "product_count_kind",
                "product_count", "emails", "phones", "stage", "followup",
                "woo_score", "lb_score", "first_seen", "last_checked",
                "ios_url", "android_url", "ios_updated", "android_updated"];
  const head = cols.join(",");
  const rows = state.filtered.map(L => {
    const ios = (L.app_matches || []).find(m => m.platform === "ios") || {};
    const and = (L.app_matches || []).find(m => m.platform === "android") || {};
    const flat = {
      ...L,
      priority: priorityOf(L),
      emails: (L.emails || []).map(e => e.address).join(";"),
      phones: (L.phones || []).map(p => p.number).join(";"),
      stage: pipe[L.domain]?.stage || "",
      followup: pipe[L.domain]?.followup || "",
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
    setStage(lead.domain, "contacted");
  } else if (e.key === "w") {
    copyToClipboard(buildWhatsApp(lead));
  } else if (e.key === "d") {
    toggleHidden(lead.domain);
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
  const newest = {};
  for (const m of lead.app_matches || []) {
    if (m.last_updated && (!newest[m.platform] || m.last_updated > newest[m.platform])) newest[m.platform] = m.last_updated;
  }
  const dates = Object.values(newest);
  if (!dates.length) return null;
  const t = Date.parse(dates.sort()[0]);
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
    no_app: "no app found", has_app: "has app", app_unknown: "unknown",
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

function showToast(message) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.remove("show"), 1500);
}

function copyToClipboard(text, message) {
  const msg = message || "Copied to clipboard";
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast(msg)).catch(() => showToast("Copy failed"));
    return;
  }
  // Fallback
  const ta = document.createElement("textarea");
  ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); showToast(msg); }
  catch { showToast("Copy failed"); }
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

function toast(msg) {
  showToast(msg);
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function safeUrl(value) {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href : "#"; }
  catch { return "#"; }
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
