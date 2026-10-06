/* ══════════════════════════════════════════════════════
   PhishGuard AI — Frontend JS
   Handles Quick Scan, Deep Scan, all novelty panels,
   session history dashboard, and PDF download.
   ══════════════════════════════════════════════════════ */
"use strict";

let lastResult = null;

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadMetrics();
  loadHistory();
  document.getElementById("url-input").addEventListener("keydown", e => {
    if (e.key === "Enter") runScan("quick");
  });
});

function setURL(url) {
  document.getElementById("url-input").value = url;
  document.getElementById("url-input").focus();
}

// ══════════════════════════════════════════════════════════════════════════════
//  SCAN ENTRY POINTS
// ══════════════════════════════════════════════════════════════════════════════

async function runScan(mode) {
  const url = (document.getElementById("url-input").value || "").trim();
  if (!url) { showToast("Please enter a URL first.", "error"); return; }

  setLoading(mode, true);
  hidePanel();

  try {
    const endpoint = mode === "deep" ? "/deep-scan" : "/analyze";
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();
    if (!resp.ok || data.error) throw new Error(data.error || "Server error");

    lastResult = data;
    renderResult(data, mode);
    loadHistory();   // refresh history table

  } catch (err) {
    showToast(`Scan failed: ${err.message}`, "error");
  } finally {
    setLoading(mode, false);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RENDER — Main result
// ══════════════════════════════════════════════════════════════════════════════

function renderResult(data, mode) {
  const panel = document.getElementById("result-panel");
  panel.classList.remove("hidden");
  panel.scrollIntoView({ behavior: "smooth", block: "start" });

  renderVerdict(data, mode);
  renderScoreBreakdown(data, mode);
  renderFlags(data.flags || []);
  renderSHAPChart(data.explanation?.chart_b64);
  renderTopFeatures(data.explanation?.top_contributors || []);
  renderFeaturesTable(data.features, data.explanation?.shap_values || []);

  // Novelty panels — only for deep scan
  if (mode === "deep") {
    renderDNS(data.dns_intelligence);
    renderTypo(data.typosquatting);
    renderIntel(data.threat_intel);
    renderMutations(data.mutation_analysis);
  } else {
    // Hide novelty sections
    ["dns-section","typo-section","intel-section","mutation-section"]
      .forEach(id => document.getElementById(id)?.classList.add("hidden"));
    document.getElementById("score-breakdown")?.classList.add("hidden");
  }
}

// ── Verdict banner ────────────────────────────────────────────────────────────
function renderVerdict(data, mode) {
  const banner     = document.getElementById("verdict-banner");
  const iconEl     = document.getElementById("verdict-icon");
  const labelEl    = document.getElementById("verdict-label");
  const urlEl      = document.getElementById("verdict-url");
  const probText   = document.getElementById("prob-text");
  const circleFill = document.getElementById("circle-fill");
  const probLabel  = document.getElementById("prob-label-txt");
  const scanBadge  = document.getElementById("scan-type-badge");

  banner.className = `verdict-banner ${data.risk_level}`;
  iconEl.textContent = { high:"🚨", medium:"⚠️", low:"✅" }[data.risk_level] || "ℹ️";
  labelEl.textContent = data.verdict;
  urlEl.textContent = data.url.length > 80 ? data.url.slice(0,77)+"…" : data.url;

  const displayPct = mode === "deep"
    ? Math.round(data.composite_score ?? data.probability)
    : Math.round(data.probability);

  probText.textContent = `${displayPct}%`;
  probLabel.textContent = mode === "deep" ? "Composite Risk Score" : "Phishing Probability";
  scanBadge.textContent = mode === "deep" ? "⚡ Deep Scan" : "Quick Scan";

  const colorMap = { high: "#f85149", medium: "#d29922", low: "#3fb950" };
  circleFill.style.stroke = colorMap[data.risk_level] || "#58a6ff";
  circleFill.style.strokeDasharray = `${displayPct},100`;
}

// ── Score breakdown (deep only) ───────────────────────────────────────────────
function renderScoreBreakdown(data, mode) {
  const section = document.getElementById("score-breakdown");
  if (mode !== "deep" || !data.score_breakdown) {
    section.classList.add("hidden"); return;
  }
  section.classList.remove("hidden");
  const bd = data.score_breakdown;

  const cards = [
    { label: "ML Model",       val: bd.ml_model,      key: "ml_model"      },
    { label: "DNS / WHOIS",    val: bd.dns_whois,      key: "dns_whois"     },
    { label: "Threat Intel",   val: bd.threat_intel,   key: "threat_intel"  },
    { label: "Typosquatting",  val: bd.typosquatting,  key: "typosquatting" },
    { label: "Composite",      val: bd.composite,      key: "composite",  composite: true },
  ];

  const grid = document.getElementById("score-grid");
  grid.innerHTML = "";
  cards.forEach(c => {
    const colorClass = c.val >= 60 ? "danger" : c.val >= 35 ? "warn" : "safe";
    const card = document.createElement("div");
    card.className = "score-card" + (c.composite ? " composite" : "");
    card.innerHTML = `
      <div class="sc-label">${c.label}</div>
      <div class="sc-value ${c.composite ? "purple" : colorClass}">${c.val.toFixed(1)}</div>`;
    grid.appendChild(card);
  });
}

// ── Security flags ────────────────────────────────────────────────────────────
function renderFlags(flags) {
  const container = document.getElementById("flags-list");
  container.innerHTML = "";
  if (!flags.length) {
    container.innerHTML = `<p class="no-flags">✅ No security flags detected.</p>`;
    return;
  }
  flags.forEach(f => {
    const div = document.createElement("div");
    div.className = `flag-item ${f.severity}`;
    div.innerHTML = `<span class="flag-sev">${f.severity}</span><span>${escHtml(f.message)}</span>`;
    container.appendChild(div);
  });
}

// ── SHAP chart ────────────────────────────────────────────────────────────────
function renderSHAPChart(b64) {
  const img = document.getElementById("shap-chart");
  if (b64 && img) img.src = `data:image/png;base64,${b64}`;
}

// ── Top feature cards ─────────────────────────────────────────────────────────
function renderTopFeatures(items) {
  const grid = document.getElementById("top-features");
  grid.innerHTML = "";
  items.forEach(item => {
    const card = document.createElement("div");
    card.className = "feature-card";
    const dir  = item.shap_value > 0 ? "positive" : "negative";
    const sign = item.shap_value > 0 ? "+" : "";
    card.innerHTML = `
      <div class="fc-name">${escHtml(item.feature)}</div>
      <div class="fc-value">${item.feature_value}</div>
      <div class="fc-shap ${dir}">SHAP ${sign}${item.shap_value.toFixed(4)}</div>`;
    grid.appendChild(card);
  });
}

// ── All features table ────────────────────────────────────────────────────────
function renderFeaturesTable(features, shapValues) {
  const tbody  = document.getElementById("features-tbody");
  tbody.innerHTML = "";
  const shapMap = {};
  shapValues.forEach(s => { shapMap[s.feature] = s.shap_value; });

  Object.entries(features).forEach(([name, val]) => {
    const sv  = shapMap[name] !== undefined ? shapMap[name] : null;
    const svStr = sv !== null
      ? `<span class="${sv>0?"shap-pos":"shap-neg"}">${sv>0?"+":""}${sv.toFixed(5)}</span>`
      : "—";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escHtml(name)}</td><td>${val}</td><td>${svStr}</td>`;
    tbody.appendChild(tr);
  });
}

// ══════════════════════════════════════════════════════════════════════════════
//  NOVELTY PANEL RENDERERS
// ══════════════════════════════════════════════════════════════════════════════

// ── DNS & WHOIS ───────────────────────────────────────────────────────────────
function renderDNS(dns) {
  const section = document.getElementById("dns-section");
  if (!dns) { section.classList.add("hidden"); return; }
  section.classList.remove("hidden");

  const grid = document.getElementById("dns-grid");
  grid.innerHTML = "";

  const reg  = dns.registration_info || {};
  const di   = dns.dns_info          || {};
  const ssl  = dns.ssl_info          || {};

  const ageVal = reg.domain_age_days != null ? `${reg.domain_age_days} days` : "Unknown";
  const ageCls = reg.domain_age_days < 30 ? "danger"
               : reg.domain_age_days < 180 ? "warn" : "safe";

  const cards = [
    { label: "Domain Age",         val: ageVal,                          cls: ageCls },
    { label: "Registered",         val: reg.registered_date || "Unknown",cls: "" },
    { label: "Registrar",          val: reg.registrar       || "Unknown",cls: "" },
    { label: "MX Record",          val: di.has_mx_record ? "Present ✓" : "Missing ✗",
                                   cls: di.has_mx_record ? "safe" : "warn" },
    { label: "A Records",          val: di.num_a_records ?? "—",         cls: "" },
    { label: "Reverse DNS",        val: di.reverse_match ? "Match ✓" : "Mismatch ✗",
                                   cls: di.reverse_match ? "safe" : "warn" },
    { label: "SSL Certificate",    val: ssl.valid ? `Valid (${ssl.issuer || "?"})` : "Invalid / None",
                                   cls: ssl.valid ? "safe" : "danger" },
    { label: "Cert Issued",        val: ssl.issued_days_ago != null ? `${ssl.issued_days_ago} days ago` : "N/A",
                                   cls: (ssl.issued_days_ago != null && ssl.issued_days_ago < 30) ? "warn" : "" },
    { label: "DNS Risk Score",     val: `${dns.dns_risk_score ?? 0}/100`,
                                   cls: dns.dns_risk_score >= 40 ? "danger" : dns.dns_risk_score >= 20 ? "warn" : "safe" },
  ];

  cards.forEach(c => {
    const card = document.createElement("div");
    card.className = "dns-card";
    card.innerHTML = `
      <div class="dns-card-label">${c.label}</div>
      <div class="dns-card-value ${c.cls}">${escHtml(String(c.val))}</div>`;
    grid.appendChild(card);
  });

  // Risk indicators
  const indContainer = document.getElementById("dns-indicators");
  indContainer.innerHTML = "";
  const indicators = dns.risk_indicators || [];
  indicators.forEach(ind => {
    const div = document.createElement("div");
    div.className = `ri-item ${ind.severity}`;
    div.innerHTML = `<span class="ri-sev">${ind.severity}</span><span>${escHtml(ind.detail)}</span>`;
    indContainer.appendChild(div);
  });
}

// ── Typosquatting ─────────────────────────────────────────────────────────────
function renderTypo(typo) {
  const section = document.getElementById("typo-section");
  if (!typo) { section.classList.add("hidden"); return; }
  section.classList.remove("hidden");

  const container = document.getElementById("typo-result");
  container.innerHTML = "";

  if (typo.typosquat_risk === "none" || !typo.impersonated_brand) {
    container.innerHTML = `<p class="typo-no-risk">✅ No brand impersonation or typosquatting patterns detected.</p>`;
    return;
  }

  const score    = typo.similarity_score || 0;
  const barColor = score >= 80 ? "#f85149" : score >= 60 ? "#d29922" : "#3fb950";
  const attacks  = (typo.attack_types || []).map(a =>
    `<span class="attack-tag">${escHtml(a)}</span>`).join("");

  const findings = (typo.findings || []).map(f => `
    <div class="ri-item high">
      <span class="ri-sev">${escHtml(f.attack)}</span>
      <span>${escHtml(f.detail)}</span>
    </div>`).join("");

  container.innerHTML = `
    <div class="typo-card">
      <div class="typo-brand">
        Potential impersonation of <strong style="color:var(--red)">${escHtml(typo.impersonated_brand)}</strong>
      </div>
      <div class="typo-score-bar-wrap">
        <div class="typo-score-label">Similarity Score: <strong>${score}%</strong></div>
        <div class="typo-score-bar">
          <div class="typo-score-fill" style="width:${score}%;background:${barColor}"></div>
        </div>
      </div>
      <div class="attack-tags">${attacks}</div>
      <div class="risk-indicators" style="margin-top:.5rem">${findings}</div>
    </div>`;
}

// ── Threat Intelligence ───────────────────────────────────────────────────────
function renderIntel(intel) {
  const section = document.getElementById("intel-section");
  if (!intel) { section.classList.add("hidden"); return; }
  section.classList.remove("hidden");

  const container = document.getElementById("intel-result");
  const score     = intel.threat_score || 0;
  const scoreCls  = score >= 60 ? "danger" : score >= 30 ? "warn" : "safe";

  const feedChips = (intel.feed_matches || []).map(f =>
    `<span class="feed-chip">🔴 ${escHtml(f)}</span>`).join("");

  const findings = (intel.intel_findings || []).map(f => `
    <div class="ri-item ${f.severity}">
      <span class="ri-sev">${escHtml(f.source || f.severity)}</span>
      <span>${escHtml(f.detail)}</span>
    </div>`).join("");

  container.innerHTML = `
    <div class="intel-score-row">
      <div class="intel-score-big ${scoreCls}">${score}<span style="font-size:1rem;font-weight:400">/100</span></div>
      <div>
        <div style="font-weight:600;margin-bottom:.3rem">Threat Score</div>
        ${feedChips ? `<div class="intel-feed-chips">${feedChips}</div>` : `<div style="color:var(--green);font-size:.84rem">✅ Not listed in live feeds</div>`}
      </div>
    </div>
    <div class="risk-indicators">${findings}</div>`;
}

// ── Mutation Analysis ─────────────────────────────────────────────────────────
function renderMutations(mut) {
  const section = document.getElementById("mutation-section");
  if (!mut) { section.classList.add("hidden"); return; }
  section.classList.remove("hidden");

  // Summary box
  document.getElementById("mutation-summary").innerHTML = `
    <strong>${mut.attack_surface}</strong> of <strong>${mut.total_mutations}</strong>
    generated attack mutations score as high-risk.
    Max mutation score: <strong style="color:var(--orange)">${mut.max_mutation_score}%</strong>.
    <br/><span style="color:var(--text2);font-size:.82rem">${escHtml(mut.summary || "")}</span>`;

  // Table
  const tbody = document.getElementById("mutation-tbody");
  tbody.innerHTML = "";
  (mut.mutations || []).forEach(m => {
    const tr = document.createElement("tr");
    const scoreColor = m.risk_score >= 70 ? "var(--red)"
                     : m.risk_score >= 40 ? "var(--yellow)" : "var(--green)";
    tr.innerHTML = `
      <td title="${escHtml(m.url)}">${escHtml(m.url.length > 55 ? m.url.slice(0,52)+"…" : m.url)}</td>
      <td>${escHtml(m.category)}</td>
      <td style="color:${scoreColor};font-weight:600">${m.risk_score}%</td>
      <td><span class="risk-pill ${m.risk_level}">${m.risk_level}</span></td>`;
    tbody.appendChild(tr);
  });
}

// ══════════════════════════════════════════════════════════════════════════════
//  SESSION HISTORY
// ══════════════════════════════════════════════════════════════════════════════

async function loadHistory() {
  try {
    const resp = await fetch("/history");
    if (!resp.ok) return;
    const data = await resp.json();
    renderHistory(data);
  } catch (_) {}
}

function renderHistory(items) {
  const tbody = document.getElementById("history-tbody");
  tbody.innerHTML = "";

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="history-empty">No scans yet — analyse a URL above.</td></tr>`;
    updateRiskDist([]);
    return;
  }

  items.forEach((item, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${items.length - idx}</td>
      <td title="${escHtml(item.url)}">${escHtml(item.url.length > 55 ? item.url.slice(0,52)+"…" : item.url)}</td>
      <td><span class="verdict-chip ${item.risk_level}">${escHtml(item.verdict)}</span></td>
      <td style="font-weight:600;color:${riskColor(item.risk_level)}">${item.prob}%</td>
      <td style="color:var(--text3);font-size:.78rem">${escHtml(item.scanned_at)}</td>
      <td>${item.deep ? '<span class="deep-chip">Deep</span>' : '<span style="color:var(--text3);font-size:.75rem">Quick</span>'}</td>`;
    tbody.appendChild(tr);
  });

  updateRiskDist(items);
}

function updateRiskDist(items) {
  const bar   = document.getElementById("risk-dist-bar");
  const total = items.length || 1;
  const counts = { high: 0, medium: 0, low: 0 };
  items.forEach(i => { if (counts[i.risk_level] !== undefined) counts[i.risk_level]++; });

  bar.innerHTML = ["high","medium","low"].map(k => {
    const w = (counts[k] / total * 100).toFixed(1);
    return `<div class="rdb-seg ${k}" style="width:${w}%" title="${counts[k]} ${k}"></div>`;
  }).join("");
}

async function clearHistory() {
  await fetch("/history/clear", { method: "POST" });
  loadHistory();
}

// ══════════════════════════════════════════════════════════════════════════════
//  PDF REPORT
// ══════════════════════════════════════════════════════════════════════════════

async function downloadReport() {
  const url = (document.getElementById("url-input").value || "").trim();
  if (!url) { showToast("No URL to report on.", "error"); return; }
  showToast("Generating PDF report…");
  try {
    const resp = await fetch("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) throw new Error((await resp.json()).error || "Failed");
    const blob = await resp.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "phishing_analysis_report.pdf";
    link.click();
    URL.revokeObjectURL(link.href);
    showToast("Report downloaded.");
  } catch (err) {
    showToast(`Report error: ${err.message}`, "error");
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  MODEL METRICS
// ══════════════════════════════════════════════════════════════════════════════

async function loadMetrics() {
  const grid = document.getElementById("metrics-grid");
  if (!grid) return;
  try {
    const resp = await fetch("/metrics");
    if (!resp.ok) return;
    const data = await resp.json();
    const modelKeys = ["random_forest","xgboost","logistic_regression","ensemble"];
    const labels    = { random_forest:"Random Forest", xgboost:"XGBoost",
                        logistic_regression:"Logistic Regression", ensemble:"Ensemble (Voting)" };
    grid.innerHTML = "";
    modelKeys.forEach(key => {
      const m = data[key];
      if (!m) return;
      const cv = m.cv_mean
        ? `<div class="metric-auc">CV: ${(m.cv_mean*100).toFixed(1)}% ± ${(m.cv_std*100).toFixed(1)}%</div>` : "";
      const card = document.createElement("div");
      card.className = "metric-card";
      card.innerHTML = `
        <div class="metric-model">${labels[key]||key}</div>
        <div class="metric-acc">${(m.accuracy*100).toFixed(1)}%</div>
        <div class="metric-auc">AUC-ROC: ${(m.auc_roc*100).toFixed(1)}%</div>${cv}`;
      grid.appendChild(card);
    });
    if (!grid.children.length)
      grid.innerHTML = `<p class="loading-txt">Run train.py to see metrics.</p>`;
  } catch (_) {
    if (grid) grid.innerHTML = `<p class="loading-txt">Metrics unavailable.</p>`;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  UI HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function setLoading(mode, on) {
  const btnId     = mode === "deep" ? "deep-btn"     : "quick-btn";
  const textId    = mode === "deep" ? "deep-text"    : "quick-text";
  const spinnerId = mode === "deep" ? "deep-spinner" : "quick-spinner";
  const btn       = document.getElementById(btnId);
  if (on) {
    document.getElementById(textId)?.classList.add("hidden");
    document.getElementById(spinnerId)?.classList.remove("hidden");
    if (btn) btn.disabled = true;
    // Disable the other button too
    const otherId = mode === "deep" ? "quick-btn" : "deep-btn";
    const other   = document.getElementById(otherId);
    if (other) other.disabled = true;
  } else {
    document.getElementById(textId)?.classList.remove("hidden");
    document.getElementById(spinnerId)?.classList.add("hidden");
    if (btn) btn.disabled = false;
    const otherId = mode === "deep" ? "quick-btn" : "deep-btn";
    const other   = document.getElementById(otherId);
    if (other) other.disabled = false;
  }
}

function hidePanel() {
  document.getElementById("result-panel")?.classList.add("hidden");
}

function resetPanel() {
  hidePanel();
  document.getElementById("url-input").value = "";
  document.getElementById("url-input").focus();
  lastResult = null;
}

let toastTimer = null;
function showToast(msg, type = "") {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.classList.remove("hidden");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function riskColor(risk) {
  return risk === "high" ? "var(--red)" : risk === "medium" ? "var(--yellow)" : "var(--green)";
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
