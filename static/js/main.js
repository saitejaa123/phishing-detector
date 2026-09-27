/* ══════════════════════════════════════════════════════
   AI Phishing URL Detector — Frontend JS
   ══════════════════════════════════════════════════════ */

"use strict";

// ── Globals ──────────────────────────────────────────────────────────────────
let lastResult = null;

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadMetrics();

  // Allow Enter key in the input box
  const input = document.getElementById("url-input");
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") analyseURL();
    });
  }
});

// ── Set URL from example buttons ─────────────────────────────────────────────
function setURL(url) {
  const input = document.getElementById("url-input");
  if (input) {
    input.value = url;
    input.focus();
  }
}

// ── Main analysis function ────────────────────────────────────────────────────
async function analyseURL() {
  const input = document.getElementById("url-input");
  const url   = (input?.value || "").trim();

  if (!url) {
    showToast("Please enter a URL to analyse.", "error");
    return;
  }

  // Show spinner
  setLoading(true);
  hidePanel();

  try {
    const resp = await fetch("/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });

    const data = await resp.json();

    if (!resp.ok || data.error) {
      throw new Error(data.error || "Server error");
    }

    lastResult = data;
    renderResult(data);

  } catch (err) {
    showToast(`Analysis failed: ${err.message}`, "error");
  } finally {
    setLoading(false);
  }
}

// ── Render full result ────────────────────────────────────────────────────────
function renderResult(data) {
  const panel = document.getElementById("result-panel");
  panel.classList.remove("hidden");
  panel.scrollIntoView({ behavior: "smooth", block: "start" });

  renderVerdict(data);
  renderFlags(data.flags || []);
  renderSHAPChart(data.explanation?.chart_b64);
  renderTopFeatures(data.explanation?.top_contributors || []);
  renderFeaturesTable(data.features, data.explanation?.shap_values || []);
}

// ── Verdict banner ────────────────────────────────────────────────────────────
function renderVerdict(data) {
  const banner    = document.getElementById("verdict-banner");
  const iconEl    = document.getElementById("verdict-icon");
  const labelEl   = document.getElementById("verdict-label");
  const urlEl     = document.getElementById("verdict-url");
  const probText  = document.getElementById("prob-text");
  const circleFill= document.getElementById("circle-fill");

  // Risk class
  banner.className = `verdict-banner ${data.risk_level}`;

  // Icon
  const icons = { high: "🚨", medium: "⚠️", low: "✅" };
  iconEl.textContent = icons[data.risk_level] || "ℹ️";

  // Label
  labelEl.textContent = data.verdict;

  // URL (truncated)
  const displayUrl = data.url.length > 80 ? data.url.slice(0, 77) + "…" : data.url;
  urlEl.textContent = displayUrl;

  // Probability circle
  const pct = Math.round(data.probability);
  probText.textContent = `${pct}%`;

  const colorMap = { high: "#f85149", medium: "#d29922", low: "#3fb950" };
  circleFill.style.stroke = colorMap[data.risk_level] || "#58a6ff";
  circleFill.style.strokeDasharray = `${pct}, 100`;
}

// ── Security flags ────────────────────────────────────────────────────────────
function renderFlags(flags) {
  const container = document.getElementById("flags-list");
  const section   = document.getElementById("flags-section");
  container.innerHTML = "";

  if (!flags.length) {
    container.innerHTML = `<p class="no-flags">✅ No specific security flags detected.</p>`;
    return;
  }

  flags.forEach(f => {
    const div = document.createElement("div");
    div.className = `flag-item ${f.severity}`;
    div.innerHTML = `
      <span class="flag-sev">${f.severity}</span>
      <span>${escapeHtml(f.message)}</span>`;
    container.appendChild(div);
  });
}

// ── SHAP chart ────────────────────────────────────────────────────────────────
function renderSHAPChart(b64) {
  const img = document.getElementById("shap-chart");
  if (b64 && img) {
    img.src = `data:image/png;base64,${b64}`;
  }
}

// ── Top features cards ────────────────────────────────────────────────────────
function renderTopFeatures(topItems) {
  const grid = document.getElementById("top-features");
  grid.innerHTML = "";

  topItems.forEach(item => {
    const card = document.createElement("div");
    card.className = "feature-card";
    const shapDir  = item.shap_value > 0 ? "positive" : "negative";
    const shapSign = item.shap_value > 0 ? "+" : "";
    card.innerHTML = `
      <div class="fc-name">${escapeHtml(item.feature)}</div>
      <div class="fc-value">${item.feature_value}</div>
      <div class="fc-shap ${shapDir}">SHAP ${shapSign}${item.shap_value.toFixed(4)}</div>`;
    grid.appendChild(card);
  });
}

// ── All features table ────────────────────────────────────────────────────────
function renderFeaturesTable(features, shapValues) {
  const tbody = document.getElementById("features-tbody");
  tbody.innerHTML = "";

  // Build a SHAP lookup map
  const shapMap = {};
  shapValues.forEach(s => { shapMap[s.feature] = s.shap_value; });

  Object.entries(features).forEach(([name, val]) => {
    const sv    = shapMap[name] !== undefined ? shapMap[name] : null;
    const svStr = sv !== null
      ? `<span class="${sv > 0 ? "shap-pos" : "shap-neg"}">${sv > 0 ? "+" : ""}${sv.toFixed(5)}</span>`
      : "—";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(name)}</td>
      <td>${val}</td>
      <td>${svStr}</td>`;
    tbody.appendChild(tr);
  });
}

// ── Download PDF report ───────────────────────────────────────────────────────
async function downloadReport() {
  const input = document.getElementById("url-input");
  const url   = (input?.value || "").trim();
  if (!url) {
    showToast("No URL to report on.", "error");
    return;
  }

  showToast("Generating PDF report…");

  try {
    const resp = await fetch("/report", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || "Failed to generate report");
    }

    const blob = await resp.blob();
    const link = document.createElement("a");
    link.href  = URL.createObjectURL(blob);
    link.download = "phishing_analysis_report.pdf";
    link.click();
    URL.revokeObjectURL(link.href);
    showToast("Report downloaded.");

  } catch (err) {
    showToast(`Report error: ${err.message}`, "error");
  }
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function resetPanel() {
  hidePanel();
  const input = document.getElementById("url-input");
  if (input) { input.value = ""; input.focus(); }
  lastResult = null;
}

// ── Load model metrics ────────────────────────────────────────────────────────
async function loadMetrics() {
  const grid = document.getElementById("metrics-grid");
  if (!grid) return;

  try {
    const resp = await fetch("/metrics");
    if (!resp.ok) return;
    const data = await resp.json();

    const modelKeys = ["random_forest", "xgboost", "logistic_regression", "ensemble"];
    const labels    = {
      random_forest:        "Random Forest",
      xgboost:              "XGBoost",
      logistic_regression:  "Logistic Regression",
      ensemble:             "Ensemble (Voting)",
    };

    grid.innerHTML = "";
    let rendered = 0;

    modelKeys.forEach(key => {
      const m = data[key];
      if (!m) return;
      const card = document.createElement("div");
      card.className = "metric-card";
      const cv = m.cv_mean
        ? `<div class="metric-auc">CV Accuracy: ${(m.cv_mean * 100).toFixed(1)}% ± ${(m.cv_std * 100).toFixed(1)}%</div>`
        : "";
      card.innerHTML = `
        <div class="metric-model">${labels[key] || key}</div>
        <div class="metric-acc">${(m.accuracy * 100).toFixed(1)}%</div>
        <div class="metric-auc">AUC-ROC: ${(m.auc_roc * 100).toFixed(1)}%</div>
        ${cv}`;
      grid.appendChild(card);
      rendered++;
    });

    if (rendered === 0) {
      grid.innerHTML = `<p class="loading-txt">Run the training script to see metrics.</p>`;
    }

  } catch (_) {
    if (grid) grid.innerHTML = `<p class="loading-txt">Metrics unavailable.</p>`;
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function setLoading(on) {
  const btnText    = document.getElementById("btn-text");
  const btnSpinner = document.getElementById("btn-spinner");
  const btn        = document.getElementById("analyse-btn");
  if (on) {
    btnText?.classList.add("hidden");
    btnSpinner?.classList.remove("hidden");
    if (btn) btn.disabled = true;
  } else {
    btnText?.classList.remove("hidden");
    btnSpinner?.classList.add("hidden");
    if (btn) btn.disabled = false;
  }
}

function hidePanel() {
  document.getElementById("result-panel")?.classList.add("hidden");
}

let toastTimer = null;
function showToast(msg, type = "") {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.className   = `toast ${type}`;
  toast.classList.remove("hidden");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
