"""
Flask Web Application
AI-Based Phishing URL Detection with Explainable Security Analysis
"""

import json
import os
import sys
import traceback
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "src"))

from feature_extractor import extract_features, FEATURE_NAMES
from explainer import PhishingExplainer

app = Flask(__name__)
CORS(app)

# ── Lazy-load models / explainer ──────────────────────────────────────────────
_explainer: PhishingExplainer = None
_model_metrics: dict = {}


def _get_explainer() -> PhishingExplainer:
    global _explainer
    if _explainer is None:
        model_path = ROOT / "models" / "ensemble.pkl"
        if not model_path.exists():
            _train_models()
        _explainer = PhishingExplainer(model_name="ensemble")
    return _explainer


def _get_metrics() -> dict:
    global _model_metrics
    if not _model_metrics:
        metrics_path = ROOT / "models" / "metrics.json"
        if metrics_path.exists():
            with open(metrics_path) as f:
                _model_metrics = json.load(f)
    return _model_metrics


def _train_models():
    """Train models if they don't exist yet."""
    print("[*] Models not found — starting training …")
    from train_model import train
    train()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    metrics = _get_metrics()
    ensemble_acc = None
    if metrics.get("ensemble"):
        ensemble_acc = metrics["ensemble"].get("accuracy")
    return render_template("index.html", accuracy=ensemble_acc)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze
    Body: { "url": "https://example.com" }
    Returns full analysis JSON.
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # 1. Extract features
        features = extract_features(url)

        # 2. Explain (includes prediction)
        explainer   = _get_explainer()
        explanation = explainer.explain(features)

        prob  = explanation["prediction_prob"]
        label = 1 if prob >= 0.5 else 0

        # 3. Build risk level
        if label == 1:
            risk_level = "high"
            verdict    = "PHISHING"
        elif prob >= 0.35:
            risk_level = "medium"
            verdict    = "SUSPICIOUS"
        else:
            risk_level = "low"
            verdict    = "LEGITIMATE"

        # 4. Collect flagged features (red-flag summary)
        flags = _build_flags(features, url)

        return jsonify({
            "url":           url,
            "label":         label,
            "verdict":       verdict,
            "probability":   round(prob * 100, 2),
            "risk_level":    risk_level,
            "features":      features,
            "explanation":   explanation,
            "flags":         flags,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/report", methods=["POST"])
def generate_report():
    """
    POST /report
    Body: same as /analyze — generates and returns a PDF report.
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        from report_generator import generate_pdf_report

        features    = extract_features(url)
        explainer   = _get_explainer()
        explanation = explainer.explain(features)

        prob  = explanation["prediction_prob"]
        label = 1 if prob >= 0.5 else 0

        pdf_path = generate_pdf_report(
            url=url,
            label=label,
            prob=prob,
            features=features,
            shap_explanation=explanation,
            chart_b64=explanation.get("chart_b64"),
        )

        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="phishing_analysis_report.pdf",
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/metrics")
def metrics():
    """GET /metrics — return stored model performance metrics."""
    return jsonify(_get_metrics())


@app.route("/global-importance")
def global_importance():
    """GET /global-importance — return base64 global feature importance chart."""
    try:
        explainer = _get_explainer()
        chart     = explainer.global_importance_chart()
        return jsonify({"chart_b64": chart})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "models_loaded": _explainer is not None})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_flags(features: dict, url: str) -> list:
    """Build a human-readable list of red-flag findings."""
    flags = []

    if features["has_ip_address"]:
        flags.append({
            "severity": "high",
            "message":  "Domain is a raw IP address — legitimate sites use domain names",
        })
    if not features["has_https"]:
        flags.append({
            "severity": "medium",
            "message":  "URL does not use HTTPS — data could be intercepted",
        })
    if features["is_shortener"]:
        flags.append({
            "severity": "medium",
            "message":  "URL uses a known shortening service — destination is obscured",
        })
    if features["has_phishing_keyword"]:
        flags.append({
            "severity": "high",
            "message":  f"URL contains {features['phishing_keyword_count']} phishing-related keyword(s)",
        })
    if features["num_at_symbols"] > 0:
        flags.append({
            "severity": "high",
            "message":  "@ symbol in URL — used to hide the real destination",
        })
    if features["subdomain_count"] >= 3:
        flags.append({
            "severity": "medium",
            "message":  f"Excessive subdomains ({features['subdomain_count']}) — spoofing technique",
        })
    if features["url_length"] > 75:
        flags.append({
            "severity": "low",
            "message":  f"Unusually long URL ({features['url_length']} chars) — may be obfuscating intent",
        })
    if features["double_slash_redirect"]:
        flags.append({
            "severity": "high",
            "message":  "Double-slash redirect detected in path — common evasion trick",
        })
    if features["prefix_suffix_hyphen"]:
        flags.append({
            "severity": "medium",
            "message":  "Domain starts or ends with a hyphen — invalid and suspicious",
        })
    if features["path_extension_suspicious"]:
        flags.append({
            "severity": "medium",
            "message":  "Path ends with a suspicious file extension (.exe, .php, etc.)",
        })
    if features["suspicious_tld"]:
        flags.append({
            "severity": "low",
            "message":  "Top-level domain is not among common trusted TLDs",
        })
    if features["entropy"] > 4.5:
        flags.append({
            "severity": "low",
            "message":  f"High URL entropy ({features['entropy']}) — may indicate random/obfuscated domain",
        })

    return flags


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Phishing URL Detection")
    print("  http://127.0.0.1:5000")
    print("=" * 60)

    # Pre-load model on startup
    try:
        _get_explainer()
        print("[+] Model loaded successfully.")
    except Exception as e:
        print(f"[!] Model load failed: {e}")
        print("[*] Models will be trained on first request.")

    app.run(debug=True, host="0.0.0.0", port=5000)
