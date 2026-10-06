"""
Flask Web Application
AI-Based Phishing URL Detection with Explainable Security Analysis
+ Novelty Features: DNS Intelligence, Typosquatting, Threat Intel, Mutation Analysis
"""

import json
import os
import sys
import traceback
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "src"))

from feature_extractor import extract_features, FEATURE_NAMES
from explainer import PhishingExplainer

app  = Flask(__name__)
CORS(app)

# ── In-memory session scan history (last 50 scans) ───────────────────────────
_scan_history: deque = deque(maxlen=50)

# ── Lazy-loaded singletons ────────────────────────────────────────────────────
_explainer: PhishingExplainer = None
_model_metrics: dict          = {}


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
        p = ROOT / "models" / "metrics.json"
        if p.exists():
            with open(p) as f:
                _model_metrics = json.load(f)
    return _model_metrics


def _train_models():
    print("[*] Models not found — starting training …")
    from train_model import train
    train()


# ── Shared helpers ────────────────────────────────────────────────────────────

def _build_flags(features: dict) -> list:
    flags = []
    if features["has_ip_address"]:
        flags.append({"severity": "high",
                      "message": "Domain is a raw IP address"})
    if not features["has_https"]:
        flags.append({"severity": "medium",
                      "message": "URL does not use HTTPS"})
    if features["is_shortener"]:
        flags.append({"severity": "medium",
                      "message": "URL uses a known shortening service"})
    if features["has_phishing_keyword"]:
        flags.append({"severity": "high",
                      "message": f"URL contains {features['phishing_keyword_count']} phishing keyword(s)"})
    if features["num_at_symbols"] > 0:
        flags.append({"severity": "high",
                      "message": "@ symbol in URL — credential redirect trick"})
    if features["subdomain_count"] >= 3:
        flags.append({"severity": "medium",
                      "message": f"Excessive subdomains ({features['subdomain_count']})"})
    if features["url_length"] > 75:
        flags.append({"severity": "low",
                      "message": f"Unusually long URL ({features['url_length']} chars)"})
    if features["double_slash_redirect"]:
        flags.append({"severity": "high",
                      "message": "Double-slash redirect in path"})
    if features["prefix_suffix_hyphen"]:
        flags.append({"severity": "medium",
                      "message": "Domain starts or ends with a hyphen"})
    if features["path_extension_suspicious"]:
        flags.append({"severity": "medium",
                      "message": "Path ends with a suspicious file extension"})
    if features["suspicious_tld"]:
        flags.append({"severity": "low",
                      "message": "TLD is not among common trusted TLDs"})
    if features["entropy"] > 4.5:
        flags.append({"severity": "low",
                      "message": f"High URL entropy ({features['entropy']}) — possible obfuscation"})
    return flags


def _verdict_from_prob(prob: float):
    if prob >= 0.5:
        return 1, "PHISHING", "high"
    if prob >= 0.35:
        return 0, "SUSPICIOUS", "medium"
    return 0, "LEGITIMATE", "low"


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Core
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    metrics      = _get_metrics()
    ensemble_acc = metrics.get("ensemble", {}).get("accuracy")
    return render_template("index.html", accuracy=ensemble_acc)


@app.route("/analyze", methods=["POST"])
def analyze():
    """Standard ML analysis (fast, no live DNS)."""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        features    = extract_features(url)
        explainer   = _get_explainer()
        explanation = explainer.explain(features)
        prob        = explanation["prediction_prob"]
        label, verdict, risk_level = _verdict_from_prob(prob)
        flags       = _build_flags(features)

        result = {
            "url":         url,
            "label":       label,
            "verdict":     verdict,
            "probability": round(prob * 100, 2),
            "risk_level":  risk_level,
            "features":    features,
            "explanation": explanation,
            "flags":       flags,
            "scanned_at":  datetime.now(timezone.utc).isoformat(),
        }

        # Add to session history
        _scan_history.appendleft({
            "url":        url,
            "verdict":    verdict,
            "risk_level": risk_level,
            "prob":       round(prob * 100, 1),
            "scanned_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Novelty Features
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/deep-scan", methods=["POST"])
def deep_scan():
    """
    POST /deep-scan
    Runs all 4 novelty modules on top of the standard ML analysis.
    Returns comprehensive security intelligence report.
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        import tldextract
        parse_url = url if "://" in url else "http://" + url
        ext       = tldextract.extract(parse_url)
        domain    = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        # ── Module 1: Standard ML ────────────────────────────────────────────
        features    = extract_features(url)
        explainer   = _get_explainer()
        explanation = explainer.explain(features)
        prob        = explanation["prediction_prob"]
        label, verdict, risk_level = _verdict_from_prob(prob)
        flags       = _build_flags(features)

        # ── Module 2: DNS & WHOIS Intelligence ──────────────────────────────
        dns_result = {}
        try:
            from dns_inspector import inspect_domain
            dns_result = inspect_domain(domain)
        except Exception as e:
            dns_result = {"error": str(e), "dns_risk_score": 0}

        # ── Module 3: Typosquatting Detection ────────────────────────────────
        typo_result = {}
        try:
            from typosquat_detector import analyse_typosquatting
            typo_result = analyse_typosquatting(url)
        except Exception as e:
            typo_result = {"error": str(e), "typosquat_risk": "unknown"}

        # ── Module 4: Threat Intelligence ────────────────────────────────────
        intel_result = {}
        try:
            from threat_intel import check_threat_intel
            intel_result = check_threat_intel(url)
        except Exception as e:
            intel_result = {"error": str(e), "threat_score": 0}

        # ── Module 5: Mutation Analysis ───────────────────────────────────────
        mutation_result = {}
        try:
            from mutation_analyzer import analyse_mutations
            mutation_result = analyse_mutations(url)
        except Exception as e:
            mutation_result = {"error": str(e), "attack_surface": 0}

        # ── Composite Risk Score ──────────────────────────────────────────────
        ml_score      = prob * 100
        dns_score     = dns_result.get("dns_risk_score", 0)
        threat_score  = intel_result.get("threat_score", 0)
        typo_score    = typo_result.get("similarity_score", 0)

        composite = round(
            ml_score     * 0.40 +
            dns_score    * 0.25 +
            threat_score * 0.25 +
            typo_score   * 0.10,
            1
        )

        if composite >= 60:
            composite_verdict = "PHISHING"
            composite_risk    = "high"
        elif composite >= 35:
            composite_verdict = "SUSPICIOUS"
            composite_risk    = "medium"
        else:
            composite_verdict = "LEGITIMATE"
            composite_risk    = "low"

        result = {
            "url":              url,
            "domain":           domain,
            # ML analysis
            "label":            label,
            "verdict":          composite_verdict,
            "probability":      round(prob * 100, 2),
            "risk_level":       composite_risk,
            "composite_score":  composite,
            "features":         features,
            "explanation":      explanation,
            "flags":            flags,
            # Novelty modules
            "dns_intelligence": dns_result,
            "typosquatting":    typo_result,
            "threat_intel":     intel_result,
            "mutation_analysis":mutation_result,
            # Score breakdown
            "score_breakdown": {
                "ml_model":         round(ml_score,     1),
                "dns_whois":        round(dns_score,    1),
                "threat_intel":     round(threat_score, 1),
                "typosquatting":    round(typo_score,   1),
                "composite":        composite,
            },
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

        # Add to session history
        _scan_history.appendleft({
            "url":        url,
            "verdict":    composite_verdict,
            "risk_level": composite_risk,
            "prob":       composite,
            "scanned_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "deep":       True,
        })

        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/dns-scan", methods=["POST"])
def dns_scan():
    """Lightweight endpoint: DNS + WHOIS only."""
    data   = request.get_json(silent=True) or {}
    url    = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        import tldextract
        from dns_inspector import inspect_domain
        ext    = tldextract.extract(url if "://" in url else "http://" + url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return jsonify(inspect_domain(domain))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/typo-scan", methods=["POST"])
def typo_scan():
    """Lightweight endpoint: Typosquatting only."""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        from typosquat_detector import analyse_typosquatting
        return jsonify(analyse_typosquatting(url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/intel-scan", methods=["POST"])
def intel_scan():
    """Lightweight endpoint: Threat intelligence only."""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        from threat_intel import check_threat_intel
        return jsonify(check_threat_intel(url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/mutation-scan", methods=["POST"])
def mutation_scan():
    """Lightweight endpoint: Mutation analysis only."""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        from mutation_analyzer import analyse_mutations
        return jsonify(analyse_mutations(url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — Session & Utilities
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/history")
def history():
    """GET /history — return session scan history."""
    return jsonify(list(_scan_history))


@app.route("/history/clear", methods=["POST"])
def clear_history():
    _scan_history.clear()
    return jsonify({"status": "cleared"})


@app.route("/report", methods=["POST"])
def generate_report():
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        from report_generator import generate_pdf_report
        features    = extract_features(url)
        explainer   = _get_explainer()
        explanation = explainer.explain(features)
        prob        = explanation["prediction_prob"]
        label, _, _ = _verdict_from_prob(prob)
        pdf_path    = generate_pdf_report(
            url=url, label=label, prob=prob,
            features=features, shap_explanation=explanation,
            chart_b64=explanation.get("chart_b64"),
        )
        return send_file(pdf_path, mimetype="application/pdf",
                         as_attachment=True,
                         download_name="phishing_analysis_report.pdf")
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/metrics")
def metrics():
    return jsonify(_get_metrics())


@app.route("/global-importance")
def global_importance():
    try:
        chart = _get_explainer().global_importance_chart()
        return jsonify({"chart_b64": chart})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "models_loaded": _explainer is not None})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  AI Phishing URL Detection  +  Novel Security Modules")
    print("  http://127.0.0.1:5000")
    print("=" * 60)
    try:
        _get_explainer()
        print("[+] Model loaded successfully.")
    except Exception as e:
        print(f"[!] Model load failed: {e}")
    app.run(debug=True, host="0.0.0.0", port=5000)
