"""
Behavioral URL Mutation Analyzer
==================================
Novelty Feature #4

Given a URL, generates plausible attack mutations and scores each one —
showing the attacker's toolbox and the "attack surface" of the domain.

Mutation types:
  - TLD swap          (paypal.com  → paypal.tk / .xyz / .ml)
  - Hyphen insertion  (paypal.com  → pay-pal.com)
  - Keyword prepend   (paypal.com  → secure-paypal.com)
  - Keyword append    (paypal.com  → paypal-login.com)
  - Subdomain inject  (paypal.com  → login.paypal.verify.com)
  - Character swap    (paypal.com  → paypa1.com)
  - Homoglyph swap    (paypal.com  → pаypal.com with Cyrillic а)
  - WWW tricks        (paypal.com  → wwwpaypal.com)
  - Double TLD        (paypal.com  → paypal.com.tk)

Each mutation is scored by the ML model + feature extractor so you
get a live risk comparison table.
"""

import sys
import itertools
from pathlib import Path

import tldextract

sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import extract_features, features_to_list

# ── Mutation config ───────────────────────────────────────────────────────────
RISKY_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".win", ".club"]

PHISHING_PREFIXES = ["secure-", "login-", "verify-", "account-", "update-",
                     "support-", "confirm-", "service-"]

PHISHING_SUFFIXES = ["-login", "-secure", "-verify", "-account", "-update",
                     "-support", "-online", "-portal", "-banking"]

PHISHING_SUBDOMAINS = ["login", "secure", "verify", "account", "update",
                       "support", "signin", "confirm", "banking"]

CHAR_SWAPS = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["1", "!"],
    "l": ["1"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "g": ["9"],
    "b": ["6"],
}

HOMOGLYPHS_INJECT = {
    "a": "а",   # Cyrillic а
    "e": "е",   # Cyrillic е
    "o": "о",   # Cyrillic о
    "p": "р",   # Cyrillic р
    "c": "с",   # Cyrillic с
    "x": "х",   # Cyrillic х
}


# ── Mutation generators ───────────────────────────────────────────────────────

def _tld_swaps(domain: str, tld: str, suffix: str) -> list:
    base = f"{domain}.{suffix}"
    return [
        f"http://{domain}{new_tld}"
        for new_tld in RISKY_TLDS
        if new_tld != f".{suffix}"
    ][:4]


def _hyphen_mutations(domain: str, suffix: str) -> list:
    results = []
    # Insert hyphen at each position
    for i in range(1, len(domain)):
        mutated = domain[:i] + "-" + domain[i:]
        results.append(f"http://{mutated}.{suffix}")
    return results[:3]


def _prefix_mutations(domain: str, suffix: str) -> list:
    return [f"http://{p}{domain}.{suffix}" for p in PHISHING_PREFIXES[:4]]


def _suffix_mutations(domain: str, suffix: str) -> list:
    return [f"http://{domain}{s}.{suffix}" for s in PHISHING_SUFFIXES[:4]]


def _subdomain_mutations(domain: str, suffix: str) -> list:
    return [f"http://{sub}.{domain}.{suffix}"
            for sub in PHISHING_SUBDOMAINS[:4]]


def _char_swap_mutations(domain: str, suffix: str) -> list:
    results = []
    for i, ch in enumerate(domain):
        if ch in CHAR_SWAPS:
            for replacement in CHAR_SWAPS[ch]:
                mutated = domain[:i] + replacement + domain[i+1:]
                results.append(f"http://{mutated}.{suffix}")
    return results[:4]


def _homoglyph_mutations(domain: str, suffix: str) -> list:
    results = []
    for i, ch in enumerate(domain):
        if ch in HOMOGLYPHS_INJECT:
            mutated = domain[:i] + HOMOGLYPHS_INJECT[ch] + domain[i+1:]
            results.append(f"http://{mutated}.{suffix}")
    return results[:3]


def _double_tld(domain: str, suffix: str) -> list:
    return [f"http://{domain}.{suffix}.{t.lstrip('.')}"
            for t in [".tk", ".xyz", ".ml"]]


def _www_trick(domain: str, suffix: str) -> list:
    return [f"http://www{domain}.{suffix}", f"http://wwww.{domain}.{suffix}"]


# ── Scoring ───────────────────────────────────────────────────────────────────

def _score_url(url: str, model) -> float:
    """Return phishing probability for a mutated URL."""
    try:
        import numpy as np
        features = extract_features(url)
        X = [features_to_list(features)]
        if hasattr(model, "predict_proba"):
            return float(model.predict_proba(X)[0][1])
        return float(model.predict(X)[0])
    except Exception:
        return 0.5


def _mutation_category(url: str, original_domain: str) -> str:
    """Label the mutation type for display."""
    url_l = url.lower()
    od    = original_domain.lower()
    if any(url_l.endswith(t) for t in RISKY_TLDS):
        return "TLD Swap"
    if any(f"/{p}{od}" in url_l or url_l.count("-") > od.count("-") for p in PHISHING_PREFIXES):
        return "Prefix Attack"
    if any(f"{od}{s}." in url_l for s in PHISHING_SUFFIXES):
        return "Suffix Attack"
    if any(f"{sub}.{od}" in url_l for sub in PHISHING_SUBDOMAINS):
        return "Subdomain Spoof"
    if "-" in url_l.split("/")[2].split(".")[0] and "-" not in od:
        return "Hyphen Insertion"
    if od not in url_l:
        return "Char Substitution"
    return "Mutation"


# ── Main analyser ─────────────────────────────────────────────────────────────

def analyse_mutations(url: str, model=None) -> dict:
    """
    Generate attack mutations of the given URL and score each one.

    Returns
    -------
    dict with:
      original_url        : str
      domain              : str
      mutations           : list of {url, category, risk_score, risk_level}
      attack_surface      : int  (count of high-risk mutations)
      max_mutation_score  : float
    """
    parse_url = url if "://" in url else "http://" + url
    ext = tldextract.extract(parse_url)
    domain = ext.domain or "unknown"
    suffix = ext.suffix or "com"

    # Load model lazily
    if model is None:
        try:
            import joblib
            model_path = Path(__file__).parent.parent / "models" / "ensemble.pkl"
            model = joblib.load(model_path)
        except Exception:
            model = None

    # Generate all mutations
    raw_mutations = []
    raw_mutations.extend(_tld_swaps(domain, domain, suffix))
    raw_mutations.extend(_hyphen_mutations(domain, suffix))
    raw_mutations.extend(_prefix_mutations(domain, suffix))
    raw_mutations.extend(_suffix_mutations(domain, suffix))
    raw_mutations.extend(_subdomain_mutations(domain, suffix))
    raw_mutations.extend(_char_swap_mutations(domain, suffix))
    raw_mutations.extend(_homoglyph_mutations(domain, suffix))
    raw_mutations.extend(_double_tld(domain, suffix))
    raw_mutations.extend(_www_trick(domain, suffix))

    # Deduplicate and exclude original
    seen = set()
    unique_mutations = []
    original_norm = parse_url.lower().rstrip("/")
    for m in raw_mutations:
        mn = m.lower().rstrip("/")
        if mn != original_norm and mn not in seen:
            seen.add(mn)
            unique_mutations.append(m)

    # Score each mutation (cap at 20 for performance)
    scored = []
    for mut_url in unique_mutations[:20]:
        score = _score_url(mut_url, model) if model else 0.5
        pct   = round(score * 100, 1)
        if pct >= 70:
            risk_level = "high"
        elif pct >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        scored.append({
            "url":        mut_url,
            "category":   _mutation_category(mut_url, domain),
            "risk_score": pct,
            "risk_level": risk_level,
        })

    # Sort by risk descending
    scored.sort(key=lambda x: x["risk_score"], reverse=True)

    high_risk    = [m for m in scored if m["risk_level"] == "high"]
    max_score    = scored[0]["risk_score"] if scored else 0.0

    return {
        "original_url":       url,
        "domain":             domain,
        "suffix":             suffix,
        "mutations":          scored,
        "total_mutations":    len(scored),
        "attack_surface":     len(high_risk),
        "max_mutation_score": max_score,
        "summary": (
            f"{len(high_risk)} of {len(scored)} generated mutations score "
            f">70% phishing probability — indicating high attack surface"
            if high_risk else
            f"None of the {len(scored)} generated mutations score as high-risk phishing"
        ),
    }
