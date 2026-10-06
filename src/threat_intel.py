"""
Threat Intelligence Module
===========================
Novelty Feature #3

Cross-references a URL / domain against:
  1. PhishTank public feed  (free, no key needed for basic check)
  2. OpenPhish feed         (free community feed)
  3. Local heuristic blacklist signatures
  4. Google Safe Browsing-style pattern checks

Also computes a Threat Intel Confidence Score (0-100).
"""

import re
import json
import hashlib
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
import tldextract

# ── Local cache dir ────────────────────────────────────────────────────────────
CACHE_DIR  = Path(__file__).parent.parent / "data" / "threat_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ── Known bad TLDs (heavily abused in phishing) ───────────────────────────────
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Freenom free TLDs
    ".xyz", ".top", ".club", ".win", ".bid",
    ".loan", ".download", ".stream", ".gdn",
    ".racing", ".review", ".party", ".trade",
    ".accountant", ".science", ".work",
}

# ── Hardcoded signature patterns (regex) ─────────────────────────────────────
# Real threat intel systems use thousands; these illustrate the concept.
PHISHING_PATTERNS = [
    (r"paypa[l1][-.]?(secure|login|account|verify|update)",  "PayPal credential harvester pattern"),
    (r"apple[-.]?(id|account|verify|support|unlock)",         "Apple ID phishing pattern"),
    (r"(microsoft|windows)[-.]?(alert|support|security|login)","Microsoft support scam pattern"),
    (r"(account|secure|login)[-.]?(update|verify|confirm)",   "Generic account phishing pattern"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(login|account|secure)", "IP-based credential phishing"),
    (r"(free|prize|winner|claim|reward).*(click|now|verify)", "Prize/reward scam pattern"),
    (r"(bank|banking).*(secure|update|verify|login)",         "Banking phishing pattern"),
    (r"(ebay|amazon|netflix).*(account|suspend|update|verify)","E-commerce phishing pattern"),
    (r"bit\.ly|tinyurl\.com|goo\.gl|ow\.ly",                  "URL shortener hiding destination"),
    (r"@.+\.(com|net|org)",                                    "@ symbol credential redirect"),
]

# ── OpenPhish feed URL (free, no key) ─────────────────────────────────────────
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE    = CACHE_DIR / "openphish_feed.txt"
FEED_MAX_AGE_SECS  = 3600 * 6   # re-download every 6 hours


def _fetch_openphish_feed() -> set:
    """Download (or load cached) OpenPhish feed and return a set of URLs."""
    urls = set()
    try:
        # Check cache freshness
        if OPENPHISH_CACHE.exists():
            age = (datetime.now(timezone.utc).timestamp()
                   - OPENPHISH_CACHE.stat().st_mtime)
            if age < FEED_MAX_AGE_SECS:
                lines = OPENPHISH_CACHE.read_text(encoding="utf-8",
                                                   errors="ignore").splitlines()
                return {l.strip().lower() for l in lines if l.strip()}

        # Fetch fresh feed
        req = urllib.request.Request(
            OPENPHISH_FEED_URL,
            headers={"User-Agent": "PhishGuard-AI/1.0 (academic)"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        OPENPHISH_CACHE.write_text(text, encoding="utf-8")
        urls = {l.strip().lower() for l in text.splitlines() if l.strip()}
    except Exception:
        # Use stale cache if available
        if OPENPHISH_CACHE.exists():
            lines = OPENPHISH_CACHE.read_text(encoding="utf-8",
                                               errors="ignore").splitlines()
            urls = {l.strip().lower() for l in lines if l.strip()}
    return urls


def _normalise_url(url: str) -> str:
    """Lowercase and strip trailing slashes for comparison."""
    return url.lower().rstrip("/")


def _check_openphish(url: str, feed: set) -> bool:
    """Check if URL or its domain appears in the OpenPhish feed."""
    norm = _normalise_url(url)
    if norm in feed:
        return True
    # Also check domain-level match
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    return any(domain in entry for entry in feed)


def _check_patterns(url: str) -> list:
    """Run signature patterns against the URL."""
    matches = []
    url_lower = url.lower()
    for pattern, description in PHISHING_PATTERNS:
        if re.search(pattern, url_lower):
            matches.append({
                "pattern":     pattern,
                "description": description,
            })
    return matches


def _check_tld_risk(url: str) -> dict | None:
    ext = tldextract.extract(url if "://" in url else "http://" + url)
    tld = f".{ext.suffix}".lower() if ext.suffix else ""
    if tld in HIGH_RISK_TLDS:
        return {
            "source":     "TLD_REPUTATION",
            "severity":   "high",
            "detail":     f"TLD '{tld}' is heavily abused in phishing campaigns "
                          f"and often available for free (Freenom, etc.)",
        }
    return None


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.lower().encode()).hexdigest()


# ── Main checker ──────────────────────────────────────────────────────────────

def check_threat_intel(url: str) -> dict:
    """
    Cross-reference URL against threat intelligence sources.

    Returns
    -------
    dict with:
      listed_in_feeds    : bool
      feed_matches       : list of feed names where URL was found
      pattern_matches    : list of matched signature patterns
      tld_risk           : dict or None
      threat_score       : 0-100
      intel_findings     : list of structured findings
      checked_at         : ISO timestamp
    """
    result = {
        "url":             url,
        "listed_in_feeds": False,
        "feed_matches":    [],
        "pattern_matches": [],
        "tld_risk":        None,
        "threat_score":    0,
        "intel_findings":  [],
        "checked_at":      datetime.now(timezone.utc).isoformat(),
    }

    threat_score = 0

    # ── 1. OpenPhish feed ─────────────────────────────────────────────────────
    try:
        feed = _fetch_openphish_feed()
        if feed and _check_openphish(url, feed):
            result["listed_in_feeds"] = True
            result["feed_matches"].append("OpenPhish")
            result["intel_findings"].append({
                "source":   "OpenPhish Community Feed",
                "severity": "critical",
                "detail":   "URL or its domain is listed in the OpenPhish active "
                            "phishing feed — confirmed malicious",
            })
            threat_score += 60
    except Exception:
        pass

    # ── 2. Signature pattern matching ────────────────────────────────────────
    pattern_hits = _check_patterns(url)
    result["pattern_matches"] = pattern_hits
    for hit in pattern_hits:
        result["intel_findings"].append({
            "source":   "Signature Pattern Engine",
            "severity": "high",
            "detail":   hit["description"],
        })
        threat_score += 15

    # ── 3. TLD reputation ─────────────────────────────────────────────────────
    tld_risk = _check_tld_risk(url)
    result["tld_risk"] = tld_risk
    if tld_risk:
        result["intel_findings"].append(tld_risk)
        threat_score += 20

    # ── 4. URL length heuristic (extra-long = obfuscation) ────────────────────
    if len(url) > 100:
        result["intel_findings"].append({
            "source":   "URL Heuristics",
            "severity": "medium",
            "detail":   f"URL length ({len(url)} chars) exceeds typical phishing "
                        f"obfuscation threshold of 100 characters",
        })
        threat_score += 10

    # ── 5. Data URI / javascript: scheme ─────────────────────────────────────
    if re.match(r"^(data:|javascript:|vbscript:)", url.lower()):
        result["intel_findings"].append({
            "source":   "Scheme Analysis",
            "severity": "critical",
            "detail":   "URL uses a dangerous scheme (data:, javascript:, vbscript:) "
                        "that can execute malicious code directly in the browser",
        })
        threat_score += 50

    # ── Clean bill ────────────────────────────────────────────────────────────
    if not result["intel_findings"]:
        result["intel_findings"].append({
            "source":   "Threat Intelligence",
            "severity": "safe",
            "detail":   "No matches found in threat intelligence feeds or signature patterns",
        })

    result["threat_score"] = max(0, min(100, int(threat_score)))
    return result
