"""
URL Feature Extractor
Extracts 30 features from a URL for phishing detection.
"""

import re
import math
import urllib.parse
from collections import Counter
import tldextract


# ── Suspicious keyword lists ──────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "credential", "wallet", "support", "alert",
    "suspend", "unlock", "validate", "ebayisapi", "paypal", "apple",
    "microsoft", "amazon", "google", "netflix", "facebook", "instagram",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "shorte.st", "adf.ly", "dlvr.it", "is.gd", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.cc", "url4.eu", "tr.im", "twit.ac",
    "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com",
}

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov"}

# Feature names (used by model + SHAP)
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_at_symbols",
    "num_question_marks",
    "num_ampersands",
    "num_equals",
    "num_digits",
    "num_special_chars",
    "has_ip_address",
    "has_https",
    "has_http",
    "subdomain_count",
    "is_shortener",
    "has_phishing_keyword",
    "phishing_keyword_count",
    "entropy",
    "digit_ratio",
    "letter_ratio",
    "suspicious_tld",
    "double_slash_redirect",
    "prefix_suffix_hyphen",
    "abnormal_url",
    "path_extension_suspicious",
    "query_param_count",
    "has_port",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_ip_address(host: str) -> bool:
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
    return bool(ipv4.match(host) or ipv6.match(host))


def _count_special(url: str) -> int:
    special = re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", url)
    return len(special)


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 30 numerical features from a URL.
    Returns an ordered dict matching FEATURE_NAMES.
    """
    url = url.strip()

    # Ensure scheme for parsing
    parse_url = url if "://" in url else "http://" + url
    try:
        parsed = urllib.parse.urlparse(parse_url)
    except Exception:
        parsed = urllib.parse.urlparse("http://unknown.com")

    ext = tldextract.extract(parse_url)
    domain = parsed.netloc or ""
    path   = parsed.path   or ""
    query  = parsed.query  or ""
    scheme = parsed.scheme or ""

    # Sub-domain list (ignore empty strings)
    subdomains = [s for s in ext.subdomain.split(".") if s]

    # Keyword scan (lowercase url)
    url_lower = url.lower()
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]

    # Digit / letter ratios
    digits  = sum(c.isdigit()  for c in url)
    letters = sum(c.isalpha()  for c in url)
    url_len = len(url) or 1

    # Suspicious extensions
    suspicious_exts = {".exe", ".zip", ".rar", ".scr", ".bat", ".cmd",
                       ".php", ".asp", ".aspx", ".js"}
    path_lower = path.lower()
    has_susp_ext = any(path_lower.endswith(e) for e in suspicious_exts)

    # Trusted TLD check
    tld_str = "." + ext.suffix if ext.suffix else ""
    is_susp_tld = int(tld_str not in TRUSTED_TLDS) if tld_str else 1

    # Port present
    has_port = int(bool(parsed.port))

    # Double-slash redirect (e.g. http://legit.com//evil.com)
    dbl_slash = int("//" in path)

    # Prefix / suffix hyphen in domain
    domain_name = ext.domain or ""
    prefix_suffix = int(domain_name.startswith("-") or domain_name.endswith("-"))

    # Abnormal URL: hostname not in URL (after scheme)
    url_after_scheme = url.split("://", 1)[-1]
    abnormal = int(bool(domain) and domain not in url_after_scheme)

    features = {
        "url_length":                len(url),
        "domain_length":             len(domain),
        "path_length":               len(path),
        "num_dots":                  url.count("."),
        "num_hyphens":               url.count("-"),
        "num_underscores":           url.count("_"),
        "num_slashes":               url.count("/"),
        "num_at_symbols":            url.count("@"),
        "num_question_marks":        url.count("?"),
        "num_ampersands":            url.count("&"),
        "num_equals":                url.count("="),
        "num_digits":                digits,
        "num_special_chars":         _count_special(url),
        "has_ip_address":            int(_is_ip_address(domain.split(":")[0])),
        "has_https":                 int(scheme == "https"),
        "has_http":                  int(scheme == "http"),
        "subdomain_count":           len(subdomains),
        "is_shortener":              int(domain in SHORTENERS),
        "has_phishing_keyword":      int(bool(matched_kw)),
        "phishing_keyword_count":    len(matched_kw),
        "entropy":                   round(_shannon_entropy(url), 4),
        "digit_ratio":               round(digits  / url_len, 4),
        "letter_ratio":              round(letters / url_len, 4),
        "suspicious_tld":            is_susp_tld,
        "double_slash_redirect":     dbl_slash,
        "prefix_suffix_hyphen":      prefix_suffix,
        "abnormal_url":              abnormal,
        "path_extension_suspicious": int(has_susp_ext),
        "query_param_count":         len(urllib.parse.parse_qs(query)),
        "has_port":                  has_port,
    }

    return features


def features_to_list(features: dict) -> list:
    """Return feature values in the canonical order of FEATURE_NAMES."""
    return [features[name] for name in FEATURE_NAMES]


def get_feature_descriptions() -> dict:
    """Human-readable descriptions for each feature (used in reports)."""
    return {
        "url_length":                "Total length of the URL",
        "domain_length":             "Length of the domain part",
        "path_length":               "Length of the URL path",
        "num_dots":                  "Number of dots in URL",
        "num_hyphens":               "Number of hyphens in URL",
        "num_underscores":           "Number of underscores in URL",
        "num_slashes":               "Number of forward slashes",
        "num_at_symbols":            "Number of @ symbols (credential injection risk)",
        "num_question_marks":        "Number of ? characters",
        "num_ampersands":            "Number of & characters",
        "num_equals":                "Number of = characters",
        "num_digits":                "Number of digit characters",
        "num_special_chars":         "Count of unusual special characters",
        "has_ip_address":            "Domain is a raw IP address",
        "has_https":                 "URL uses HTTPS scheme",
        "has_http":                  "URL uses HTTP scheme",
        "subdomain_count":           "Number of subdomains",
        "is_shortener":              "Domain is a known URL shortener",
        "has_phishing_keyword":      "URL contains at least one phishing keyword",
        "phishing_keyword_count":    "Number of phishing keywords found",
        "entropy":                   "Shannon entropy (randomness) of the URL",
        "digit_ratio":               "Proportion of digits in URL",
        "letter_ratio":              "Proportion of letters in URL",
        "suspicious_tld":            "TLD is not among common trusted TLDs",
        "double_slash_redirect":     "Path contains // (redirect trick)",
        "prefix_suffix_hyphen":      "Domain starts or ends with a hyphen",
        "abnormal_url":              "Hostname does not appear in URL body",
        "path_extension_suspicious": "Path ends with a suspicious file extension",
        "query_param_count":         "Number of query parameters",
        "has_port":                  "URL specifies an explicit port number",
    }
