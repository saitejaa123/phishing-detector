"""
Typosquatting & Visual Similarity Detector
===========================================
Novelty Feature #2

Detects if a URL is impersonating a known brand by:
  - Character substitution  (paypa1.com  → paypal.com)
  - Homoglyph attacks       (microsоft.com — Cyrillic 'о')
  - Insertion / deletion    (gooogle.com, googl.com)
  - Hyphenation tricks      (pay-pal.com, micro-soft-login.com)
  - Combosquatting          (paypal-secure.com)
  - Subdomain spoofing      (paypal.evil.com)
  - Levenshtein distance    (fuzzy brand similarity)
  - Bigram similarity       (structural text similarity)

Returns a similarity score and the closest brand match.
"""

import re
import unicodedata
from difflib import SequenceMatcher
import tldextract


# ── Known brand registry ──────────────────────────────────────────────────────
# (brand_name, canonical_domain, keywords)
KNOWN_BRANDS = [
    ("PayPal",      "paypal",      ["paypal", "payment", "wallet"]),
    ("Apple",       "apple",       ["apple", "icloud", "itunes", "iphone"]),
    ("Microsoft",   "microsoft",   ["microsoft", "msn", "outlook", "azure", "office"]),
    ("Google",      "google",      ["google", "gmail", "youtube"]),
    ("Amazon",      "amazon",      ["amazon", "aws", "kindle"]),
    ("Facebook",    "facebook",    ["facebook", "fb", "meta"]),
    ("Netflix",     "netflix",     ["netflix", "streaming"]),
    ("Instagram",   "instagram",   ["instagram", "insta"]),
    ("Twitter",     "twitter",     ["twitter", "tweet"]),
    ("eBay",        "ebay",        ["ebay", "ebayisapi"]),
    ("Chase",       "chase",       ["chase", "jpmorgan"]),
    ("Wells Fargo", "wellsfargo",  ["wellsfargo", "wf"]),
    ("Bank of America", "bankofamerica", ["bankofamerica", "bofa"]),
    ("Citibank",    "citibank",    ["citi", "citibank"]),
    ("Steam",       "steampowered",["steam", "steampowered", "steamcommunity"]),
    ("Dropbox",     "dropbox",     ["dropbox"]),
    ("LinkedIn",    "linkedin",    ["linkedin"]),
    ("Adobe",       "adobe",       ["adobe", "acrobat"]),
    ("Spotify",     "spotify",     ["spotify"]),
    ("WhatsApp",    "whatsapp",    ["whatsapp"]),
]

# Homoglyph mapping (look-alike characters → ASCII equivalent)
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p",   # Cyrillic look-alikes
    "с": "c", "х": "x", "і": "i", "ѕ": "s",
    "ì": "i", "ï": "i", "î": "i", "ĺ": "l",
    "ó": "o", "ô": "o", "ö": "o", "ú": "u",
    "ń": "n", "ñ": "n",
}


# ── Normalisation helpers ─────────────────────────────────────────────────────

def _normalise(text: str) -> str:
    """Lowercase, strip accents, resolve homoglyphs."""
    text = text.lower()
    # Unicode normalise to decompose accented chars
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    # Replace homoglyphs
    text = "".join(HOMOGLYPHS.get(c, c) for c in text)
    return text


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance."""
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]


def _bigram_similarity(s1: str, s2: str) -> float:
    """Dice coefficient on character bigrams — good for typo detection."""
    def bigrams(s):
        return [s[i:i+2] for i in range(len(s) - 1)]
    b1, b2 = bigrams(s1), bigrams(s2)
    if not b1 or not b2:
        return 0.0
    intersection = sum(min(b1.count(b), b2.count(b)) for b in set(b1))
    return (2.0 * intersection) / (len(b1) + len(b2))


def _sequence_similarity(s1: str, s2: str) -> float:
    return SequenceMatcher(None, s1, s2).ratio()


# ── Attack pattern detectors ──────────────────────────────────────────────────

def _detect_combosquatting(domain_name: str, brand: str) -> bool:
    """brand + any word: paypal-secure, amazon-login, etc."""
    norm = _normalise(domain_name)
    norm_brand = _normalise(brand)
    if norm_brand in norm and norm != norm_brand:
        return True
    return False


def _detect_subdomain_spoofing(subdomain: str, brand: str) -> bool:
    """brand.evil.com — brand appears in subdomain."""
    if not subdomain:
        return False
    norm_sub   = _normalise(subdomain)
    norm_brand = _normalise(brand)
    return norm_brand in norm_sub


def _detect_homoglyph_attack(domain_name: str, brand: str) -> bool:
    """Check if raw domain (pre-normalisation) differs from normalised."""
    raw_norm  = domain_name.lower()
    full_norm = _normalise(domain_name)
    norm_brand = _normalise(brand)
    return (norm_brand in full_norm) and (norm_brand not in raw_norm)


def _keyword_in_path(path: str, keywords: list) -> bool:
    norm_path = _normalise(path)
    return any(kw in norm_path for kw in keywords)


# ── Main analyser ─────────────────────────────────────────────────────────────

def analyse_typosquatting(url: str) -> dict:
    """
    Analyse a URL for brand impersonation and typosquatting attacks.

    Returns
    -------
    dict with keys:
      impersonated_brand   : str or None
      attack_types         : list of detected attack types
      similarity_score     : 0-100 (100 = identical to brand)
      findings             : list of detailed finding dicts
      typosquat_risk       : "high" | "medium" | "low" | "none"
    """
    url = url.strip()
    parse_url = url if "://" in url else "http://" + url
    ext = tldextract.extract(parse_url)

    domain_name = ext.domain or ""
    subdomain   = ext.subdomain or ""
    full_domain = f"{subdomain}.{domain_name}".strip(".") if subdomain else domain_name

    # Path for keyword check
    try:
        from urllib.parse import urlparse
        path = urlparse(parse_url).path or ""
    except Exception:
        path = ""

    norm_domain = _normalise(domain_name)
    norm_full   = _normalise(full_domain)

    best_brand        = None
    best_score        = 0.0
    best_brand_name   = None
    all_findings      = []
    attack_types      = set()

    for brand_name, brand_key, keywords in KNOWN_BRANDS:
        norm_brand = _normalise(brand_key)

        # ── Exact match in domain (not spoofing if TLD is legit) ─────────────
        if norm_domain == norm_brand:
            # Likely legit — skip
            continue

        scores = []
        findings = []

        # 1. Levenshtein similarity on domain name
        lev  = _levenshtein(norm_domain, norm_brand)
        max_len = max(len(norm_domain), len(norm_brand), 1)
        lev_score = max(0.0, 1.0 - lev / max_len)
        scores.append(lev_score)

        # 2. Bigram similarity
        bi_score = _bigram_similarity(norm_domain, norm_brand)
        scores.append(bi_score)

        # 3. Sequence similarity
        seq_score = _sequence_similarity(norm_domain, norm_brand)
        scores.append(seq_score)

        composite = (lev_score * 0.4 + bi_score * 0.35 + seq_score * 0.25)

        # 4. Combosquatting bonus
        if _detect_combosquatting(domain_name, brand_key):
            composite = max(composite, 0.75)
            findings.append({
                "attack": "COMBOSQUATTING",
                "detail": f"Domain '{domain_name}' contains brand '{brand_name}' "
                          f"combined with other words (e.g. {brand_key}-secure, {brand_key}-login)",
            })
            attack_types.add("Combosquatting")

        # 5. Subdomain spoofing
        if _detect_subdomain_spoofing(subdomain, brand_key):
            composite = max(composite, 0.80)
            findings.append({
                "attack": "SUBDOMAIN_SPOOFING",
                "detail": f"Brand '{brand_name}' appears in subdomain '{subdomain}' "
                          f"while the real domain is different — classic spoofing trick",
            })
            attack_types.add("Subdomain spoofing")

        # 6. Homoglyph attack
        if _detect_homoglyph_attack(domain_name, brand_key):
            composite = max(composite, 0.85)
            findings.append({
                "attack": "HOMOGLYPH_ATTACK",
                "detail": f"Domain uses visually similar characters to impersonate "
                          f"'{brand_name}' (e.g. 'paypa1' for 'paypal', Cyrillic letters)",
            })
            attack_types.add("Homoglyph attack")

        # 7. Keyword in path
        if _keyword_in_path(path, keywords):
            composite = min(1.0, composite + 0.10)
            findings.append({
                "attack": "BRAND_KEYWORD_IN_PATH",
                "detail": f"Path contains '{brand_name}'-related keywords, "
                          f"suggesting impersonation of brand's login/verify page",
            })
            attack_types.add("Keyword in path")

        # 8. Close typo (high lev score but not exact)
        if lev_score >= 0.80 and lev <= 2 and norm_domain != norm_brand:
            findings.append({
                "attack": "TYPO_SUBSTITUTION",
                "detail": f"'{domain_name}' is {lev} character edit(s) away from "
                          f"'{brand_key}' — likely typosquatting",
            })
            attack_types.add("Typo substitution")

        if composite > best_score and composite > 0.50:
            best_score      = composite
            best_brand      = brand_key
            best_brand_name = brand_name
            all_findings    = findings

    # ── Risk classification ───────────────────────────────────────────────────
    score_pct = int(best_score * 100)

    if score_pct >= 80:
        risk = "high"
    elif score_pct >= 60:
        risk = "medium"
    elif score_pct >= 40:
        risk = "low"
    else:
        risk = "none"
        all_findings = []

    return {
        "impersonated_brand": best_brand_name,
        "brand_key":          best_brand,
        "attack_types":       sorted(attack_types),
        "similarity_score":   score_pct,
        "findings":           all_findings,
        "typosquat_risk":     risk,
        "analysed_domain":    domain_name,
        "normalised_domain":  _normalise(domain_name),
    }
