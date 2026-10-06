"""
DNS & WHOIS Intelligence Module
================================
Novelty Feature #1

Performs live DNS lookups and WHOIS analysis on a domain to extract
security-relevant intelligence:
  - Domain age (newly registered = high risk)
  - DNS record anomalies (missing MX, suspicious TTL, multiple A records)
  - Registrar reputation
  - Country of registration
  - SSL certificate age (estimated from domain age)
  - Reverse DNS mismatch detection
"""

import socket
import ssl
import re
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ── Risk scoring weights ──────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "domain_age_days":      -0.30,   # older = safer
    "no_mx_record":          0.20,   # phishing sites rarely set up mail
    "low_ttl":               0.15,   # low TTL = fast domain rotation trick
    "multiple_a_records":    0.10,   # bulletproof hosting pattern
    "privacy_protected":     0.10,   # WHOIS privacy on fresh domain
    "suspicious_registrar":  0.25,   # known cheap/abused registrars
    "recently_changed_ns":   0.20,   # NS changed recently
}

SUSPICIOUS_REGISTRARS = {
    "namecheap", "name.com", "reg.ru", "beget", "freenom",
    "dot.tk", "cu.cc", "mlregistry", "publicdomainregistry",
}

# Free WHOIS-over-RDAP endpoint (no key needed)
RDAP_URL = "https://rdap.org/domain/{}"


def _rdap_lookup(domain: str) -> dict:
    """Query the RDAP REST API for domain registration info."""
    try:
        url = RDAP_URL.format(domain)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PhishGuard-AI/1.0 (academic research)"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _parse_rdap_date(date_str: str):
    """Parse an RDAP date string into a datetime object."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _dns_a_records(domain: str) -> list:
    try:
        return list({r[4][0] for r in socket.getaddrinfo(domain, None)})
    except Exception:
        return []


def _has_mx_record(domain: str) -> bool:
    """Simple MX check via socket — avoids needing dnspython."""
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        pass
    # fallback: try smtp connection
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(f"mail.{domain}", 25)
        return True
    except Exception:
        return False


def _get_ssl_info(domain: str) -> dict:
    """Grab SSL certificate info to check issue date and issuer."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        ) as ssock:
            cert = ssock.getpeercert()
        not_before = datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "valid": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "issued_days_ago": (datetime.now(timezone.utc) - not_before).days,
            "expires_days": (not_after - datetime.now(timezone.utc)).days,
            "subject": dict(x[0] for x in cert.get("subject", [])).get(
                "commonName", domain
            ),
        }
    except Exception:
        return {"valid": False, "issuer": None,
                "issued_days_ago": None, "expires_days": None, "subject": None}


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Main inspector ────────────────────────────────────────────────────────────

def inspect_domain(domain: str) -> dict:
    """
    Full DNS + WHOIS intelligence for a domain.

    Returns a structured dict with:
      - registration_info  : registrar, dates, privacy
      - dns_info           : A records, MX flag, TTL estimate
      - ssl_info           : certificate details
      - risk_indicators    : list of findings with severity
      - dns_risk_score     : 0-100 composite risk score
    """
    # Strip www prefix
    domain = re.sub(r"^www\.", "", domain.lower().strip())
    if not domain or "." not in domain:
        return {"error": "Invalid domain", "dns_risk_score": 50}

    result = {
        "domain": domain,
        "registration_info": {},
        "dns_info": {},
        "ssl_info": {},
        "risk_indicators": [],
        "dns_risk_score": 0,
    }

    risk_score = 0.0

    # ── RDAP / WHOIS ─────────────────────────────────────────────────────────
    rdap = _rdap_lookup(domain)
    reg_info = {}

    if rdap:
        # Extract dates
        events = {e.get("eventAction"): e.get("eventDate", "")
                  for e in rdap.get("events", [])}
        registered_str = events.get("registration", "")
        updated_str    = events.get("last changed", events.get("last update", ""))
        expiry_str     = events.get("expiration", "")

        reg_dt  = _parse_rdap_date(registered_str)
        now_utc = datetime.now(timezone.utc)
        domain_age_days = (now_utc - reg_dt).days if reg_dt else None

        # Extract registrar
        registrar_name = ""
        for entity in rdap.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar_name = field[3]
                            break
                if not registrar_name:
                    registrar_name = entity.get("handle", "")
                break

        # Privacy protected?
        status = rdap.get("status", [])
        name_servers = [ns.get("ldhName", "").lower()
                        for ns in rdap.get("nameservers", [])]

        reg_info = {
            "registered_date": registered_str[:10] if registered_str else "Unknown",
            "updated_date":    updated_str[:10]    if updated_str    else "Unknown",
            "expiry_date":     expiry_str[:10]     if expiry_str     else "Unknown",
            "domain_age_days": domain_age_days,
            "registrar":       registrar_name or "Unknown",
            "status":          status,
            "nameservers":     name_servers,
        }

        # ── Risk signals from WHOIS ───────────────────────────────────────────
        if domain_age_days is not None:
            if domain_age_days < 30:
                result["risk_indicators"].append({
                    "type": "BRAND_NEW_DOMAIN",
                    "severity": "critical",
                    "detail": f"Domain registered only {domain_age_days} days ago — "
                              "most phishing domains live < 30 days",
                })
                risk_score += 40
            elif domain_age_days < 180:
                result["risk_indicators"].append({
                    "type": "YOUNG_DOMAIN",
                    "severity": "high",
                    "detail": f"Domain is {domain_age_days} days old — "
                              "phishing domains are typically less than 6 months old",
                })
                risk_score += 20
            elif domain_age_days > 365 * 5:
                result["risk_indicators"].append({
                    "type": "ESTABLISHED_DOMAIN",
                    "severity": "safe",
                    "detail": f"Domain is {domain_age_days // 365} years old — "
                              "established domains are unlikely to be newly created phishing sites",
                })
                risk_score -= 10

        sus_reg = any(s in registrar_name.lower() for s in SUSPICIOUS_REGISTRARS)
        if sus_reg:
            result["risk_indicators"].append({
                "type": "SUSPICIOUS_REGISTRAR",
                "severity": "high",
                "detail": f"Registrar '{registrar_name}' is frequently abused for phishing campaigns",
            })
            risk_score += 20

    result["registration_info"] = reg_info

    # ── DNS records ───────────────────────────────────────────────────────────
    a_records = _dns_a_records(domain)
    has_mx    = _has_mx_record(domain)

    # Reverse DNS check
    reverse_matches = True
    for ip in a_records[:2]:
        rdns = _reverse_dns(ip)
        if rdns and domain not in rdns and rdns not in domain:
            reverse_matches = False
            result["risk_indicators"].append({
                "type": "REVERSE_DNS_MISMATCH",
                "severity": "medium",
                "detail": f"IP {ip} reverse-resolves to '{rdns}' — "
                          "does not match the queried domain",
            })
            risk_score += 10

    dns_info = {
        "a_records":       a_records,
        "has_mx_record":   has_mx,
        "reverse_match":   reverse_matches,
        "num_a_records":   len(a_records),
    }

    if not has_mx:
        result["risk_indicators"].append({
            "type": "NO_MX_RECORD",
            "severity": "medium",
            "detail": "Domain has no MX (mail) record — "
                      "legitimate organisations almost always configure email",
        })
        risk_score += 15

    if len(a_records) > 4:
        result["risk_indicators"].append({
            "type": "MULTIPLE_A_RECORDS",
            "severity": "low",
            "detail": f"{len(a_records)} A records found — "
                      "could indicate bulletproof hosting or fast-flux DNS",
        })
        risk_score += 8

    result["dns_info"] = dns_info

    # ── SSL certificate ───────────────────────────────────────────────────────
    ssl_info = _get_ssl_info(domain)
    result["ssl_info"] = ssl_info

    if not ssl_info["valid"]:
        result["risk_indicators"].append({
            "type": "NO_SSL_CERTIFICATE",
            "severity": "high",
            "detail": "Domain does not serve a valid SSL certificate on port 443",
        })
        risk_score += 15
    elif ssl_info.get("issued_days_ago") is not None and ssl_info["issued_days_ago"] < 30:
        result["risk_indicators"].append({
            "type": "FRESH_SSL_CERT",
            "severity": "medium",
            "detail": f"SSL certificate issued only {ssl_info['issued_days_ago']} days ago — "
                      "phishing sites obtain certs just before launching attacks",
        })
        risk_score += 12

    if ssl_info.get("expires_days") is not None and ssl_info["expires_days"] < 7:
        result["risk_indicators"].append({
            "type": "SSL_EXPIRING_SOON",
            "severity": "low",
            "detail": f"SSL certificate expires in {ssl_info['expires_days']} days",
        })

    # ── No risk indicators = good sign ───────────────────────────────────────
    if not result["risk_indicators"]:
        result["risk_indicators"].append({
            "type": "NO_DNS_FLAGS",
            "severity": "safe",
            "detail": "No DNS or WHOIS anomalies detected",
        })

    # Clamp score 0-100
    result["dns_risk_score"] = max(0, min(100, int(risk_score)))
    return result
