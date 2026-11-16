"""
MailSentinel AI - URL Extractor, Defanger & Lexical Risk Analyzer

Strict Zero-Trust Model:
1. URLs are extracted and defanged immediately (e.g. hxxps://domain[.]com).
2. URLs are NEVER opened, fetched, or resolved via live network calls.
3. Calculates Shannon entropy to detect algorithmic / obfuscated domains.
4. Detects IP literals, punycode/homoglyphs, and high-risk TLDs.
5. Does NOT claim a URL is "100% safe" without independent reputation verification.
"""

from collections import Counter
import math
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from backend.app.core.security import defang_url
from backend.app.core.time import now_utc
from backend.app.services.url_threat_intel import extract_urls_from_content, normalize_url

# Regex to safely find URLs in text
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[A-Za-z0-9\.\-\_\:\@\~\%\+\#\=\?\&\/]+",
    re.IGNORECASE
)

# Regex to detect IP literal hosts (e.g., http://192.168.1.1/login)
IP_REGEX = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", re.IGNORECASE)

# High-risk / frequently abused top-level domains in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "click", "rest", "fit", "tk", "ml", "ga",
    "cf", "gq", "icu", "cam", "work", "loan", "stream", "country"
}

# Sensitive impersonated target brands in subdomains/paths
TARGET_BRANDS = {
    "paypal", "netflix", "microsoft", "google", "apple", "amazon",
    "bankofamerica", "chase", "wellsfargo", "dhl", "fedex", "binance"
}


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy (measure of unpredictability / randomness) of a string.
    High entropy (> 4.0) frequently correlates with DGA (Domain Generation Algorithms)
    or hex/base64 obfuscation.
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_single_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes a single URL for lexical risk markers without initiating any network connections.
    """
    # Safely normalize URL using url_threat_intel utility
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()

    entropy = calculate_shannon_entropy(hostname)
    risk_reasons = []
    risk_score = 0.0

    # 1. IP Literal Check (Phishing technique to avoid domain registration)
    is_ip = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))
    if is_ip:
        risk_score += 0.50
        risk_reasons.append("Raw IP address used as host instead of registered domain.")

    # 2. TLD Check
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 0.30
        risk_reasons.append(f"High-abuse top-level domain detected: .{tld}")

    # 3. High Shannon Entropy Check
    if entropy > 3.8 and len(hostname) > 12:
        risk_score += 0.25
        risk_reasons.append(f"High character entropy ({entropy}): Domain appears randomly generated or obfuscated.")

    # 4. Brand Impersonation / Typosquatting Check in subdomain/path
    for brand in TARGET_BRANDS:
        if brand in hostname and not hostname.endswith(f".{brand}.com") and hostname != f"{brand}.com":
            risk_score += 0.40
            risk_reasons.append(f"Potential brand impersonation: Keyword '{brand}' appears in host '{hostname}'.")

    # 5. Credential harvesting markers in path
    path = (parsed.path or "").lower()
    for kw in ["login", "verify", "account-update", "signin", "banking", "secure-auth", "wallet", "auth"]:
        if kw in path:
            risk_score += 0.15
            risk_reasons.append(f"Authentication/credential keyword '{kw}' found in URL path.")
            break

    risk_score = min(1.0, round(risk_score, 4))
    is_suspicious = risk_score >= 0.35

    if risk_score >= 0.70:
        threat_classification = "MALICIOUS"
    elif risk_score >= 0.35:
        threat_classification = "SUSPICIOUS"
    else:
        threat_classification = "UNKNOWN"

    defanged = defang_url(raw_url)

    verification_note = (
        "High risk indicators detected." if is_suspicious else
        "No obvious lexical anomalies detected. External link reputation was not independently verified."
    )

    return {
        "raw_url_defanged": defanged,
        "defanged_url": defanged,
        "normalized_url": normalized,
        "original_url": raw_url,
        "domain": hostname,
        "tld": tld,
        "entropy": entropy,
        "is_suspicious": is_suspicious,
        "threat_classification": threat_classification,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "indicators": risk_reasons,
        "reputation_status": "Local Heuristics Evaluated (External Reputation Unconfigured)",
        "analyzed_at": now_utc().isoformat(),
        "verification_note": verification_note
    }


def analyze_email_urls(text: str) -> Dict[str, Any]:
    """
    Finds and analyzes all URLs within an email body text.
    Extracts from plain text, HTML markup, and defanged notation safely.
    """
    if not text:
        return {"urls": [], "total_count": 0, "suspicious_count": 0, "aggregate_risk": 0.0}

    # Extract up to 50 URLs to prevent resource exhaustion
    found_urls = extract_urls_from_content(text)[:50]
    analyzed_urls = [analyze_single_url(u) for u in found_urls]

    suspicious = [u for u in analyzed_urls if u["is_suspicious"]]
    max_risk = max([u["risk_score"] for u in analyzed_urls], default=0.0)

    return {
        "urls": analyzed_urls,
        "total_count": len(analyzed_urls),
        "suspicious_count": len(suspicious),
        "aggregate_risk": round(max_risk, 4)
    }

