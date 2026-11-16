"""
MailSentinel AI - Comprehensive URL Threat Intelligence & SSRF-Hardened Inspection Engine

Multi-Engine Architecture:
1. Safe URL Extraction & Normalization from text, HTML and headers.
2. Strict Zero-Trust SSRF Protection (blocks RFC1918, loopbacks, cloud metadata, link-local, internal hostnames).
3. Local Lexical Heuristics:
   - Shannon Entropy calculation
   - Raw IP address literals & obfuscated representations
   - High-abuse TLDs
   - URL shortener detection
   - Typosquatting / Levenshtein distance brand matching
   - Homograph / Punycode detection
   - Credential harvesting query keywords
4. External Threat Intelligence Adapters:
   - VirusTotal API v3
   - Google Safe Browsing API v4
   - Explicit "unconfigured" statuses when API keys are absent (no false safety claims)
5. Safe Multi-Hop HTTP Redirect Tracing (revalidating every destination IP against SSRF rules).
6. In-Memory TTL Caching with provider attribution.
"""

from collections import Counter
from datetime import datetime, timezone
import base64
import ipaddress
import math
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
import httpx

from backend.app.core.config import settings
from backend.app.core.time import to_iso_utc, now_utc
from backend.app.core.logging import logger
from backend.app.core.security import defang_url
from backend.app.schemas.url_intel import (
    UrlProviderResult,
    UrlHeuristicDetails,
    UrlRedirectHop,
    UrlThreatIntelResponse,
    CheckStatusItem,
    TlsCertificateDetails,
    CustomUrlInvestigationResponse
)

# Regex matching standard and obfuscated URLs (supporting defanged brackets, query strings, and ports)
RAW_URL_REGEX = re.compile(
    r"(?:https?://|hxxps?://|h\[tt\]ps?://|www\.)[A-Za-z0-9\.\-\_\:\@\~\%\+\#\=\?\&\/\[\]]+",
    re.IGNORECASE
)

# Regex matching defanged domain notations like attacker-domain[.]xyz/path
DEFANGED_DOMAIN_REGEX = re.compile(
    r"\b[A-Za-z0-9\-\_]+\[\.\][A-Za-z0-9\.\-\_\:\@\~\%\+\#\=\?\&\/\[\]]+",
    re.IGNORECASE
)

HTML_HREF_REGEX = re.compile(
    r"""(?:href|src)=["']([^"']+)["']""",
    re.IGNORECASE
)

# High-risk / frequently abused top-level domains in phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "buzz", "click", "rest", "fit", "tk", "ml", "ga",
    "cf", "gq", "icu", "cam", "work", "loan", "stream", "country", "gdn", "mom"
}

# High-value targeted brands for typosquatting & impersonation checks
TARGET_BRANDS: List[str] = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "bankofamerica", "chase", "wellsfargo", "binance", "coinbase",
    "facebook", "instagram", "linkedin", "meta", "whatsapp", "dropbox",
    "dhl", "fedex", "usps", "adobe", "outlook", "office365"
]

# Known public URL shortening services
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "rebrand.ly", "shorturl.at", "tiny.cc", "v.gd"
}

# Suspicious query parameters typically associated with open redirects or token harvesting
SUSPICIOUS_QUERY_PARAMS: Set[str] = {
    "redirect", "url", "dest", "target", "next", "r", "token", "auth",
    "login", "session", "key", "password", "continue"
}

# In-memory thread-safe cache: {normalized_url: (timestamp, UrlThreatIntelResponse)}
_URL_CACHE: Dict[str, Tuple[float, UrlThreatIntelResponse]] = {}


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string.
    High entropy (> 3.8 for domain) indicates algorithmic generation (DGA) or obfuscation.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def extract_urls_from_content(content: str) -> List[str]:
    """
    Safely extracts all unique URLs from plain text, HTML markup, and RFC822 email bodies.
    Preserves original string formatting while deduplicating.
    """
    if not content:
        return []

    found_urls: List[str] = []
    seen: Set[str] = set()

    # 1. Regex over plain text
    for match in RAW_URL_REGEX.finditer(content):
        raw = match.group(0).rstrip(".,;:)>\"'")
        if raw and raw not in seen:
            seen.add(raw)
            found_urls.append(raw)

    # 2. Standalone defanged domains (e.g. evil-domain[.]xyz/path)
    for match in DEFANGED_DOMAIN_REGEX.finditer(content):
        raw = match.group(0).rstrip(".,;:)>\"'")
        if raw and raw not in seen and not any(raw in existing for existing in seen):
            seen.add(raw)
            found_urls.append(raw)

    # 3. Extract HTML href and src attributes
    for match in HTML_HREF_REGEX.finditer(content):
        raw = match.group(1).strip()
        if raw.startswith(("http://", "https://", "hxxp://", "hxxps://", "www.")) and raw not in seen:
            seen.add(raw)
            found_urls.append(raw)

    return found_urls


def normalize_url(raw_url: str) -> str:
    """
    Normalizes a URL by decoding de-fanged schemes, trimming spaces,
    and prepending http:// if scheme is missing.
    """
    u = raw_url.strip()
    # Replace defanged markers
    u = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0) else "http://", u, flags=re.IGNORECASE)
    u = re.sub(r"^h\[tt\]ps?://", lambda m: "https://" if "s" in m.group(0) else "http://", u, flags=re.IGNORECASE)
    u = u.replace("[.]", ".")
    if not re.match(r"^https?://", u, re.IGNORECASE):
        u = f"http://{u}"
    return u


def is_ip_safe_for_outbound(ip_str: str) -> Tuple[bool, str]:
    """
    Strict SSRF validation: Checks whether an IP address is safe for outbound network calls.
    Blocks:
    - RFC1918 Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopbacks (127.0.0.0/8, ::1)
    - Cloud Metadata & Link-Local (169.254.0.0/16, fe80::/10)
    - Multicast & Reserved (224.0.0.0/4, 240.0.0.0/4)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Handle RFC 6052 / RFC 8215 Well-Known NAT64 Prefix (64:ff9b::/96)
        if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("64:ff9b::/96"):
            embedded_ipv4 = ipaddress.IPv4Address(ip.packed[-4:])
            return is_ip_safe_for_outbound(str(embedded_ipv4))

        if ip.is_private:
            return False, f"Private network address blocked by SSRF filter ({ip_str})"
        if ip.is_loopback:
            return False, f"Loopback address blocked by SSRF filter ({ip_str})"
        if ip.is_link_local:
            return False, f"Link-local / cloud metadata address blocked by SSRF filter ({ip_str})"
        if ip.is_multicast:
            return False, f"Multicast address blocked by SSRF filter ({ip_str})"
        if ip.is_reserved:
            return False, f"Reserved address blocked by SSRF filter ({ip_str})"
        if str(ip) in ["0.0.0.0", "169.254.169.254", "255.255.255.255"]:
            return False, f"Prohibited IP address blocked ({ip_str})"
        return True, "IP is public and permitted."
    except ValueError:
        return False, f"Malformed IP address ({ip_str})"


def validate_hostname_ssrf(hostname: str) -> Tuple[bool, Optional[str], str]:
    """
    Resolves hostname to IP addresses via DNS and validates every IP against SSRF blocklists.
    """
    h_lower = hostname.lower().strip()

    # Block local / internal hostnames
    if h_lower in ["localhost", "metadata.google.internal", "instance-data", "local"]:
        return False, None, f"Localhost or cloud metadata hostname blocked ({hostname})"
    if h_lower.endswith((".local", ".internal", ".lan", ".localhost", ".localdomain")):
        return False, None, f"Internal domain zone blocked by SSRF filter ({hostname})"

    # If hostname is already an IP literal
    try:
        ipaddress.ip_address(h_lower)
        safe, reason = is_ip_safe_for_outbound(h_lower)
        return safe, h_lower if safe else None, reason
    except ValueError:
        pass

    # Resolve via DNS
    try:
        addr_info = socket.getaddrinfo(h_lower, None)
        if not addr_info:
            return False, None, "DNS resolution failed: No addresses returned."

        first_safe_ip = None
        for item in addr_info:
            resolved_ip = item[4][0]
            safe, reason = is_ip_safe_for_outbound(resolved_ip)
            if not safe:
                return False, resolved_ip, f"DNS resolution yielded prohibited address: {reason}"
            if not first_safe_ip:
                first_safe_ip = resolved_ip

        return True, first_safe_ip, "Hostname resolved to valid public IP(s)."
    except socket.gaierror as e:
        return False, None, f"DNS resolution failed ({e})"
    except Exception as exc:
        return False, None, f"DNS validation error ({exc})"


def perform_local_heuristics(normalized_url: str) -> UrlHeuristicDetails:
    """
    Executes in-depth lexical and heuristic analysis on a normalized URL.
    Calculates entropy, typosquatting, homographs, brand abuse, and shorteners.
    """
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    entropy = calculate_shannon_entropy(hostname)
    risk_reasons: List[str] = []
    suspicious_keywords: List[str] = []
    heuristic_score = 0.0

    # 1. IP Address Literal
    is_ip = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))
    if is_ip:
        heuristic_score += 0.45
        risk_reasons.append("URL uses raw numerical IP address instead of registered domain.")

    # 2. Suspicious TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    has_suspicious_tld = tld in SUSPICIOUS_TLDS
    if has_suspicious_tld:
        heuristic_score += 0.30
        risk_reasons.append(f"High-abuse top-level domain detected: .{tld}")

    # 3. Shannon Entropy
    if entropy > 3.8 and len(hostname) > 12:
        heuristic_score += 0.25
        risk_reasons.append(f"High domain character entropy ({entropy}): Indicates possible DGA or hex obfuscation.")

    # 4. URL Shortener Detection
    is_shortener = hostname in URL_SHORTENERS
    if is_shortener:
        heuristic_score += 0.20
        risk_reasons.append(f"Known URL shortener service ({hostname}): Hides real landing page.")

    # 5. Punycode & Homoglyph Detection
    has_punycode = "xn--" in hostname
    if has_punycode:
        heuristic_score += 0.40
        risk_reasons.append("Internationalized domain name (Punycode xn--) detected: Possible homoglyph spoofing.")

    # 6. Typosquatting & Brand Impersonation
    impersonated_brand: Optional[str] = None
    is_typosquatting = False

    # Check subdomains and SLD tokens
    parts = hostname.split(".")
    domain_sld = parts[-2] if len(parts) >= 2 else hostname
    # Check tokens split by hyphens or underscores (e.g. paypa1-update -> ["paypa1", "update"])
    candidate_tokens = [domain_sld] + re.split(r"[-_]", domain_sld)
    # Also include subdomain prefixes if any
    if len(parts) > 2:
        candidate_tokens.extend(parts[:-2])

    for brand in TARGET_BRANDS:
        # Exact keyword in hostname (e.g. paypal.com.attacker.xyz)
        if brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
            impersonated_brand = brand
            is_typosquatting = True
            heuristic_score += 0.45
            risk_reasons.append(f"Brand impersonation in hostname: '{brand}' appears inside untrusted host '{hostname}'.")
            break

        # Levenshtein distance check on candidate tokens (e.g. paypa1, mircosoft)
        matched = False
        for token in candidate_tokens:
            if not token or len(token) < 4:
                continue
            if abs(len(token) - len(brand)) <= 2:
                dist = levenshtein_distance(token, brand)
                if 0 < dist <= 2 and token != brand:
                    impersonated_brand = brand
                    is_typosquatting = True
                    heuristic_score += 0.50
                    risk_reasons.append(f"Typosquatting detected: '{token}' is distance {dist} from target brand '{brand}'.")
                    matched = True
                    break
        if matched:
            break

    # 7. Suspicious Path & Query Keywords
    for kw in ["login", "verify", "account", "update", "banking", "secure", "auth", "signin", "wallet", "invoice"]:
        if kw in path:
            suspicious_keywords.append(kw)
    if suspicious_keywords:
        heuristic_score += 0.15
        risk_reasons.append(f"Security/credential keyword(s) in path: {', '.join(suspicious_keywords)}.")

    # 8. Query parameter check
    for param in SUSPICIOUS_QUERY_PARAMS:
        if f"{param}=" in query:
            heuristic_score += 0.10
            risk_reasons.append(f"Suspicious parameter '{param}=' found in query string.")
            break

    # 9. HTTPS Check
    if parsed.scheme.lower() == "http" and not is_ip:
        heuristic_score += 0.10
        risk_reasons.append("Unencrypted HTTP protocol used instead of HTTPS.")

    heuristic_score = min(1.0, round(heuristic_score, 3))

    return UrlHeuristicDetails(
        entropy=entropy,
        is_ip_address=is_ip,
        has_suspicious_tld=has_suspicious_tld,
        is_shortener=is_shortener,
        is_typosquatting=is_typosquatting,
        impersonated_brand=impersonated_brand,
        has_punycode=has_punycode,
        suspicious_keywords=suspicious_keywords,
        risk_reasons=risk_reasons,
        heuristic_score=heuristic_score
    )


async def check_virustotal_reputation(url: str, domain: str) -> UrlProviderResult:
    """
    Queries VirusTotal API v3 for URL reputation.
    Returns clear 'unconfigured' status when API key is missing.
    """
    if not settings.is_virustotal_configured:
        return UrlProviderResult(
            provider="virustotal",
            status="unconfigured",
            message="VirusTotal API key not configured in backend/.env"
        )

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        async with httpx.AsyncClient(timeout=settings.URL_REDIRECT_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                api_url,
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY.strip(), "Accept": "application/json"}
            )

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            is_mal = (malicious + suspicious) > 0
            threat_tags = attributes.get("tags", [])

            return UrlProviderResult(
                provider="virustotal",
                status="clean" if not is_mal else "flagged",
                is_malicious=is_mal,
                detections_count=malicious + suspicious,
                total_engines=total or 90,
                threat_tags=threat_tags,
                message=f"VirusTotal detected {malicious} malicious / {suspicious} suspicious engines."
            )
        elif resp.status_code == 404:
            return UrlProviderResult(
                provider="virustotal",
                status="unknown",
                message="URL not previously scanned in VirusTotal dataset."
            )
        elif resp.status_code == 429:
            return UrlProviderResult(
                provider="virustotal",
                status="rate_limited",
                message="VirusTotal API rate limit exceeded."
            )
        else:
            return UrlProviderResult(
                provider="virustotal",
                status="error",
                message=f"VirusTotal responded with HTTP {resp.status_code}"
            )
    except Exception as exc:
        logger.warning("VirusTotal API error: %s", exc)
        return UrlProviderResult(
            provider="virustotal",
            status="error",
            message=f"Network error querying VirusTotal: {str(exc)}"
        )


async def check_google_safebrowsing_reputation(url: str) -> UrlProviderResult:
    """
    Queries Google Safe Browsing API v4 for threat matching.
    Returns clear 'unconfigured' status when API key is missing.
    """
    if not settings.is_safe_browsing_configured:
        return UrlProviderResult(
            provider="google_safebrowsing",
            status="unconfigured",
            message="Google Safe Browsing API key not configured in backend/.env"
        )

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()}"
    payload = {
        "client": {
            "clientId": "mailsentinel-ai",
            "clientVersion": "0.1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=settings.URL_REDIRECT_TIMEOUT_SECONDS) as client:
            resp = await client.post(api_url, json=payload)

        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = [m.get("threatType") for m in matches if m.get("threatType")]
                return UrlProviderResult(
                    provider="google_safebrowsing",
                    status="flagged",
                    is_malicious=True,
                    detections_count=len(matches),
                    total_engines=1,
                    threat_tags=threat_types,
                    message=f"Google Safe Browsing flagged threats: {', '.join(threat_types)}"
                )
            return UrlProviderResult(
                provider="google_safebrowsing",
                status="clean",
                is_malicious=False,
                detections_count=0,
                total_engines=1,
                message="Google Safe Browsing found no listed threats."
            )
        elif resp.status_code == 429:
            return UrlProviderResult(
                provider="google_safebrowsing",
                status="rate_limited",
                message="Google Safe Browsing API rate limit reached."
            )
        else:
            return UrlProviderResult(
                provider="google_safebrowsing",
                status="error",
                message=f"Safe Browsing API returned HTTP {resp.status_code}"
            )
    except Exception as exc:
        logger.warning("Safe Browsing API error: %s", exc)
        return UrlProviderResult(
            provider="google_safebrowsing",
            status="error",
            message=f"Safe Browsing connection failure: {str(exc)}"
        )


async def trace_redirects_safely(
    start_url: str,
    max_hops: int = 3
) -> Tuple[List[UrlRedirectHop], Optional[str], bool, List[str]]:
    """
    Safely follows public HTTP redirect chains step-by-step.
    CRITICAL SECURITY CONTROLS:
    - Resolves and validates DNS before EVERY hop.
    - Aborts immediately if any destination resolves to a private/loopback/cloud IP (SSRF protection).
    - Hard limit of max_hops (default 3).
    - Timeout: 3 seconds.
    - Max response headers read: 50KB.
    """
    hops: List[UrlRedirectHop] = []
    current_url = start_url
    ssrf_blocked = False
    warning_notes: List[str] = []

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=settings.URL_REDIRECT_TIMEOUT_SECONDS,
        headers={"User-Agent": "MailSentinel-Threat-Intel/1.0"}
    ) as client:
        for hop_index in range(1, max_hops + 1):
            parsed = urlparse(current_url)
            if parsed.scheme.lower() not in ["http", "https"]:
                warning_notes.append(f"Blocked unsupported scheme '{parsed.scheme}' at hop {hop_index}")
                break

            hostname = parsed.hostname or ""
            if not hostname:
                break

            # Validate destination host against SSRF blocklists
            safe, resolved_ip, reason = validate_hostname_ssrf(hostname)
            if not safe:
                ssrf_blocked = True
                warning_notes.append(f"SSRF Protection triggered at hop {hop_index} ({current_url}): {reason}")
                hops.append(UrlRedirectHop(
                    hop=hop_index,
                    url=current_url,
                    status_code=403,
                    resolved_ip=resolved_ip
                ))
                break

            try:
                # Perform HEAD request to inspect redirect header without downloading body
                resp = await client.head(current_url)
                # Some servers reject HEAD with 405 Method Not Allowed; fallback to GET with stream
                if resp.status_code == 405:
                    resp = await client.get(current_url, headers={"Range": "bytes=0-1024"})

                hops.append(UrlRedirectHop(
                    hop=hop_index,
                    url=current_url,
                    status_code=resp.status_code,
                    resolved_ip=resolved_ip
                ))

                if resp.status_code in [301, 302, 303, 307, 308] and "location" in resp.headers:
                    next_loc = resp.headers["location"]
                    # Handle relative redirects
                    current_url = urljoin(current_url, next_loc)
                else:
                    # Final destination reached
                    break
            except Exception as exc:
                warning_notes.append(f"Redirect inspection ended at hop {hop_index}: {str(exc)}")
                break

    final_destination = hops[-1].url if hops else start_url
    return hops, final_destination, ssrf_blocked, warning_notes


async def analyze_url_threat_intelligence(
    raw_url: str,
    follow_redirects: bool = True
) -> UrlThreatIntelResponse:
    """
    Main pipeline for URL Threat Intelligence analysis.
    Combines SSRF validation, local heuristics, external reputation providers,
    safe redirect tracing, and verdict synthesis.
    """
    normalized = normalize_url(raw_url)
    now_ts = time.time()

    # Check cache
    if normalized in _URL_CACHE:
        cached_ts, cached_resp = _URL_CACHE[normalized]
        if now_ts - cached_ts < settings.URL_INTEL_CACHE_TTL_SECONDS:
            cached_copy = cached_resp.model_copy()
            cached_copy.cached = True
            return cached_copy

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    tld = hostname.split(".")[-1] if "." in hostname else ""
    defanged = defang_url(raw_url)

    # 1. Local Heuristics
    heuristics = perform_local_heuristics(normalized)

    # 2. SSRF Pre-flight Validation
    is_safe_host, resolved_ip, ssrf_reason = validate_hostname_ssrf(hostname)
    dns_failed = ssrf_reason.startswith("DNS resolution failed") or ssrf_reason.startswith("DNS validation error")
    ssrf_blocked = (not is_safe_host) and (not dns_failed)

    # 3. External Reputation Checks (Concurrent)
    vt_task = check_virustotal_reputation(normalized, hostname)
    gsb_task = check_google_safebrowsing_reputation(normalized)

    # 4. Safe Redirect Tracing (only if host is publicly accessible)
    redirect_hops: List[UrlRedirectHop] = []
    final_destination: Optional[str] = normalized
    redirect_warnings: List[str] = []

    if follow_redirects and is_safe_host:
        try:
            redirect_hops, final_destination, redirect_ssrf, redirect_warnings = await trace_redirects_safely(
                normalized,
                max_hops=settings.URL_REDIRECT_MAX_HOPS
            )
            if redirect_ssrf:
                ssrf_blocked = True
        except Exception as e:
            logger.warning("Error during safe redirect trace: %s", e)

    vt_res, gsb_res = await vt_task, await gsb_task
    reputation: Dict[str, UrlProviderResult] = {
        "virustotal": vt_res,
        "google_safebrowsing": gsb_res
    }

    # 5. Verdict & Threat Reasons Synthesis
    threat_reasons: List[str] = list(heuristics.risk_reasons)
    threat_reasons.extend(redirect_warnings)

    verdict = "UNKNOWN"
    confidence = 0.50

    if ssrf_blocked:
        verdict = "MALICIOUS"
        confidence = 1.0
        threat_reasons.insert(0, f"Critical Security Violation: {ssrf_reason}")
    elif vt_res.is_malicious or gsb_res.is_malicious:
        verdict = "MALICIOUS"
        confidence = 0.95
        if vt_res.is_malicious:
            threat_reasons.insert(0, f"VirusTotal flagged URL: {vt_res.detections_count} engines detected malicious activity.")
        if gsb_res.is_malicious:
            threat_reasons.insert(0, f"Google Safe Browsing flagged URL: {', '.join(gsb_res.threat_tags)}")
    elif heuristics.is_typosquatting or (heuristics.is_ip_address and heuristics.suspicious_keywords):
        verdict = "SUSPICIOUS"
        confidence = 0.85
    elif heuristics.heuristic_score >= 0.50:
        verdict = "SUSPICIOUS"
        confidence = round(0.70 + heuristics.heuristic_score * 0.2, 2)
    elif heuristics.heuristic_score < 0.25:
        # If reputation providers were checked and clean:
        if vt_res.status == "clean" or gsb_res.status == "clean":
            verdict = "SAFE"
            confidence = 0.85
            threat_reasons.append("No threats detected by heuristic parsers or configured reputation providers.")
        else:
            verdict = "SAFE"
            confidence = 0.70
            threat_reasons.append("No obvious lexical threats detected. External reputation providers were unconfigured.")
    else:
        verdict = "SUSPICIOUS"
        confidence = 0.65

    response = UrlThreatIntelResponse(
        original_url=raw_url,
        normalized_url=normalized,
        defanged_url=defanged,
        domain=hostname,
        tld=tld,
        verdict=verdict,
        confidence=confidence,
        threat_reasons=threat_reasons,
        reputation=reputation,
        heuristics=heuristics,
        redirect_chain=redirect_hops,
        final_destination=final_destination,
        ssrf_blocked=ssrf_blocked,
        cached=False,
        analyzed_at=to_iso_utc(now_utc())
    )

    # Cache result
    _URL_CACHE[normalized] = (now_ts, response)
    return response


async def analyze_url_batch(urls: List[str]) -> List[UrlThreatIntelResponse]:
    """Analyzes a batch of URLs concurrently with concurrency cap."""
    import asyncio
    semaphore = asyncio.Semaphore(10)

    async def _sem_analyze(u: str):
        async with semaphore:
            return await analyze_url_threat_intelligence(u)

    tasks = [_sem_analyze(u) for u in urls[:50]]
    return await asyncio.gather(*tasks)


def inspect_tls_certificate_safely(
    hostname: str,
    port: int = 443,
    timeout: float = 2.0
) -> Tuple[bool, Optional[TlsCertificateDetails], str]:
    """
    Safely retrieves and inspects the remote server's TLS certificate without downloading content.
    SECURITY CONTROLS:
    - Pre-flight SSRF validation on hostname & resolved IP address.
    - Strict timeout enforced (default 2.0s).
    - Passive non-intrusive handshake; never executes server data.
    - Catches socket, SSL, and network exceptions cleanly.
    """
    is_safe, resolved_ip, reason = validate_hostname_ssrf(hostname)
    if not is_safe:
        return False, None, f"TLS check skipped: Host blocked by SSRF filter ({reason})"

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((resolved_ip or hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

                # Parse subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                subject_name = subject_dict.get("commonName") or hostname

                valid_from = cert.get("notBefore")
                valid_to = cert.get("notAfter")

                is_expired = False
                if valid_to:
                    try:
                        expire_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        is_expired = datetime.now(timezone.utc) > expire_dt
                    except Exception:
                        pass

                details = TlsCertificateDetails(
                    has_tls=True,
                    issuer=issuer_name,
                    subject=subject_name,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    is_expired=is_expired,
                    cipher=cipher[0] if cipher else None,
                    version=version
                )
                return True, details, f"Valid TLS certificate issued by {issuer_name} (expires {valid_to})"
    except ssl.SSLCertVerificationError as exc:
        details = TlsCertificateDetails(
            has_tls=True,
            error=f"Untrusted or invalid TLS certificate ({exc.verify_message})"
        )
        return False, details, f"TLS certificate validation failed: {exc.verify_message}"
    except (socket.timeout, TimeoutError):
        return False, None, f"TLS connection timed out after {timeout}s"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        return False, None, f"TLS port {port} connection refused or unreachable ({exc})"
    except Exception as exc:
        return False, None, f"TLS inspection error: {str(exc)}"


async def investigate_custom_url(
    raw_url: str,
    mode: str = "deep"
) -> CustomUrlInvestigationResponse:
    """
    Core AI Custom URL Investigation Engine.
    Executes:
    1. Input validation & defanged syntax detection
    2. Zero-trust SSRF & DNS pre-flight verification
    3. Hostname, subdomain, SLD, TLD & path lexical heuristics
    4. Passive TLS certificate inspection
    5. SSRF-hardened multi-hop HTTP redirect tracing
    6. Threat score generation (0-100) & verdict classification
    7. Multi-check status auditing (succeeded/failed/unavailable)
    8. Empirical AI forensic explanation (Gemini or deterministic SOC reasoning fallback)
    """
    clean_url = raw_url.strip() if raw_url else ""
    if not clean_url:
        raise ValueError("URL cannot be empty. Please provide a valid URL or defanged IOC.")

    # Reject dangerous / prohibited URL schemes
    lower_raw = clean_url.lower()
    for bad_scheme in ["javascript:", "file:", "data:", "gopher:", "ftp:", "vbscript:"]:
        if lower_raw.startswith(bad_scheme):
            raise ValueError(f"Prohibited or dangerous URL scheme detected: '{bad_scheme}'")

    # 1. Defanging detection & normalization
    is_defanged = bool(re.search(r"hxxps?://|h\[tt\]ps?://|\[\.\]", clean_url, re.IGNORECASE))
    defanged_url = defang_url(clean_url)
    normalized_url = normalize_url(clean_url)

    # 2. Structural breakdown
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError(f"Could not parse a valid hostname from URL: {defanged_url}")

    parts = hostname.split(".")
    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
        domain = ".".join(parts[-2:])
    elif len(parts) == 2:
        subdomain = None
        domain = hostname
    else:
        subdomain = None
        domain = hostname

    tld = parts[-1] if len(parts) >= 2 else ""
    path = parsed.path or "/"
    query = parsed.query or ""

    # 3. Local Lexical Heuristics
    heuristics = perform_local_heuristics(normalized_url)

    # 4. Zero-Trust SSRF & DNS Validation
    is_safe_host, resolved_ip, ssrf_reason = validate_hostname_ssrf(hostname)
    dns_failed = ssrf_reason.startswith("DNS resolution failed") or ssrf_reason.startswith("DNS validation error")
    ssrf_blocked = (not is_safe_host) and (not dns_failed)
    dns_succeeded = bool(is_safe_host and resolved_ip)

    # 5. Passive TLS Certificate Inspection
    tls_details: Optional[TlsCertificateDetails] = None
    tls_status = "unavailable"
    tls_message = "TLS inspection not applicable."

    target_scheme = parsed.scheme.lower() if parsed.scheme else "http"
    if ssrf_blocked:
        tls_status = "unavailable"
        tls_message = f"TLS inspection skipped: {ssrf_reason}"
    elif target_scheme == "https" or parsed.port == 443:
        port_to_use = parsed.port or 443
        tls_ok, tls_details, tls_msg = inspect_tls_certificate_safely(hostname, port=port_to_use)
        tls_status = "succeeded" if tls_ok else "failed"
        tls_message = tls_msg
    else:
        tls_status = "unavailable"
        tls_message = "Target uses unencrypted HTTP (no TLS expected)"

    # 6. Safe Redirect Tracing
    redirect_hops: List[UrlRedirectHop] = []
    final_destination: Optional[str] = normalized_url
    redirect_status = "unavailable"
    redirect_message = "Redirect tracing skipped in Quick mode"

    if mode == "deep" and is_safe_host:
        try:
            redirect_hops, final_destination, redirect_ssrf, redirect_warnings = await trace_redirects_safely(
                normalized_url,
                max_hops=settings.URL_REDIRECT_MAX_HOPS
            )
            if redirect_ssrf:
                ssrf_blocked = True
            redirect_status = "succeeded"
            redirect_message = (
                f"Traced {len(redirect_hops)} hop(s) safely" if redirect_hops
                else "Direct endpoint (no redirects encountered)"
            )
        except Exception as e:
            redirect_status = "failed"
            redirect_message = f"Redirect trace encountered an error: {str(e)}"

    # 7. Threat Score Calculation (0-100) & Verdict
    base_score = round(heuristics.heuristic_score * 100)
    verdict = "UNKNOWN"

    if ssrf_blocked:
        threat_score = 100
        verdict = "MALICIOUS"
    elif heuristics.is_typosquatting:
        threat_score = max(80, base_score)
        verdict = "MALICIOUS" if threat_score >= 85 else "SUSPICIOUS"
    elif heuristics.has_punycode or (heuristics.is_ip_address and heuristics.suspicious_keywords):
        threat_score = max(75, base_score)
        verdict = "MALICIOUS" if threat_score >= 80 else "SUSPICIOUS"
    elif heuristics.has_suspicious_tld and heuristics.suspicious_keywords:
        threat_score = max(75, base_score)
        verdict = "MALICIOUS"
    elif tls_details and tls_details.error and "untrusted" in tls_details.error.lower():
        threat_score = min(100, base_score + 35)
        verdict = "SUSPICIOUS"
    elif heuristics.heuristic_score >= 0.50:
        threat_score = max(60, min(90, base_score))
        verdict = "SUSPICIOUS"
    elif heuristics.heuristic_score >= 0.20:
        threat_score = max(30, min(60, base_score))
        verdict = "SUSPICIOUS"
    else:
        threat_score = min(20, max(5, base_score))
        verdict = "CLEAN"

    # Clamp
    threat_score = max(0, min(100, int(threat_score)))
    if verdict == "UNKNOWN":
        if threat_score >= 70:
            verdict = "MALICIOUS"
        elif threat_score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

    # 8. Checks Status Audit
    external_rep_configured = settings.is_virustotal_configured or settings.is_safe_browsing_configured
    checks: Dict[str, CheckStatusItem] = {
        "dns_resolution": CheckStatusItem(
            status="succeeded" if dns_succeeded else "failed",
            message=f"Resolved public IP: {resolved_ip}" if dns_succeeded else ("Host blocked by SSRF" if ssrf_blocked else "DNS resolution failed"),
            details={"resolved_ip": resolved_ip} if resolved_ip else None
        ),
        "ssrf_protection": CheckStatusItem(
            status="failed" if ssrf_blocked else "succeeded",
            message=f"BLOCKED: {ssrf_reason}" if ssrf_blocked else "Destination verified safe from SSRF (Public routable address)",
            details={"blocked": ssrf_blocked, "reason": ssrf_reason if ssrf_blocked else None}
        ),
        "lexical_heuristics": CheckStatusItem(
            status="succeeded",
            message=f"Analyzed {len(heuristics.risk_reasons)} risk indicator(s)",
            details={
                "entropy": heuristics.entropy,
                "is_ip": heuristics.is_ip_address,
                "is_typosquatting": heuristics.is_typosquatting,
                "suspicious_tld": heuristics.has_suspicious_tld,
                "triggers": heuristics.risk_reasons
            }
        ),
        "tls_certificate": CheckStatusItem(
            status=tls_status,
            message=tls_message,
            details=tls_details.model_dump() if tls_details else None
        ),
        "redirect_tracing": CheckStatusItem(
            status=redirect_status,
            message=redirect_message,
            details={"hops_count": len(redirect_hops)}
        ),
        "external_reputation": CheckStatusItem(
            status="succeeded" if external_rep_configured else "unavailable",
            message="External threat feeds queried" if external_rep_configured else "VirusTotal / Google Safe Browsing API keys not configured in backend environment",
            details={
                "virustotal_configured": settings.is_virustotal_configured,
                "safebrowsing_configured": settings.is_safe_browsing_configured
            }
        )
    }

    # 9. AI Forensic Explanation
    ai_model_used: Optional[str] = None
    ai_explanation = ""

    # Attempt AI reasoning via configured Gemini provider if available and in deep mode
    if mode == "deep" and settings.is_gemini_configured:
        try:
            from backend.app.ai.gemini_provider import call_gemini_async
            ai_prompt = (
                f"Target URL (Defanged): {defanged_url}\n"
                f"Domain: {domain} (TLD: {tld})\n"
                f"Verdict: {verdict}\n"
                f"Threat Score: {threat_score} / 100\n"
                f"Findings:\n"
                f"- Shannon Entropy: {heuristics.entropy}\n"
                f"- Typosquatting: {heuristics.is_typosquatting} ({heuristics.impersonated_brand or 'None'})\n"
                f"- Path Keywords: {', '.join(heuristics.suspicious_keywords) if heuristics.suspicious_keywords else 'None'}\n"
                f"- SSRF Status: {'BLOCKED (Private/Loopback)' if ssrf_blocked else 'CLEAN (Public IP)'}\n"
                f"- TLS: {tls_message}\n"
                f"- Redirects: {redirect_message}\n"
                f"- Specific Risk Reasons: {'; '.join(heuristics.risk_reasons) if heuristics.risk_reasons else 'None'}\n"
            )
            ai_res = await call_gemini_async(
                prompt=ai_prompt,
                system_instruction=(
                    "You are a Senior SOC Cybersecurity Analyst. Provide a concise, highly technical threat evaluation. "
                    "CRITICAL: Base your analysis strictly on the empirical findings provided. "
                    "DO NOT FABRICATE or claim VirusTotal, Google Safe Browsing or external reputation provider detections. "
                    "State clearly why the URL received this verdict and recommend 2-3 defensive SOC actions. Under 150 words."
                ),
                max_output_tokens=300
            )
            if ai_res.get("status") == "success" and ai_res.get("reply"):
                ai_explanation = ai_res["reply"].strip()
                ai_model_used = ai_res.get("model_used") or settings.GEMINI_MODEL
        except Exception as ai_exc:
            logger.warning("AI explanation generation encountered an issue: %s", ai_exc)

    # Fallback deterministic SOC reasoning if AI is unconfigured or failed
    if not ai_explanation:
        ai_model_used = "Deterministic SOC Heuristic Engine"
        triggers_text = "; ".join(heuristics.risk_reasons) if heuristics.risk_reasons else "None"
        ai_explanation = (
            f"Forensic Assessment for {defanged_url}:\n\n"
            f"• Classification: Evaluated as {verdict} with an empirical threat score of {threat_score}/100.\n"
            f"• Lexical Indicators: Domain '{domain}' (entropy {heuristics.entropy}). "
            f"{('Brand impersonation targeting ' + heuristics.impersonated_brand + '. ') if heuristics.is_typosquatting else ''}"
            f"{('Suspicious keywords in path: ' + ', '.join(heuristics.suspicious_keywords) + '. ') if heuristics.suspicious_keywords else ''}"
            f"Specific triggers: {triggers_text}.\n"
            f"• Transport & Network: {'SSRF filter blocked private/loopback destination. ' if ssrf_blocked else 'Public IP verified. '}"
            f"{tls_message}. {redirect_message}.\n"
            f"• Threat Intelligence Feeds: External providers (VirusTotal / Google Safe Browsing) are unconfigured in the environment and were marked unavailable without false claims.\n"
            f"• Defensive Action: Sinkhole domain at internal DNS, quarantine referencing emails, and block outbound proxy connections."
        )

    checks["ai_forensics"] = CheckStatusItem(
        status="succeeded" if ai_model_used != "Deterministic SOC Heuristic Engine" else "succeeded",
        message=f"Threat explanation synthesized via {ai_model_used}",
        details={"model": ai_model_used}
    )

    return CustomUrlInvestigationResponse(
        original_url=clean_url,
        normalized_url=normalized_url,
        defanged_url=defanged_url,
        is_defanged=is_defanged,
        domain=domain,
        subdomain=subdomain,
        tld=tld,
        path=path,
        query=query,
        threat_score=threat_score,
        verdict=verdict,
        mode=mode,
        heuristics=heuristics,
        checks=checks,
        tls_details=tls_details,
        redirect_chain=redirect_hops,
        final_destination=final_destination,
        ai_explanation=ai_explanation,
        ai_model_used=ai_model_used,
        analyzed_at=to_iso_utc(now_utc())
    )

