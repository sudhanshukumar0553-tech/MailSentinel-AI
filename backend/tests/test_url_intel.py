"""
Tests for URL Threat Intelligence Engine (Phase 3.5).
Covers URL extraction, normalization, defanging, Shannon entropy,
Levenshtein typosquatting, strict SSRF blocking, safe redirect tracing,
and URL analysis API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.url_threat_intel import (
    calculate_shannon_entropy,
    extract_urls_from_content,
    normalize_url,
    levenshtein_distance,
    perform_local_heuristics,
    is_ip_safe_for_outbound,
    validate_hostname_ssrf,
    analyze_url_threat_intelligence,
)


@pytest.fixture
def client():
    return TestClient(app)


# 1. URL Extraction Tests
def test_extract_urls_plain_and_html():
    text = (
        "Check this link: https://example.com/login and click "
        '<a href="http://malicious-phish.xyz/verify">here</a> or visit '
        "hxxps://evil-attacker[.]com/drop."
    )
    urls = extract_urls_from_content(text)
    assert len(urls) >= 3
    assert any("evil-attacker" in u for u in urls)
    assert any("malicious-phish" in u for u in urls)
    assert any("example.com" in u for u in urls)


def test_normalize_url():
    raw_url = "hxxps://paypa1[.]com/update-security"
    normalized = normalize_url(raw_url)
    assert normalized.startswith("https://")
    assert "paypa1.com" in normalized
    assert "[.]" not in normalized


# 2. Shannon Entropy Tests
def test_shannon_entropy_calculation():
    low_entropy = calculate_shannon_entropy("google.com")
    high_entropy = calculate_shannon_entropy("a98z7q2w1v0p4x3m8k.com/x?token=89abcf103289deadbeef")
    assert high_entropy > low_entropy
    assert low_entropy < 3.5
    assert high_entropy > 3.8


# 3. Brand Typosquatting / Levenshtein Tests
def test_brand_typosquatting_detection():
    # Levenshtein distance 1 from paypal
    dist = levenshtein_distance("paypa1", "paypal")
    assert dist == 1

    # Exact match distance 0
    assert levenshtein_distance("paypal", "paypal") == 0

    # Heuristics detection
    heuristics = perform_local_heuristics("http://paypa1.com/login")
    assert heuristics.impersonated_brand == "paypal"
    assert heuristics.is_typosquatting is True


# 4. Strict SSRF Protection Tests
def test_ssrf_blocking_private_and_loopback_ips():
    # Loopback
    safe, _ = is_ip_safe_for_outbound("127.0.0.1")
    assert safe is False

    safe, _ = is_ip_safe_for_outbound("::1")
    assert safe is False

    # RFC 1918 Private
    safe, _ = is_ip_safe_for_outbound("10.0.0.1")
    assert safe is False

    safe, _ = is_ip_safe_for_outbound("192.168.1.1")
    assert safe is False

    safe, _ = is_ip_safe_for_outbound("172.16.0.1")
    assert safe is False

    # Cloud Metadata
    safe, _ = is_ip_safe_for_outbound("169.254.169.254")
    assert safe is False

    # Valid Public IP
    safe, _ = is_ip_safe_for_outbound("8.8.8.8")
    assert safe is True


def test_ssrf_blocking_hostname():
    # Localhost
    safe, _, reason = validate_hostname_ssrf("localhost")
    assert safe is False
    assert "blocked" in reason.lower()

    # Local / internal domain suffixes
    safe, _, reason = validate_hostname_ssrf("internal.corp.local")
    assert safe is False


@pytest.mark.asyncio
async def test_url_service_rejects_ssrf_target():
    result = await analyze_url_threat_intelligence("http://127.0.0.1:8000/internal-admin")
    assert result.verdict == "MALICIOUS"
    assert result.ssrf_blocked is True
    assert any("Critical Security Violation" in r or "prohibited" in r.lower() or "blocked" in r.lower() for r in result.threat_reasons)


# 5. Service Analysis & Heuristics Tests
@pytest.mark.asyncio
async def test_url_service_flags_typosquatting():
    result = await analyze_url_threat_intelligence("http://paypa1-update.xyz/login")
    assert result.verdict in ["SUSPICIOUS", "MALICIOUS"]
    assert result.heuristics.is_typosquatting is True
    assert result.heuristics.impersonated_brand == "paypal"


@pytest.mark.asyncio
async def test_url_service_cache():
    url = "https://example.com/safe-page"
    r1 = await analyze_url_threat_intelligence(url, follow_redirects=False)
    assert r1.cached is False

    r2 = await analyze_url_threat_intelligence(url, follow_redirects=False)
    assert r2.cached is True
    assert r2.normalized_url == r1.normalized_url


# 6. API Endpoints Tests
def test_api_url_providers(client):
    response = client.get("/api/v1/url/providers")
    assert response.status_code == 200
    data = response.json()
    assert "providers" in data
    assert "virustotal" in data["providers"]
    assert "google_safebrowsing" in data["providers"]
    assert "local_heuristics" in data["providers"]
    assert "ssrf_protection" in data["providers"]


def test_api_url_analyze_safe(client):
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "https://example.com/docs", "follow_redirects": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert "defanged_url" in data
    assert "confidence" in data
    assert "heuristics" in data
    assert "reputation" in data


def test_api_url_analyze_ssrf_blocked(client):
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "http://169.254.169.254/latest/meta-data"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "MALICIOUS"
    assert data["ssrf_blocked"] is True


def test_api_url_batch_analyze(client):
    response = client.post(
        "/api/v1/url/batch",
        json={
            "urls": [
                "https://example.com",
                "http://paypa1-alert.com/login",
                "http://127.0.0.1/admin"
            ]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 3


def test_api_url_extract_and_analyze(client):
    email_content = (
        "URGENT: Verify your account at hxxps://login.microsoft365-verify[.]xyz/auth immediately! "
        'Also visit <a href="http://paypa1-security.xyz/login">here</a> and repeat '
        "hxxps://login.microsoft365-verify[.]xyz/auth"  # duplicate
    )
    response = client.post(
        "/api/v1/url/extract",
        json={"content": email_content, "follow_redirects": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Deduplication check: 2 unique URLs instead of 3
    assert len(data) == 2
    domains = [item["domain"] for item in data]
    assert any("microsoft365-verify" in d for d in domains)
    assert any("paypa1-security" in d for d in domains)
    assert all("defanged_url" in item for item in data)
    assert all("threat_reasons" in item for item in data)


def test_api_url_extract_empty_and_no_urls(client):
    # Empty content
    r1 = client.post("/api/v1/url/extract", json={"content": ""})
    assert r1.status_code == 200
    assert r1.json() == []

    # Whitespace content
    r2 = client.post("/api/v1/url/extract", json={"content": "   \n\t  "})
    assert r2.status_code == 200
    assert r2.json() == []

    # Content without any URLs
    r3 = client.post(
        "/api/v1/url/extract",
        json={"content": "Hello team, please process this invoice for our quarterly review. Thanks."}
    )
    assert r3.status_code == 200
    assert r3.json() == []


# 8. Custom AI URL Investigation Tests (Phase 4.2)
def test_custom_url_investigate_defanged_phish(client):
    """Tests custom URL scanner with defanged credential harvesting phishing URL."""
    payload = {
        "url": "hxxps://login.microsoft365-verify[.]xyz/auth",
        "mode": "deep"
    }
    response = client.post("/api/v1/url/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["is_defanged"] is True
    assert "login[.]microsoft365-verify[.]xyz" in data["defanged_url"]
    assert data["normalized_url"].startswith("https://")
    assert data["domain"] == "microsoft365-verify.xyz"
    assert data["subdomain"] == "login"
    assert data["tld"] == "xyz"
    assert data["path"] == "/auth"
    assert data["threat_score"] >= 70
    assert data["verdict"] in ["MALICIOUS", "SUSPICIOUS"]

    # Verify checks dictionary
    assert "checks" in data
    assert data["checks"]["ssrf_protection"]["status"] == "succeeded"
    assert data["checks"]["lexical_heuristics"]["status"] == "succeeded"
    assert data["checks"]["external_reputation"]["status"] == "unavailable"
    assert "ai_explanation" in data
    assert len(data["ai_explanation"]) > 20


def test_custom_url_investigate_ssrf_blocking(client):
    """Verifies that private IP, loopback, and cloud metadata targets are strictly blocked."""
    prohibited_urls = [
        "http://127.0.0.1:8000/admin",
        "http://localhost/metrics",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/internal-api",
        "http://192.168.1.1/router"
    ]
    for target in prohibited_urls:
        res = client.post("/api/v1/url/investigate", json={"url": target, "mode": "quick"})
        assert res.status_code == 200
        data = res.json()
        assert data["threat_score"] == 100
        assert data["verdict"] == "MALICIOUS"
        assert data["checks"]["ssrf_protection"]["status"] == "failed"
        assert "SSRF" in data["checks"]["ssrf_protection"]["message"] or "blocked" in data["checks"]["ssrf_protection"]["message"].lower()


def test_custom_url_investigate_clean_url(client):
    """Verifies that legitimate domains receive a CLEAN verdict with low risk score."""
    res = client.post("/api/v1/url/investigate", json={"url": "https://example.com", "mode": "quick"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "CLEAN"
    assert data["threat_score"] <= 25
    assert data["heuristics"]["is_typosquatting"] is False
    assert data["heuristics"]["has_suspicious_tld"] is False


def test_custom_url_investigate_malformed_and_prohibited_schemes(client):
    """Verifies rejection of dangerous URL schemes and empty payloads."""
    # Javascript scheme
    res1 = client.post("/api/v1/url/investigate", json={"url": "javascript:alert(1)"})
    assert res1.status_code == 400
    assert "scheme" in res1.json()["detail"].lower()

    # File scheme
    res2 = client.post("/api/v1/url/investigate", json={"url": "file:///etc/passwd"})
    assert res2.status_code == 400
    assert "scheme" in res2.json()["detail"].lower()

    # Empty payload
    res3 = client.post("/api/v1/url/investigate", json={"url": "   "})
    assert res3.status_code == 400

