"""
Unit tests for email parsing, SPF/DKIM header analysis, URL defanging, and risk engine.
"""

from backend.app.services.email_parser import parse_email_input
from backend.app.services.header_analyzer import analyze_email_headers
from backend.app.services.url_analyzer import analyze_email_urls, calculate_shannon_entropy
from backend.app.services.risk_engine import calculate_unified_risk


def test_plain_pasted_text_does_not_claim_spf_verification():
    """
    CRITICAL REQUIREMENT: Pasted email text without headers must explicitly
    state that headers are not provided and NOT claim SPF/DKIM verification.
    """
    pasted_text = "Dear employee, your mailbox is full. Click here to clean it."
    parsed = parse_email_input(pasted_text)

    assert parsed["has_headers"] is False
    assert parsed["body"] == pasted_text

    header_result = analyze_email_headers(parsed["raw_headers"], parsed["has_headers"])
    assert header_result["status"] == "headers_not_provided"
    assert header_result["spf_status"] == "not_provided"
    assert header_result["dkim_status"] == "not_provided"
    assert "Headers not provided" in header_result["findings"][0]


def test_mime_email_parsing_with_auth_headers():
    """Verify standard RFC822 transport header extraction."""
    raw_rfc822 = """Received: from mail.evil.com (1.2.3.4) by mx.company.com
Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail
From: Security Alert <spoofed@bank.com>
To: target@victim.com
Subject: Unauthorized Withdrawal Alert
Date: Mon, 15 Nov 2026 12:00:00 +0000

We detected an unauthorized transaction. Please verify immediately.
"""
    parsed = parse_email_input(raw_rfc822)
    assert parsed["has_headers"] is True
    assert parsed["subject"] == "Unauthorized Withdrawal Alert"

    header_result = analyze_email_headers(parsed["raw_headers"], parsed["has_headers"])
    assert header_result["status"] == "failed"
    assert header_result["spf_status"] == "fail"
    assert header_result["dkim_status"] == "fail"
    assert header_result["dmarc_status"] == "fail"
    assert header_result["risk_score"] >= 0.70


def test_url_extraction_defanging_and_entropy():
    """Verify URL defanging and lexical anomaly detection without making network requests."""
    text_with_links = (
        "Check this link: http://192.168.1.100/login and https://security-auth-99xkz.xyz/reset"
    )
    result = analyze_email_urls(text_with_links)
    assert result["total_count"] == 2
    assert result["suspicious_count"] >= 1

    urls = result["urls"]
    for u in urls:
        # Verify defanging
        assert "http://" not in u["raw_url_defanged"]
        assert "https://" not in u["raw_url_defanged"]
        assert "[.]" in u["raw_url_defanged"]
        # Verify verification note is cautious
        assert "100% safe" not in u["verification_note"].lower()

    # Test Shannon entropy calculation
    low_entropy = calculate_shannon_entropy("google.com")
    high_entropy = calculate_shannon_entropy("x7k9p3q1z8a2b5c0d.xyz")
    assert high_entropy > low_entropy


def test_risk_scoring_matrix():
    """Verify threat tier classification thresholds."""
    # Safe scenario
    safe = calculate_unified_risk(spam_prob=0.05, phish_prob=0.02, url_risk=0.0, header_risk=0.0, has_headers=True)
    assert safe["threat_level"] == "SAFE"

    # Suspicious scenario
    suspicious = calculate_unified_risk(spam_prob=0.55, phish_prob=0.35, url_risk=0.2, header_risk=0.0, has_headers=False)
    assert suspicious["threat_level"] == "SUSPICIOUS"

    # Critical phishing scenario
    critical = calculate_unified_risk(spam_prob=0.85, phish_prob=0.95, url_risk=0.8, header_risk=0.9, has_headers=True)
    assert critical["threat_level"] == "CRITICAL"
    assert len(critical["recommendations"]) > 0

