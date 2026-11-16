"""
Unit tests for smolagents cybersecurity tools and agent orchestration.
"""

import json
from backend.app.ai.tools import (
    analyze_spam_probability,
    analyze_phishing_probability,
    inspect_email_urls,
    inspect_email_headers,
    calculate_threat_risk,
    generate_security_report
)
from backend.app.ai.agent import execute_deterministic_fallback_investigation


def test_individual_agent_tools():
    """Verify that each of the 6 security tools returns valid structured outputs."""
    sample_text = "Verify your account at https://paypa1-update.xyz/login immediately!"

    # Tool 1: Spam
    spam_res = json.loads(analyze_spam_probability(sample_text))
    assert spam_res["tool"] == "analyze_spam_probability"
    assert "spam_probability" in spam_res

    # Tool 2: Phishing
    phish_res = json.loads(analyze_phishing_probability(sample_text))
    assert phish_res["tool"] == "analyze_phishing_probability"
    assert "phishing_probability" in phish_res

    # Tool 3: URLs
    url_res = json.loads(inspect_email_urls(sample_text))
    assert url_res["tool"] == "inspect_email_urls"
    assert url_res["total_urls_found"] == 1
    assert "hxxps://" in url_res["inspected_urls"][0]["defanged_url"]

    # Tool 4: Headers
    headers_res = json.loads(inspect_email_headers("none"))
    assert headers_res["tool"] == "inspect_email_headers"
    assert headers_res["status"] == "headers_not_provided"

    # Tool 5: Risk calculation
    risk_res = json.loads(calculate_threat_risk(
        spam_prob=0.8,
        phish_prob=0.9,
        url_risk=0.85,
        header_risk=0.0
    ))
    assert risk_res["tool"] == "calculate_threat_risk"
    assert risk_res["risk_score"] > 70.0
    assert risk_res["threat_level"] in ["DANGEROUS", "CRITICAL"]

    # Tool 6: Security Report
    report = generate_security_report(
        verdict="Phishing Detected",
        risk_score=85.0,
        findings="- Malicious URL detected"
    )
    assert "MailSentinel AI - SOC Incident Investigation Report" in report
    assert "85.0" in report


def test_deterministic_investigation_pipeline():
    """Verify that the full multi-tool investigation pipeline completes flawlessly."""
    test_email = "Your PayPal account has been locked. Verify at http://192.168.1.1/login"
    result = execute_deterministic_fallback_investigation(test_email, raw_headers="none")

    assert result["status"] == "completed"
    assert result["steps_count"] == 5
    assert len(result["steps"]) == 5
    assert "final_report" in result
    assert result["risk_score"] > 0

