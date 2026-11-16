"""
MailSentinel AI - smolagents Security Investigation Tools

The 6 mandated tools for the autonomous SOC investigation agent:
1. analyze_spam_probability
2. analyze_phishing_probability
3. inspect_email_urls
4. inspect_email_headers
5. calculate_threat_risk
6. generate_security_report
"""

import json
try:
    from smolagents import tool
except ImportError:
    # Resilient fallback decorator if smolagents is unavailable
    def tool(func):
        return func
from backend.app.ml.models import SpamClassifier, PhishingClassifier
from backend.app.services.url_analyzer import analyze_email_urls
from backend.app.services.header_analyzer import analyze_email_headers
from backend.app.services.email_parser import parse_email_input
from backend.app.services.risk_engine import calculate_unified_risk


@tool
def analyze_spam_probability(email_text: str) -> str:
    """Runs the trained Spam Detection Machine Learning model to calculate spam probability and identify trigger keywords.
    Args:
        email_text: The untrusted email body or snippet to analyze for spam indicators.
    """
    res = SpamClassifier.predict(email_text)
    return json.dumps({
        "tool": "analyze_spam_probability",
        "spam_probability": res["probability"],
        "is_spam": res["is_spam"],
        "confidence": res["confidence"],
        "detected_triggers": res["triggers"]
    })


@tool
def analyze_phishing_probability(email_text: str) -> str:
    """Runs the trained Phishing Detection Machine Learning model to detect credential harvesting and deceptive intent.
    Args:
        email_text: The untrusted email body to analyze for credential theft and phishing indicators.
    """
    res = PhishingClassifier.predict(email_text)
    return json.dumps({
        "tool": "analyze_phishing_probability",
        "phishing_probability": res["probability"],
        "is_phishing": res["is_phishing"],
        "confidence": res["confidence"],
        "detected_triggers": res["triggers"]
    })


@tool
def inspect_email_urls(email_text: str) -> str:
    """Extracts all embedded URLs, defangs them, computes Shannon entropy, and flags suspicious TLDs or IP addresses without opening them.
    Args:
        email_text: The email body containing links to inspect.
    """
    res = analyze_email_urls(email_text)
    return json.dumps({
        "tool": "inspect_email_urls",
        "total_urls_found": res["total_count"],
        "suspicious_urls_count": res["suspicious_count"],
        "max_url_risk_score": res["aggregate_risk"],
        "inspected_urls": [
            {
                "defanged_url": u["raw_url_defanged"],
                "normalized_url": u.get("normalized_url", u["raw_url_defanged"]),
                "domain": u["domain"],
                "threat_classification": u.get("threat_classification", "SUSPICIOUS" if u["is_suspicious"] else "UNKNOWN"),
                "risk_score": u.get("risk_score", 0.0),
                "entropy": u["entropy"],
                "is_suspicious": u["is_suspicious"],
                "risk_reasons": u["risk_reasons"],
                "indicators": u.get("indicators", u["risk_reasons"]),
                "reputation_status": u.get("reputation_status", "Local Heuristics Evaluated"),
                "analyzed_at": u.get("analyzed_at", ""),
                "note": u["verification_note"]
            }
            for u in res["urls"][:10]
        ]
    })


@tool
def inspect_email_headers(raw_headers: str) -> str:
    """Inspects RFC822 transport headers for SPF, DKIM, and DMARC integrity. If headers are absent, explicitly reports that headers were not provided.
    Args:
        raw_headers: The raw transport headers string or 'none' if headers were omitted.
    """
    if not raw_headers or raw_headers.strip().lower() in ["none", "empty", "", "null"]:
        return json.dumps({
            "tool": "inspect_email_headers",
            "status": "headers_not_provided",
            "header_risk_score": 0.0,
            "spf_status": "not_provided",
            "dkim_status": "not_provided",
            "dmarc_status": "not_provided",
            "is_spoofed": False,
            "findings": ["Headers not provided; SPF/DKIM/DMARC authentication not evaluated."],
            "message": "Headers not provided; SPF/DKIM/DMARC authentication not evaluated."
        })

    parsed = parse_email_input(raw_headers)
    res = analyze_email_headers(parsed["raw_headers"], parsed["has_headers"])
    return json.dumps({
        "tool": "inspect_email_headers",
        "status": res["status"],
        "header_risk_score": res["risk_score"],
        "spf_status": res["spf_status"],
        "dkim_status": res["dkim_status"],
        "dmarc_status": res["dmarc_status"],
        "is_spoofed": res["is_spoofed"],
        "findings": res["findings"]
    })


@tool
def calculate_threat_risk(
    spam_prob: float,
    phish_prob: float,
    url_risk: float,
    header_risk: float
) -> str:
    """Synthesizes all tool findings into a unified 0-100 threat risk score and severity tier (SAFE, SUSPICIOUS, DANGEROUS, CRITICAL).
    Args:
        spam_prob: Probability of spam between 0.0 and 1.0.
        phish_prob: Probability of phishing between 0.0 and 1.0.
        url_risk: Highest URL risk score between 0.0 and 1.0.
        header_risk: Header authentication risk score between 0.0 and 1.0.
    """
    has_headers = header_risk > 0.0
    res = calculate_unified_risk(spam_prob, phish_prob, url_risk, header_risk, has_headers=has_headers)
    return json.dumps({
        "tool": "calculate_threat_risk",
        "risk_score": res["risk_score"],
        "threat_level": res["threat_level"],
        "verdict": res["verdict"],
        "recommendations": res["recommendations"]
    })


@tool
def generate_security_report(
    verdict: str,
    risk_score: float,
    findings: str
) -> str:
    """Formats the synthesized investigation evidence into a professional SOC Incident Analysis Report.
    Args:
        verdict: Final threat verdict label.
        risk_score: Unified threat score between 0 and 100.
        findings: Key summary findings gathered from prior tool executions.
    """
    return f"""### MailSentinel AI - SOC Incident Investigation Report
- **Threat Verdict**: {verdict}
- **Synthesized Threat Score**: {risk_score} / 100.0
- **Forensic Findings**:
{findings}

**Recommended Analyst Action**:
- Implement immediate firewall domain block if malicious URLs were identified.
- Inform end-users not to interact with unverified senders.
- Report finalized by MailSentinel AI Autonomous Investigation Agent.
"""


ALL_SECURITY_TOOLS = [
    analyze_spam_probability,
    analyze_phishing_probability,
    inspect_email_urls,
    inspect_email_headers,
    calculate_threat_risk,
    generate_security_report
]

