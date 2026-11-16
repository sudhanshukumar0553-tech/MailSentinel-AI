"""
MailSentinel AI - Email Header Authentication Analyzer

Evaluates transport headers for email spoofing and sender authentication:
- Checks SPF (Sender Policy Framework)
- Checks DKIM (DomainKeys Identified Mail)
- Checks DMARC (Domain-based Message Authentication, Reporting & Conformance)
- Checks Received hop chains

CRITICAL ACCURACY RULE:
If email transport headers were NOT provided (e.g. pasted email body),
the analyzer explicitly reports "Headers not provided" and NEVER claims
SPF/DKIM passed or verified.
"""

import re
from typing import Any, Dict


def analyze_email_headers(raw_headers: Dict[str, str], has_headers: bool) -> Dict[str, Any]:
    """
    Analyzes email transport headers for spoofing, SPF, DKIM, and DMARC integrity.

    Returns:
        Dictionary containing:
        - status: "verified", "failed", or "headers_not_provided"
        - risk_score: 0.0 (clean/no headers) to 1.0 (critical failure)
        - spf_status: "pass", "fail", "softfail", "none", or "not_provided"
        - dkim_status: "pass", "fail", "none", or "not_provided"
        - dmarc_status: "pass", "fail", "none", or "not_provided"
        - findings: List of human-readable security observations
    """
    if not has_headers or not raw_headers:
        return {
            "status": "headers_not_provided",
            "risk_score": 0.0,
            "spf_status": "not_provided",
            "dkim_status": "not_provided",
            "dmarc_status": "not_provided",
            "hop_count": 0,
            "findings": [
                "Headers not provided: Email was analyzed from plain text content alone.",
                "SPF, DKIM, and DMARC authentication could not be evaluated without transport headers."
            ],
            "is_spoofed": False
        }

    findings = []
    risk_score = 0.0
    headers_lower = {k.lower(): str(v).lower() for k, v in raw_headers.items()}

    # 1. Analyze SPF
    spf_status = "none"
    auth_results = headers_lower.get("authentication-results", "")
    received_spf = headers_lower.get("received-spf", "")

    combined_spf_text = f"{auth_results} {received_spf}"
    if "spf=pass" in combined_spf_text:
        spf_status = "pass"
        findings.append("SPF verification passed.")
    elif "spf=fail" in combined_spf_text:
        spf_status = "fail"
        risk_score += 0.40
        findings.append("CRITICAL: SPF check failed! The sending server is unauthorized.")
    elif "spf=softfail" in combined_spf_text:
        spf_status = "softfail"
        risk_score += 0.25
        findings.append("WARNING: SPF softfail detected. Mail may be forwarded or spoofed.")
    else:
        spf_status = "none"
        findings.append("SPF record was not explicitly found in headers.")

    # 2. Analyze DKIM
    dkim_status = "none"
    if "dkim=pass" in auth_results:
        dkim_status = "pass"
        findings.append("DKIM cryptographic signature verified.")
    elif "dkim=fail" in auth_results:
        dkim_status = "fail"
        risk_score += 0.40
        findings.append("CRITICAL: DKIM signature verification failed! Message was altered in transit.")
    elif "dkim-signature" in headers_lower:
        dkim_status = "present_unverified"
        findings.append("DKIM-Signature header present.")
    else:
        findings.append("DKIM signature was not found.")

    # 3. Analyze DMARC
    dmarc_status = "none"
    if "dmarc=pass" in auth_results:
        dmarc_status = "pass"
        findings.append("DMARC alignment passed.")
    elif "dmarc=fail" in auth_results:
        dmarc_status = "fail"
        risk_score += 0.35
        findings.append("CRITICAL: DMARC policy check failed.")

    # 4. Hop Count Analysis
    received_headers = [v for k, v in raw_headers.items() if k.lower() == "received"]
    hop_count = len(received_headers)
    if hop_count > 8:
        risk_score += 0.10
        findings.append(f"Suspicious relaying: Email traversed an unusually long route ({hop_count} hops).")

    # Final Risk Normalization
    risk_score = min(1.0, round(risk_score, 4))
    overall_status = "failed" if risk_score >= 0.40 else "verified" if risk_score == 0.0 else "suspicious"

    return {
        "status": overall_status,
        "risk_score": risk_score,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "hop_count": hop_count,
        "findings": findings,
        "is_spoofed": risk_score >= 0.40
    }

