"""
MailSentinel AI - Unified Risk Scoring Engine

Calculates an overall threat score (0-100) and severity rating by synthesizing:
1. Machine Learning Spam Probability
2. Machine Learning Phishing Probability
3. Lexical URL Risk Analysis
4. Transport Header Authentication Status (SPF/DKIM/DMARC)
"""

from typing import Any, Dict, List


def calculate_unified_risk(
    spam_prob: float,
    phish_prob: float,
    url_risk: float,
    header_risk: float,
    has_headers: bool = False
) -> Dict[str, Any]:
    """
    Computes a synthesized 0-100 risk score and categorizes into threat severity tiers.

    Tiers:
    - SAFE: 0.0 - 25.0
    - SUSPICIOUS: 25.1 - 60.0
    - DANGEROUS: 60.1 - 85.0
    - CRITICAL: 85.1 - 100.0
    """
    # Ensure inputs are bounded between 0.0 and 1.0
    s_prob = max(0.0, min(1.0, float(spam_prob)))
    p_prob = max(0.0, min(1.0, float(phish_prob)))
    u_risk = max(0.0, min(1.0, float(url_risk)))
    h_risk = max(0.0, min(1.0, float(header_risk)))

    # Weighted calculation adjusting for whether headers were provided
    if has_headers:
        # Standard full-transport weighting
        raw_score = (s_prob * 0.25) + (p_prob * 0.40) + (u_risk * 0.20) + (h_risk * 0.15)
    else:
        # Weighting redistributed to text and URLs when headers are absent
        raw_score = (s_prob * 0.30) + (p_prob * 0.45) + (u_risk * 0.25)

    # Multiplier: If phishing model has very high confidence (>0.85), increase score
    if p_prob >= 0.85:
        raw_score = max(raw_score, p_prob * 0.90)

    # Scale to 0-100
    risk_score = round(min(100.0, max(0.0, raw_score * 100.0)), 1)

    # Determine Threat Level Tier
    if risk_score <= 25.0:
        threat_level = "SAFE"
        verdict = "Low Risk / Clean Message"
        color = "#10B981"  # Emerald
    elif risk_score <= 60.0:
        threat_level = "SUSPICIOUS"
        verdict = "Suspicious Email - Exercise Caution"
        color = "#F59E0B"  # Amber
    elif risk_score <= 85.0:
        threat_level = "DANGEROUS"
        verdict = "High Risk Phishing or Malicious Payload"
        color = "#F97316"  # Orange
    else:
        threat_level = "CRITICAL"
        verdict = "Critical Security Threat / Confirmed Malicious"
        color = "#EF4444"  # Rose

    # Generate actionable remediation recommendations
    recommendations: List[str] = []
    if threat_level in ["DANGEROUS", "CRITICAL"]:
        recommendations.append("Do not click any embedded links or respond to the sender.")
        recommendations.append("Quarantine this email in the mail gateway.")
        if p_prob >= 0.70:
            recommendations.append("If credentials were entered, immediately reset account passwords and revoke active sessions.")
        if h_risk >= 0.40:
            recommendations.append("Add the sending IP/domain to the firewall blocklist.")
    elif threat_level == "SUSPICIOUS":
        recommendations.append("Inspect links manually in an isolated sandbox before interacting.")
        recommendations.append("Confirm the sender's identity through an out-of-band communication channel.")
    else:
        recommendations.append("No immediate threats detected. Standard security hygiene applies.")

    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "verdict": verdict,
        "theme_color": color,
        "factor_breakdown": {
            "spam_contribution": round(s_prob * 100, 1),
            "phishing_contribution": round(p_prob * 100, 1),
            "url_contribution": round(u_risk * 100, 1),
            "header_contribution": round(h_risk * 100, 1) if has_headers else None
        },
        "recommendations": recommendations
    }

