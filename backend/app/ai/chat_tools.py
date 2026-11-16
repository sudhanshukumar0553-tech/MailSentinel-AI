"""
MailSentinel AI - Conversational Security Assistant Tools

Specialized tools for the interactive Cyber SOC Assistant:
1. summarize_email: Safely extracts key facts, deadlines, financial amounts, and requested actions.
2. draft_secure_reply: Generates defensive, policy-compliant email replies (e.g. asking for out-of-band verification).
3. explain_detection_verdict: Provides plain-English Explainable AI (XAI) analysis of ML scores and trigger tokens.
4. explain_security_concept: Educational tool for email authentication and cybersecurity threat vectors.
"""

import json
import re
from typing import Dict, Any, List
from smolagents import tool
from backend.app.ml.models import SpamClassifier, PhishingClassifier
from backend.app.services.url_analyzer import analyze_email_urls
from backend.app.services.risk_engine import calculate_unified_risk
from backend.app.services.email_parser import parse_email_input


@tool
def summarize_email(email_text: str) -> str:
    """Summarizes an untrusted email safely by extracting sender claims, deadlines, requested actions, and financial amounts.
    Args:
        email_text: The untrusted email text to summarize.
    """
    if not email_text or not email_text.strip():
        return json.dumps({
            "tool": "summarize_email",
            "summary": "Empty or whitespace-only email text provided.",
            "urgency_detected": False,
            "financial_request": False,
            "actions_requested": []
        })

    text = email_text.strip()
    lines = [line.strip() for line in text.split("\n") if line.strip()]

    # Extract subject if present
    subject = "Not specified"
    for line in lines[:5]:
        if line.lower().startswith("subject:"):
            subject = line[8:].strip()
            break

    # Urgency cues
    urgency_words = ["urgent", "immediate", "immediately", "24 hours", "expires", "suspended", "deadline", "action required"]
    found_urgency = [w for w in urgency_words if re.search(rf"\b{re.escape(w)}\b", text, re.IGNORECASE)]

    # Financial cues
    financial_pattern = r"(\$\s*[\d,]+|\bUSD\b|\bEUR\b|\bwire transfer\b|\binvoice\b|\bpayment\b|\bbitcoin\b|\bcrypto\b)"
    financial_matches = re.findall(financial_pattern, text, re.IGNORECASE)

    # Action detection
    action_cues = []
    if re.search(r"\b(click|link|portal|log ?in|sign ?in)\b", text, re.IGNORECASE):
        action_cues.append("Requests clicking a link or accessing an external portal.")
    if re.search(r"\b(password|credential|verify account|update billing)\b", text, re.IGNORECASE):
        action_cues.append("Requests account credential or billing verification.")
    if re.search(r"\b(transfer|wire|send money|pay)\b", text, re.IGNORECASE):
        action_cues.append("Requests monetary transfer or transaction execution.")
    if re.search(r"\b(download|open attachment|review document|docusign)\b", text, re.IGNORECASE):
        action_cues.append("Requests opening a document or electronic signature.")

    summary = (
        f"Subject: '{subject}' | Total Length: {len(text)} chars | "
        f"Urgency Level: {'HIGH' if found_urgency else 'NORMAL'} | "
        f"Financial Reference: {'YES' if financial_matches else 'NO'} | "
        f"Key Actions: {'; '.join(action_cues) if action_cues else 'General communication / Informational.'}"
    )

    return json.dumps({
        "tool": "summarize_email",
        "subject": subject,
        "summary": summary,
        "urgency_detected": bool(found_urgency),
        "urgency_triggers": found_urgency[:4],
        "financial_request": bool(financial_matches),
        "financial_cues": list(set(financial_matches))[:4],
        "actions_requested": action_cues
    })


@tool
def draft_secure_reply(email_text: str, reply_intent: str) -> str:
    """Drafts a safe, defensive professional reply to an email without clicking links, disclosing sensitive credentials, or committing to financial transfers.
    Args:
        email_text: The incoming email text being replied to.
        reply_intent: The purpose of the reply, e.g. 'out_of_band_verification', 'decline_request', 'request_invoice_validation', or 'safe_acknowledgement'.
    """
    intent = (reply_intent or "out_of_band_verification").lower().strip()

    if "out_of_band" in intent or "verify" in intent or "phone" in intent:
        draft = (
            "Dear Sender,\n\n"
            "Thank you for contacting us. In accordance with our organization's information security policy, "
            "we do not process sensitive requests or click external authentication links directly via email.\n\n"
            "To verify the authenticity of this request, please contact our team directly through our registered corporate "
            "phone number or official intranet directory.\n\n"
            "Best regards,\n"
            "[Your Name / Department]"
        )
        rationale = "Requests verification through a known, trusted secondary communication channel (out-of-band)."

    elif "decline" in intent or "refuse" in intent:
        draft = (
            "Dear Sender,\n\n"
            "We have received your message. However, our security protocols prohibit the disclosure of internal "
            "credentials, configuration details, or unverified financial transfers via email.\n\n"
            "We are unable to fulfill this request. If you believe this is an error, please escalate through "
            "official procurement or internal management channels.\n\n"
            "Best regards,\n"
            "[Your Name / Department]"
        )
        rationale = "Firmly and professionally refuses to interact with suspicious requests."

    elif "invoice" in intent or "financial" in intent:
        draft = (
            "Dear Accounts Team,\n\n"
            "We have received your payment notice. In line with strict anti-fraud controls, any modification to "
            "vendor banking details or expedited wire requests requires two-party voice confirmation with the designated "
            "contract manager on our pre-approved record.\n\n"
            "Please confirm your pre-established corporate phone extension so we can schedule the verification call.\n\n"
            "Sincerely,\n"
            "[Finance & Procurement Operations]"
        )
        rationale = "Applies strict dual-authorization controls against Business Email Compromise (BEC) wire fraud."

    else:
        draft = (
            "Dear Sender,\n\n"
            "Thank you for your email. We have logged your request. We will review the matter in accordance "
            "with standard operating procedures and respond via our standard verified communication channels.\n\n"
            "Regards,\n"
            "[Your Name / Department]"
        )
        rationale = "Safe generic acknowledgment that makes zero security commitments."

    return json.dumps({
        "tool": "draft_secure_reply",
        "intent_applied": intent,
        "rationale": rationale,
        "recommended_reply": draft
    })


@tool
def explain_detection_verdict(email_text: str) -> str:
    """Explains why an email was classified with a specific risk score and identifies the key malicious or safe indicators.
    Args:
        email_text: The email body to explain detection scores for.
    """
    spam_res = SpamClassifier.predict(email_text)
    phish_res = PhishingClassifier.predict(email_text)
    url_res = analyze_email_urls(email_text)

    unified = calculate_unified_risk(
        spam_prob=spam_res["probability"],
        phish_prob=phish_res["probability"],
        url_risk=url_res["aggregate_risk"],
        header_risk=0.0,
        has_headers=False
    )

    score = unified["risk_score"]
    level = unified["threat_level"]

    explanation_points = []
    if phish_res["probability"] > 0.5:
        explanation_points.append(
            f"Phishing Classifier flagged a {phish_res['probability']*100:.1f}% probability due to credential harvesting tokens: {', '.join(phish_res['triggers'][:5])}."
        )
    if spam_res["probability"] > 0.5:
        explanation_points.append(
            f"Spam Detection model detected unsolicited commercial promotion patterns ({spam_res['probability']*100:.1f}% likelihood) triggered by: {', '.join(spam_res['triggers'][:5])}."
        )
    if url_res["total_count"] > 0:
        susp_count = url_res["suspicious_count"]
        explanation_points.append(
            f"Identified {url_res['total_count']} embedded URL(s) ({susp_count} with elevated risk/entropy or suspicious TLDs). Links were defanged for safe inspection."
        )
    if not explanation_points:
        explanation_points.append(
            "The email exhibits low statistical risk across all models with vocabulary characteristic of standard corporate communication."
        )

    return json.dumps({
        "tool": "explain_detection_verdict",
        "risk_score": score,
        "threat_level": level,
        "verdict": unified["verdict"],
        "spam_probability": spam_res["probability"],
        "phishing_probability": phish_res["probability"],
        "key_reasons": explanation_points,
        "recommendations": unified["recommendations"]
    })


@tool
def explain_security_concept(concept_name: str) -> str:
    """Provides authoritative, beginner-friendly cybersecurity education on email authentication protocols and threat vectors.
    Args:
        concept_name: Name of the security concept, e.g. 'spf', 'dkim', 'dmarc', 'shannon_entropy', 'bec', 'phishing', or 'defanging'.
    """
    c = (concept_name or "").lower().strip()

    knowledge_base = {
        "spf": (
            "SPF (Sender Policy Framework) is an email authentication method that lets a domain owner publish a DNS record "
            "specifying which mail servers (IP addresses) are authorized to send emails on behalf of that domain. If an email originates "
            "from an unlisted IP, it fails SPF verification."
        ),
        "dkim": (
            "DKIM (DomainKeys Identified Mail) provides cryptographic integrity to emails. The sender attaches a digital signature "
            "to the email header using a private key. The recipient validates the signature using the sender's public key published in DNS, "
            "proving the message was not tampered with in transit."
        ),
        "dmarc": (
            "DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds on top of SPF and DKIM. It tells the recipient's "
            "mail server what policy to apply if SPF or DKIM fails (none, quarantine, or reject) and sends telemetry reports back to the domain owner."
        ),
        "shannon_entropy": (
            "Shannon Entropy measures the randomness or unpredictability of characters in a string. In MailSentinel AI, we compute entropy "
            "for URLs and domain names. Randomly generated strings like 'x7q9k2-login-secure.xyz' have high entropy (>4.0), which is a common "
            "indicator of algorithmically generated phishing domains."
        ),
        "defanging": (
            "Defanging is the security practice of modifying URLs or IP addresses (e.g. changing 'http://evil.com' to 'hxxp://evil[.]com') "
            "so that security analysts and software cannot accidentally click or execute malicious links while inspecting them."
        ),
        "bec": (
            "BEC (Business Email Compromise) is a sophisticated form of spear phishing where an attacker impersonates a company executive, "
            "vendor, or trusted partner to trick employees into executing wire transfers or redirecting invoice payments to attacker-controlled accounts."
        ),
        "phishing": (
            "Phishing is a social-engineering attack where malicious actors impersonate legitimate organizations (such as banks, Microsoft, "
            "or IT support) to trick victims into revealing passwords, credentials, or installing malware."
        )
    }

    # Match best concept
    matched_text = None
    for k, v in knowledge_base.items():
        if k in c or c in k:
            matched_text = v
            break

    if not matched_text:
        matched_text = (
            f"Concept '{concept_name}': In email cybersecurity, defense-in-depth relies on combining automated machine learning classifiers, "
            "cryptographic transport authentication (SPF, DKIM, DMARC), URL lexical analysis, and vigilant user awareness."
        )

    return json.dumps({
        "tool": "explain_security_concept",
        "concept": concept_name,
        "explanation": matched_text
    })


ALL_CHAT_TOOLS = [
    summarize_email,
    draft_secure_reply,
    explain_detection_verdict,
    explain_security_concept
]

