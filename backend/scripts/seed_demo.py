"""
MailSentinel AI - Database Seeder Script

Populates the database with realistic SOC security incidents,
threat distributions, and detection history for live dashboard demonstration.

Usage:
    python backend/scripts/seed_demo.py
"""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.db.session import AsyncSessionLocal, init_db
from backend.app.db.models.scan import ScanRecord, DetectedUrlRecord
from backend.app.db.models.investigation import AgentInvestigationRecord


SAMPLE_INCIDENTS = [
    {
        "subject": "URGENT: Your Microsoft 365 Password Expires in 2 Hours",
        "sender": "admin@m1crosoft-auth-portal.com",
        "recipient": "cto@enterprise.com",
        "has_headers": True,
        "body": "Your corporate password is set to expire. Keep your existing password by verifying at https://m1crosoft-auth-portal.com/login now.",
        "risk_score": 94.5,
        "threat_level": "CRITICAL",
        "verdict": "Credential Harvesting Phishing Campaign",
        "spam_prob": 0.82,
        "phish_prob": 0.98,
        "header_risk": 0.85,
        "url_risk": 0.95,
        "urls": [
            ("hxxps://m1crosoft-auth-portal[.]com/login", "m1crosoft-auth-portal.com", "com", 4.12, True, ["Typosquatting brand impersonation", "Credential login keyword in path"])
        ],
        "days_ago": 1
    },
    {
        "subject": "Dispute Resolution: Unauthorized transaction on your PayPal account",
        "sender": "service@paypa1-dispute-center.xyz",
        "recipient": "finance@enterprise.com",
        "has_headers": True,
        "body": "A transaction of $749.00 USD was initiated from Nigeria. If this was not you, cancel it immediately at http://192.168.1.188/cancel.",
        "risk_score": 91.0,
        "threat_level": "CRITICAL",
        "verdict": "Financial Coercion Phishing",
        "spam_prob": 0.70,
        "phish_prob": 0.95,
        "header_risk": 0.80,
        "url_risk": 0.90,
        "urls": [
            ("hxxp://192[.]168[.]1[.]188/cancel", "192.168.1.188", "188", 3.25, True, ["IP literal host used instead of registered domain"])
        ],
        "days_ago": 2
    },
    {
        "subject": "FedEx: Package pending customs clearance fee ($2.40 USD)",
        "sender": "delivery-tracking@fedex-express-notice.top",
        "recipient": "user@enterprise.com",
        "has_headers": False,
        "body": "Your package cannot be delivered due to an outstanding unpaid fee. Update delivery address and pay at https://fedex-express-notice.top/pay.",
        "risk_score": 78.5,
        "threat_level": "DANGEROUS",
        "verdict": "Smishing/Phishing Smokescreen",
        "spam_prob": 0.75,
        "phish_prob": 0.84,
        "header_risk": 0.0,
        "url_risk": 0.85,
        "urls": [
            ("hxxps://fedex-express-notice[.]top/pay", "fedex-express-notice.top", "top", 3.90, True, ["Suspicious high-abuse TLD .top", "Brand impersonation"])
        ],
        "days_ago": 3
    },
    {
        "subject": "CONFIDENTIAL: Immediate Wire Transfer Needed for Acquisition",
        "sender": "ceo.office@executive-privatemail.org",
        "recipient": "treasury@enterprise.com",
        "has_headers": False,
        "body": "Please process a wire transfer of $84,500 immediately for our vendor retainer. Do not call as I am currently in a closed board meeting.",
        "risk_score": 86.0,
        "threat_level": "CRITICAL",
        "verdict": "Executive Impersonation (CEO Fraud / BEC)",
        "spam_prob": 0.60,
        "phish_prob": 0.92,
        "header_risk": 0.0,
        "url_risk": 0.0,
        "urls": [],
        "days_ago": 4
    },
    {
        "subject": "Guaranteed 450% Return - Next-Gen AI Crypto Presale",
        "sender": "invest@moonshot-tokens.buzz",
        "recipient": "team@enterprise.com",
        "has_headers": False,
        "body": "Exclusive private whitelist token sale. Guaranteed profit multiplier. Connect your wallet at https://moonshot-tokens.buzz/whitelist.",
        "risk_score": 68.0,
        "threat_level": "DANGEROUS",
        "verdict": "Cryptocurrency Investment Scam / Spam",
        "spam_prob": 0.96,
        "phish_prob": 0.65,
        "header_risk": 0.0,
        "url_risk": 0.70,
        "urls": [
            ("hxxps://moonshot-tokens[.]buzz/whitelist", "moonshot-tokens.buzz", "buzz", 3.75, True, ["Abused TLD .buzz", "Wallet credential harvesting marker"])
        ],
        "days_ago": 5
    },
    {
        "subject": "Special Discount: 70% Off Business SEO & Growth Marketing",
        "sender": "promo@global-leads-market.com",
        "recipient": "sales@enterprise.com",
        "has_headers": False,
        "body": "Increase your Google search ranking with our certified backlink packages. Unsubscribe here if not interested.",
        "risk_score": 42.0,
        "threat_level": "SUSPICIOUS",
        "verdict": "Unsolicited Commercial Bulk Email (Spam)",
        "spam_prob": 0.88,
        "phish_prob": 0.15,
        "header_risk": 0.0,
        "url_risk": 0.10,
        "urls": [],
        "days_ago": 5
    },
    {
        "subject": "Sprint Review & Q4 Engineering Roadmap Meeting",
        "sender": "engineering-lead@company.com",
        "recipient": "dev-team@company.com",
        "has_headers": True,
        "body": "Hi team, please find the meeting agenda attached for our bi-weekly roadmap sync. The meeting will start at 10:00 AM.",
        "risk_score": 8.0,
        "threat_level": "SAFE",
        "verdict": "Internal Corporate Communication (Clean)",
        "spam_prob": 0.04,
        "phish_prob": 0.02,
        "header_risk": 0.0,
        "url_risk": 0.0,
        "urls": [],
        "days_ago": 6
    },
    {
        "subject": "[GitHub] Pull Request #142 Merged: Update authentication middleware",
        "sender": "notifications@github.com",
        "recipient": "developer@company.com",
        "has_headers": True,
        "body": "Merged PR #142 by lead-dev into main branch. View diff and test artifacts on GitHub.",
        "risk_score": 5.0,
        "threat_level": "SAFE",
        "verdict": "Legitimate Automated Developer Notification",
        "spam_prob": 0.02,
        "phish_prob": 0.01,
        "header_risk": 0.0,
        "url_risk": 0.0,
        "urls": [
            ("hxxps://github[.]com/enterprise/repo/pull/142", "github.com", "com", 2.85, False, [])
        ],
        "days_ago": 6
    },
    {
        "subject": "Your Amazon.com order #112-9984712-44123 has shipped",
        "sender": "shipment-tracking@amazon.com",
        "recipient": "employee@company.com",
        "has_headers": True,
        "body": "Your package is on its way. Track your order on Amazon. Estimated delivery date: Thursday, Nov 18.",
        "risk_score": 12.0,
        "threat_level": "SAFE",
        "verdict": "Authenticated E-Commerce Order Confirmation",
        "spam_prob": 0.08,
        "phish_prob": 0.04,
        "header_risk": 0.0,
        "url_risk": 0.05,
        "urls": [],
        "days_ago": 7
    }
]


async def seed():
    print("[*] Initializing database tables...")
    await init_db()

    print("[*] Seeding sample security incidents...")
    async with AsyncSessionLocal() as session:
        for item in SAMPLE_INCIDENTS:
            created_time = datetime.now(timezone.utc) - timedelta(days=item["days_ago"])
            scan = ScanRecord(
                created_at=created_time,
                subject=item["subject"],
                sender=item["sender"],
                recipient=item["recipient"],
                has_headers=item["has_headers"],
                body_preview=item["body"],
                risk_score=item["risk_score"],
                threat_level=item["threat_level"],
                verdict=item["verdict"],
                summary=f"Incident: {item['verdict']} with threat score {item['risk_score']}%.",
                spam_probability=item["spam_prob"],
                phishing_probability=item["phish_prob"],
                header_risk_score=item["header_risk"],
                url_risk_score=item["url_risk"],
                indicators={"reasons": [item["verdict"]]}
            )
            session.add(scan)
            await session.flush()

            for u_url, u_dom, u_tld, u_ent, u_susp, u_reasons in item["urls"]:
                url_record = DetectedUrlRecord(
                    scan_id=scan.id,
                    defanged_url=u_url,
                    domain=u_dom,
                    tld=u_tld,
                    entropy=u_ent,
                    is_suspicious=u_susp,
                    risk_reasons={"reasons": u_reasons}
                )
                session.add(url_record)

            # Add investigation for critical records
            if item["threat_level"] == "CRITICAL":
                inv = AgentInvestigationRecord(
                    scan_id=scan.id,
                    created_at=created_time,
                    model_used="openai/gpt-oss-20b",
                    steps_count=5,
                    tools_invoked={"executed_tools": ["analyze_spam", "analyze_phish", "inspect_urls", "inspect_headers", "calculate_risk"]},
                    thought_process="Autonomous smolagents tool calling trace confirmed malicious intent.",
                    final_assessment=f"CRITICAL INCIDENT: Confirmed {item['verdict']}. Immediate gateway quarantine enforced."
                )
                session.add(inv)

        await session.commit()
    print("[+] Successfully seeded demo security incidents into database!")


if __name__ == "__main__":
    asyncio.run(seed())

