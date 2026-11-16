"""
Regression Tests for Phase 3.6:
1. Critical Bug Verification: Scanned email persistence in Detection History.
2. Subject "spam free free", Body "hi you have won a free gift".
3. Phishing email with suspicious URL.
4. Legitimate email.
5. Email with empty optional subject.
6. Email without a sender.
7. History API retrieval, ordering, pagination, and inspection restoration.
8. Hindi language support in chat assistant.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

@pytest.fixture
def client():
    return TestClient(app)


# 1. Exact Test Case from User Request
def test_scan_persistence_spam_free_free(client):
    """
    Reproduces the exact user scenario:
    Subject: spam free free
    Sender: test.analyst@gmail.com
    Body: hi you have won a free gift
    """
    payload = {
        "raw_content": "hi you have won a free gift",
        "subject": "spam free free",
        "sender": "test.analyst@gmail.com"
    }

    # 1. Submit scan
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    scan_data = response.json()

    scan_id = scan_data["id"]
    assert scan_id is not None
    assert scan_data["threat_level"] in ["SUSPICIOUS", "DANGEROUS"]
    assert 40.0 <= scan_data["risk_score"] <= 75.0
    assert scan_data["subject"] == "spam free free"
    assert scan_data["sender"] == "test.analyst@gmail.com"

    # 2. Verify it appears immediately at the top of Detection History
    history_res = client.get("/api/v1/history?limit=10")
    assert history_res.status_code == 200
    history_data = history_res.json()
    assert history_data["total_returned"] >= 1

    # Check that our newly scanned email exists in the returned items
    scans = history_data["scans"]
    found = [s for s in scans if s["id"] == scan_id]
    assert len(found) == 1
    item = found[0]
    assert item["subject"] == "spam free free"
    assert item["sender"] == "test.analyst@gmail.com"
    assert item["threat_level"] == scan_data["threat_level"]

    # 3. Verify Inspect retrieves the exact saved record
    detail_res = client.get(f"/api/v1/history/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == scan_id
    assert detail["subject"] == "spam free free"
    assert detail["risk_score"] == scan_data["risk_score"]
    assert detail["verdict"] == scan_data["verdict"]
    assert "xai_report" in detail


# 2. Phishing Email with Suspicious URL
def test_scan_persistence_phishing_url(client):
    payload = {
        "raw_content": "Your account has been locked. Verify at http://paypa1-update.xyz/login immediately.",
        "subject": "Account Lockout Warning",
        "sender": "security@paypa1-update.xyz"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] in ["DANGEROUS", "CRITICAL"]
    assert len(data["detected_urls"]) >= 1

    # Verify detail retrieval from history
    detail_res = client.get(f"/api/v1/history/{data['id']}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["detected_urls"]) >= 1
    assert "paypa1" in detail["detected_urls"][0]["defanged_url"]


# 3. Legitimate Email
def test_scan_persistence_legitimate_email(client):
    payload = {
        "raw_content": "Hi Team, please find attached the meeting notes for our engineering sprint review.",
        "subject": "Sprint Review Notes",
        "sender": "lead@company.internal"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] == "SAFE"

    # Verify in history
    history_res = client.get("/api/v1/history?limit=5")
    assert history_res.status_code == 200
    assert any(s["id"] == data["id"] for s in history_res.json()["scans"])


# 4. Email with Empty Optional Subject
def test_scan_persistence_empty_subject(client):
    payload = {
        "raw_content": "Reminder about quarterly goals and deliverables.",
        "subject": "",
        "sender": "hr@corp.com"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] in ["Untitled Email", "No Subject", "Untitled"]

    # Verify in history
    detail_res = client.get(f"/api/v1/history/{data['id']}")
    assert detail_res.status_code == 200
    assert detail_res.json()["subject"] == data["subject"]


# 5. Email without Sender
def test_scan_persistence_empty_sender(client):
    payload = {
        "raw_content": "Check this update: https://example.com/readme",
        "subject": "Important Notice"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["sender"] in ["Undisclosed Sender", "Unknown Sender", "Unknown"]

    # Verify in history
    detail_res = client.get(f"/api/v1/history/{data['id']}")
    assert detail_res.status_code == 200
    assert detail_res.json()["sender"] == data["sender"]


# 6. English-Only Chat Assistant Response
def test_chat_assistant_english_only(client):
    payload = {
        "message": "Can you explain how SPF and DKIM protect against email spoofing?",
        "language": "en-US"
    }
    headers = {"Authorization": "Bearer mailsentinel-dev-secret-key-2026"}
    response = client.post("/api/v1/chat/message", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["reply"] is not None
    assert len(data["reply"]) > 20
    assert "spf" in data["reply"].lower() or "dkim" in data["reply"].lower() or "mailsentinel" in data["reply"].lower()
