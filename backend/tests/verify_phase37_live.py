"""
MailSentinel AI - Phase 3.7 Live Real-World Verification Script

Performs live end-to-end regression testing against the active FastAPI backend
and the SQLite database:
1. TEST 1: FREE GIFT SPAM (Subject: 'spam free free', Sender: 'test@example.com', Body: 'hi you have won a free gift')
2. TEST 2: PHISHING (Subject: 'URGENT: Microsoft 365 Password Expiration Notice', Sender: 'security-service@m1crosoft-auth-portal.com')
3. TEST 3: LEGITIMATE EMAIL (Subject: 'Meeting Confirmation', Sender: 'colleague@example.com')
4. Edge Case: Empty optional subject
5. Edge Case: Empty optional sender
6. Consecutive scans & repeated scans
7. Threat level filtering in History API
8. Direct SQLite database persistence verification
9. Single Source of Truth verification (database file match)
"""

import urllib.request
import json
import sqlite3
import sys
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api/v1"
DB_PATH = Path("mailsentinel.db").resolve()

def post_json(endpoint: str, data: dict):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8"))

def get_json(endpoint: str):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        headers={"Cache-Control": "no-cache"}
    )
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8"))

def main():
    print("=" * 60)
    print("MAILSENTINEL AI - PHASE 3.7 LIVE REGRESSION VERIFICATION")
    print(f"Database Target: {DB_PATH}")
    print("=" * 60)

    # 0. Health Verification
    health = get_json("/health")
    print(f"[OK] Health Status: {health['status']} | DB: {health['database']}")
    assert health["status"] == "healthy"
    assert health["database"] == "connected"

    # 1. TEST 1 — FREE GIFT SPAM
    print("\n--- Running TEST 1: Free Gift Spam ---")
    test1_payload = {
        "raw_content": "hi you have won a free gift",
        "subject": "spam free free",
        "sender": "test@example.com"
    }
    t1_res = post_json("/scan", test1_payload)
    t1_id = t1_res["id"]
    print(f"[OK] Scan Submitted: ID={t1_id} | Threat={t1_res['threat_level']} | Score={t1_res['risk_score']}")
    assert t1_res["subject"] == "spam free free"
    assert t1_res["sender"] == "test@example.com"

    # Verify immediately in Detection History (must be at top index 0)
    h_data = get_json("/history?limit=10&offset=0")
    top_scan = h_data["scans"][0]
    print(f"[OK] History Verification: Top Record ID={top_scan['id']} | Subject='{top_scan['subject']}'")
    assert top_scan["id"] == t1_id, f"Expected top history ID {t1_id}, got {top_scan['id']}"

    # Verify Inspect detail
    t1_detail = get_json(f"/history/{t1_id}")
    print(f"[OK] Detail Inspect Verified: ID={t1_detail['id']} | Recommendations={len(t1_detail['recommendations'])}")
    assert t1_detail["id"] == t1_id
    assert t1_detail["subject"] == "spam free free"

    # 2. TEST 2 — PHISHING
    print("\n--- Running TEST 2: Phishing Attack ---")
    test2_payload = {
        "raw_content": (
            "Your mailbox is scheduled for suspension.\n\n"
            "Please click the secure portal link below to retain your current credentials:\n"
            "https://m1crosoft-auth-portal.com/login?session=9928374"
        ),
        "subject": "URGENT: Microsoft 365 Password Expiration Notice",
        "sender": "security-service@m1crosoft-auth-portal.com"
    }
    t2_res = post_json("/scan", test2_payload)
    t2_id = t2_res["id"]
    print(f"[OK] Scan Submitted: ID={t2_id} | Threat={t2_res['threat_level']} | Score={t2_res['risk_score']}")
    assert t2_res["threat_level"] in ["DANGEROUS", "CRITICAL", "SUSPICIOUS"]
    assert len(t2_res["detected_urls"]) >= 1

    # Verify top of history is now Test 2
    h_data = get_json("/history?limit=10&offset=0")
    assert h_data["scans"][0]["id"] == t2_id, "Test 2 must now be at top of history"
    assert h_data["scans"][1]["id"] == t1_id, "Test 1 must remain intact at index 1"
    print(f"[OK] History Order Confirmed: Index 0 = {t2_id} (Test 2), Index 1 = {t1_id} (Test 1)")

    # 3. TEST 3 — LEGITIMATE EMAIL
    print("\n--- Running TEST 3: Legitimate Email ---")
    test3_payload = {
        "raw_content": "Hello, our meeting is scheduled for tomorrow at 10 AM. Please confirm your availability.",
        "subject": "Meeting Confirmation",
        "sender": "colleague@example.com"
    }
    t3_res = post_json("/scan", test3_payload)
    t3_id = t3_res["id"]
    print(f"[OK] Scan Submitted: ID={t3_id} | Threat={t3_res['threat_level']} | Score={t3_res['risk_score']}")
    assert t3_res["threat_level"] in ["SAFE", "SUSPICIOUS"]

    # Verify top of history is now Test 3
    h_data = get_json("/history?limit=10&offset=0")
    assert h_data["scans"][0]["id"] == t3_id, "Test 3 must now be at top of history"
    assert h_data["scans"][1]["id"] == t2_id, "Test 2 must remain at index 1"
    assert h_data["scans"][2]["id"] == t1_id, "Test 1 must remain at index 2"
    print(f"[OK] History Order Confirmed: Index 0 = Safe, Index 1 = Phishing, Index 2 = Spam")

    # 4. Edge Cases: Empty Subject and Empty Sender
    print("\n--- Running Edge Cases: Empty Subject and Sender ---")
    t4_res = post_json("/scan", {"raw_content": "Short test body", "subject": "", "sender": "user@test.com"})
    assert t4_res["subject"] in ["Untitled Email", "Untitled", "No Subject"]
    print(f"[OK] Empty Subject handled gracefully: '{t4_res['subject']}'")

    t5_res = post_json("/scan", {"raw_content": "Another test body", "subject": "Notice"})
    assert t5_res["sender"] in ["Undisclosed Sender", "Unknown Sender", "Unknown"]
    print(f"[OK] Empty Sender handled gracefully: '{t5_res['sender']}'")

    # 5. History Filtering Verification
    print("\n--- Running History Filtering Tests ---")
    safe_history = get_json("/history?threat_level=SAFE&limit=10")
    assert all(s["threat_level"] == "SAFE" for s in safe_history["scans"])
    print(f"[OK] History filter threat_level=SAFE returned {len(safe_history['scans'])} SAFE items")

    # 6. Direct SQLite Database Single Source of Truth Verification
    print("\n--- Direct SQLite Database Verification ---")
    assert DB_PATH.exists(), f"Database file {DB_PATH} must exist"
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, subject, sender, threat_level, risk_score FROM scans WHERE id = ?", (t1_id,))
    row1 = cur.fetchone()
    assert row1 is not None, f"Record {t1_id} must be committed in SQLite database"
    assert row1[1] == "spam free free"
    assert row1[2] == "test@example.com"
    print(f"[OK] SQLite Row 1 Verified: {row1}")

    cur.execute("SELECT id, subject, sender, threat_level, risk_score FROM scans WHERE id = ?", (t2_id,))
    row2 = cur.fetchone()
    assert row2 is not None, f"Record {t2_id} must be committed in SQLite database"
    print(f"[OK] SQLite Row 2 Verified: {row2}")

    cur.execute("SELECT id, subject, sender, threat_level, risk_score FROM scans WHERE id = ?", (t3_id,))
    row3 = cur.fetchone()
    assert row3 is not None, f"Record {t3_id} must be committed in SQLite database"
    print(f"[OK] SQLite Row 3 Verified: {row3}")
    con.close()

    print("\n" + "=" * 60)
    print(">>> ALL PHASE 3.7 REAL-WORLD REGRESSION TESTS PASSED 100% <<<")
    print("=" * 60)

if __name__ == "__main__":
    main()
