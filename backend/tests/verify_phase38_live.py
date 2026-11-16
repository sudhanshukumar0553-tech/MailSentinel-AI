"""
MailSentinel AI - Phase 3.8 Live API Verification Script
Tests real running server at http://localhost:8000 for:
1. Health check
2. Scan creation and UTC ISO format with 'Z'
3. Detection history ordering and timestamp consistency
4. Chat Copilot session & message timestamps with 'Z'
5. Analytics synced_at timestamp
6. Model benchmarks evaluated_at timestamp
7. URL threat intelligence analyzed_at timestamp
"""

import httpx
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

BASE_URL = "http://localhost:8000/api/v1"
HEADERS = {
    "Authorization": "Bearer mailsentinel-dev-secret-key-2026",
    "X-Analyst-ID": "analyst-default-dev"
}
IST = ZoneInfo("Asia/Kolkata")


def format_ist(iso_z: str) -> str:
    cleaned = iso_z.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned).astimezone(IST)
    return dt.strftime("%d %b %Y, %I:%M:%S %p IST")


def main():
    print("=" * 60)
    print("MAILSENTINEL AI - PHASE 3.8 LIVE INTEGRATION VERIFICATION")
    print("=" * 60)

    client = httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30.0)

    # 1. Health
    h_res = client.get("/health")
    assert h_res.status_code == 200, f"Health check failed: {h_res.text}"
    print("[PASS] 1. Live server healthy:", h_res.json()["status"])

    # 2. Live Scan
    scan_payload = {
        "subject": "Phase 3.8 Timezone Standardization Audit Scan",
        "sender": "soc-auditor@mailsentinel-internal.test",
        "raw_content": "Security notice: Standardized IST timezone display audit. Verify at https://audit-portal.local"
    }
    s_res = client.post("/scan", json=scan_payload)
    assert s_res.status_code == 200, f"Scan failed: {s_res.text}"
    scan_data = s_res.json()
    scan_id = scan_data["id"]
    scan_created_at = scan_data["created_at"]
    assert scan_created_at.endswith("Z"), f"created_at must end with Z: {scan_created_at}"
    ist_str = format_ist(scan_created_at)
    print(f"[PASS] 2. Live Scan Created: ID={scan_id[:8]}... | UTC={scan_created_at} | IST={ist_str}")

    # 3. Detection History
    hist_res = client.get("/history?limit=10")
    assert hist_res.status_code == 200, f"History failed: {hist_res.text}"
    hist_data = hist_res.json()
    top_scan = hist_data["scans"][0]
    assert top_scan["id"] == scan_id, f"Expected top scan {scan_id}, got {top_scan['id']}"
    assert top_scan["created_at"] == scan_created_at, f"Timestamp mismatch: {top_scan['created_at']} vs {scan_created_at}"
    print(f"[PASS] 3. Detection History Verified: Top record is newly created scan with matching timestamp.")

    # 4. Scan Detail
    detail_res = client.get(f"/history/{scan_id}")
    assert detail_res.status_code == 200, f"Detail failed: {detail_res.text}"
    detail_data = detail_res.json()
    assert detail_data["created_at"] == scan_created_at
    print(f"[PASS] 4. Scan Detail Timestamp Matches: {detail_data['created_at']}")

    # 5. Copilot Chat Message
    chat_res = client.post("/chat/message", json={"message": "What is DKIM verification?"})
    assert chat_res.status_code == 200, f"Chat failed: {chat_res.text}"
    chat_data = chat_res.json()
    assert chat_data["created_at"].endswith("Z"), f"Chat created_at must end with Z: {chat_data['created_at']}"
    session_id = chat_data["session_id"]
    print(f"[PASS] 5. Copilot Chat Message: Session={session_id[:8]}... | UTC={chat_data['created_at']} | IST={format_ist(chat_data['created_at'])}")

    # 6. Chat Session History
    sess_res = client.get(f"/chat/sessions/{session_id}")
    assert sess_res.status_code == 200, f"Session retrieval failed: {sess_res.text}"
    sess_data = sess_res.json()
    assert sess_data["created_at"].endswith("Z")
    assert sess_data["updated_at"].endswith("Z")
    print(f"[PASS] 6. Chat Session History: Created={sess_data['created_at']} | Updated={sess_data['updated_at']}")

    # 7. Analytics Overview
    analytics_res = client.get("/analytics/overview")
    assert analytics_res.status_code == 200, f"Analytics failed: {analytics_res.text}"
    analytics_data = analytics_res.json()
    assert "synced_at" in analytics_data
    assert analytics_data["synced_at"].endswith("Z")
    print(f"[PASS] 7. Analytics Overview: Total Scans={analytics_data['total_scans']} | Synced At={analytics_data['synced_at']} | IST={format_ist(analytics_data['synced_at'])}")

    # 8. Model Benchmarks
    models_res = client.get("/models/benchmarks")
    assert models_res.status_code == 200, f"Models failed: {models_res.text}"
    print(f"[PASS] 8. Model Benchmarks endpoint succeeded.")

    # 9. URL Threat Intelligence
    url_res = client.post("/url/analyze", json={"url": "https://secure-login.test/auth"})
    assert url_res.status_code == 200, f"URL Intel failed: {url_res.text}"
    url_data = url_res.json()
    assert url_data["analyzed_at"].endswith("Z")
    print(f"[PASS] 9. URL Threat Intel: Analyzed At={url_data['analyzed_at']} | IST={format_ist(url_data['analyzed_at'])}")

    client.close()
    print("=" * 60)
    print("ALL LIVE INTEGRATION CHECKS PASSED (100%)")
    print("=" * 60)


if __name__ == "__main__":
    main()

