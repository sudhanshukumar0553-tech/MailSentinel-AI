import urllib.request
import json
import sys

def main():
    print("Executing live MailSentinel AI Phase 3.6 verification...")

    # 1. Health check
    try:
        req = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health")
        health = json.loads(req.read().decode("utf-8"))
        print(f"[OK] 1. Health check: status={health.get('status')} db={health.get('database')}")
    except Exception as e:
        print(f"[FAIL] 1. Health check failed: {e}")
        sys.exit(1)

    # 2. Live Scan with user's exact test case
    payload = {
        "raw_content": "hi you have won a free gift claim now http://free-gift-claim.xyz",
        "subject": "spam free free",
        "sender": "winner@lottery-promo.com"
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/scan",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    res = urllib.request.urlopen(req)
    scan_result = json.loads(res.read().decode("utf-8"))
    scan_id = scan_result["id"]
    print(f"[OK] 2. Live Scan executed: id={scan_id} threat_level={scan_result.get('threat_level')} confidence={scan_result.get('confidence')}")

    # 3. Detection History Verification
    req = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/history?limit=10&offset=0")
    history = json.loads(req.read().decode("utf-8"))
    top_record = history["scans"][0]
    print(f"[OK] 3. Detection History top record: id={top_record['id']} subject='{top_record['subject']}'")
    assert top_record["id"] == scan_id, f"Expected top record {scan_id}, got {top_record['id']}"
    assert top_record["subject"] == "spam free free"

    # 4. History Detail Verification (Inspect)
    req = urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/history/{scan_id}")
    detail = json.loads(req.read().decode("utf-8"))
    recommendations = detail.get("recommendations", [])
    detected_urls = detail.get("detected_urls", [])
    xai_report = detail.get("xai_report")
    print(f"[OK] 4. Detail Inspect: {len(recommendations)} recommendations, {len(detected_urls)} URLs, has xai_report: {bool(xai_report)}")
    assert len(recommendations) > 0, "Expected recommendations to be populated in detail record"
    assert xai_report is not None, "Expected xai_report to be populated in detail record"

    # 5. Hindi Chat Copilot
    chat_payload = {
        "message": "फ़िशिंग ईमेल क्या है?",
        "language": "hi"
    }
    data = json.dumps(chat_payload).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/chat/message",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer mailsentinel-dev-secret-key-2026"
        },
        method="POST"
    )
    res = urllib.request.urlopen(req)
    chat_res = json.loads(res.read().decode("utf-8"))
    reply = chat_res.get("reply", "")
    print(f"[OK] 5. Hindi Chat Copilot: status={chat_res.get('operational_status')}")
    print(f"     Reply preview: {reply[:100]}...")
    assert len(reply) > 20, "Expected non-empty reply"

    print("\n>>> ALL 5 LIVE E2E VERIFICATIONS SUCCEEDED 100%! <<<")

if __name__ == "__main__":
    main()
