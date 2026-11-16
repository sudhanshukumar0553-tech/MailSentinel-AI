"""
MailSentinel AI - RFC822 MIME & Plain Text Email Parser

Safely decodes and extracts structured email forensic data:
- Identifies whether transport headers are present.
- Extracts sender, recipient, subject, and date.
- Extracts and standardizes body text (plain text & HTML alternatives).
- Strictly follows Zero-Execution policy (attachments are identified, never executed).
"""

import email
from email import policy
from email.message import EmailMessage
import re
from typing import Any, Dict, List, Optional, Tuple
from backend.app.core.security import sanitize_untrusted_text


# Common transport header keys used to determine if authentic headers are present
TRANSPORT_HEADER_KEYS = {
    "received",
    "authentication-results",
    "dkim-signature",
    "received-spf",
    "arc-seal",
    "delivered-to",
    "x-received"
}


def _extract_body_from_mime(msg: EmailMessage) -> Tuple[str, List[Dict[str, str]]]:
    """
    Recursively extracts plain text body and metadata for any attachments.
    Never executes or saves attachments to disk.
    """
    body_parts = []
    attachments_metadata = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                filename = part.get_filename() or "unnamed_attachment"
                attachments_metadata.append({
                    "filename": sanitize_untrusted_text(filename),
                    "content_type": content_type,
                    "size_bytes": len(part.get_payload(decode=True) or b"")
                })
                continue

            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))
            elif content_type == "text/html" and not body_parts:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body_parts.append(payload.decode(charset, errors="replace"))

    full_body = "\n".join(body_parts) if body_parts else str(msg.get_payload() or "")
    return full_body, attachments_metadata


def parse_email_input(raw_input: str) -> Dict[str, Any]:
    """
    Parses either a full RFC822 MIME raw email or pasted plain text.

    Returns:
        Structured dictionary containing:
        - subject, sender, recipient, date
        - body (sanitized string)
        - has_headers (boolean flag)
        - raw_headers (dictionary of header fields)
        - attachments (list of metadata records)
    """
    if not raw_input or not raw_input.strip():
        return {
            "subject": "Empty Message",
            "sender": "Unknown",
            "recipient": "Unknown",
            "date": None,
            "body": "",
            "has_headers": False,
            "raw_headers": {},
            "attachments": []
        }

    raw_clean = raw_input.strip()

    # Attempt standard RFC822 MIME parsing
    try:
        msg = email.message_from_string(raw_clean, policy=policy.default)
        headers_dict = {k.lower(): str(v) for k, v in msg.items()}

        # Check if authentic transport headers exist
        transport_headers_found = [h for h in headers_dict.keys() if h in TRANSPORT_HEADER_KEYS]
        has_headers = len(transport_headers_found) > 0

        # Extract subject and addresses
        subject = msg.get("Subject") or "No Subject"
        sender = msg.get("From") or "Unknown Sender"
        recipient = msg.get("To") or "Unknown Recipient"
        date_str = msg.get("Date")

        body, attachments = _extract_body_from_mime(msg)

        # If body is completely empty and no transport headers, treat whole input as body
        if not body.strip() and not has_headers:
            body = raw_clean

        return {
            "subject": sanitize_untrusted_text(subject, max_length=500),
            "sender": sanitize_untrusted_text(sender, max_length=255),
            "recipient": sanitize_untrusted_text(recipient, max_length=255),
            "date": date_str,
            "body": sanitize_untrusted_text(body),
            "has_headers": has_headers,
            "raw_headers": headers_dict,
            "attachments": attachments
        }
    except Exception:
        # Fallback to treat as plain pasted text
        return {
            "subject": "Pasted Email Text",
            "sender": "Not specified in plain text",
            "recipient": "Not specified in plain text",
            "date": None,
            "body": sanitize_untrusted_text(raw_clean),
            "has_headers": False,
            "raw_headers": {},
            "attachments": []
        }

