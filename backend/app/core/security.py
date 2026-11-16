"""
MailSentinel AI - Security & Zero-Trust Input Sanitizer

Enforces the Zero-Trust security model:
1. All email text and attachments are treated as untrusted data.
2. URLs and IPs are defanged immediately to prevent accidental client execution.
3. Content is bounded to prevent memory exhaustion / Denial of Service.
"""

import re
from typing import List
from backend.app.core.config import settings


def defang_url(url: str) -> str:
    """
    Defangs a URL so that it cannot be accidentally clicked or automatically fetched.
    Example:
        http://evil.com/login -> hxxp://evil[.]com/login
        https://phish.xyz -> hxxps://phish[.]xyz
    """
    if not url:
        return ""
    # Normalize any existing defanging first to avoid nested brackets like [[.]]
    clean = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", url, flags=re.IGNORECASE)
    clean = clean.replace("[.]", ".")
    defanged = re.sub(r"^https://", "hxxps://", clean, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    defanged = defanged.replace(".", "[.]")
    return defanged


def refang_url(defanged_url: str) -> str:
    """
    Restores a defanged URL for internal lexical parsing only.
    NEVER use this to perform an outbound network request!
    """
    if not defanged_url:
        return ""
    restored = re.sub(r"^hxxps://", "https://", defanged_url, flags=re.IGNORECASE)
    restored = re.sub(r"^hxxp://", "http://", restored, flags=re.IGNORECASE)
    restored = restored.replace("[.]", ".")
    return restored


def sanitize_untrusted_text(text: str, max_length: int = None) -> str:
    """
    Sanitizes untrusted input text:
    - Strips NULL bytes (\x00) and harmful control characters.
    - Limits character length to prevent memory exhaustion / DoS attacks.
    """
    if not text:
        return ""
    limit = max_length or settings.MAX_EMAIL_BODY_LENGTH
    # Strip null bytes and non-printable control characters (except newline, tab, carriage return)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "\n[... Content truncated by MailSentinel security limit ...]"
    return cleaned


def wrap_untrusted_evidence(text: str) -> str:
    """
    Wraps email content in an explicit forensic quarantine boundary
    to defend against Indirect Prompt Injection attacks.
    """
    sanitized = sanitize_untrusted_text(text)
    return f"""<UNTRUSTED_EMAIL_DATA>
{sanitized}
</UNTRUSTED_EMAIL_DATA>"""

