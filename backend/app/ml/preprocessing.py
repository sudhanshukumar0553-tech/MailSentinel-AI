"""
MailSentinel AI - Text Preprocessing Pipeline

Prepares raw email content for TF-IDF vectorization and machine learning models.
Features:
- HTML tag stripping
- Email address & URL token normalization
- Whitespace normalization and lowercasing
"""

import re
from typing import List, Optional


# Precompiled regex patterns for speed
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
URL_REGEX = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
WHITESPACE_REGEX = re.compile(r"\s+")
SPECIAL_CHARS_REGEX = re.compile(r"[^\w\s]")


def clean_email_text(text: Optional[str], replace_urls: bool = False, replace_emails: bool = False) -> str:
    """
    Cleans raw email text for machine learning feature extraction.

    Args:
        text: Raw email body or string.
        replace_urls: If True, replaces URLs with a normalized token 'http_url'.
        replace_emails: If True, replaces emails with a normalized token 'email_address'.

    Returns:
        Cleaned lowercase string suitable for TF-IDF.
    """
    if not text or not isinstance(text, str):
        return ""

    # Strip HTML tags
    cleaned = HTML_TAG_REGEX.sub(" ", text)

    # Optionally normalize URLs and Emails
    if replace_urls:
        cleaned = URL_REGEX.sub(" http_url ", cleaned)
    if replace_emails:
        cleaned = EMAIL_REGEX.sub(" email_address ", cleaned)

    # Convert to lowercase
    cleaned = cleaned.lower()

    # Normalize whitespace (newlines, tabs, multiple spaces to a single space)
    cleaned = WHITESPACE_REGEX.sub(" ", cleaned).strip()

    return cleaned


def batch_clean_texts(texts: List[str]) -> List[str]:
    """Applies text cleaning to a batch of email texts."""
    return [clean_email_text(t) for t in texts]

