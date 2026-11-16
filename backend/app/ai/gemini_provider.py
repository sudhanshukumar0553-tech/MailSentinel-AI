"""
MailSentinel AI - Google Gemini API Provider (Fast & Resilient Sentinel Copilot)

Implements the Google GenAI Python SDK ("google-genai") client with:
- Primary Model: "gemini-3.1-flash-lite"
- Candidate Fallback Hierarchy: "gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.7-flash"
- Exponential Backoff & Automatic Retries for 503 (High Demand), 429 (Rate Limit), and 5xx errors.
- Pre-egress PII, credential, and key redaction.
- User-friendly error messaging (no raw API exceptions displayed to end users).
- Multi-turn conversation history and streaming support.
"""

import re
import time
import random
import asyncio
from typing import AsyncGenerator, Dict, Any, List, Optional, Tuple
from google import genai
from google.genai import types
from google.genai import errors

from backend.app.core.config import settings
from backend.app.core.logging import logger

_CLIENT_INSTANCE: Optional[genai.Client] = None

# Verified Google Gemini candidate models for fallback hierarchy
_FALLBACK_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.7-flash"
]

MAX_RETRIES_PER_MODEL = 3
INITIAL_BACKOFF_SECONDS = 1.0
BACKOFF_FACTOR = 1.8
MAX_BACKOFF_SECONDS = 5.0

FRIENDLY_HIGH_DEMAND_MESSAGE = (
    "⚠️ **AI Service High Demand:** The Sentinel Copilot AI is currently experiencing high demand "
    "across Google Gemini cloud nodes. Please wait a moment and resubmit your query, or review "
    "the empirical threat indicators and ML model metrics in the tabs above."
)

# Sensitive pattern matching for pre-egress redaction
REDACTION_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{15,}\b", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\b(?:hf|ghp|sk|AIza)[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED_CARD_NUMBER]"),
    (re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]+"), "password: [REDACTED_PASSWORD]")
]


def redact_sensitive_data(text: str) -> str:
    """
    Sanitizes email body and user queries by redacting credentials, private keys,
    and financial numbers before sending untrusted payloads to external LLM APIs.
    """
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def is_transient_error(exc: Exception) -> Tuple[bool, int, str]:
    """
    Determines if an error is transient (HTTP 503 High Demand, 429 Rate Limit, 5xx),
    qualifying for exponential backoff and candidate model fallback.
    """
    code = getattr(exc, "code", None)
    msg = str(exc).lower()

    if code in (503, 429, 500, 502, 504):
        return True, code, str(exc)

    transient_indicators = (
        "high demand",
        "unavailable",
        "temporarily",
        "resource_exhausted",
        "rate limit",
        "quota",
        "overloaded",
        "try again later",
        "server error"
    )
    if any(k in msg for k in transient_indicators):
        return True, code or 503, str(exc)

    return False, code or 0, str(exc)


def get_gemini_client() -> Optional[genai.Client]:
    """
    Provides or lazily instantiates a singleton Google GenAI client.
    Returns None if GEMINI_API_KEY is not configured.
    """
    global _CLIENT_INSTANCE
    if not settings.is_gemini_configured:
        return None

    if _CLIENT_INSTANCE is None:
        try:
            _CLIENT_INSTANCE = genai.Client(api_key=settings.GEMINI_API_KEY.strip())
            logger.info("Google GenAI client initialized successfully (Primary Model: %s)", settings.GEMINI_MODEL)
        except Exception as e:
            logger.error("Failed to initialize Google GenAI client: %s", e)
            return None

    return _CLIENT_INSTANCE


async def call_gemini_async(
    prompt: str,
    system_instruction: str,
    max_output_tokens: Optional[int] = None,
    temperature: float = 0.2
) -> Dict[str, Any]:
    """
    Performs an asynchronous call to Google Gemini with exponential backoff,
    transient retry logic, and seamless candidate model fallback.
    """
    client = get_gemini_client()
    if client is None:
        return {
            "status": "unavailable",
            "reply": None,
            "error": "Gemini API key is not configured.",
            "error_type": "ApiKeyMissing",
            "model_used": None,
            "latency_ms": 0.0
        }

    clean_prompt = redact_sensitive_data(prompt)
    clean_system = redact_sensitive_data(system_instruction)

    tokens = max_output_tokens or settings.GEMINI_MAX_OUTPUT_TOKENS
    config = types.GenerateContentConfig(
        system_instruction=clean_system,
        max_output_tokens=tokens,
        temperature=temperature
    )

    # Establish model priority: configured primary model first, followed by fallbacks
    models_to_try = [settings.GEMINI_MODEL]
    for fb in _FALLBACK_MODELS:
        if fb not in models_to_try:
            models_to_try.append(fb)

    last_error: Optional[Tuple[str, str]] = None
    start_time = time.perf_counter()

    for target_model in models_to_try:
        logger.info("Initiating Gemini request on candidate model: %s", target_model)

        for attempt in range(MAX_RETRIES_PER_MODEL):
            try:
                response = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=target_model,
                        contents=clean_prompt,
                        config=config
                    ),
                    timeout=settings.GEMINI_TIMEOUT_SECONDS
                )
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
                text_output = response.text or ""

                if text_output.strip():
                    logger.info("Gemini inference succeeded on model %s (%.1fms)", target_model, elapsed_ms)
                    return {
                        "status": "success",
                        "reply": text_output,
                        "error": None,
                        "error_type": None,
                        "model_used": target_model,
                        "latency_ms": elapsed_ms
                    }

            except errors.APIError as api_err:
                code = getattr(api_err, "code", 500)
                msg = str(api_err)
                retryable, _, _ = is_transient_error(api_err)

                if code == 404:
                    logger.info("Model %s returned 404. Advancing to next fallback model.", target_model)
                    last_error = ("ModelNotFound", msg)
                    break  # Don't retry a 404 on the same model; try next model

                if retryable and attempt < MAX_RETRIES_PER_MODEL - 1:
                    jitter = random.uniform(0.1, 0.4)
                    delay = min(MAX_BACKOFF_SECONDS, INITIAL_BACKOFF_SECONDS * (BACKOFF_FACTOR ** attempt)) + jitter
                    logger.warning(
                        "Gemini %s returned transient error (HTTP %s). Backing off for %.2fs (attempt %d/%d)...",
                        target_model, code, delay, attempt + 1, MAX_RETRIES_PER_MODEL
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.warning(
                        "Gemini %s exhausted %d retries (HTTP %s). Advancing to next candidate model.",
                        target_model, attempt + 1, code
                    )
                    last_error = ("TransientError", msg)
                    break

            except asyncio.TimeoutError:
                logger.warning(
                    "Gemini %s timed out after %.1fs. Advancing immediately to next candidate model in fallback hierarchy.",
                    target_model, settings.GEMINI_TIMEOUT_SECONDS
                )
                last_error = ("TimeoutError", f"Request timed out after {settings.GEMINI_TIMEOUT_SECONDS}s on {target_model}")
                break

            except Exception as exc:
                retryable, code, _ = is_transient_error(exc)
                if retryable and attempt < MAX_RETRIES_PER_MODEL - 1:
                    delay = INITIAL_BACKOFF_SECONDS * (BACKOFF_FACTOR ** attempt) + random.uniform(0.1, 0.3)
                    logger.warning("Gemini %s error (%s). Retrying in %.2fs...", target_model, type(exc).__name__, delay)
                    await asyncio.sleep(delay)
                    continue
                logger.warning("Gemini execution failed on %s: %s", target_model, exc)
                last_error = (type(exc).__name__, str(exc))
                break

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
    err_type = last_error[0] if last_error else "HighDemand"
    
    # Return user-friendly error without exposing raw backend traces
    return {
        "status": "unavailable",
        "reply": FRIENDLY_HIGH_DEMAND_MESSAGE,
        "error": FRIENDLY_HIGH_DEMAND_MESSAGE,
        "error_type": err_type,
        "model_used": None,
        "latency_ms": elapsed_ms
    }


async def call_gemini_stream(
    prompt: str,
    system_instruction: str,
    max_output_tokens: Optional[int] = None,
    temperature: float = 0.2
) -> AsyncGenerator[str, None]:
    """
    Yields chunks in real-time using Google Gemini streaming with
    exponential backoff retry and automatic candidate model fallback.
    """
    client = get_gemini_client()
    if client is None:
        yield "[Notice: Gemini API key is not configured. Switching to local deterministic engine...]"
        return

    clean_prompt = redact_sensitive_data(prompt)
    clean_system = redact_sensitive_data(system_instruction)
    tokens = max_output_tokens or settings.GEMINI_MAX_OUTPUT_TOKENS

    config = types.GenerateContentConfig(
        system_instruction=clean_system,
        max_output_tokens=tokens,
        temperature=temperature
    )

    models_to_try = [settings.GEMINI_MODEL]
    for fb in _FALLBACK_MODELS:
        if fb not in models_to_try:
            models_to_try.append(fb)

    stream_started = False

    for target_model in models_to_try:
        logger.info("Initiating streaming Gemini response on model: %s", target_model)

        for attempt in range(MAX_RETRIES_PER_MODEL):
            try:
                response_stream = await client.aio.models.generate_content_stream(
                    model=target_model,
                    contents=clean_prompt,
                    config=config
                )
                iterator = response_stream.__aiter__()
                while True:
                    try:
                        chunk = await asyncio.wait_for(iterator.__anext__(), timeout=settings.GEMINI_TIMEOUT_SECONDS)
                        if chunk.text:
                            stream_started = True
                            yield chunk.text
                    except StopAsyncIteration:
                        break

                # Stream completed successfully
                return

            except asyncio.TimeoutError:
                if stream_started:
                    logger.warning("Stream on %s timed out mid-delivery.", target_model)
                    yield "\n\n*(Stream timed out by provider)*"
                    return
                logger.warning(
                    "Streaming connection to %s timed out after %.1fs. Advancing to next candidate model.",
                    target_model, settings.GEMINI_TIMEOUT_SECONDS
                )
                break

            except errors.APIError as api_err:
                code = getattr(api_err, "code", 500)
                retryable, _, _ = is_transient_error(api_err)

                if stream_started:
                    # Chunks were already delivered to user; finish gracefully
                    logger.warning("Stream on %s interrupted mid-delivery: %s", target_model, api_err)
                    yield "\n\n*(Stream ended by provider)*"
                    return

                if code == 404:
                    logger.info("Model %s returned 404. Trying next fallback model...", target_model)
                    break

                if retryable and attempt < MAX_RETRIES_PER_MODEL - 1:
                    delay = min(MAX_BACKOFF_SECONDS, INITIAL_BACKOFF_SECONDS * (BACKOFF_FACTOR ** attempt)) + random.uniform(0.1, 0.4)
                    logger.warning("Streaming transient error on %s (HTTP %s). Retrying in %.2fs...", target_model, code, delay)
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.warning("Streaming failed on %s after %d retries. Advancing to next model.", target_model, attempt + 1)
                    break

            except Exception as exc:
                if stream_started:
                    logger.warning("Streaming on %s interrupted: %s", target_model, exc)
                    yield "\n\n*(Stream ended)*"
                    return

                retryable, _, _ = is_transient_error(exc)
                if retryable and attempt < MAX_RETRIES_PER_MODEL - 1:
                    delay = INITIAL_BACKOFF_SECONDS * (BACKOFF_FACTOR ** attempt) + random.uniform(0.1, 0.3)
                    logger.warning("Streaming exception on %s (%s). Retrying in %.2fs...", target_model, type(exc).__name__, delay)
                    await asyncio.sleep(delay)
                    continue

                logger.warning("Streaming connection failed on %s: %s", target_model, exc)
                break

    # If all models and retries failed before any chunk was sent, emit friendly message
    if not stream_started:
        yield FRIENDLY_HIGH_DEMAND_MESSAGE
