"""
MailSentinel AI - Application Configuration

This module loads and validates application settings from environment
variables and .env files using Pydantic Settings and python-dotenv.

CRITICAL SECURITY NOTICE:
- API secrets such as HF_TOKEN are strictly loaded on the backend.
- They are NEVER exposed to the frontend or included in API responses.
- Logging or printing the settings object will automatically mask the token.
"""

import os
from typing import List, Union
from pathlib import Path
import json
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Dynamically locate the backend directory and .env file regardless of current working directory
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
ENV_PATH = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    """
    Application configuration settings.
    Default values are provided for local development.
    Overrides are loaded securely from backend/.env.
    """
    model_config = SettingsConfigDict(
        env_file=(str(ENV_PATH), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # General Project Metadata
    PROJECT_NAME: str = "MailSentinel AI"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server Binding (supports Render/PaaS standard PORT env var)
    API_HOST: str = "0.0.0.0"
    API_PORT: int = int(os.environ.get("PORT", 8000))

    # Interview Demo Mode (Disabled in production: enforces Clerk authentication only)
    DEMO_MODE: bool = False

    # Google Gemini AI Configuration (Primary Copilot LLM - Server-Side Only)
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.1-flash-lite"
    GEMINI_MAX_OUTPUT_TOKENS: int = 1024
    GEMINI_TIMEOUT_SECONDS: float = 12.0

    # Hugging Face AI Configuration (Secondary/Fallback Provider)
    HF_TOKEN: str = ""
    HF_MODEL_ID: str = "openai/gpt-oss-20b"

    # URL Threat Intelligence API Providers
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    URL_INTEL_CACHE_TTL_SECONDS: int = 3600
    URL_REDIRECT_MAX_HOPS: int = 3
    URL_REDIRECT_TIMEOUT_SECONDS: float = 3.0
    URL_MAX_RESPONSE_BYTES: int = 50_000

    # Database Configuration (Async SQLite by default)
    DATABASE_URL: str = "sqlite+aiosqlite:///./mailsentinel.db"

    # Enterprise Clerk Authentication Configuration
    CLERK_SECRET_KEY: str = ""
    CLERK_PUBLISHABLE_KEY: str = ""
    CLERK_ISSUER: str = ""
    CLERK_AUTHORIZED_PARTIES: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173"
    ]
    CLERK_JWKS_CACHE_TTL_SECONDS: int = 3600

    # CORS Origins (Frontend domains permitted to talk to backend API)
    CORS_ORIGINS: Union[str, List[str]] = [
        "https://mailsentinel-ai-sigma.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173"
    ]

    # Security & Input Safety Guardrails
    MAX_EMAIL_BODY_LENGTH: int = 1_000_000  # 1MB limit
    MAX_AGENT_STEPS: int = 5  # Hard-capped steps to avoid infinite loops

    @field_validator("CLERK_AUTHORIZED_PARTIES", mode="before")
    @classmethod
    def assemble_authorized_parties(cls, v: Union[str, List[str]]) -> List[str]:
        """Ensures CLERK_AUTHORIZED_PARTIES is always parsed as a list of strings."""
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [party.strip() for party in v.split(",") if party.strip()]
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Ensures CORS_ORIGINS is always parsed as a list of string URLs."""
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def resolve_database_url(cls, v: str) -> str:
        """
        Ensures SQLite database file paths resolve deterministically.
        In serverless environments (Vercel / AWS Lambda), routes database to writable /tmp.
        In standard environments, resolves relative paths against PROJECT_ROOT.
        """
        is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
        if is_serverless and "sqlite" in v:
            import tempfile
            import shutil
            tmp_dir = Path(tempfile.gettempdir())
            tmp_db = tmp_dir / "mailsentinel.db"
            if not tmp_db.exists():
                seed_db = PROJECT_ROOT / "mailsentinel.db"
                if seed_db.exists():
                    try:
                        shutil.copy2(seed_db, tmp_db)
                    except Exception:
                        pass
            posix_path = tmp_db.as_posix()
            if not posix_path.startswith("/"):
                posix_path = f"/{posix_path}"
            return f"sqlite+aiosqlite:///{posix_path}"

        if v.startswith("sqlite+aiosqlite:///./") or v.startswith("sqlite+aiosqlite:////./"):
            rel_file = v.replace("sqlite+aiosqlite:////./", "").replace("sqlite+aiosqlite:///./", "")
            abs_file = (PROJECT_ROOT / rel_file).resolve().as_posix()
            if not abs_file.startswith("/"):
                abs_file = f"/{abs_file}"
            return f"sqlite+aiosqlite://{abs_file}"
        return v

    @property
    def is_hf_token_configured(self) -> bool:
        """
        Safely checks whether a valid Hugging Face token is present.
        Returns True/False without ever disclosing the secret token value.
        """
        token = (self.HF_TOKEN or "").strip()
        # Verify it is not blank, not a placeholder, and follows HF token prefix pattern
        return bool(token and not token.startswith("hf_your_") and len(token) > 10)

    @property
    def is_gemini_configured(self) -> bool:
        """
        Safely checks whether a valid Google Gemini API key is configured.
        Returns True/False without ever disclosing the secret key.
        """
        key = (self.GEMINI_API_KEY or "").strip()
        return bool(key and not key.startswith("your_") and len(key) >= 15)

    @property
    def is_virustotal_configured(self) -> bool:
        """Checks whether a valid VirusTotal API key is configured."""
        key = (self.VIRUSTOTAL_API_KEY or "").strip()
        return bool(key and not key.startswith("your_") and len(key) >= 20)

    @property
    def is_safe_browsing_configured(self) -> bool:
        """Checks whether a valid Google Safe Browsing API key is configured."""
        key = (self.GOOGLE_SAFE_BROWSING_API_KEY or "").strip()
        return bool(key and not key.startswith("your_") and len(key) >= 20)

    @property
    def is_clerk_configured(self) -> bool:
        """Checks whether Clerk authentication is configured."""
        secret = (self.CLERK_SECRET_KEY or "").strip()
        pub = (self.CLERK_PUBLISHABLE_KEY or "").strip()
        issuer = (self.CLERK_ISSUER or "").strip()
        return bool(secret or pub or issuer)

    def __repr__(self) -> str:
        """
        Prevents accidental leakage of sensitive secrets in logs or console output.
        """
        hf_status = "Configured" if self.is_hf_token_configured else "Not Configured"
        gemini_status = "Configured" if self.is_gemini_configured else "Not Configured"
        vt_status = "Configured" if self.is_virustotal_configured else "Not Configured"
        gsb_status = "Configured" if self.is_safe_browsing_configured else "Not Configured"
        clerk_status = "Configured" if self.is_clerk_configured else "Not Configured"
        return (
            f"Settings(PROJECT_NAME='{self.PROJECT_NAME}', "
            f"ENVIRONMENT='{self.ENVIRONMENT}', "
            f"GEMINI_MODEL='{self.GEMINI_MODEL}', "
            f"GEMINI_API_KEY='*** {gemini_status} ***', "
            f"VIRUSTOTAL_API_KEY='*** {vt_status} ***', "
            f"GOOGLE_SAFE_BROWSING_API_KEY='*** {gsb_status} ***', "
            f"CLERK_AUTH='*** {clerk_status} ***', "
            f"HF_MODEL_ID='{self.HF_MODEL_ID}', "
            f"HF_TOKEN='*** {hf_status} ***', "
            f"DATABASE_URL='{self.DATABASE_URL}')"
        )


# Singleton instance of settings to be imported throughout the backend
settings = Settings()
