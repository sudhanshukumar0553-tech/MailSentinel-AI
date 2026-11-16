"""
Unit tests for MailSentinel AI application configuration & secret masking.
"""

from backend.app.core.config import Settings, settings


def test_settings_loads_correctly():
    """Verify that settings are loaded with correct project metadata."""
    assert settings.PROJECT_NAME == "MailSentinel AI"
    assert settings.HF_MODEL_ID == "openai/gpt-oss-20b"
    assert isinstance(settings.CORS_ORIGINS, list)


def test_hf_token_configured_safely():
    """
    Verify that the system detects whether HF_TOKEN is configured
    without exposing or displaying the raw secret.
    """
    # The application can detect token presence via boolean check
    assert isinstance(settings.is_hf_token_configured, bool)

    # Verify that printing or string-formatting Settings NEVER reveals the raw token
    settings_repr = repr(settings)
    assert "***" in settings_repr
    assert "hf_" not in settings_repr or "hf_your_" in settings_repr


def test_dummy_token_masking():
    """Test custom settings instance with a mock secret."""
    test_settings = Settings(HF_TOKEN="hf_sampledummysecret1234567890abcdef")
    assert test_settings.is_hf_token_configured is True
    # Ensure the secret string is not in the representation
    assert "hf_sampledummysecret1234567890abcdef" not in repr(test_settings)
    assert "*** Configured ***" in repr(test_settings)

