"""
MailSentinel AI - Hugging Face LLM Provider Configuration

Integrates with Hugging Face Inference Providers using smolagents.InferenceClientModel.
Supports openai/gpt-oss-20b and other configurable open-weights models.
"""

from typing import Optional, Any
try:
    from smolagents import InferenceClientModel
except ImportError:
    InferenceClientModel = None
from backend.app.core.config import settings
from backend.app.core.logging import logger


def get_inference_model() -> Optional[Any]:
    """
    Initializes the Hugging Face InferenceClientModel using the configured HF_TOKEN.
    """
    if InferenceClientModel is None:
        logger.info("smolagents not installed; skipping InferenceClientModel initialization.")
        return None
    token = settings.HF_TOKEN if settings.is_hf_token_configured else None
    logger.info("Initializing smolagents InferenceClientModel (Model: %s)", settings.HF_MODEL_ID)
    try:
        model = InferenceClientModel(
            model_id=settings.HF_MODEL_ID,
            token=token,
            timeout=5.0
        )
        return model
    except Exception as exc:
        logger.warning("Failed to initialize Hugging Face InferenceClientModel: %s", exc)
        return None

