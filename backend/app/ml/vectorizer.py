"""
MailSentinel AI - TF-IDF Vectorizer Pipeline

Manages the extraction of numerical n-gram features from preprocessed text.
Prevents data leakage by fitting exclusively on training splits.
"""

from pathlib import Path
from typing import List, Optional, Tuple
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from backend.app.core.logging import logger

# Default ML artifacts directory
ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"


def create_vectorizer(
    max_features: int = 5000,
    ngram_range: Tuple[int, int] = (1, 2),
    sublinear_tf: bool = True
) -> TfidfVectorizer:
    """
    Creates a standardized TF-IDF vectorizer configured for spam/phishing classification.
    Uses English stop-words and unigram + bigram combinations.
    """
    return TfidfVectorizer(
        max_features=max_features,
        ngram_range=ngram_range,
        sublinear_tf=sublinear_tf,
        stop_words="english",
        strip_accents="unicode"
    )


def save_vectorizer(vectorizer: TfidfVectorizer, filename: str) -> Path:
    """Saves a fitted vectorizer to the artifacts directory."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = ARTIFACTS_DIR / filename
    joblib.dump(vectorizer, target_path)
    logger.info("Saved TF-IDF vectorizer to %s (vocab size: %d)", target_path, len(vectorizer.vocabulary_))
    return target_path


def load_vectorizer(filename: str) -> Optional[TfidfVectorizer]:
    """Loads a previously fitted vectorizer from the artifacts directory."""
    target_path = ARTIFACTS_DIR / filename
    if not target_path.exists():
        logger.warning("Vectorizer artifact not found at %s", target_path)
        return None
    return joblib.load(target_path)

