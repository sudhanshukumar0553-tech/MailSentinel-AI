"""
MailSentinel AI - Machine Learning Model Definitions & Inference Engine

Implements:
1. Spam Classifier: Logistic Regression (primary) & Multinomial Naive Bayes (comparison baseline)
2. Phishing Classifier: Logistic Regression
3. High-performance inference functions with cached lazy-loading.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from backend.app.core.logging import logger
from backend.app.ml.preprocessing import clean_email_text
from backend.app.ml.vectorizer import ARTIFACTS_DIR, load_vectorizer

# Global model cache to avoid reading from disk on every API call
_MODEL_CACHE: Dict[str, Any] = {}


def train_logistic_regression(
    X_train: Any,
    y_train: Any,
    c_param: float = 1.0,
    random_state: int = 42
) -> LogisticRegression:
    """Trains a calibrated Logistic Regression model with balanced class weights."""
    model = LogisticRegression(
        C=c_param,
        max_iter=1000,
        class_weight="balanced",
        random_state=random_state,
        solver="lbfgs"
    )
    model.fit(X_train, y_train)
    return model


def train_multinomial_nb(X_train: Any, y_train: Any, alpha: float = 0.1) -> MultinomialNB:
    """Trains a Multinomial Naive Bayes classifier as a fast baseline."""
    model = MultinomialNB(alpha=alpha)
    model.fit(X_train, y_train)
    return model


def save_model(model: Any, filename: str) -> Path:
    """Persists a trained scikit-learn model to the artifacts directory."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = ARTIFACTS_DIR / filename
    joblib.dump(model, target_path)
    logger.info("Saved model artifact to %s", target_path)
    return target_path


def load_model(filename: str) -> Optional[Any]:
    """Loads a persisted model from the artifacts directory, using caching."""
    if filename in _MODEL_CACHE:
        return _MODEL_CACHE[filename]

    target_path = ARTIFACTS_DIR / filename
    if not target_path.exists():
        logger.warning("Model artifact not found at %s", target_path)
        return None

    model = joblib.load(target_path)
    _MODEL_CACHE[filename] = model
    return model


class SpamClassifier:
    """Inference wrapper for the trained Spam Detection model."""

    @classmethod
    def predict(cls, raw_text: str) -> Dict[str, Any]:
        """
        Predicts spam probability for an email text.
        Returns:
            dict containing probability (0.0 to 1.0), is_spam (bool), and top trigger keywords.
        """
        vectorizer = load_vectorizer("spam_tfidf.joblib")
        model = load_model("spam_lr.joblib")

        cleaned = clean_email_text(raw_text)
        if not cleaned:
            return {"probability": 0.0, "is_spam": False, "confidence": "high", "triggers": []}

        if vectorizer is None or model is None:
            # Fallback heuristic if models have not yet been trained
            logger.warning("Spam ML model not yet trained. Using fallback heuristic keyword scanner.")
            lower = raw_text.lower()
            spam_triggers = [w for w in ["viagra", "lottery", "winner", "free money", "crypto investment", "casino", "wire transfer"] if w in lower]
            prob = min(0.95, len(spam_triggers) * 0.35) if spam_triggers else 0.05
            return {
                "probability": round(prob, 4),
                "is_spam": prob >= 0.5,
                "confidence": "fallback_heuristic",
                "triggers": spam_triggers
            }

        features = vectorizer.transform([cleaned])
        proba = float(model.predict_proba(features)[0][1])

        # Extract active trigger words present in this email
        triggers = []
        if hasattr(model, "coef_"):
            feature_names = vectorizer.get_feature_names_out()
            feature_idx = features.nonzero()[1]
            coefs = model.coef_[0]
            word_weights = [(feature_names[i], coefs[i]) for i in feature_idx if coefs[i] > 0.5]
            word_weights.sort(key=lambda x: x[1], reverse=True)
            triggers = [w for w, _ in word_weights[:8]]

        return {
            "probability": round(proba, 4),
            "is_spam": proba >= 0.5,
            "confidence": "calibrated_ml",
            "triggers": triggers
        }


class PhishingClassifier:
    """Inference wrapper for the trained Phishing Detection model."""

    @classmethod
    def predict(cls, raw_text: str) -> Dict[str, Any]:
        """
        Predicts phishing probability for an email text.
        Returns:
            dict containing probability (0.0 to 1.0), is_phishing (bool), and key indicators.
        """
        vectorizer = load_vectorizer("phishing_tfidf.joblib")
        model = load_model("phishing_lr.joblib")

        cleaned = clean_email_text(raw_text)
        if not cleaned:
            return {"probability": 0.0, "is_phishing": False, "confidence": "high", "triggers": []}

        if vectorizer is None or model is None:
            # Fallback heuristic if models have not yet been trained
            logger.warning("Phishing ML model not yet trained. Using fallback heuristic scanner.")
            lower = raw_text.lower()
            phish_triggers = [w for w in ["verify your account", "suspend", "password reset", "unauthorized access", "update billing", "urgent action required", "login immediately"] if w in lower]
            prob = min(0.95, len(phish_triggers) * 0.40) if phish_triggers else 0.05
            return {
                "probability": round(prob, 4),
                "is_phishing": prob >= 0.5,
                "confidence": "fallback_heuristic",
                "triggers": phish_triggers
            }

        features = vectorizer.transform([cleaned])
        proba = float(model.predict_proba(features)[0][1])

        # Extract active phishing indicators
        triggers = []
        if hasattr(model, "coef_"):
            feature_names = vectorizer.get_feature_names_out()
            feature_idx = features.nonzero()[1]
            coefs = model.coef_[0]
            word_weights = [(feature_names[i], coefs[i]) for i in feature_idx if coefs[i] > 0.5]
            word_weights.sort(key=lambda x: x[1], reverse=True)
            triggers = [w for w, _ in word_weights[:8]]

        return {
            "probability": round(proba, 4),
            "is_phishing": proba >= 0.5,
            "confidence": "calibrated_ml",
            "triggers": triggers
        }

