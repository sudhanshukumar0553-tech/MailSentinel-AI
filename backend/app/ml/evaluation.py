"""
MailSentinel AI - ML Model Evaluation & Explainability (XAI)

Calculates evaluation metrics on unseen test splits and extracts
token feature importance for Explainable AI (XAI).
"""

from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from backend.app.core.logging import logger


def evaluate_classifier(model: Any, X_test: Any, y_test: Any) -> Dict[str, Any]:
    """
    Evaluates a trained classifier on test features and labels.

    Returns:
        Dictionary containing accuracy, precision, recall, f1, roc_auc, and confusion matrix.
    """
    y_pred = model.predict(X_test)

    # Calculate probabilities if supported
    y_prob = None
    roc_auc = None
    if hasattr(model, "predict_proba"):
        try:
            y_prob = model.predict_proba(X_test)[:, 1]
            roc_auc = float(roc_auc_score(y_test, y_prob))
        except Exception as exc:
            logger.debug("ROC-AUC computation skipped: %s", exc)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "confusion_matrix": {
            "matrix": cm.tolist(),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "total_test_samples": len(y_test)
    }

    logger.info(
        "Evaluation results: Accuracy=%.4f, Precision=%.4f, Recall=%.4f, F1=%.4f",
        metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1_score"]
    )
    return metrics


def extract_feature_importance(
    model: Any,
    vectorizer: Any,
    top_n: int = 15
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extracts the highest-weighted predictive keywords from a Logistic Regression model.

    Returns:
        - malicious_indicators: Words that strongly indicate spam or phishing (positive weights).
        - safe_indicators: Words that strongly indicate legitimate emails (negative weights).
    """
    if not hasattr(model, "coef_"):
        return {"malicious_indicators": [], "safe_indicators": []}

    feature_names = np.array(vectorizer.get_feature_names_out())
    coefficients = model.coef_[0]

    # Top positive weights (indicators of spam/phishing)
    top_malicious_idx = np.argsort(coefficients)[-top_n:][::-1]
    malicious_words = [
        {"token": str(feature_names[i]), "weight": round(float(coefficients[i]), 4)}
        for i in top_malicious_idx if coefficients[i] > 0
    ]

    # Top negative weights (indicators of legitimate/safe email)
    top_safe_idx = np.argsort(coefficients)[:top_n]
    safe_words = [
        {"token": str(feature_names[i]), "weight": round(float(coefficients[i]), 4)}
        for i in top_safe_idx if coefficients[i] < 0
    ]

    return {
        "malicious_indicators": malicious_words,
        "safe_indicators": safe_words
    }

