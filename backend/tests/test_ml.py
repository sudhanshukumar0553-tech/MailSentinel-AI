"""
Unit tests for Machine Learning preprocessing, vectorization, models, and evaluation.
"""

import numpy as np
import pytest
from backend.app.ml.preprocessing import clean_email_text, batch_clean_texts
from backend.app.ml.vectorizer import create_vectorizer
from backend.app.ml.models import (
    train_logistic_regression,
    train_multinomial_nb,
    SpamClassifier,
    PhishingClassifier
)
from backend.app.ml.evaluation import evaluate_classifier, extract_feature_importance


def test_text_preprocessing():
    """Verify HTML stripping, whitespace normalization, and lowercasing."""
    raw_html = "<html><body><h1>URGENT: Click Here!</h1>  <p>Win $1000 now.</p></body></html>"
    cleaned = clean_email_text(raw_html)
    assert "<h1>" not in cleaned
    assert "<html>" not in cleaned
    assert "urgent: click here! win $1000 now." == cleaned

    # Test batch
    batch = ["<b>Hello</b> World", "<i>Test</i> email"]
    cleaned_batch = batch_clean_texts(batch)
    assert cleaned_batch == ["hello world", "test email"]


def test_ml_pipeline_train_evaluate_and_xai():
    """Verify TF-IDF fitting, Logistic Regression training, metric evaluation, and XAI."""
    corpus = [
        "Congratulations you have won a free lottery prize wire money now",
        "Exclusive cash prize claim your lottery reward immediately",
        "Win free money casino jackpot bonus payout",
        "Quarterly financial report meeting scheduled for tomorrow morning",
        "Project status review and sprint planning document attached",
        "Team lunch discussion and agenda for next week conference",
        "Please review the attached architectural blueprint draft",
        "Urgent invoice payment required please verify your account credentials"
    ]
    labels = [1, 1, 1, 0, 0, 0, 0, 1]  # 1 = malicious/spam, 0 = benign

    # Fit TF-IDF Vectorizer
    vectorizer = create_vectorizer(max_features=100)
    X = vectorizer.fit_transform(corpus)
    assert X.shape[0] == len(corpus)

    # Train Logistic Regression
    lr = train_logistic_regression(X, labels, c_param=1.0)
    metrics_lr = evaluate_classifier(lr, X, labels)
    assert metrics_lr["accuracy"] >= 0.75
    assert "confusion_matrix" in metrics_lr

    # Train Naive Bayes
    nb = train_multinomial_nb(X, labels)
    metrics_nb = evaluate_classifier(nb, X, labels)
    assert metrics_nb["accuracy"] >= 0.75

    # Extract Feature Importance (XAI)
    xai = extract_feature_importance(lr, vectorizer, top_n=5)
    assert "malicious_indicators" in xai
    assert "safe_indicators" in xai


def test_classifier_inference_safely():
    """Verify SpamClassifier and PhishingClassifier handle empty and sample inputs safely."""
    empty_result = SpamClassifier.predict("")
    assert empty_result["is_spam"] is False
    assert empty_result["probability"] == 0.0

    phish_empty = PhishingClassifier.predict("")
    assert phish_empty["is_phishing"] is False
    assert phish_empty["probability"] == 0.0

    # Test with obvious text (either using trained artifact or fallback heuristic)
    sample_spam = SpamClassifier.predict("Claim your free lottery winner payout wire money")
    assert isinstance(sample_spam["probability"], float)
    assert isinstance(sample_spam["is_spam"], bool)
    assert isinstance(sample_spam["triggers"], list)

