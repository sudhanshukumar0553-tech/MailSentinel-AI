"""
MailSentinel AI - Model Training & Evaluation Orchestrator

Executes the full pipeline:
1. Loads & splits both datasets independently.
2. Fits separate TF-IDF vectorizers (zero data leakage).
3. Trains and compares Spam classifiers (Logistic Regression vs Naive Bayes).
4. Trains Phishing classifier (Logistic Regression).
5. Computes full metrics & confusion matrices.
6. Persists .joblib artifacts and records benchmarks in database.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from backend.app.core.logging import logger
from backend.app.ml.dataset_loader import load_enron_spam_dataset, load_phishing_dataset
from backend.app.ml.vectorizer import ARTIFACTS_DIR, create_vectorizer, save_vectorizer
from backend.app.ml.models import (
    train_logistic_regression,
    train_multinomial_nb,
    save_model
)
from backend.app.ml.evaluation import evaluate_classifier, extract_feature_importance


def run_full_training(
    max_samples: Optional[int] = 5000,
    save_to_db: bool = True
) -> Dict[str, Any]:
    """
    Executes end-to-end training and evaluation for both models.

    Args:
        max_samples: Maximum samples per dataset for fast, robust training (default 5,000).
                     Pass None to train on the entire dataset.
        save_to_db: Whether to record benchmark results into the SQLite/Postgres database.
    """
    logger.info("=== Starting MailSentinel AI Dual-Model Training Pipeline ===")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "status": "completed",
        "models": {}
    }

    # -------------------------------------------------------------
    # 1. SPAM CLASSIFIER (bvk/ENRON-spam)
    # -------------------------------------------------------------
    logger.info("--- Stage 1: Training Spam Classifiers (Enron-Spam) ---")
    (X_train_spam, y_train_spam), _, (X_test_spam, y_test_spam), meta_spam = load_enron_spam_dataset(
        max_samples=max_samples
    )

    # Fit TF-IDF Vectorizer ONLY on training set
    spam_vectorizer = create_vectorizer()
    X_train_spam_vec = spam_vectorizer.fit_transform(X_train_spam)
    X_test_spam_vec = spam_vectorizer.transform(X_test_spam)
    save_vectorizer(spam_vectorizer, "spam_tfidf.joblib")

    # Primary: Logistic Regression
    spam_lr = train_logistic_regression(X_train_spam_vec, y_train_spam)
    save_model(spam_lr, "spam_lr.joblib")
    metrics_spam_lr = evaluate_classifier(spam_lr, X_test_spam_vec, y_test_spam)
    xai_spam_lr = extract_feature_importance(spam_lr, spam_vectorizer)

    # Comparison Baseline: Multinomial Naive Bayes
    spam_nb = train_multinomial_nb(X_train_spam_vec, y_train_spam)
    save_model(spam_nb, "spam_nb.joblib")
    metrics_spam_nb = evaluate_classifier(spam_nb, X_test_spam_vec, y_test_spam)

    report["models"]["spam_logistic_regression"] = {
        **metrics_spam_lr,
        "dataset": meta_spam["dataset_name"],
        "class_distribution": meta_spam["class_distribution"],
        "top_features": xai_spam_lr
    }
    report["models"]["spam_naive_bayes_baseline"] = {
        **metrics_spam_nb,
        "dataset": meta_spam["dataset_name"]
    }

    # -------------------------------------------------------------
    # 2. PHISHING CLASSIFIER (zefang-liu/phishing-email-dataset)
    # -------------------------------------------------------------
    logger.info("--- Stage 2: Training Phishing Classifier (Phishing Dataset) ---")
    (X_train_phish, y_train_phish), _, (X_test_phish, y_test_phish), meta_phish = load_phishing_dataset(
        max_samples=max_samples
    )

    phish_vectorizer = create_vectorizer()
    X_train_phish_vec = phish_vectorizer.fit_transform(X_train_phish)
    X_test_phish_vec = phish_vectorizer.transform(X_test_phish)
    save_vectorizer(phish_vectorizer, "phishing_tfidf.joblib")

    phish_lr = train_logistic_regression(X_train_phish_vec, y_train_phish)
    save_model(phish_lr, "phishing_lr.joblib")
    metrics_phish_lr = evaluate_classifier(phish_lr, X_test_phish_vec, y_test_phish)
    xai_phish_lr = extract_feature_importance(phish_lr, phish_vectorizer)

    report["models"]["phishing_logistic_regression"] = {
        **metrics_phish_lr,
        "dataset": meta_phish["dataset_name"],
        "class_distribution": meta_phish["class_distribution"],
        "top_features": xai_phish_lr
    }

    # -------------------------------------------------------------
    # 3. SAVE CONSOLIDATED METRICS REPORT
    # -------------------------------------------------------------
    metrics_file = ARTIFACTS_DIR / "metrics_report.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Saved consolidated metrics report to %s", metrics_file)

    # -------------------------------------------------------------
    # 4. RECORD BENCHMARKS IN DATABASE
    # -------------------------------------------------------------
    if save_to_db:
        try:
            import asyncio
            from backend.app.db.session import AsyncSessionLocal
            from backend.app.db.models.benchmark import ModelBenchmarkRecord

            async def _persist_benchmarks():
                async with AsyncSessionLocal() as session:
                    # Spam LR
                    session.add(ModelBenchmarkRecord(
                        model_name="Logistic Regression",
                        task_type="spam",
                        dataset_name=meta_spam["dataset_name"],
                        accuracy=metrics_spam_lr["accuracy"],
                        precision=metrics_spam_lr["precision"],
                        recall=metrics_spam_lr["recall"],
                        f1_score=metrics_spam_lr["f1_score"],
                        confusion_matrix=metrics_spam_lr["confusion_matrix"]
                    ))
                    # Spam NB
                    session.add(ModelBenchmarkRecord(
                        model_name="Multinomial Naive Bayes",
                        task_type="spam",
                        dataset_name=meta_spam["dataset_name"],
                        accuracy=metrics_spam_nb["accuracy"],
                        precision=metrics_spam_nb["precision"],
                        recall=metrics_spam_nb["recall"],
                        f1_score=metrics_spam_nb["f1_score"],
                        confusion_matrix=metrics_spam_nb["confusion_matrix"]
                    ))
                    # Phishing LR
                    session.add(ModelBenchmarkRecord(
                        model_name="Logistic Regression",
                        task_type="phishing",
                        dataset_name=meta_phish["dataset_name"],
                        accuracy=metrics_phish_lr["accuracy"],
                        precision=metrics_phish_lr["precision"],
                        recall=metrics_phish_lr["recall"],
                        f1_score=metrics_phish_lr["f1_score"],
                        confusion_matrix=metrics_phish_lr["confusion_matrix"]
                    ))
                    await session.commit()
                    logger.info("Successfully persisted model benchmark records to database.")

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(_persist_benchmarks())
                else:
                    loop.run_until_complete(_persist_benchmarks())
            except Exception:
                asyncio.run(_persist_benchmarks())
        except Exception as exc:
            logger.warning("Could not persist benchmarks to DB: %s", exc)

    logger.info("=== MailSentinel AI Dual-Model Training Completed Successfully! ===")
    return report

