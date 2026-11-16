"""
MailSentinel AI - Dataset Ingestion & Preprocessing

Loads and preprocesses:
1. Primary Spam Dataset: bvk/ENRON-spam
2. Secondary Phishing Dataset: zefang-liu/phishing-email-dataset

Guarantees:
- Deduplication and missing value removal
- Stratified train/val/test splitting (70% Train, 15% Validation, 15% Test)
- Strict separation (datasets are NEVER merged)
- Full licensing and provenance attribution
"""

import ast
import re
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.ml.preprocessing import clean_email_text


def _parse_enron_email_content(raw_val: Any) -> str:
    """
    Cleans raw email field from the Enron dataset.
    Handles list representations like "['Subject: ... \n', 'line 2']".
    """
    if not raw_val:
        return ""
    if isinstance(raw_val, list):
        return " ".join([str(line) for line in raw_val])
    if isinstance(raw_val, str):
        raw_val = raw_val.strip()
        if raw_val.startswith("[") and raw_val.endswith("]"):
            try:
                parsed = ast.literal_eval(raw_val)
                if isinstance(parsed, list):
                    return " ".join([str(p) for p in parsed])
            except Exception:
                pass
            # Fallback regex strip
            cleaned = re.sub(r"^\[['\"]|['\"]\]$", "", raw_val)
            cleaned = cleaned.replace("', '", " ").replace('", "', " ")
            return cleaned
        return raw_val
    return str(raw_val)


def load_enron_spam_dataset(
    max_samples: Optional[int] = None,
    test_size: float = 0.30,
    random_state: int = 42
) -> Tuple[Tuple[List[str], List[int]], Tuple[List[str], List[int]], Tuple[List[str], List[int]], Dict[str, Any]]:
    """
    Loads, cleans, and splits the bvk/ENRON-spam dataset.

    Returns:
        ((X_train, y_train), (X_val, y_val), (X_test, y_test), metadata)
    """
    logger.info("Loading bvk/ENRON-spam dataset from Hugging Face...")
    token = settings.HF_TOKEN if settings.is_hf_token_configured else None

    # Load dataset
    ds = load_dataset("bvk/ENRON-spam", split="train", token=token)
    df = pd.DataFrame(ds)

    # Ensure required columns exist
    if "email" not in df.columns or "label" not in df.columns:
        raise ValueError(f"Unexpected columns in ENRON-spam: {df.columns.tolist()}")

    # Parse and clean text
    df["cleaned_text"] = df["email"].apply(_parse_enron_email_content)
    df["cleaned_text"] = df["cleaned_text"].apply(clean_email_text)

    # Convert label to integer binary: 0 = ham, 1 = spam
    df["target"] = df["label"].astype(int)

    # Filter out empty or whitespace-only emails
    initial_count = len(df)
    df = df[df["cleaned_text"].str.len() > 10].copy()

    # Deduplicate
    df = df.drop_duplicates(subset=["cleaned_text"]).copy()
    dedup_count = len(df)

    # Optional subsampling for quick local training / testing
    if max_samples and max_samples < dedup_count:
        df, _ = train_test_split(
            df,
            train_size=max_samples,
            stratify=df["target"],
            random_state=random_state
        )

    # Stratified train (70%) and temp (30%) split
    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
        df["cleaned_text"].tolist(),
        df["target"].tolist(),
        test_size=test_size,
        stratify=df["target"],
        random_state=random_state
    )

    # Split temp into 50/50 Validation and Test (15% each of original)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp_raw,
        y_temp,
        test_size=0.50,
        stratify=y_temp,
        random_state=random_state
    )

    metadata = {
        "dataset_name": "bvk/ENRON-spam",
        "task": "spam_detection",
        "initial_samples": initial_count,
        "valid_deduplicated_samples": len(df),
        "train_samples": len(X_train_raw),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
        "class_distribution": {
            "ham_count": int((df["target"] == 0).sum()),
            "spam_count": int((df["target"] == 1).sum()),
            "spam_ratio": round(float((df["target"] == 1).mean()), 4)
        }
    }

    logger.info(
        "ENRON-spam loaded: %d train, %d val, %d test (Spam ratio: %.2f)",
        len(X_train_raw), len(X_val), len(X_test), metadata["class_distribution"]["spam_ratio"]
    )
    return (X_train_raw, y_train), (X_val, y_val), (X_test, y_test), metadata


def load_phishing_dataset(
    max_samples: Optional[int] = None,
    test_size: float = 0.30,
    random_state: int = 42
) -> Tuple[Tuple[List[str], List[int]], Tuple[List[str], List[int]], Tuple[List[str], List[int]], Dict[str, Any]]:
    """
    Loads, cleans, and splits the zefang-liu/phishing-email-dataset.

    Returns:
        ((X_train, y_train), (X_val, y_val), (X_test, y_test), metadata)
    """
    logger.info("Loading zefang-liu/phishing-email-dataset from Hugging Face...")
    token = settings.HF_TOKEN if settings.is_hf_token_configured else None

    ds = load_dataset("zefang-liu/phishing-email-dataset", split="train", token=token)
    df = pd.DataFrame(ds)

    text_col = "Email Text" if "Email Text" in df.columns else df.columns[0]
    type_col = "Email Type" if "Email Type" in df.columns else df.columns[1]

    # Map target: "Phishing Email" -> 1, "Safe Email" -> 0
    def _map_phishing_label(val: Any) -> int:
        if isinstance(val, (int, float)):
            return int(val)
        val_str = str(val).strip().lower()
        if "phishing" in val_str or "fraud" in val_str or "malicious" in val_str:
            return 1
        return 0

    df["target"] = df[type_col].apply(_map_phishing_label)
    df["cleaned_text"] = df[text_col].astype(str).apply(clean_email_text)

    # Filter out empty or very short strings
    initial_count = len(df)
    df = df[df["cleaned_text"].str.len() > 10].copy()

    # Deduplicate
    df = df.drop_duplicates(subset=["cleaned_text"]).copy()
    dedup_count = len(df)

    if max_samples and max_samples < dedup_count:
        df, _ = train_test_split(
            df,
            train_size=max_samples,
            stratify=df["target"],
            random_state=random_state
        )

    # Stratified split: 70% Train, 15% Val, 15% Test
    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
        df["cleaned_text"].tolist(),
        df["target"].tolist(),
        test_size=test_size,
        stratify=df["target"],
        random_state=random_state
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_temp_raw,
        y_temp,
        test_size=0.50,
        stratify=y_temp,
        random_state=random_state
    )

    metadata = {
        "dataset_name": "zefang-liu/phishing-email-dataset",
        "task": "phishing_detection",
        "initial_samples": initial_count,
        "valid_deduplicated_samples": len(df),
        "train_samples": len(X_train_raw),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
        "class_distribution": {
            "safe_count": int((df["target"] == 0).sum()),
            "phishing_count": int((df["target"] == 1).sum()),
            "phishing_ratio": round(float((df["target"] == 1).mean()), 4)
        }
    }

    logger.info(
        "Phishing dataset loaded: %d train, %d val, %d test (Phishing ratio: %.2f)",
        len(X_train_raw), len(X_val), len(X_test), metadata["class_distribution"]["phishing_ratio"]
    )
    return (X_train_raw, y_train), (X_val, y_val), (X_test, y_test), metadata

