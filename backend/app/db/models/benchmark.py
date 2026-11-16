"""
MailSentinel AI - Database ORM Model for ML Model Benchmarks
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Float,
    String,
    JSON
)
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base
from backend.app.core.time import UTCDateTime, now_utc


class ModelBenchmarkRecord(Base):
    """
    Tracks evaluation metrics (Accuracy, Precision, Recall, F1, Confusion Matrix)
    for both Spam and Phishing classifiers.
    """
    __tablename__ = "model_benchmarks"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    model_name: Mapped[str] = mapped_column(String(100), index=True)
    task_type: Mapped[str] = mapped_column(String(50), index=True)  # "spam" or "phishing"
    dataset_name: Mapped[str] = mapped_column(String(100))
    accuracy: Mapped[float] = mapped_column(Float)
    precision: Mapped[float] = mapped_column(Float)
    recall: Mapped[float] = mapped_column(Float)
    f1_score: Mapped[float] = mapped_column(Float)
    confusion_matrix: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        default=now_utc,
        index=True
    )

