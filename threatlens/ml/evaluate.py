"""Model evaluation and comparison.

Produces:
    - accuracy / precision / recall / F1 (per class + weighted)
    - confusion matrix
    - ROC-AUC (where applicable)
    - training time and prediction time
    - feature importance (where available)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
)

logger = logging.getLogger(__name__)


@dataclass
class ModelMetrics:
    """Evaluation metrics for a single model."""
    name: str
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    roc_auc: Optional[float] = None
    train_time: float = 0.0
    predict_time: float = 0.0
    per_class_report: dict = field(default_factory=dict)
    confusion: list = field(default_factory=list)
    feature_importance: list = field(default_factory=list)


def evaluate_model(
    model,
    X_train, y_train,
    X_test, y_test,
    model_name: str = "model",
    feature_names: Optional[list] = None,
    average: str = "weighted",
) -> ModelMetrics:
    """Train and evaluate a model, returning ModelMetrics."""
    logger.info("Training %s on %d samples, %d features", model_name, X_train.shape[0], X_train.shape[1])

    metrics = ModelMetrics(name=model_name)

    # Train
    t0 = time.time()
    model.fit(X_train, y_train)
    metrics.train_time = time.time() - t0

    # Predict
    t0 = time.time()
    y_pred = model.predict(X_test)
    metrics.predict_time = time.time() - t0

    # Core metrics
    metrics.accuracy = accuracy_score(y_test, y_pred)
    metrics.precision = precision_score(y_test, y_pred, average=average, zero_division=0)
    metrics.recall = recall_score(y_test, y_pred, average=average, zero_division=0)
    metrics.f1 = f1_score(y_test, y_pred, average=average, zero_division=0)

    # ROC-AUC (multi-class needs one-vs-rest with predict_proba)
    try:
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)
            if y_proba.shape[1] == 2:  # binary
                metrics.roc_auc = roc_auc_score(y_test, y_proba[:, 1])
            else:  # multi-class
                metrics.roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average=average)
    except Exception as e:
        logger.debug("ROC-AUC calculation failed: %s", e)

    # Per-class report
    metrics.per_class_report = classification_report(
        y_test, y_pred, output_dict=True, zero_division=0,
    )

    # Confusion matrix
    metrics.confusion = confusion_matrix(y_test, y_pred).tolist()

    # Feature importance
    if hasattr(model, "feature_importances_") and feature_names:
        importances = list(zip(feature_names, model.feature_importances_))
        metrics.feature_importance = sorted(importances, key=lambda x: x[1], reverse=True)[:20]

    logger.info(
        "%s: accuracy=%.4f precision=%.4f recall=%.4f F1=%.4f train=%.2fs",
        model_name, metrics.accuracy, metrics.precision, metrics.recall, metrics.f1, metrics.train_time,
    )

    return metrics


def compare_models(metrics_list: list) -> pd.DataFrame:
    """Build comparison DataFrame from multiple ModelMetrics."""
    rows = []
    for m in metrics_list:
        rows.append({
            "Model": m.name,
            "Accuracy": round(m.accuracy, 4),
            "Precision": round(m.precision, 4),
            "Recall": round(m.recall, 4),
            "F1": round(m.f1, 4),
            "ROC-AUC": round(m.roc_auc, 4) if m.roc_auc is not None else "N/A",
            "Train (s)": round(m.train_time, 2),
            "Predict (s)": round(m.predict_time, 3),
        })
    return pd.DataFrame(rows).set_index("Model")


def print_comparison(metrics_list: list, out_file: Optional[str] = None):
    """Print and optionally save a comparison table."""
    df = compare_models(metrics_list)
    print("\n" + "=" * 70)
    print("MODEL COMPARISON")
    print("=" * 70)
    print(df.to_string())
    print("=" * 70)

    if out_file:
        df.to_csv(out_file)
        logger.info("Saved comparison to %s", out_file)
    return df


def print_feature_importance(metrics: ModelMetrics, top_n: int = 15):
    """Print top-N features by importance."""
    if not metrics.feature_importance:
        return
    print(f"\nTop {top_n} features for {metrics.name}:")
    # Use ASCII bars to avoid Windows cp1251 encoding issues
    for name, imp in metrics.feature_importance[:top_n]:
        bar = "#" * int(imp * 50)
        print(f"  {name:40s} {imp:.4f}  {bar}")
