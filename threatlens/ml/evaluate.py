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


# ---------------------------------------------------------------------------
# K-fold cross-validation
# ---------------------------------------------------------------------------


@dataclass
class CVResult:
    """Per-fold and aggregate metrics from StratifiedKFold cross-validation."""
    model_name: str
    n_splits: int
    accuracy: list = field(default_factory=list)
    precision: list = field(default_factory=list)
    recall: list = field(default_factory=list)
    f1: list = field(default_factory=list)
    train_time: list = field(default_factory=list)
    predict_time: list = field(default_factory=list)

    def summary(self) -> dict:
        """Return mean, std, and 95% CI half-width for each metric."""
        out = {"model": self.model_name, "n_splits": self.n_splits}
        for name, values in (
            ("accuracy", self.accuracy),
            ("precision", self.precision),
            ("recall", self.recall),
            ("f1", self.f1),
            ("train_time", self.train_time),
            ("predict_time", self.predict_time),
        ):
            arr = np.asarray(values, dtype=np.float64)
            mean = float(arr.mean())
            std = float(arr.std(ddof=1)) if len(arr) > 1 else 0.0
            # 95% CI half-width assuming approximate normality.
            # t-critical: df=n_splits-1 → 2.776 (n=3), 2.132 (n=5). We use
            # 1.96 for n>=5 (close enough) and 2.776 for smaller n.
            crit = 1.96 if self.n_splits >= 5 else 2.776
            half_ci = crit * std / np.sqrt(max(1, len(arr)))
            out[f"{name}_mean"] = mean
            out[f"{name}_std"] = std
            out[f"{name}_ci95"] = float(half_ci)
        return out


def cross_validate_model(
    clf_factory,
    X,
    y,
    n_splits: int = 5,
    random_state: int = 42,
    model_name: str = "model",
) -> CVResult:
    """Run StratifiedKFold CV and return per-fold metrics.

    Args:
        clf_factory: zero-arg callable that returns a freshly-constructed
            estimator. A fresh instance is created per fold to avoid state
            leakage between folds.
        X, y: numpy-like arrays; y is the encoded target (integers).
        n_splits: 3 or 5 recommended.
        model_name: label used in logs and results.
    """
    from collections import Counter
    from sklearn.model_selection import StratifiedKFold

    X = np.asarray(X)
    y = np.asarray(y)

    # Drop classes with fewer samples than n_splits — otherwise a fold can
    # miss them entirely. After dropping, re-encode labels to 0..K-1 so
    # XGBoost (which requires contiguous class indices) doesn't choke.
    counts = Counter(y.tolist())
    rare = {cls for cls, n in counts.items() if n < n_splits}
    if rare:
        logger.warning(
            "Dropping %d class(es) with < %d samples before CV: %s",
            len(rare), n_splits, sorted(rare),
        )
        keep = ~np.isin(y, list(rare))
        X, y = X[keep], y[keep]

    # Remap remaining labels to contiguous 0..K-1 range.
    unique_sorted = np.sort(np.unique(y))
    remap = {int(old): new for new, old in enumerate(unique_sorted)}
    y = np.array([remap[int(v)] for v in y], dtype=np.int64)

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    res = CVResult(model_name=model_name, n_splits=n_splits)

    for fold_idx, (train_idx, test_idx) in enumerate(cv.split(X, y), start=1):
        X_tr, X_te = X[train_idx], X[test_idx]
        y_tr, y_te = y[train_idx], y[test_idx]

        clf = clf_factory()
        t0 = time.time()
        clf.fit(X_tr, y_tr)
        res.train_time.append(time.time() - t0)

        t0 = time.time()
        y_pred = clf.predict(X_te)
        res.predict_time.append(time.time() - t0)

        res.accuracy.append(accuracy_score(y_te, y_pred))
        res.precision.append(
            precision_score(y_te, y_pred, average="weighted", zero_division=0)
        )
        res.recall.append(
            recall_score(y_te, y_pred, average="weighted", zero_division=0)
        )
        res.f1.append(f1_score(y_te, y_pred, average="weighted", zero_division=0))

        logger.info(
            "  %s fold %d/%d: acc=%.4f f1=%.4f (train %.2fs)",
            model_name, fold_idx, n_splits,
            res.accuracy[-1], res.f1[-1], res.train_time[-1],
        )

    return res


def print_cv_comparison(cv_results: list, out_file: str = None):
    """Render CV results as `mean +/- std` table; optionally save to CSV."""
    rows = []
    for res in cv_results:
        s = res.summary()
        rows.append({
            "model": s["model"],
            "accuracy": f"{s['accuracy_mean']:.4f} +/- {s['accuracy_std']:.4f}",
            "precision": f"{s['precision_mean']:.4f} +/- {s['precision_std']:.4f}",
            "recall": f"{s['recall_mean']:.4f} +/- {s['recall_std']:.4f}",
            "f1": f"{s['f1_mean']:.4f} +/- {s['f1_std']:.4f}",
            "train_s": f"{s['train_time_mean']:.2f} +/- {s['train_time_std']:.2f}",
            "ci95_f1": f"+/-{s['f1_ci95']:.4f}",
        })
    df = pd.DataFrame(rows)

    print("\n" + "=" * 90)
    print(f"{cv_results[0].n_splits}-FOLD CROSS-VALIDATION  (mean +/- std)")
    print("=" * 90)
    print(df.to_string(index=False))
    print("=" * 90)

    if out_file:
        numeric = pd.DataFrame([r.summary() for r in cv_results])
        numeric.to_csv(out_file, index=False)
        logger.info("Saved CV results to %s", out_file)
    return df
