"""ML model factories for network intrusion detection.

Three complementary approaches:
    - Random Forest: interpretable ensemble, good baseline
    - XGBoost: gradient boosting, SOTA on tabular data
    - Isolation Forest: unsupervised, anomaly detection for 0-day attacks

All classifiers support .fit(X, y) and .predict(X).
"""

import logging
from sklearn.ensemble import RandomForestClassifier, IsolationForest

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

logger = logging.getLogger(__name__)


def build_random_forest(n_estimators: int = 100, random_state: int = 42, n_jobs: int = -1):
    """Random Forest classifier — good baseline, interpretable.

    Pros:
        - Handles mixed feature scales without preprocessing
        - Provides feature_importances_
        - Robust to outliers and irrelevant features
    Cons:
        - Can overfit on small classes
        - Slower prediction than boosted trees
    """
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=None,  # let trees grow fully
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",  # critical for imbalanced IDS data
        n_jobs=n_jobs,
        random_state=random_state,
        verbose=0,
    )


def build_xgboost(n_estimators: int = 200, random_state: int = 42, n_jobs: int = -1):
    """XGBoost classifier — typically SOTA on tabular data.

    Pros:
        - Highest accuracy on network flow benchmarks
        - Built-in regularization
        - Fast prediction
    Cons:
        - More hyperparameters to tune
        - Slightly less interpretable than RF
    """
    if not HAS_XGBOOST:
        raise ImportError("xgboost not installed. pip install xgboost")

    return XGBClassifier(
        n_estimators=n_estimators,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softmax",  # updated automatically for binary
        tree_method="hist",  # fast histogram-based algorithm
        n_jobs=n_jobs,
        random_state=random_state,
        verbosity=0,
        eval_metric="mlogloss",
    )


def build_isolation_forest(contamination: float = 0.1, random_state: int = 42, n_jobs: int = -1):
    """Isolation Forest — unsupervised anomaly detection.

    Trained ONLY on benign traffic. Predicts -1 for anomaly, +1 for normal.
    Use wrapper .predict_attack() to convert to 0/1 attack labels.

    Args:
        contamination: expected fraction of anomalies in training data

    Pros:
        - Detects unknown (0-day) attacks
        - No need for labeled attack data during training
        - Fast training and prediction
    Cons:
        - Higher false-positive rate than supervised
        - Cannot identify specific attack type
    """
    return IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        n_jobs=n_jobs,
        random_state=random_state,
        verbose=0,
    )


class IsolationForestDetector:
    """Wrapper turning Isolation Forest into a 0/1 attack classifier.

    Usage:
        det = IsolationForestDetector()
        det.fit(X_benign)  # train on normal traffic only
        y_pred = det.predict(X_test)  # 1 = attack, 0 = benign
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.model = build_isolation_forest(contamination=contamination, random_state=random_state)

    def fit(self, X, y=None):
        """Fit on benign samples only. y is ignored (unsupervised)."""
        self.model.fit(X)
        return self

    def predict(self, X):
        """Return 1 for anomaly (attack), 0 for normal (benign)."""
        raw = self.model.predict(X)
        # IsolationForest: -1 = anomaly, +1 = inlier
        return (raw == -1).astype(int)

    def decision_function(self, X):
        """Anomaly score (higher = more anomalous)."""
        # sklearn returns negative values for anomalies; flip for intuitive scores
        return -self.model.decision_function(X)
