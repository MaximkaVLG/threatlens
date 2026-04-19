"""ThreatLens ML — Network Intrusion Detection using machine learning.

Models:
    - Random Forest (supervised, fast, interpretable)
    - XGBoost (supervised, SOTA on tabular data)
    - Isolation Forest (unsupervised, anomaly detection for 0-day)

Dataset: CIC-IDS2017 (https://www.unb.ca/cic/datasets/ids-2017.html)
"""

from threatlens.ml.dataset import load_cicids2017, SAMPLE_FEATURES
from threatlens.ml.features import preprocess, FeaturePipeline
from threatlens.ml.models import build_random_forest, build_xgboost, build_isolation_forest
from threatlens.ml.evaluate import evaluate_model, compare_models

__all__ = [
    "load_cicids2017", "SAMPLE_FEATURES",
    "preprocess", "FeaturePipeline",
    "build_random_forest", "build_xgboost", "build_isolation_forest",
    "evaluate_model", "compare_models",
]
