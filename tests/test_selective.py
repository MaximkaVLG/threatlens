"""Unit tests for threatlens.ml.selective.

Uses tiny hand-crafted data where the right Mahalanobis distances are
easy to verify by hand, plus one end-to-end test with a mock XGBoost.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from threatlens.ml.selective import (
    MahalanobisAbstainer, SelectiveFlowDetector, ABSTAIN_LABEL,
)


@pytest.fixture
def toy_data():
    """Two Gaussian clusters in 2D.
    - Class 0 mean (0,0) with unit variance
    - Class 1 mean (5,5) with unit variance
    100 samples each.
    """
    rng = np.random.default_rng(42)
    X0 = rng.normal(loc=0.0, scale=1.0, size=(100, 2))
    X1 = rng.normal(loc=5.0, scale=1.0, size=(100, 2))
    X = np.vstack([X0, X1])
    y = np.array([0] * 100 + [1] * 100)
    return X, y


def test_fit_stores_means_and_inverse_covariance(toy_data):
    X, y = toy_data
    m = MahalanobisAbstainer().fit(X, y)
    assert m.feature_dim == 2
    assert set(m.class_means.keys()) == {0, 1}
    # Means close to (0,0) and (5,5)
    np.testing.assert_allclose(m.class_means[0], [0, 0], atol=0.3)
    np.testing.assert_allclose(m.class_means[1], [5, 5], atol=0.3)
    # Inverse covariance exists and is symmetric positive-definite
    assert m.inv_covariance is not None
    np.testing.assert_allclose(m.inv_covariance, m.inv_covariance.T, atol=1e-10)
    eigenvalues = np.linalg.eigvalsh(m.inv_covariance)
    assert all(ev > 0 for ev in eigenvalues)


def test_distance_to_own_centroid_small(toy_data):
    X, y = toy_data
    m = MahalanobisAbstainer().fit(X, y)
    # Distance of a class-0 sample to class-0 centroid should be small;
    # distance to class-1 centroid should be large.
    sample = np.array([[0.1, -0.2]])  # very close to class-0 mean
    d_own = m.distances(sample, np.array([0]))[0]
    d_other = m.distances(sample, np.array([1]))[0]
    assert d_own < 1.0
    assert d_other > 5.0


def test_tune_thresholds_respects_target_coverage(toy_data):
    X, y = toy_data
    m = MahalanobisAbstainer().fit(X, y)
    # "Predictions" match ground truth so coverage is computed on correct rows
    taus = m.tune_thresholds(X, y_val=y, y_pred=y, target_coverage=0.95)
    assert 0 in taus and 1 in taus
    # Check: exactly 95 % of correct-class-0 samples should have distance <= tau_0
    d0 = m.distances(X[y == 0], np.zeros(100, dtype=int))
    frac_under = (d0 <= taus[0]).mean()
    assert 0.90 <= frac_under <= 1.0  # allow small jitter


def test_should_abstain_flags_obvious_outlier(toy_data):
    X, y = toy_data
    m = MahalanobisAbstainer().fit(X, y)
    m.tune_thresholds(X, y, y, target_coverage=0.99)

    # Constructed outlier far from either cluster
    outlier = np.array([[50.0, 50.0]])
    abstain, _ = m.should_abstain(outlier, np.array([0]))
    assert bool(abstain[0]) is True

    # Point well inside class-0 cluster should not be abstained
    inlier = np.array([[0.0, 0.0]])
    abstain, _ = m.should_abstain(inlier, np.array([0]))
    assert bool(abstain[0]) is False


def test_save_and_load_roundtrip(toy_data):
    X, y = toy_data
    m = MahalanobisAbstainer().fit(X, y)
    m.tune_thresholds(X, y, y, target_coverage=0.99)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "abstainer.joblib"
        m.save(str(path))
        m2 = MahalanobisAbstainer.load(str(path))

    np.testing.assert_array_equal(m.class_means[0], m2.class_means[0])
    np.testing.assert_array_equal(m.inv_covariance, m2.inv_covariance)
    assert m.thresholds == m2.thresholds
    assert m._global_fallback == m2._global_fallback


def test_per_class_covariance_mode(toy_data):
    """When use_pooled_covariance=False, a per-class inverse is stored."""
    X, y = toy_data
    m = MahalanobisAbstainer(use_pooled_covariance=False).fit(X, y)
    assert 0 in m.inv_covariance_per_class
    assert 1 in m.inv_covariance_per_class


# ---- End-to-end: SelectiveFlowDetector ----

class _MockClassifier:
    """Classifier that always predicts the one class in its encoder."""
    def __init__(self, class_id=0):
        self.class_id = class_id

    def predict(self, X):
        return np.full(X.shape[0], self.class_id, dtype=int)

    def predict_proba(self, X):
        # Return 99.9% confidence on the predicted class
        proba = np.full((X.shape[0], 2), 0.001)
        proba[:, self.class_id] = 0.999
        return proba


class _MockPipeline:
    """Minimal pipeline with a passthrough scaler and a label encoder."""
    def __init__(self, feature_names, classes):
        self.feature_names = feature_names
        class _PassthroughScaler:
            def transform(self, X):
                return np.asarray(X, dtype=np.float64)
        class _LabelEncoder:
            def __init__(self, classes):
                self.classes_ = np.array(classes)
            def inverse_transform(self, y):
                return self.classes_[y]
            def transform(self, y):
                return np.searchsorted(self.classes_, y)
        self.scaler = _PassthroughScaler()
        self.label_encoder = _LabelEncoder(classes)


def test_selective_flow_detector_returns_unknown_for_outliers():
    """End-to-end: SelectiveFlowDetector should flag an OOD row as UNKNOWN
    even though the mock classifier is 99.9 %-confident on it."""
    # In-distribution features — 50 rows near the centroid
    X_train = np.random.default_rng(0).normal(0, 1, size=(100, 3))
    y_train = np.zeros(100, dtype=int)

    # Fit abstainer on the training distribution
    abstainer = MahalanobisAbstainer().fit(X_train, y_train)
    abstainer.tune_thresholds(X_train, y_train, y_train, target_coverage=0.99)

    pipeline = _MockPipeline(feature_names=["f1", "f2", "f3"], classes=["BENIGN", "Bot"])
    classifier = _MockClassifier(class_id=0)  # always predicts BENIGN
    detector = SelectiveFlowDetector(pipeline=pipeline, classifier=classifier,
                                      abstainer=abstainer)

    # Mix of in-distribution and far-away rows
    df = pd.DataFrame([
        {"f1": 0.1, "f2": 0.0, "f3": -0.1},  # in-distribution
        {"f1": 100.0, "f2": 100.0, "f3": 100.0},  # far OOD
        {"f1": 0.2, "f2": -0.5, "f3": 0.3},  # in-distribution
    ])
    out = detector.predict_with_abstention(df)

    assert len(out) == 3
    # OOD row must be abstained → label == UNKNOWN, abstained == True
    assert out.loc[1, "abstained"] is np.True_ or out.loc[1, "abstained"] is True
    assert out.loc[1, "label"] == ABSTAIN_LABEL
    assert out.loc[1, "raw_label"] == "BENIGN"

    # In-distribution rows must NOT be abstained
    for i in (0, 2):
        assert out.loc[i, "abstained"] is np.False_ or out.loc[i, "abstained"] is False
        assert out.loc[i, "label"] == "BENIGN"


def test_selective_flow_detector_empty_dataframe():
    """Edge case: empty input should produce empty output without errors."""
    X_train = np.random.default_rng(0).normal(0, 1, size=(50, 3))
    abstainer = MahalanobisAbstainer().fit(X_train, np.zeros(50, dtype=int))
    abstainer.tune_thresholds(X_train, np.zeros(50), np.zeros(50), 0.99)
    pipeline = _MockPipeline(["f1", "f2", "f3"], ["BENIGN"])
    detector = SelectiveFlowDetector(
        pipeline=pipeline, classifier=_MockClassifier(0), abstainer=abstainer,
    )
    out = detector.predict_with_abstention(pd.DataFrame())
    assert out.empty
    assert set(out.columns) == {
        "label", "raw_label", "abstained",
        "mahalanobis_distance", "tau", "confidence",
    }


def test_selective_flow_detector_fills_missing_features():
    """If input DataFrame is missing some feature columns, they must be
    zero-filled (same behavior as FlowDetector.predict)."""
    X_train = np.random.default_rng(0).normal(0, 1, size=(50, 3))
    abstainer = MahalanobisAbstainer().fit(X_train, np.zeros(50, dtype=int))
    abstainer.tune_thresholds(X_train, np.zeros(50), np.zeros(50), 0.99)
    pipeline = _MockPipeline(["f1", "f2", "f3"], ["BENIGN"])
    detector = SelectiveFlowDetector(
        pipeline=pipeline, classifier=_MockClassifier(0), abstainer=abstainer,
    )
    # Supply only f1; f2, f3 must be filled with 0
    df = pd.DataFrame([{"f1": 0.1}])
    out = detector.predict_with_abstention(df)
    assert len(out) == 1
    # (0.1, 0, 0) is near centroid, should not abstain
    assert not bool(out.loc[0, "abstained"])
