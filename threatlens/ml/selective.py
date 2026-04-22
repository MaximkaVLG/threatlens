"""Selective prediction via Mahalanobis distance to training distribution.

Day 7's diagnostic showed that the XGBoost model is uniformly confident
on *every* input — including real-world PCAPs where its F1 collapses.
Traditional softmax-threshold abstention (``refuse if max(proba) < 0.5``)
is inert on such a model. To flag out-of-distribution flows the system
has to look at *where* the flow lives in feature space, not just *how
confidently* the model labelled it.

Mahalanobis distance to the predicted class centroid — computed on
the scaled 78-feature vector — is the cheap, classic choice for this:

    d(x) = sqrt( (x - mu_c)^T Sigma^{-1} (x - mu_c) )

- ``mu_c`` is the class-conditional mean of the training features for
  class *c*.
- ``Sigma`` is the training feature covariance (pooled across classes
  by default — more stable when some classes have few samples, and in
  practice works well for tree-model feature spaces that have already
  been standardised).
- A small ridge is added to ``Sigma`` for invertibility.

A flow with large distance from its predicted class's centroid is
*in the wrong neighbourhood* of feature space — the classifier may
still be confident, but the input looks like nothing the training set
ever saw for that class. Abstain.

The per-class threshold ``tau_c`` is tuned on a validation split so
that a target fraction (default 99 %) of correctly-classified training
flows lie under it — i.e. we keep ~99 % of the model's correct
in-distribution predictions and abstain on the tail.

Designed to wrap an already-trained pipeline + classifier produced by
:mod:`threatlens.ml.train`. No retraining required.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

ABSTAIN_LABEL = "UNKNOWN"


@dataclass
class MahalanobisAbstainer:
    """Fits Mahalanobis parameters on scaled training features.

    Usage:
        m = MahalanobisAbstainer().fit(X_scaled, y_encoded, classes)
        tau = m.tune_thresholds(X_val_scaled, y_val_encoded, target_coverage=0.99)
        abstain_mask = m.should_abstain(X_scaled, y_pred_encoded)

    The ``classes`` argument is the list of integer-encoded class ids
    so we can store per-class means even for classes with few samples.
    """
    ridge: float = 1e-4
    use_pooled_covariance: bool = True

    # Learned parameters — populated by fit()
    class_means: Dict[int, np.ndarray] = field(default_factory=dict)
    inv_covariance: Optional[np.ndarray] = None  # shared or per-class if pooled=False
    inv_covariance_per_class: Dict[int, np.ndarray] = field(default_factory=dict)
    feature_dim: int = 0

    # Tuned per-class thresholds — populated by tune_thresholds()
    thresholds: Dict[int, float] = field(default_factory=dict)
    # Fallback threshold for classes that never appeared in the tuning set
    _global_fallback: float = float("inf")

    def fit(self, X: np.ndarray, y: np.ndarray,
            classes: Optional[List[int]] = None) -> "MahalanobisAbstainer":
        """Compute class-conditional means and (pooled) covariance.

        X must be *scaled* (StandardScaler output) — the same transform
        the classifier sees. Otherwise mu and Sigma won't match.
        """
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)
        self.feature_dim = X.shape[1]
        if classes is None:
            classes = sorted(set(y.tolist()))

        # Class means
        for c in classes:
            mask = (y == c)
            if mask.sum() == 0:
                continue
            self.class_means[int(c)] = X[mask].mean(axis=0)

        # Covariance
        if self.use_pooled_covariance:
            # Pool: subtract the per-class mean from each row, then take
            # the covariance of the residuals. This gives the same matrix
            # scikit-learn's LinearDiscriminantAnalysis uses.
            residuals = np.empty_like(X)
            for c, mu in self.class_means.items():
                mask = (y == c)
                residuals[mask] = X[mask] - mu
            sigma = np.cov(residuals, rowvar=False)
            sigma = sigma + self.ridge * np.eye(sigma.shape[0])
            self.inv_covariance = np.linalg.inv(sigma)
        else:
            for c, mu in self.class_means.items():
                mask = (y == c)
                if mask.sum() < self.feature_dim + 2:
                    # Too few samples for a stable per-class covariance;
                    # fall back to global covariance for this class.
                    continue
                sigma_c = np.cov(X[mask], rowvar=False)
                sigma_c = sigma_c + self.ridge * np.eye(sigma_c.shape[0])
                self.inv_covariance_per_class[int(c)] = np.linalg.inv(sigma_c)

            # Global fallback (pooled) for classes lacking per-class Σ
            residuals = np.empty_like(X)
            for c, mu in self.class_means.items():
                mask = (y == c)
                residuals[mask] = X[mask] - mu
            sigma = np.cov(residuals, rowvar=False) + self.ridge * np.eye(X.shape[1])
            self.inv_covariance = np.linalg.inv(sigma)

        logger.info(
            "MahalanobisAbstainer fitted: %d classes, %d features, ridge=%g, pooled=%s",
            len(self.class_means), self.feature_dim, self.ridge, self.use_pooled_covariance,
        )
        return self

    def distances(self, X: np.ndarray, y_pred: np.ndarray) -> np.ndarray:
        """Return Mahalanobis distance of each row to its predicted class mean."""
        X = np.asarray(X, dtype=np.float64)
        y_pred = np.asarray(y_pred)
        out = np.empty(len(X), dtype=np.float64)

        # Group by predicted class so we do one matmul per class.
        for c in np.unique(y_pred):
            mask = (y_pred == c)
            mu = self.class_means.get(int(c))
            if mu is None:
                out[mask] = np.inf  # unknown class (e.g., new label at inference)
                continue
            inv = (self.inv_covariance_per_class.get(int(c))
                   if not self.use_pooled_covariance else None)
            if inv is None:
                inv = self.inv_covariance
            diff = X[mask] - mu
            # Batch Mahalanobis: for each row d_i = sqrt(diff_i @ inv @ diff_i.T)
            # Using einsum to avoid constructing the full (n, n) product.
            d2 = np.einsum("ij,jk,ik->i", diff, inv, diff)
            # d2 can go slightly negative from numerical noise when x is
            # almost exactly on the centroid; clip.
            d2 = np.maximum(d2, 0.0)
            out[mask] = np.sqrt(d2)
        return out

    def tune_thresholds(self, X_val: np.ndarray, y_val: np.ndarray,
                        y_pred: np.ndarray,
                        target_coverage: float = 0.99) -> Dict[int, float]:
        """Pick per-class tau as the *target_coverage* percentile of
        distances from correctly-classified validation flows.

        Rationale: we want to *keep* the model's in-distribution
        correct predictions (don't abstain on things it reliably gets
        right) while flagging everything outside that envelope. Using
        only correct predictions for the threshold avoids biasing tau
        with the (usually near-centroid but occasionally far) wrong
        predictions.
        """
        assert 0 < target_coverage < 1
        X_val = np.asarray(X_val, dtype=np.float64)
        y_val = np.asarray(y_val)
        y_pred = np.asarray(y_pred)

        # Distances from each sample to its *predicted* class centroid
        dists = self.distances(X_val, y_pred)

        # Keep only rows where the prediction matched ground truth
        correct_mask = (y_pred == y_val)

        thresholds: Dict[int, float] = {}
        for c in sorted(set(y_pred.tolist())):
            sel = (y_pred == c) & correct_mask
            if sel.sum() < 20:
                # Too few correct-class-c examples to pick a stable percentile
                # -> fall back to the class mean + 3 stdev of pooled distance
                continue
            thresholds[int(c)] = float(np.quantile(dists[sel], target_coverage))

        # Global fallback: overall percentile across all correct predictions
        if correct_mask.sum() >= 20:
            self._global_fallback = float(np.quantile(dists[correct_mask], target_coverage))

        self.thresholds = thresholds
        logger.info(
            "Thresholds tuned at coverage=%.2f for %d classes; global fallback tau=%.3f",
            target_coverage, len(thresholds), self._global_fallback,
        )
        return thresholds

    def should_abstain(self, X: np.ndarray, y_pred: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Return (abstain_mask, distance_array).

        abstain_mask[i] == True means distance to predicted class centroid
        exceeded tau — caller should surface the flow as UNKNOWN.
        """
        dists = self.distances(X, y_pred)
        taus = np.empty(len(X), dtype=np.float64)
        for c in np.unique(y_pred):
            mask = (y_pred == c)
            taus[mask] = self.thresholds.get(int(c), self._global_fallback)
        return (dists > taus), dists

    # ---- Persistence ----
    def save(self, path: str) -> None:
        joblib.dump({
            "ridge": self.ridge,
            "use_pooled_covariance": self.use_pooled_covariance,
            "class_means": self.class_means,
            "inv_covariance": self.inv_covariance,
            "inv_covariance_per_class": self.inv_covariance_per_class,
            "feature_dim": self.feature_dim,
            "thresholds": self.thresholds,
            "_global_fallback": self._global_fallback,
        }, path)

    @classmethod
    def load(cls, path: str) -> "MahalanobisAbstainer":
        d = joblib.load(path)
        m = cls(ridge=d["ridge"], use_pooled_covariance=d["use_pooled_covariance"])
        m.class_means = d["class_means"]
        m.inv_covariance = d["inv_covariance"]
        m.inv_covariance_per_class = d["inv_covariance_per_class"]
        m.feature_dim = d["feature_dim"]
        m.thresholds = d["thresholds"]
        m._global_fallback = d["_global_fallback"]
        return m


@dataclass
class SelectiveFlowDetector:
    """Wraps a trained classifier + preprocessing pipeline with
    Mahalanobis-based abstention.

    predict_with_abstention(flows_df) returns a DataFrame with:
      - label: predicted class OR "UNKNOWN" if abstained
      - raw_label: what the classifier actually picked (always a real class)
      - abstained: bool
      - mahalanobis_distance: float
      - tau: float, the threshold that was applied
      - confidence: classifier's softmax max (informational, not used for gating)
    """
    pipeline: object  # FeaturePipeline from threatlens.ml.features
    classifier: object  # sklearn-compatible classifier with predict / predict_proba
    abstainer: MahalanobisAbstainer

    def predict_with_abstention(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        if flows_df.empty:
            return pd.DataFrame(columns=[
                "label", "raw_label", "abstained",
                "mahalanobis_distance", "tau", "confidence",
            ])

        # Ensure every expected column is present (zero-fill missing)
        expected = self.pipeline.feature_names
        X_raw = flows_df.copy()
        for c in expected:
            if c not in X_raw.columns:
                X_raw[c] = 0.0
        X = X_raw[expected].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        X_scaled = self.pipeline.scaler.transform(X.values)

        # Classify
        y_enc = self.classifier.predict(X_scaled)
        raw_labels = self.pipeline.label_encoder.inverse_transform(y_enc)

        if hasattr(self.classifier, "predict_proba"):
            proba = self.classifier.predict_proba(X_scaled)
            conf = proba[np.arange(len(y_enc)), y_enc]
        else:
            conf = np.full(len(y_enc), np.nan)

        abstain_mask, dists = self.abstainer.should_abstain(X_scaled, y_enc)

        taus = np.array([
            self.abstainer.thresholds.get(int(c), self.abstainer._global_fallback)
            for c in y_enc
        ])

        final_labels = np.where(abstain_mask, ABSTAIN_LABEL, raw_labels)

        return pd.DataFrame({
            "label": final_labels,
            "raw_label": raw_labels,
            "abstained": abstain_mask,
            "mahalanobis_distance": dists,
            "tau": taus,
            "confidence": conf,
        })
