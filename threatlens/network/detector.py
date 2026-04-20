"""Apply trained CIC-IDS2017 models to flows extracted from PCAP.

Loads the joblib artefacts produced by `threatlens.ml.train` and exposes a
simple API:

    detector = FlowDetector.from_results_dir("results/cicids2017")
    predictions = detector.predict(flows_df)

`predictions` is a DataFrame with one row per input flow, including the
predicted label, attack/benign flag, confidence, and the anomaly score from
the Isolation Forest branch (when available).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS
from threatlens.ml.shap_explainer import ShapExplainerCache

logger = logging.getLogger(__name__)


@dataclass
class DetectorArtefacts:
    feature_pipeline: object
    random_forest: object
    xgboost: object
    isolation_forest: object


class FlowDetector:
    """Apply supervised + unsupervised models to flow feature rows."""

    PRIMARY_MODEL = "xgboost"  # highest F1 in our benchmarks

    def __init__(self, artefacts: DetectorArtefacts):
        self._art = artefacts
        self._pipeline = artefacts.feature_pipeline
        self._models = {
            "random_forest": artefacts.random_forest,
            "xgboost": artefacts.xgboost,
        }
        self._isolation = artefacts.isolation_forest
        self._label_encoder = self._pipeline.label_encoder
        self._shap_cache = ShapExplainerCache(
            models=self._models,
            feature_names=self._pipeline.feature_names,
            label_encoder=self._label_encoder,
        )

    @classmethod
    def from_results_dir(cls, results_dir: str) -> "FlowDetector":
        """Load all model artefacts from a directory produced by `train.py`."""
        def _load(name: str):
            path = os.path.join(results_dir, name)
            if not os.path.exists(path):
                raise FileNotFoundError(f"Missing model artefact: {path}")
            return joblib.load(path)

        art = DetectorArtefacts(
            feature_pipeline=_load("feature_pipeline.joblib"),
            random_forest=_load("random_forest.joblib"),
            xgboost=_load("xgboost.joblib"),
            isolation_forest=_load("isolation_forest.joblib"),
        )
        return cls(art)

    def predict(
        self,
        flows_df: pd.DataFrame,
        model: Optional[str] = None,
    ) -> pd.DataFrame:
        """Predict attack labels for each flow.

        Args:
            flows_df: DataFrame with (at minimum) the 70 CIC-IDS2017 feature
                columns. Extra columns (5-tuple metadata) are preserved.
            model: "random_forest" or "xgboost"; defaults to XGBoost.

        Returns:
            DataFrame with one row per input flow and columns:
                label, is_attack, confidence, anomaly_score, anomaly_flag
            plus any metadata columns from the input (src_ip, dst_ip, ...).
        """
        if flows_df.empty:
            return flows_df.copy()

        model_name = model or self.PRIMARY_MODEL
        if model_name not in self._models:
            raise ValueError(
                f"Unknown model {model_name!r}. Available: {list(self._models)}"
            )

        # Ensure all expected feature columns exist; fill missing with zeros.
        X_raw = flows_df.copy()
        for col in CIC_FEATURE_COLUMNS:
            if col not in X_raw.columns:
                X_raw[col] = 0.0

        # Transform via the training-time preprocessing pipeline.
        X_features = X_raw[self._pipeline.feature_names]
        X_scaled, _ = self._pipeline.transform(X_features)

        clf = self._models[model_name]
        y_pred_encoded = clf.predict(X_scaled)
        labels = self._label_encoder.inverse_transform(y_pred_encoded)

        # Per-class probability -> confidence = prob of predicted class
        if hasattr(clf, "predict_proba"):
            probs = clf.predict_proba(X_scaled)
            confidence = probs[np.arange(len(y_pred_encoded)), y_pred_encoded]
        else:
            confidence = np.full(len(y_pred_encoded), np.nan)

        # Unsupervised branch: Isolation Forest for 0-day-style anomalies
        iso_raw = self._isolation.predict(X_scaled)  # -1 anomaly / +1 inlier
        anomaly_flag = (iso_raw == -1).astype(int)
        # decision_function returns higher = more normal; flip for intuitive score
        anomaly_score = -self._isolation.decision_function(X_scaled)

        is_attack = np.array([lbl != "BENIGN" for lbl in labels], dtype=int)

        out = pd.DataFrame({
            "label": labels,
            "is_attack": is_attack,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "anomaly_flag": anomaly_flag,
        })

        meta_cols = [c for c in ("src_ip", "dst_ip", "src_port", "protocol", "timestamp")
                     if c in flows_df.columns]
        if meta_cols:
            out = pd.concat([flows_df[meta_cols].reset_index(drop=True), out], axis=1)

        # Also carry over the destination port for readability
        if "Destination Port" in flows_df.columns:
            insert_idx = len([c for c in meta_cols if c != "timestamp"]) if meta_cols else 0
            out.insert(
                insert_idx,
                "dst_port",
                flows_df["Destination Port"].astype(int).values,
            )

        # Preserve the raw 70 CIC-IDS2017 feature values so downstream
        # endpoints (SHAP, LLM explanation) can reuse them without the client
        # having to round-trip the PCAP again.
        feature_cols = [c for c in CIC_FEATURE_COLUMNS if c in flows_df.columns]
        if feature_cols:
            out = pd.concat(
                [out, flows_df[feature_cols].reset_index(drop=True)],
                axis=1,
            )

        return out

    def explain_shap(
        self,
        flow: Dict[str, object],
        model: Optional[str] = None,
        top_k: int = 10,
    ) -> dict:
        """Compute SHAP feature attributions for a single flow.

        Args:
            flow: dict with at least the 70 CIC-IDS2017 feature columns.
            model: "random_forest" or "xgboost"; defaults to XGBoost.
            top_k: how many features to return, ranked by |SHAP|.
        """
        model_name = model or self.PRIMARY_MODEL
        if model_name not in self._models:
            raise ValueError(
                f"Unknown model {model_name!r}. Available: {list(self._models)}"
            )
        top_k = max(1, min(int(top_k), 30))

        # Build a single-row DataFrame with all expected feature columns.
        row = {c: flow.get(c, 0.0) for c in CIC_FEATURE_COLUMNS}
        X_raw = pd.DataFrame([row])[self._pipeline.feature_names]
        X_scaled, _ = self._pipeline.transform(X_raw)

        clf = self._models[model_name]
        predicted_idx = int(clf.predict(X_scaled)[0])

        explainer = self._shap_cache.get(model_name)
        explanation = explainer.explain(
            X_scaled_row=X_scaled[0],
            X_raw_row=X_raw.iloc[0].values.astype(float),
            predicted_class_idx=predicted_idx,
            top_k=top_k,
            model_name=model_name,
        )
        return explanation.as_dict()

    def summary(self, predictions: pd.DataFrame) -> Dict[str, object]:
        """Aggregate detection results into a summary suitable for UI display."""
        if predictions.empty:
            return {
                "total_flows": 0,
                "attack_flows": 0,
                "benign_flows": 0,
                "anomaly_flows": 0,
                "labels": {},
                "top_talkers": [],
                "protocols": {},
                "timeline": [],
            }

        label_counts = predictions["label"].value_counts().to_dict()
        attack_flows = int(predictions["is_attack"].sum())
        anomaly_flows = int(predictions.get("anomaly_flag", pd.Series(dtype=int)).sum())

        top_talkers: List[Dict[str, object]] = []
        if "src_ip" in predictions.columns:
            grouped = (
                predictions.assign(_n=1)
                .groupby("src_ip")
                .agg(flows=("_n", "sum"), attacks=("is_attack", "sum"))
                .sort_values("flows", ascending=False)
                .head(10)
                .reset_index()
            )
            top_talkers = grouped.to_dict(orient="records")

        proto_counts: Dict[str, int] = {}
        if "protocol" in predictions.columns:
            proto_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
            for proto, n in predictions["protocol"].value_counts().items():
                proto_counts[proto_names.get(int(proto), f"IP {int(proto)}")] = int(n)

        timeline = _build_timeline(predictions)

        return {
            "total_flows": int(len(predictions)),
            "attack_flows": attack_flows,
            "benign_flows": int(len(predictions) - attack_flows),
            "anomaly_flows": anomaly_flows,
            "labels": {str(k): int(v) for k, v in label_counts.items()},
            "top_talkers": top_talkers,
            "protocols": proto_counts,
            "timeline": timeline,
        }


def _build_timeline(predictions: pd.DataFrame, max_buckets: int = 60) -> List[Dict[str, object]]:
    """Bucket flows by start time into up to `max_buckets` equal-width windows.

    Returns a list of {bucket, timestamp, benign, attack} dicts so the UI can
    render a stacked bar / line chart without doing the bucketing itself.
    """
    if "timestamp" not in predictions.columns:
        return []

    ts = predictions["timestamp"].astype(float)
    ts = ts[ts > 0]
    if ts.empty:
        return []

    t_min = float(ts.min())
    t_max = float(ts.max())
    span = max(t_max - t_min, 1.0)
    bucket_size = max(span / max_buckets, 1.0)  # at least 1 second per bucket
    n_buckets = int(np.ceil(span / bucket_size)) + 1

    buckets = np.zeros((n_buckets, 2), dtype=int)  # columns: benign, attack
    for ts_val, is_attack in zip(ts, predictions.loc[ts.index, "is_attack"]):
        idx = int((ts_val - t_min) / bucket_size)
        if 0 <= idx < n_buckets:
            buckets[idx, 1 if is_attack else 0] += 1

    return [
        {
            "bucket": i,
            "timestamp": t_min + i * bucket_size,
            "benign": int(buckets[i, 0]),
            "attack": int(buckets[i, 1]),
        }
        for i in range(n_buckets)
    ]
