"""Apply trained models to flows extracted from PCAP.

Loads the joblib artefacts produced by `threatlens.ml.train` (or the
Day 9e python-only retrain pipeline) and exposes a simple API:

    detector = FlowDetector.from_results_dir("results/python_only")
    predictions = detector.predict(flows_df)

`predictions` is a DataFrame with one row per input flow, including the
predicted label, attack/benign flag, confidence, an anomaly score from
the Isolation Forest branch (when available) and an `is_uncertain`
flag from the optional Mahalanobis abstainer.

Artefact discovery is best-effort: only `xgboost.joblib` and
`feature_pipeline.joblib` are required. `random_forest.joblib`,
`isolation_forest.joblib`, and `mahalanobis_abstainer.joblib` are
loaded if present, otherwise their corresponding output columns are
filled with safe defaults (no anomaly flag / no abstention).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from threatlens.network.flow_extractor import CIC_FEATURE_COLUMNS
from threatlens.ml.shap_explainer import ShapExplainerCache

logger = logging.getLogger(__name__)

# Label surfaced when the Mahalanobis abstainer flags a prediction as
# out-of-distribution. Kept distinct from the model's own labels so the UI
# can colour it neutrally (yellow / "review needed") rather than treating
# it as either BENIGN or ATTACK.
UNCERTAIN_LABEL = "UNCERTAIN"


@dataclass
class DetectorArtefacts:
    feature_pipeline: object
    xgboost: object
    random_forest: Optional[object] = None
    isolation_forest: Optional[object] = None
    mahalanobis_abstainer: Optional[object] = None
    source_dir: Optional[str] = None


class FlowDetector:
    """Apply supervised + unsupervised models to flow feature rows."""

    PRIMARY_MODEL = "xgboost"  # highest F1 in our benchmarks

    def __init__(self, artefacts: DetectorArtefacts,
                 strict_abstention: bool = False):
        """
        Args:
            artefacts: bundle of joblib-loaded models + pipeline.
            strict_abstention: if True and an abstainer is available, the
                ``label`` column is rewritten to ``UNCERTAIN`` for flows the
                abstainer flags. Otherwise the original prediction is kept
                and ``is_uncertain=1`` simply marks it for the UI to colour
                differently.
        """
        self._art = artefacts
        self._pipeline = artefacts.feature_pipeline
        self._models = {"xgboost": artefacts.xgboost}
        if artefacts.random_forest is not None:
            self._models["random_forest"] = artefacts.random_forest
        self._isolation = artefacts.isolation_forest
        self._abstainer = artefacts.mahalanobis_abstainer
        self._strict_abstention = bool(strict_abstention)
        self._label_encoder = self._pipeline.label_encoder
        self._shap_cache = ShapExplainerCache(
            models=self._models,
            feature_names=self._pipeline.feature_names,
            label_encoder=self._label_encoder,
        )
        logger.info(
            "FlowDetector ready: models=%s, isolation=%s, abstainer=%s, "
            "strict=%s, n_features=%d, n_classes=%d",
            list(self._models.keys()),
            "yes" if self._isolation is not None else "no",
            "yes" if self._abstainer is not None else "no",
            self._strict_abstention,
            len(self._pipeline.feature_names),
            len(self._label_encoder.classes_),
        )

    @property
    def available_models(self) -> List[str]:
        """Names of supervised classifiers actually loaded (e.g. ['xgboost'])."""
        return sorted(self._models.keys())

    @property
    def has_abstainer(self) -> bool:
        return self._abstainer is not None

    @classmethod
    def from_results_dir(cls, results_dir: str,
                          strict_abstention: bool = False) -> "FlowDetector":
        """Load model artefacts from a results directory.

        Required files:
          - ``feature_pipeline.joblib``
          - ``xgboost.joblib``

        Optional files (loaded if present, skipped silently otherwise):
          - ``random_forest.joblib``
          - ``isolation_forest.joblib``
          - ``mahalanobis_abstainer.joblib``
        """
        def _required(name: str):
            path = os.path.join(results_dir, name)
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Missing required model artefact: {path}")
            return joblib.load(path)

        def _optional(name: str):
            path = os.path.join(results_dir, name)
            if not os.path.exists(path):
                logger.info("optional artefact not found: %s", path)
                return None
            try:
                return joblib.load(path)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("failed to load optional artefact %s: %s",
                               path, exc)
                return None

        art = DetectorArtefacts(
            feature_pipeline=_required("feature_pipeline.joblib"),
            xgboost=_required("xgboost.joblib"),
            random_forest=_optional("random_forest.joblib"),
            isolation_forest=_optional("isolation_forest.joblib"),
            mahalanobis_abstainer=_optional("mahalanobis_abstainer.joblib"),
            source_dir=os.path.abspath(results_dir),
        )
        return cls(art, strict_abstention=strict_abstention)

    def predict(
        self,
        flows_df: pd.DataFrame,
        model: Optional[str] = None,
    ) -> pd.DataFrame:
        """Predict attack labels for each flow.

        Args:
            flows_df: DataFrame with the feature columns the loaded pipeline
                expects (CIC-2017 base + spectral + YARA on the python_only
                model). Missing columns are filled with zeros — but the model
                will degrade if the YARA / spectral features are completely
                absent for a flow that needs them.
            model: ``"xgboost"`` (and ``"random_forest"`` if RF was loaded);
                defaults to XGBoost.

        Returns:
            DataFrame with one row per input flow, columns:
                label, is_attack, confidence,
                anomaly_score, anomaly_flag,                 # 0/safe defaults if no IsolationForest
                is_uncertain, distance_to_centroid           # 0/safe defaults if no abstainer
            plus any metadata columns from the input (src_ip, dst_ip, ...).
        """
        if flows_df.empty:
            return flows_df.copy()

        model_name = model or self.PRIMARY_MODEL
        if model_name not in self._models:
            raise ValueError(
                f"Unknown model {model_name!r}. "
                f"Available: {list(self._models)}"
            )

        # Source-of-truth for which columns to feed the model is the
        # pipeline's feature_names (set at training time). The legacy
        # CIC_FEATURE_COLUMNS list only covers the 70 base features and
        # would silently drop spectral + YARA features needed by the
        # python_only model.
        expected_cols = list(self._pipeline.feature_names)

        X_raw = flows_df.copy()
        for col in expected_cols:
            if col not in X_raw.columns:
                X_raw[col] = 0.0

        X_features = X_raw[expected_cols]
        # Pipeline.transform() handles inf/NaN scrubbing internally and
        # accepts y=None at inference time.
        X_scaled, _ = self._pipeline.transform(X_features)

        clf = self._models[model_name]
        y_pred_encoded = clf.predict(X_scaled)
        labels = self._label_encoder.inverse_transform(y_pred_encoded)

        # Per-class probability -> confidence = prob of predicted class
        if hasattr(clf, "predict_proba"):
            probs = clf.predict_proba(X_scaled)
            confidence = probs[
                np.arange(len(y_pred_encoded)), y_pred_encoded]
        else:
            confidence = np.full(len(y_pred_encoded), np.nan)

        # Unsupervised branch: Isolation Forest (legacy combined_v2 only).
        # python_only ships without one — fill safe defaults.
        if self._isolation is not None:
            iso_raw = self._isolation.predict(X_scaled)  # -1=anom, +1=inlier
            anomaly_flag = (iso_raw == -1).astype(int)
            anomaly_score = -self._isolation.decision_function(X_scaled)
        else:
            anomaly_flag = np.zeros(len(y_pred_encoded), dtype=int)
            anomaly_score = np.zeros(len(y_pred_encoded), dtype=float)

        # Mahalanobis abstention layer (Day 8/9 selective prediction).
        # Surfaced regardless of strict_abstention so the UI can show a
        # subtle "review needed" hint; only the LABEL is rewritten when
        # strict_abstention=True.
        if self._abstainer is not None:
            try:
                abstain_mask, distances = self._abstainer.should_abstain(
                    X_scaled, y_pred_encoded)
                is_uncertain = abstain_mask.astype(int)
                distance_to_centroid = distances.astype(float)
                if self._strict_abstention:
                    labels = np.where(abstain_mask, UNCERTAIN_LABEL, labels)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "abstainer.should_abstain failed: %s — falling back to "
                    "no abstention", exc)
                is_uncertain = np.zeros(len(y_pred_encoded), dtype=int)
                distance_to_centroid = np.zeros(len(y_pred_encoded),
                                                  dtype=float)
        else:
            is_uncertain = np.zeros(len(y_pred_encoded), dtype=int)
            distance_to_centroid = np.zeros(len(y_pred_encoded), dtype=float)

        is_attack = np.array(
            [lbl not in ("BENIGN", UNCERTAIN_LABEL) for lbl in labels],
            dtype=int)

        out = pd.DataFrame({
            "label": labels,
            "is_attack": is_attack,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "anomaly_flag": anomaly_flag,
            "is_uncertain": is_uncertain,
            "distance_to_centroid": distance_to_centroid,
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

        # Preserve the raw feature values so downstream endpoints (SHAP,
        # LLM explanation) can reuse them without the client having to
        # round-trip the PCAP again. Use pipeline.feature_names so we
        # carry through spectral / YARA columns on the python_only model.
        feature_cols = [c for c in self._pipeline.feature_names
                        if c in flows_df.columns]
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

        # Build a single-row DataFrame using the pipeline's actual feature
        # names — covers CIC base + spectral + YARA on python_only.
        row = {c: flow.get(c, 0.0) for c in self._pipeline.feature_names}
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
                "uncertain_flows": 0,
                "labels": {},
                "top_talkers": [],
                "protocols": {},
                "timeline": [],
                "model_info": self.model_info(),
            }

        label_counts = predictions["label"].value_counts().to_dict()
        attack_flows = int(predictions["is_attack"].sum())
        anomaly_flows = int(predictions.get(
            "anomaly_flag", pd.Series(dtype=int)).sum())
        uncertain_flows = int(predictions.get(
            "is_uncertain", pd.Series(dtype=int)).sum())

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

        # is_uncertain is an INDEPENDENT flag — a flow can be ATTACK and
        # UNCERTAIN at the same time (the abstainer just signals "the
        # model is on shaky ground for this prediction"). So count
        # benign by label, not by subtraction.
        benign_flows = int(
            (predictions["label"] == "BENIGN").sum()
            if "label" in predictions.columns else 0)
        return {
            "total_flows": int(len(predictions)),
            "attack_flows": attack_flows,
            "benign_flows": benign_flows,
            "anomaly_flows": anomaly_flows,
            "uncertain_flows": uncertain_flows,
            "labels": {str(k): int(v) for k, v in label_counts.items()},
            "top_talkers": top_talkers,
            "protocols": proto_counts,
            "timeline": timeline,
            "model_info": self.model_info(),
        }

    def model_info(self) -> Dict[str, object]:
        """Lightweight metadata describing the loaded detector — useful
        for the UI footer / debug overlay so users can see which model
        version produced a prediction."""
        return {
            "source_dir": (os.path.basename(self._art.source_dir)
                            if self._art.source_dir else None),
            "models": list(self._models.keys()),
            "primary_model": self.PRIMARY_MODEL,
            "n_features": int(len(self._pipeline.feature_names)),
            "n_classes": int(len(self._label_encoder.classes_)),
            "classes": [str(c) for c in self._label_encoder.classes_],
            "has_isolation_forest": self._isolation is not None,
            "has_abstainer": self._abstainer is not None,
            "strict_abstention": self._strict_abstention,
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
