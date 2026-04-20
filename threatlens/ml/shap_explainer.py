"""SHAP-based per-flow explanations for the network intrusion detector.

Wraps `shap.TreeExplainer` around XGBoost / RandomForest classifiers from
`threatlens.ml.models`. For a single flow, produces the top-K features that
pushed the model toward (positive SHAP) or away from (negative SHAP) the
predicted class.

Design:
    - Explainer construction is expensive — cache one per (model_name) pair.
    - `TreeExplainer` is exact and fast for tree ensembles; no background
      dataset needed.
    - For multi-class outputs we pick the column corresponding to the
      predicted class only. A complete attribution over all 14 classes is
      possible but not useful in a diploma-level UI.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FeatureContribution:
    feature: str
    shap_value: float
    feature_value: float  # the raw (unscaled) feature value used as input


@dataclass
class ShapExplanation:
    model: str
    predicted_class: str
    base_value: float
    contributions: List[FeatureContribution]

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "predicted_class": self.predicted_class,
            "base_value": self.base_value,
            "contributions": [c.__dict__ for c in self.contributions],
        }


class ShapExplainer:
    """Lazy wrapper around shap.TreeExplainer for one sklearn/xgboost model."""

    def __init__(self, model, feature_names: List[str], label_encoder):
        import shap  # heavy import — defer to construction time only

        self._explainer = shap.TreeExplainer(model)
        self._feature_names = list(feature_names)
        self._label_encoder = label_encoder

    def explain(
        self,
        X_scaled_row: np.ndarray,
        X_raw_row: np.ndarray,
        predicted_class_idx: int,
        top_k: int = 10,
        model_name: str = "xgboost",
    ) -> ShapExplanation:
        """Compute SHAP attributions for one row.

        Args:
            X_scaled_row: 1D array (n_features,) — scaled input the model saw.
            X_raw_row: 1D array (n_features,) — original unscaled values,
                surfaced to the UI for readability.
            predicted_class_idx: integer index of the predicted class.
            top_k: how many features to return, ranked by |SHAP|.
            model_name: string passed through to the output metadata.
        """
        sv = self._explainer(X_scaled_row.reshape(1, -1))
        # sv.values: (1, n_features) for binary; (1, n_features, n_classes) for multi-class.
        values = sv.values[0]
        base = sv.base_values[0] if hasattr(sv, "base_values") else 0.0

        if values.ndim == 2:
            per_feat = values[:, predicted_class_idx]
            base_val = (
                float(base[predicted_class_idx])
                if hasattr(base, "__len__")
                else float(base)
            )
        else:
            per_feat = values
            base_val = float(base) if not hasattr(base, "__len__") else float(base[0])

        # Rank by absolute contribution so the most influential features come first.
        order = np.argsort(-np.abs(per_feat))[:top_k]

        contributions = [
            FeatureContribution(
                feature=self._feature_names[i],
                shap_value=float(per_feat[i]),
                feature_value=float(X_raw_row[i]),
            )
            for i in order
        ]
        predicted_class = str(
            self._label_encoder.inverse_transform([predicted_class_idx])[0]
        )
        return ShapExplanation(
            model=model_name,
            predicted_class=predicted_class,
            base_value=base_val,
            contributions=contributions,
        )


class ShapExplainerCache:
    """Hold one ShapExplainer per model. Constructed lazily on first request."""

    def __init__(self, models: Dict[str, object], feature_names: List[str], label_encoder):
        self._models = models
        self._feature_names = feature_names
        self._label_encoder = label_encoder
        self._cached: Dict[str, ShapExplainer] = {}

    def get(self, model_name: str) -> ShapExplainer:
        if model_name not in self._cached:
            if model_name not in self._models:
                raise KeyError(f"Unknown model {model_name!r}")
            logger.info("Building SHAP TreeExplainer for %s", model_name)
            self._cached[model_name] = ShapExplainer(
                self._models[model_name],
                self._feature_names,
                self._label_encoder,
            )
        return self._cached[model_name]
