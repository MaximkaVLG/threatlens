"""Feature engineering for network flow data.

Pipeline:
    1. Handle NaN/inf (replace with 0 or median)
    2. Remove zero-variance columns
    3. Standardize (StandardScaler) — needed for Isolation Forest
    4. Encode string labels to integers
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import VarianceThreshold

logger = logging.getLogger(__name__)


@dataclass
class FeaturePipeline:
    """Reusable preprocessing pipeline.

    Fit on training data, then transform test data with the same parameters.
    """
    scaler: StandardScaler = field(default_factory=StandardScaler)
    label_encoder: LabelEncoder = field(default_factory=LabelEncoder)
    variance_selector: VarianceThreshold = field(default_factory=lambda: VarianceThreshold(threshold=0.0))
    feature_names: list = field(default_factory=list)
    fitted: bool = False

    def fit_transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None):
        """Fit on X (and optionally y) and return transformed X, y."""
        # Replace inf and NaN
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Remove zero-variance columns
        X_var = self.variance_selector.fit_transform(X)
        kept_cols = X.columns[self.variance_selector.get_support()].tolist()
        self.feature_names = kept_cols
        logger.info("Kept %d/%d features after variance filtering", len(kept_cols), X.shape[1])

        # Standardize
        X_scaled = self.scaler.fit_transform(X_var)

        # Encode labels if provided
        y_encoded = None
        if y is not None:
            y_encoded = self.label_encoder.fit_transform(y.astype(str))
            logger.info("Classes: %s", list(self.label_encoder.classes_))

        self.fitted = True
        return X_scaled, y_encoded

    def transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None):
        """Transform using already-fitted params."""
        if not self.fitted:
            raise RuntimeError("Pipeline not fitted. Call fit_transform first.")

        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
        # Keep only the columns the pipeline knows about
        X = X[self.feature_names]
        # Pass numpy array to scaler — it was fitted without feature names
        X_scaled = self.scaler.transform(X.values)

        y_encoded = None
        if y is not None:
            # Handle unseen labels gracefully
            known = set(self.label_encoder.classes_)
            y_clean = y.astype(str).apply(lambda v: v if v in known else self.label_encoder.classes_[0])
            y_encoded = self.label_encoder.transform(y_clean)

        return X_scaled, y_encoded

    def inverse_transform_labels(self, y_encoded):
        """Convert predicted integer labels back to strings."""
        return self.label_encoder.inverse_transform(y_encoded)


def preprocess(X: pd.DataFrame, y: pd.Series):
    """One-shot preprocessing. Returns (X_processed, y_encoded, pipeline)."""
    pipeline = FeaturePipeline()
    X_proc, y_proc = pipeline.fit_transform(X, y)
    return X_proc, y_proc, pipeline
