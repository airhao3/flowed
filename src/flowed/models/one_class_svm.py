import pandas as pd
from sklearn.svm import OneClassSVM

from .base import BaseModel

class OneClassSVMModel(BaseModel):
    """One-Class SVM model for anomaly detection."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.model = OneClassSVM(**self.config)

    def fit(self, features: pd.DataFrame):
        """Train the One-Class SVM model."""
        self.logger.info(f"Training One-Class SVM model on {len(features)} samples.")
        self.model.fit(features)
        self.logger.info("Model training complete.")

    def predict(self, features: pd.DataFrame) -> pd.Series:
        """Predict anomalies using the trained One-Class SVM model."""
        if features.empty:
            self.logger.warning("Feature DataFrame is empty. Cannot perform detection.")
            return pd.Series(dtype=int)

        self.logger.info(f"Performing anomaly detection on {len(features)} samples.")
        predictions = self.model.predict(features)
        return pd.Series(predictions, index=features.index)
