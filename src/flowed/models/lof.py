import pandas as pd
from sklearn.neighbors import LocalOutlierFactor

from .base import BaseModel

class LOFModel(BaseModel):
    """Local Outlier Factor (LOF) model for anomaly detection."""

    def __init__(self, config: dict):
        super().__init__(config)
        # LOF's fit_predict is what we need for unsupervised outlier detection
        self.model = LocalOutlierFactor(**self.config)

    def fit(self, features: pd.DataFrame):
        """
        For LOF, fitting is combined with prediction. 
        This method is here to satisfy the base class interface but the main logic is in predict.
        """
        self.logger.info("LOF is an unsupervised learner; fitting occurs during prediction.")
        # We can fit the model here, but it won't be used for transform, only for fit_predict
        self.model.fit(features)
        self.logger.info("Model fitting complete.")

    def predict(self, features: pd.DataFrame) -> pd.Series:
        """Predict anomalies using the LOF model."""
        if features.empty:
            self.logger.warning("Feature DataFrame is empty. Cannot perform detection.
")
            return pd.Series(dtype=int)

        self.logger.info(f"Performing anomaly detection with LOF on {len(features)} samples.")
        # For LOF, fit_predict is used for outlier detection
        predictions = self.model.fit_predict(features)
        return pd.Series(predictions, index=features.index)
