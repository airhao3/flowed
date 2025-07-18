import json
import joblib
from pathlib import Path
from typing import Optional, Dict, Any

import pandas as pd
from loguru import logger
from sklearn.ensemble import IsolationForest


class ModelManager:
    """
    Manages the lifecycle of anomaly detection models, including creation, training,
    saving, loading, and inference.

    This class ensures a consistent structure for the model object, whether it is
    newly trained or loaded from disk.
    """

    def __init__(self, config: dict):
        """
        Initialize the model manager.

        Args:
            config: Global configuration dictionary.
        """
        self.config = config
        self.model_config = config.get('model', {})
        self.model_type = self.model_config.get('type')

        if not self.model_type:
            raise ValueError("Model type not specified in the configuration.")

        self.logger = logger.bind(module=__name__)
        self.model: Optional[Any] = None  # Initialize model as None
        self.logger.debug(f"Initialized ModelManager for model type: {self.model_type}")

    def _get_model_path(self, model_name: Optional[str] = None) -> Path:
        """Construct the path for saving/loading the model."""
        save_dir = Path(self.model_config.get('save_dir', 'data/models'))
        model_name = model_name or self.model_config.get('name', f"{self.model_type}_model")
        model_dir = save_dir / model_name
        model_dir.mkdir(parents=True, exist_ok=True)
        return model_dir

    def load_model(self, model_name: Optional[str] = None) -> bool:
        """
        Load a pre-trained model from disk.
        """
        model_dir = self._get_model_path(model_name)
        model_path = model_dir / 'model.joblib'
        features_path = model_dir / 'feature_names.json'

        if not model_path.exists() or not features_path.exists():
            self.logger.warning(f"Model file or feature names not found in {model_dir}. Cannot load model.")
            return False

        try:
            self.logger.info(f"Loading model from {model_path}...")
            loaded_model = joblib.load(model_path)

            with open(features_path, 'r') as f:
                feature_names = json.load(f)

            # Create the container for the loaded model
            self.model = type('ModelContainer', (), {})()
            self.model.model = loaded_model
            self.model.feature_names_in_ = feature_names

            self.logger.success(f"Successfully loaded model and {len(feature_names)} feature names.")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load model from {model_dir}: {e}", exc_info=True)
            self.model = None
            return False

    def train(self, features: pd.DataFrame):
        """Train a new model and save it."""
        self.logger.info(f"Starting training for {self.model_type} model...")
        self.logger.info(f"Training data shape: {features.shape}")

        model_instance = None
        try:
            # Create and train a new model instance
            model_params = self.model_config.get('params', {})
            model_instance = IsolationForest(**model_params)
            
            features_df = features.copy()
            
            # Select only numeric columns for training
            numeric_features_df = features_df.select_dtypes(include='number')
            self.logger.info(f"Selected {numeric_features_df.shape[1]} numeric features for training out of {features_df.shape[1]} total features.")

            # Identify and log dropped columns for debugging
            dropped_cols = set(features_df.columns) - set(numeric_features_df.columns)
            if dropped_cols:
                self.logger.warning(f"Dropping non-numeric columns from training data: {list(dropped_cols)}")

            feature_names = numeric_features_df.columns.tolist()
            model_instance.fit(numeric_features_df)
            self.logger.success(f"Successfully trained {self.model_type} model.")

            # Create a temporary container for saving
            model_to_save = type('ModelContainer', (), {})()
            model_to_save.model = model_instance
            model_to_save.feature_names_in_ = feature_names

            # Save the newly trained model
            if self.save_model(model_to_save):
                # If save is successful, assign the container to self.model
                self.model = model_to_save
                self.logger.info("Model is trained, saved, and ready for detection.")
            else:
                # If save fails, log a critical error and ensure model is None
                self.logger.error("Failed to save the newly trained model. The model will not be available.")
                self.model = None

        except Exception as e:
            self.logger.error(f"An error occurred during model training: {e}", exc_info=True)
            self.model = None
            raise  # Re-raise to ensure the error is not silenced

    def detect(self, features: Dict[str, Any]) -> Optional[float]:
        """Detect anomalies for a single session."""
        if not self.model or not hasattr(self.model, 'model'):
            self.logger.error("Model not available. Cannot perform detection.")
            return None

        try:
            model_features = self.model.feature_names_in_

            # Create a DataFrame from the feature vector with columns in the correct order
            ordered_features = {key: features.get(key, 0) for key in model_features}
            features_df = pd.DataFrame([ordered_features], columns=model_features)

            # Get the anomaly score from the underlying model
            # For IsolationForest, lower scores are more anomalous.
            anomaly_score = self.model.model.decision_function(features_df)

            return float(anomaly_score[0])

        except Exception as e:
            self.logger.error(f"An error occurred during detection: {e}", exc_info=True)
            return None

    def save_model(self, model_container: Any, model_name: Optional[str] = None) -> bool:
        """Save the provided model container to disk."""
        if not model_container or not hasattr(model_container, 'model'):
            self.logger.error("Invalid model container provided. Nothing to save.")
            return False

        try:
            model_dir = self._get_model_path(model_name)
            model_path = model_dir / 'model.joblib'
            features_path = model_dir / 'feature_names.json'

            self.logger.info(f"Saving model to {model_path}")
            joblib.dump(model_container.model, model_path)

            self.logger.info(f"Saving {len(model_container.feature_names_in_)} feature names to {features_path}")
            with open(features_path, 'w') as f:
                json.dump(model_container.feature_names_in_, f, indent=4)

            self.logger.success(f"Successfully saved model and feature names to {model_dir}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving model to {model_dir}: {e}", exc_info=True)
            raise  # Re-raise the exception to see the root cause
