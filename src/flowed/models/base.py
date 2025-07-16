from abc import ABC, abstractmethod
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

import pandas as pd
import joblib
from loguru import logger

class BaseModel(ABC):
    """
    Abstract base class for all anomaly detection models.
    
    This class defines the interface that all model implementations must follow,
    including methods for training, prediction, and model persistence.
    """

    def __init__(self, config: dict):
        """
        Initialize the model with its configuration.
        
        Args:
            config: Dictionary containing model configuration parameters
        """
        self.config = config.get('params', {})
        self.model_name = config.get('name', config.get('type', 'unknown'))
        self.model = None
        self.logger = logger.bind(module=self.__class__.__name__)
        self.training_metrics: Dict[str, Any] = {}
        self.feature_importances_: Optional[pd.Series] = None

    @abstractmethod
    def fit(self, features: pd.DataFrame):
        """
        Train the model on the given features.
        
        Args:
            features: DataFrame containing the training features
        """
        pass

    @abstractmethod
    def predict(self, features: pd.DataFrame) -> pd.Series:
        """
        Make predictions on the given features.
        
        Args:
            features: DataFrame containing the input features
            
        Returns:
            pd.Series: Predicted values or anomaly scores
        """
        pass

    def save(self, path: Union[str, Path]) -> bool:
        """
        Save the trained model and its metadata to disk.
        
        Args:
            path: Path where the model should be saved
            
        Returns:
            bool: True if the model was saved successfully, False otherwise
        """
        if not self.model:
            self.logger.warning("Model is not trained. Nothing to save.")
            return False
            
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save the model
            self.logger.info(f"Saving model to {path}")
            joblib.dump(self.model, path)
            
            # Save training metrics if available
            if hasattr(self, 'training_metrics') and self.training_metrics:
                metrics_path = path.parent / 'training_metrics.json'
                with open(metrics_path, 'w') as f:
                    json.dump(self.training_metrics, f, indent=2)
            
            # Save feature importances if available
            if hasattr(self, 'feature_importances_') and self.feature_importances_ is not None:
                importances_path = path.parent / 'feature_importances.csv'
                self.feature_importances_.to_frame('importance').to_csv(importances_path)
            
            # Save metadata
            metadata = {
                'model_type': self.__class__.__name__,
                'model_name': self.model_name,
                'created_at': datetime.utcnow().isoformat(),
                'num_features': len(self.training_metrics.get('feature_names', [])) if self.training_metrics else 0,
                'training_date': self.training_metrics.get('training_date', '') if self.training_metrics else '',
                'model_parameters': self.config
            }
            
            metadata_path = path.parent / 'metadata.yaml'
            with open(metadata_path, 'w') as f:
                yaml.safe_dump(metadata, f, default_flow_style=False)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}", exc_info=True)
            return False

    def load(self, path: Union[str, Path]) -> bool:
        """
        Load a model and its metadata from disk.
        
        Args:
            path: Path to the model file or directory
            
        Returns:
            bool: True if the model was loaded successfully, False otherwise
        """
        path = Path(path)
        
        # If path is a directory, look for model files inside it
        if path.is_dir():
            model_files = list(path.glob('*.joblib'))
            if not model_files:
                self.logger.error(f"No model files found in {path}")
                return False
            path = model_files[0]  # Use the first .joblib file found
        
        if not path.exists():
            self.logger.error(f"Model file does not exist: {path}")
            return False
            
        try:
            self.logger.info(f"Loading model from {path}")
            self.model = joblib.load(path)
            
            # Try to load training metrics if available
            metrics_path = path.parent / 'training_metrics.json'
            if metrics_path.exists():
                with open(metrics_path, 'r') as f:
                    self.training_metrics = json.load(f)
            
            # Try to load feature importances if available
            importances_path = path.parent / 'feature_importances.csv'
            if importances_path.exists():
                self.feature_importances_ = pd.read_csv(importances_path, index_col=0)['importance']
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model from {path}: {e}", exc_info=True)
            return False
