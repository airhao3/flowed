import importlib
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Union

import pandas as pd
from loguru import logger

from .base import BaseModel

def _snake_to_pascal(snake_case: str) -> str:
    """Convert snake_case_string to PascalCaseString."""
    return "".join(word.capitalize() for word in snake_case.split('_'))

class ModelManager:
    """
    Manages the lifecycle of anomaly detection models, including creation, training,
    saving, loading, and inference.
    
    This class serves as a high-level interface to different model implementations,
    handling the common operations while delegating model-specific logic to the
    individual model classes.
    """

    def __init__(self, config: dict):
        """
        Initialize the model manager with the provided configuration.

        Args:
            config: Global configuration dictionary containing model configuration
                  under the 'model' key.
                  
        Raises:
            ValueError: If the model type is not specified in the configuration.
        """
        self.config = config
        self.model_config = config.get('model', {})
        self.model_type = self.model_config.get('type')
        
        if not self.model_type:
            raise ValueError("Model type not specified in the configuration.")

        self.logger = logger.bind(module=__name__)
        self.logger.debug(f"Initializing ModelManager with model type: {self.model_type}")
        self.logger.debug(f"Model configuration: {self.model_config}")
        
        # Initialize the model instance
        self.model: Optional[BaseModel] = self._create_model_instance()
        self.logger.info(f"Successfully initialized {self.model_type} model")

    def _get_model_path(self, model_name: Optional[str] = None) -> Path:
        """
        Construct the path for saving/loading the model.
        
        Args:
            model_name: Optional custom model name. If not provided, uses the name from config.
            
        Returns:
            Path: Path to the model directory
        """
        save_dir = Path(self.model_config.get('save_dir', 'data/models'))
        model_name = model_name or self.model_config.get('name', f"{self.model_type}_model")
        model_dir = save_dir / model_name
        
        # Ensure the save directory exists
        model_dir.mkdir(parents=True, exist_ok=True)
        self.logger.debug(f"Using model directory: {model_dir}")
        
        return model_dir

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about the current model.
        
        Returns:
            dict: A dictionary containing model information, including:
                - Basic model info (type, name, class)
                - Model parameters
                - Training metrics and statistics
                - Feature importances (if available)
                - Model metadata (if available)
        """
        if not self.model:
            return {
                'status': 'error',
                'message': 'No model loaded or initialized',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        try:
            # Basic model information
            info = {
                'model_type': self.model_type,
                'model_name': self.model_config.get('name', f"{self.model_type}_model"),
                'model_class': self.model.__class__.__name__,
                'parameters': self.model_config.get('params', {}),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Add model metadata if available
            if hasattr(self.model, 'model') and self.model.model is not None:
                info['model_attributes'] = {
                    'n_features_in_': getattr(self.model.model, 'n_features_in_', None),
                    'offset_': float(getattr(self.model.model, 'offset_', 0.0)),
                    'contamination': getattr(self.model.model, 'contamination', None),
                    'n_estimators': getattr(self.model.model, 'n_estimators', None)
                }
            
            # Add training metrics if available
            if hasattr(self.model, 'training_metrics') and self.model.training_metrics:
                info['training_metrics'] = self.model.training_metrics
                
                # Add a summary of training metrics for easier access
                if 'performance_metrics' in self.model.training_metrics:
                    perf_metrics = self.model.training_metrics['performance_metrics']
                    if 'anomaly_score_stats' in perf_metrics:
                        stats = perf_metrics['anomaly_score_stats']
                        info['training_summary'] = {
                            'samples_trained': self.model.training_metrics.get('data_stats', {}).get('num_samples', 0),
                            'num_features': self.model.training_metrics.get('data_stats', {}).get('num_features', 0),
                            'anomaly_score_mean': stats.get('mean', 0),
                            'anomaly_score_std': stats.get('std', 0),
                            'training_time_seconds': self.model.training_metrics.get('training_time_seconds')
                        }
            
            # Add feature importances if available
            if hasattr(self.model, 'feature_importances_') and self.model.feature_importances_ is not None:
                importances = self.model.feature_importances_
                top_features = importances.sort_values(ascending=False).head(20)
                
                info['feature_analysis'] = {
                    'num_features': len(importances),
                    'top_features': top_features.to_dict(),
                    'importance_stats': {
                        'min': float(importances.min()),
                        'max': float(importances.max()),
                        'mean': float(importances.mean()),
                        'median': float(importances.median())
                    }
                }
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error getting model info: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'Error getting model info: {str(e)}',
                'timestamp': datetime.utcnow().isoformat()
            }

    def _create_model_instance(self) -> BaseModel:
        """
        Create an instance of the model based on the configuration.
        
        Returns:
            BaseModel: An instance of the requested model class.
            
        Raises:
            ValueError: If the model type is not supported or cannot be imported.
        """
        try:
            # Special case handling for models with non-standard naming
            model_class_mapping = {
                'lof': 'LOFModel',  # Local Outlier Factor
                'iforest': 'IsolationForestModel',  # Isolation Forest
                # Add other model mappings as needed
            }
            
            # Get the class name, using mapping or standard naming convention
            class_name = model_class_mapping.get(
                self.model_type.lower(),
                f"{_snake_to_pascal(self.model_type)}Model"
            )
            
            # Import the model module
            module_name = f"flowed.models.{self.model_type.lower()}"
            model_module = importlib.import_module(module_name)
            model_class = getattr(model_module, class_name)
            
            # Create and return the model instance
            instance = model_class(self.model_config)
            self.logger.info(f"Successfully created model instance: {class_name}")
            return instance
            
        except ImportError as e:
            self.logger.error(f"Could not import module for model type '{self.model_type}': {e}")
            raise ValueError(f"Unsupported model type: {self.model_type}") from e
            
        except AttributeError as e:
            self.logger.error(f"Model class not found in module: {e}")
            raise ValueError(f"Invalid model class for type: {self.model_type}") from e

    def load_model(self, model_path: Optional[Union[str, Path]] = None) -> bool:
        """
        Load a pre-trained model from disk, including its metadata and metrics.
        
        Args:
            model_path: Optional path to the model file or directory. If not provided,
                      uses the path from the model configuration.
                      
        Returns:
            bool: True if the model was loaded successfully, False otherwise
        """
        if not self.model:
            self.logger.error("Model not initialized, cannot load.")
            return False
            
        try:
            # If no specific path provided, use the configured path
            if model_path is None:
                model_dir = self._get_model_path()
                model_path = model_dir / 'model.joblib'
            else:
                model_path = Path(model_path)
                model_dir = model_path.parent if model_path.is_file() else model_path
            
            # If path is a directory, look for model files inside it
            if model_path.is_dir():
                joblib_files = list(model_path.glob('*.joblib'))
                if not joblib_files:
                    self.logger.error(f"No model files found in {model_path}")
                    return False
                model_path = joblib_files[0]
                self.logger.info(f"Found model file: {model_path}")
            
            # Check if model file exists
            if not model_path.exists():
                self.logger.error(f"Model file not found: {model_path}")
                return False
            
            # Load the model
            self.logger.info(f"Loading model from {model_path}")
            if not self.model.load(model_path):
                self.logger.error(f"Failed to load model from {model_path}")
                return False
            
            # Log model info
            model_info = self.get_model_info()
            self.logger.info(f"Successfully loaded model: {model_info.get('model_name', 'unknown')}")
            self.logger.info(f"Model type: {model_info.get('model_type', 'unknown')}")
            if 'training_metrics' in model_info:
                metrics = model_info['training_metrics']
                if 'data_stats' in metrics:
                    self.logger.info(
                        f"Trained on {metrics['data_stats'].get('num_samples', 0):,} samples with "
                        f"{metrics['data_stats'].get('num_features', 0)} features"
                    )
                if 'performance_metrics' in metrics and 'anomaly_score_stats' in metrics['performance_metrics']:
                    stats = metrics['performance_metrics']['anomaly_score_stats']
                    self.logger.info(
                        f"Anomaly scores - Mean: {stats.get('mean', 0):.4f} ± {stats.get('std', 0):.4f}"
                    )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}", exc_info=True)
            return False

    def train(self, features: pd.DataFrame):
        """Train the currently loaded model with validation."""
        if not self.model:
            self.logger.error("Model not loaded, cannot train.")
            return
            
        # Check minimum sample requirements
        min_samples = self.model_config.get('train', {}).get('min_samples', 1000)
        if len(features) < min_samples:
            self.logger.error(f"Insufficient training data: {len(features)} < {min_samples} required samples.")
            return
            
        self.logger.info(f"Starting model training with {len(features)} samples...")
        
        # Split data for validation if configured
        validation_split = self.model_config.get('train', {}).get('validation_split', 0.0)
        if validation_split > 0:
            from sklearn.model_selection import train_test_split
            train_features, val_features = train_test_split(
                features, 
                test_size=validation_split, 
                random_state=42
            )
            self.logger.info(f"Split data: {len(train_features)} training, {len(val_features)} validation")
            
            # Train on training set
            self.model.fit(train_features)
            
            # Validate on validation set
            val_scores = self.model.predict(val_features)
            anomaly_rate = (val_scores == -1).mean()
            self.logger.info(f"Validation anomaly rate: {anomaly_rate:.3f}")
            
            # Store validation metrics
            if hasattr(self.model, 'training_metrics'):
                self.model.training_metrics['validation'] = {
                    'anomaly_rate': float(anomaly_rate),
                    'validation_samples': len(val_features)
                }
        else:
            self.model.fit(features)
            
        self.logger.info("Model training complete.")
        self.save_model()

    def detect(self, features: pd.DataFrame) -> Optional[pd.Series]:
        """Detect anomalies using the currently loaded model."""
        if self.model:
            return self.model.predict(features)
        
        self.logger.error("Model not loaded, cannot detect.")
        return None

    def save_model(self, model_name: Optional[str] = None, save_dir: Optional[Union[str, Path]] = None) -> bool:
        """
        Save the current model to disk, including its metadata, metrics, and feature importances.
        
        Args:
            model_name: Optional custom name for the model. If not provided, uses the name from config.
            save_dir: Optional custom directory to save the model. If not provided, uses the directory from config.
            
        Returns:
            bool: True if the model was saved successfully, False otherwise
        """
        if not self.model:
            self.logger.error("No model to save.")
            return False
            
        try:
            # Determine the save directory and model path
            if save_dir is not None:
                model_dir = Path(save_dir)
                if model_name:
                    model_dir = model_dir / model_name
            else:
                model_dir = self._get_model_path(model_name=model_name)
            
            model_dir.mkdir(parents=True, exist_ok=True)
            model_path = model_dir / 'model.joblib'
            
            # Save the model using the model's save method
            self.logger.info(f"Saving model to {model_path}")
            success = self.model.save(model_path)
            
            if success:
                # The model's save method handles saving metrics and feature importances
                self.logger.info(f"Successfully saved model to {model_path}")
                
                # Log model info
                model_info = self.get_model_info()
                self.logger.info(f"Model type: {model_info.get('model_type', 'unknown')}")
                if 'training_metrics' in model_info:
                    metrics = model_info['training_metrics']
                    if 'data_stats' in metrics:
                        self.logger.info(
                            f"Trained on {metrics['data_stats'].get('num_samples', 0):,} samples with "
                            f"{metrics['data_stats'].get('num_features', 0)} features"
                        )
                
                return True
                
            self.logger.error("Model save operation failed")
            return False
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}", exc_info=True)
            return False
