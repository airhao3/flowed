import numpy as np
import pandas as pd
import joblib
import yaml
import json
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from joblib import dump, load

from sklearn.ensemble import IsolationForest
from loguru import logger

from .base import BaseModel

class IsolationForestModel(BaseModel):
    """
    Isolation Forest model for anomaly detection.
    
    This implementation extends scikit-learn's IsolationForest with additional
    functionality for tracking training metrics, feature importances, and model metadata.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the Isolation Forest model.
        
        Args:
            config: Dictionary containing model configuration parameters.
                   See sklearn.ensemble.IsolationForest for available parameters.
        """
        super().__init__(config or {})
        self.logger = logger.bind(module=__name__)
        
        # Set default parameters
        default_params = {
            'n_estimators': 100,
            'max_samples': 'auto',  # Will be converted to float later
            'contamination': 'auto',  # Will be converted to float later
            'random_state': 42,  # Set a default random state for reproducibility
            'n_jobs': -1,
            'bootstrap': False,
            'verbose': 0
        }
        
        # Update with user-provided config
        if config:
            # Convert string parameters to appropriate types
            if 'max_samples' in config and config['max_samples'] == 'auto':
                config['max_samples'] = 1.0
                
            if 'contamination' in config and config['contamination'] == 'auto':
                config['contamination'] = 0.1
                
            # Update defaults with user config
            default_params.update(config)
        
        # Store the config
        self.config = default_params
        
        # Filter out any parameters that aren't valid for IsolationForest
        valid_params = {
            'n_estimators', 'max_samples', 'contamination', 'max_features',
            'bootstrap', 'n_jobs', 'random_state', 'verbose', 'warm_start'
        }
        model_params = {k: v for k, v in default_params.items() if k in valid_params}
        
        # Initialize the model with the filtered parameters
        self.model = IsolationForest(**model_params)
        self.feature_importances_ = None
        self.training_metrics = {}
        self.metadata = {}
        self._training_time_seconds = 0.0

    def _calculate_feature_importances(self, features: pd.DataFrame) -> Optional[pd.Series]:
        """
        Calculate feature importances based on the trained model.
        
        Args:
            features: DataFrame containing the features used for training
            
        Returns:
            pd.Series: Feature importances with feature names as index, or None if calculation fails
        """
        try:
            # Convert features to numpy array if it's a DataFrame
            if hasattr(features, 'values'):
                X = features.values
                feature_names = features.columns.tolist()
            else:
                X = features
                feature_names = [f'feature_{i}' for i in range(X.shape[1])]
            
            # Initialize importance array
            n_features = X.shape[1]
            importances = np.zeros(n_features)
            
            # For Isolation Forest, we'll use a simpler approach based on feature usage
            # Calculate how often each feature is used for splitting across all trees
            for tree in self.model.estimators_:
                # Get the tree structure
                tree_structure = tree.tree_
                feature_indices = tree_structure.feature
                
                # Count feature usage (exclude leaf nodes which have feature = -2)
                for feature_idx in feature_indices:
                    if 0 <= feature_idx < n_features:
                        importances[feature_idx] += 1
            
            # Normalize by total number of splits
            total_splits = np.sum(importances)
            if total_splits > 0:
                importances = importances / total_splits
            else:
                # If no splits found, assign equal importance
                importances = np.ones(n_features) / n_features
            
            # Normalize to sum to 1
            importances = importances / np.sum(importances)
            
            # Create a Series with feature names
            self.feature_importances_ = pd.Series(importances, index=feature_names, name='importance')
            
            # Store feature importance statistics in training metrics
            if not hasattr(self, 'training_metrics'):
                self.training_metrics = {}
                
            self.training_metrics['feature_importance'] = {
                'mean_importance': float(np.mean(importances)),
                'max_importance': float(np.max(importances)),
                'min_importance': float(np.min(importances)),
                'top_features': self.feature_importances_.nlargest(10).to_dict()
            }
            
            # Log top 10 most important features
            if len(self.feature_importances_) > 0:
                self.logger.info("Top 10 most important features:")
                self.logger.info(self.feature_importances_.nlargest(10).to_string())
            
            return self.feature_importances_
            
        except Exception as e:
            error_msg = f"Error calculating feature importances: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.feature_importances_ = {}
            
            # Store error in training metrics if available
            if hasattr(self, 'training_metrics'):
                if not isinstance(self.training_metrics, dict):
                    self.training_metrics = {}
                self.training_metrics['feature_importance_error'] = error_msg
            
            return None

    def _calculate_training_metrics(self, features: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate and return training metrics for the model.
        
        Args:
            features: DataFrame containing the training data
            
        Returns:
            Dict: Dictionary containing training metrics
        """
        try:
            # Store start time for training metrics
            train_start_time = datetime.now(timezone.utc).isoformat()
            
            # Calculate anomaly scores
            scores = self.model.score_samples(features)
            
            # Ensure scores is a numpy array
            scores = np.asarray(scores).flatten()
            
            # Get contamination from model config
            contamination = self.config.get('contamination', 'auto')
            if contamination == 'auto':
                contamination = 0.1  # Default contamination if 'auto'
            else:
                contamination = float(contamination)
            
            # Calculate threshold based on contamination
            threshold = np.percentile(scores, 100 * contamination, method='lower')
            
            # Calculate number of anomalies
            is_anomaly = scores <= threshold
            num_anomalies = int(np.sum(is_anomaly))
            
            # Calculate basic statistics
            metrics = {
                'train_start_time': train_start_time,
                'train_end_time': datetime.now(timezone.utc).isoformat(),
                'train_duration_seconds': self._training_time_seconds,
                'n_samples': len(features),
                'n_features': features.shape[1],
                'model_parameters': self.model.get_params(),
                'contamination': contamination,
                'estimated_contamination': num_anomalies / len(features) if len(features) > 0 else 0.0,
                'threshold': float(threshold),
                'num_anomalies': num_anomalies,
                # Flatten anomaly score statistics for test compatibility
                'anomaly_score_mean': float(np.mean(scores)),
                'anomaly_score_std': float(np.std(scores)),
                'anomaly_score_min': float(np.min(scores)),
                'anomaly_score_max': float(np.max(scores)),
                'anomaly_score_median': float(np.median(scores)),
                # Keep nested structure for detailed analysis
                'anomaly_score': {
                    'mean': float(np.mean(scores)),
                    'std': float(np.std(scores)),
                    'min': float(np.min(scores)),
                    'max': float(np.max(scores)),
                    'median': float(np.median(scores)),
                    '25%': float(np.percentile(scores, 25)),
                    '75%': float(np.percentile(scores, 75)),
                    'range': float(np.max(scores) - np.min(scores))
                },
                'feature_names': features.columns.tolist() if hasattr(features, 'columns') else []
            }
            
            # Add feature importances if available
            if hasattr(self, 'feature_importances_') and self.feature_importances_ is not None:
                metrics['feature_importance'] = {
                    'mean_importance': float(self.feature_importances_.mean()),
                    'min_importance': float(self.feature_importances_.min()),
                    'max_importance': float(self.feature_importances_.max()),
                    'top_features': self.feature_importances_.nlargest(10).to_dict()
                }
            
            self.training_metrics = metrics
            
            # Log summary
            self.logger.info("\n" + "=" * 50)
            self.logger.info("TRAINING SUMMARY")
            self.logger.info("=" * 50)
            self.logger.info(f"Samples: {metrics['n_samples']}")
            self.logger.info(f"Features: {metrics['n_features']}")
            self.logger.info(f"Training time: {metrics['train_duration_seconds']:.2f} seconds")
            self.logger.info(f"Anomaly scores - Mean: {metrics['anomaly_score']['mean']:.4f} ± {metrics['anomaly_score']['std']:.4f}")
            self.logger.info(f"Anomaly scores - Range: [{metrics['anomaly_score']['min']:.4f}, {metrics['anomaly_score']['max']:.4f}]")
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error during post-training analysis: {e}", exc_info=True)
            return {}

    def fit(self, features: pd.DataFrame):
        """
        Train the Isolation Forest model on the provided features.
        
        This method handles data preprocessing, model training, and calculation of
        training metrics and feature importances.
        
        Args:
            features: DataFrame containing the training features
        """
        if features.empty:
            self.logger.error("No features provided for training.")
            return
            
        start_time = datetime.now(timezone.utc)
        self.logger.info(f"Starting Isolation Forest training on {len(features)} samples...")

        # Select only numeric columns for training
        numeric_features = features.select_dtypes(include=['number']).copy()
        if numeric_features.empty:
            self.logger.error("No numeric features available for training. Aborting.")
            return
            
        self.logger.info(f"Selected {len(numeric_features.columns)} numeric features for training")
        self.logger.debug(f"Numeric features: {', '.join(numeric_features.columns)}")

        # Data cleaning with better memory management
        self.logger.debug("Preprocessing numeric features...")
        
        # Check for infinite values before replacement
        inf_counts = np.isinf(numeric_features.values).sum()
        if inf_counts > 0:
            self.logger.warning(f"Found {inf_counts} infinite values. Replacing with NaN.")
            numeric_features = numeric_features.replace([np.inf, -np.inf], np.nan)
        
        # Handle missing values with better strategy
        missing_stats = numeric_features.isnull().sum()
        if missing_stats.sum() > 0:
            missing_cols = missing_stats[missing_stats > 0]
            self.logger.warning(f"Found {missing_stats.sum()} missing values in {len(missing_cols)} columns.")
            
            # Use median for continuous features, 0 for count features
            for col in missing_cols.index:
                if 'count' in col.lower() or 'flag' in col.lower():
                    numeric_features[col].fillna(0, inplace=True)
                else:
                    median_val = numeric_features[col].median()
                    numeric_features[col].fillna(median_val, inplace=True)
                    
            self.logger.debug(f"Filled missing values using appropriate strategies.")
        
        # Validate data ranges to prevent model instability
        for col in numeric_features.columns:
            col_data = numeric_features[col]
            if col_data.std() == 0:
                self.logger.warning(f"Column {col} has zero variance, removing from training.")
                numeric_features.drop(columns=[col], inplace=True)

        try:
            # Train the model
            self.logger.info("Training model...")
            self.model.fit(numeric_features)
            training_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self._training_time_seconds = training_time
            
            self.logger.info(f"Model training completed in {training_time:.2f} seconds")
            self.logger.debug(f"Model parameters: {self.model.get_params()}")
            self.logger.info(f"Model training completed in {training_time:.2f} seconds.")
            
            # Calculate training metrics and feature importances
            self.logger.debug("Calculating training metrics...")
            self.training_metrics = self._calculate_training_metrics(numeric_features)
            
            # Calculate feature importances
            self.logger.debug("Calculating feature importances...")
            self._calculate_feature_importances(numeric_features)
            
            # Log training summary
            perf_metrics = self.training_metrics.get('performance_metrics', {})
            anomaly_stats = perf_metrics.get('anomaly_score_stats', {})
            
            self.logger.info("\n" + "="*50)
            self.logger.info("TRAINING SUMMARY")
            self.logger.info("="*50)
            self.logger.info(f"Samples: {len(numeric_features):,}")
            self.logger.info(f"Features: {numeric_features.shape[1]}")
            self.logger.info(f"Training time: {training_time:.2f} seconds")
            self.logger.info(f"Anomaly scores - Mean: {anomaly_stats.get('mean', 0):.4f} ± {anomaly_stats.get('std', 0):.4f}")
            self.logger.info(f"Anomaly scores - Range: [{anomaly_stats.get('min', 0):.4f}, {anomaly_stats.get('max', 0):.4f}]")
            
            # Log top features if available
            if self.feature_importances_ is not None:
                top_features = self.feature_importances_.sort_values(ascending=False).head(5)
                self.logger.info("\nTop 5 most important features:")
                for feat, imp in top_features.items():
                    self.logger.info(f"  {feat}: {imp:.4f}")
            
            self.logger.info("="*50 + "\n")
                
        except Exception as e:
            self.logger.error(f"Error during post-training analysis: {e}", exc_info=True)
            # Don't raise the exception to allow the model to be used even if metrics calculation fails

    def predict(self, features: pd.DataFrame) -> pd.Series:
        """
        Predict anomaly scores for the input features.
        
        Anomaly scores are the opposite of the decision function and are shifted by the model's
        offset. Lower scores indicate more anomalous samples.
        
        Args:
            features: DataFrame containing the input features
            
        Returns:
            pd.Series: Anomaly scores with the same index as the input features.
                     Lower values indicate more anomalous samples.
        """
        if not hasattr(self, 'model') or self.model is None:
            raise RuntimeError("Model has not been trained. Call fit() first.")
            
        self.logger.debug(f"Predicting on {len(features)} samples...")
        
        # Select and validate features
        if hasattr(self.model, 'feature_names_in_'):
            # Use the same features as during training
            missing_features = set(self.model.feature_names_in_) - set(features.columns)
            if missing_features:
                raise ValueError(f"Missing required features: {missing_features}")
            features = features[list(self.model.feature_names_in_)]
        else:
            # Fallback: use only numeric columns
            features = features.select_dtypes(include=['number'])
            if features.empty:
                raise ValueError("No numeric features found for prediction")
        
        # Clean the data
        features = features.replace([np.inf, -np.inf], np.nan)
        
        # Check for missing values
        missing_stats = features.isnull().sum()
        if missing_stats.sum() > 0:
            missing_cols = missing_stats[missing_stats > 0]
            self.logger.warning(f"Found {missing_stats.sum()} missing values in {len(missing_cols)} columns. Filling with 0.")
            features.fillna(0, inplace=True)
        
        # Make predictions
        try:
            scores = self.model.score_samples(features)
            return pd.Series(
                scores,
                index=features.index,
                name='anomaly_score'
            )
        except Exception as e:
            self.logger.error(f"Error during prediction: {e}", exc_info=True)
            return pd.Series(dtype=int)

    def save(self, path: Path) -> bool:
        """
        Save the trained model and its metadata to disk.
        
        Creates a model directory structure:
        models/
        ├── model_name/
        │   ├── model.joblib           # The trained model
        │   ├── metadata.yaml          # Model metadata and training parameters
        │   ├── feature_importances.csv  # Feature importances
        │   └── training_metrics.json   # Detailed training metrics
        """
        try:
            path = Path(path)
            
            # If path is a directory, create it if it doesn't exist
            if path.suffix == '':
                path.mkdir(parents=True, exist_ok=True)
                model_path = path / 'model.joblib'
            else:
                # Ensure parent directory exists
                path.parent.mkdir(parents=True, exist_ok=True)
                model_path = path
            
            self.logger.info(f"Saving model to {model_path}")
            
            # Determine the model directory
            if model_path.suffix != '':
                # If saving to a specific file, use its parent directory
                model_dir = model_path.parent
            else:
                # If path is a directory, use it directly
                model_dir = model_path.parent
            
            # Save the model
            joblib.dump(self.model, model_path)
            
            # Save metadata
            metadata = {
                'model_type': 'IsolationForest',
                'model_name': model_path.stem,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'num_features': self.training_metrics.get('num_features', 0) if self.training_metrics else 0,
                'training_date': self.training_metrics.get('training_date', '') if self.training_metrics else '',
                'model_parameters': self.model.get_params(),
                'files': {
                    'model': str(model_path.relative_to(model_path.parent.parent) if model_path.suffix != '' else model_path.name),
                    'metrics': 'training_metrics.json',
                    'feature_importances': 'feature_importances.csv' if self.feature_importances_ is not None else None
                }
            }
            
            # Save metadata
            metadata_path = model_path.parent / 'metadata.yaml'
            with open(metadata_path, 'w') as f:
                yaml.dump(metadata, f, default_flow_style=False)
            
            # Save training metrics if available
            if self.training_metrics:
                metrics_path = model_path.parent / 'training_metrics.json'
                with open(metrics_path, 'w') as f:
                    json.dump(self.training_metrics, f, indent=2, default=str)
            
            # Save feature importances if available
            if self.feature_importances_ is not None:
                importances_path = model_path.parent / 'feature_importances.csv'
                if hasattr(self.feature_importances_, 'to_frame'):
                    self.feature_importances_.to_frame('importance').to_csv(importances_path)
                elif isinstance(self.feature_importances_, (pd.Series, pd.DataFrame)):
                    self.feature_importances_.to_csv(importances_path)
                else:
                    pd.Series(self.feature_importances_).to_csv(importances_path)
            
            # If the original path was a file, create a symlink for backward compatibility
            if path.suffix != '' and path != model_path:
                try:
                    if path.exists():
                        path.unlink()
                    path.symlink_to(model_path)
                except (OSError, AttributeError) as e:
                    self.logger.warning(f"Could not create symlink: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {str(e)}", exc_info=True)
            return False

    def load(self, path: Path) -> bool:
        """
        Load the model from disk.
        
        Args:
            path: Path to the saved model file or directory.
                
        Returns:
            bool: True if loading was successful, False otherwise.
        """
        try:
            path = Path(path)
            
            # Determine the model path and directory
            if path.is_dir():
                # If path is a directory, look for model.joblib inside it
                model_dir = path
                model_path = model_dir / 'model.joblib'
            elif path.suffix == '.joblib':
                # If path points to a .joblib file, use it directly
                model_path = path
                model_dir = path.parent
            else:
                # Treat as directory
                model_dir = path
                model_path = model_dir / 'model.joblib'
            
            if not model_path.exists():
                self.logger.error(f"Model file not found at {model_path}")
                return False
                
            # Load the model
            self.model = load(model_path)
            
            # Load metadata if available
            metadata_path = model_dir / 'metadata.yaml'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    self.metadata = yaml.safe_load(f)
                self.logger.debug("Loaded model metadata")
            
            # Load training metrics if available
            metrics_path = model_dir / 'training_metrics.json'
            if metrics_path.exists():
                with open(metrics_path, 'r') as f:
                    self.training_metrics = json.load(f)
                self.logger.debug("Loaded training metrics")
            
            # Load feature importances if available
            importances_path = model_dir / 'feature_importances.csv'
            if importances_path.exists():
                try:
                    importances = pd.read_csv(importances_path, index_col=0)
                    if len(importances.columns) == 1:  # Single column
                        self.feature_importances_ = importances.squeeze()
                    else:  # Multiple columns (DataFrame)
                        self.feature_importances_ = importances
                    self.logger.debug("Loaded feature importances")
                except Exception as e:
                    self.logger.warning(f"Could not load feature importances: {e}")
                    self.feature_importances_ = None
            
            self.logger.info(f"Model loaded successfully from {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}", exc_info=True)
            return False
