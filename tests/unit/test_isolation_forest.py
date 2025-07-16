import os
import json
import yaml
import numpy as np
import pandas as pd
import pytest
from pathlib import Path

from flowed.models.isolation_forest import IsolationForestModel

def test_isolation_forest_model(tmp_path):
    """Test IsolationForest model training, saving, and loading."""
    # Create sample data
    np.random.seed(42)
    X = np.random.normal(0, 1, (100, 5))
    X[50:] += 10  # Add some anomalies
    df = pd.DataFrame(X, columns=[f'feat_{i}' for i in range(5)])

    # Initialize model
    config = {
        'n_estimators': 100,
        'max_samples': 'auto',
        'contamination': 0.1,
        'random_state': 42
    }
    model = IsolationForestModel(config)

    # Train model
    model.fit(df)

    # Save model
    model_path = tmp_path / "test_model.joblib"
    model.save(model_path)
    assert model_path.exists()

    # Load model
    loaded_model = IsolationForestModel(config)
    assert loaded_model.load(model_path)

    # Compare predictions
    pred1 = model.predict(df)
    pred2 = loaded_model.predict(df)
    assert pred1.equals(pred2)

    # Clean up
    if model_path.exists():
        os.remove(model_path)


def test_training_metrics_logging():
    """Test that training metrics are properly logged and saved."""
    # Create sample data
    np.random.seed(42)
    X = np.random.normal(0, 1, (100, 5))
    X[50:] += 10  # Add some anomalies
    df = pd.DataFrame(X, columns=[f'feat_{i}' for i in range(5)])

    # Initialize and train model
    config = {'n_estimators': 50, 'random_state': 42}
    model = IsolationForestModel(config)
    model.fit(df)

    # Check training metrics
    assert hasattr(model, 'training_metrics'), "Training metrics not found"
    assert 'train_start_time' in model.training_metrics
    assert 'train_end_time' in model.training_metrics
    assert 'train_duration_seconds' in model.training_metrics
    assert 'model_parameters' in model.training_metrics
    assert 'n_samples' in model.training_metrics
    assert 'n_features' in model.training_metrics
    assert 'anomaly_score_mean' in model.training_metrics
    assert 'anomaly_score_std' in model.training_metrics


def test_feature_importance_calculation():
    """Test that feature importance is calculated correctly."""
    # Create sample data with clear feature differences
    np.random.seed(42)
    X = np.random.normal(0, 1, (200, 3))
    # Make one feature have more extreme values (more useful for isolation)
    X[:, 0] = X[:, 0] * 5  # Scale up the first feature
    df = pd.DataFrame(X, columns=['important', 'noise1', 'noise2'])

    # Initialize and train model
    config = {'n_estimators': 100, 'random_state': 42}
    model = IsolationForestModel(config)
    model.fit(df)

    # Check feature importance
    assert hasattr(model, 'feature_importances_'), "Feature importances not calculated"
    assert len(model.feature_importances_) == 3
    
    # Check that all importances are positive and sum to 1
    assert all(model.feature_importances_ > 0), "All feature importances should be positive"
    assert abs(model.feature_importances_.sum() - 1.0) < 1e-6, "Feature importances should sum to 1"
    
    # Check that feature importances are reasonable (no single feature dominates completely)
    max_importance = model.feature_importances_.max()
    min_importance = model.feature_importances_.min()
    assert max_importance < 0.8, "No single feature should dominate completely"
    assert min_importance > 0.1, "All features should have some importance"


def test_model_save_load_with_metadata(tmp_path):
    """Test saving and loading model with metadata and metrics."""
    # Create sample data
    np.random.seed(42)
    X = np.random.normal(0, 1, (100, 3))
    X[50:] += 10  # Add some anomalies
    df = pd.DataFrame(X, columns=['feat1', 'feat2', 'feat3'])

    # Initialize and train model
    config = {'n_estimators': 50, 'random_state': 42}
    model = IsolationForestModel(config)
    model.fit(df)

    # Save model to directory
    model_dir = tmp_path / "test_model"
    model_dir.mkdir()
    model_path = model_dir / "model.joblib"
    
    # Save model
    model.save(model_path)
    
    # Check all expected files were created
    assert model_path.exists()
    assert (model_dir / "metadata.yaml").exists()
    assert (model_dir / "training_metrics.json").exists()
    assert (model_dir / "feature_importances.csv").exists()
    
    # Load model
    loaded_model = IsolationForestModel(config)
    assert loaded_model.load(model_path)
    
    # Verify metadata and metrics were loaded correctly
    assert hasattr(loaded_model, 'training_metrics')
    assert hasattr(loaded_model, 'feature_importances_')
    assert len(loaded_model.feature_importances_) == 3
    
    # Verify predictions match
    pred1 = model.predict(df)
    pred2 = loaded_model.predict(df)
    assert pred1.equals(pred2)
    
    # Clean up
    for file in model_dir.glob("*"):
        file.unlink()
    model_dir.rmdir()


def test_model_config_handling():
    """Test that model configuration is handled correctly."""
    # Test with minimal config
    config = {}
    model = IsolationForestModel(config)
    assert model.model is not None
    
    # Test with custom parameters
    custom_config = {
        'n_estimators': 100,
        'max_samples': 0.8,
        'contamination': 0.1,
        'random_state': 42,
        'n_jobs': -1
    }
    model = IsolationForestModel(custom_config)
    for param, value in custom_config.items():
        assert getattr(model.model, param) == value
