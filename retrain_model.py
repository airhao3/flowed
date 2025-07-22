#!/usr/bin/env python3
"""
Script to retrain the network traffic anomaly detection model with all available features.
"""
import sys
import os
import logging
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from loguru import logger

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

def setup_logging():
    """Configure logging for the retraining process."""
    logger.remove()  # Remove default handler
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    logger.add(
        "logs/retrain.log",
        rotation="10 MB",
        retention="10 days",
        level="DEBUG"
    )

def load_training_data():
    """Load and prepare the training data."""
    data_path = Path("data/processed/training_data.csv")
    if not data_path.exists():
        logger.error(f"Training data not found at {data_path}")
        return None
    
    logger.info(f"Loading training data from {data_path}")
    try:
        df = pd.read_csv(data_path)
        logger.info(f"Loaded {len(df)} samples with {df.shape[1]} features")
        
        # Select only numeric columns for training
        numeric_cols = df.select_dtypes(include='number').columns.tolist()
        logger.info(f"Found {len(numeric_cols)} numeric features")
        
        # Handle missing values
        df = df[numeric_cols].fillna(0)
        
        return df
    except Exception as e:
        logger.error(f"Error loading training data: {e}")
        return None

def train_model(X):
    """Train a new Isolation Forest model."""
    logger.info("Training new Isolation Forest model...")
    
    # Model parameters from config
    params = {
        'n_estimators': 100,
        'max_samples': 'auto',
        'contamination': 0.05,
        'random_state': 42,
        'n_jobs': -1
    }
    
    model = IsolationForest(**params)
    model.fit(X)
    
    # Save feature names for inference
    model.feature_names_ = X.columns.tolist()
    
    return model

def save_model(model, output_dir):
    """Save the trained model and feature names."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save model
    model_path = output_dir / "model.joblib"
    joblib.dump(model, model_path)
    
    # Save feature names
    features_path = output_dir / "feature_names.json"
    import json
    with open(features_path, 'w') as f:
        json.dump(model.feature_names_, f)
    
    logger.info(f"Model saved to {model_path}")
    logger.info(f"Feature names saved to {features_path}")

def main():
    """Main function to retrain the model."""
    setup_logging()
    logger.info("Starting model retraining...")
    
    # Load and prepare data
    df = load_training_data()
    if df is None or df.empty:
        logger.error("No training data available")
        return 1
    
    # Train model
    model = train_model(df)
    
    # Save model
    save_model(model, "data/models")
    
    logger.success("Model retraining completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
