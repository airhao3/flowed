#!/usr/bin/env python3
"""
Script to retrain the network traffic anomaly detection model.
"""
import sys
import os
import logging
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from flowed.cli import main

def retrain_model():
    """Retrain the model with the current configuration."""
    # Set up command line arguments
    sys.argv = [
        '--config', 'test_config.yaml',
        '--train',
        '--verbose'
    ]
    
    print("Starting model retraining...")
    print(f"Current working directory: {os.getcwd()}")
    
    try:
        # Run the main CLI with our arguments
        main()
        print("Model retraining completed successfully!")
        return 0
    except Exception as e:
        print(f"Error during model retraining: {str(e)}", file=sys.stderr)
        logging.exception("Model retraining failed")
        return 1

if __name__ == "__main__":
    sys.exit(retrain_model())
