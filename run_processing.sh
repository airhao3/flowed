#!/bin/bash

# Activate virtual environment
source .venv/bin/activate

# Remove existing model file
rm -f data/models/isolation_forest_model.joblib

# Run the processing
python3 -c "import sys; sys.argv.extend(['--config', 'test_config.yaml', '--verbose']); from flowed.cli import main; main()"
