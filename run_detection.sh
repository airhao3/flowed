#!/bin/bash

# Activate virtual environment
source .venv/bin/activate

# Run the detection process
python3 src/flowed/cli.py detect --config custom_config.yaml
