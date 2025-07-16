#!/bin/bash
# Run tests for the traffic detection system

set -e

# Activate virtual environment
source .venv/bin/activate

# Run tests with coverage
echo "Running tests..."
python -m pytest tests/ -v --cov=src/traffic_detect --cov-report=term-missing

# Generate coverage report
echo -e "\nGenerating coverage report..."
python -m coverage html
echo "Coverage report generated at htmlcov/index.html"
