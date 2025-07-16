#!/bin/bash
# Installation script for the traffic detection system

set -e

# Create and activate virtual environment
echo "Checking for uv..."
if ! command -v uv &> /dev/null
then
    echo "uv could not be found. Please install it first: https://github.com/astral-sh/uv"
    exit 1
fi

echo "Creating Python virtual environment in '.venv' using uv..."
uv venv

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies from requirements.txt using uv..."
uv pip install -r requirements.txt

echo "Installing project in editable mode with dev dependencies using uv..."
uv pip install -e .[dev,docs]

# Create necessary directories
echo "Creating data directories..."
mkdir -p data/raw data/processed data/models logs

echo "Installation complete! Activate the virtual environment with:"
echo "source .venv/bin/activate"
