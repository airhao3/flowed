# Network Traffic Anomaly Detection System

A Python-based system for detecting anomalies in network traffic using machine learning.

## Features

- PCAP file processing
- Feature extraction from network traffic
- Anomaly detection using various algorithms
- Interactive visualization of results
- Customizable configuration

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/traffic_detect.git
   cd traffic_detect
   ```

2. Create and activate a virtual environment:
   This project uses `uv` for high-speed environment management and package installation. Please [install `uv`](https://github.com/astral-sh/uv) before proceeding.

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install in development mode:
   ```bash
   pip install -e .
   ```

## Usage

### Basic usage

```bash
# Analyze PCAP files in the default directory
python -m traffic_detect.main

# Specify input and output directories
python -m traffic_detect.main --input-dir /path/to/pcaps --output-dir /path/to/results

# Train a new model
python -m traffic_detect.main --train

# Set log level
python -m traffic_detect.main --log-level DEBUG
```

### Configuration

The system can be configured using a YAML configuration file. By default, it looks for `config/default_config.yaml` in the package directory.

## Project Structure

```
traffic_detect/
├── data/               # Data files (not version controlled)
│   ├── raw/            # Raw PCAP files
│   ├── processed/      # Processed data
│   └── models/         # Trained models
├── docs/               # Documentation
├── src/                # Source code
│   └── traffic_detect/ # Main package
│       ├── data/       # Data collection and processing
│       ├── features/   # Feature extraction
│       ├── models/     # Anomaly detection models
│       ├── utils/      # Utility functions
│       └── visualization/  # Visualization tools
├── tests/              # Unit and integration tests
├── .gitignore          # Git ignore file
├── README.md           # This file
├── requirements.txt    # Python dependencies
└── setup.py           # Package setup file
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
