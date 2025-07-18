"""Command-line interface for the traffic detection system."""
import sys
import argparse
from loguru import logger

from flowed.main import TrafficDetector

def main():
    """Main entry point for the flowed command line interface."""
    parser = argparse.ArgumentParser(description="Flowed: Network Traffic Anomaly Detection System",
                                     formatter_class=argparse.RawTextHelpFormatter
                                     )
    parser.add_argument('--config', type=str, default=None,
                        help='Path to the configuration file.')
    parser.add_argument('--source', type=str, default=None,
                        choices=['pcap', 'arkime'],
                        help='Data source to use. Overrides the config file.')
    parser.add_argument('--input-dir', type=str, default=None,
                        help='Override the input directory for PCAP files.')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Override the output directory for reports and processed data.')
    parser.add_argument('--train', action='store_true',
                        help='Force the model to be retrained on the current data.')
    parser.add_argument('--log-level', type=str, default=None,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Override the logging level.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging (equivalent to --log-level DEBUG)')

    args = parser.parse_args()

    try:
        detector = TrafficDetector(config_path=args.config)

        # Override config with CLI args
        if args.source:
            detector.config['data']['source'] = args.source
        if args.train:
            detector.config['model']['train']['force_retrain'] = True
        
        detector.run()
        logger.success("Traffic detection process finished successfully.")

    except Exception as e:
        logger.critical(f"A fatal error occurred in the application: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
