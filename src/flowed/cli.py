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
        # Initialize the main application
        detector = TrafficDetector(config_path=args.config)

        # Override configuration with CLI arguments where provided
        if args.input_dir:
            detector.config['data']['input_dir'] = args.input_dir
        if args.output_dir:
            detector.config['data']['output_dir'] = args.output_dir
            detector.config['visualization']['output_dir'] = args.output_dir
            detector.config['model']['save_dir'] = f"{args.output_dir}/models"
        if args.source:
            detector.config['data']['source'] = args.source
        # Set log level based on --verbose or --log-level
        if args.verbose:
            detector.config['logging']['level'] = 'DEBUG'
        elif args.log_level:
            detector.config['logging']['level'] = args.log_level
        if args.train:
            detector.config['train']['force_retrain'] = True

        # Run the detection pipeline
        detector.run()
        
        logger.success("Traffic detection process finished.")
        return 0

    except Exception as e:
        logger.critical(f"A fatal error occurred: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
