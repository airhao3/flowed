#!/usr/bin/env python3
"""
Main CLI entry point for the flow detection system.
"""

import sys
import argparse
import traceback
from loguru import logger

logger.debug("Top of file")

try:
    from flowed.main import TrafficDetector
    logger.debug("Successfully imported TrafficDetector")
except Exception as e:
    logger.error(f"Error importing TrafficDetector: {e}")
    traceback.print_exc()
    sys.exit(1)

from flowed.utils.config import load_config, setup_logging

def main():
    print("[DEBUG] cli.py: Entered main() function")
    """Main entry point for the flowed command line interface."""
    # 添加信号处理，捕获SIGINT (Ctrl+C) 和 SIGTERM
    import signal
    def signal_handler(sig, frame):
        print(f"\n[DEBUG] Received signal {sig}. Exiting gracefully...")
        logger.warning(f"Process interrupted by signal {sig}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Main parser setup
    parser = argparse.ArgumentParser(
        description="""Flowed: Network Traffic Anomaly Detection System
        
        Commands:
          detect      Run network traffic anomaly detection
          train       Train a new model with current data
          retrain     Retrain existing models with new data
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required command argument
    parser.add_argument(
        'command', 
        type=str, 
        choices=['detect', 'train', 'retrain'],
        help='Command to execute (detect/train/retrain)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--config', 
        type=str, 
        default='custom_config.yaml', 
        help='Path to the configuration YAML file (default: custom_config.yaml)'
    )
    parser.add_argument(
        '--source', 
        type=str, 
        help='Override the data source path (overrides config file)'
    )
    parser.add_argument(
        '--destination', 
        type=str, 
        help='Override the output destination path (overrides config file)'
    )
    parser.add_argument(
        '--log-level', 
        type=str.upper,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level (overrides config file)'
    )
    parser.add_argument(
        '--force-retrain', 
        action='store_true', 
        help='Force retraining of models even if they exist'
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true',
        help='Enable verbose output (equivalent to --log-level DEBUG)'
    )
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='''Enable debug mode with additional diagnostics and checks. 
        This may include detailed error reporting and additional logging.'''
    )

    args = parser.parse_args()
    
    config = load_config(config_path=args.config)
    
    # Override log level from CLI args before setting up logging
    if args.log_level:
        config.logging.level = args.log_level.upper()
    if args.verbose:
        config.logging.level = 'DEBUG'

    # Now setup logging with the potentially overridden config
    setup_logging(config.logging)

    try:
        logger.info("Initializing Traffic Detection System...")
        
        # Override other config settings with CLI args after loading
        if args.source:
            config.data.source_path = args.source
        if args.destination:
            config.data.destination_path = args.destination
        if args.force_retrain:
            if 'model' not in config:
                config.model = {}
            config.model.force_retrain = True
            logger.debug(f"Force retrain set to {config.model.force_retrain}")
        
        if args.debug:
            # 在debug模式下启用更多调试功能
            logger.debug("Debug mode enabled - activating extra diagnostics")
            # 输出完整的配置信息用于调试
            logger.debug(f"Using configuration: {config}")
            
            # 导入模型训练代码并查看可能的依赖
            try:
                logger.debug("Checking model dependencies...")
                import tensorflow as tf
                logger.debug(f"TensorFlow version: {tf.__version__}")
            except ImportError as e:
                logger.warning(f"TensorFlow import error: {e}")
            
            # 检查模型目录
            import os
            model_dir = os.path.join(os.getcwd(), "data", "models")
            os.makedirs(model_dir, exist_ok=True)
            logger.debug(f"Model directory: {model_dir} (exists={os.path.exists(model_dir)})")

        # Pass the fully prepared config object to the detector
        logger.debug("Creating TrafficDetector instance...")
        detector = TrafficDetector(config)
        logger.debug("Running traffic detection...")
        detector.run()
        logger.success("Traffic detection process finished successfully.")

    except KeyboardInterrupt:
        logger.warning("Process interrupted by user (KeyboardInterrupt)")
        sys.exit(130)  # 标准的Ctrl+C中断退出码
    except ModuleNotFoundError as e:
        logger.critical(f"Missing required module: {e}")
        logger.info("Please check installation and dependencies.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"A fatal error occurred in the application: {e}")
        logger.debug("Detailed traceback:", exc_info=True)
        import traceback
        print(f"\n[DEBUG TRACEBACK] {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    print("[DEBUG] cli.py: Inside __name__ == '__main__' block")
    sys.exit(main())
