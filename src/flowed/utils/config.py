"""Configuration management for the traffic detection system."""
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import yaml
from loguru import logger

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file. If None, loads default config.
        
    Returns:
        Dictionary containing the configuration.
    """
    default_config_path = Path(__file__).parent.parent / 'config' / 'default_config.yaml'
    
    # If no config path provided, use default
    if config_path is None:
        config_path = default_config_path
    else:
        config_path = Path(config_path)
    
    # Load the configuration file
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
        logger.info(f"Loaded configuration from {config_path}")
    except FileNotFoundError:
        if config_path != default_config_path:
            logger.warning(f"Config file {config_path} not found, using default configuration")
        with open(default_config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
        logger.info(f"Loaded default configuration from {default_config_path}")
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise
    
    # Validate and fix configuration
    config = _validate_and_fix_config(config)
    
    return config

def _validate_and_fix_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration and apply fixes for common issues.
    
    Args:
        config: Raw configuration dictionary
        
    Returns:
        Validated and fixed configuration dictionary
    """
    # Ensure required sections exist
    required_sections = ['data', 'features', 'model', 'logging']
    for section in required_sections:
        if section not in config:
            logger.warning(f"Missing required config section '{section}', using defaults")
            config[section] = {}
    
    # Fix features.calculators if it's a list instead of dict
    if 'calculators' in config.get('features', {}):
        calculators = config['features']['calculators']
        if isinstance(calculators, list):
            logger.warning("Converting features.calculators from list to dict format")
            # Convert list to dict with enabled=True
            new_calculators = {}
            for calc in calculators:
                if isinstance(calc, str):
                    new_calculators[calc] = {'enabled': True}
                elif isinstance(calc, dict) and len(calc) == 1:
                    key, value = next(iter(calc.items()))
                    new_calculators[key] = value if isinstance(value, dict) else {'enabled': bool(value)}
            config['features']['calculators'] = new_calculators
    
    # Validate model configuration
    model_config = config.get('model', {})
    if 'type' not in model_config:
        logger.warning("Model type not specified, defaulting to 'isolation_forest'")
        model_config['type'] = 'isolation_forest'
    
    # Ensure params is a dict
    if 'params' not in model_config or not isinstance(model_config['params'], dict):
        logger.warning("Model params not properly configured, using defaults")
        model_config['params'] = {'contamination': 0.05, 'random_state': 42}
    
    # Validate data source
    data_config = config.get('data', {})
    if 'source' not in data_config:
        logger.warning("Data source not specified, defaulting to 'pcap'")
        data_config['source'] = 'pcap'
    
    return config

def setup_logging(log_config: Dict[str, Any]) -> None:
    """Configure logging based on the configuration.
    
    Args:
        log_config: Logging configuration dictionary.
    """
    from loguru import logger
    
    # Remove default handler
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stderr,
        level=log_config.get('level', 'INFO'),
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    
    # Add text file handler
    log_file = log_config.get('file')
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            rotation=f"{log_config.get('max_size', 10)} MB",
            retention=f"{log_config.get('backup_count', 5)} days",
            level=log_config.get('level', 'INFO'),
            enqueue=True, # Make it thread-safe
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
        )

    # Add structured JSON file handler if enabled
    if log_config.get('structured', False):
        json_log_file = log_config.get('json_file')
        if json_log_file:
            Path(json_log_file).parent.mkdir(parents=True, exist_ok=True)
            logger.add(
                json_log_file,
                level=log_config.get('level', 'INFO'),
                serialize=True, # This is the key to structured logging
                rotation=f"{log_config.get('max_size', 10)} MB",
                retention=f"{log_config.get('backup_count', 5)} days",
                enqueue=True
            )
    
    logger.info("Logging configured")
