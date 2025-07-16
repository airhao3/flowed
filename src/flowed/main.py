#!/usr/bin/env python3
"""
Network Traffic Anomaly Detection System

This module provides the main entry point for the traffic detection system.
"""
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from loguru import logger

from flowed.utils.config import load_config, setup_logging
from flowed.data.collector import DataCollector
from flowed.data.arkime_collector import ArkimeCollector
from flowed.data.ingestor import DataIngestor
from flowed.features.extractor import FeatureExtractor
from flowed.models import ModelManager
from flowed.visualization.dashboard import ResultVisualizer

class TrafficDetector:
    """Main class for the Traffic Detection System."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the Traffic Detection System.
        
        Args:
            config_path: Path to the configuration file. If None, default config is used.
        """
        # Load configuration
        self.config = load_config(config_path)
        
        # Setup logging
        setup_logging(self.config['logging'])
        self.logger = logger.bind(module=__name__)
        
        # Initialize components based on config
        self.data_ingestor = DataIngestor(self.config)
        self.feature_extractor = FeatureExtractor(self.config)
        self.model_manager = ModelManager(self.config)
        self.visualizer = ResultVisualizer(self.config['visualization'])
        
        self.logger.info("Traffic Detection System initialized")
    
    def run(self) -> Dict[str, Any]:
        """Run the traffic detection pipeline.
        
        Returns:
            Dictionary containing the results of the analysis.
        """
        results = {}
        
        try:
            # Step 1: Data Collection
            self.logger.info("Starting data collection...")
            data_source = self.config.get('data', {}).get('source', 'pcap')

            processed_data = None
            if data_source == 'arkime':
                arkime_config = self.config.get('data', {}).get('arkime', {})
                collector = ArkimeCollector(arkime_config)
                processed_data = collector.collect()
            elif data_source == 'pcap':
                pcap_config = self.config.get('data', {}).get('pcap', {})
                collector = DataCollector(pcap_config)
                raw_files = collector.collect()
                if not raw_files:
                    self.logger.warning("No new PCAP files found. Exiting.")
                    return {}
                self.logger.info(f"Collected {len(raw_files)} PCAP files. Ingesting...")
                processed_data = self.data_ingestor.process_files(raw_files)
            else:
                self.logger.error(f"Invalid data source '{data_source}' in configuration.")
                return {}

            if processed_data is None or processed_data.empty:
                self.logger.warning("No data was processed. Exiting.")
                return {}

            # Step 2: Feature Extraction
            self.logger.info("Extracting features from processed data...")
            try:
                features = self.feature_extractor.extract_features(processed_data)
                if features.empty:
                    self.logger.error("Feature extraction resulted in empty DataFrame.")
                    return {}
                self.logger.info(f"Extracted {features.shape[1]} features from {features.shape[0]} records.")
            except Exception as e:
                self.logger.error(f"Feature extraction failed: {e}", exc_info=True)
                return {}
            
            # Step 3: Model Training/Loading
            self.logger.debug("Checking model loading/training...")
            try:
                if self.config.get('train', {}).get('force_retrain', False):
                    self.logger.info("Training model as per configuration...")
                    self.model_manager.train(features)
                else:
                    # Try to load existing model
                    self.logger.debug("Attempting to load existing model...")
                    if not self.model_manager.load_model():
                        self.logger.info("No existing model found. Training a new model...")
                        self.model_manager.train(features)
                    else:
                        self.logger.info("Successfully loaded existing model")
            except Exception as e:
                self.logger.error(f"Model training/loading failed: {e}", exc_info=True)
                return {}

            # Step 4: Anomaly Detection
            self.logger.info("Detecting anomalies...")
            try:
                predictions = self.model_manager.detect(features)
                if predictions is None or predictions.empty:
                    self.logger.error("Anomaly detection failed or returned empty results.")
                    return {}
                
                anomaly_count = (predictions == -1).sum()
                self.logger.info(f"Detected {anomaly_count} anomalies out of {len(predictions)} samples.")
            except Exception as e:
                self.logger.error(f"Anomaly detection failed: {e}", exc_info=True)
                return {}
            
            # Step 5: Generate Report
            if self.config.get('visualization', {}).get('enable', True):
                self.logger.info("Generating report...")
                # Add the anomaly predictions back to the feature-rich DataFrame for reporting
                features['anomaly'] = predictions
                anomalies = features[features['anomaly'] == -1]
                report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                report_path = self.visualizer.generate_report(features, anomalies, report_name)
                self.logger.info(f"Report generated at: {report_path}")
            else:
                self.logger.info("Visualization is disabled. Skipping report generation.")
                
            results = {
                'features': features,
                'predictions': predictions,
                'report': report_path
            }
            
            self.logger.info("Analysis completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            raise
        
        return results

# This file defines the main application class. 
# The command-line entry point is now in cli.py.
