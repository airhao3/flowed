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
import pandas as pd

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
        self.config = load_config(config_path)
        setup_logging(self.config['logging'])
        self.logger = logger.bind(module=__name__)
        self.data_ingestor = DataIngestor(self.config)
        self.feature_extractor = FeatureExtractor(self.config)
        self.model_manager = ModelManager(self.config)
        self.visualizer = ResultVisualizer(self.config['visualization'])
        self.logger.info("Traffic Detection System initialized")

    def run(self) -> Dict[str, Any]:
        """Run the traffic detection pipeline."""
        all_session_results = []
        results = {}
        run_summary = {
            'ingestion_stats': {},
            'sessionization_stats': {},
            'detection_stats': {},
            'error': None
        }

        try:
            # Step 1: Data Collection and Ingestion
            self.logger.info("Starting data collection...")
            data_source = self.config.get('data', {}).get('source', 'pcap')
            processed_data = None
            ingestion_stats = {}

            if data_source == 'arkime':
                # ... (Arkime implementation would also need to return stats)
                pass
            elif data_source == 'pcap':
                pcap_config = self.config.get('data', {}).get('pcap', {})
                collector = DataCollector(pcap_config)
                raw_files = collector.collect()
                if not raw_files:
                    self.logger.warning("No new PCAP files found. Exiting.")
                    return {}
                self.logger.info(f"Collected {len(raw_files)} PCAP files. Ingesting...")
                processed_data, ingestion_stats = self.data_ingestor.process_files(raw_files)
            
            run_summary['ingestion_stats'] = ingestion_stats

            if processed_data is None or processed_data.empty:
                self.logger.warning("No data was processed. Exiting.")
                self._log_summary(run_summary)
                return {}

            # Step 2: Sessionization
            self.logger.info("Starting session-based processing...")
            session_key = 'src_ip'
            if session_key not in processed_data.columns:
                raise RuntimeError(f"Session key '{session_key}' not found in data.")

            grouped_sessions = processed_data.groupby(session_key)
            run_summary['sessionization_stats'] = {
                'total_records_before_sessionization': len(processed_data),
                'total_sessions_created': len(grouped_sessions)
            }
            self.logger.info(f"Aggregated {len(processed_data)} records into {len(grouped_sessions)} sessions.")

            # Step 3: Feature Extraction and Detection
            self._ensure_model_is_ready(processed_data)
            
            processed_sessions = 0
            for i, (client_ip, session_df) in enumerate(grouped_sessions):
                self.logger.debug(f"Processing session {i+1}/{len(grouped_sessions)} for IP: {client_ip}")
                try:
                    session_features, _ = self.feature_extractor.extract_session_features(session_df, client_ip)
                    if not session_features:
                        continue

                    anomaly_score = self.model_manager.detect(session_features)
                    if anomaly_score is None:
                        continue
                    
                    all_session_results.append({
                        'client_ip': client_ip,
                        'features': session_features,
                        'anomaly_score': anomaly_score,
                        'anomaly': -1 if anomaly_score > self.config.get('model', {}).get('threshold', 0.5) else 1
                    })
                    processed_sessions += 1
                except Exception as e:
                    self.logger.error(f"Failed to process session for IP {client_ip}: {e}", exc_info=True)

            run_summary['detection_stats'] = {
                'sessions_processed_successfully': processed_sessions,
                'sessions_skipped_or_failed': len(grouped_sessions) - processed_sessions,
                'anomalies_detected': sum(1 for r in all_session_results if r['anomaly'] == -1)
            }

            if not all_session_results:
                self.logger.warning("No sessions were successfully processed.")
                self._log_summary(run_summary)
                return {}

            # Step 4: Generate Report
            report_path = None
            if self.config.get('visualization', {}).get('enable', True):
                self.logger.info("Generating report...")
                results_df = pd.DataFrame([r['features'] for r in all_session_results])
                anomalies = [res for res in all_session_results if res.get('anomaly') == -1]
                report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                report_path = self.visualizer.generate_report(results_df, anomalies, report_name, run_summary)
                self.logger.info(f"Report generated at: {report_path}")
            
            results = {'session_results': all_session_results, 'report_path': report_path, 'run_summary': run_summary}
            self.logger.info("Analysis completed successfully.")

        except Exception as e:
            self.logger.error(f"A fatal error occurred: {e}", exc_info=True)
            run_summary['error'] = str(e)
            results['error'] = str(e)
        
        self._log_summary(run_summary)
        return results

    def _log_summary(self, summary: Dict[str, Any]):
        """Logs a formatted summary of the processing run."""
        ingestion = summary.get('ingestion_stats', {})
        session = summary.get('sessionization_stats', {})
        detection = summary.get('detection_stats', {})

        log_message = "\n\n" + "="*60
        log_message += "\n" + "                  RUN PROCESSING SUMMARY"
        log_message += "\n" + "="*60
        log_message += "\n\n--- Data Ingestion ---\n"
        log_message += f"  - Files Found: {ingestion.get('total_files', 0)}\n"
        log_message += f"  - Packets Read: {ingestion.get('total_packets_read', 0)}\n"
        log_message += f"  - Packets Filtered/Skipped: {ingestion.get('total_packets_read', 0) - ingestion.get('packets_successfully_processed', 0)}\n"
        log_message += f"  - Packets Processed: {ingestion.get('packets_successfully_processed', 0)}\n"
        log_message += "\n--- Sessionization ---\n"
        log_message += f"  - Records Before Aggregation: {session.get('total_records_before_sessionization', 0)}\n"
        log_message += f"  - Unique Sessions (by src_ip): {session.get('total_sessions_created', 0)}\n"
        log_message += "\n--- Anomaly Detection ---\n"
        log_message += f"  - Sessions Processed: {detection.get('sessions_processed_successfully', 0)}\n"
        log_message += f"  - Sessions Skipped/Failed: {detection.get('sessions_skipped_or_failed', 0)}\n"
        log_message += f"  - Anomalies Detected: {detection.get('anomalies_detected', 0)}\n"
        
        if summary.get('error'):
            log_message += "\n--- Errors ---\n"
            log_message += f"  - A fatal error occurred: {summary['error']}\n"

        log_message += "\n" + "="*60 + "\n"
        self.logger.info(log_message)

    def _ensure_model_is_ready(self, data_for_training: pd.DataFrame):
        """Checks if a model is loaded, and trains one if not."""
        train_config = self.config.get('model', {}).get('train', {})
        if not train_config.get('force_retrain', False) and self.model_manager.load_model():
            self.logger.info("Successfully loaded existing model.")
            return
        
        self.logger.info("Training a new model...")
        try:
            self.logger.info("Extracting features for training...")
            session_key = 'src_ip'
            if session_key not in data_for_training.columns:
                raise RuntimeError(f"Session key '{session_key}' not found in training data.")

            all_features = []
            for client_ip, session_df in data_for_training.groupby(session_key):
                session_features, _ = self.feature_extractor.extract_session_features(session_df, client_ip)
                if session_features:
                    all_features.append(pd.DataFrame([session_features]))

            if not all_features:
                raise RuntimeError("Feature extraction yielded no data for training.")

            features = pd.concat(all_features, ignore_index=True)
            if features.empty:
                raise RuntimeError("Feature extraction yielded no data.")

            self.logger.info(f"Training model with {len(features)} records...")
            self.model_manager.train(features)
            self.logger.info("Model training completed.")

        except Exception as e:
            self.logger.error(f"Failed to train model: {e}", exc_info=True)
            raise RuntimeError("Model training failed") from e

# This file defines the main application class. 
# The command-line entry point is now in cli.py.
