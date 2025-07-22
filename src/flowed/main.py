#!/usr/bin/env python3
"""
Network Traffic Anomaly Detection System

This module provides the main entry point for the traffic detection system.
"""
import sys
import os
import time
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any
import json
from loguru import logger
from box import Box
import pandas as pd

from flowed.utils.config import load_config, setup_logging
from flowed.data.collector import DataCollector
from flowed.data.arkime_collector import ArkimeCollector
from flowed.data.ingestor import DataIngestor
from flowed.features.extractor import FeatureExtractor
from flowed.models import ModelManager
from flowed.data.sequence_builder import SequenceBuilder
from flowed.visualization.dashboard import ResultVisualizer

class TrafficDetector:
    """Main class for the Traffic Detection System."""

    def __init__(self, config: Box):
        """Initialize the Traffic Detection System.

        Args:
            config: A Box object containing the application configuration.
        """
        self.config = config
        logger.info("TrafficDetector initialized with pre-loaded configuration.")

        self.feature_extractor = FeatureExtractor(self.config)
        self.model_manager = ModelManager(self.config)
        self.data_ingestor = DataIngestor(self.config['data_ingestion'])
        
        self.detection_mode = self.config['model']['detection_mode']
        self.sequence_builder = None
        if self.detection_mode in ['lstm_autoencoder', 'collaborative']:
            lstm_params = self.config['model']['lstm_autoencoder']['params']
            self.sequence_builder = SequenceBuilder(sequence_length=lstm_params['sequence_length'])
            logger.info(f"SequenceBuilder initialized for '{self.detection_mode}' mode.")

        self.visualizer = ResultVisualizer(self.config['visualization'])
        logger.info("Traffic Detection System initialized")

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
            logger.info("Starting data collection...")
            data_source = self.config['data']['source']
            processed_data = None
            ingestion_stats = {}

            if data_source == 'arkime':
                # ... (Arkime implementation would also need to return stats)
                pass
            elif data_source == 'pcap':
                pcap_config = self.config['data']['pcap']
                collector = DataCollector(pcap_config)
                raw_files = collector.collect()
                if not raw_files:
                    logger.warning("No new PCAP files found. Exiting.")
                    return {}
                logger.info(f"Collected {len(raw_files)} PCAP files. Ingesting...")
                processed_data, ingestion_stats = self.data_ingestor.process_files(raw_files)
            
            run_summary['ingestion_stats'] = ingestion_stats

            if processed_data is None or processed_data.empty:
                logger.warning("No data was processed. Exiting.")
                self._log_summary(run_summary)
                return {}

            # Step 2: Sessionization
            logger.info("Starting session-based processing...")
            session_key = 'src_ip'
            if session_key not in processed_data.columns:
                raise RuntimeError(f"Session key '{session_key}' not found in data.")

            grouped_sessions = processed_data.groupby(session_key)
            run_summary['sessionization_stats'] = {
                'total_records_before_sessionization': len(processed_data),
                'total_sessions_created': len(grouped_sessions)
            }
            logger.info(f"Aggregated {len(processed_data)} records into {len(grouped_sessions)} sessions.")
            
            # 将会话数据转换为列表并保存为实例变量，供训练模型使用
            self.sessions = []
            for _, session_df in grouped_sessions:
                session_dict = session_df.to_dict('records')[0] if not session_df.empty else {}
                self.sessions.append(session_dict)
            logger.debug(f"Stored {len(self.sessions)} sessions as instance variable for model training")

            # Step 3: Feature Extraction and Detection
            self._ensure_model_is_ready()
            
            processed_sessions = 0
            for i, (client_ip, session_df) in enumerate(grouped_sessions):
                logger.debug(f"Processing session {i+1}/{len(grouped_sessions)} for IP: {client_ip}")
                self._process_and_detect(session_df)

            run_summary['detection_stats'] = {
                'sessions_processed_successfully': processed_sessions,
                'sessions_skipped_or_failed': len(grouped_sessions) - processed_sessions,
                'anomalies_detected': sum(1 for r in all_session_results if r['anomaly'] == -1)
            }

            if not all_session_results:
                logger.warning("No sessions were successfully processed.")
                self._log_summary(run_summary)
                return {}

            # Step 4: Generate Report
            report_path = None
            if self.config['visualization']['enable']:
                logger.info("Generating report...")
                results_df = pd.DataFrame([r['features'] for r in all_session_results])
                anomalies = [res for res in all_session_results if res.get('anomaly') == -1]
                report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                report_path = self.visualizer.generate_report(results_df, anomalies, report_name, run_summary)
                logger.info(f"Report generated at: {report_path}")
            
            results = {'session_results': all_session_results, 'report_path': report_path, 'run_summary': run_summary}
            logger.info("Analysis completed successfully.")

        except Exception as e:
            logger.error(f"A fatal error occurred: {e}", exc_info=True)
            run_summary['error'] = str(e)
            results['error'] = str(e)
        
        self._log_summary(run_summary)
        return results

    def _process_and_detect(self, session_df):
        # 从session_df中提取client_ip (即源IP)
        if session_df.empty:
            logger.warning("Cannot process empty session DataFrame.")
            return
        
        # 假设session_df按源IP分组，所有行都是同一个client_ip
        try:
            if hasattr(session_df['src_ip'], 'iloc'):
                client_ip = session_df['src_ip'].iloc[0]
            else:
                client_ip = str(session_df['src_ip'])
            logger.debug(f"Processing session for client IP: {client_ip}")
        except Exception as e:
            logger.error(f"Error extracting client IP: {e}")
            client_ip = "unknown"
            logger.debug(f"Using default client IP: {client_ip}")
        
        # 传递client_ip参数给extract_session_features
        features, _ = self.feature_extractor.extract_session_features(session_df, client_ip)
        if features is None:
            return

        # 检查特征类型并转换为DataFrame
        if isinstance(features, dict):
            logger.debug(f"Extracted features for detection (dict): {len(features)} features")
            logger.trace(f"Features content: {features}")
            
            # 将字典转换为DataFrame，因为ModelManager中的预测方法期期DataFrame
            import pandas as pd
            features_df = pd.DataFrame([features])
            logger.debug(f"Converted features dict to DataFrame with shape {features_df.shape}")
        else:
            # 如果已经是DataFrame，直接使用
            features_df = features
            logger.debug(f"Using existing DataFrame with shape {features_df.shape if hasattr(features_df, 'shape') else 'unknown'}")
        
        logger.trace(f"Features DataFrame content:\n{features_df}")
        
        scores, results = self.model_manager.detect(features_df, self.sequence_builder)

        if scores is None:
            logger.info("Detection yielded no result (e.g., not enough sequence data).")
            return

        score = scores[0]
        result_type = results[0]
        
        # 获取client_ip时增加类型兼容性处理
        try:
            if hasattr(features['client_ip'], 'iloc'):
                client_ip = features['client_ip'].iloc[0]
            else:
                client_ip = str(features['client_ip'])
        except Exception as e:
            logger.error(f"Error extracting client IP for result: {e}")
            client_ip = "unknown"

        if result_type == 'isolation_forest_high_risk':
            logger.critical(f"HIGH RISK ANOMALY | IP: {client_ip} | Score: {score:.2f} | Reason: Static feature anomaly detected by Isolation Forest.")
        elif result_type == 'lstm_sequence_anomaly':
            logger.critical(f"CRITICAL ANOMALY | IP: {client_ip} | Score: {score:.4f} | Reason: Behavioral sequence anomaly confirmed by LSTM.")
        elif result_type == 'normal':
            logger.info(f"Normal traffic | IP: {client_ip} | IF Score: {score:.2f}")
        elif result_type == 'isolation_forest' or result_type == 'lstm_autoencoder':
            # Handle single-model mode detection results
            logger.warning(f"Anomaly detected | IP: {client_ip} | Score: {score:.4f} | Model: {result_type}")
        else:
            logger.info(f"Detection result: {result_type} for IP {client_ip}")

    def _ensure_model_is_ready(self):
        try:
            logger.debug("Starting _ensure_model_is_ready method...")
            if not self.model_manager.load_model():
                logger.warning("Failed to load one or more pre-trained models. Checking for training data.")
                
                logger.debug(f"Config type: {type(self.config)}")
                logger.debug(f"Config has 'model' attribute: {hasattr(self.config, 'model')}")
                logger.debug(f"Config.model has 'train' attribute: {hasattr(self.config.model, 'train') if hasattr(self.config, 'model') else False}")
                
                training_data_path = self.config.model.train.dataset
                logger.debug(f"Training data path: {training_data_path}")
                
                if not Path(training_data_path).exists():
                    # 如果训练数据不存在，尝试从当前处理的会话数据生成
                    logger.info(f"Training data not found at {training_data_path}. Generating from processed sessions...")
                    
                    # 确保目录存在
                    os.makedirs(os.path.dirname(training_data_path), exist_ok=True)
                    logger.debug(f"Created directory: {os.path.dirname(training_data_path)}")
                    
                    if hasattr(self, 'sessions') and self.sessions and len(self.sessions) > 0:
                        # 从当前会话数据中提取特征
                        logger.info(f"Exporting features from {len(self.sessions)} processed sessions...")
                        features_list = []
                        
                        for session in self.sessions:
                            # 只提取数值特征，跳过非数值字段
                            feature_dict = {}
                            for key, value in session.items():
                                if isinstance(value, (int, float)) and not isinstance(value, bool):
                                    feature_dict[key] = value
                            
                            features_list.append(feature_dict)
                        
                        if not features_list:
                            raise ValueError("No numeric features found in processed sessions for training.")
                        
                        # 创建DataFrame并保存为CSV
                        training_df = pd.DataFrame(features_list)
                        training_df.to_csv(training_data_path, index=False)
                        logger.info(f"Generated training dataset with {len(training_df)} samples and saved to {training_data_path}")
                    else:
                        raise FileNotFoundError("No processed sessions available to generate training data. Please process data first.")
                
                logger.info(f"Loading training data from {training_data_path}...")
                training_df = pd.read_csv(training_data_path)
                
                # 选择数值特征用于训练
                numeric_features = training_df.select_dtypes(include='number')
                logger.info(f"Selected {numeric_features.shape[1]} numeric features for training.")
                
                # 训练模型
                self.model_manager.train_model_if_needed(numeric_features)
            else:
                logger.info("All required models loaded successfully. Ready for detection.")
        except Exception as e:
            logger.error(f"Error in _ensure_model_is_ready: {e}")
            # 打印更详细的异常信息以便调试
            import traceback
            logger.debug(f"Exception traceback: {traceback.format_exc()}")
            raise

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
        logger.info(log_message)

# This file defines the main application class. 
# The command-line entry point is now in cli.py.
