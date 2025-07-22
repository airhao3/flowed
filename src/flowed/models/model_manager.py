import os
import json
import joblib
from pathlib import Path
from typing import Optional, Dict, Any, Union

import pandas as pd
import numpy as np
from loguru import logger
from sklearn.ensemble import IsolationForest
from tensorflow.keras.models import load_model as keras_load_model

from .lstm_autoencoder import LSTMAutoencoder


class ModelManager:
    """
    Manages the lifecycle of anomaly detection models, including creation, training,
    saving, loading, and inference for multiple model types.
    """

    def __init__(self, config):
        self.config = config
        self.detection_mode = self.config.model.detection_mode
        self.models = {}
        self.scalers = {}
        self.loaded_models = {}  # 用于存储已加载的模型
        self.logger = logger  # 添加logger属性
        self.models_dir = os.path.join(self.config.model.save_dir, 'models')  # 添加models_dir属性
        
        # 确保模型目录存在
        os.makedirs(self.models_dir, exist_ok=True)

        # Load parameters for collaborative mode
        if self.detection_mode == 'collaborative':
            collab_params = self.config.model.collaborative.params
            self.high_risk_threshold = collab_params.high_risk_threshold
            self.suspicious_threshold = collab_params.suspicious_threshold
            self.lstm_anomaly_threshold = collab_params.lstm_anomaly_threshold

        self.model_configs = {
            'isolation_forest': {
                'model_path': os.path.join(self.config.model.save_dir, 'model.joblib'),
                'scaler_path': os.path.join(self.config.model.save_dir, 'isolation_forest_scaler.joblib')
            },
            'lstm_autoencoder': {
                'model_path': os.path.join(self.config.model.save_dir, 'lstm_autoencoder.h5'),
                'scaler_path': os.path.join(self.config.model.save_dir, 'lstm_autoencoder_scaler.joblib')
            }
        }

        os.makedirs(self.config.model.save_dir, exist_ok=True)

    def load_model(self):
        model_types_to_load = []
        if self.detection_mode == 'collaborative':
            model_types_to_load = ['isolation_forest', 'lstm_autoencoder']
        else:
            model_types_to_load = [self.detection_mode]

        all_models_loaded = True
        for model_type in model_types_to_load:
            paths = self.model_configs[model_type]
            model_path = paths['model_path']
            scaler_path = paths['scaler_path']

            logger.info(f"Attempting to load model '{model_type}' from {model_path}")
            if not os.path.exists(model_path):
                logger.warning(f"Model file for '{model_type}' not found at {model_path}. Model needs to be trained.")
                all_models_loaded = False
                continue

            try:
                if model_type == 'isolation_forest':
                    self.models['isolation_forest'] = joblib.load(model_path)
                    logger.success(f"'{model_type}' model loaded successfully.")
                elif model_type == 'lstm_autoencoder':
                    self.models['lstm_autoencoder'] = keras_load_model(model_path)
                    if os.path.exists(scaler_path):
                        self.scalers['lstm_autoencoder'] = joblib.load(scaler_path)
                        logger.success(f"'{model_type}' model and scaler loaded successfully.")
                    else:
                        logger.warning(f"Scaler for '{model_type}' not found at {scaler_path}. It might need to be created during training.")
            except Exception as e:
                logger.error(f"Failed to load model '{model_type}' from {model_path}: {e}")
                self.models[model_type] = None
                all_models_loaded = False

        return all_models_loaded

    def train(self, model_type: str, data: Union[pd.DataFrame, np.ndarray]):
        """Train a new model and save it."""
        self.logger.info(f"Starting training for {model_type} model...")
        
        if model_type == 'isolation_forest':
            self._train_isolation_forest(data)
        elif model_type == 'lstm_autoencoder':
            self._train_lstm_autoencoder(data)
        else:
            self.logger.error(f"Unknown model type '{model_type}' for training.")
            raise ValueError(f"Unsupported model type: {model_type}")

    def _train_isolation_forest(self, features: pd.DataFrame):
        """Handles training for the Isolation Forest model."""
        self.logger.info("Training Isolation Forest model...")
        model_params = self.config.model.isolation_forest.params if hasattr(self.config.model, 'isolation_forest') and hasattr(self.config.model.isolation_forest, 'params') else {}
        model_instance = IsolationForest(**model_params)

        # 选择数值型特征并处理缺失值
        numeric_features_df = features.select_dtypes(include='number')
        
        # 检查并记录NaN值
        nan_columns = numeric_features_df.columns[numeric_features_df.isna().any()].tolist()
        if nan_columns:
            self.logger.warning(f"Found NaN values in columns: {nan_columns}")
            self.logger.info("Filling NaN values for Isolation Forest training...")
            
            # 计算每列NaN的比例
            nan_percentages = numeric_features_df.isna().mean() * 100
            for col, pct in nan_percentages[nan_percentages > 0].items():
                self.logger.debug(f"Column '{col}' has {pct:.1f}% NaN values")
            
            # 适应不同的填充策略
            # 1. 对于TCP特征，可能是由于非TCP流量导致的缺失，用0填充
            tcp_columns = [col for col in nan_columns if col.startswith('tcp_')]
            if tcp_columns:
                self.logger.info(f"Filling TCP-related features with 0: {tcp_columns}")
                numeric_features_df[tcp_columns] = numeric_features_df[tcp_columns].fillna(0)
            
            # 2. 对于其他特征，采用中位数填充
            other_nan_columns = [col for col in nan_columns if not col.startswith('tcp_')]
            if other_nan_columns:
                self.logger.info(f"Filling other features with median: {other_nan_columns}")
                for col in other_nan_columns:
                    median_val = numeric_features_df[col].median()
                    # 如果中位数也是NaN，则使用0填充
                    fill_val = 0 if pd.isna(median_val) else median_val
                    numeric_features_df[col] = numeric_features_df[col].fillna(fill_val)
            
            # 检查是否还有NaN值
            remaining_nans = numeric_features_df.isna().sum().sum()
            if remaining_nans > 0:
                self.logger.warning(f"Still found {remaining_nans} NaN values after filling. Using 0 to fill all remaining.")
                numeric_features_df = numeric_features_df.fillna(0)
                
            self.logger.info(f"Successfully processed data with {len(numeric_features_df)} samples for training.")
        
        self.logger.debug(f"Training Isolation Forest with {len(numeric_features_df)} samples and {numeric_features_df.shape[1]} features")
        
        # 训练模型
        model_instance.fit(numeric_features_df.values)  # 使用.values避免pandas索引问题
        self.logger.info("Isolation Forest model training complete.")
        
        # 保存模型
        model_path = os.path.join(self.models_dir, 'isolation_forest.joblib')
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(model_instance, model_path)
        self.logger.info(f"Isolation Forest model saved to {model_path}")
        
        # 将模型加入到已加载模型字典
        self.loaded_models['isolation_forest'] = model_instance
        return model_instance

    def _train_lstm_autoencoder(self, data):
        """Handles training for the LSTM Autoencoder model."""
        self.logger.info("Training LSTM Autoencoder model...")
        
        # Extract configuration parameters
        params = self.config.model.lstm_autoencoder.params
        sequence_length = params.get('sequence_length', 50)
        encoding_dim = params.get('encoding_dim', 32)
        epochs = params.get('epochs', 50)
        batch_size = params.get('batch_size', 64)
        lstm_layers = params.get('lstm_layers', 1)
        dropout_rate = params.get('dropout_rate', 0.0)
        
        self.logger.debug(f"LSTM parameters: {{'sequence_length': {sequence_length}, 'encoding_dim': {encoding_dim}, 'epochs': {epochs}, 'batch_size': {batch_size}, 'lstm_layers': {lstm_layers}, 'dropout_rate': {dropout_rate}}}")
        self.logger.debug(f"Training LSTM with {len(data)} samples and {data.shape[1]} features")
        
        # 创建LSTM模型
        lstm_model = LSTMAutoencoder(
            sequence_length=sequence_length,
            num_features=data.shape[1],
            encoding_dim=encoding_dim,
            epochs=epochs,
            batch_size=batch_size,
            lstm_layers=lstm_layers,
            dropout_rate=dropout_rate
        )
        
        # 将2D数据转换为3D序列数据
        # 由于样本量较小，我们创建重叠滑动窗口来增加训练样本
        self.logger.info(f"Converting 2D data (shape {data.shape}) to 3D sequences for LSTM training")
        
        if len(data) < sequence_length:
            self.logger.warning(f"Not enough samples ({len(data)}) for sequence_length ({sequence_length}). Creating synthetic sequences...")
            # 数据不足，通过重复样本创建合成序列
            num_samples = max(1, int(sequence_length / len(data)) + 1)  # 确保至少创建1个样本
            data_3d = np.zeros((num_samples, sequence_length, data.shape[1]))
            
            # 填充序列
            for i in range(num_samples):
                # 循环复制现有样本直到填满序列长度
                for j in range(sequence_length):
                    data_3d[i, j] = data.iloc[j % len(data)].values
            
            self.logger.info(f"Created {num_samples} synthetic sequences with shape {data_3d.shape}")
        else:
            # 数据充足，创建滑动窗口
            stride = max(1, len(data) // 10)  # 用总样本的1/10作为步长
            max_sequences = min(30, (len(data) - sequence_length) // stride + 1)  # 限制最大序列数
            
            self.logger.info(f"Creating sliding window sequences with stride {stride}, up to {max_sequences} sequences")
            data_3d = np.zeros((max_sequences, sequence_length, data.shape[1]))
            
            # 填充滑动窗口序列
            for i in range(max_sequences):
                start_idx = i * stride
                end_idx = start_idx + sequence_length
                if end_idx <= len(data):
                    data_3d[i] = data.iloc[start_idx:end_idx].values
            
            self.logger.info(f"Created {max_sequences} sliding window sequences with shape {data_3d.shape}")
        
        # 训练模型
        self.logger.info(f"Training LSTM with 3D data shape: {data_3d.shape}")
        lstm_model.train(data_3d)
        
        # 保存模型
        model_path = os.path.join(self.models_dir, 'lstm_autoencoder.h5')
        lstm_model.model.save(model_path)
        self.lstm_autoencoder_model = lstm_model
        self.logger.info(f"LSTM Autoencoder model saved to {model_path}")
        # 将模型和标准化器加入到已加载字典
        self.loaded_models['lstm_autoencoder'] = lstm_model.model
        self.scalers['lstm_autoencoder'] = lstm_model.scaler
        
        return lstm_model.model

    def train_model_if_needed(self, data):
        """Train models based on detection_mode if they are not already loaded.
        
        This method ensures all required models for the current detection mode are trained.
        
        Args:
            data: DataFrame containing the training features
        """
        self.logger.info(f"Training models for detection mode: {self.detection_mode}")
        
        if self.detection_mode == 'isolation_forest' or self.detection_mode == 'collaborative':
            # Isolation Forest is needed for both standalone and collaborative modes
            if 'isolation_forest' not in self.loaded_models:
                self._train_isolation_forest(data)
        
        if self.detection_mode == 'lstm_autoencoder' or self.detection_mode == 'collaborative':
            # LSTM is needed for both standalone and collaborative modes
            if 'lstm_autoencoder' not in self.loaded_models:
                self._train_lstm_autoencoder(data)
        
        self.logger.info("Model training completed for all required models.")
        return True

    def detect(self, features, sequence_builder=None):
        if self.detection_mode == 'collaborative':
            return self._collaborative_predict(features, sequence_builder)
        elif self.detection_mode == 'isolation_forest':
            return self._predict_isolation_forest(features)
        elif self.detection_mode == 'lstm_autoencoder':
            # Note: Standalone LSTM detection requires pre-built sequences.
            return self._predict_lstm_autoencoder(features, sequence_builder)
            
    def _collaborative_predict(self, features, sequence_builder):
        # Step 1: Fast screening with Isolation Forest
        if_scores, _ = self._predict_isolation_forest(features)
        if_score = if_scores[0] # Assuming one feature set at a time
        
        # 增加类型检查和兼容性处理
        try:
            # 如果是DataFrame类型
            if hasattr(features['client_ip'], 'iloc'):
                client_ip = features['client_ip'].iloc[0]
            else:
                client_ip = str(features['client_ip'])
                
            # 处理特征
            if hasattr(features, 'drop') and callable(features.drop):
                # DataFrame类型
                if hasattr(features.iloc[0], 'to_dict'):
                    features_dict = features.drop('client_ip', axis=1).iloc[0].to_dict()
                else:
                    features_dict = {k: v for k, v in features.items() if k != 'client_ip'}
            else:
                # 其他类型，尝试将其转换为字典
                features_dict = {k: v for k, v in features.items() if k != 'client_ip'}
                
            self.logger.debug(f"Processing features for client_ip: {client_ip} with {len(features_dict)} features")
        except Exception as e:
            self.logger.error(f"Error extracting client_ip and features: {e}")
            # 尝试其他方式提取client_ip
            client_ip = str(features.get('client_ip', 'unknown'))
            features_dict = {}
            
        # Always update the sequence builder for context
        sequence_builder.add(client_ip, features_dict)
            
        # Step 2: Triage based on score
        if if_score >= self.high_risk_threshold:
            self.logger.warning(f"High risk event detected by Isolation Forest for IP {client_ip} (Score: {if_score:.2f})")
            return np.array([if_score]), ['isolation_forest_high_risk']

        if if_score >= self.suspicious_threshold:
            logger.info(f"Suspicious event for IP {client_ip} (Score: {if_score:.2f}). Triggering LSTM analysis.")
            # Step 3: In-depth analysis with LSTM for suspicious events
            if sequence_builder.is_ready(client_ip):
                lstm_score, _ = self._predict_lstm_autoencoder(features, sequence_builder, use_existing_sequence=True)
                if lstm_score[0] > self.lstm_anomaly_threshold:
                    logger.warning(f"Sequence anomaly confirmed by LSTM for IP {client_ip} (Error: {lstm_score[0]:.4f})")
                    return lstm_score, ['lstm_sequence_anomaly']
            else:
                 logger.info(f"Not enough sequence data for LSTM analysis for IP {client_ip}. Passing as low risk for now.")

        # If all checks pass, mark as normal
        return np.array([if_score]), ['normal']

    def _predict_isolation_forest(self, features):
        model = self.loaded_models.get('isolation_forest')
        if not model:
            logger.error("Isolation Forest model not loaded.")
            return np.array([-1]), [None]
        
        try:
            # Convert input to DataFrame if it's not already
            if not isinstance(features, pd.DataFrame):
                features = pd.DataFrame([features])
            
            # Get the feature names the model was trained with
            if hasattr(model, 'feature_names_in_'):
                model_features = model.feature_names_
            else:
                # If model doesn't have feature names, we need to ensure we use the same features as training
                # This is a fallback and might need adjustment based on your training code
                model_features = [
                    'flow_pkt_count', 'flow_byte_count', 'flow_duration_seconds',
                    'flow_pkts_per_sec', 'flow_bytes_per_sec', 'flow_bytes_per_packet',
                    'src_host_pkt_count_win', 'src_host_byte_count_win',
                    'src_host_distinct_dst_ips_win', 'src_host_distinct_dst_ports_win',
                    'src_host_dst_port_entropy_win', 'dst_host_pkt_count_win',
                    'dst_host_byte_count_win', 'dst_host_distinct_src_ips_win',
                    'tcp_flag_syn', 'tcp_flag_ack'
                ]
            
            # Create a DataFrame with the expected features
            features_for_prediction = pd.DataFrame()
            
            # Only include features that exist in both the input and the model
            for feature in model_features:
                if feature in features.columns:
                    features_for_prediction[feature] = features[feature]
                else:
                    # If a feature is missing, log a warning and fill with 0
                    self.logger.warning(f"Feature '{feature}' not found in input. Filling with 0.")
                    features_for_prediction[feature] = 0
            
            self.logger.debug(f"Processing isolation forest prediction with {len(model_features)} features")
            
            # Ensure we have the right number of features
            if len(features_for_prediction.columns) != len(model_features):
                self.logger.error(f"Feature count mismatch. Expected {len(model_features)} features, got {len(features_for_prediction.columns)}")
                return np.array([-1]), [None]
                
        except Exception as e:
            self.logger.error(f"Error preparing features for isolation forest prediction: {e}")
            return np.array([-1]), [None]
        
        # Handle potential NaN values
        if features_for_prediction.isna().any().any():
            self.logger.warning("NaN values found in features for prediction. Filling with 0.")
            features_for_prediction = features_for_prediction.fillna(0)

        # 调用模型进行预测
        try:
            scores = model.decision_function(features_for_prediction)
            # Normalize scores to be 0-1 where 1 is more anomalous
            normalized_scores = (0.5 - scores) # In IF, scores are <= 0. Closer to -1 is more anomalous.
            return normalized_scores, ['isolation_forest'] * len(features)

        except Exception as e:
            self.logger.error(f"Error predicting with Isolation Forest: {e}")
            return np.array([-1]), [None]

    def _predict_lstm_autoencoder(self, features, sequence_builder, use_existing_sequence=False):
        model = self.models.get('lstm_autoencoder')
        scaler = self.scalers.get('lstm_autoencoder')
        if not model or not scaler:
            logger.error("LSTM model or scaler not loaded.")
            return np.array([-1]), [None]

        # 增加类型兼容性处理
        try:
            # 如果是DataFrame类型
            if hasattr(features['client_ip'], 'iloc'):
                client_ip = features['client_ip'].iloc[0]
            else:
                client_ip = str(features['client_ip'])
                
            # 处理特征
            if hasattr(features, 'drop') and callable(features.drop):
                # DataFrame类型
                if hasattr(features.iloc[0], 'to_dict'):
                    features_dict = features.drop('client_ip', axis=1).iloc[0].to_dict()
                else:
                    features_dict = {k: v for k, v in features.items() if k != 'client_ip'}
            else:
                # 其他类型，尝试将其转换为字典
                features_dict = {k: v for k, v in features.items() if k != 'client_ip'}
                
            self.logger.debug(f"Processing LSTM features for client_ip: {client_ip} with {len(features_dict)} features")
        except Exception as e:
            self.logger.error(f"Error extracting client_ip and features for LSTM: {e}")
            # 尝试其他方式提取client_ip
            client_ip = str(features.get('client_ip', 'unknown'))
            features_dict = {}
        
        if not use_existing_sequence:
            sequence_builder.add(client_ip, features_dict)

        if sequence_builder.is_ready(client_ip):
            sequence = sequence_builder.get_sequence(client_ip)
            sequence_df = pd.DataFrame(sequence)
            
            scaled_sequence = scaler.transform(sequence_df)
            # The LSTM model itself should handle prediction logic
            # Assuming the model is an instance of our LSTMAutoencoder class which has a predict method returning MSE
            mse = self.models['lstm_autoencoder'].predict(np.array([scaled_sequence]))
            return mse, ['lstm_autoencoder']
        else:
            return np.array([-1]), [None] # Not enough data

    def save_model(self, model_type: str, model_container: Any) -> bool:
        """Save the provided model container to disk."""
        if not model_container or not hasattr(model_container, 'model'):
            self.logger.error("Invalid model container provided. Nothing to save.")
            return False

        try:
            model_dir = self._get_model_path(model_type)
            features_path = model_dir / 'feature_names.json'

            with open(features_path, 'w') as f:
                json.dump(model_container.feature_names_in_, f, indent=4)
            self.logger.info(f"Saved {len(model_container.feature_names_in_)} feature names to {features_path}")

            if model_type == 'isolation_forest':
                model_path = model_dir / 'model.joblib'
                self.logger.info(f"Saving IsolationForest model to {model_path}")
                joblib.dump(model_container.model, model_path)
            
            elif model_type == 'lstm_autoencoder':
                model_path = model_dir / 'model.h5'
                self.logger.info(f"Saving LSTM Autoencoder model to {model_path}")
                # We save the internal Keras model, not the wrapper class
                model_container.model.model.save(model_path)

            self.logger.success(f"Successfully saved '{model_type}' model to {model_dir}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving '{model_type}' model to {model_dir}: {e}", exc_info=True)
            return False
