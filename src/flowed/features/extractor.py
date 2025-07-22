"""Feature extraction module for the traffic detection system."""
import pandas as pd
import numpy as np
from loguru import logger
import ipaddress
import pkgutil
import inspect
from pathlib import Path
from typing import List, Optional, Dict, Any

from flowed.enrichers.base_enricher import BaseEnricher
from flowed.enrichers.cache_manager import CacheManager
from .calculators.base_calculator import BaseCalculator
from .calculators.profile_comparison_calculator import ProfileComparisonCalculator
from ..profiles.profile_store import ProfileStore

class FeatureExtractor:
    """Coordinates feature extraction by loading and applying enrichers and feature calculators."""

    def __init__(self, config: dict):
        self.config = config
        self.features_config = config.get('features', {})
        self.enrichment_config = config.get('enrichment', {'enabled': False})
        self.logger = logger.bind(module=__name__)
        
        self.enrichers = []
        self.calculators = []

        # Initialize Enrichment Layer
        if self.enrichment_config.get('enabled', False):
            self.logger.info("Data enrichment is enabled. Initializing...")
            cache_dir = self.enrichment_config.get('cache_dir', 'data/cache')
            self.cache_manager = CacheManager(cache_dir=cache_dir)
            self._load_enrichers()
        else:
            self.logger.info("Data enrichment is disabled.")

        # Initialize Feature Calculators
        self.logger.info("Initializing feature calculators...")
        self._load_calculators()

        # Initialize Profile-based components (for L3 features)
        self.logger.info("Initializing profile store and comparison calculator...")
        self.profile_store = ProfileStore()
        # The config for ProfileComparisonCalculator can be enhanced in the future
        self.profile_comparison_calculator = ProfileComparisonCalculator(config=self.features_config)

    def extract_session_features(self, session_df: pd.DataFrame, client_ip: str) -> (Optional[Dict[str, Any]], Optional[Dict[str, Any]]):
        """
        Runs the new session-centric feature extraction pipeline (L2 + L3).

        Args:
            session_df: DataFrame containing all packets/flows for a single session.
            client_ip: The client IP address for this session.

        Returns:
            A tuple containing:
            - A dictionary representing the final feature vector for the session.
            - The historical profile used for comparison.
        """
        if session_df.empty:
            self.logger.warning(f"Input DataFrame for session {client_ip} is empty. Skipping.")
            return None, None

        # 1. Calculate L2 features for the session
        session_with_l2_features = self._apply_l2_calculators(session_df)

        # 2. Aggregate L2 features into a single dictionary for the session
        # This simple aggregation takes the first row. More complex logic can be added.
        # For example, summing/averaging features if a session contains multiple flows.
        if session_with_l2_features.empty:
            self.logger.warning(f"L2 feature calculation returned empty df for {client_ip}. Skipping.")
            return None, None
        session_l2_features = session_with_l2_features.iloc[0].to_dict()
        session_l2_features['client_ip'] = client_ip # Ensure IP is in the feature set

        # Ensure timestamps are in a serializable format (string)
        for key, value in session_l2_features.items():
            if isinstance(value, pd.Timestamp):
                session_l2_features[key] = value.isoformat()

        # 3. Get historical profile for the IP
        historical_profile = self.profile_store.get_profile(client_ip)

        # 4. Calculate L3 features by comparing session to profile
        session_l3_features = self.profile_comparison_calculator.calculate(
            session_features=session_l2_features,
            historical_profile=historical_profile
        )

        # 5. Merge L2 and L3 features
        final_features = {**session_l2_features, **session_l3_features}

        # 6. Update the profile with the latest session info
        # This step is crucial for the system to learn and evolve its understanding of the client.
        self.profile_store.update_profile(client_ip, final_features)

        self.logger.debug(f"Successfully extracted {len(final_features)} features for session from {client_ip}")

        return final_features, historical_profile
        
        self.logger.success(f"Successfully extracted L2+L3 features for {client_ip}")
        return final_features, historical_profile

    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Runs the full feature extraction pipeline.
        1. Applies enrichment.
        2. Applies all configured feature calculators.
        
        Args:
            data: DataFrame with processed packet data or pre-aggregated flow data.
            
        Returns:
            DataFrame with all new features.
        """
        self.logger.info(f"Starting feature extraction pipeline on data with shape {data.shape}")
        self.logger.debug(f"Input DataFrame columns: {data.columns.tolist()}")

        if data.empty:
            self.logger.warning("Input DataFrame is empty, returning as is.")
            return pd.DataFrame()

        # Step 0: Prepare data (convert types, sort)
        data = self._prepare_data(data)

        # Step 1: Apply data enrichment
        if self.enrichers:
            self.logger.debug(f"Applying {len(self.enrichers)} enrichers")
            data = self._apply_enrichment(data)
            self.logger.debug(f"After enrichment: {data.columns.tolist()}")

        # Step 2: Apply L2 feature calculators
        data = self._apply_l2_calculators(data)

        # Final check for NaN values
        # if data.isnull().values.any():
        #     self.logger.warning("NaN values detected in features. Filling with 0.")
        #     data.fillna(0, inplace=True)

        # Step 3: Preprocess and clean final features
        if self.features_config.get('quality_control', {}).get('enabled', True):
            data = self._preprocess_features(data)

        self.logger.success(f"Feature extraction pipeline complete. Final shape: {data.shape}")
        return data

    def _apply_l2_calculators(self, df: pd.DataFrame) -> pd.DataFrame:
        """Applies all loaded L2 feature calculators to the DataFrame."""
        for calculator in self.calculators:
            calculator_name = calculator.__class__.__name__
            log = self.logger.bind(calculator=calculator_name)
            log.info(f"Applying {calculator_name}...")
            df = calculator.calculate(df)
            log.success(f"Finished applying {calculator_name}. DF shape: {df.shape}")
            self.logger.debug(f"Columns after {calculator_name}: {df.columns.tolist()}")
        return df

    def _prepare_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepares the DataFrame for feature calculation."""
        self.logger.info("Preparing data for feature extraction...")
        # Ensure timestamp is in datetime format
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df.sort_values('timestamp', inplace=True)
            self.logger.debug("Converted 'timestamp' to datetime and sorted DataFrame.")
        else:
            self.logger.warning("'timestamp' column not found. Cannot sort by time.")
        
        return df

    def _load_calculators(self):
        """Dynamically discover and load feature calculator classes."""
        calculators_path = Path(__file__).parent / 'calculators'
        calculators_config = self.features_config.get('calculators', {})
        
        # 验证配置格式
        if not isinstance(calculators_config, dict):
            self.logger.error(f"Invalid calculators config format: {type(calculators_config)}. Expected dict.")
            return
        
        for (_, name, _) in pkgutil.iter_modules([str(calculators_path)]):
            if name == 'base_calculator':
                continue
            
            try:
                module = __import__(f"flowed.features.calculators.{name}", fromlist=[''])
                for member_name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, BaseCalculator) and obj is not BaseCalculator:
                        calculator_key = name.replace('_calculator', '')
                        calculator_config = calculators_config.get(calculator_key, {})
                        
                        # 验证计算器配置
                        if not isinstance(calculator_config, dict):
                            self.logger.warning(f"Invalid config for calculator {calculator_key}: {calculator_config}")
                            calculator_config = {}
                        
                        # Only load if the calculator has an explicit config and is enabled
                        if calculator_key in self.features_config.get('calculators', {}) and calculator_config.get('enabled', False):
                            self.logger.info(f"Loading calculator: {member_name}")
                            self.calculators.append(obj(calculator_config))
                        else:
                            self.logger.debug(f"Calculator {calculator_key} is disabled")
            except Exception as e:
                self.logger.error(f"Failed to load calculator {name}: {e}", exc_info=True)


    def _load_enrichers(self):
        """Dynamically discover and load enricher classes."""
        enrichers_path = Path(__file__).parent.parent / 'enrichers'
        for (_, name, _) in pkgutil.iter_modules([str(enrichers_path)]):
            module = __import__(f"flowed.enrichers.{name}", fromlist=[''])
            for member_name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BaseEnricher) and obj is not BaseEnricher:
                    enricher_key = name.split('_')[0]
                    if self.enrichment_config.get('enrichers', {}).get(enricher_key, {}).get('enabled', False):
                        self.logger.info(f"Loading enricher: {member_name}")
                        enricher_config = self.enrichment_config['enrichers'][enricher_key]
                        self.enrichers.append(obj(enricher_config, self.cache_manager))

    def _preprocess_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Feature preprocessing and standardization."""
        self.logger.info("Starting feature preprocessing and cleaning...")
        
        # Handle infinite values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        self.logger.debug(f"Replaced infinite values in {len(numeric_cols)} numeric columns.")

        # Fill missing values
        # We can use a more sophisticated strategy from config if needed
        df[numeric_cols] = df[numeric_cols].fillna(0)
        self.logger.debug("Filled NaN values with 0.")

        # Outlier detection and handling (clipping)
        clip_config = self.features_config.get('quality_control', {}).get('clip_outliers', {})
        if clip_config.get('enabled', True):
            for col in numeric_cols:
                # Apply clipping to rate-based features or as specified
                if col.endswith('_per_sec') or col.endswith('_rate'):
                    upper_bound = df[col].quantile(clip_config.get('quantile', 0.99))
                    df[col] = df[col].clip(upper=upper_bound)
                    self.logger.trace(f"Clipped column '{col}' at quantile {clip_config.get('quantile', 0.99)}.")

        self.logger.success("Feature preprocessing complete.")
        return df

    def _apply_enrichment(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply all loaded enrichers to the DataFrame."""
        # Get unique IPs to minimize lookups
        src_ips = df['src_ip'].unique()
        dst_ips = df['dst_ip'].unique()
        all_ips = list(set(src_ips) | set(dst_ips))

        self.logger.info(f"Enriching {len(all_ips)} unique IP addresses...")

        for enricher in self.enrichers:
            enrichment_data = enricher.enrich_ips(all_ips)
            if not enrichment_data:
                continue

            # Convert enrichment data to a DataFrame for easy merging
            enrich_df = pd.DataFrame.from_dict(enrichment_data, orient='index')

            # Merge for source IPs
            src_enrich_df = enrich_df.add_prefix('src_')
            df = df.merge(src_enrich_df, left_on='src_ip', right_index=True, how='left')

            # Merge for destination IPs
            dst_enrich_df = enrich_df.add_prefix('dst_')
            df = df.merge(dst_enrich_df, left_on='dst_ip', right_index=True, how='left')

        return df
