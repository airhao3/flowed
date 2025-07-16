import pandas as pd
import numpy as np
from typing import Dict, Any
from loguru import logger

from .base_calculator import BaseCalculator

class FlowCalculator(BaseCalculator):
    """
    Calculates features based on traffic flows.

    A flow is defined by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates flow-based statistical features.

        Args:
            df: The input pandas DataFrame with packet data.

        Returns:
            The DataFrame with new flow-based features added.
        """
        self.logger.info("Calculating flow-based features...")

        # If flow features already exist, skip calculation
        if 'flow_pkt_count' in df.columns:
            self.logger.info("Flow features already exist. Skipping flow calculation.")
            return df

        # These are the columns required to calculate flow stats from packet data
        required_cols = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'frame_len']
        if not self.validate_columns(df, required_cols):
            return df

        # Define the flow key
        flow_key = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']

        # Sort by timestamp to correctly calculate time-based features like duration
        df_sorted = df.sort_values(by='timestamp').copy()

        # Calculate inter-arrival time for each packet within its flow
        df_sorted['inter_arrival_time'] = df_sorted.groupby(flow_key)['timestamp'].diff().dt.total_seconds().fillna(0)

        # Group by flow key
        grouped_flows = df_sorted.groupby(flow_key)

        # --- Feature Calculation ---
        self.logger.info(f"Aggregating features for {len(grouped_flows)} flows...")

        # Define aggregation rules
        aggregations = {
            'frame_len': ['count', 'sum', 'mean', 'std'],
            'timestamp': ['min', 'max'],
            'inter_arrival_time': ['mean', 'std', 'max'],
            # Add other packet-level features to aggregate here
        }

        # Dynamically add rules for features that exist in the dataframe
        http_rsp_cols = ['http_rsp_success', 'http_rsp_redirect', 'http_rsp_client_error', 'http_rsp_server_error']
        for col in http_rsp_cols:
            if col in df_sorted.columns:
                aggregations[col] = ['sum']
        
        # Perform aggregation
        flow_features = grouped_flows.agg(aggregations).reset_index()

        # Flatten the multi-level column names
        flow_features.columns = ['_'.join(col).strip() if isinstance(col, tuple) and col[1] else col[0] for col in flow_features.columns.values]
        # Rename the timestamp and other core columns for clarity and consistency
        rename_dict = {
            'timestamp_min': 'flow_start_time',
            'timestamp_max': 'flow_end_time',
            'frame_len_count': 'flow_pkt_count',
            'frame_len_sum': 'flow_byte_count',
            'frame_len_mean': 'flow_mean_pkt_size',
            'frame_len_std': 'flow_std_pkt_size',
            'inter_arrival_time_mean': 'flow_inter_arrival_time_mean',
            'inter_arrival_time_std': 'flow_inter_arrival_time_stddev',
            'inter_arrival_time_max': 'flow_inter_arrival_time_max',
        }
        flow_features.rename(columns=rename_dict, inplace=True)

        # Calculate duration and rates
        flow_features['flow_duration_seconds'] = (flow_features['flow_end_time'] - flow_features['flow_start_time']).dt.total_seconds()
        
        # Avoid division by zero for flows with a single packet (duration=0)
        flow_features['flow_pkts_per_sec'] = flow_features['flow_pkt_count'] / (flow_features['flow_duration_seconds'] + 1e-6)
        flow_features['flow_bytes_per_sec'] = flow_features['flow_byte_count'] / (flow_features['flow_duration_seconds'] + 1e-6)
        
        # Add critical anomaly detection features
        flow_features['flow_bytes_per_packet'] = flow_features['flow_byte_count'] / flow_features['flow_pkt_count']
        
        # Flow direction analysis (forward vs backward)
        # This requires additional packet-level analysis which we'll add to the aggregation
        
        # Flow activity patterns
        flow_features['flow_is_short'] = (flow_features['flow_duration_seconds'] < 1.0).astype(int)
        flow_features['flow_is_long'] = (flow_features['flow_duration_seconds'] > 300.0).astype(int)
        flow_features['flow_is_single_packet'] = (flow_features['flow_pkt_count'] == 1).astype(int)
        
        # Packet size variance (high variance might indicate different types of data)
        flow_features['flow_pkt_size_variance'] = flow_features['flow_std_pkt_size'] ** 2
        flow_features['flow_pkt_size_cv'] = flow_features['flow_std_pkt_size'] / (flow_features['flow_mean_pkt_size'] + 1e-6)
        
        # --- Merge features back into the original DataFrame ---
        self.logger.info("Merging flow features back to the main DataFrame...")
        
        # Select only the new features to merge
        # The original flow_key is already in flow_features after reset_index()
        merge_cols = [col for col in flow_features.columns if col not in df.columns or col in flow_key]
        df = df.merge(flow_features[merge_cols], on=flow_key, how='left')

        self.logger.success("Finished calculating flow-based features.")
        return df
