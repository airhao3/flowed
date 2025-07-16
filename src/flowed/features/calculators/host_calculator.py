import pandas as pd
from typing import Dict, Any
from loguru import logger

from .base_calculator import BaseCalculator

class HostCalculator(BaseCalculator):
    """
    Calculates features based on host behavior within time windows.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)
        # Make the time window configurable
        self.time_window = self.config.get('time_window', '1s')

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates host-based statistical features over a time window.

        Args:
            df: The input pandas DataFrame with packet data.

        Returns:
            The DataFrame with new host-based features added.
        """
        self.logger.info(f"Calculating host-based features with a '{self.time_window}' window...")

        required_cols = ['timestamp', 'src_ip', 'dst_ip', 'frame_len']
        if not self.validate_columns(df, required_cols):
            return df

        df_copy = df.copy()
        df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
        df_copy.set_index('timestamp', inplace=True)

        # --- Source Host Features ---
        # Define base aggregations for source hosts
        src_aggs = {
            "frame_len": ["count", "sum"],
            "dst_ip": ["nunique"],
            "dst_port": ["nunique"],
        }

        # Dynamically add DNS feature aggregations if columns exist
        dns_cols = {'dns_qry_name_len': ['mean', 'std'], 'dns_qry_name_entropy': ['mean', 'std']}
        for col, aggs in dns_cols.items():
            if col in df_copy.columns:
                src_aggs[col] = aggs

        # Dynamically add TLS feature aggregations if columns exist
        if 'tls_ja3' in df_copy.columns:
            src_aggs['tls_ja3'] = ['nunique']

        src_host_features = df_copy.groupby(['src_ip', pd.Grouper(freq=self.time_window)]).agg(src_aggs)
        
        # Flatten multi-index columns and rename for clarity
        src_host_features.columns = ['_'.join(col).strip() for col in src_host_features.columns.values]
        src_host_features.rename(columns={
            'frame_len_count': 'src_host_pkt_count_win',
            'frame_len_sum': 'src_host_byte_count_win',
            'dst_ip_nunique': 'src_host_distinct_dst_ips_win',
            'dst_port_nunique': 'src_host_distinct_dst_ports_win',
            'dns_qry_name_len_mean': 'src_host_dns_qry_len_mean_win',
            'dns_qry_name_len_std': 'src_host_dns_qry_len_std_win',
            'dns_qry_name_entropy_mean': 'src_host_dns_qry_entropy_mean_win',
            'dns_qry_name_entropy_std': 'src_host_dns_qry_entropy_std_win',
            'tls_ja3_nunique': 'src_host_distinct_ja3_win',
        }, inplace=True)
        src_host_features.reset_index(inplace=True)

        # --- Destination Host Features ---
        dst_host_features = df_copy.groupby(['dst_ip', pd.Grouper(freq=self.time_window)]).agg(
            dst_host_pkt_count_win=("frame_len", "count"),
            dst_host_byte_count_win=("frame_len", "sum"),
            dst_host_distinct_src_ips_win=("src_ip", "nunique"),
        ).reset_index()

        # Merge features back. This requires aligning the original timestamp to the window.
        df_copy.reset_index(inplace=True)
        df_copy['time_window'] = df_copy['timestamp'].dt.floor(self.time_window)

        # Rename columns for merging
        src_host_features.rename(columns={'timestamp': 'time_window'}, inplace=True)
        dst_host_features.rename(columns={'timestamp': 'time_window'}, inplace=True)

        df_merged = df_copy.merge(src_host_features, on=['src_ip', 'time_window'], how='left')
        df_merged = df_merged.merge(dst_host_features, on=['dst_ip', 'time_window'], how='left')

        # Clean up
        df_merged.drop(columns=['time_window'], inplace=True)
        # To handle NaNs from the merge, we first sort by time to ensure correct order
        df_merged.sort_values('timestamp', inplace=True)

        # Now, forward-fill the host features. This propagates the last valid observation forward.
        feature_cols = [col for col in df_merged.columns if col.startswith(('src_host_', 'dst_host_'))]
        df_merged[feature_cols] = df_merged[feature_cols].ffill()

        # Any remaining NaNs at the beginning of the dataframe can be filled with 0.
        df_merged[feature_cols] = df_merged[feature_cols].fillna(0)

        self.logger.success("Finished calculating host-based features.")
        return df_merged
