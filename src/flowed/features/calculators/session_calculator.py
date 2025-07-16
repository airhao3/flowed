"""
Session Calculator - 提供双向会话级别的统计信息
"""
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
from loguru import logger
from .base_calculator import BaseCalculator

class SessionCalculator(BaseCalculator):
    """
    计算双向会话级别的统计信息
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.config = config or {}
        self.local_networks = self.config.get('local_networks', ['172.19.0.0/16'])
        self.logger = logger.bind(module=__name__)
    
    def _get_session_key(self, row: pd.Series) -> str:
        """生成不区分方向的会话键"""
        src_ip = str(row.get('src_ip', ''))
        dst_ip = str(row.get('dst_ip', ''))
        src_port = str(row.get('src_port', ''))
        dst_port = str(row.get('dst_port', ''))
        protocol = str(row.get('protocol', ''))

        # 对IP和端口进行排序以确保双向会话使用相同的键
        if src_ip < dst_ip or (src_ip == dst_ip and src_port <= dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _get_direction(self, row: pd.Series) -> str:
        """确定流量的方向"""
        src_ip = str(row.get('src_ip', ''))
        # 这里简化处理，实际中可能需要更复杂的逻辑来确定内外网
        if src_ip.startswith('172.19.'):
            return 'outbound'
        return 'inbound'
    
    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        计算会话级别的统计信息
        
        Args:
            df: 包含流数据的DataFrame
            
        Returns:
            添加了会话统计信息的DataFrame
        """
        if df.empty:
            return df

        self.logger.info("Calculating session-based features...")

        df = df.copy()
        # Filter out rows where essential components for session key are missing
        required_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        df.dropna(subset=required_cols, inplace=True)
        if df.empty:
            self.logger.warning("DataFrame is empty after dropping NaNs in required columns for session calculation.")
            return df

        df['session_key'] = df.apply(self._get_session_key, axis=1)
        df['direction'] = df.apply(self._get_direction, axis=1)
        
        # 计算每个会话的基本统计信息
        session_stats = df.groupby('session_key').agg({
            'src_ip': 'first',
            'src_port': 'first',
            'dst_ip': 'first',
            'dst_port': 'first',
            'protocol': 'first',
            'frame_len': ['count', 'sum', 'mean', 'std'],
            'flow_duration_seconds': 'max',
            'timestamp': ['min', 'max']
        })
        
        # 展平多级列名
        session_stats.columns = ['_'.join(col).strip('_') for col in session_stats.columns.values]
        session_stats = session_stats.rename(columns={
            'frame_len_count': 'total_packets',
            'frame_len_sum': 'total_bytes',
            'frame_len_mean': 'avg_packet_size',
            'frame_len_std': 'std_packet_size',
            'flow_duration_seconds_max': 'session_duration',
            'timestamp_min': 'session_start',
            'timestamp_max': 'session_end'
        })
        
        # 计算每个方向的统计信息
        for direction in ['inbound', 'outbound']:
            dir_df = df[df['direction'] == direction]
            if not dir_df.empty:
                dir_stats = dir_df.groupby('session_key').agg({
                    'frame_len': ['count', 'sum'],
                    'tcp_flags': lambda x: x.value_counts().to_dict()
                })
                
                # 展平列名
                dir_stats.columns = [f"{direction}_{col[0]}" for col in dir_stats.columns]
                
                # 合并回主统计表
                session_stats = session_stats.join(dir_stats)
        
        # --- Asymmetry and Ratio Features ---
        session_stats.fillna({'inbound_frame_len_sum': 0, 'outbound_frame_len_sum': 0, 
                              'inbound_frame_len_count': 0, 'outbound_frame_len_count': 0}, inplace=True)

        # Bytes and Packets Ratio
        session_stats['session_bytes_ratio'] = session_stats['outbound_frame_len_sum'] / (session_stats['inbound_frame_len_sum'] + 1e-6)
        session_stats['session_packets_ratio'] = session_stats['outbound_frame_len_count'] / (session_stats['inbound_frame_len_count'] + 1e-6)

        # Small Packet Ratio
        small_packet_threshold = self.config.get('small_packet_threshold', 64)
        df['is_small_packet'] = (df['frame_len'] < small_packet_threshold).astype(int)
        small_packet_stats = df.groupby('session_key')['is_small_packet'].sum().reset_index(name='small_packet_count')
        session_stats = session_stats.merge(small_packet_stats, on='session_key', how='left')
        session_stats['small_packet_ratio'] = session_stats['small_packet_count'] / session_stats['total_packets']
        
        # --- Active/Idle Time Analysis ---
        # Calculate active time (sum of flow durations) and idle time
        active_time_stats = df.groupby('session_key')['flow_duration_seconds'].sum().reset_index(name='session_active_time')
        session_stats = session_stats.merge(active_time_stats, on='session_key', how='left')
        session_stats['session_idle_time'] = session_stats['session_duration'] - session_stats['session_active_time']
        session_stats['active_idle_ratio'] = session_stats['session_active_time'] / (session_stats['session_idle_time'] + 1e-6)

        # 添加会话活跃度指标
        session_stats['packets_per_second'] = session_stats['total_packets'] / (session_stats['session_duration'] + 1e-6)
        session_stats['bytes_per_second'] = session_stats['total_bytes'] / (session_stats['session_duration'] + 1e-6)
        
        # 重置索引以便与原始DataFrame合并
        session_stats = session_stats.reset_index()
        
        # 将统计信息合并回原始DataFrame
        df = df.merge(session_stats, on='session_key', how='left')
        
        self.logger.success(f"Calculated session statistics for {len(session_stats)} unique sessions")
        return df
