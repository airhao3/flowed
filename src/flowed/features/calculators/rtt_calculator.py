"""
RTT Calculator - 计算网络延迟和往返时间(RTT)
"""
from typing import Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np
from loguru import logger
from .base_calculator import BaseCalculator

class RTTCalculator(BaseCalculator):
    """
    计算网络延迟和往返时间(RTT)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.config = config or {}
        self.local_networks = self.config.get('local_networks', ['172.19.0.0/16'])
        self.syn_timeout = self.config.get('syn_timeout', 60.0)  # 秒
        self.logger = logger.bind(module=__name__)
    
    def _is_local_ip(self, ip: str) -> bool:
        """检查IP是否为本地网络"""
        return any(ip.startswith(net.split('/')[0]) for net in self.local_networks)
    
    def _estimate_rtt_tcp_handshake(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        通过TCP三次握手估计RTT
        
        对于每个连接，计算SYN到SYN-ACK的时间作为RTT估计
        """
        df = df.copy()
        
        # 只处理TCP流量
        tcp_df = df[df['protocol'] == 'TCP'].copy()
        
        # 为每个流创建唯一标识符
        tcp_df['flow_id'] = tcp_df.apply(
            lambda x: f"{x['src_ip']}:{x['src_port']}-{x['dst_ip']}:{x['dst_port']}", 
            axis=1
        )
        
        # 提取SYN和SYN-ACK包
        syn_mask = (tcp_df['tcp_flags'] & 0x02) > 0  # SYN标志
        syn_df = tcp_df[syn_mask].copy()
        
        # 分离客户端的SYN和服务器的SYN-ACK
        client_syn = syn_df[syn_df['src_ip'].apply(self._is_local_ip)]
        server_syn_ack = syn_df[~syn_df['src_ip'].apply(self._is_local_ip)]
        
        # 创建查找字典：flow_id -> timestamp
        syn_times = dict(zip(client_syn['flow_id'], client_syn['timestamp']))
        syn_ack_times = dict(zip(
            server_syn_ack['flow_id'].str.split('-').str[::-1].str.join('-'),  # 反转flow_id
            server_syn_ack['timestamp']
        ))
        
        # 计算RTT
        rtts = {}
        for flow_id, syn_time in syn_times.items():
            if flow_id in syn_ack_times:
                rtt = (syn_ack_times[flow_id] - syn_time).total_seconds() * 1000  # 转换为毫秒
                if 0 < rtt < self.syn_timeout * 1000:  # 过滤异常值
                    rtts[flow_id] = rtt
        
        # 将RTT添加到原始DataFrame
        df['rtt_ms'] = df['flow_key'].map(rtts)
        return df
    
    def _estimate_rtt_ack_latency(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        通过数据包和ACK的间隔估计RTT
        
        对于每个数据包，查找对应的ACK包，计算时间差作为RTT
        """
        df = df.copy()
        
        # 只处理TCP流量
        tcp_df = df[df['protocol'] == 'TCP'].copy()
        
        if tcp_df.empty:
            df['rtt_ack_ms'] = None
            return df
            
        # 为每个流创建唯一标识符
        tcp_df['flow_key'] = tcp_df.apply(
            lambda x: f"{x['src_ip']}:{x['src_port']}-{x['dst_ip']}:{x['dst_port']}", 
            axis=1
        )
        
        # 创建ACK序号映射：flow_key -> {seq: timestamp}
        ack_map = {}
        
        # 按时间戳排序
        tcp_df = tcp_df.sort_values('timestamp')
        
        # 计算RTT
        rtts = [None] * len(tcp_df)
        
        # 为每个流单独处理
        for flow_key, flow_df in tcp_df.groupby('flow_key'):
            # 为当前流创建ACK映射
            flow_ack_map = {}
            
            # 首先收集所有ACK包
            ack_packets = flow_df[flow_df['tcp_flags'].apply(lambda x: x & 0x10 > 0)]
            for _, pkt in ack_packets.iterrows():
                ack_num = pkt['tcp_ack']
                flow_ack_map[ack_num] = pkt['timestamp']
            
            # 然后处理每个数据包，查找对应的ACK
            for idx, pkt in flow_df.iterrows():
                # 计算下一个期望的ACK号
                tcp_len = max(1, pkt.get('ip_len', 0) - 40)  # 估算TCP载荷长度
                seq_num = pkt['tcp_seq'] + tcp_len
                
                # 查找对应的ACK
                if seq_num in flow_ack_map:
                    rtt = (flow_ack_map[seq_num] - pkt['timestamp']).total_seconds() * 1000  # 毫秒
                    if 0 < rtt < self.syn_timeout * 1000:  # 过滤异常值
                        rtts[tcp_df.index.get_loc(idx)] = rtt
        
        # 将RTT添加到DataFrame
        tcp_df['rtt_ack_ms'] = rtts
        
        # 合并回原始DataFrame
        if 'rtt_ack_ms' in df.columns:
            df = df.drop('rtt_ack_ms', axis=1)
            
        df = df.merge(
            tcp_df[['timestamp', 'flow_key', 'rtt_ack_ms']],
            on=['timestamp', 'flow_key'],
            how='left'
        )
        
        return df
    
    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        计算网络延迟和RTT
        
        Args:
            df: 包含网络流量的DataFrame
            
        Returns:
            添加了RTT和延迟指标的DataFrame
        """
        if df.empty:
            return df
            
        self.logger.info("Calculating network latency and RTT...")
        
        # 添加flow_key列用于分组
        if 'flow_key' not in df.columns:
            df['flow_key'] = df.apply(
                lambda x: f"{x['src_ip']}:{x['src_port']}-{x['dst_ip']}:{x['dst_port']}", 
                axis=1
            )
        
        # 方法1：通过TCP握手计算RTT
        df = self._estimate_rtt_tcp_handshake(df)
        
        # 方法2：通过ACK延迟计算RTT
        df = self._estimate_rtt_ack_latency(df)
        
        # 计算平均RTT
        if 'rtt_ms' in df.columns and 'rtt_ack_ms' in df.columns:
            df['rtt_combined_ms'] = df[['rtt_ms', 'rtt_ack_ms']].mean(axis=1, skipna=True)
        
        # 计算会话级别的RTT统计
        if 'rtt_combined_ms' in df.columns:
            rtt_stats = df.groupby('flow_key')['rtt_combined_ms'].agg(
                ['mean', 'std', 'min', 'max', 'count']
            ).reset_index()
            rtt_stats.columns = [
                'flow_key', 
                'avg_rtt_ms', 
                'std_rtt_ms', 
                'min_rtt_ms', 
                'max_rtt_ms',
                'rtt_sample_count'
            ]
            
            # 合并回原始DataFrame
            df = df.merge(rtt_stats, on='flow_key', how='left')
        
        self.logger.success("Finished calculating network latency and RTT")
        return df
