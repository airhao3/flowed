import yaml
import pandas as pd
import time
from loguru import logger
from pathlib import Path

# Configure logger to be verbose and output to a file
logger.add("debug.log", level="DEBUG", format="{time} {level} {message}")

from flowed.data.processors.pcap_processor import PcapProcessor
from flowed.features.extractor import FeatureExtractor
from flowed.features.calculators.flow_calculator import FlowCalculator
from flowed.features.calculators.host_calculator import HostCalculator
from flowed.features.calculators.packet_calculator import PacketCalculator
from flowed.features.calculators.session_calculator import SessionCalculator
from flowed.features.calculators.rtt_calculator import RTTCalculator

def print_step_header(step_name):
    """Print a formatted step header."""
    print("\n" + "="*80)
    print(f"STEP: {step_name}")
    print("="*80)

def display_dataframe_info(df, title, show_dtypes=True, show_head=True):
    """Display information about a DataFrame."""
    print(f"\n--- {title} ---")
    print(f"Shape: {df.shape}")
    if show_head:
        print("\nFirst 5 rows:")
        with pd.option_context('display.max_columns', None, 'display.width', 1000, 'display.max_colwidth', 20):
            print(df.head())
    if show_dtypes:
        print("\nData types:")
        print(df.dtypes)
    print("-" * 50)

def main():
    """
    A debugging script to isolate and test the PCAP processing and feature extraction pipeline.
    """
    start_time = time.time()
    logger.info("--- Starting PCAP debugging script ---")

    # --- Load Configuration ---
    print_step_header("1. Loading Configuration")
    config_path = 'src/flowed/config/default_config.yaml'
    logger.info(f"Loading configuration from {config_path}")
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.success("Configuration loaded successfully.")
        print(f"Config loaded from: {Path(config_path).resolve()}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return

    # --- 2. PCAP Processing ---
    print_step_header("2. PCAP Processing")
    pcap_file = 'data/raw/test.pcapng'
    logger.info(f"Processing PCAP file: {pcap_file}")
    try:
        pcap_processor = PcapProcessor(config)
        
        # Process the PCAP file
        process_start = time.time()
        df = pcap_processor.process(pcap_file)
        process_time = time.time() - process_start
        
        logger.success(f"PCAP processing complete. Took {process_time:.2f} seconds")
        display_dataframe_info(df, "After PCAP Processing")
        
    except Exception as e:
        logger.error(f"An error occurred during PCAP processing: {e}", exc_info=True)
        return

    # --- 3. Feature Extraction ---
    print_step_header("3. Feature Extraction")
    logger.info("Initializing FeatureExtractor...")
    
    try:
        feature_extractor = FeatureExtractor(config)
        
        # --- 3.1 Flow Features ---
        print_step_header("3.1 Flow Features")
        logger.info("Calculating flow features...")
        flow_calc = FlowCalculator(config={
            'enabled': config.get('features', {}).get('flow', {}).get('enabled', True),
            'params': config.get('features', {}).get('flow_params', {})
        })
        df_flow = df.copy()
        flow_start = time.time()
        df_flow = flow_calc.calculate(df_flow)
        flow_time = time.time() - flow_start
        logger.success(f"Flow features calculated in {flow_time:.2f} seconds")
        display_dataframe_info(df_flow, "After Flow Features", show_dtypes=False)
        
        # --- 3.2 Host Features ---
        print_step_header("3.2 Host Features")
        logger.info("Calculating host features...")
        host_calc = HostCalculator(config={
            'enabled': config.get('features', {}).get('host', {}).get('enabled', True),
            'window': '1s',  # Default window size
            'params': config.get('features', {}).get('host_params', {})
        })
        df_host = df_flow.copy()
        host_start = time.time()
        df_host = host_calc.calculate(df_host)
        host_time = time.time() - host_start
        logger.success(f"Host features calculated in {host_time:.2f} seconds")
        
        # Show only the newly added columns
        new_cols = list(set(df_host.columns) - set(df_flow.columns))
        print("\nNew host features added:")
        print(new_cols)
        display_dataframe_info(df_host, "After Host Features (New Columns Only)", 
                             show_dtypes=False, show_head=False)
        
        # --- 3.3 Packet-Level Features ---
        print_step_header("3.3 Packet-Level Features")
        logger.info("Calculating packet-level features...")
        packet_calc = PacketCalculator(config={
            'enabled': config.get('features', {}).get('packet', {}).get('enabled', True),
            'extract_flags': config.get('features', {}).get('tcp', {}).get('extract_flags', True),
            'extract_timing': config.get('features', {}).get('tcp', {}).get('extract_timing', True),
            'params': config.get('features', {}).get('packet_params', {})
        })
        df_packet = df_host.copy()
        packet_start = time.time()
        df_packet = packet_calc.calculate(df_packet)
        packet_time = time.time() - packet_start
        logger.success(f"Packet features calculated in {packet_time:.2f} seconds")
        
        # --- 3.4 Session-Level Features ---
        print_step_header("3.4 Session-Level Features")
        logger.info("Calculating session-level features...")
        session_calc = SessionCalculator(config={
            'local_networks': ['172.19.0.0/16']  # 根据您的网络配置调整
        })
        df_session = df_packet.copy()
        session_start = time.time()
        df_session = session_calc.calculate(df_session)
        session_time = time.time() - session_start
        logger.success(f"Session features calculated in {session_time:.2f} seconds")
        
        # --- 3.5 Network Latency & RTT ---
        print_step_header("3.5 Network Latency & RTT")
        logger.info("Calculating network latency and RTT...")
        rtt_calc = RTTCalculator(config={
            'local_networks': ['172.19.0.0/16'],
            'syn_timeout': 10.0  # 10秒超时
        })
        df_rtt = df_session.copy()
        rtt_start = time.time()
        df_rtt = rtt_calc.calculate(df_rtt)
        rtt_time = time.time() - rtt_start
        logger.success(f"RTT calculation completed in {rtt_time:.2f} seconds")
        
        # 显示RTT统计信息
        if 'avg_rtt_ms' in df_rtt.columns:
            print("\n--- RTT Statistics (ms) ---")
            rtt_cols = ['flow_key', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                       'avg_rtt_ms', 'min_rtt_ms', 'max_rtt_ms', 'std_rtt_ms', 'rtt_sample_count']
            
            # 只显示存在的列
            rtt_display_cols = [col for col in rtt_cols if col in df_rtt.columns]
            rtt_stats = df_rtt[rtt_display_cols].drop_duplicates()
            
            with pd.option_context('display.max_columns', None, 'display.width', 1000, 'display.max_colwidth', 20):
                print(rtt_stats)
        
        # 显示会话统计信息
        if 'total_packets' in df_session.columns:
            print("\n--- Session Statistics ---")
            session_cols = ['session_key', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                          'total_packets', 'total_bytes', 'session_duration',
                          'inbound_frame_len_count', 'outbound_frame_len_count',
                          'inbound_frame_len_sum', 'outbound_frame_len_sum',
                          'inbound_ratio', 'outbound_ratio',
                          'packets_per_second', 'bytes_per_second']
            
            # 只显示存在的列
            display_cols = [col for col in session_cols if col in df_session.columns]
            session_stats = df_session[display_cols].drop_duplicates()
            
            with pd.option_context('display.max_columns', None, 'display.width', 1000, 'display.max_colwidth', 20):
                print(session_stats)
        
        # Show only the newly added columns
        new_cols = list(set(df_packet.columns) - set(df_host.columns))
        print("\nNew packet features added:")
        print(new_cols)
        
        # Display the first few rows of the new columns
        print("\n--- After Packet Features (New Columns Only) ---")
        if len(new_cols) > 0:
            display_dataframe_info(df_packet[new_cols], "", show_dtypes=False)
        else:
            print("No new packet features added.")
        print("-" * 50)
        
        # Show RTT-related columns if they exist
        if 'rtt_combined_ms' in df_rtt.columns:
            rtt_cols = [col for col in df_rtt.columns if 'rtt' in col.lower() or 'latency' in col.lower()]
            print("\n--- RTT/Latency Features ---")
            display_dataframe_info(df_rtt[rtt_cols].head(), "", show_dtypes=True)
            print("-" * 50)
        
        # --- Final Output ---
        print_step_header("FINAL RESULTS")
        total_time = time.time() - start_time
        logger.success(f"All processing completed in {total_time:.2f} seconds")
        
        # Display final dataframe info
        display_dataframe_info(df_rtt, "Final DataFrame")
        
        # Display memory usage
        print("\nMemory Usage:")
        print(f"DataFrame size: {df_rtt.memory_usage(deep=True).sum() / (1024*1024):.2f} MB")
        
    except Exception as e:
        logger.error(f"An error occurred during feature extraction: {e}", exc_info=True)
        return

    logger.info("--- Debugging script finished successfully ---")

if __name__ == "__main__":
    main()
