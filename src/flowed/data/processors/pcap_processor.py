from typing import Dict, Any, Optional

import pandas as pd
import pyshark
from loguru import logger

from .base_processor import BaseProcessor

class PcapProcessor(BaseProcessor):
    """Processes raw PCAP network traffic data."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def process(self, file_path: str) -> pd.DataFrame:
        """Process a single PCAP file.

        Args:
            file_path: Path to the input PCAP file.

        Returns:
            A standardized DataFrame containing the processed data.
        """
        self.logger.info(f"Processing PCAP file: {file_path}")

        try:
            cap = pyshark.FileCapture(
                file_path,
                display_filter=self.config.get('display_filter', 'tcp or udp')
            )

            packets = []
            max_packets = self.config.get('max_packets', 50000)
            batch_size = self.config.get('batch_size', 1000)
            skip_malformed = self.config.get('skip_malformed', True)
            min_packet_size = self.config.get('min_packet_size', 14)
            max_packet_size = self.config.get('max_packet_size', 65535)
            
            packet_count = 0
            malformed_count = 0
            
            for i, packet in enumerate(cap):
                if i >= max_packets:
                    self.logger.warning(f"Reached max packets limit ({max_packets}).")
                    break

                # Basic packet size validation
                try:
                    packet_len = int(packet.length)
                    if packet_len < min_packet_size or packet_len > max_packet_size:
                        if not skip_malformed:
                            self.logger.warning(f"Packet {i} has invalid size: {packet_len}")
                        continue
                except (ValueError, AttributeError):
                    malformed_count += 1
                    if skip_malformed:
                        continue
                    else:
                        raise

                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    packets.append(packet_info)
                    packet_count += 1
                    
                    # Process in batches to manage memory
                    if packet_count % batch_size == 0:
                        self.logger.debug(f"Processed {packet_count} packets...")
            
            cap.close()
            
            if malformed_count > 0:
                self.logger.info(f"Skipped {malformed_count} malformed packets")

            if not packets:
                self.logger.warning(f"No processable packets found in {file_path}")
                return pd.DataFrame()

            df = pd.DataFrame(packets)
            # Convert Unix timestamp to datetime objects
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            return df

        except Exception as e:
            self.logger.error(f"Error processing PCAP file {file_path}: {e}")
            raise

    def _extract_packet_info(self, packet: pyshark.packet.packet.Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a single packet."""
        try:
            packet_info = {
                'timestamp': float(packet.sniff_timestamp),
                'frame_len': int(packet.length),
                'protocol': packet.highest_layer
            }

            if 'IP' in packet:
                ip_layer = packet.ip
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'ip_version': int(ip_layer.version),
                    'ip_ttl': int(ip_layer.ttl),
                    'ip_len': int(ip_layer.len)
                })

            if 'TCP' in packet:
                tcp_layer = packet.tcp
                packet_info.update({
                    'src_port': int(tcp_layer.srcport),
                    'dst_port': int(tcp_layer.dstport),
                    # Handle both hex strings and integers for flags
                    'tcp_flags': int(tcp_layer.flags) if isinstance(tcp_layer.flags, int) 
                                  else int(str(tcp_layer.flags), 16),
                    'tcp_window_size': int(tcp_layer.window_size),
                    'tcp_ack': int(tcp_layer.ack),
                    'tcp_seq': int(tcp_layer.seq)
                })
            
            elif 'UDP' in packet:
                udp_layer = packet.udp
                packet_info.update({
                    'src_port': int(udp_layer.srcport),
                    'dst_port': int(udp_layer.dstport)
                })

            # --- Application Layer Protocols ---
            if 'SSH' in packet:
                ssh_layer = packet.ssh
                packet_info.update({
                    'ssh_protocol': ssh_layer.protocol,
                    'ssh_server_version': getattr(ssh_layer, 'server_version', None),
                    'ssh_client_version': getattr(ssh_layer, 'client_version', None),
                })

            if 'TDS' in packet and hasattr(packet.tds, 'query'):
                packet_info.update({
                    'sql_query': packet.tds.query
                })

            if 'HTTP' in packet:
                http_layer = packet.http
                # Check for request fields
                if hasattr(http_layer, 'request_method'):
                    packet_info.update({
                        'http_request_method': getattr(http_layer, 'request_method', None),
                        'http_uri': getattr(http_layer, 'request_uri', None),
                        'http_user_agent': getattr(http_layer, 'user_agent', None),
                        'http_host': getattr(http_layer, 'host', None)
                    })
                # Check for response fields
                if hasattr(http_layer, 'response_code'):
                    packet_info.update({
                        'http_response_code': int(getattr(http_layer, 'response_code', 0))
                    })

            if 'DNS' in packet:
                dns_layer = packet.dns
                # A single DNS packet can have multiple queries, but we focus on the first for simplicity.
                if hasattr(dns_layer, 'qry_name'):
                    packet_info.update({
                        'dns_qry_name': getattr(dns_layer, 'qry_name', None),
                        'dns_qry_type': int(getattr(dns_layer, 'qry_type', 0))
                    })

            if 'SSL' in packet and hasattr(packet.ssl, 'handshake_type') and packet.ssl.handshake_type == '1': # Client Hello
                try:
                    ssl_layer = packet.ssl
                    # JA3 Fingerprint fields
                    version = ssl_layer.handshake_version
                    # Cipher suites are provided as a comma-separated string, convert to '-'
                    cipher_suites = getattr(ssl_layer, 'handshake_ciphersuites', '').replace(',', '-')
                    extensions = getattr(ssl_layer, 'handshake_extensions_type', '').replace(',', '-')
                    elliptic_curves = getattr(ssl_layer, 'handshake_extensions_supported_group', '').replace(',', '-')
                    ec_point_formats = getattr(ssl_layer, 'handshake_extensions_ec_point_format', '').replace(',', '-')

                    ja3_string = f"{version},{cipher_suites},{extensions},{elliptic_curves},{ec_point_formats}"
                    packet_info['tls_ja3'] = ja3_string

                except AttributeError:
                    # Some fields might be missing in certain Client Hello packets
                    pass

            return packet_info

        except AttributeError as e:
            # This can happen if a field is missing in a malformed packet
            self.logger.trace(f"Attribute error extracting packet info: {e}")
            return None
