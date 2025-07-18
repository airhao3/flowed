from typing import Dict, Any, Optional
import ipaddress

import pandas as pd
import pyshark
from loguru import logger

from .base_processor import BaseProcessor

class PcapProcessor(BaseProcessor):
    """Processes raw PCAP network traffic data."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def process(self, file_path: str) -> (pd.DataFrame, Dict[str, Any]):
        """Process a single PCAP file and return statistics.

        Args:
            file_path: Path to the input PCAP file.

        Returns:
            A tuple containing:
            - A standardized DataFrame containing the processed data.
            - A dictionary with processing statistics.
        """
        self.logger.info(f"Processing PCAP file: {file_path}")
        
        stats = {
            'file_path': file_path,
            'total_packets_read': 0,
            'max_packets_limit': self.config.get('max_packets', 50000),
            'malformed_packets_skipped': 0,
            'packets_failed_validation': 0,
            'packets_out_of_size_range': 0,
            'packets_successfully_processed': 0,
        }

        try:
            cap = pyshark.FileCapture(
                file_path,
                display_filter=self.config.get('display_filter', 'tcp or udp')
            )

            packets = []
            min_packet_size = self.config.get('min_packet_size', 14)
            max_packet_size = self.config.get('max_packet_size', 65535)
            skip_malformed = self.config.get('skip_malformed', True)

            for i, packet in enumerate(cap):
                stats['total_packets_read'] = i + 1
                if i >= stats['max_packets_limit']:
                    self.logger.warning(f"Reached max packets limit ({stats['max_packets_limit']}).")
                    break

                try:
                    packet_len = int(packet.length)
                    if not (min_packet_size <= packet_len <= max_packet_size):
                        stats['packets_out_of_size_range'] += 1
                        continue
                except (ValueError, AttributeError):
                    stats['malformed_packets_skipped'] += 1
                    if skip_malformed:
                        continue
                    else:
                        raise

                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    if self.config.get('quality_control', {}).get('validate_packets', True):
                        if not self._validate_packet_data(packet_info):
                            stats['packets_failed_validation'] += 1
                            continue

                    packets.append(packet_info)
                else:
                    stats['malformed_packets_skipped'] += 1

            cap.close()

            if not packets:
                self.logger.warning(f"No processable packets found in {file_path}")
                return pd.DataFrame(), stats

            df = pd.DataFrame(packets)
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            stats['packets_successfully_processed'] = len(df)
            
            self.logger.info(f"Finished processing {file_path}. Successfully processed {len(df)} packets.")
            return df, stats

        except Exception as e:
            self.logger.error(f"Error processing PCAP file {file_path}: {e}")
            raise

    def _validate_packet_data(self, packet_info: Dict[str, Any]) -> bool:
        """Validate the reasonableness of the extracted packet data."""
        # IP address format check
        if 'src_ip' in packet_info and packet_info['src_ip']:
            try:
                ipaddress.ip_address(packet_info['src_ip'])
            except ValueError:
                self.logger.trace(f"Invalid source IP address: {packet_info['src_ip']}")
                return False
        if 'dst_ip' in packet_info and packet_info['dst_ip']:
            try:
                ipaddress.ip_address(packet_info['dst_ip'])
            except ValueError:
                self.logger.trace(f"Invalid destination IP address: {packet_info['dst_ip']}")
                return False

        # Port range check
        for port_field in ['src_port', 'dst_port']:
            if port_field in packet_info and packet_info[port_field] is not None:
                port = packet_info[port_field]
                if not (0 <= port <= 65535):
                    self.logger.trace(f"Invalid port number: {port}")
                    return False

        # Packet length sanity check
        if 'frame_len' in packet_info and packet_info['frame_len'] is not None:
            # Based on Ethernet v2, min frame size is 64 bytes (including FCS), but pyshark length is often without FCS (60).
            # We use a slightly more relaxed lower bound.
            min_len = self.config.get('quality_control', {}).get('min_packet_size', 14)
            max_len = self.config.get('quality_control', {}).get('max_packet_size', 65535)
            if not (min_len <= packet_info['frame_len'] <= max_len):
                self.logger.trace(f"Packet length out of bounds: {packet_info['frame_len']}")
                return False

        return True

    def _extract_packet_info(self, packet: pyshark.packet.packet.Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a single packet."""
        try:
            packet_info = {
                'timestamp': float(packet.sniff_timestamp),
                'frame_len': int(packet.length),
                'protocol': packet.highest_layer,
                'payload': packet.tcp.payload.raw_value if 'TCP' in packet and hasattr(packet.tcp, 'payload') else (packet.udp.payload.raw_value if 'UDP' in packet and hasattr(packet.udp, 'payload') else None)
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
                    'tcp_flags': int(str(tcp_layer.flags), 16),
                    'tcp_window_size': int(tcp_layer.window_size),
                    'tcp_ack': int(tcp_layer.ack),
                    'tcp_seq': int(tcp_layer.seq),
                    'tcp_mss': getattr(tcp_layer, 'options_mss_val', None),
                    'tcp_window_scale': getattr(tcp_layer, 'options_wscale_val', None),
                    'tcp_sack_permitted': getattr(tcp_layer, 'options_sack_perm', None),
                    'tcp_timestamp': getattr(tcp_layer, 'options_timestamp_tsval', None),
                    'tcp_urgent_pointer': int(tcp_layer.urgent_pointer),
                    'tcp_checksum': getattr(tcp_layer, 'checksum', None),
                })
            
            elif 'UDP' in packet:
                udp_layer = packet.udp
                packet_info.update({
                    'src_port': int(udp_layer.srcport),
                    'dst_port': int(udp_layer.dstport)
                })

            if 'ICMP' in packet:
                icmp_layer = packet.icmp
                packet_info.update({
                    'icmp_type': int(icmp_layer.type),
                    'icmp_code': int(icmp_layer.code),
                    'icmp_checksum': getattr(icmp_layer, 'checksum', None),
                    'icmp_id': getattr(icmp_layer, 'id', None),
                    'icmp_seq': getattr(icmp_layer, 'seq', None),
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
                # Count headers by splitting the header block
                header_block = getattr(http_layer, 'request_headers', None) or getattr(http_layer, 'response_headers', None)
                if header_block:
                    packet_info['http_header_count'] = len(header_block.split('\n'))
                else:
                    packet_info['http_header_count'] = 0

                packet_info.update({
                    'http_content_type': getattr(http_layer, 'content_type', None),
                    'http_content_length': getattr(http_layer, 'content_length', None),
                    'http_referer': getattr(http_layer, 'referer', None),
                    'http_cookie': getattr(http_layer, 'cookie', None),
                    'http_authorization': getattr(http_layer, 'authorization', None),
                    'http_x_forwarded_for': getattr(http_layer, 'x_forwarded_for', None),
                    'http_server': getattr(http_layer, 'server', None),
                    'http_location': getattr(http_layer, 'location', None),
                })
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
                packet_info.update({
                    'dns_id': getattr(dns_layer, 'id', None),
                    'dns_flags': getattr(dns_layer, 'flags', None),
                    'dns_qr': getattr(dns_layer, 'flags_response', None),
                    'dns_opcode': getattr(dns_layer, 'flags_opcode', None),
                    'dns_rcode': getattr(dns_layer, 'flags_rcode', None),
                    'dns_qd_count': getattr(dns_layer, 'count_queries', None),
                    'dns_an_count': getattr(dns_layer, 'count_answers', None),
                    'dns_response_ip': getattr(dns_layer, 'a', None),
                })
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
