import pandas as pd
from .base_calculator import BaseCalculator

class NetworkSecurityCalculator(BaseCalculator):
    """Calculates network security-related features."""

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        try:
            return ip.is_private
        except AttributeError:
            # Handle cases where the input is not a valid IP address object
            from ipaddress import ip_address
            try:
                return ip_address(ip).is_private
            except ValueError:
                return False

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates network security features."""
        if not self.validate_columns(df, ['dst_port', 'src_ip', 'dst_ip', 'frame_len']):
            return df

        # Port scanning detection features
        df['is_common_port'] = df['dst_port'].isin([21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]).astype(int)
        df['is_high_port'] = (df['dst_port'] > 1024).astype(int)

        # Private IP detection
        df['src_is_private'] = df['src_ip'].apply(self._is_private_ip).astype(int)
        df['dst_is_private'] = df['dst_ip'].apply(self._is_private_ip).astype(int)

        # Abnormal packet size detection
        df['is_jumbo_frame'] = (df['frame_len'] > 1500).astype(int)
        df['is_tiny_packet'] = (df['frame_len'] < 64).astype(int)

        return df
