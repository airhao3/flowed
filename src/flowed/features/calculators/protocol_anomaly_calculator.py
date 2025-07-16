import pandas as pd
from .base_calculator import BaseCalculator

class ProtocolAnomalyCalculator(BaseCalculator):
    """Calculates protocol anomaly features."""

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates protocol anomaly features."""

        # TCP anomaly detection
        if 'tcp_flags' in df.columns:
            # Handle NaN values and convert to integer for bitwise operations
            flags_int = df['tcp_flags'].fillna(0).astype(int)

            # Abnormal flag combinations
            df['tcp_flags_null_scan'] = (flags_int == 0).astype(int)
            df['tcp_flags_xmas_scan'] = ((flags_int & 0x29) == 0x29).astype(int)  # FIN+URG+PSH
            df['tcp_flags_syn_flood'] = ((flags_int & 0x02) == 0x02).astype(int)  # Only SYN

        # DNS anomaly detection
        if 'dns_qry_name' in df.columns:
            df['dns_suspicious_tld'] = df['dns_qry_name'].str.contains(
                r'\.(tk|ml|ga|cf)$', case=False, na=False
            ).astype(int)

        return df
