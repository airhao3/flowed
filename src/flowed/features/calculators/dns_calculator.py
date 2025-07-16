import pandas as pd
import numpy as np
from typing import Dict, Any
from loguru import logger
from scipy.stats import entropy

from .base_calculator import BaseCalculator

class DnsCalculator(BaseCalculator):
    """
    Calculates features based on DNS layer data, targeting DNS tunneling detection.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculates the entropy of a string."""
        if not isinstance(s, str) or not s:
            return 0.0
        p, _ = np.histogram(list(map(ord, s)), bins=256, range=(0, 256))
        p = p[p>0]
        p = p / p.sum()
        return entropy(p, base=2)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates DNS-specific features.

        Args:
            df: The input pandas DataFrame with packet data, including dns fields.

        Returns:
            The DataFrame with new DNS features added.
        """
        self.logger.info("Calculating DNS-based features...")

        dns_cols = ['dns_qry_name', 'dns_qry_type', 'dns_an_count', 'dns_response_ip']
        if not self.validate_columns(df, dns_cols):
            return df

        df_copy = df.copy()

        if 'dns_qry_name' in df_copy.columns:
            # Feature: Query Name Length
            df_copy['dns_qry_name_len'] = df_copy['dns_qry_name'].str.len().fillna(0)
            self.logger.debug("Calculated dns_qry_name_len.")

            # Feature: Query Name Entropy
            df_copy['dns_qry_name_entropy'] = df_copy['dns_qry_name'].apply(self.calculate_entropy).fillna(0)
            self.logger.debug("Calculated dns_qry_name_entropy.")

        if 'dns_an_count' in df_copy.columns and 'dns_response_ip' in df_copy.columns:
            # Feature: DNS Response IP to Query Ratio
            # Count the number of IPs in the response field (can be a list)
            def count_ips(val):
                if isinstance(val, str):
                    return len(val.split(','))
                return 0

            df_copy['dns_response_ip_count'] = df_copy['dns_response_ip'].apply(count_ips)
            df_copy['dns_response_ip_to_query_ratio'] = df_copy['dns_response_ip_count'] / (df_copy['dns_an_count'] + 1e-6)
            df_copy.drop(columns=['dns_response_ip_count'], inplace=True)
            self.logger.debug("Calculated dns_response_ip_to_query_ratio.")

        self.logger.success("Finished calculating DNS-based features.")
        return df_copy
