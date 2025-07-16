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

        dns_cols = ['dns_qry_name', 'dns_qry_type']
        if not any(col in df.columns for col in dns_cols):
            self.logger.warning("No DNS columns found. Skipping DNS calculations.")
            return df

        df_copy = df.copy()

        if 'dns_qry_name' in df_copy.columns:
            # Feature: Query Name Length
            df_copy['dns_qry_name_len'] = df_copy['dns_qry_name'].str.len().fillna(0)
            self.logger.debug("Calculated dns_qry_name_len.")

            # Feature: Query Name Entropy
            df_copy['dns_qry_name_entropy'] = df_copy['dns_qry_name'].apply(self.calculate_entropy).fillna(0)
            self.logger.debug("Calculated dns_qry_name_entropy.")

        self.logger.success("Finished calculating DNS-based features.")
        return df_copy
