import pandas as pd
import numpy as np
from typing import Dict, Any
from loguru import logger
from scipy.stats import entropy

from .base_calculator import BaseCalculator

class HttpCalculator(BaseCalculator):
    """
    Calculates features based on HTTP layer data.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculates the entropy of a string."""
        if not isinstance(s, str) or not s:
            return 0.0
        # Calculate probability of each character
        p, _ = np.histogram(list(map(ord, s)), bins=256, range=(0, 256))
        p = p[p>0]
        p = p / p.sum()
        return entropy(p, base=2)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates HTTP-specific features.

        Args:
            df: The input pandas DataFrame with packet data, including http fields.

        Returns:
            The DataFrame with new HTTP features added.
        """
        self.logger.info("Calculating HTTP-based features...")

        http_cols = [
            'http_request_method', 'http_request_uri', 'http_host',
            'http_user_agent', 'http_response_code'
        ]

        # Check if any http columns exist
        if not any(col in df.columns for col in http_cols):
            self.logger.warning("No HTTP columns found in DataFrame. Skipping HTTP calculations.")
            return df

        df_copy = df.copy()

        # Feature: URI Length
        if 'http_request_uri' in df_copy.columns:
            df_copy['http_uri_length'] = df_copy['http_request_uri'].str.len().fillna(0)
            self.logger.debug("Calculated http_uri_length.")

            # Feature: URI Entropy
            df_copy['http_uri_entropy'] = df_copy['http_request_uri'].apply(self.calculate_entropy).fillna(0)
            self.logger.debug("Calculated http_uri_entropy.")

        # Feature: One-hot encode request method
        if 'http_request_method' in df_copy.columns:
            # Read parameters from the dedicated http_params section
            http_params = self.config.get('http_params', {})
            methods_to_encode = http_params.get('common_methods', ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'])
            for method in methods_to_encode:
                col_name = f'http_method_{method.lower()}'
                df_copy[col_name] = (df_copy['http_request_method'] == method).astype(int)
            self.logger.debug(f"One-hot encoded HTTP methods: {methods_to_encode}")

        # Feature: Categorize response codes
        if 'http_response_code' in df_copy.columns:
            # Ensure the column is numeric, coercing errors
            codes = pd.to_numeric(df_copy['http_response_code'], errors='coerce').fillna(0).astype(int)

            df_copy['http_rsp_success'] = ((codes >= 200) & (codes < 300)).astype(int)
            df_copy['http_rsp_redirect'] = ((codes >= 300) & (codes < 400)).astype(int)
            df_copy['http_rsp_client_error'] = ((codes >= 400) & (codes < 500)).astype(int)
            df_copy['http_rsp_server_error'] = ((codes >= 500) & (codes < 600)).astype(int)
            self.logger.debug("Categorized HTTP response codes.")

        self.logger.success("Finished calculating HTTP-based features.")
        return df_copy
