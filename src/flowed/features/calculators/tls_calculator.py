import pandas as pd
from typing import Dict, Any
from loguru import logger

from .base_calculator import BaseCalculator

class TlsCalculator(BaseCalculator):
    """
    Processes TLS layer data, primarily focusing on JA3 fingerprints.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Ensures TLS JA3 fingerprint column is present and correctly formatted.

        Args:
            df: The input pandas DataFrame with packet data.

        Returns:
            The DataFrame, potentially with a cleaned tls_ja3 column.
        """
        self.logger.info("Calculating TLS-based features...")

        if 'tls_ja3' not in df.columns:
            self.logger.warning("No 'tls_ja3' column found. Skipping TLS calculations.")
            return df

        df_copy = df.copy()

        # Ensure the column is of string type, filling NaNs with an empty string
        if not pd.api.types.is_string_dtype(df_copy['tls_ja3']):
            df_copy['tls_ja3'] = df_copy['tls_ja3'].astype(str).fillna('')
            self.logger.debug("Converted 'tls_ja3' column to string type.")

        self.logger.success("Finished calculating TLS-based features.")
        return df_copy
