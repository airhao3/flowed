import pandas as pd
from typing import Dict, Any
from loguru import logger

from .base_calculator import BaseCalculator

class SshCalculator(BaseCalculator):
    """
    Calculates features based on SSH layer data.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates SSH-specific features.

        Args:
            df: The input pandas DataFrame with packet data, including ssh fields.

        Returns:
            The DataFrame with new SSH features added.
        """
        self.logger.info("Calculating SSH-based features...")

        ssh_cols = ['ssh_protocol', 'ssh_server_version', 'ssh_client_version']

        if not any(col in df.columns for col in ssh_cols):
            self.logger.warning("No SSH columns found in DataFrame. Skipping SSH calculations.")
            return df

        df_copy = df.copy()

        # Example Feature: Check if SSH protocol is version 2.0
        if 'ssh_protocol' in df_copy.columns:
            df_copy['ssh_is_v2'] = (df_copy['ssh_protocol'].str.contains('2.0', na=False)).astype(int)
            self.logger.debug("Calculated ssh_is_v2 feature.")

        # Example Feature: Identify potentially vulnerable SSH versions (this is a placeholder)
        # In a real scenario, this would check against a list of known vulnerable versions.
        if 'ssh_server_version' in df_copy.columns:
            df_copy['ssh_server_is_potentially_vulnerable'] = (
                df_copy['ssh_server_version'].str.contains('OpenSSH_7.4', na=False)
            ).astype(int)
            self.logger.debug("Calculated ssh_server_is_potentially_vulnerable feature.")

        self.logger.success("Finished calculating SSH-based features.")
        return df_copy
