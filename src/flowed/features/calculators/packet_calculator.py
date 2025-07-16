import pandas as pd
from typing import Dict, Any
from loguru import logger

from .base_calculator import BaseCalculator

class PacketCalculator(BaseCalculator):
    """
    Calculates features that can be derived from a single packet (row).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates packet-level features.

        - Parses TCP flags into individual columns.

        Args:
            df: The input pandas DataFrame.

        Returns:
            The DataFrame with new packet-level features added.
        """
        self.logger.info("Calculating packet-level features...")
        self.logger.debug(f"Input DataFrame shape: {df.shape}")
        
        if 'tcp_flags' not in df.columns:
            self.logger.warning("Column 'tcp_flags' not found in DataFrame. Skipping TCP flag parsing.")
            return df

        # Make a copy to avoid SettingWithCopyWarning
        df_copy = df.copy()
        self.logger.debug(f"tcp_flags column sample: {df_copy['tcp_flags'].head()}")

        # TCP flags are often a bitmask. Standard flags:
        # FIN = 1 (0b000001)
        # SYN = 2 (0b000010)
        # RST = 4 (0b000100)
        # PSH = 8 (0b001000)
        # ACK = 16 (0b010000)
        # URG = 32 (0b100000)

        # Debug the tcp_flags column
        self.logger.debug(f"tcp_flags dtype: {df_copy['tcp_flags'].dtype}")
        self.logger.debug(f"tcp_flags unique values: {df_copy['tcp_flags'].unique()[:10]}")

        # Convert hex flags (e.g., '0x12') to int if they are strings
        if pd.api.types.is_string_dtype(df_copy['tcp_flags']):
            flags_int = df_copy['tcp_flags'].apply(
                lambda x: int(str(x), 16) if pd.notna(x) and str(x).startswith('0x') else 0
            )
        else:
            flags_int = df_copy['tcp_flags']

        # Convert to numeric, handle errors, and ensure integer type
        flags_int = pd.to_numeric(flags_int, errors='coerce').fillna(0).astype(int)
        self.logger.debug(f"flags_int dtype after conversion: {flags_int.dtype}")
        self.logger.debug(f"flags_int unique values: {flags_int.unique()[:10]}")

        # Apply bitwise operations safely
        df_copy['tcp_flag_fin'] = flags_int.apply(lambda x: (x & 1)).astype(int)
        df_copy['tcp_flag_syn'] = flags_int.apply(lambda x: ((x >> 1) & 1)).astype(int)
        df_copy['tcp_flag_rst'] = flags_int.apply(lambda x: ((x >> 2) & 1)).astype(int)
        df_copy['tcp_flag_psh'] = flags_int.apply(lambda x: ((x >> 3) & 1)).astype(int)
        df_copy['tcp_flag_ack'] = flags_int.apply(lambda x: ((x >> 4) & 1)).astype(int)
        df_copy['tcp_flag_urg'] = flags_int.apply(lambda x: ((x >> 5) & 1)).astype(int)

        self.logger.success("Finished calculating packet-level features.")
        return df_copy
