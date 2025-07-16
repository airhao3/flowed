import pandas as pd
import numpy as np
from scipy.stats import entropy
import string
from .base_calculator import BaseCalculator

class PayloadCalculator(BaseCalculator):
    """Calculates features based on the raw payload of packets."""

    def _calculate_entropy(self, payload_hex: str) -> float:
        """Calculates the entropy of a hex-encoded payload."""
        if not payload_hex or not isinstance(payload_hex, str):
            return 0.0
        try:
            # Convert hex string to bytes
            payload_bytes = bytes.fromhex(payload_hex)
            if not payload_bytes:
                return 0.0
            
            # Calculate frequency of each byte
            _, counts = np.unique(list(payload_bytes), return_counts=True)
            
            # Calculate entropy
            return entropy(counts, base=2)
        except (ValueError, TypeError):
            # Handle cases where conversion from hex fails
            return 0.0

    def _calculate_printable_ratio(self, payload_hex: str) -> float:
        """Calculates the ratio of printable ASCII characters in a hex-encoded payload."""
        if not payload_hex or not isinstance(payload_hex, str):
            return 0.0
        try:
            # Convert hex string to bytes
            payload_bytes = bytes.fromhex(payload_hex)
            if not payload_bytes:
                return 0.0
            
            printable_chars = set(bytes(string.printable, 'ascii'))
            printable_count = sum(1 for byte in payload_bytes if byte in printable_chars)
            
            return printable_count / len(payload_bytes)
        except (ValueError, TypeError):
            return 0.0

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates payload-based features."""
        if 'payload' not in df.columns:
            self.logger.warning("Skipping PayloadCalculator. 'payload' column not found.")
            return df

        self.logger.info("Calculating payload features (entropy, printable char ratio)...")
        
        df['payload_entropy'] = df['payload'].apply(self._calculate_entropy)
        df['payload_printable_char_ratio'] = df['payload'].apply(self._calculate_printable_ratio)

        self.logger.success("Finished calculating payload features.")
        return df
