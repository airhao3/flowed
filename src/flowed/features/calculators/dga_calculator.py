import pandas as pd
import numpy as np
from scipy.stats import entropy
from .base_calculator import BaseCalculator

class DgaCalculator(BaseCalculator):
    """Calculates features to detect Domain Generation Algorithms (DGA)."""

    def _calculate_entropy(self, domain: str) -> float:
        """Calculates the entropy of a domain name."""
        if not domain or not isinstance(domain, str):
            return 0.0
        # Exclude TLD
        parts = domain.split('.')
        if len(parts) > 1:
            domain = '.'.join(parts[:-1])
        
        _, counts = np.unique(list(domain), return_counts=True)
        return entropy(counts, base=2)

    def _calculate_numeric_ratio(self, domain: str) -> float:
        """Calculates the ratio of numeric characters in a domain name."""
        if not domain or not isinstance(domain, str):
            return 0.0
        
        num_count = sum(c.isdigit() for c in domain)
        return num_count / len(domain) if len(domain) > 0 else 0.0

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates DGA-related features and a DGA score."""
        if 'dns_qry_name' not in df.columns:
            self.logger.warning("Skipping DgaCalculator. 'dns_qry_name' column not found.")
            return df

        self.logger.info("Calculating DGA detection features...")
        
        df['dga_domain_entropy'] = df['dns_qry_name'].apply(self._calculate_entropy)
        df['dga_numeric_ratio'] = df['dns_qry_name'].apply(self._calculate_numeric_ratio)

        # A simple DGA score heuristic
        df['dga_score'] = (df['dga_domain_entropy'] / 4.0) + (df['dga_numeric_ratio'] * 2.0)
        
        # Flag potential DGA based on a threshold
        dga_threshold = self.config.get('dga_threshold', 1.0)
        df['is_dga_domain'] = (df['dga_score'] > dga_threshold).astype(int)

        self.logger.success("Finished calculating DGA detection features.")
        return df
