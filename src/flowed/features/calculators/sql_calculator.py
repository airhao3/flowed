import pandas as pd
import numpy as np
from typing import Dict, Any
from loguru import logger
from scipy.stats import entropy

from .base_calculator import BaseCalculator

class SqlCalculator(BaseCalculator):
    """
    Calculates features based on SQL query data (from TDS protocol).
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logger.bind(module=__name__)
        sql_params = self.config.get('sql_params', {})
        self.suspicious_keywords = sql_params.get('suspicious_keywords', [
            'union select', 'drop table', 'xp_cmdshell', '--', ';', 'insert into',
            'update set', 'delete from'
        ])

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
        Calculates SQL-specific features from the 'sql_query' column.

        Args:
            df: The input pandas DataFrame with a 'sql_query' column.

        Returns:
            The DataFrame with new SQL features added.
        """
        if 'sql_query' not in df.columns:
            self.logger.trace("No 'sql_query' column found. Skipping SQL calculations.")
            return df

        self.logger.info("Calculating SQL-based features...")
        df_copy = df.copy()

        # Ensure query column is string type, fill NaNs
        queries = df_copy['sql_query'].astype(str).fillna('')

        # Feature: Query Length
        df_copy['sql_query_length'] = queries.str.len()

        # Feature: Query Entropy
        df_copy['sql_query_entropy'] = queries.apply(self.calculate_entropy)

        # Feature: Contains suspicious keywords
        keyword_pattern = '|'.join(self.suspicious_keywords)
        df_copy['sql_contains_suspicious_keywords'] = queries.str.contains(
            keyword_pattern, case=False, na=False
        ).astype(int)

        self.logger.success("Finished calculating SQL-based features.")
        return df_copy
