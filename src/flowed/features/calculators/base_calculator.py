from abc import ABC, abstractmethod
from typing import Dict, Any, List

import pandas as pd
from loguru import logger


class BaseCalculator(ABC):
    """Abstract base class for all feature calculators."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logger.bind(module=self.__class__.__name__)

    @abstractmethod
    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates features and adds them to the DataFrame."""
        pass

    def validate_columns(self, df: pd.DataFrame, required_columns: List[str]) -> bool:
        """Checks if all required columns are present in the DataFrame."""
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            self.logger.warning(
                f"Skipping {self.__class__.__name__}. Missing required columns: {missing_columns}"
            )
            return False
        return True
