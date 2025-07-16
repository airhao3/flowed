from abc import ABC, abstractmethod
import pandas as pd
from typing import Dict, Any

class BaseProcessor(ABC):
    """
    Abstract base class for data processors.

    Each processor is responsible for reading a specific data format (e.g., PCAP, NetFlow)
    and converting it into a standardized pandas DataFrame.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initializes the processor with its configuration.

        Args:
            config: A dictionary containing configuration parameters for the processor.
        """
        self.config = config

    @abstractmethod
    def process(self, file_path: str) -> pd.DataFrame:
        """
        Processes the given file and returns a standardized DataFrame.

        Args:
            file_path: The path to the raw data file.

        Returns:
            A pandas DataFrame with a standardized structure.
        """
        pass
