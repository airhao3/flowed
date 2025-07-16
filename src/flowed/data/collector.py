"""Data collection module for the traffic detection system."""
import os
import glob
from pathlib import Path
from typing import List, Optional

from loguru import logger

class DataCollector:
    """Collects network traffic data from various sources."""
    
    def __init__(self, config: dict):
        """Initialize the data collector.
        
        Args:
            config: Configuration dictionary for data collection.
        """
        self.config = config
        self.logger = logger.bind(module=__name__)
        
        # Ensure input directory exists
        self.input_dir = Path(config.get('input_dir', 'data/raw'))
        if not self.input_dir.exists():
            self.logger.warning(f"Input directory {self.input_dir} does not exist")
            self.input_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created input directory: {self.input_dir}")
    
    def collect(self) -> List[str]:
        """Collect data files from the input directory.
        
        Returns:
            List of paths to the collected files.
        """
        file_pattern = self.config.get('file_pattern', '*.pcap')
        search_path = self.input_dir / '**' / file_pattern
        
        self.logger.info(f"Searching for files matching: {search_path}")
        files = [str(f) for f in glob.glob(str(search_path), recursive=True)]
        
        if not files:
            self.logger.warning(f"No files found matching {file_pattern} in {self.input_dir}")
        else:
            self.logger.info(f"Found {len(files)} files to process")
        
        return files
