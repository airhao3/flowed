import importlib
import pkgutil
from pathlib import Path
from typing import Dict, Any, Type, Optional

import pandas as pd
from loguru import logger

from .processors.base_processor import BaseProcessor

class DataIngestor:
    """
    Discovers and manages data processors to ingest data from various sources.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initializes the DataIngestor.

        Args:
            config: The main configuration dictionary, which should contain
                    a 'data_ingestion' section.
        """
        self.config = config.get('data_ingestion', {})
        self.logger = logger.bind(module=__name__)
        self._processors: Dict[str, Type[BaseProcessor]] = {}
        self._discover_processors()

    def _discover_processors(self):
        """
        Dynamically discovers all available processor classes in the 'processors' module.
        """
        processors_package_path = Path(__file__).parent / "processors"
        package_name = 'flowed.data.processors'

        self.logger.info("Discovering data processors...")
        self.logger.debug(f"Looking for processors in: {processors_package_path}")
        
        for _, module_name, _ in pkgutil.iter_modules([str(processors_package_path)]):
            self.logger.debug(f"Found module: {module_name}")
            if module_name.startswith('base_'):
                continue
            
            try:
                module = importlib.import_module(f".{module_name}", package=package_name)
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isinstance(attribute, type) and issubclass(attribute, BaseProcessor) and attribute is not BaseProcessor:
                        processor_key = module_name.replace('_processor', '')
                        self._processors[processor_key] = attribute
                        self.logger.info(f"Discovered processor: '{processor_key}' -> {attribute.__name__}")
            except Exception as e:
                self.logger.warning(f"Could not import or inspect module {module_name}: {e}")

    def process_files(self, file_paths: list) -> (pd.DataFrame, Dict[str, Any]):
        """Process a list of raw data files and return aggregated statistics."""
        all_data = []
        aggregated_stats = {
            'total_files': len(file_paths),
            'files_processed_successfully': 0,
            'total_packets_read': 0,
            'malformed_packets_skipped': 0,
            'packets_failed_validation': 0,
            'packets_out_of_size_range': 0,
            'packets_successfully_processed': 0,
        }

        for file_path in file_paths:
            try:
                processed_df, stats = self.process_file(file_path)
                if not processed_df.empty:
                    all_data.append(processed_df)
                    aggregated_stats['files_processed_successfully'] += 1
                    # Aggregate stats from each file
                    for key in stats:
                        if key in aggregated_stats and isinstance(stats[key], int):
                            aggregated_stats[key] += stats[key]
            except Exception as e:
                self.logger.error(f"Failed to process file {file_path}: {e}")

        if not all_data:
            self.logger.warning("No data was successfully ingested from any of the provided files.")
            return pd.DataFrame(), aggregated_stats

        final_df = pd.concat(all_data, ignore_index=True)
        self.logger.info(f"Successfully ingested {len(final_df)} records from {len(file_paths)} files.")
        return final_df, aggregated_stats

    def process_file(self, file_path: str, processor_type: Optional[str] = None) -> (pd.DataFrame, Dict[str, Any]):
        """
        Processes a single data file using the appropriate processor.

        Args:
            file_path: The path to the data file.
            processor_type: The type of processor to use (e.g., 'pcap'). If not provided,
                            it will be inferred from the configuration.

        Returns:
            A tuple of (DataFrame, stats_dict).
        """
        if processor_type is None:
            # For now, we infer from file extension. Could be made more robust.
            file_suffix = Path(file_path).suffix.lstrip('.').lower()
            if file_suffix in ['pcap', 'pcapng']:
                processor_type = 'pcap'
            else:
                raise ValueError(f"Could not determine processor type for file: {file_path}")
        
        log = self.logger.bind(file_path=file_path, processor_type=processor_type)
        log.info("Processing file with selected processor")

        ProcessorClass = self._processors.get(processor_type)
        if not ProcessorClass:
            log.error(
                "Processor not found for the given type",
                available_processors=list(self._processors.keys())
            )
            raise ValueError(f"Processor type '{processor_type}' not supported.")

        processor_config = self.config.get('processors', {}).get(processor_type, {})
        processor_instance = ProcessorClass(config=processor_config)
        
        return processor_instance.process(file_path)
