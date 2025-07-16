from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseEnricher(ABC):
    """
    Abstract base class for data enrichers.

    Each enricher is responsible for fetching contextual information for a list of IPs.
    """

    def __init__(self, config: Dict[str, Any], cache_manager=None):
        """
        Initializes the enricher.

        Args:
            config: A dictionary containing configuration for the enricher.
            cache_manager: An optional cache manager instance for caching results.
        """
        self.config = config
        self.cache = cache_manager

    @abstractmethod
    def enrich_ips(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Enriches a list of unique IP addresses.

        This method should handle fetching data from its source (API, local DB)
        and utilize the cache to avoid redundant lookups.

        Args:
            ips: A list of unique IP addresses to enrich.

        Returns:
            A dictionary where keys are the input IPs and values are dictionaries
            of the enrichment data. E.g.:
            {
                '8.8.8.8': {'country': 'USA', 'asn': 'Google LLC'},
                '1.1.1.1': {'country': 'Australia', 'asn': 'Cloudflare'}
            }
        """
        pass
