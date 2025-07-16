from pathlib import Path
from typing import List, Dict, Any

import geoip2.database
import geoip2.errors
from loguru import logger

from .base_enricher import BaseEnricher

class GeoIPEnricher(BaseEnricher):
    """
    Enriches IP addresses with Geo-location information using a local MaxMind DB.
    """

    def __init__(self, config: Dict[str, Any], cache_manager=None):
        super().__init__(config, cache_manager)
        self.logger = logger.bind(module=__name__)
        self.db_path = Path(self.config.get('db_path', 'data/geodb/GeoLite2-City.mmdb'))
        self.reader = None

        if not self.db_path.exists():
            self.logger.error(f"GeoIP database not found at {self.db_path}. ")
            self.logger.error("Please download it from MaxMind and place it in the correct directory.")
        else:
            try:
                self.reader = geoip2.database.Reader(str(self.db_path))
                self.logger.info("GeoIP database loaded successfully.")
            except Exception as e:
                self.logger.error(f"Failed to load GeoIP database: {e}")

    def enrich_ips(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Enriches a list of IPs with geo-location data.

        Args:
            ips: A list of unique IP addresses.

        Returns:
            A dictionary mapping each IP to its enrichment data.
        """
        if not self.reader:
            self.logger.warning("GeoIP reader not available. Skipping enrichment.")
            return {}

        results = {}
        for ip in ips:
            # First, try to get from cache
            if self.cache:
                cached_data = self.cache.get(f"geoip_{ip}")
                if cached_data:
                    results[ip] = cached_data
                    continue
            
            # If not in cache, look it up
            try:
                response = self.reader.city(ip)
                data = {
                    'country': response.country.name,
                    'country_iso': response.country.iso_code,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'asn': response.traits.autonomous_system_number,
                    'asn_org': response.traits.autonomous_system_organization
                }
                results[ip] = data

                # Store in cache (no TTL, as GeoIP data is static)
                if self.cache:
                    self.cache.set(f"geoip_{ip}", data)

            except geoip2.errors.AddressNotFoundError:
                self.logger.trace(f"IP address not found in GeoIP database: {ip}")
                # Cache the fact that it's not found to avoid re-querying
                if self.cache:
                    self.cache.set(f"geoip_{ip}", {'error': 'not_found'}, ttl_seconds=86400) # cache for 1 day
            except Exception as e:
                self.logger.warning(f"Error enriching IP {ip}: {e}")
        
        return results

    def __del__(self):
        if self.reader:
            self.reader.close()
