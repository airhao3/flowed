import ipaddress
from typing import List, Dict, Any

import requests
from loguru import logger

from .base_enricher import BaseEnricher

class IpregistryEnricher(BaseEnricher):
    """
    Enriches IP addresses using the ipregistry.co API.
    """
    API_BASE_URL = "https://api.ipregistry.co"

    def __init__(self, config: Dict[str, Any], cache_manager=None):
        super().__init__(config, cache_manager)
        self.logger = logger.bind(module=__name__)
        self.api_key = self.config.get('api_key')
        self.session = requests.Session()

        if not self.api_key:
            self.logger.error("ipregistry API key is missing. Please add it to your configuration.")
            self.api_key = None # Ensure it's None if empty

    def enrich_ips(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Enriches a list of IPs using the ipregistry.co bulk lookup.

        Args:
            ips: A list of unique IP addresses.

        Returns:
            A dictionary mapping each IP to its enrichment data.
        """
        if not self.api_key:
            self.logger.warning("ipregistry enricher is disabled due to missing API key.")
            return {}

        # Filter out private/reserved IP addresses
        public_ips = []
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    public_ips.append(ip)
            except ValueError:
                self.logger.warning(f"Invalid IP address format: {ip}")

        if not public_ips:
            self.logger.info("No public IPs to enrich.")
            return {}

        results = {}
        ips_to_fetch = []

        # Step 1: Check cache first
        if self.cache:
            for ip in public_ips:
                cached_data = self.cache.get(f"ipregistry_{ip}")
                if cached_data:
                    results[ip] = cached_data
                else:
                    ips_to_fetch.append(ip)
        else:
            ips_to_fetch = public_ips

        if not ips_to_fetch:
            return results

        # Step 2: Fetch non-cached IPs from the API using bulk lookup
        self.logger.info(f"Fetching {len(ips_to_fetch)} IPs from ipregistry.co API...")
        try:
            response = self.session.post(
                f"{self.API_BASE_URL}?key={self.api_key}",
                json=ips_to_fetch
            )
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            api_results = response.json().get('results', [])

            # Step 3: Process results and update cache
            for data in api_results:
                ip = data.get('ip')
                if not ip:
                    continue
                
                # Flatten the nested structure for easier use in pandas
                flat_data = {
                    'company_name': data.get('company', {}).get('name'),
                    'company_domain': data.get('company', {}).get('domain'),
                    'connection_asn': data.get('connection', {}).get('asn'),
                    'connection_org': data.get('connection', {}).get('organization'),
                    'connection_type': data.get('connection', {}).get('type'),
                    'country_code': data.get('location', {}).get('country', {}).get('code'),
                    'country_name': data.get('location', {}).get('country', {}).get('name'),
                    'city': data.get('location', {}).get('city'),
                    'latitude': data.get('location', {}).get('latitude'),
                    'longitude': data.get('location', {}).get('longitude'),
                    'security_is_threat': data.get('security', {}).get('is_threat'),
                    'threat_types': ','.join(data.get('security', {}).get('threats', []) or []),
                }
                results[ip] = flat_data
                if self.cache:
                    # Cache for 1 day as threat data can change
                    self.cache.set(f"ipregistry_{ip}", flat_data, ttl_seconds=86400)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch data from ipregistry API: {e}")
        
        return results
