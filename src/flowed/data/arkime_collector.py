import re
from datetime import datetime
from io import StringIO

import pandas as pd
import requests
from loguru import logger

class ArkimeCollector:
    """
    Collects traffic data from an Arkime API endpoint.
    """
    def __init__(self, config):
        self.api_url = config.get('url')
        self.auth_header = config.get('auth_header')
        self.verify_ssl = config.get('verify_ssl', True)
        self.logger = logger.bind(module=__name__)

    def collect(self) -> pd.DataFrame:
        """
        Fetches data from the Arkime API and returns it as a pandas DataFrame.

        Returns:
            A DataFrame containing the traffic data, or an empty DataFrame on error.
        """
        if not self.api_url or not self.auth_header:
            self.logger.error("Arkime API URL or auth header is not configured.")
            return pd.DataFrame()

        self.logger.info(f"Fetching data from Arkime API: {self.api_url}")
        try:
            response = requests.get(
                self.api_url,
                headers={"Authorization": self.auth_header},
                verify=self.verify_ssl
            )
            response.raise_for_status()

            csv_data = response.text
            # The timestamp column from Arkime is 'firstPacket'
            df = pd.read_csv(StringIO(csv_data), header=0, parse_dates=['firstPacket'])
            df.columns = [self._sanitize_column_name(col) for col in df.columns]

            # Rename 'firstpacket' to 'timestamp' for downstream compatibility
            if 'firstpacket' in df.columns:
                df.rename(columns={'firstpacket': 'timestamp'}, inplace=True)
            else:
                self.logger.error("Timestamp column ('firstPacket') not found in Arkime data.")
                return pd.DataFrame()

            self.logger.success(f"Successfully collected and processed {len(df)} records from Arkime.")
            return df

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch data from Arkime API: {e}")
            return pd.DataFrame()

    def _sanitize_column_name(self, column_name: str) -> str:
        """Converts a column name to a standardized snake_case format."""
        # Replace known abbreviations and special cases
        name = column_name.replace(' ', '_').replace('.', '_').lower()
        # Handle cases like 'SrcIP' -> 'src_ip'
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
        # Remove any remaining non-alphanumeric characters
        name = re.sub(r'[^a-z0-9_]+', '', name)
        return name
