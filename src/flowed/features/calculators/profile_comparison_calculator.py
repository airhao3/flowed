from typing import Dict, Any
import datetime

from .base_calculator import BaseCalculator

class ProfileComparisonCalculator(BaseCalculator):
    """
    Calculates L3 features by comparing current session features against a historical profile.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

    def calculate(self, session_features: Dict[str, Any], historical_profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates comparison features (L3) based on live session data and historical profile.

        Args:
            session_features: A dictionary of L2 features for the current session.
            historical_profile: A dictionary representing the IP's historical profile.

        Returns:
            A dictionary containing the new L3 comparison features.
        """
        l3_features = {}

        # --- Feature: Is this a new URI for this IP? ---
        current_uri = session_features.get('uri')
        if current_uri:
            l3_features['is_new_uri_for_ip'] = 1 if current_uri not in historical_profile.get('uris', set()) else 0
        else:
            l3_features['is_new_uri_for_ip'] = 0

        # --- Feature: Is this a new User-Agent for this IP? ---
        current_ua = session_features.get('user_agent')
        if current_ua:
            l3_features['is_new_user_agent_for_ip'] = 1 if current_ua not in historical_profile.get('user_agents', set()) else 0
        else:
            l3_features['is_new_user_agent_for_ip'] = 0

        # --- Feature: Is this the first session for this IP? ---
        l3_features['is_first_session_for_ip'] = 1 if historical_profile.get('session_count', 0) <= 1 else 0

        # --- Time-based features ---
        now = datetime.datetime.now(datetime.timezone.utc)
        first_seen_str = historical_profile.get('first_seen')
        last_seen_str = historical_profile.get('last_seen')

        if first_seen_str:
            first_seen_dt = datetime.datetime.fromisoformat(first_seen_str)
            l3_features['days_since_first_seen'] = (now - first_seen_dt).total_seconds() / (24 * 3600)
        else:
            l3_features['days_since_first_seen'] = 0

        if last_seen_str:
            last_seen_dt = datetime.datetime.fromisoformat(last_seen_str)
            l3_features['days_since_last_seen'] = (now - last_seen_dt).total_seconds() / (24 * 3600)
        else:
            l3_features['days_since_last_seen'] = 0

        return l3_features
