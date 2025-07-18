from collections import defaultdict
from typing import Dict, Any, Set, List

class ProfileStore:
    """
    A singleton in-memory store for client IP profiles.
    This is a simplified version for the MVP. In a production environment,
    this would be backed by a persistent store like Redis.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ProfileStore, cls).__new__(cls)
            # Use defaultdict to simplify profile creation on first access
            cls._instance.profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
                'uris': set(),
                'user_agents': set(),
                'session_count': 0,
                'total_bytes': 0,
                'first_seen': None,
                'last_seen': None,
                'session_features_history': [] # To store history for sequence analysis
            })
        return cls._instance

    def get_profile(self, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves the historical profile for a given IP address.
        Returns a default profile if the IP is new.
        """
        return self.profiles[ip_address]

    def update_profile(self, ip_address: str, session_features: Dict[str, Any]):
        """
        Updates the profile for a given IP address with new session features.
        
        Args:
            ip_address: The client IP address.
            session_features: The L2 features calculated for the latest session.
        """
        profile = self.get_profile(ip_address)

        # Update profile attributes
        profile['session_count'] += 1
        if 'uri' in session_features:
            profile['uris'].add(session_features['uri'])
        if 'user_agent' in session_features:
            profile['user_agents'].add(session_features['user_agent'])
        if 'total_bytes' in session_features:
            profile['total_bytes'] += session_features.get('total_bytes', 0)
        
        current_timestamp = session_features.get('timestamp', None)
        if profile.get('first_seen') is None:
            profile['first_seen'] = current_timestamp
        profile['last_seen'] = current_timestamp

        # Keep a history of recent session features for potential sequence analysis
        profile['session_features_history'].append(session_features)
        # Optional: Limit the history size
        max_history = 50
        if len(profile['session_features_history']) > max_history:
            profile['session_features_history'].pop(0)

        # Note: self.profiles is updated by reference
