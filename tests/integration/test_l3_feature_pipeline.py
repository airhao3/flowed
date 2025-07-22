import unittest
import pandas as pd
import datetime

from flowed.features.extractor import FeatureExtractor
from flowed.profiles.profile_store import ProfileStore

class TestL3FeaturePipeline(unittest.TestCase):

    def setUp(self):
        """Set up a clean FeatureExtractor and ProfileStore for each test."""
        # Reset the singleton instance for test isolation
        ProfileStore._instance = None
        self.profile_store = ProfileStore()
        
        # Basic config for the extractor
        self.config = {
            'features': {
                'calculators': {
                    'flow_calculator': {'enabled': True},
                    'session_calculator': {'enabled': True},
                    'http_calculator': {'enabled': True}
                }
            }
        }
        self.feature_extractor = FeatureExtractor(self.config)

    def test_full_l3_pipeline_and_profile_update(self):
        """Tests the full pipeline from session data to L3 feature generation and profile update."""
        client_ip = "192.168.1.100"

        # --- First Session --- 
        session_1_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_1_data = pd.DataFrame([{
            'timestamp': session_1_timestamp,
            'src_ip': client_ip,
            'dst_ip': '8.8.8.8',
            'uri': '/api/v1/login',
            'user_agent': 'TestClient/1.0',
            'total_bytes': 500
        }])

        # Process the first session
        final_features_1, profile_1 = self.feature_extractor.extract_session_features(
            session_df=session_1_data, 
            client_ip=client_ip
        )

        # Assertions for the first session
        self.assertIsNotNone(final_features_1)
        self.assertEqual(final_features_1['is_first_session_for_ip'], 1)
        self.assertEqual(final_features_1['is_new_uri_for_ip'], 1)
        self.assertEqual(final_features_1['is_new_user_agent_for_ip'], 1)
        self.assertEqual(final_features_1['days_since_first_seen'], 0)

        # Verify profile store was updated
        updated_profile_1 = self.profile_store.get_profile(client_ip)
        self.assertEqual(updated_profile_1['session_count'], 1)
        self.assertIn('/api/v1/login', updated_profile_1['uris'])
        self.assertEqual(updated_profile_1['total_bytes'], 500)

        # --- Second Session (simulating a subsequent request) ---
        session_2_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_2_data = pd.DataFrame([{
            'timestamp': session_2_timestamp,
            'src_ip': client_ip,
            'dst_ip': '8.8.4.4',
            'uri': '/api/v1/login', # Same URI
            'user_agent': 'TestClient/1.0', # Same User-Agent
            'total_bytes': 250
        }])

        # Process the second session
        final_features_2, profile_2 = self.feature_extractor.extract_session_features(
            session_df=session_2_data, 
            client_ip=client_ip
        )

        # Assertions for the second session
        self.assertIsNotNone(final_features_2)
        self.assertEqual(final_features_2['is_first_session_for_ip'], 0)
        self.assertEqual(final_features_2['is_new_uri_for_ip'], 0) # Not new anymore
        self.assertEqual(final_features_2['is_new_user_agent_for_ip'], 0) # Not new anymore

        # Verify profile store was updated again
        updated_profile_2 = self.profile_store.get_profile(client_ip)
        self.assertEqual(updated_profile_2['session_count'], 2)
        self.assertEqual(updated_profile_2['total_bytes'], 750) # 500 + 250

if __name__ == '__main__':
    unittest.main()
