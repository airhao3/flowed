import unittest
import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock

from flowed.data.sequence_builder import SequenceBuilder
from flowed.models.model_manager import ModelManager
from flowed.utils.config import load_config

class TestLSTMPipeline(unittest.TestCase):
    """Integration test for the full LSTM pipeline."""

    def setUp(self):
        """Set up a clean environment for each test."""
        # Load default config and override for testing
        self.config = load_config()
        self.config['model']['lstm_autoencoder']['params'] = {
            'encoding_dim': 8,
            'epochs': 1, # Run quickly for tests
            'batch_size': 1
        }
        self.model_manager = ModelManager(self.config)
        self.sequence_length = self.config['model']['sequence']['length']
        self.num_features = 10 # Example number of features

    def _generate_dummy_sequence_data(self, num_sequences):
        """Generates dummy data for training and testing."""
        return np.random.rand(num_sequences, self.sequence_length, self.num_features)

    def test_full_lstm_pipeline(self):
        """
        Tests the full pipeline: training an LSTM model, saving it, loading it,
        and using it for detection.
        """
        # 1. Generate training data
        training_data = self._generate_dummy_sequence_data(num_sequences=20)

        # 2. Train the model
        # The train method will automatically save the model upon completion
        with patch('tensorflow.keras.models.Model.save') as mock_save:
            self.model_manager.train('lstm_autoencoder', training_data)
            mock_save.assert_called_once() # Ensure save was attempted

        # Check if the model is in memory after training
        self.assertIsNotNone(self.model_manager.models['lstm_autoencoder'])
        self.assertTrue(hasattr(self.model_manager.models['lstm_autoencoder'].model, 'model'))

        # 3. Generate a new sequence for detection
        # This sequence is similar to the training data (normal)
        normal_sequence = self._generate_dummy_sequence_data(num_sequences=1)
        
        # This sequence is deliberately different (anomalous)
        anomalous_sequence = self._generate_dummy_sequence_data(num_sequences=1) + 5.0

        # 4. Detect anomalies
        normal_score = self.model_manager.detect('lstm_autoencoder', normal_sequence)
        anomalous_score = self.model_manager.detect('lstm_autoencoder', anomalous_sequence)

        # 5. Assertions
        self.assertIsNotNone(normal_score)
        self.assertIsNotNone(anomalous_score)

        # The reconstruction error for the anomalous sequence should be significantly higher
        self.assertGreater(anomalous_score, normal_score)
        self.assertGreater(anomalous_score, 0.1) # Expect a high error for the anomaly
        self.assertLess(normal_score, 0.9) # Expect a low error for normal data

        print(f"\nLSTM Test: Normal Score = {normal_score:.4f}, Anomalous Score = {anomalous_score:.4f}")

if __name__ == '__main__':
    unittest.main()
