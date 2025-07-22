from collections import deque
from typing import Dict, List, Any

import numpy as np


class SequenceBuilder:
    """
    Builds and manages fixed-length sequences of session feature vectors for each IP.

    This class is responsible for taking the feature vector of each new session
    and appending it to a sequence associated with the client's IP address.
    When a sequence reaches the required length, it is ready to be fed into the
    LSTM model for anomaly detection.
    """

    def __init__(self, sequence_length: int = 50):
        """
        Initializes the SequenceBuilder.

        Args:
            sequence_length: The fixed length of the feature sequences required by the LSTM model.
        """
        self.sequence_length = sequence_length
        self.sequences: Dict[str, deque] = {}

    def add_session_features(self, ip_address: str, features: List[float]) -> np.ndarray | None:
        """
        Adds a new session's feature vector to the corresponding IP's sequence.

        Args:
            ip_address: The client IP address.
            features: A list of numerical features for the session.

        Returns:
            A NumPy array of shape (sequence_length, num_features) if a full
            sequence is ready, otherwise None.
        """
        if ip_address not in self.sequences:
            self.sequences[ip_address] = deque(maxlen=self.sequence_length)
        
        self.sequences[ip_address].append(features)

        if len(self.sequences[ip_address]) == self.sequence_length:
            return np.array(self.sequences[ip_address])
        
        return None
        
    def add(self, ip_address: str, features: Dict[str, Any]) -> np.ndarray | None:
        """
        Alias for add_session_features for backward compatibility.
        
        Args:
            ip_address: The client IP address.
            features: A dictionary of features for the session.
            
        Returns:
            A NumPy array of shape (sequence_length, num_features) if a full
            sequence is ready, otherwise None.
        """
        # 将特征字典转换为列表形式
        feature_list = list(features.values())
        return self.add_session_features(ip_address, feature_list)
        
    def is_ready(self, ip_address: str) -> bool:
        """
        Checks if the sequence for the given IP address is ready for prediction.
        
        Args:
            ip_address: The client IP address to check.
            
        Returns:
            bool: True if a full sequence is ready, False otherwise.
        """
        return (ip_address in self.sequences and 
                len(self.sequences[ip_address]) == self.sequence_length)
