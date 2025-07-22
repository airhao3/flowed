import numpy as np
import pandas as pd
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import StandardScaler

class LSTMAutoencoder:
    """
    An LSTM Autoencoder model for detecting anomalies in time-series sequences of network behavior.
    """

    def __init__(self, sequence_length: int, num_features: int, encoding_dim: int = 32, epochs: int = 50, batch_size: int = 64, lstm_layers: int = 1, dropout_rate: float = 0.0):
        """
        Initializes the LSTM Autoencoder.

        Args:
            sequence_length: The number of time steps in each sequence.
            num_features: The number of features in each time step.
            encoding_dim: The dimensionality of the latent space (bottleneck).
            epochs: The number of epochs for training.
            batch_size: The batch size for training.
        """
        self.sequence_length = sequence_length
        self.num_features = num_features
        self.encoding_dim = encoding_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lstm_layers = lstm_layers
        self.dropout_rate = dropout_rate
        self.scaler = StandardScaler()
        self.model = self._build_model()

    def _build_model(self) -> Model:
        """
        Builds the Keras LSTM Autoencoder model architecture.
        """
        # Encoder
        inputs = Input(shape=(self.sequence_length, self.num_features))
        x = inputs
        for i in range(self.lstm_layers):
            x = LSTM(self.encoding_dim, activation='relu', return_sequences=(i < self.lstm_layers - 1))(x)
            if self.dropout_rate > 0:
                x = Dropout(self.dropout_rate)(x)
        encoder = x

        # Bottleneck
        bottleneck = RepeatVector(self.sequence_length)(encoder)

        # Decoder
        decoder = LSTM(self.encoding_dim, activation='relu', return_sequences=True)(bottleneck)
        output = TimeDistributed(Dense(self.num_features))(decoder)

        model = Model(inputs=inputs, outputs=output)
        model.compile(optimizer='adam', loss='mae')
        model.summary()
        return model

    def train(self, data: np.ndarray):
        """
        Trains the autoencoder on the provided sequence data.

        Args:
            data: A 3D NumPy array of shape (num_samples, sequence_length, num_features).
        """
        # Scale the data
        # Reshape to 2D for scaler, then back to 3D
        nsamples, nx, ny = data.shape
        d2_data = data.reshape((nsamples * nx, ny))
        scaled_data_2d = self.scaler.fit_transform(d2_data)
        scaled_data = scaled_data_2d.reshape(nsamples, nx, ny)

        early_stopping = EarlyStopping(monitor='val_loss', patience=5, mode='min', restore_best_weights=True)
        self.model.fit(
            scaled_data,
            scaled_data, # Autoencoder learns to reconstruct the input
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_split=0.1,
            callbacks=[early_stopping]
        )

    def predict(self, data: np.ndarray) -> np.ndarray:
        """
        Calculates the reconstruction error for new sequences.

        Args:
            data: A 3D NumPy array of new sequences to evaluate.

        Returns:
            A 1D array of reconstruction errors (mean absolute error) for each sequence.
        """
        nsamples, nx, ny = data.shape
        d2_data = data.reshape((nsamples * nx, ny))
        scaled_data_2d = self.scaler.transform(d2_data)
        scaled_data = scaled_data_2d.reshape(nsamples, nx, ny)

        reconstructed_data = self.model.predict(scaled_data)
        mae = np.mean(np.abs(reconstructed_data - scaled_data), axis=(1, 2))
        return mae
