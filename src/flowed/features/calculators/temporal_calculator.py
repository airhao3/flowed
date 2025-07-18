import pandas as pd
from .base_calculator import BaseCalculator

class TemporalCalculator(BaseCalculator):
    """Calculates time-based features."""

    def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculates temporal features."""
        if 'timestamp' not in df.columns:
            return df

        # Ensure timestamp is timezone-aware (UTC)
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)

        df = df.sort_values('timestamp').copy()

        # Inter-arrival time
        df['inter_arrival_time'] = df.groupby(['src_ip', 'dst_ip'])['timestamp'].diff().dt.total_seconds()

        # Activity intensity in a time window
        # Ensure timestamp is the index for rolling window operations
        df_indexed = df.set_index('timestamp')
        df['packets_in_1s_window'] = df_indexed.groupby('src_ip')['frame_len'].rolling('1s').count().reset_index(0, drop=True)

        # Periodicity detection
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_business_hours'] = ((df['hour_of_day'] >= 9) & (df['hour_of_day'] <= 17)).astype(int)

        return df
