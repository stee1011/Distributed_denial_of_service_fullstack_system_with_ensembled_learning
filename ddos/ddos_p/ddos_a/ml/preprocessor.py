
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle
import os

class DDoSPreprocessor:
    """
    Preprocesses network flow data for DDoS detection models
    """
    def __init__(self):
        self.scaler = None
        self.feature_columns = None
    
    def fit(self, df):
        """
        Fit the preprocessor on training data
        
        Args:
            df: DataFrame containing network flow features
        """
        # Identify numerical columns to scale
        self.feature_columns = [
            'duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'packet_size_min', 'packet_size_max', 'packet_size_mean', 'packet_size_std',
            'iat_min', 'iat_max', 'iat_mean', 'iat_std',
            'flow_iat_min', 'flow_iat_max', 'flow_iat_mean', 'flow_iat_std',
            'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes'
        ]
        
        # Initialize and fit scaler
        self.scaler = StandardScaler()
        self.scaler.fit(df[self.feature_columns])
        
        return self
    
    def transform(self, df):
        """
        Transform network flow data for model input
        
        Args:
            df: DataFrame containing network flow features
            
        Returns:
            DataFrame with preprocessed features
        """
        # Create a copy to avoid modifying the original
        df_processed = df.copy()
        
        # Handle protocol encoding
        protocols = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
        df_processed['protocol_code'] = df_processed['protocol'].map(protocols)
        
        # Fill missing values
        df_processed = df_processed.fillna(0)
        
        # Scale features
        if self.scaler is not None and self.feature_columns is not None:
            df_processed[self.feature_columns] = self.scaler.transform(df_processed[self.feature_columns])
        
        # Add computed features
        df_processed['bytes_per_packet'] = df_processed['bytes_sent'] / (df_processed['packets_sent'] + 1)
        df_processed['packet_rate'] = df_processed['packets_sent'] / (df_processed['duration'] + 0.001)
        df_processed['byte_rate'] = df_processed['bytes_sent'] / (df_processed['duration'] + 0.001)
        
        return df_processed
    
    def save(self, path):
        """Save preprocessor to disk"""
        with open(path, 'wb') as f:
            pickle.dump({
                'scaler': self.scaler,
                'feature_columns': self.feature_columns
            }, f)
    
    def load(self, path):
        """Load preprocessor from disk"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.scaler = data['scaler']
            self.feature_columns = data['feature_columns']
        return self

# 9. Create a basic detector interface
