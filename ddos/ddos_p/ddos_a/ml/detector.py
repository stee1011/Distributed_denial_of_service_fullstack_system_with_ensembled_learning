# detection/ml/detector.py

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle
import os
import json

class DDoSDetector:
    """
    DDoS detection model implementation
    """
    def __init__(self):
        self.model = None
        self.preprocessor = None
        self.feature_columns = None
        self.attack_types = None
    
    def train(self, X_train, y_train, attack_types=None):
        """
        Train the detector on preprocessed data
        
        Args:
            X_train: Preprocessed feature DataFrame
            y_train: Target labels (0 for normal, 1+ for attack types)
            attack_types: Dictionary mapping label values to attack type names
        """
        self.feature_columns = X_train.columns.tolist()
        self.attack_types = attack_types or {0: 'Normal', 1: 'DDoS'}
        
        # Create and train the model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_train, y_train)
        
        return self
    
    def predict(self, X):
        """
        Predict on new data
        
        Args:
            X: Preprocessed feature DataFrame
            
        Returns:
            Predictions and confidence scores
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Ensure we have the expected features
        X = X[self.feature_columns]
        
        # Make predictions
        y_pred = self.model.predict(X)
        
        # Get probability scores
        y_proba = self.model.predict_proba(X)
        
        # Get confidence (highest probability)
        confidence = np.max(y_proba, axis=1)
        
        # Map numeric labels to attack types
        attack_types = [self.attack_types.get(int(label), 'Unknown') for label in y_pred]
        
        results = {
            'is_attack': (y_pred > 0).astype(bool),
            'attack_type': attack_types,
            'confidence': confidence,
            'raw_scores': y_proba
        }
        
        return results
    
    def get_feature_importance(self):
        """
        Get feature importance scores
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        importances = self.model.feature_importances_
        feature_importance = dict(zip(self.feature_columns, importances))
        return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
    
    def save(self, model_path, metadata_path=None):
        """
        Save the model and metadata
        
        Args:
            model_path: Path to save model file
            metadata_path: Path to save metadata (optional)
        """
        # Save the model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Save metadata if requested
        if metadata_path:
            metadata = {
                'feature_columns': self.feature_columns,
                'attack_types': self.attack_types,
                'feature_importance': self.get_feature_importance()
            }
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
    
    def load(self, model_path, metadata_path=None):
        """
        Load the model and metadata
        
        Args:
            model_path: Path to model file
            metadata_path: Path to metadata (optional)
        """
        # Load the model
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        # Load metadata if provided
        if metadata_path and os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.feature_columns = metadata.get('feature_columns')
                self.attack_types = metadata.get('attack_types')
        
        return self