# 2. Script for training and evaluating models
# detection/management/commands/train_model.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from detection.models import DatasetInfo, NetworkFlow, DetectionModel, FeatureImportance, AttackType
from detection.ml.preprocessor import DDoSPreprocessor
from detection.ml.detector import DDoSDetector
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import json
import os
import uuid

class Command(BaseCommand):
    help = 'Train a DDoS detection model'

    def add_arguments(self, parser):
        parser.add_argument('--dataset', type=str, required=True, help='Dataset name to use for training')
        parser.add_argument('--model-name', type=str, required=True, help='Name for the model')
        parser.add_argument('--algorithm', type=str, default='RandomForest', help='Algorithm to use')
        parser.add_argument('--test-size', type=float, default=0.2, help='Test set ratio')
        parser.add_argument('--output-dir', type=str, default='models', help='Directory to save models')

    def handle(self, *args, **options):
        dataset_name = options['dataset']
        model_name = options['model_name']
        algorithm = options['algorithm']
        test_size = options['test_size']
        output_dir = options['output_dir']
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get dataset
        try:
            dataset = DatasetInfo.objects.get(name=dataset_name)
        except DatasetInfo.DoesNotExist:
            self.stderr.write(self.style.ERROR(f'Dataset {dataset_name} does not exist'))
            return
        
        self.stdout.write(self.style.SUCCESS(f'Loading data from {dataset_name}'))
        
        # Create a unique version based on timestamp
        version = timezone.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate model file paths
        model_file = os.path.join(output_dir, f'{model_name}_{version}.pkl')
        preprocessor_file = os.path.join(output_dir, f'{model_name}_{version}_preprocessor.pkl')
        metadata_file = os.path.join(output_dir, f'{model_name}_{version}_metadata.json')
        
        # Load data from database
        self.stdout.write(self.style.SUCCESS('Querying flows from database...'))
        # For large datasets, you might need to implement batching here
        flows = NetworkFlow.objects.filter(dataset=dataset).values(
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'packet_size_min', 'packet_size_max', 'packet_size_mean', 'packet_size_std',
            'iat_min', 'iat_max', 'iat_mean', 'iat_std',
            'flow_iat_min', 'flow_iat_max', 'flow_iat_mean', 'flow_iat_std',
            'is_fwd', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes'
        )
        
        # Convert to DataFrame
        df = pd.DataFrame(list(flows))
        
        # For this example, we'll simulate labels (in a real scenario, labels would come from the dataset)
        # Here we're using a simple heuristic: flows with extremely high packet rates are considered attacks
        packet_rate = df['packets_sent'] / (df['duration'] + 0.001)
        byte_rate = df['bytes_sent'] / (df['duration'] + 0.001)
        
        # Assign synthetic labels for demonstration
        # In a real scenario, you would use actual labels from your dataset
        df['label'] = 0  # Default: normal traffic
        # Mark as DoS attack based on packet rate threshold
        df.loc[packet_rate > packet_rate.quantile(0.95), 'label'] = 1
        # Mark as DDoS attack based on byte rate threshold
        df.loc[byte_rate > byte_rate.quantile(0.98), 'label'] = 2
        
        # Split data
        X = df.drop(columns=['label'])
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Preprocess data
        self.stdout.write(self.style.SUCCESS('Preprocessing data...'))
        preprocessor = DDoSPreprocessor()
        preprocessor.fit(X_train)
        
        X_train_processed = preprocessor.transform(X_train)
        X_test_processed = preprocessor.transform(X_test)
        
        # Train model
        self.stdout.write(self.style.SUCCESS(f'Training {algorithm} model...'))
        attack_types = {0: 'Normal', 1: 'DoS', 2: 'DDoS'}
        detector = DDoSDetector()
        detector.train(X_train_processed, y_train, attack_types=attack_types)
        
        # Evaluate model
        self.stdout.write(self.style.SUCCESS('Evaluating model...'))
        results = detector.predict(X_test_processed)
        
        y_pred = np.array([attack_types.get(int(label), 'Unknown') for label in y_test])
        y_pred_labels = np.array([list(attack_types.keys())[list(attack_types.values()).index(at)] 
                          if at in attack_types.values() else 0 
                          for at in results['attack_type']])
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred_labels)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred_labels, average='weighted'
        )
        
        # Save detection model details to database
        model_db = DetectionModel.objects.create(
            name=model_name,
            version=version,
            algorithm=algorithm,
            description=f"Trained on {dataset_name} dataset",
            creation_date=timezone.now(),
            is_active=False,  # Set to False initially
            model_file_path=model_file,
            performance_metrics={
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
        )
        
        # Add dataset relation
        model_db.trained_on.add(dataset)
        
        # Save feature importances
        feature_importance = detector.get_feature_importance()
        for feature, importance in feature_importance.items():
            FeatureImportance.objects.create(
                model=model_db,
                feature_name=feature,
                importance_score=float(importance)
                            )
        
        # Save model files (model, preprocessor, metadata)
        self.stdout.write(self.style.SUCCESS(f'Saving model files to {output_dir}...'))
        with open(model_file, 'wb') as f:
            detector.save(f)
        
        with open(preprocessor_file, 'wb') as f:
            preprocessor.save(f)
        
        metadata = {
            'model_name': model_name,
            'version': version,
            'algorithm': algorithm,
            'dataset': dataset_name,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'features': list(X.columns)
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)
        
        self.stdout.write(self.style.SUCCESS(f'Model {model_name} training complete.'))
