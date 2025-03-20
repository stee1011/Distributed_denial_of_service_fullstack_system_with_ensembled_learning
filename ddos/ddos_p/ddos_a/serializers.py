# detection/serializers.py

from rest_framework import serializers
from .models import (
    NetworkFlow, DetectionResult, Alert,
    TrafficStatistics, DetectionModel
)

class NetworkFlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkFlow
        fields = '__all__'

class DetectionResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionResult
        fields = '__all__'

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'

class TrafficStatisticsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficStatistics
        fields = '__all__'

class DetectionModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionModel
        fields = '__all__'
        read_only_fields = ['creation_date', 'performance_metrics']

# 8. Create a basic preprocessor for ML