# detection/models.py

from django.db import models
from django.utils import timezone
import uuid

class DatasetInfo(models.Model):
    """Information about the DDoS dataset being used"""
    name = models.CharField(max_length=255)
    source = models.CharField(max_length=255)
    description = models.TextField()
    date_added = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return self.name

class AttackType(models.Model):
    """Types of DDoS attacks that can be detected"""
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity_level = models.IntegerField(choices=[
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
        (4, 'Critical')
    ])
    
    def __str__(self):
        return self.name

class NetworkFlow(models.Model):
    """Represents a single network flow with its features"""
    flow_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    
    # Source and destination info
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    
    # Basic flow statistics
    duration = models.FloatField(help_text="Flow duration in seconds")
    bytes_sent = models.BigIntegerField()
    bytes_received = models.BigIntegerField()
    packets_sent = models.IntegerField()
    packets_received = models.IntegerField()
    
    # Packet statistics
    packet_size_min = models.FloatField()
    packet_size_max = models.FloatField()
    packet_size_mean = models.FloatField()
    packet_size_std = models.FloatField()
    
    # Inter-arrival time statistics
    iat_min = models.FloatField(help_text="Minimum inter-arrival time")
    iat_max = models.FloatField(help_text="Maximum inter-arrival time")
    iat_mean = models.FloatField(help_text="Mean inter-arrival time")
    iat_std = models.FloatField(help_text="Standard deviation of inter-arrival time")
    
    # TCP flags
    tcp_flags = models.CharField(max_length=50, null=True, blank=True)
    
    # Flow features
    flow_iat_min = models.FloatField(help_text="Minimum inter-arrival time of flows")
    flow_iat_max = models.FloatField(help_text="Maximum inter-arrival time of flows")
    flow_iat_mean = models.FloatField(help_text="Mean inter-arrival time of flows")
    flow_iat_std = models.FloatField(help_text="Standard deviation of inter-arrival time of flows")
    
    # Flags
    is_fwd = models.BooleanField(help_text="Is the flow in the forward direction")
    
    # Additional features
    fwd_packets = models.IntegerField(help_text="Number of packets in forward direction")
    bwd_packets = models.IntegerField(help_text="Number of packets in backward direction")
    fwd_bytes = models.BigIntegerField(help_text="Number of bytes in forward direction")
    bwd_bytes = models.BigIntegerField(help_text="Number of bytes in backward direction")
    
    # For building indices
    dataset = models.ForeignKey(DatasetInfo, on_delete=models.CASCADE, related_name='flows')
    
    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
    
    class Meta:
        indexes = [
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['protocol']),
        ]

class DetectionResult(models.Model):
    """Results of DDoS detection on a network flow"""
    flow = models.OneToOneField(NetworkFlow, on_delete=models.CASCADE, related_name='detection')
    is_attack = models.BooleanField(default=False)
    attack_type = models.ForeignKey(AttackType, on_delete=models.SET_NULL, null=True, blank=True)
    confidence = models.FloatField(help_text="Confidence score of the detection (0-1)")
    detection_time = models.DateTimeField(default=timezone.now)
    
    # Features that contributed to the detection
    top_features = models.JSONField(default=dict, help_text="Top features that contributed to the detection")
    
    # Raw classification scores
    classification_scores = models.JSONField(default=dict, help_text="Raw classification scores")
    
    def __str__(self):
        return f"Detection for {self.flow.flow_id} - {'Attack' if self.is_attack else 'Normal'}"

class Alert(models.Model):
    """Alerts generated from detection results"""
    alert_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    detection = models.ForeignKey(DetectionResult, on_delete=models.CASCADE, related_name='alerts')
    timestamp = models.DateTimeField(default=timezone.now)
    severity = models.IntegerField(choices=[
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
        (4, 'Critical')
    ])
    message = models.TextField()
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Alert {self.alert_id} - {self.get_severity_display()}"

class DetectionModel(models.Model):
    """ML model information for DDoS detection"""
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50)
    algorithm = models.CharField(max_length=100)
    description = models.TextField()
    creation_date = models.DateTimeField(default=timezone.now)
    trained_on = models.ManyToManyField(DatasetInfo, related_name='models')
    is_active = models.BooleanField(default=False)
    model_file_path = models.CharField(max_length=255)
    performance_metrics = models.JSONField(default=dict, help_text="Performance metrics (accuracy, precision, recall, F1)")
    
    def __str__(self):
        return f"{self.name} v{self.version}"

class FeatureImportance(models.Model):
    """Feature importance for a detection model"""
    model = models.ForeignKey(DetectionModel, on_delete=models.CASCADE, related_name='feature_importances')
    feature_name = models.CharField(max_length=100)
    importance_score = models.FloatField()
    
    def __str__(self):
        return f"{self.feature_name} - {self.importance_score}"
    
    class Meta:
        ordering = ['-importance_score']

class TrafficStatistics(models.Model):
    """Aggregated traffic statistics for monitoring"""
    timestamp = models.DateTimeField(default=timezone.now)
    time_period = models.CharField(max_length=20, choices=[
        ('1min', '1 Minute'),
        ('5min', '5 Minutes'),
        ('15min', '15 Minutes'),
        ('1hour', '1 Hour'),
        ('1day', '1 Day'),
    ])
    total_flows = models.IntegerField()
    total_bytes = models.BigIntegerField()
    total_packets = models.BigIntegerField()
    avg_flow_duration = models.FloatField()
    attack_flows = models.IntegerField()
    attack_percentage = models.FloatField()
    
    def __str__(self):
        return f"Traffic Stats {self.timestamp} - {self.time_period}"
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['time_period']),
        ]

class BenignTrafficProfile(models.Model):
    """Baseline profile of normal traffic behavior"""
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # Baseline statistics
    avg_flow_duration = models.FloatField()
    avg_bytes_per_flow = models.FloatField()
    avg_packets_per_flow = models.FloatField()
    avg_packet_size = models.FloatField()
    avg_iat = models.FloatField(help_text="Average inter-arrival time")
    
    # Protocol distribution
    protocol_distribution = models.JSONField(default=dict)
    
    # Port distribution
    port_distribution = models.JSONField(default=dict)
    
    # Time-based features
    time_of_day_pattern = models.JSONField(default=dict)
    day_of_week_pattern = models.JSONField(default=dict)
    
    def __str__(self):
        return self.name

class ConfigSetting(models.Model):
    """System configuration settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.JSONField()
    description = models.TextField()
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.key
