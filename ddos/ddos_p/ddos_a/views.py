# detection/views.py
from django.shortcuts import render
from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny

from .models import (
    NetworkFlow, DetectionResult, Alert,
    TrafficStatistics, DetectionModel
)
from .serializers import (
    NetworkFlowSerializer, DetectionResultSerializer,
    AlertSerializer, TrafficStatisticsSerializer,
    DetectionModelSerializer
)
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
import random


def main_(request):
    context = {
        "message":"Hey welcome tho this system"
    }
    return render(request, 'ddos_a/base.html', context)

class NetworkFlowViewSet(viewsets.ModelViewSet):
    """API endpoint for network flows"""
    queryset = NetworkFlow.objects.all().order_by('-timestamp')
    serializer_class = NetworkFlowSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['src_ip', 'dst_ip', 'protocol', 'dataset']
    search_fields = ['src_ip', 'dst_ip']
    ordering_fields = ['timestamp', 'bytes_sent', 'packets_sent']

class DetectionResultViewSet(viewsets.ModelViewSet):
    """API endpoint for detection results"""
    queryset = DetectionResult.objects.all().order_by('-detection_time')
    serializer_class = DetectionResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_attack', 'attack_type']
    search_fields = ['flow__src_ip', 'flow__dst_ip']
    ordering_fields = ['detection_time', 'confidence']

class AlertViewSet(viewsets.ModelViewSet):
    """API endpoint for alerts"""
    queryset = Alert.objects.all().order_by('-timestamp')
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['severity', 'is_acknowledged']
    search_fields = ['message']
    ordering_fields = ['timestamp', 'severity']

class TrafficStatisticsViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for traffic statistics"""
    queryset = TrafficStatistics.objects.all().order_by('-timestamp')
    serializer_class = TrafficStatisticsSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['time_period']
    ordering_fields = ['timestamp', 'total_flows', 'attack_percentage']

class DetectionModelViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for detection models"""
    queryset = DetectionModel.objects.all().order_by('-creation_date')
    serializer_class = DetectionModelSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['algorithm', 'is_active']
    search_fields = ['name', 'description']

from django.utils import timezone


from django.db.models import Count, Sum, Avg

from .models import (
    DatasetInfo, AttackType, NetworkFlow, DetectionResult,
    Alert, DetectionModel, FeatureImportance, TrafficStatistics,
    BenignTrafficProfile, ConfigSetting
)
import random


@api_view(['GET'])
@permission_classes([AllowAny])
def ddos_status(request):
    """API endpoint for real-time DDoS system status from the database"""

    # System Status (Active if any recent attacks detected)
    recent_detections = DetectionResult.objects.filter(
        detection_time__gte=timezone.now() - timezone.timedelta(minutes=5),
        is_attack=True
    ).count()
    system_status = "active" if recent_detections > 0 else "idle"

    # Traffic Statistics (Fetch latest)
    latest_statistics = TrafficStatistics.objects.order_by('-timestamp').first()
    current_traffic = {
        "value": round(latest_statistics.total_bytes / 1000000000, 1) if latest_statistics else 0,  # Convert bytes to Gbps
        "unit": "Gbps",
        "trend": latest_statistics.byte_trend if latest_statistics else 0
    }

    # Blocked Traffic (Sum of bytes from blocked attacks)
    blocked_traffic_value = DetectionResult.objects.filter(is_attack=True).aggregate(
        total=Sum('flow__bytes_sent')
    )['total'] or 0

    blocked_traffic = {
        "value": round(blocked_traffic_value / 1000000000, 1),  # Convert bytes to Gbps
        "unit": "Gbps",
        "trend": random.randint(-15, 15)  # Placeholder for lack of historical blocked data
    }

    # Active Attacks Count (Recent detections)
    past_hour_attack_count = DetectionResult.objects.filter(
        detection_time__gte=timezone.now() - timezone.timedelta(hours=1),
        is_attack=True
    ).count()

    attack_trend = past_hour_attack_count - recent_detections

    active_attacks_data = {
        "count": recent_detections,
        "trend": attack_trend
    }

    # Alerts Data
    alerts = list(Alert.objects.order_by('-timestamp').values("message", "severity", "timestamp")[:5])

    # Attack Distribution (Count by attack type)
    attack_distribution = (
    DetectionResult.objects.filter(is_attack=True)
    .values("attack_type__name")
    .annotate(count=Count("attack_type__name"))
)


    # Geographic Data (Source IPs count)
    geographic_data = list(NetworkFlow.objects.values('src_ip').annotate(attacks=Count('flow_id')))


    # Recent Attacks (Detection results)
    recent_attacks = list(
    DetectionResult.objects.filter(is_attack=True)
    .order_by("-detection_time")
    .values(
        "detection_time",
        "attack_type__name",
        "flow__src_ip",
        "flow__dst_ip",
        "flow__bytes_sent",
        "is_attack",
    )[:5]
)


    # Defense Modules Status (Assume ConfigSetting represents modules)
    defense_modules = {
        config.setting_name: config.setting_value for config in ConfigSetting.objects.all()
    }

    # Traffic Chart Data (Last 6 TrafficStatistics entries)
    traffic_logs = TrafficStatistics.objects.order_by('-timestamp')[:6]
    traffic_chart_data = {
        "timestamps": [],
        "trafficValues": []
    }

    for log in traffic_logs:
        if log.total_bytes is not None:
            traffic_chart_data["timestamps"].append(log.timestamp.strftime("%H:%M"))
            traffic_chart_data["trafficValues"].append(log.total_bytes / 1000000000)  # Convert bytes to Gbps

    # Response JSON
    data = {
        "systemStatus": system_status,
        "currentTraffic": current_traffic,
        "blockedTraffic": blocked_traffic,
        "activeAttacks": active_attacks_data,
        "alerts": alerts,
        "attackDistribution": attack_distribution,
        "geographicData": geographic_data,
        "recentAttacks": recent_attacks,
        "defenseModules": defense_modules,
        "trafficChartData": traffic_chart_data
    }
    
    return Response(data)
