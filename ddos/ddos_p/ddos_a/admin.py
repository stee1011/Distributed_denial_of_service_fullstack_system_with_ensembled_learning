
# detection/admin.py

from django.contrib import admin
from .models import (
    DatasetInfo, AttackType, NetworkFlow, DetectionResult, Alert,
    DetectionModel, FeatureImportance, TrafficStatistics, BenignTrafficProfile,
    ConfigSetting
)


@admin.register(DatasetInfo)
class DatasetInfoAdmin(admin.ModelAdmin):
    list_display = ('name', 'source', 'date_added')
    search_fields = ('name', 'description')

@admin.register(AttackType)
class AttackTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity_level')
    list_filter = ('severity_level',)
    search_fields = ('name', 'description')

@admin.register(NetworkFlow)
class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ('flow_id', 'src_ip', 'dst_ip', 'protocol', 'timestamp')
    list_filter = ('protocol', 'dataset')
    search_fields = ('src_ip', 'dst_ip')
    date_hierarchy = 'timestamp'
    readonly_fields = ('flow_id',)

@admin.register(DetectionResult)
class DetectionResultAdmin(admin.ModelAdmin):
    list_display = ('flow', 'is_attack', 'attack_type', 'confidence', 'detection_time')
    list_filter = ('is_attack', 'attack_type')
    search_fields = ('flow__src_ip', 'flow__dst_ip')
    date_hierarchy = 'detection_time'

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_id', 'severity', 'timestamp', 'is_acknowledged', 'acknowledged_by')
    list_filter = ('severity', 'is_acknowledged')
    search_fields = ('message', 'detection__flow__src_ip', 'detection__flow__dst_ip')
    date_hierarchy = 'timestamp'
    readonly_fields = ('alert_id',)

@admin.register(DetectionModel)
class DetectionModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'algorithm', 'creation_date', 'is_active')
    list_filter = ('algorithm', 'is_active')
    search_fields = ('name', 'description')
    filter_horizontal = ('trained_on',)

@admin.register(FeatureImportance)
class FeatureImportanceAdmin(admin.ModelAdmin):
    list_display = ('feature_name', 'importance_score', 'model')
    list_filter = ('model',)
    search_fields = ('feature_name',)

@admin.register(TrafficStatistics)
class TrafficStatisticsAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'time_period', 'total_flows', 'attack_percentage')
    list_filter = ('time_period',)
    date_hierarchy = 'timestamp'

@admin.register(BenignTrafficProfile)
class BenignTrafficProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('name',)

@admin.register(ConfigSetting)
class ConfigSettingAdmin(admin.ModelAdmin):
    list_display = ('key', 'last_updated')
    search_fields = ('key', 'description')

# 5. Create URL configuration