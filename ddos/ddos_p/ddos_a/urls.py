from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    NetworkFlowViewSet, DetectionResultViewSet, AlertViewSet,
    TrafficStatisticsViewSet, DetectionModelViewSet, ddos_status, main_
)

router = DefaultRouter()
router.register(r'flows', NetworkFlowViewSet)
router.register(r'detections', DetectionResultViewSet)
router.register(r'alerts', AlertViewSet)
router.register(r'statistics', TrafficStatisticsViewSet)
router.register(r'models', DetectionModelViewSet)

urlpatterns = [
    path('status/', ddos_status, name='ddos-status'),
    path('home/', main_, name="main"), # Keep the status URL
    path('', include(router.urls)),  # Include API endpoints
]
