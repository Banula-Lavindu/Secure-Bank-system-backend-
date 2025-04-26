from django.urls import path
from banking_api.notifications.views import (
    NotificationListView, NotificationDetailView,
    NotificationMarkAllReadView, NotificationCountView,
    NotificationPreferenceView
)

urlpatterns = [
    # Notification endpoints
    path('list/', NotificationListView.as_view(), name='notification-list'),
    path('<int:pk>/', NotificationDetailView.as_view(), name='notification-detail'),
    path('mark-all-read/', NotificationMarkAllReadView.as_view(), name='notification-mark-all-read'),
    path('count/', NotificationCountView.as_view(), name='notification-count'),
    path('preferences/', NotificationPreferenceView.as_view(), name='notification-preferences'),
]