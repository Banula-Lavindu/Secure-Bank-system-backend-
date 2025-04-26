from rest_framework import serializers
from banking_api.notifications.models import Notification, NotificationPreference

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""
    notification_type_display = serializers.CharField(source='get_notification_type_display', read_only=True)
    
    class Meta:
        model = Notification
        fields = [
            'id', 'user', 'notification_type', 'notification_type_display',
            'title', 'message', 'read', 'important', 'date_created',
            'date_read', 'action_url', 'action_text', 'related_object_id',
            'related_object_type'
        ]
        read_only_fields = fields

class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """Serializer for notification preferences"""
    transaction_channel_display = serializers.CharField(source='get_transaction_channel_display', read_only=True)
    security_channel_display = serializers.CharField(source='get_security_channel_display', read_only=True)
    promotional_channel_display = serializers.CharField(source='get_promotional_channel_display', read_only=True)
    info_channel_display = serializers.CharField(source='get_info_channel_display', read_only=True)
    
    class Meta:
        model = NotificationPreference
        fields = [
            'id', 'user', 'transaction_notifications', 'security_notifications',
            'promotional_notifications', 'info_notifications',
            'transaction_channel', 'transaction_channel_display',
            'security_channel', 'security_channel_display',
            'promotional_channel', 'promotional_channel_display',
            'info_channel', 'info_channel_display'
        ]
        read_only_fields = ['id', 'user']