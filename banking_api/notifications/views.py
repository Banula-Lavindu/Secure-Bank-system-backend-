from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.utils import timezone

from banking_api.notifications.models import Notification, NotificationPreference
from banking_api.notifications.serializers import (
    NotificationSerializer, NotificationPreferenceSerializer
)

class NotificationListView(APIView):
    """API view for listing user notifications"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get query parameters
        read_status = request.query_params.get('read')
        notification_type = request.query_params.get('type')
        
        # Base query - get notifications for the current user
        notifications = Notification.objects.filter(user=request.user)
        
        # Apply filters
        if read_status is not None:
            is_read = read_status.lower() == 'true'
            notifications = notifications.filter(read=is_read)
        
        if notification_type:
            notifications = notifications.filter(notification_type=notification_type)
        
        # Order by importance and recency
        notifications = notifications.order_by('-important', '-date_created')
        
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

class NotificationDetailView(APIView):
    """API view for individual notification operations"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        # Ensure notification belongs to the requesting user
        notification = get_object_or_404(Notification, pk=pk, user=request.user)
        serializer = NotificationSerializer(notification)
        return Response(serializer.data)
    
    def put(self, request, pk):
        # Ensure notification belongs to the requesting user
        notification = get_object_or_404(Notification, pk=pk, user=request.user)
        
        # Only allow updating the read status
        if 'read' in request.data:
            notification.read = request.data['read']
            if notification.read and not notification.date_read:
                notification.date_read = timezone.now()
            notification.save()
        
        serializer = NotificationSerializer(notification)
        return Response(serializer.data)

class NotificationMarkAllReadView(APIView):
    """API view to mark all notifications as read"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Get unread notifications for the user
        unread = Notification.objects.filter(user=request.user, read=False)
        count = unread.count()
        
        # Mark all as read
        unread.update(read=True, date_read=timezone.now())
        
        return Response({
            'message': f'Marked {count} notifications as read',
            'count': count
        })

class NotificationCountView(APIView):
    """API view to get count of unread notifications"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Count unread notifications
        unread_count = Notification.objects.filter(user=request.user, read=False).count()
        important_count = Notification.objects.filter(
            user=request.user, read=False, important=True
        ).count()
        
        return Response({
            'total_unread': unread_count,
            'important_unread': important_count
        })

class NotificationPreferenceView(APIView):
    """API view for notification preferences"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get or create notification preferences
        preferences, created = NotificationPreference.objects.get_or_create(user=request.user)
        serializer = NotificationPreferenceSerializer(preferences)
        return Response(serializer.data)
    
    def put(self, request):
        # Get or create notification preferences
        preferences, created = NotificationPreference.objects.get_or_create(user=request.user)
        
        serializer = NotificationPreferenceSerializer(preferences, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)