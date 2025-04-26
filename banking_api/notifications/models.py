from django.db import models
from django.utils.translation import gettext_lazy as _
from banking_api.accounts.models import User

class Notification(models.Model):
    """Model for storing user notifications"""
    NOTIFICATION_TYPES = (
        ('transaction', 'Transaction Notification'),
        ('security', 'Security Alert'),
        ('promotion', 'Promotional Message'),
        ('info', 'General Information'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=100)
    message = models.TextField()
    read = models.BooleanField(default=False)
    important = models.BooleanField(default=False)
    date_created = models.DateTimeField(auto_now_add=True)
    date_read = models.DateTimeField(null=True, blank=True)
    action_url = models.CharField(max_length=255, blank=True, help_text="URL for action button in notification")
    action_text = models.CharField(max_length=50, blank=True, help_text="Text for action button in notification")
    related_object_id = models.PositiveIntegerField(null=True, blank=True, help_text="ID of related object (transaction, etc.)")
    related_object_type = models.CharField(max_length=50, blank=True, help_text="Type of related object")
    
    class Meta:
        verbose_name = _('notification')
        verbose_name_plural = _('notifications')
        ordering = ['-important', '-date_created']
    
    def __str__(self):
        return f"{self.get_notification_type_display()} - {self.title}"
    
    @property
    def short_message(self):
        """Return a shortened version of the message"""
        if len(self.message) <= 100:
            return self.message
        return f"{self.message[:97]}..."

class NotificationPreference(models.Model):
    """Model for storing user notification preferences"""
    NOTIFICATION_CHANNELS = (
        ('app', 'In-App Notification'),
        ('email', 'Email Notification'),
        ('sms', 'SMS Notification'),
        ('push', 'Push Notification'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notification_preferences')
    transaction_notifications = models.BooleanField(default=True)
    security_notifications = models.BooleanField(default=True)
    promotional_notifications = models.BooleanField(default=False)
    info_notifications = models.BooleanField(default=True)
    
    # Channel preferences
    transaction_channel = models.CharField(max_length=10, choices=NOTIFICATION_CHANNELS, default='app')
    security_channel = models.CharField(max_length=10, choices=NOTIFICATION_CHANNELS, default='app')
    promotional_channel = models.CharField(max_length=10, choices=NOTIFICATION_CHANNELS, default='app')
    info_channel = models.CharField(max_length=10, choices=NOTIFICATION_CHANNELS, default='app')
    
    class Meta:
        verbose_name = _('notification preference')
        verbose_name_plural = _('notification preferences')
    
    def __str__(self):
        return f"Notification Preferences for {self.user.email}"