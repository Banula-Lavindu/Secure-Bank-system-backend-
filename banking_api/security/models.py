from django.db import models
from django.utils.translation import gettext_lazy as _
from banking_api.accounts.models import User

class SecurityAuditLog(models.Model):
    """Model for storing security audit logs"""
    EVENT_TYPES = (
        ('auth_success', 'Successful Authentication'),
        ('auth_failure', 'Failed Authentication'),
        ('access_denied', 'Access Denied'),
        ('password_change', 'Password Changed'),
        ('email_change', 'Email Changed'),
        ('profile_update', 'Profile Updated'),
        ('role_change', 'Role Changed'),
        ('api_access', 'API Access'),
        ('sensitive_data', 'Sensitive Data Access'),
        ('otp_verify', 'OTP Verification'),
        ('lockout', 'Account Lockout'),
        ('suspicious', 'Suspicious Activity'),
    )
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='security_logs'
    )
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    event_description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_info = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=10, choices=(
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ), default='low')
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = _('security audit log')
        verbose_name_plural = _('security audit logs')
        ordering = ['-timestamp']
    
    def __str__(self):
        user_info = self.user.email if self.user else 'Anonymous'
        return f"{self.get_event_type_display()} - {user_info} - {self.timestamp}"

class BlacklistedToken(models.Model):
    """Model for storing blacklisted JWT tokens"""
    token = models.TextField(unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    reason = models.CharField(max_length=100, blank=True)
    
    class Meta:
        verbose_name = _('blacklisted token')
        verbose_name_plural = _('blacklisted tokens')
        ordering = ['-blacklisted_at']
    
    def __str__(self):
        return f"Token blacklisted at {self.blacklisted_at}"

class IPBlacklist(models.Model):
    """Model for storing blacklisted IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    added_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='added_ip_blacklist'
    )
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Leave blank for permanent blacklisting")
    
    class Meta:
        verbose_name = _('IP blacklist')
        verbose_name_plural = _('IP blacklists')
        ordering = ['-blacklisted_at']
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"
    
    @property
    def is_active(self):
        """Check if the blacklist is still active"""
        if not self.expires_at:
            return True
        from django.utils import timezone
        return self.expires_at > timezone.now()