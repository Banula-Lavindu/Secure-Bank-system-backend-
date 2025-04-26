from django.db import models
from django.utils.translation import gettext_lazy as _
from banking_api.accounts.models import User

class AdminActivity(models.Model):
    """Model for tracking admin activities in the system"""
    ACTION_TYPES = (
        ('view', 'View Record'),
        ('create', 'Create Record'),
        ('update', 'Update Record'),
        ('delete', 'Delete Record'),
        ('approve', 'Approve Action'),
        ('reject', 'Reject Action'),
        ('reset', 'Reset Password'),
        ('lock', 'Lock Account'),
        ('unlock', 'Unlock Account'),
        ('other', 'Other Action'),
    )
    
    admin_user = models.ForeignKey(User, on_delete=models.PROTECT, related_name='admin_activities')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    target_model = models.CharField(max_length=50, help_text="Model name affected by the action")
    target_id = models.PositiveIntegerField(null=True, blank=True, help_text="ID of the affected record")
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    additional_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = _('admin activity')
        verbose_name_plural = _('admin activities')
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.admin_user.email} - {self.get_action_type_display()} - {self.timestamp}"

class SystemSetting(models.Model):
    """Model for global system settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    data_type = models.CharField(max_length=20, choices=(
        ('string', 'String'),
        ('integer', 'Integer'),
        ('float', 'Float'),
        ('boolean', 'Boolean'),
        ('json', 'JSON'),
    ), default='string')
    description = models.TextField(blank=True)
    is_public = models.BooleanField(default=False, help_text="Whether this setting can be accessed by the public API")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_modified_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='modified_settings'
    )
    
    class Meta:
        verbose_name = _('system setting')
        verbose_name_plural = _('system settings')
        ordering = ['key']
    
    def __str__(self):
        return f"{self.key}: {self.value}"

    @property
    def typed_value(self):
        """Return the value converted to its proper Python type"""
        if self.data_type == 'integer':
            return int(self.value)
        elif self.data_type == 'float':
            return float(self.value)
        elif self.data_type == 'boolean':
            return self.value.lower() in ('true', 'yes', '1')
        elif self.data_type == 'json':
            import json
            return json.loads(self.value)
        # Default to string
        return self.value

class PendingApproval(models.Model):
    """Model for operations that require admin approval"""
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    ACTION_TYPES = (
        ('large_transfer', 'Large Transfer'),
        ('user_role_change', 'User Role Change'),
        ('account_closure', 'Account Closure'),
        ('limit_change', 'Limit Change'),
        ('system_setting', 'System Setting Change'),
        ('other', 'Other Action'),
    )
    
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    requester = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='requested_approvals'
    )
    approver = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='processed_approvals'
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    request_data = models.JSONField(help_text="Data for the requested action")
    reason = models.TextField(help_text="Reason for the request")
    response_note = models.TextField(blank=True, help_text="Note from the approver")
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = _('pending approval')
        verbose_name_plural = _('pending approvals')
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.get_action_type_display()} - {self.status}"