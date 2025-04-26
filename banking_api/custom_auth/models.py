from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _  # Add this import for translation
import logging

# Fix User import issue
from django.conf import settings

# Setup logger
logger = logging.getLogger(__name__)

class OTPVerification(models.Model):
    """Model for OTP verification codes"""
    # Fix the User reference by using settings.AUTH_USER_MODEL
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='otp_verifications'
    )
    email = models.EmailField()
    verification_code = models.CharField(max_length=6)
    purpose = models.CharField(
        max_length=20,
        choices=[
            ('registration', 'Registration'),
            ('login', 'Login'),
            ('reset_password', 'Reset Password'),
            ('change_email', 'Change Email')
        ]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
    
    def __str__(self):
        return f"OTP for {self.email} ({self.purpose})"
    
    def is_valid(self):
        """Check if OTP is still valid"""
        return (
            self.is_active and 
            not self.is_used and 
            self.expires_at > timezone.now()
        )
    
    def save(self, *args, **kwargs):
        try:
            super().save(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error saving OTP: {str(e)}", exc_info=True)
            # Handle the error gracefully, possibly by using a fallback method
            
    def invalidate(self):
        """Mark this OTP as used and inactive"""
        try:
            self.is_used = True
            self.is_active = False
            self.save(update_fields=['is_used', 'is_active'])
        except Exception as e:
            logger.error(f"Error invalidating OTP: {str(e)}", exc_info=True)
            # Even if we can't save to the database, continue with the flow

class TOTPDeviceManager(models.Manager):
    """Custom manager for TOTP devices"""
    def get_or_create_device(self, user):
        """Get existing device or create new one"""
        device, created = TOTPDevice.objects.get_or_create(
            user=user,
            defaults={
                'name': f"{user.email}'s device",
                'confirmed': False
            }
        )
        return device, created

class LoginAttempt(models.Model):
    """Model for tracking login attempts"""
    username = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    successful = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    failure_reason = models.CharField(max_length=100, blank=True)
    
    class Meta:
        verbose_name = _('login attempt')
        verbose_name_plural = _('login attempts')
        ordering = ['-timestamp']
    
    def __str__(self):
        status = "Success" if self.successful else "Failed"
        return f"{status} - {self.username} - {self.timestamp}"

class RefreshToken(models.Model):
    """Model for storing refresh tokens with device binding"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')  # Fix User reference
    token = models.CharField(max_length=255, unique=True)
    device_identifier = models.CharField(max_length=255, help_text="Device fingerprint for binding token to device")
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = _('refresh token')
        verbose_name_plural = _('refresh tokens')
    
    def __str__(self):
        return f"{self.user.email} - {'Active' if not self.revoked else 'Revoked'}"
    
    @property
    def is_valid(self):
        """Check if token is valid"""
        return not self.revoked and timezone.now() < self.expires_at
    
    def revoke(self):
        """Revoke the token"""
        self.revoked = True
        self.revoked_at = timezone.now()
        self.save(update_fields=['revoked', 'revoked_at'])