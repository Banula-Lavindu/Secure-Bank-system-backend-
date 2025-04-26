from django.contrib import admin
from .models import OTPVerification, LoginAttempt, RefreshToken
import logging

logger = logging.getLogger(__name__)

class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ('email', 'purpose', 'created_at', 'expires_at', 'is_used', 'is_active')
    list_filter = ('purpose', 'is_used', 'is_active', 'created_at')
    search_fields = ('email',)
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation of OTPs
    
    def save_model(self, request, obj, form, change):
        try:
            super().save_model(request, obj, form, change)
        except Exception as e:
            logger.error(f"Error saving OTP in admin: {str(e)}")
            self.message_user(request, "Error saving OTP. Please check Redis connection.", level="ERROR")

class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'successful', 'ip_address', 'timestamp', 'failure_reason')
    list_filter = ('successful', 'timestamp')
    search_fields = ('username', 'ip_address')
    date_hierarchy = 'timestamp'
    readonly_fields = ('username', 'successful', 'ip_address', 'timestamp', 'user_agent', 'failure_reason')
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation
    
    def has_change_permission(self, request, obj=None):
        return False  # Prevent changes

class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'revoked')
    list_filter = ('revoked', 'created_at')
    search_fields = ('user__email',)
    date_hierarchy = 'created_at'
    readonly_fields = ('user', 'token', 'device_identifier', 'ip_address', 
                      'user_agent', 'created_at', 'expires_at')
    
    def has_add_permission(self, request):
        return False  # Prevent manual creation

# Register models with admin site
try:
    admin.site.register(OTPVerification, OTPVerificationAdmin)
    admin.site.register(LoginAttempt, LoginAttemptAdmin)
    admin.site.register(RefreshToken, RefreshTokenAdmin)
except Exception as e:
    logger.error(f"Error registering auth models with admin: {str(e)}")
