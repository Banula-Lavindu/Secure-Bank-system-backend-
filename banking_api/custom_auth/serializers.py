from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
import re
import logging

from banking_api.accounts.models import User
from banking_api.custom_auth.models import OTPVerification

import random
import string

logger = logging.getLogger(__name__)

class LoginSerializer(serializers.Serializer):
    """Serializer for user login endpoint"""
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate_email(self, value):
        """Additional validation for email format"""
        # Check if email follows proper format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError(_('Enter a valid email address.'))
        
        # Check for common email security issues
        if len(value) > 255:  # RFC 5321 email length limit
            raise serializers.ValidationError(_('Email address is too long.'))
        
        return value
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if not email or not password:
            raise serializers.ValidationError(_('Must include email and password.'))
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Use a generic error to prevent user enumeration
            raise serializers.ValidationError(_('Invalid email or password.'))
        
        # Authenticate user
        user = authenticate(
            request=self.context.get('request'), 
            username=email, 
            password=password
        )
        
        if not user:
            raise serializers.ValidationError(_('Invalid email or password.'))
        
        attrs['user'] = user
        return attrs

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration endpoint"""
    password = serializers.CharField(
        write_only=True, 
        required=True,
        style={'input_type': 'password'},
    )
    password2 = serializers.CharField(
        write_only=True, 
        required=True,
        style={'input_type': 'password'},
    )
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password', 'password2', 'phone')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'phone': {'required': True}
        }
    
    def validate_email(self, value):
        """Additional validation for email format and uniqueness"""
        # Check if email follows proper format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError(_('Enter a valid email address.'))
        
        # Check for common email security issues
        if len(value) > 255:  # RFC 5321 email length limit
            raise serializers.ValidationError(_('Email address is too long.'))
        
        # Check if email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(_('A user with that email already exists.'))
        
        return value
    
    def validate_phone(self, value):
        """Validate phone number format"""
        # Strip non-alphanumeric characters for comparison
        cleaned_phone = re.sub(r'\W+', '', value)
        
        # Ensure phone number contains only digits, +, -, and spaces
        if not re.match(r'^[0-9+\-\s()]+$', value):
            raise serializers.ValidationError(_('Enter a valid phone number.'))
        
        # Check length (after removing non-digits)
        digits_only = re.sub(r'\D+', '', value)
        if len(digits_only) < 7 or len(digits_only) > 15:
            raise serializers.ValidationError(_('Phone number must be between 7 and 15 digits.'))
        
        return value
    
    def validate_password(self, value):
        """Validate password strength"""
        if len(value) < 8:
            raise serializers.ValidationError(_('Password must be at least 8 characters long.'))
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(_('Password must contain at least one uppercase letter.'))
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(_('Password must contain at least one lowercase letter.'))
        
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError(_('Password must contain at least one number.'))
        
        if not re.search(r'[^A-Za-z0-9]', value):
            raise serializers.ValidationError(_('Password must contain at least one special character.'))
        
        return value
    
    def validate_first_name(self, value):
        """Validate first name"""
        if not re.match(r'^[a-zA-Z\s\-\']+$', value):
            raise serializers.ValidationError(_('First name can only contain letters, spaces, hyphens and apostrophes.'))
        return value
    
    def validate_last_name(self, value):
        """Validate last name"""
        if not re.match(r'^[a-zA-Z\s\-\']+$', value):
            raise serializers.ValidationError(_('Last name can only contain letters, spaces, hyphens and apostrophes.'))
        return value
    
    def validate(self, attrs):
        """Validate that the passwords match"""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": _("Password fields didn't match.")})
        
        return attrs
    
    def create(self, validated_data):
        """Create a new user with validated data"""
        # Remove password2 as we don't store it
        validated_data.pop('password2', None)
        
        # Generate username from email if not provided
        if 'username' not in validated_data:
            email = validated_data.get('email')
            # Generate username based on the part before @ in email
            base_username = email.split('@')[0]
            # Make it unique by appending random digits if needed
            username = base_username
            suffix = 1
            
            # Check if username exists and make it unique
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{suffix}"
                suffix += 1
            
            validated_data['username'] = username
        
        # Create the user
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        return user

class OTPVerificationSerializer(serializers.Serializer):
    """Serializer for OTP verification endpoint"""
    email = serializers.EmailField(required=True)
    verification_code = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate(self, attrs):
        email = attrs.get('email')
        code = attrs.get('verification_code')
        
        # Find the latest active OTP for this email
        try:
            otp = OTPVerification.objects.filter(
                email=email,
                is_used=False,
                is_active=True,
                expires_at__gt=timezone.now()
            ).latest('created_at')
        except OTPVerification.DoesNotExist:
            raise serializers.ValidationError(_('Invalid or expired verification code.'))
        
        # Verify the code
        if otp.verification_code != code:
            raise serializers.ValidationError(_('Invalid verification code.'))
        
        # Mark OTP as used
        otp.invalidate()
        
        # Find the user
        try:
            user = User.objects.get(email=email)
            if user.is_active == False:
                # Activate user after successful verification
                user.is_active = True
                user.save(update_fields=['is_active'])
            attrs['user'] = user
        except User.DoesNotExist:
            # This shouldn't happen in normal flow since user is created during registration
            raise serializers.ValidationError(_('User not found.'))
        
        return attrs

class GenerateOTPSerializer(serializers.Serializer):
    """Serializer for generating OTP"""
    email = serializers.EmailField(required=True)
    purpose = serializers.ChoiceField(
        choices=['registration', 'login', 'reset_password', 'change_email'],
        required=True
    )
    
    def validate(self, attrs):
        email = attrs.get('email')
        purpose = attrs.get('purpose')
        
        # For registration, email should not exist
        if purpose == 'registration':
            if User.objects.filter(email=email).exists():
                raise serializers.ValidationError({"email": _("A user with this email already exists.")})
        
        # For other purposes, email should exist
        elif purpose in ['login', 'reset_password', 'change_email']:
            try:
                user = User.objects.get(email=email)
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError({"email": _("No user found with this email.")})
        
        return attrs
    
    def create(self, validated_data):
        email = validated_data.get('email')
        purpose = validated_data.get('purpose')
        user = validated_data.get('user', None)
        
        try:
            # Invalidate any existing active OTPs for this email and purpose
            OTPVerification.objects.filter(
                email=email,
                purpose=purpose,
                is_active=True
            ).update(is_active=False)
        except Exception as e:
            # Log the error but continue
            logger.error(f"Error invalidating existing OTPs: {str(e)}", exc_info=True)
        
        # Generate random 6-digit OTP
        verification_code = ''.join(random.choices(string.digits, k=6))
        
        try:
            # Create new OTP record
            otp = OTPVerification.objects.create(
                user=user,
                email=email,
                verification_code=verification_code,
                purpose=purpose,
                expires_at=timezone.now() + timezone.timedelta(minutes=10),
                ip_address=self.context.get('ip_address'),
                user_agent=self.context.get('user_agent', '')
            )
            return otp
        except Exception as e:
            # Log the error and create an in-memory OTP object
            logger.error(f"Error creating OTP: {str(e)}", exc_info=True)
            
            # Create and return an in-memory OTP object (won't be saved to DB)
            otp = OTPVerification(
                user=user,
                email=email,
                verification_code=verification_code,
                purpose=purpose,
                expires_at=timezone.now() + timezone.timedelta(minutes=10),
                ip_address=self.context.get('ip_address'),
                user_agent=self.context.get('user_agent', '')
            )
            
            # Store the OTP in the request session if possible
            request = self.context.get('request')
            if request and hasattr(request, 'session'):
                request.session[f'otp_{email}_{purpose}'] = {
                    'code': verification_code,
                    'expires_at': timezone.now().timestamp() + 600  # 10 minutes
                }
            
            return otp

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile data"""
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name', 
            'phone', 'date_of_birth', 'address', 'two_factor_enabled', 
            'dark_mode', 'language', 'notifications_enabled'
        ]
        read_only_fields = ['id', 'email', 'two_factor_enabled']

class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change endpoint"""
    current_password = serializers.CharField(
        style={'input_type': 'password'},
        required=True,
        write_only=True
    )
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        required=True,
        write_only=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        style={'input_type': 'password'},
        required=True,
        write_only=True
    )
    
    def validate(self, attrs):
        # Check if new passwords match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": _("New passwords don't match.")})
        
        # Check if current password is correct
        user = self.context['request'].user
        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError({"current_password": _("Current password is incorrect.")})
        
        return attrs