from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.utils import timezone
from django.contrib.auth.models import update_last_login
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters
import redis
from django.core.cache import cache
from django.core.cache.backends.base import CacheKeyWarning
import re
import random
import string
import logging
from django.core.exceptions import ValidationError
from django.conf import settings

from banking_api.accounts.models import User, UserSession
from banking_api.custom_auth.models import OTPVerification, RefreshToken as CustomRefreshToken
from banking_api.custom_auth.serializers import (
    LoginSerializer, RegisterSerializer, OTPVerificationSerializer,
    GenerateOTPSerializer, UserProfileSerializer, PasswordChangeSerializer
)
from banking_api.security.models import SecurityAuditLog

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_tokens_for_user(user):
    """Generate JWT tokens for a user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@method_decorator(sensitive_post_parameters('password'), name='dispatch')
class LoginView(APIView):
    """API view for user login"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            # Sanitize the input data before serialization
            input_data = {
                'email': self._sanitize_email(request.data.get('email', '')),
                'password': request.data.get('password', '')  # Don't modify password
            }
            
            serializer = LoginSerializer(data=input_data, context={'request': request})
            
            if serializer.is_valid():
                user = serializer.validated_data['user']
                
                # Check if 2FA is enabled for the user
                if user.two_factor_enabled:
                    # Generate and send OTP
                    ip_address = get_client_ip(request)
                    user_agent = request.META.get('HTTP_USER_AGENT', '')
                    
                    otp_serializer = GenerateOTPSerializer(
                        data={'email': user.email, 'purpose': 'login'},
                        context={'ip_address': ip_address, 'user_agent': user_agent}
                    )
                    
                    if otp_serializer.is_valid():
                        otp = otp_serializer.save()
                        
                        # In a real application, you would send the OTP via email or SMS here
                        # For demo purposes, we'll return it in the response (NEVER do this in production)
                        
                        return Response({
                            'message': 'Please verify your identity with the OTP sent to your email.',
                            'email': user.email,
                            'requires_otp': True,
                            'otp_code': otp.verification_code,  # REMOVE THIS IN PRODUCTION
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response(otp_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
                # If 2FA is not enabled, generate tokens directly
                tokens = get_tokens_for_user(user)
                
                # Update last login
                update_last_login(None, user)
                
                # Create user session record
                UserSession.objects.create(
                    user=user,
                    device=request.META.get('HTTP_USER_AGENT', 'Unknown'),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Log successful login
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='auth_success',
                    event_description=f"User {user.email} logged in successfully",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='low'
                )
                
                # Return user and tokens with structure that the frontend expects
                response_data = {
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_staff': user.is_staff,
                        'is_admin': user.is_superuser,
                        'role': 'admin' if user.is_staff else 'customer',
                        'dark_mode': user.dark_mode,
                        'language': user.language
                    },
                    # Ensure "token" key is present as expected by frontend
                    'token': tokens['access'],
                    'refresh_token': tokens['refresh'],
                }
                
                return Response(response_data, status=status.HTTP_200_OK)
            
            # Log failed login attempt
            email = request.data.get('email', 'unknown')
            SecurityAuditLog.objects.create(
                user=None,
                event_type='auth_failure',
                event_description=f"Failed login attempt for email: {email}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            # Log unexpected errors but don't expose them
            logger.error(f"Login error: {str(e)}")
            return Response(
                {"error": "An error occurred during login. Please try again."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _sanitize_email(self, email):
        """Sanitize email input"""
        if not email:
            return ""
        
        # Convert to lowercase
        email = email.lower()
        
        # Remove leading/trailing whitespace
        email = email.strip()
        
        # Limit length
        email = email[:255]
        
        return email

@method_decorator(sensitive_post_parameters('password', 'password2'), name='dispatch')
class RegisterView(APIView):
    """API view for user registration"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            # Sanitize input
            sanitized_data = self._sanitize_registration_data(request.data)
            
            # Validate required fields are present
            required_fields = ['email', 'first_name', 'last_name', 'password', 'password2']
            missing_fields = [field for field in required_fields if field not in sanitized_data or not sanitized_data[field]]
            
            if missing_fields:
                return Response({
                    'message': 'Missing required fields',
                    'errors': {field: ['This field is required'] for field in missing_fields}
                }, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = RegisterSerializer(data=sanitized_data)
            if serializer.is_valid():
                try:
                    user = serializer.save()
                    
                    # Generate OTP for email verification
                    ip_address = get_client_ip(request)
                    user_agent = request.META.get('HTTP_USER_AGENT', '')
                    
                    try:
                        # Add request to context for session storage fallback
                        context = {
                            'ip_address': ip_address, 
                            'user_agent': user_agent,
                            'request': request
                        }
                        
                        otp_serializer = GenerateOTPSerializer(
                            data={'email': user.email, 'purpose': 'registration'},
                            context=context
                        )
                        
                        if otp_serializer.is_valid():
                            try:
                                otp = otp_serializer.save()
                                otp_code = otp.verification_code
                                
                                # Log successful registration
                                SecurityAuditLog.objects.create(
                                    user=user,
                                    event_type='api_access',
                                    event_description=f"New user registration: {user.email}",
                                    ip_address=ip_address,
                                    user_agent=user_agent,
                                    severity='low'
                                )
                                
                                # Ensure consistent response format with otp_code at top level
                                return Response({
                                    'message': 'Registration successful. Please verify your email with the OTP.',
                                    'email': user.email,
                                    'otp_code': otp_code,  # REMOVE THIS IN PRODUCTION
                                }, status=status.HTTP_201_CREATED)
                            except Exception as e:
                                logger.error(f"Error in OTP generation: {str(e)}", exc_info=True)
                                # Generate a fallback OTP
                                fallback_otp = ''.join(random.choices(string.digits, k=6))
                                # Store in session
                                request.session[f'otp_{user.email}_registration'] = {
                                    'code': fallback_otp,
                                    'created_at': timezone.now().isoformat()
                                }
                                
                                # Ensure consistent response format with otp_code at top level
                                return Response({
                                    'message': 'Registration successful. Please use the verification code below.',
                                    'email': user.email,
                                    'otp_code': fallback_otp,  # REMOVE THIS IN PRODUCTION
                                    'note': 'Using fallback verification method'
                                }, status=status.HTTP_201_CREATED)
                        else:
                            # OTP validation error, but still keep the user registered
                            # Return a generated OTP even in case of validation error
                            emergency_otp = ''.join(random.choices(string.digits, k=6))
                            request.session[f'otp_{user.email}_registration_emergency'] = {
                                'code': emergency_otp,
                                'created_at': timezone.now().isoformat()
                            }
                            return Response({
                                'message': 'Registration successful, but there was an issue with verification code generation.',
                                'email': user.email,
                                'otp_code': emergency_otp,  # REMOVE THIS IN PRODUCTION
                                'errors': otp_serializer.errors
                            }, status=status.HTTP_201_CREATED)
                    except Exception as e:
                        logger.error(f"Registration OTP error: {str(e)}", exc_info=True)
                        # Registration still successful even with OTP issues
                        # Generate a fallback OTP for any exception case
                        emergency_fallback_otp = ''.join(random.choices(string.digits, k=6))
                        return Response({
                            'message': 'Registration successful. Please contact support for verification.',
                            'email': user.email,
                            'otp_code': emergency_fallback_otp,  # REMOVE THIS IN PRODUCTION
                        }, status=status.HTTP_201_CREATED)
                
                except TypeError as e:
                    # Specifically catch the username missing error
                    if "missing 1 required positional argument: 'username'" in str(e):
                        logger.error(f"Username generation error: {str(e)}")
                        return Response({
                            "message": "Could not generate a valid username. Please try again with a different email.",
                            "error": "username_generation_failed"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    # Re-raise other TypeError exceptions
                    raise
            else:
                # Improved error response format
                return Response({
                    'message': 'Registration validation failed',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Log failed registration attempt
            try:
                email = request.data.get('email', 'unknown')
                SecurityAuditLog.objects.create(
                    user=None,
                    event_type='auth_failure',
                    event_description=f"Failed registration attempt for email: {email}",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='medium'
                )
            except Exception as log_error:
                logger.error(f"Failed to log registration failure: {str(log_error)}")
        
        except ValidationError as e:
            # Handle validation errors
            logger.warning(f"Registration validation error: {str(e)}")
            return Response({
                "message": str(e),
                "error": "validation_error"
            }, status=status.HTTP_400_BAD_REQUEST)
        except TypeError as e:
            # Handle TypeError exceptions specifically
            logger.error(f"Registration type error: {str(e)}", exc_info=True)
            return Response({
                "error": "There was an issue with your registration data. Please check all fields and try again."
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Log unexpected errors but don't expose them
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            return Response({
                "message": "An error occurred during registration. Please try again.",
                "error": "server_error"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _sanitize_registration_data(self, data):
        """Sanitize registration input data"""
        sanitized = {}
        
        # Email: lowercase and trim
        if 'email' in data and data['email']:
            sanitized['email'] = data['email'].lower().strip()[:255]
        else:
            sanitized['email'] = ""
        
        # Names: strip and limit length
        if 'first_name' in data and data['first_name']:
            sanitized['first_name'] = data['first_name'].strip()[:30]
        else:
            sanitized['first_name'] = ""
            
        if 'last_name' in data and data['last_name']:
            sanitized['last_name'] = data['last_name'].strip()[:30]
        else:
            sanitized['last_name'] = ""
        
        # Phone: keep only allowed characters
        if 'phone' in data and data['phone']:
            # Keep only digits, +, -, spaces, and parentheses
            sanitized['phone'] = re.sub(r'[^\d\+\-\s\(\)]', '', data['phone'])[:20]
        
        # Passwords: don't modify, but include them
        if 'password' in data:
            sanitized['password'] = data['password']
            
        if 'password2' in data:
            sanitized['password2'] = data['password2']
        
        return sanitized

class OTPVerifyView(APIView):
    """API view for OTP verification"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate tokens
            tokens = get_tokens_for_user(user)
            
            # Update last login
            update_last_login(None, user)
            
            # Create user session record
            UserSession.objects.create(
                user=user,
                device=request.META.get('HTTP_USER_AGENT', 'Unknown'),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log successful verification
            SecurityAuditLog.objects.create(
                user=user,
                event_type='otp_verify',
                event_description=f"OTP verification successful for {user.email}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='low'
            )
            
            # Return user and tokens with consistent structure
            response_data = {
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_staff': user.is_staff,
                    'is_admin': user.is_superuser,
                    'role': 'admin' if user.is_staff else 'customer',
                    'dark_mode': user.dark_mode,
                    'language': user.language
                },
                'token': tokens['access'],  # Frontend expects this
                'refresh_token': tokens['refresh'],
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        # Improve error response
        return Response({
            'message': 'Invalid verification code or email',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class GenerateOTPView(APIView):
    """API view for generating OTP"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = GenerateOTPSerializer(
            data=request.data,
            context={
                'ip_address': get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')
            }
        )
        
        if serializer.is_valid():
            otp = serializer.save()
            
            # In a real application, send the OTP via email or SMS here
            # For demo purposes, we'll return it in the response
            
            return Response({
                'message': 'OTP sent successfully.',
                'email': otp.email,
                'otp_code': otp.verification_code,  # REMOVE THIS IN PRODUCTION
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """API view for user logout"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                # Blacklist the refresh token
                RefreshToken(refresh_token).blacklist()
                
                # Close user session
                user_sessions = UserSession.objects.filter(
                    user=request.user, 
                    is_active=True,
                    ip_address=get_client_ip(request)
                )
                user_sessions.update(is_active=False)
                
                # Log logout
                SecurityAuditLog.objects.create(
                    user=request.user,
                    event_type='auth_success',
                    event_description=f"User {request.user.email} logged out",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='low'
                )
                
                return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}")
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    """API view for user profile operations"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user profile details"""
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)
    
    def put(self, request):
        """Update user profile details"""
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            
            # Log profile update
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='profile_update',
                event_description=f"User {request.user.email} updated profile",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='low',
                additional_data={'updated_fields': list(request.data.keys())}
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    """API view for changing password"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = request.user
            # Set new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Log password change
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='password_change',
                event_description=f"Password changed for {user.email}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)