from django.urls import path
from banking_api.custom_auth.views import (
    LoginView, RegisterView, OTPVerifyView, GenerateOTPView,
    LogoutView, UserProfileView, ChangePasswordView
)

urlpatterns = [
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('otp-verify/', OTPVerifyView.as_view(), name='otp-verify'),
    path('generate-otp/', GenerateOTPView.as_view(), name='generate-otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # User profile endpoints
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]