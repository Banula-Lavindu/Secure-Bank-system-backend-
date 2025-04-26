from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404

from banking_api.accounts.models import BankAccount, UserSession
from banking_api.accounts.serializers import (
    BankAccountSerializer, UserSessionSerializer, UserPreferencesSerializer
)
from banking_api.security.models import SecurityAuditLog
from banking_api.custom_auth.views import get_client_ip

class BankAccountListView(APIView):
    """API view for listing user's bank accounts"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        accounts = BankAccount.objects.filter(user=request.user)
        serializer = BankAccountSerializer(accounts, many=True)
        return Response(serializer.data)

class BankAccountDetailView(APIView):
    """API view for bank account details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        # Ensure the account belongs to the requesting user
        account = get_object_or_404(BankAccount, pk=pk, user=request.user)
        serializer = BankAccountSerializer(account)
        
        # Log access to sensitive information
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='sensitive_data',
            event_description=f"Accessed bank account details for account {account.get_masked_account_number()}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='low'
        )
        
        return Response(serializer.data)

class UserSessionListView(APIView):
    """API view for listing user's active sessions"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        sessions = UserSession.objects.filter(user=request.user).order_by('-last_active')
        serializer = UserSessionSerializer(sessions, many=True)
        return Response(serializer.data)

class UserSessionTerminateView(APIView):
    """API view for terminating a user session"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        # Ensure the session belongs to the requesting user
        session = get_object_or_404(UserSession, pk=pk, user=request.user)
        
        if not session.is_active:
            return Response(
                {'error': 'Session is already terminated'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Terminate session
        session.is_active = False
        session.save()
        
        # Log session termination
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Terminated session from {session.device}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='medium'
        )
        
        return Response({'message': 'Session terminated successfully'}, status=status.HTTP_200_OK)

class UserPreferencesView(APIView):
    """API view for user preferences"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserPreferencesSerializer(request.user)
        return Response(serializer.data)
    
    def put(self, request):
        serializer = UserPreferencesSerializer(request.user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            
            # Log preference changes
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='profile_update',
                event_description=f"Updated user preferences",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='low',
                additional_data={'updated_fields': list(request.data.keys())}
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)