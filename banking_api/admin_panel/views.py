from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q

from banking_api.admin_panel.models import AdminActivity, SystemSetting, PendingApproval
from banking_api.admin_panel.serializers import (
    AdminUserSerializer, AdminBankAccountSerializer,
    AdminActivitySerializer, SystemSettingSerializer,
    PendingApprovalSerializer
)
from banking_api.accounts.models import User, BankAccount
from banking_api.security.models import SecurityAuditLog
from banking_api.custom_auth.views import get_client_ip
from banking_api.notifications.models import Notification

# Custom permissions
class IsAdminUser(IsAuthenticated):
    """Permission class that checks if the user is an admin"""
    def has_permission(self, request, view):
        return super().has_permission(request, view) and request.user.is_staff

class AdminPagination(PageNumberPagination):
    """Custom pagination for admin views"""
    page_size = 15
    page_size_query_param = 'page_size'
    max_page_size = 100

# Helper functions
def log_admin_activity(request, action_type, target_model, target_id, description, additional_data=None):
    """Helper function to log admin activities"""
    AdminActivity.objects.create(
        admin_user=request.user,
        action_type=action_type,
        target_model=target_model,
        target_id=target_id,
        description=description,
        ip_address=get_client_ip(request),
        additional_data=additional_data or {}
    )

# User management views
class AdminUserListView(APIView):
    """API view for listing and creating users (admin only)"""
    permission_classes = [IsAdminUser]
    pagination_class = AdminPagination
    
    def get(self, request):
        # Query parameters for filtering
        search = request.query_params.get('search', '')
        role = request.query_params.get('role', '')
        status_filter = request.query_params.get('status', '')
        
        # Base query
        users = User.objects.all()
        
        # Apply filters
        if search:
            users = users.filter(
                Q(email__icontains=search) |
                Q(username__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(phone__icontains=search)
            )
        
        if role:
            if role == 'admin':
                users = users.filter(is_staff=True)
            elif role == 'customer':
                users = users.filter(is_staff=False)
        
        if status_filter:
            is_active = status_filter.lower() == 'active'
            users = users.filter(is_active=is_active)
        
        # Order by most recently joined
        users = users.order_by('-date_joined')
        
        # Paginate results
        paginator = self.pagination_class()
        paginated_users = paginator.paginate_queryset(users, request)
        
        serializer = AdminUserSerializer(paginated_users, many=True)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='User',
            target_id=None,
            description=f"Viewed user list with {users.count()} users"
        )
        
        return paginator.get_paginated_response(serializer.data)
    
    def post(self, request):
        serializer = AdminUserSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create user
            user = serializer.save()
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='create',
                target_model='User',
                target_id=user.id,
                description=f"Created user: {user.email}"
            )
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Admin created user: {user.email}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminUserDetailView(APIView):
    """API view for retrieving, updating and deleting users (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        serializer = AdminUserSerializer(user)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='User',
            target_id=user.id,
            description=f"Viewed user details for: {user.email}"
        )
        
        return Response(serializer.data)
    
    def put(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        serializer = AdminUserSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Check if role change requires approval
            is_role_change = ('is_staff' in request.data and user.is_staff != request.data['is_staff'])
            
            if is_role_change and not request.user.is_superuser:
                # Create a pending approval for role change
                PendingApproval.objects.create(
                    action_type='user_role_change',
                    requester=request.user,
                    status='pending',
                    request_data={
                        'user_id': user.id,
                        'email': user.email,
                        'current_role': 'admin' if user.is_staff else 'customer',
                        'new_role': 'admin' if request.data['is_staff'] else 'customer',
                        'changes': request.data
                    },
                    reason=request.data.get('approval_reason', 'No reason provided')
                )
                
                # Log admin activity
                log_admin_activity(
                    request=request,
                    action_type='other',
                    target_model='User',
                    target_id=user.id,
                    description=f"Requested role change for user: {user.email}"
                )
                
                return Response({
                    'message': 'Role change requires approval from a superuser.',
                    'status': 'pending_approval'
                })
            
            # Normal update
            updated_user = serializer.save()
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='update',
                target_model='User',
                target_id=user.id,
                description=f"Updated user: {user.email}",
                additional_data={'changes': request.data}
            )
            
            # Log security event for sensitive changes
            sensitive_fields = ['is_active', 'is_staff', 'is_superuser']
            has_sensitive_change = any(field in request.data for field in sensitive_fields)
            
            if has_sensitive_change:
                SecurityAuditLog.objects.create(
                    user=request.user,
                    event_type='role_change',
                    event_description=f"Admin updated sensitive user data for: {user.email}",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='high',
                    additional_data={'changes': {k: v for k, v in request.data.items() if k in sensitive_fields}}
                )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        
        # Only superusers can delete users
        if not request.user.is_superuser:
            return Response({
                'error': 'Only superusers can delete users.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Check if the user has accounts
        has_accounts = BankAccount.objects.filter(user=user).exists()
        
        if has_accounts:
            return Response({
                'error': 'Cannot delete a user with active bank accounts.',
                'message': 'Deactivate the user instead.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Log before deletion
        email = user.email
        user_id = user.id
        
        # Delete user
        user.delete()
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='delete',
            target_model='User',
            target_id=user_id,
            description=f"Deleted user: {email}"
        )
        
        # Log security event
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Admin deleted user: {email}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='high'
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)

# Bank account management views
class AdminBankAccountListView(APIView):
    """API view for listing and creating bank accounts (admin only)"""
    permission_classes = [IsAdminUser]
    pagination_class = AdminPagination
    
    def get(self, request):
        # Query parameters for filtering
        user_id = request.query_params.get('user_id', '')
        account_type = request.query_params.get('account_type', '')
        status_filter = request.query_params.get('status', '')
        min_balance = request.query_params.get('min_balance', '')
        max_balance = request.query_params.get('max_balance', '')
        
        # Base query
        accounts = BankAccount.objects.all()
        
        # Apply filters
        if user_id:
            accounts = accounts.filter(user_id=user_id)
        
        if account_type:
            accounts = accounts.filter(account_type=account_type)
        
        if status_filter:
            is_active = status_filter.lower() == 'active'
            accounts = accounts.filter(is_active=is_active)
        
        if min_balance:
            accounts = accounts.filter(balance__gte=min_balance)
        
        if max_balance:
            accounts = accounts.filter(balance__lte=max_balance)
        
        # Order by most recently created
        accounts = accounts.order_by('-created_at')
        
        # Paginate results
        paginator = self.pagination_class()
        paginated_accounts = paginator.paginate_queryset(accounts, request)
        
        serializer = AdminBankAccountSerializer(paginated_accounts, many=True)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='BankAccount',
            target_id=None,
            description=f"Viewed bank account list with {accounts.count()} accounts"
        )
        
        return paginator.get_paginated_response(serializer.data)
    
    def post(self, request):
        serializer = AdminBankAccountSerializer(data=request.data)
        
        if serializer.is_valid():
            # Create account
            account = serializer.save()
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='create',
                target_model='BankAccount',
                target_id=account.id,
                description=f"Created bank account: {account.account_number} for user: {account.user.email}"
            )
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Admin created bank account: {account.get_masked_account_number()}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            # Notify user
            Notification.objects.create(
                user=account.user,
                notification_type='info',
                title='New Account Created',
                message=f"A new {account.get_account_type_display()} account has been created for you.",
                important=True,
                action_url='/accounts',
                action_text='View Account'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminBankAccountDetailView(APIView):
    """API view for retrieving, updating and deleting bank accounts (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request, pk):
        account = get_object_or_404(BankAccount, pk=pk)
        serializer = AdminBankAccountSerializer(account)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='BankAccount',
            target_id=account.id,
            description=f"Viewed bank account details for: {account.get_masked_account_number()}"
        )
        
        return Response(serializer.data)
    
    def put(self, request, pk):
        account = get_object_or_404(BankAccount, pk=pk)
        serializer = AdminBankAccountSerializer(account, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Check if updating balance directly
            is_balance_update = 'balance' in request.data
            current_balance = account.balance
            
            # Keep track of sensitive fields
            sensitive_fields = ['balance', 'credit_limit', 'interest_rate', 'is_active']
            has_sensitive_change = any(field in request.data for field in sensitive_fields)
            
            # Check if this needs approval
            if has_sensitive_change and not request.user.is_superuser:
                # Create a pending approval
                PendingApproval.objects.create(
                    action_type='account_closure' if 'is_active' in request.data and not request.data['is_active'] else 'limit_change',
                    requester=request.user,
                    status='pending',
                    request_data={
                        'account_id': account.id,
                        'account_number': account.get_masked_account_number(),
                        'user_email': account.user.email,
                        'current_values': {
                            field: getattr(account, field) 
                            for field in sensitive_fields if field in request.data
                        },
                        'new_values': {
                            field: request.data[field] 
                            for field in sensitive_fields if field in request.data
                        },
                    },
                    reason=request.data.get('approval_reason', 'No reason provided')
                )
                
                # Log admin activity
                log_admin_activity(
                    request=request,
                    action_type='other',
                    target_model='BankAccount',
                    target_id=account.id,
                    description="Requested approval for account changes"
                )
                
                return Response({
                    'message': 'Changes to sensitive account data require approval.',
                    'status': 'pending_approval'
                })
            
            # Regular update
            updated_account = serializer.save()
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='update',
                target_model='BankAccount',
                target_id=account.id,
                description=f"Updated bank account: {account.get_masked_account_number()}",
                additional_data={'changes': request.data}
            )
            
            # Log security event for sensitive changes
            if has_sensitive_change:
                SecurityAuditLog.objects.create(
                    user=request.user,
                    event_type='api_access',
                    event_description=f"Admin updated sensitive account data for: {account.get_masked_account_number()}",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='high',
                    additional_data={'changes': {k: v for k, v in request.data.items() if k in sensitive_fields}}
                )
                
                # Notify user of important account changes
                if is_balance_update:
                    Notification.objects.create(
                        user=account.user,
                        notification_type='transaction',
                        title='Account Balance Updated',
                        message=f"Your account balance has been updated from {current_balance} to {account.balance}.",
                        important=True,
                        action_url='/accounts',
                        action_text='View Account'
                    )
                elif 'is_active' in request.data:
                    status_text = 'activated' if account.is_active else 'deactivated'
                    Notification.objects.create(
                        user=account.user,
                        notification_type='security',
                        title=f'Account {status_text.capitalize()}',
                        message=f"Your account has been {status_text}. Please contact support if this was unexpected.",
                        important=True,
                        action_url='/support',
                        action_text='Contact Support'
                    )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# System settings views
class AdminSystemSettingListView(APIView):
    """API view for listing and creating system settings (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        # Superusers can see all settings, regular admins only see public ones
        if request.user.is_superuser:
            settings = SystemSetting.objects.all()
        else:
            settings = SystemSetting.objects.filter(is_public=True)
        
        settings = settings.order_by('key')
        serializer = SystemSettingSerializer(settings, many=True)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='SystemSetting',
            target_id=None,
            description=f"Viewed system settings"
        )
        
        return Response(serializer.data)
    
    def post(self, request):
        # Only superusers can create system settings
        if not request.user.is_superuser:
            return Response({
                'error': 'Only superusers can create system settings.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Add the current user as the last modified by
        request.data['last_modified_by'] = request.user.id
        
        serializer = SystemSettingSerializer(data=request.data)
        if serializer.is_valid():
            # Create setting
            setting = serializer.save(last_modified_by=request.user)
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='create',
                target_model='SystemSetting',
                target_id=setting.id,
                description=f"Created system setting: {setting.key}"
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminSystemSettingDetailView(APIView):
    """API view for retrieving, updating and deleting system settings (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request, pk):
        # Ensure the setting exists
        setting = get_object_or_404(SystemSetting, pk=pk)
        
        # Check if user has permission to view this setting
        if not setting.is_public and not request.user.is_superuser:
            return Response({
                'error': 'You do not have permission to view this setting.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = SystemSettingSerializer(setting)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='SystemSetting',
            target_id=setting.id,
            description=f"Viewed system setting: {setting.key}"
        )
        
        return Response(serializer.data)
    
    def put(self, request, pk):
        # Ensure the setting exists
        setting = get_object_or_404(SystemSetting, pk=pk)
        
        # Check if user has permission to update this setting
        if not request.user.is_superuser:
            # Create a pending approval
            PendingApproval.objects.create(
                action_type='system_setting',
                requester=request.user,
                status='pending',
                request_data={
                    'setting_id': setting.id,
                    'key': setting.key,
                    'current_value': setting.value,
                    'new_value': request.data.get('value', setting.value),
                    'changes': request.data
                },
                reason=request.data.get('approval_reason', 'No reason provided')
            )
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='other',
                target_model='SystemSetting',
                target_id=setting.id,
                description=f"Requested approval to update system setting: {setting.key}"
            )
            
            return Response({
                'message': 'Changes to system settings require superuser approval.',
                'status': 'pending_approval'
            })
        
        serializer = SystemSettingSerializer(setting, data=request.data, partial=True)
        if serializer.is_valid():
            # Update setting and record who modified it
            updated_setting = serializer.save(last_modified_by=request.user)
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='update',
                target_model='SystemSetting',
                target_id=setting.id,
                description=f"Updated system setting: {setting.key}",
                additional_data={'changes': request.data}
            )
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Superuser updated system setting: {setting.key}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        # Only superusers can delete settings
        if not request.user.is_superuser:
            return Response({
                'error': 'Only superusers can delete system settings.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        setting = get_object_or_404(SystemSetting, pk=pk)
        
        # Log before deletion
        key = setting.key
        setting_id = setting.id
        
        # Delete setting
        setting.delete()
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='delete',
            target_model='SystemSetting',
            target_id=setting_id,
            description=f"Deleted system setting: {key}"
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)

# Pending approvals views
class AdminPendingApprovalListView(APIView):
    """API view for listing pending approvals (admin only)"""
    permission_classes = [IsAdminUser]
    pagination_class = AdminPagination
    
    def get(self, request):
        # Query parameters
        status_filter = request.query_params.get('status', 'pending')
        action_type = request.query_params.get('action_type', '')
        
        # Base query - get all pending approvals that this user can approve
        approvals = PendingApproval.objects.all()
        
        # Regular admins can only see their own requests
        if not request.user.is_superuser:
            approvals = approvals.filter(requester=request.user)
        
        # Apply filters
        if status_filter:
            approvals = approvals.filter(status=status_filter)
        
        if action_type:
            approvals = approvals.filter(action_type=action_type)
        
        # Order by created date
        approvals = approvals.order_by('-created_at')
        
        # Paginate results
        paginator = self.pagination_class()
        paginated_approvals = paginator.paginate_queryset(approvals, request)
        
        serializer = PendingApprovalSerializer(paginated_approvals, many=True)
        
        # Log admin activity if viewing pending ones
        if status_filter == 'pending':
            log_admin_activity(
                request=request,
                action_type='view',
                target_model='PendingApproval',
                target_id=None,
                description=f"Viewed pending approvals"
            )
        
        return paginator.get_paginated_response(serializer.data)

class AdminPendingApprovalDetailView(APIView):
    """API view for retrieving and processing pending approvals (admin only)"""
    permission_classes = [IsAdminUser]
    
    def get(self, request, pk):
        # Get the pending approval
        approval = get_object_or_404(PendingApproval, pk=pk)
        
        # Check if user has permission to view this approval
        if not request.user.is_superuser and approval.requester != request.user:
            return Response({
                'error': 'You do not have permission to view this approval.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = PendingApprovalSerializer(approval)
        
        # Log admin activity
        log_admin_activity(
            request=request,
            action_type='view',
            target_model='PendingApproval',
            target_id=approval.id,
            description=f"Viewed pending approval #{approval.id}"
        )
        
        return Response(serializer.data)
    
    def put(self, request, pk):
        # Get the pending approval
        approval = get_object_or_404(PendingApproval, pk=pk)
        
        # Check if user can process this approval
        if not request.user.is_superuser:
            return Response({
                'error': 'Only superusers can process approval requests.',
                'message': 'Operation not permitted.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Check if approval is still pending
        if approval.status != 'pending':
            return Response({
                'error': 'This approval has already been processed.',
                'message': f'Current status: {approval.get_status_display()}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = PendingApprovalSerializer(approval, data=request.data, partial=True)
        if serializer.is_valid():
            # Set approver and processing time
            approval.approver = request.user
            approval.processed_at = timezone.now()
            
            # Update the approval
            updated_approval = serializer.save()
            
            # Process the request if approved
            if updated_approval.status == 'approved':
                try:
                    self._process_approved_request(updated_approval)
                except Exception as e:
                    # Log the error
                    log_admin_activity(
                        request=request,
                        action_type='other',
                        target_model='PendingApproval',
                        target_id=approval.id,
                        description=f"Error processing approval: {str(e)}"
                    )
                    return Response({
                        'error': 'Error processing the approved request.',
                        'message': str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Log admin activity
            log_admin_activity(
                request=request,
                action_type='approve' if updated_approval.status == 'approved' else 'reject',
                target_model='PendingApproval',
                target_id=approval.id,
                description=f"{updated_approval.get_status_display()} approval request #{approval.id}"
            )
            
            # Notify the requester
            Notification.objects.create(
                user=approval.requester,
                notification_type='info',
                title=f'Approval Request {updated_approval.get_status_display()}',
                message=f"Your {approval.get_action_type_display()} request has been {updated_approval.get_status_display()}.",
                important=True,
                action_text='View Details',
                related_object_id=approval.id,
                related_object_type='PendingApproval'
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _process_approved_request(self, approval):
        """Process the actual changes for an approved request"""
        action = approval.action_type
        data = approval.request_data
        
        if action == 'user_role_change':
            # Update user role
            user_id = data.get('user_id')
            user = get_object_or_404(User, pk=user_id)
            
            # Apply changes
            changes = data.get('changes', {})
            for key, value in changes.items():
                setattr(user, key, value)
            user.save()
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=approval.approver,
                event_type='role_change',
                event_description=f"User role changed to {data.get('new_role')} for {user.email}",
                severity='high',
                additional_data={'changes': changes}
            )
            
        elif action == 'account_closure' or action == 'limit_change':
            # Update account
            account_id = data.get('account_id')
            account = get_object_or_404(BankAccount, pk=account_id)
            
            # Apply changes
            new_values = data.get('new_values', {})
            for key, value in new_values.items():
                setattr(account, key, value)
            account.save()
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=approval.approver,
                event_type='api_access',
                event_description=f"Account {account.get_masked_account_number()} updated via approval process",
                severity='high',
                additional_data={'changes': new_values}
            )
            
            # Notify account owner
            is_closure = action == 'account_closure' and new_values.get('is_active') is False
            
            Notification.objects.create(
                user=account.user,
                notification_type='security' if is_closure else 'info',
                title='Account Closed' if is_closure else 'Account Updated',
                message=(
                    f"Your account has been closed. Please contact support if you have questions." 
                    if is_closure else 
                    f"Your account settings have been updated."
                ),
                important=True,
                action_url='/accounts' if not is_closure else '/support',
                action_text='View Account' if not is_closure else 'Contact Support'
            )
            
        elif action == 'system_setting':
            # Update system setting
            setting_id = data.get('setting_id')
            setting = get_object_or_404(SystemSetting, pk=setting_id)
            
            # Apply changes
            setting.value = data.get('new_value', setting.value)
            setting.last_modified_by = approval.approver
            setting.save()
            
            # Log security event
            SecurityAuditLog.objects.create(
                user=approval.approver,
                event_type='api_access',
                event_description=f"System setting {setting.key} updated via approval process",
                severity='medium',
                additional_data={
                    'old_value': data.get('current_value'),
                    'new_value': data.get('new_value')
                }
            )
            
        elif action == 'large_transfer':
            # Process large transfer
            # This would be implemented based on the specific requirements
            pass