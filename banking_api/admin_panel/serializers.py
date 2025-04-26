from rest_framework import serializers
from banking_api.admin_panel.models import AdminActivity, SystemSetting, PendingApproval
from banking_api.accounts.models import User, BankAccount

class AdminUserSerializer(serializers.ModelSerializer):
    """Serializer for user management in admin panel"""
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'phone', 'date_of_birth', 'address', 'is_active',
            'is_staff', 'is_superuser', 'date_joined', 'last_login',
            'two_factor_enabled'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']

class AdminBankAccountSerializer(serializers.ModelSerializer):
    """Serializer for bank account management in admin panel"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)
    
    class Meta:
        model = BankAccount
        fields = [
            'id', 'user', 'user_email', 'user_name', 
            'account_type', 'account_type_display', 'account_number', 
            'balance', 'currency', 'is_active', 'created_at', 
            'updated_at', 'credit_limit', 'due_date',
            'loan_amount', 'interest_rate', 'next_payment_date', 
            'next_payment_amount'
        ]
    
    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

class AdminActivitySerializer(serializers.ModelSerializer):
    """Serializer for admin activity logs"""
    admin_email = serializers.CharField(source='admin_user.email', read_only=True)
    admin_name = serializers.SerializerMethodField()
    action_type_display = serializers.CharField(source='get_action_type_display', read_only=True)
    
    class Meta:
        model = AdminActivity
        fields = [
            'id', 'admin_user', 'admin_email', 'admin_name',
            'action_type', 'action_type_display', 'target_model',
            'target_id', 'description', 'ip_address',
            'timestamp', 'additional_data'
        ]
        read_only_fields = fields
    
    def get_admin_name(self, obj):
        return f"{obj.admin_user.first_name} {obj.admin_user.last_name}".strip() or obj.admin_user.username

class SystemSettingSerializer(serializers.ModelSerializer):
    """Serializer for system settings"""
    modified_by_email = serializers.CharField(source='last_modified_by.email', read_only=True)
    
    class Meta:
        model = SystemSetting
        fields = [
            'id', 'key', 'value', 'data_type', 'description',
            'is_public', 'created_at', 'updated_at',
            'last_modified_by', 'modified_by_email'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_modified_by', 'modified_by_email']

class PendingApprovalSerializer(serializers.ModelSerializer):
    """Serializer for operations requiring approval"""
    requester_email = serializers.CharField(source='requester.email', read_only=True)
    approver_email = serializers.CharField(source='approver.email', read_only=True)
    action_type_display = serializers.CharField(source='get_action_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = PendingApproval
        fields = [
            'id', 'action_type', 'action_type_display', 
            'requester', 'requester_email', 'approver', 
            'approver_email', 'status', 'status_display',
            'request_data', 'reason', 'response_note', 
            'created_at', 'processed_at'
        ]
        read_only_fields = ['id', 'action_type', 'requester', 'created_at']
    
    def validate(self, attrs):
        # Validate that only pending approvals can be processed
        if self.instance and self.instance.status != 'pending' and 'status' in attrs:
            raise serializers.ValidationError({
                'status': 'Only pending approvals can be processed.'
            })
        
        # Validate that a response note is provided when rejecting
        if attrs.get('status') == 'rejected' and not attrs.get('response_note'):
            raise serializers.ValidationError({
                'response_note': 'A response note is required when rejecting a request.'
            })
        
        return attrs