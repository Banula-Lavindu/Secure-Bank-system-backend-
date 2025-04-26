from rest_framework import serializers
from banking_api.accounts.models import BankAccount, User, UserSession

class BankAccountSerializer(serializers.ModelSerializer):
    """Serializer for bank account data"""
    account_type_display = serializers.CharField(source='get_account_type_display', read_only=True)
    masked_account_number = serializers.CharField(source='get_masked_account_number', read_only=True)
    
    class Meta:
        model = BankAccount
        fields = [
            'id', 'user', 'account_type', 'account_type_display', 'account_number', 
            'masked_account_number', 'balance', 'currency', 'is_active', 
            'created_at', 'updated_at', 'credit_limit', 'due_date',
            'loan_amount', 'interest_rate', 'next_payment_date', 'next_payment_amount'
        ]
        read_only_fields = [
            'id', 'user', 'balance', 'is_active', 'created_at', 
            'updated_at', 'account_number'
        ]

class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user session data"""
    class Meta:
        model = UserSession
        fields = [
            'id', 'device', 'ip_address', 'location', 
            'last_active', 'login_time', 'is_active'
        ]
        read_only_fields = fields

class UserPreferencesSerializer(serializers.ModelSerializer):
    """Serializer for user preferences"""
    class Meta:
        model = User
        fields = ['dark_mode', 'language', 'notifications_enabled']
        
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance