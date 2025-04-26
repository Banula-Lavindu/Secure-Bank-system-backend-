from rest_framework import serializers
from django.db import transaction
from django.utils import timezone
import uuid

from banking_api.transactions.models import Transaction, RecurringTransfer, Statement, Beneficiary
from banking_api.accounts.models import BankAccount

class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for transaction data"""
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    category = serializers.CharField(source='transaction_category', read_only=True)
    source_account_number = serializers.CharField(source='source_account.get_masked_account_number', read_only=True)
    destination_account_number = serializers.CharField(source='destination_account.get_masked_account_number', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'user', 'source_account', 'destination_account', 
            'source_account_number', 'destination_account_number',
            'destination_account_external', 'destination_bank_external',
            'transaction_type', 'transaction_type_display', 'amount', 
            'currency', 'status', 'status_display', 'description', 
            'reference_number', 'date_created', 'date_processed',
            'category'
        ]
        read_only_fields = [
            'id', 'user', 'reference_number', 'status', 
            'date_created', 'date_processed'
        ]

class TransferFundsSerializer(serializers.Serializer):
    """Serializer for fund transfer operations"""
    source_account_id = serializers.IntegerField(required=True)
    destination_account_id = serializers.IntegerField(required=False)
    destination_account_external = serializers.CharField(required=False, max_length=50)
    destination_bank_external = serializers.CharField(required=False, max_length=100)
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, required=True)
    description = serializers.CharField(required=True, max_length=255)
    
    def validate(self, attrs):
        # Check if source account exists and belongs to user
        source_account_id = attrs.get('source_account_id')
        user = self.context['request'].user
        
        try:
            source_account = BankAccount.objects.get(pk=source_account_id, user=user)
            attrs['source_account'] = source_account
        except BankAccount.DoesNotExist:
            raise serializers.ValidationError({"source_account_id": "Invalid source account."})
        
        # Check if source account has sufficient balance
        amount = attrs.get('amount')
        if amount <= 0:
            raise serializers.ValidationError({"amount": "Amount must be greater than zero."})
        
        if source_account.balance < amount:
            raise serializers.ValidationError({"amount": "Insufficient balance in source account."})
        
        # Check destination account
        destination_account_id = attrs.get('destination_account_id')
        destination_account_external = attrs.get('destination_account_external')
        
        if not destination_account_id and not destination_account_external:
            raise serializers.ValidationError(
                {"destination": "Either destination account ID or external account number is required."}
            )
        
        if destination_account_id:
            try:
                destination_account = BankAccount.objects.get(pk=destination_account_id)
                attrs['destination_account'] = destination_account
                
                # Validate that source and destination are different accounts
                if source_account.id == destination_account.id:
                    raise serializers.ValidationError(
                        {"destination_account_id": "Source and destination accounts cannot be the same."}
                    )
                    
                # If external account info was also provided, remove it
                attrs.pop('destination_account_external', None)
                attrs.pop('destination_bank_external', None)
                
            except BankAccount.DoesNotExist:
                raise serializers.ValidationError({"destination_account_id": "Invalid destination account."})
        
        elif destination_account_external:
            if 'destination_bank_external' not in attrs or not attrs['destination_bank_external']:
                raise serializers.ValidationError(
                    {"destination_bank_external": "Bank name is required for external transfers."}
                )
        
        return attrs
    
    def create(self, validated_data):
        user = self.context['request'].user
        source_account = validated_data['source_account']
        destination_account = validated_data.get('destination_account', None)
        amount = validated_data['amount']
        description = validated_data['description']
        
        # Generate reference number
        reference_number = f"TRN{uuid.uuid4().hex[:10].upper()}"
        
        # Create transaction object
        transaction_data = {
            'user': user,
            'source_account': source_account,
            'transaction_type': 'transfer',
            'amount': amount,
            'currency': source_account.currency,
            'status': 'pending',
            'description': description,
            'reference_number': reference_number,
            'ip_address': self.context.get('ip_address'),
            'device_info': self.context.get('user_agent', '')
        }
        
        if destination_account:
            transaction_data['destination_account'] = destination_account
        else:
            transaction_data['destination_account_external'] = validated_data.get('destination_account_external')
            transaction_data['destination_bank_external'] = validated_data.get('destination_bank_external')
        
        with transaction.atomic():
            # Create transaction record
            transaction_obj = Transaction.objects.create(**transaction_data)
            
            # For internal transfers, process immediately
            if destination_account:
                # Deduct from source account
                source_account.balance -= amount
                source_account.save()
                
                # Add to destination account
                destination_account.balance += amount
                destination_account.save()
                
                # Update transaction status
                transaction_obj.status = 'completed'
                transaction_obj.date_processed = timezone.now()
                transaction_obj.save(update_fields=['status', 'date_processed'])
            
            # For external transfers, leave as pending (would be processed by a background job)
            
        return transaction_obj

class RecurringTransferSerializer(serializers.ModelSerializer):
    """Serializer for recurring transfer data"""
    source_account_number = serializers.CharField(source='source_account.get_masked_account_number', read_only=True)
    destination_account_number = serializers.CharField(source='destination_account.get_masked_account_number', read_only=True)
    frequency_display = serializers.CharField(source='get_frequency_display', read_only=True)
    
    class Meta:
        model = RecurringTransfer
        fields = [
            'id', 'user', 'source_account', 'destination_account',
            'source_account_number', 'destination_account_number',
            'destination_account_external', 'destination_bank_external',
            'amount', 'description', 'frequency', 'frequency_display',
            'start_date', 'end_date', 'next_transfer_date',
            'is_active', 'date_created', 'last_updated'
        ]
        read_only_fields = ['id', 'user', 'date_created', 'last_updated']

class StatementSerializer(serializers.ModelSerializer):
    """Serializer for statement data"""
    account_number = serializers.CharField(source='account.get_masked_account_number', read_only=True)
    
    class Meta:
        model = Statement
        fields = [
            'id', 'account', 'account_number', 'statement_date',
            'start_date', 'end_date', 'opening_balance',
            'closing_balance', 'statement_file', 'is_generated',
            'date_generated'
        ]
        read_only_fields = fields

class BeneficiarySerializer(serializers.ModelSerializer):
    """Serializer for beneficiary data"""
    
    class Meta:
        model = Beneficiary
        fields = [
            'id', 'user', 'name', 'account_number', 'bank', 
            'branch', 'nickname', 'is_favorite', 'is_active',
            'date_created', 'date_updated'
        ]
        read_only_fields = ['id', 'user', 'date_created', 'date_updated']
    
    def create(self, validated_data):
        # Set the user from the request context
        user = self.context['request'].user
        validated_data['user'] = user
        
        try:
            beneficiary = Beneficiary.objects.create(**validated_data)
            return beneficiary
        except Exception as e:
            raise serializers.ValidationError(f"Failed to create beneficiary: {str(e)}")
    
    def validate(self, attrs):
        user = self.context['request'].user
        account_number = attrs.get('account_number')
        bank = attrs.get('bank')
        
        # Check if beneficiary with same account number and bank already exists for this user
        if self.instance is None:  # Only for creation, not updates
            if Beneficiary.objects.filter(user=user, account_number=account_number, bank=bank).exists():
                raise serializers.ValidationError({
                    "account_number": "You already have a beneficiary with this account number and bank."
                })
        
        return attrs