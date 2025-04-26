from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404
from django.db.models import Q, Sum
from django.utils import timezone

from banking_api.transactions.models import Transaction, RecurringTransfer, Statement, Beneficiary
from banking_api.accounts.models import BankAccount
from banking_api.transactions.serializers import (
    TransactionSerializer, TransferFundsSerializer,
    RecurringTransferSerializer, StatementSerializer, BeneficiarySerializer
)
from banking_api.security.models import SecurityAuditLog
from banking_api.custom_auth.views import get_client_ip
from banking_api.notifications.models import Notification

class TransactionPagination(PageNumberPagination):
    """Custom pagination for transactions"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class TransactionListView(APIView):
    """API view for listing user's transactions"""
    permission_classes = [IsAuthenticated]
    pagination_class = TransactionPagination
    
    def get(self, request):
        # Query parameters
        account_id = request.query_params.get('account_id')
        transaction_type = request.query_params.get('type')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        min_amount = request.query_params.get('min_amount')
        max_amount = request.query_params.get('max_amount')
        
        # Base query - get transactions for the current user
        transactions = Transaction.objects.filter(user=request.user)
        
        # Apply filters
        if account_id:
            transactions = transactions.filter(
                Q(source_account_id=account_id) | Q(destination_account_id=account_id)
            )
        
        if transaction_type:
            transactions = transactions.filter(transaction_type=transaction_type)
        
        if start_date:
            transactions = transactions.filter(date_created__gte=start_date)
        
        if end_date:
            transactions = transactions.filter(date_created__lte=end_date)
        
        if min_amount:
            transactions = transactions.filter(amount__gte=min_amount)
        
        if max_amount:
            transactions = transactions.filter(amount__lte=max_amount)
        
        # Order by date (most recent first)
        transactions = transactions.order_by('-date_created')
        
        # Paginate results
        paginator = self.pagination_class()
        paginated_transactions = paginator.paginate_queryset(transactions, request)
        
        serializer = TransactionSerializer(paginated_transactions, many=True)
        
        return paginator.get_paginated_response(serializer.data)

class TransactionDetailView(APIView):
    """API view for transaction details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        # Ensure transaction belongs to the requesting user
        transaction = get_object_or_404(Transaction, pk=pk, user=request.user)
        serializer = TransactionSerializer(transaction)
        
        # Log access to transaction details
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Accessed transaction details for {transaction.reference_number}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='low'
        )
        
        return Response(serializer.data)

class TransferFundsView(APIView):
    """API view for transferring funds"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = TransferFundsSerializer(
            data=request.data,
            context={
                'request': request,
                'ip_address': get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')
            }
        )
        
        if serializer.is_valid():
            transaction = serializer.save()
            
            # Log transfer
            severity = 'medium' if transaction.amount > 1000 else 'low'
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Fund transfer: {transaction.amount} {transaction.currency}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity=severity
            )
            
            # Create notification
            Notification.objects.create(
                user=request.user,
                notification_type='transaction',
                title='Fund Transfer Completed',
                message=f"Your transfer of {transaction.amount} {transaction.currency} has been processed. Reference: {transaction.reference_number}",
                important=False,
                action_url='/transactions',
                action_text='View Details',
                related_object_id=transaction.id,
                related_object_type='Transaction'
            )
            
            # Return transaction data
            response_serializer = TransactionSerializer(transaction)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RecurringTransferListView(APIView):
    """API view for listing recurring transfers"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        recurring_transfers = RecurringTransfer.objects.filter(user=request.user)
        serializer = RecurringTransferSerializer(recurring_transfers, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        # Add user to data
        data = request.data.copy()
        
        serializer = RecurringTransferSerializer(data=data)
        if serializer.is_valid():
            # Set user before saving
            recurring_transfer = serializer.save(user=request.user)
            
            # Log creation of recurring transfer
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Created recurring transfer: {recurring_transfer.amount} {recurring_transfer.source_account.currency}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RecurringTransferDetailView(APIView):
    """API view for recurring transfer details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        # Ensure recurring transfer belongs to the requesting user
        recurring_transfer = get_object_or_404(RecurringTransfer, pk=pk, user=request.user)
        serializer = RecurringTransferSerializer(recurring_transfer)
        return Response(serializer.data)
    
    def put(self, request, pk):
        # Ensure recurring transfer belongs to the requesting user
        recurring_transfer = get_object_or_404(RecurringTransfer, pk=pk, user=request.user)
        
        serializer = RecurringTransferSerializer(recurring_transfer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            # Log update
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Updated recurring transfer #{pk}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        # Ensure recurring transfer belongs to the requesting user
        recurring_transfer = get_object_or_404(RecurringTransfer, pk=pk, user=request.user)
        
        # Soft delete (deactivate)
        recurring_transfer.is_active = False
        recurring_transfer.save()
        
        # Log deletion
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Cancelled recurring transfer #{pk}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='medium'
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)

class StatementListView(APIView):
    """API view for listing account statements"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Query parameters
        account_id = request.query_params.get('account_id')
        
        # Base query - get statements for the current user's accounts
        if account_id:
            # Check if account belongs to user
            account = get_object_or_404(BankAccount, pk=account_id, user=request.user)
            statements = Statement.objects.filter(account=account)
        else:
            user_accounts = BankAccount.objects.filter(user=request.user).values_list('id', flat=True)
            statements = Statement.objects.filter(account_id__in=user_accounts)
        
        # Order by date (most recent first)
        statements = statements.order_by('-statement_date')
        
        serializer = StatementSerializer(statements, many=True)
        return Response(serializer.data)

class StatementDetailView(APIView):
    """API view for statement details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        # Ensure statement belongs to one of the user's accounts
        user_accounts = BankAccount.objects.filter(user=request.user).values_list('id', flat=True)
        statement = get_object_or_404(Statement, pk=pk, account_id__in=user_accounts)
        
        serializer = StatementSerializer(statement)
        
        # Log access to statement
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='sensitive_data',
            event_description=f"Accessed statement for {statement.account.get_masked_account_number()}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='low'
        )
        
        return Response(serializer.data)

class TransactionSummaryView(APIView):
    """API view for transaction summary statistics"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Default to current month if not specified
        start_date = request.query_params.get('start_date', timezone.now().replace(day=1).date())
        end_date = request.query_params.get('end_date', timezone.now().date())
        
        # Get user's accounts
        user_accounts = BankAccount.objects.filter(user=request.user)
        account_ids = user_accounts.values_list('id', flat=True)
        
        # Total outgoing
        outgoing = Transaction.objects.filter(
            source_account__in=account_ids,
            date_created__range=(start_date, end_date),
            status='completed'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Total incoming
        incoming = Transaction.objects.filter(
            destination_account__in=account_ids,
            date_created__range=(start_date, end_date),
            status='completed'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        # Get spending by category
        transactions = Transaction.objects.filter(
            source_account__in=account_ids,
            date_created__range=(start_date, end_date),
            status='completed'
        )
        
        # Group transactions by category
        categories = {}
        for txn in transactions:
            category = txn.transaction_category
            if category not in categories:
                categories[category] = 0
            categories[category] += float(txn.amount)
        
        # Prepare category data for response
        category_data = [
            {'category': category, 'amount': amount}
            for category, amount in categories.items()
        ]
        
        return Response({
            'summary': {
                'outgoing': outgoing,
                'incoming': incoming,
                'net': incoming - outgoing,
                'period_start': start_date,
                'period_end': end_date
            },
            'categories': category_data
        })

class BeneficiaryView(APIView):
    """API view for managing beneficiaries"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """List all beneficiaries for the current user"""
        beneficiaries = Beneficiary.objects.filter(user=request.user, is_active=True)
        serializer = BeneficiarySerializer(beneficiaries, many=True)
        
        # Log access
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Accessed beneficiaries list",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='low'
        )
        
        return Response(serializer.data)
    
    def post(self, request):
        """Add a new beneficiary"""
        serializer = BeneficiarySerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            beneficiary = serializer.save()
            
            # Log creation
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Added beneficiary: {beneficiary.name} ({beneficiary.bank})",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            # Create notification
            Notification.objects.create(
                user=request.user,
                notification_type='beneficiary',
                title='Beneficiary Added',
                message=f"New beneficiary {beneficiary.name} has been successfully added to your account.",
                important=False,
                action_url='/beneficiaries',
                action_text='View Beneficiaries'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BeneficiaryDetailView(APIView):
    """API view for beneficiary details"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        """Get a specific beneficiary"""
        beneficiary = get_object_or_404(Beneficiary, pk=pk, user=request.user, is_active=True)
        serializer = BeneficiarySerializer(beneficiary)
        return Response(serializer.data)
    
    def put(self, request, pk):
        """Update a beneficiary"""
        beneficiary = get_object_or_404(Beneficiary, pk=pk, user=request.user, is_active=True)
        serializer = BeneficiarySerializer(beneficiary, data=request.data, context={'request': request}, partial=True)
        
        if serializer.is_valid():
            updated_beneficiary = serializer.save()
            
            # Log update
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='api_access',
                event_description=f"Updated beneficiary: {updated_beneficiary.name}",
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                severity='medium'
            )
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete a beneficiary (soft delete by marking as inactive)"""
        beneficiary = get_object_or_404(Beneficiary, pk=pk, user=request.user, is_active=True)
        
        # Soft delete
        beneficiary.is_active = False
        beneficiary.save()
        
        # Log deletion
        SecurityAuditLog.objects.create(
            user=request.user,
            event_type='api_access',
            event_description=f"Deleted beneficiary: {beneficiary.name}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            severity='medium'
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)