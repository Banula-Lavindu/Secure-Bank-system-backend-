from django.db import models
from django.utils.translation import gettext_lazy as _
from banking_api.accounts.models import User, BankAccount

class Transaction(models.Model):
    """Model for storing transaction records"""
    TRANSACTION_TYPES = (
        ('transfer', 'Fund Transfer'),
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('payment', 'Payment'),
        ('fee', 'Fee'),
        ('interest', 'Interest'),
    )
    
    TRANSACTION_STATUS = (
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    )
    
    user = models.ForeignKey(User, on_delete=models.PROTECT, related_name='transactions')
    source_account = models.ForeignKey(BankAccount, on_delete=models.PROTECT, related_name='outgoing_transactions', null=True, blank=True)
    destination_account = models.ForeignKey(BankAccount, on_delete=models.PROTECT, related_name='incoming_transactions', null=True, blank=True)
    destination_account_external = models.CharField(max_length=50, blank=True, null=True, help_text="External account number for transfers outside the system")
    destination_bank_external = models.CharField(max_length=100, blank=True, null=True, help_text="External bank name for transfers outside the system")
    
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='LKR')
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='pending')
    description = models.CharField(max_length=255, blank=True)
    reference_number = models.CharField(max_length=50, unique=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_processed = models.DateTimeField(null=True, blank=True)
    
    # Additional fields for audit trail
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    
    class Meta:
        verbose_name = _('transaction')
        verbose_name_plural = _('transactions')
        ordering = ['-date_created']
    
    def __str__(self):
        return f"{self.reference_number} - {self.get_transaction_type_display()} - {self.amount} {self.currency}"
    
    @property
    def is_completed(self):
        return self.status == 'completed'
    
    @property
    def is_internal_transfer(self):
        """Check if transaction is between accounts in the system"""
        return self.source_account and self.destination_account
    
    @property
    def transaction_category(self):
        """Get a category for the transaction based on description or type"""
        # Implement categorization logic here
        if 'salary' in self.description.lower():
            return 'Income'
        if any(word in self.description.lower() for word in ['food', 'grocery', 'restaurant']):
            return 'Food'
        if any(word in self.description.lower() for word in ['netflix', 'spotify', 'subscription']):
            return 'Entertainment'
        # Default category based on transaction type
        if self.transaction_type == 'deposit':
            return 'Income'
        if self.transaction_type == 'fee':
            return 'Fees'
        return 'Other'

class RecurringTransfer(models.Model):
    """Model for storing scheduled recurring transfers"""
    FREQUENCY_CHOICES = (
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('biweekly', 'Bi-weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('yearly', 'Yearly'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recurring_transfers')
    source_account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='recurring_outgoing')
    destination_account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='recurring_incoming', null=True, blank=True)
    destination_account_external = models.CharField(max_length=50, blank=True, null=True)
    destination_bank_external = models.CharField(max_length=100, blank=True, null=True)
    
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.CharField(max_length=255, blank=True)
    frequency = models.CharField(max_length=10, choices=FREQUENCY_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    next_transfer_date = models.DateField()
    is_active = models.BooleanField(default=True)
    date_created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = _('recurring transfer')
        verbose_name_plural = _('recurring transfers')
    
    def __str__(self):
        return f"{self.user.email} - {self.amount} - {self.frequency}"

class Statement(models.Model):
    """Model for storing statements"""
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='statements')
    statement_date = models.DateField()
    start_date = models.DateField()
    end_date = models.DateField()
    opening_balance = models.DecimalField(max_digits=12, decimal_places=2)
    closing_balance = models.DecimalField(max_digits=12, decimal_places=2)
    statement_file = models.FileField(upload_to='statements/%Y/%m/', null=True, blank=True)
    is_generated = models.BooleanField(default=False)
    date_generated = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = _('statement')
        verbose_name_plural = _('statements')
        ordering = ['-statement_date']
    
    def __str__(self):
        return f"{self.account} - {self.statement_date}"

class Beneficiary(models.Model):
    """Model for storing beneficiary information for fund transfers"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='beneficiaries')
    name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=20)
    bank = models.CharField(max_length=100)
    branch = models.CharField(max_length=100, blank=True)
    nickname = models.CharField(max_length=50, blank=True)
    is_favorite = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = _('beneficiary')
        verbose_name_plural = _('beneficiaries')
        ordering = ['-is_favorite', 'name']
        unique_together = ['user', 'account_number', 'bank']
    
    def __str__(self):
        return f"{self.name} - {self.account_number} ({self.bank})"