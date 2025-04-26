from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django_otp.models import Device

class User(AbstractUser):
    """Custom user model with additional fields for banking application"""
    email = models.EmailField(_('email address'), unique=True)
    phone = models.CharField(_('phone number'), max_length=15, blank=True)
    date_of_birth = models.DateField(_('date of birth'), null=True, blank=True)
    address = models.TextField(_('address'), blank=True)
    two_factor_enabled = models.BooleanField(_('two-factor auth enabled'), default=False)
    dark_mode = models.BooleanField(_('dark mode enabled'), default=False)
    language = models.CharField(_('preferred language'), max_length=5, default='en')
    notifications_enabled = models.BooleanField(_('notifications enabled'), default=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
    
    def __str__(self):
        return self.email

class BankAccount(models.Model):
    """Bank account model for storing account information"""
    ACCOUNT_TYPES = (
        ('checking', 'Checking Account'),
        ('savings', 'Savings Account'),
        ('credit', 'Credit Card'),
        ('loan', 'Loan Account'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts')
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES)
    account_number = models.CharField(max_length=20, unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default='LKR')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Fields for Credit Cards
    credit_limit = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    
    # Fields for Loans
    loan_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    next_payment_date = models.DateField(null=True, blank=True)
    next_payment_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    
    class Meta:
        verbose_name = _('bank account')
        verbose_name_plural = _('bank accounts')
    
    def __str__(self):
        return f"{self.get_account_type_display()} - {self.account_number}"
    
    def get_masked_account_number(self):
        """Return masked account number for security"""
        if len(self.account_number) <= 4:
            return self.account_number
        return f"**** {self.account_number[-4:]}"
    
    @property
    def is_credit_card(self):
        return self.account_type == 'credit'
    
    @property
    def is_loan(self):
        return self.account_type == 'loan'
    
    def save(self, *args, **kwargs):
        """Override save to update other fields based on account type"""
        if not self.is_credit_card:
            self.credit_limit = None
            self.due_date = None
        
        if not self.is_loan:
            self.loan_amount = None
            self.interest_rate = None
            self.next_payment_date = None
            self.next_payment_amount = None
        
        super().save(*args, **kwargs)

class UserSession(models.Model):
    """Model for tracking user login sessions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    device = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=255, blank=True)
    last_active = models.DateTimeField(auto_now=True)
    login_time = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        verbose_name = _('user session')
        verbose_name_plural = _('user sessions')
    
    def __str__(self):
        return f"{self.user.email} - {self.device} - {self.login_time}"