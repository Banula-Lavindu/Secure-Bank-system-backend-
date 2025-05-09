#!/usr/bin/env python

"""
Script to add Sri Lankan bank accounts to the database for testing purposes
"""
import os
import django
import sys
from decimal import Decimal
from datetime import date, timedelta

# Set up Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'banking_api.settings')
django.setup()

# Import models after Django setup
from django.contrib.auth import get_user_model
from banking_api.accounts.models import BankAccount

User = get_user_model()

def create_sri_lankan_accounts():
    # Get the first user (or create one if none exists)
    user = User.objects.first()
    
    if not user:
        print("No users found in the database. Please create a user first.")
        return
    
    # Delete existing accounts to avoid duplicates
    BankAccount.objects.filter(user=user).delete()
    
    # Create a Savings Account in LKR
    savings = BankAccount.objects.create(
        user=user,
        account_type='savings',
        account_number='LKR78524906321',
        balance=Decimal('250000.00'),
        currency='LKR',
        is_active=True
    )
    
    # Create a Checking/Current Account in LKR
    checking = BankAccount.objects.create(
        user=user,
        account_type='checking',
        account_number='LKR12345678901',
        balance=Decimal('85000.00'),
        currency='LKR',
        is_active=True
    )
    
    # Create a Credit Card Account in LKR
    credit = BankAccount.objects.create(
        user=user,
        account_type='credit',
        account_number='LKR42657891234',
        balance=Decimal('15000.00'),
        currency='LKR',
        is_active=True,
        credit_limit=Decimal('100000.00'),
        due_date=date.today() + timedelta(days=15)
    )
    
    # Create a Loan Account in LKR
    loan = BankAccount.objects.create(
        user=user,
        account_type='loan',
        account_number='LKR98765432101',
        balance=Decimal('500000.00'),
        currency='LKR',
        is_active=True,
        loan_amount=Decimal('1000000.00'),
        interest_rate=Decimal('12.50'),
        next_payment_date=date.today() + timedelta(days=30),
        next_payment_amount=Decimal('25000.00')
    )
    
    print(f"Created {BankAccount.objects.count()} bank accounts:")
    for account in BankAccount.objects.all():
        print(f"- {account.get_account_type_display()}: {account.currency} {account.balance}")

if __name__ == "__main__":
    create_sri_lankan_accounts()
