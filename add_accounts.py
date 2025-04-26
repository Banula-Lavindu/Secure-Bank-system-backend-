from django.contrib.auth import get_user_model
from banking_api.accounts.models import BankAccount
from decimal import Decimal
from datetime import date, timedelta

# Get the user model and first user
User = get_user_model()
user = User.objects.first()

if user:
    # Delete existing accounts to avoid duplicates
    BankAccount.objects.all().delete()
    
    # Create a Checking Account with LKR currency
    checking = BankAccount.objects.create(
        user=user,
        account_type='checking',
        name='Checking Account',
        account_number='4567',
        balance=Decimal('5842.50'),
        currency='LKR',
        is_active=True
    )
    
    # Create a Savings Account with LKR currency
    savings = BankAccount.objects.create(
        user=user,
        account_type='savings',
        name='Savings Account',
        account_number='7890',
        balance=Decimal('12750.75'),
        currency='LKR',
        is_active=True
    )
    
    # Create a Credit Card with LKR currency
    credit = BankAccount.objects.create(
        user=user,
        account_type='credit',
        name='Credit Card',
        account_number='1234',
        balance=Decimal('1250.00'),
        currency='LKR',
        is_active=True,
        credit_limit=Decimal('5000.00'),
        due_date=date.today() + timedelta(days=15)
    )
    
    # Create a Loan Account with LKR currency
    loan = BankAccount.objects.create(
        user=user,
        account_type='loan',
        name='Personal Loan',
        account_number='LN-12345',
        balance=Decimal('15000.00'),
        currency='LKR',
        is_active=True,
        loan_amount=Decimal('25000.00'),
        interest_rate=Decimal('12.50'),
        next_payment_date=date.today() + timedelta(days=30),
        next_payment_amount=Decimal('750.00')
    )
    
    print('Successfully added 4 bank accounts with Sri Lankan details')
    print(f'Now there are {BankAccount.objects.count()} bank accounts in the database')
else:
    print('No user found in the database. Please register a user first.')