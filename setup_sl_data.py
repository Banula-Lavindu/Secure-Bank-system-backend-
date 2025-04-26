#!/usr/bin/env python
"""
Script to set up Sri Lankan demo data for the banking application
- Creates a user if none exists
- Creates bank accounts with LKR currency
- Adds transactions with Sri Lankan details
"""
import os
import sys
import django
import random
from decimal import Decimal
from datetime import datetime, timedelta

# Set up Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "banking_api.settings")
django.setup()

# Import Django models
from django.contrib.auth import get_user_model
from banking_api.accounts.models import BankAccount
from banking_api.transactions.models import Transaction

# Get user model
User = get_user_model()

def create_user():
    """Create a user if none exists"""
    if User.objects.count() == 0:
        print("Creating test user...")
        user = User.objects.create_user(
            email='test@example.com',
            password='Test@123',
            username='testuser',  # Username is required
            first_name='Test',
            last_name='User',
            phone='+94712345678',  # Field is named 'phone' not 'phone_number'
            date_of_birth='1990-01-01',
            is_active=True,
        )
        print(f"Created user: {user.email}")
        return user
    else:
        user = User.objects.first()
        print(f"Using existing user: {user.email}")
        return user

def create_accounts(user):
    """Create bank accounts with LKR currency"""
    # Delete existing accounts if any
    if BankAccount.objects.filter(user=user).exists():
        print("Deleting existing accounts...")
        BankAccount.objects.filter(user=user).delete()
    
    # Create accounts
    accounts = []
    
    # Checking account
    checking = BankAccount.objects.create(
        user=user,
        account_type='checking',
        account_number='108765432100',
        balance=Decimal('150000.00'),
        currency='LKR',
        is_active=True
    )
    accounts.append(checking)
    print(f"Created checking account: {checking.account_number}")
    
    # Savings account
    savings = BankAccount.objects.create(
        user=user,
        account_type='savings',
        account_number='208765432100',
        balance=Decimal('450000.00'),
        currency='LKR',
        is_active=True,
        interest_rate=Decimal('7.50')  # Typical Sri Lankan savings rate
    )
    accounts.append(savings)
    print(f"Created savings account: {savings.account_number}")
    
    # Credit account (credit card)
    next_due = datetime.now() + timedelta(days=15)
    credit = BankAccount.objects.create(
        user=user,
        account_type='credit',
        account_number='551234567890',
        balance=Decimal('-35000.00'),
        credit_limit=Decimal('500000.00'),
        currency='LKR',
        is_active=True,
        interest_rate=Decimal('24.00'),  # Typical Sri Lankan credit card rate
        due_date=next_due.date()
    )
    accounts.append(credit)
    print(f"Created credit account: {credit.account_number}")
    
    # Loan account
    next_payment = datetime.now() + timedelta(days=10)
    loan = BankAccount.objects.create(
        user=user,
        account_type='loan',
        account_number='308765432100',
        balance=Decimal('-600000.00'),
        currency='LKR',
        is_active=True,
        loan_amount=Decimal('750000.00'),
        interest_rate=Decimal('16.00'),  # Typical Sri Lankan personal loan rate
        next_payment_date=next_payment.date(),
        next_payment_amount=Decimal('25000.00')
    )
    accounts.append(loan)
    print(f"Created loan account: {loan.account_number}")
    
    return accounts

def create_transactions(user, accounts):
    """Add Sri Lankan transactions with proper LKR details"""
    # Delete existing transactions
    if Transaction.objects.filter(user=user).exists():
        print("Deleting existing transactions...")
        Transaction.objects.filter(user=user).delete()
    
    # Sri Lankan merchants and categories
    merchants = [
        # Supermarkets/Retail
        'Cargills Food City', 'Keells Super', 'Arpico Super Center', 'LAUGFS Supermarket',
        'Lanka Sathosa', 'Odel', 'Fashion Bug', 'Cotton Collection', 'House of Fashions',
        
        # Banks
        'Sampath Bank', 'Commercial Bank', 'Bank of Ceylon', 'People\'s Bank', 
        'Nations Trust Bank', 'Hatton National Bank', 'NSB',
        
        # Telecom and Utilities
        'Dialog Axiata', 'SLT Mobitel', 'Airtel Lanka', 'Ceylon Electricity Board',
        'National Water Supply', 'Lanka IOC', 'Litro Gas Lanka',
        
        # Restaurants/Food
        'Burger King Sri Lanka', 'Pizza Hut Lanka', 'Domino\'s Pizza', 'KFC Sri Lanka',
        'Café Barista', 'Dilmah Tea Lounge', 'Elephant House Ice Cream',
        
        # Electronics/Appliances
        'Abans', 'Singer Sri Lanka', 'Softlogic', 'Damro', 'Innovex',
        'Metropolitan', 'Dinapala Group',
        
        # Transportation
        'Sri Lankan Airlines', 'PickMe', 'Uber Lanka', 'Kangaroo Cabs',
        'Sri Lanka Railways', 'Expressway Bus Service',
        
        # Other
        'Hemas Hospital', 'Asiri Hospital', 'Nawaloka Hospital',
        'University of Colombo', 'Royal College', 'Virtusa Lanka', 'WSO2'
    ]
    
    # Transaction descriptions templates - crafted to trigger the proper categories
    credit_descriptions = [
        'Salary from {}',
        'Received from {}',
        'Refund from {}',
        'Repayment from {}',
        'Interest from {}',
        'Dividend from {}',
        'Bonus from {}'
    ]
    
    debit_descriptions = [
        'Payment to {}',
        'Purchase at {}',
        'Monthly bill - {}',
        'Subscription to {}',
        'Withdrawal for {}',
        'Fee for {} service',
        'Loan payment to {}'
    ]
    
    # Category-specific descriptions to influence the transaction_category property
    food_descriptions = ['Food purchase at {}', 'Grocery shopping at {}', 'Restaurant bill at {}']
    entertainment_descriptions = ['Netflix subscription via {}', 'Spotify payment through {}', 'Movie tickets at {}']
    
    # Create transactions
    transactions_count = 50
    print(f"Creating {transactions_count} Sri Lankan transactions...")
    
    for i in range(transactions_count):
        # Select random account
        account = random.choice(accounts)
        
        # Randomize transaction details - more recent dates for more transactions
        if random.random() < 0.7:  # 70% of transactions in last 30 days
            days_ago = random.randint(1, 30)
        else:
            days_ago = random.randint(31, 90)  # Older transactions
            
        trans_date = datetime.now() - timedelta(days=days_ago)
        
        # Randomize credit or debit (incoming/outgoing)
        is_credit = random.random() < 0.4  # 40% chance of credit
        
        # Random amount between 500 and 50000 LKR with more realistic distribution
        if random.random() < 0.6:  # 60% small transactions
            amount = round(random.uniform(500, 7000), 2)
        elif random.random() < 0.9:  # 30% medium transactions
            amount = round(random.uniform(7001, 20000), 2)
        else:  # 10% large transactions
            amount = round(random.uniform(20001, 100000), 2)
        
        # For salary credits, larger amounts
        if is_credit and random.random() < 0.3:
            amount = round(random.uniform(50000, 150000), 2)
            merchant = random.choice(['Virtusa Lanka', 'WSO2', 'Commercial Bank', 'Sampath Bank', 'Dialog Axiata'])
        else:
            merchant = random.choice(merchants)
        
        # Generate reference number with LK prefix for Sri Lanka
        ref_number = f'LK-{random.randint(100000, 999999)}'
        
        # Choose description based on merchant to influence the transaction_category property
        if any(food in merchant for food in ['Food City', 'Keells', 'Pizza', 'KFC', 'Burger']):
            description_template = random.choice(food_descriptions)
        elif any(ent in merchant for ent in ['Dialog', 'SLT', 'Mobitel']):
            description_template = random.choice(entertainment_descriptions)
        elif is_credit:
            description_template = random.choice(credit_descriptions)
        else:
            description_template = random.choice(debit_descriptions)
            
        description = description_template.format(merchant)
        
        # Set transaction type
        if is_credit:
            transaction_type = 'deposit' if 'Salary' in description or 'Bonus' in description else 'transfer'
        else:
            if 'bill' in description.lower():
                transaction_type = 'payment'
            elif 'withdrawal' in description.lower():
                transaction_type = 'withdrawal'
            else:
                transaction_type = 'payment'
        
        # Create the transaction
        transaction = Transaction.objects.create(
            user=user,
            source_account=None if is_credit else account,
            destination_account=account if is_credit else None,
            destination_account_external=None if is_credit else f"DEST-{random.randint(1000, 9999)}",
            transaction_type=transaction_type,
            amount=Decimal(str(amount)),
            currency='LKR',
            status='completed',
            description=description,
            reference_number=ref_number,
            date_created=trans_date,
            date_processed=trans_date
        )
    
    print(f"Created {Transaction.objects.filter(user=user).count()} Sri Lankan transactions with LKR currency")

if __name__ == "__main__":
    print("Setting up Sri Lankan demo data...")
    user = create_user()
    accounts = create_accounts(user)
    create_transactions(user, accounts)
    print("Setup complete!")