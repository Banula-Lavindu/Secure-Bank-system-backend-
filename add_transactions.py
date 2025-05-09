from django.contrib.auth import get_user_model
from banking_api.accounts.models import BankAccount
from banking_api.transactions.models import Transaction
from decimal import Decimal
from datetime import datetime, timedelta
import random

# Get user and accounts
User = get_user_model()
user = User.objects.first()
accounts = BankAccount.objects.filter(user=user)

if accounts.exists():
    # Delete existing transactions
    Transaction.objects.all().delete()
    
    # Sri Lankan merchants and categories
    merchants = [
        # Supermarkets/Retail
        'Cargills Food City', 'Keells Super', 'Arpico Super Center', 'LAUGFS Supermarket',
        'Lanka Sathosa', 'Odel', 'Fashion Bug', 'Cotton Collection', 'House of Fashions',
        
        # Banks
        'Sampath Bank', 'Commercial Bank', 'Bank of Ceylon', 'People\'s Bank', 
        'Nations Trust Bank', 'Hatton National Bank', 'NDB Bank',
        
        # Telecom and Utilities
        'Dialog Axiata', 'SLT Mobitel', 'Airtel Lanka', 'Ceylon Electricity Board',
        'National Water Supply', 'Lanka IOC', 'Litro Gas Lanka',
        
        # Restaurants/Food
        'Burger King Sri Lanka', 'Pizza Hut Lanka', 'Domino\'s Pizza', 'KFC Sri Lanka',
        'Cafe Barista', 'Dilmah Tea', 'Elephant House',
        
        # Electronics/Appliances
        'Abans', 'Singer Sri Lanka', 'Softlogic', 'Damro', 'Innovex',
        'Metropolitan', 'Dinapala Electronics',
        
        # Transportation
        'Sri Lankan Airlines', 'Kangaroo Cabs', 'PickMe', 'Uber Lanka',
        'Railway Express', 'EasyBooking.lk',
        
        # Other
        'Hemas Hospital', 'Asiri Hospital', 'Nawaloka Hospital',
        'Royal College Fees', 'University of Colombo'
    ]
    
    # Sri Lankan specific categories
    categories = [
        'Groceries', 'Utilities', 'Entertainment', 'Transport', 
        'Food', 'Shopping', 'Bills', 'Transfer', 'Education',
        'Healthcare', 'Salary', 'Savings', 'Loans', 'Family',
        'Charity', 'Investment', 'Housing'
    ]
    
    # Transaction descriptions templates
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
    
    # Create sample transactions
    transactions = []
    num_transactions = 50  # Create 50 transactions
    
    for i in range(num_transactions):
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
        if is_credit and "Salary" in random.choice(credit_descriptions):
            amount = round(random.uniform(50000, 150000), 2)
        
        # Generate reference number with LK prefix for Sri Lanka
        ref_number = f'LK-{random.randint(100000, 999999)}'
        
        # Select random merchant and category
        merchant = random.choice(merchants)
        
        # Assign relevant categories based on merchant type
        if any(bank in merchant for bank in ['Bank', 'Nations Trust', 'NDB', 'Sampath', 'Commercial', 'People\'s']):
            category = random.choice(['Transfer', 'Savings', 'Loans'])
        elif any(food in merchant for food in ['Food City', 'Keells', 'Arpico', 'LAUGFS', 'Sathosa']):
            category = 'Groceries'
        elif any(telecom in merchant for telecom in ['Dialog', 'SLT', 'Mobitel', 'Airtel']):
            category = 'Utilities'
        elif any(hospital in merchant for hospital in ['Hospital', 'Hemas', 'Asiri', 'Nawaloka']):
            category = 'Healthcare'
        elif any(edu in merchant for edu in ['College', 'University', 'School']):
            category = 'Education'
        elif any(transport in merchant for transport in ['Airlines', 'Cabs', 'PickMe', 'Uber', 'Railway']):
            category = 'Transport'
        else:
            category = random.choice(categories)
        
        # Create description based on transaction type
        if is_credit:
            description_template = random.choice(credit_descriptions)
            description = description_template.format(merchant)
            transaction_type = 'deposit' if 'Salary' in description else 'transfer'
        else:
            description_template = random.choice(debit_descriptions)
            description = description_template.format(merchant)
            
            if 'bill' in description.lower():
                transaction_type = 'payment'
            elif 'withdrawal' in description.lower():
                transaction_type = 'withdrawal'
            else:
                transaction_type = 'payment'
        
        # Create the transaction
        Transaction.objects.create(
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
            date_processed=trans_date,
            category=category
        )
    
    print(f'Created {Transaction.objects.count()} Sri Lankan transactions with LKR currency')
else:
    print('No bank accounts found. Please create accounts first.')
    print('Please run add_accounts.py first to create test accounts.')

