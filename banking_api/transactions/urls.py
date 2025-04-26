from django.urls import path
from banking_api.transactions.views import (
    TransactionListView, TransactionDetailView, TransferFundsView,
    RecurringTransferListView, RecurringTransferDetailView,
    StatementListView, StatementDetailView, TransactionSummaryView,
    BeneficiaryView, BeneficiaryDetailView
)

urlpatterns = [
    # Transaction endpoints
    path('list/', TransactionListView.as_view(), name='transaction-list'),
    path('<int:pk>/', TransactionDetailView.as_view(), name='transaction-detail'),
    path('transfer/', TransferFundsView.as_view(), name='transfer-funds'),
    path('summary/', TransactionSummaryView.as_view(), name='transaction-summary'),
    
    # Recurring transfer endpoints
    path('recurring/', RecurringTransferListView.as_view(), name='recurring-transfer-list'),
    path('recurring/<int:pk>/', RecurringTransferDetailView.as_view(), name='recurring-transfer-detail'),
    
    # Statement endpoints
    path('statements/', StatementListView.as_view(), name='statement-list'),
    path('statements/<int:pk>/', StatementDetailView.as_view(), name='statement-detail'),
    
    # Beneficiary endpoints
    path('beneficiaries/', BeneficiaryView.as_view(), name='beneficiary-list'),
    path('beneficiaries/<int:pk>/', BeneficiaryDetailView.as_view(), name='beneficiary-detail'),
]