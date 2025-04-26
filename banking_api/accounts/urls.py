from django.urls import path
from banking_api.accounts.views import (
    BankAccountListView, BankAccountDetailView, 
    UserSessionListView, UserSessionTerminateView, 
    UserPreferencesView
)

urlpatterns = [
    # Bank account endpoints
    path('bank-accounts/', BankAccountListView.as_view(), name='bank-account-list'),
    path('bank-accounts/<int:pk>/', BankAccountDetailView.as_view(), name='bank-account-detail'),
    
    # User session endpoints
    path('sessions/', UserSessionListView.as_view(), name='user-session-list'),
    path('sessions/<int:pk>/terminate/', UserSessionTerminateView.as_view(), name='user-session-terminate'),
    
    # User preferences endpoints
    path('preferences/', UserPreferencesView.as_view(), name='user-preferences'),
]