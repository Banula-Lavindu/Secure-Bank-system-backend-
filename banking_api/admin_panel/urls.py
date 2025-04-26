from django.urls import path
from banking_api.admin_panel.views import (
    AdminUserListView, AdminUserDetailView,
    AdminBankAccountListView, AdminBankAccountDetailView,
    AdminSystemSettingListView, AdminSystemSettingDetailView,
    AdminPendingApprovalListView, AdminPendingApprovalDetailView
)

urlpatterns = [
    # User management endpoints
    path('users/', AdminUserListView.as_view(), name='admin-user-list'),
    path('users/<int:pk>/', AdminUserDetailView.as_view(), name='admin-user-detail'),
    
    # Bank account management endpoints
    path('accounts/', AdminBankAccountListView.as_view(), name='admin-account-list'),
    path('accounts/<int:pk>/', AdminBankAccountDetailView.as_view(), name='admin-account-detail'),
    
    # System settings endpoints
    path('settings/', AdminSystemSettingListView.as_view(), name='admin-setting-list'),
    path('settings/<int:pk>/', AdminSystemSettingDetailView.as_view(), name='admin-setting-detail'),
    
    # Pending approval endpoints
    path('approvals/', AdminPendingApprovalListView.as_view(), name='admin-approval-list'),
    path('approvals/<int:pk>/', AdminPendingApprovalDetailView.as_view(), name='admin-approval-detail'),
]