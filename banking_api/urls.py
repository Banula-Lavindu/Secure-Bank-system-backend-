"""Banking API URL Configuration"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# API documentation schema
schema_view = get_schema_view(
   openapi.Info(
      title="Modern Banking API",
      default_version='v1',
      description="API for Modern Banking System",
      terms_of_service="https://www.example.com/terms/",
      contact=openapi.Contact(email="contact@example.com"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Admin panel
    path('admin/', admin.site.urls),
    
    # API versioning
    path('api/v1/', include([
        # API endpoints
        path('auth/', include('banking_api.custom_auth.urls')),
        path('accounts/', include('banking_api.accounts.urls')),
        path('transactions/', include('banking_api.transactions.urls')),
        path('notifications/', include('banking_api.notifications.urls')),
        path('admin-panel/', include('banking_api.admin_panel.urls')),
    ])),
    
    # API documentation
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)