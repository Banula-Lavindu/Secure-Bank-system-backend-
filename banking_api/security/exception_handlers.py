import logging
import traceback
from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import exception_handler as drf_exception_handler
from django.core.exceptions import ValidationError, PermissionDenied
from django.db import IntegrityError, DatabaseError
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied as DRFPermissionDenied,
    ValidationError as DRFValidationError,
    APIException,
)

# Configure logger
logger = logging.getLogger('security.exceptions')

def custom_exception_handler(exc, context):
    """
    Custom exception handler for the banking API.
    
    This handler:
    1. Logs all exceptions with appropriate context
    2. Formats exception responses in a consistent way
    3. Hides technical details in production
    4. Provides unique error codes for tracking
    """
    # Call DRF's default exception handler first
    response = drf_exception_handler(exc, context)
    
    # Generate a unique error reference code (could be a UUID in production)
    # Here using timestamp for simplicity
    import time
    error_id = f"ERR-{int(time.time())}"
    
    # Extract request information for logging
    request = context.get('request')
    view = context.get('view')
    
    log_data = {
        'error_id': error_id,
        'view': view.__class__.__name__ if view else 'Unknown',
        'user_id': request.user.id if request and request.user and request.user.is_authenticated else 'Anonymous',
        'path': request.path if request else 'Unknown',
        'method': request.method if request else 'Unknown',
        'exception_type': exc.__class__.__name__,
    }
    
    # Get the stack trace for logging (but don't expose to users)
    stack_trace = traceback.format_exc()
    
    # Handle REST framework exceptions
    if response is not None:
        # For DRF exceptions, we already have a response but we'll enhance it
        error_detail = response.data
        
        # Format the response consistently
        response.data = {
            'status': 'error',
            'error_id': error_id,
            'type': exc.__class__.__name__,
            'detail': error_detail
        }
        
        # Log the error
        logger.error(f"API Error [{error_id}]: {exc}", extra=log_data)
        logger.debug(f"Stack trace for error [{error_id}]:\n{stack_trace}")
        
        return response
    
    # Handle Django and Python exceptions that DRF doesn't handle
    
    # Authentication errors
    if isinstance(exc, (AuthenticationFailed, NotAuthenticated)):
        logger.warning(f"Authentication error [{error_id}]: {exc}", extra=log_data)
        return JsonResponse({
            'status': 'error',
            'error_id': error_id,
            'type': 'AuthenticationError',
            'detail': str(exc) or 'Authentication failed.'
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    # Permission errors
    elif isinstance(exc, (PermissionDenied, DRFPermissionDenied)):
        logger.warning(f"Permission error [{error_id}]: {exc}", extra=log_data)
        return JsonResponse({
            'status': 'error',
            'error_id': error_id,
            'type': 'PermissionDenied',
            'detail': str(exc) or 'You do not have permission to perform this action.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Validation errors
    elif isinstance(exc, (ValidationError, DRFValidationError)):
        logger.info(f"Validation error [{error_id}]: {exc}", extra=log_data)
        return JsonResponse({
            'status': 'error',
            'error_id': error_id, 
            'type': 'ValidationError',
            'detail': exc.message_dict if hasattr(exc, 'message_dict') else str(exc)
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Database integrity errors
    elif isinstance(exc, IntegrityError):
        logger.error(f"Database integrity error [{error_id}]: {exc}", extra=log_data)
        logger.debug(f"Stack trace for error [{error_id}]:\n{stack_trace}")
        return JsonResponse({
            'status': 'error',
            'error_id': error_id,
            'type': 'DatabaseIntegrityError',
            'detail': 'A database constraint was violated.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # General database errors
    elif isinstance(exc, DatabaseError):
        logger.error(f"Database error [{error_id}]: {exc}", extra=log_data)
        logger.debug(f"Stack trace for error [{error_id}]:\n{stack_trace}")
        return JsonResponse({
            'status': 'error', 
            'error_id': error_id,
            'type': 'DatabaseError',
            'detail': 'A database error occurred.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # All other exceptions - treated as server errors
    else:
        logger.critical(f"Unhandled exception [{error_id}]: {exc}", extra=log_data)
        logger.debug(f"Stack trace for error [{error_id}]:\n{stack_trace}")
        return JsonResponse({
            'status': 'error',
            'error_id': error_id,
            'type': 'ServerError',
            'detail': 'An unexpected error occurred. Our team has been notified.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def handle_404(request, exception=None):
    """Custom 404 handler"""
    return JsonResponse({
        'status': 'error',
        'type': 'NotFound',
        'detail': 'The requested resource was not found.'
    }, status=status.HTTP_404_NOT_FOUND)


def handle_500(request):
    """Custom 500 handler"""
    # Generate a unique error reference code
    import time
    error_id = f"ERR-{int(time.time())}"
    
    # Log the server error
    logger.critical(f"Server error [{error_id}]", extra={
        'error_id': error_id,
        'path': request.path,
        'method': request.method,
        'user_id': request.user.id if request.user.is_authenticated else 'Anonymous',
    })
    
    return JsonResponse({
        'status': 'error',
        'error_id': error_id,
        'type': 'ServerError',
        'detail': 'An unexpected error occurred. Our team has been notified.'
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def handle_400(request, exception=None):
    """Custom 400 handler"""
    return JsonResponse({
        'status': 'error',
        'type': 'BadRequest',
        'detail': 'The server could not process this request.'
    }, status=status.HTTP_400_BAD_REQUEST)


def handle_403(request, exception=None):
    """Custom 403 handler"""
    return JsonResponse({
        'status': 'error',
        'type': 'Forbidden',
        'detail': 'You do not have permission to access this resource.'
    }, status=status.HTTP_403_FORBIDDEN)