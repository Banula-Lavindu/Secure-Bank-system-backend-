"""
Utility module to check Redis connectivity and handle Redis-related errors.
This can be imported and used in various parts of the application.
"""

import redis
import logging
import random
import string
import os
from functools import wraps

logger = logging.getLogger(__name__)

def check_redis_connection(host='127.0.0.1', port=6379, db=0, timeout=1):
    """
    Check if Redis is available
    Returns True if connection successful, False otherwise
    """
    try:
        redis_client = redis.Redis(
            host=host, 
            port=port, 
            db=db, 
            socket_timeout=timeout,
            socket_connect_timeout=timeout
        )
        return redis_client.ping()
    except redis.exceptions.ConnectionError:
        logger.warning(f"Redis connection failed at {host}:{port}")
        return False
    except Exception as e:
        logger.error(f"Error checking Redis connection: {str(e)}")
        return False

def get_fallback_storage():
    """Returns a directory path for fallback storage"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fallback_dir = os.path.join(base_dir, 'tmp', 'fallback_cache')
    os.makedirs(fallback_dir, exist_ok=True)
    return fallback_dir

def store_fallback_otp(email, otp_code, expires_in_minutes=10):
    """
    Store OTP in a fallback file-based storage when Redis is unavailable
    """
    try:
        fallback_dir = get_fallback_storage()
        # Create a filename based on email (safely)
        safe_email = ''.join(c if c.isalnum() else '_' for c in email)
        filename = os.path.join(fallback_dir, f"otp_{safe_email}.txt")
        
        # Write OTP with expiry time
        import time
        expiry = time.time() + (expires_in_minutes * 60)
        
        with open(filename, 'w') as f:
            f.write(f"{otp_code}:{expiry}")
        
        return True
    except Exception as e:
        logger.error(f"Error storing fallback OTP: {str(e)}")
        return False

def verify_fallback_otp(email, otp_code):
    """
    Verify OTP from fallback storage
    """
    try:
        fallback_dir = get_fallback_storage()
        safe_email = ''.join(c if c.isalnum() else '_' for c in email)
        filename = os.path.join(fallback_dir, f"otp_{safe_email}.txt")
        
        if not os.path.exists(filename):
            return False
        
        with open(filename, 'r') as f:
            content = f.read().strip()
        
        stored_otp, expiry = content.split(':')
        import time
        if time.time() > float(expiry):
            # OTP expired, remove the file
            os.remove(filename)
            return False
        
        # Check if OTP matches
        if stored_otp == otp_code:
            # OTP verified, remove the file
            os.remove(filename)
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error verifying fallback OTP: {str(e)}")
        return False

def redis_connection_required(view_func):
    """
    Decorator for views that require Redis.
    If Redis is not available, it will use fallback methods.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Set a flag in the request to indicate if Redis is available
        request.redis_available = check_redis_connection()
        return view_func(request, *args, **kwargs)
    return _wrapped_view
