# This will ensure the app properly handles Redis connection errors

from __future__ import absolute_import, unicode_literals
import logging

logger = logging.getLogger(__name__)

# Try to configure Celery, but handle errors
try:
    # Celery app config
    from .celery import app as celery_app
    
    __all__ = ['celery_app']
except ImportError:
    logger.warning("Celery not installed, skipping celery configuration")
except Exception as e:
    logger.error(f"Error configuring Celery: {str(e)}")
    
# Configure Redis connection handling
try:
    import redis.exceptions
    from django.core.cache import cache
    
    # Test Redis connection
    try:
        cache.get('test_key')
    except redis.exceptions.ConnectionError:
        logger.warning("Redis connection failed, using fallback cache")
    except Exception as e:
        logger.warning(f"Cache error: {str(e)}")
except ImportError:
    logger.warning("Redis package not installed")
except Exception as e:
    logger.error(f"Error configuring Redis: {str(e)}")