import logging
from django.core.exceptions import MiddlewareNotUsed
from django.conf import settings

logger = logging.getLogger(__name__)

class RedisConnectionMiddleware:
    """
    Middleware to handle Redis connection errors by falling back to alternative methods.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Check if we're using Redis-based cache
        using_redis = False
        if hasattr(settings, 'CACHES') and 'default' in settings.CACHES:
            cache_backend = settings.CACHES['default'].get('BACKEND', '')
            if 'redis' in cache_backend.lower():
                using_redis = True
        
        # If we're not using Redis, this middleware is not needed
        if not using_redis:
            raise MiddlewareNotUsed('Not using Redis cache backend')
        
        logger.info("RedisConnectionMiddleware initialized")
    
    def __call__(self, request):
        # Mark request as potentially having Redis issues
        request.redis_available = self._check_redis_connection()
        
        response = self.get_response(request)
        return response
    
    def _check_redis_connection(self):
        """Check if Redis is available"""
        try:
            from django.core.cache import cache
            # Try a simple cache operation
            cache.set('redis_check', True, 1)
            return True
        except Exception:
            # Redis is not available
            return False
