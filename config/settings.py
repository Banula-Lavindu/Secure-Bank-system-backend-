# Fix Redis connection configuration
if 'redis' in CACHES['default']['BACKEND'].lower():
    # Make sure the Redis client options don't have problematic SSL settings
    if 'OPTIONS' in CACHES['default'] and 'CONNECTION_POOL_KWARGS' in CACHES['default']['OPTIONS']:
        if 'ssl_cert_reqs' in CACHES['default']['OPTIONS']['CONNECTION_POOL_KWARGS']:
            # Remove the problematic setting
            del CACHES['default']['OPTIONS']['CONNECTION_POOL_KWARGS']['ssl_cert_reqs']

# Also fix Redis broker settings if using Celery
if 'CELERY_BROKER_URL' in globals() and CELERY_BROKER_URL.startswith('redis'):
    if 'CELERY_BROKER_TRANSPORT_OPTIONS' in globals():
        if 'ssl_cert_reqs' in CELERY_BROKER_TRANSPORT_OPTIONS:
            del CELERY_BROKER_TRANSPORT_OPTIONS['ssl_cert_reqs']