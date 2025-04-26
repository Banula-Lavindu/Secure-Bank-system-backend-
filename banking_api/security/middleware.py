import re
import json
import logging
from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from django.db.utils import OperationalError, ProgrammingError
# Updated import for ipware based on official documentation
from ipware import get_client_ip
from user_agents import parse as parse_user_agent
# Updated model imports to match what's defined in models.py
from banking_api.security.models import SecurityAuditLog, IPBlacklist as BannedIP

# Setup logger
logger = logging.getLogger('security')

class SecurityMiddleware:
    """Middleware for handling various security measures"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Compile regex patterns for sensitive data
        self.sensitive_patterns = [
            re.compile(r'password', re.IGNORECASE),
            re.compile(r'ssn', re.IGNORECASE),
            re.compile(r'social_?security', re.IGNORECASE),
            re.compile(r'card_?number', re.IGNORECASE),
            re.compile(r'credit_?card', re.IGNORECASE),
            re.compile(r'cvv', re.IGNORECASE),
            re.compile(r'secret', re.IGNORECASE),
            re.compile(r'account_?number', re.IGNORECASE),
            re.compile(r'token', re.IGNORECASE),
        ]
        
        # Security headers
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=(self)',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
        }
        
        # Define allowed HTTP methods
        self.allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']
        
        # Define auth endpoints for special handling
        self.auth_endpoints = [
            '/api/auth/login/',
            '/api/auth/register/',
            '/api/v1/auth/login/',
            '/api/v1/auth/register/',
        ]
        
        # Safe content patterns - allowed in auth endpoints
        self.safe_auth_patterns = [
            r'@',                      # Allow @ in email addresses
            r'[a-zA-Z0-9._-]+@',       # Email format
            r'\+',                     # Allow + in phone numbers
            r'\d{3}-\d{3}-\d{4}',      # Phone number format
            r'password\s*:',           # Allow password field in JSON
        ]
    
    def __call__(self, request):
        # Get client IP
        ip_address, is_routable = get_client_ip(request)
        if ip_address is None:
            ip_address = '0.0.0.0'
        
        try:
            # Check for banned IP
            if self.is_ip_banned(ip_address):
                logger.warning(f"Request from banned IP: {ip_address}")
                return JsonResponse(
                    {'error': 'Access denied.', 'message': 'Your IP address has been blocked.'},
                    status=403
                )
            
            # Check rate limits
            if self.is_rate_limited(request, ip_address):
                logger.warning(f"Rate limit exceeded for IP: {ip_address}")
                return JsonResponse(
                    {'error': 'Too many requests.', 'message': 'Please try again later.'},
                    status=429
                )
        except (OperationalError, ProgrammingError) as e:
            # Log the database error but continue processing the request
            logger.error(f"Database error in security middleware: {str(e)}")
        
        # Validate request method
        if request.method not in self.allowed_methods:
            logger.warning(f"Invalid HTTP method: {request.method} from {ip_address}")
            return JsonResponse(
                {'error': 'Method not allowed.', 'message': 'The requested method is not supported.'},
                status=405
            )
        
        # Special handling for auth endpoints
        is_auth_endpoint = any(request.path.endswith(endpoint) for endpoint in self.auth_endpoints)
        
        # Different validation logic for auth endpoints
        if is_auth_endpoint:
            # Use less strict validation for login/register
            has_suspicious = self.has_suspicious_auth_content(request)
        else:
            # Use standard validation for other endpoints
            has_suspicious = self.has_suspicious_content(request)
        
        # Check for suspicious content
        if has_suspicious:
            logger.warning(f"Suspicious content detected from {ip_address}")
            try:
                # Check if the table exists before attempting to log
                if SecurityAuditLog.objects.count() >= 0:  # This will raise exception if table doesn't exist
                    self.log_security_event(
                        request, 'suspicious_content', 
                        'Suspicious content detected in request', 
                        ip_address, 'medium'
                    )
            except (OperationalError, ProgrammingError) as e:
                logger.error(f"Could not log security event due to database error: {str(e)}")
                # Continue processing even if logging fails
            
            return JsonResponse(
                {'error': 'Invalid request.', 'message': 'The request contains suspicious content.'},
                status=400
            )
        
        # Sanitize sensitive data in request body for logging
        sanitized_body = self.sanitize_sensitive_data(request)
        
        # Log API access for sensitive endpoints if needed
        if self.is_sensitive_endpoint(request.path):
            try:
                self.log_security_event(
                    request, 'api_access', 
                    f"Access to sensitive endpoint: {request.path}", 
                    ip_address, 'low'
                )
            except (OperationalError, ProgrammingError) as e:
                logger.error(f"Database error when logging security event: {str(e)}")
        
        # Process the request
        response = self.get_response(request)
        
        # Add security headers to response
        for header, value in self.security_headers.items():
            response[header] = value
        
        # Remove sensitive server information
        if 'Server' in response:
            del response['Server']
        
        return response
    
    def has_suspicious_auth_content(self, request):
        """
        Special validation for auth endpoints (login/register)
        Uses a more permissive validation that allows email addresses and passwords
        but still blocks actual attack patterns
        """
        # Critical attack patterns to still block
        critical_patterns = [
            # SQL injection
            r'(\%27)|(\')|(--)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(--)|(\%3B)|(\;))',
            r'((\%27)|(\'))union',
            r'exec(\s|\+)+(s|x)p\w+',
            r'UNION\s+ALL\s+SELECT\s+',
            
            # XSS - more strict subset
            r'<script[^>]*>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'eval\s*\(',
            
            # Path traversal
            r'\.\./',
            r'\.\.\%2f',
            r'\.\.\\',
        ]
        
        try:
            # For POST body validation (specific to auth)
            if request.body:
                body_content = request.body.decode('utf-8')
                
                # Parse JSON if possible to validate structure
                try:
                    body_data = json.loads(body_content)
                    
                    # If we have JSON data, validate each required field
                    if 'email' in body_data:
                        email = body_data['email']
                        # Basic email format validation
                        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                            logger.warning(f"Invalid email format in request: {email}")
                            return True
                    
                    # Check password existence but don't validate format
                    # (let the backend handle password strength validation)
                    
                except json.JSONDecodeError:
                    # If not valid JSON, run simple pattern checks
                    for pattern in critical_patterns:
                        if re.search(pattern, body_content, re.IGNORECASE):
                            return True
            
            # Check URL path for critical patterns
            for pattern in critical_patterns:
                if re.search(pattern, request.path, re.IGNORECASE):
                    return True
            
            # Check query parameters
            for key, value in request.GET.items():
                for pattern in critical_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return True
            
            return False
        except:
            # If any error occurs during validation, be safe and report as suspicious
            logger.error("Error during auth content validation", exc_info=True)
            return True
    
    def is_ip_banned(self, ip_address):
        """Check if the IP address is banned"""
        now = timezone.now()
        try:
            return BannedIP.objects.filter(
                ip_address=ip_address,
                expires_at__gt=now  # Check if ban is still active (not expired)
            ).exists()
        except (OperationalError, ProgrammingError):
            # If the table doesn't exist, return False
            return False
    
    def is_rate_limited(self, request, ip_address):
        """Check rate limits based on IP and endpoint"""
        try:
            # Simple rate limiting since RateLimitRule model doesn't exist
            # Count requests from this IP in the last minute
            time_window = timezone.now() - timezone.timedelta(seconds=60)
            
            count = SecurityAuditLog.objects.filter(
                ip_address=ip_address,
                timestamp__gte=time_window,
                event_type='api_access'
            ).count()
            
            # Hard-coded rate limit of 60 requests per minute
            if count >= 60:
                # Log rate limit exceeded
                try:
                    self.log_security_event(
                        request, 'rate_limit_exceeded',
                        "Rate limit exceeded: 60 requests per minute",
                        ip_address, 'medium',
                        {'limit': 60, 'window': '60 seconds'}
                    )
                except (OperationalError, ProgrammingError):
                    # Log error but continue
                    logger.error("Could not log rate limit event due to database error")
                
                return True
            
            return False
        except (OperationalError, ProgrammingError):
            # If the table doesn't exist, don't rate limit
            return False
    
    def has_suspicious_content(self, request):
        """Check for common attack patterns in request"""
        # Check for SQL injection attempts
        sql_patterns = [
            r'(\%27)|(\')|(--)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(--)|(\%3B)|(\;))',
            r'((\%27)|(\'))union',
            r'exec(\s|\+)+(s|x)p\w+',
            r'UNION\s+ALL\s+SELECT\s+',
        ]
        
        # Check for XSS attempts
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'eval\s*\(',
            r'document\.cookie',
        ]
        
        # Check for path traversal
        path_traversal_patterns = [
            r'\.\./',
            r'\.\.\%2f',
            r'\.\.\\',
            r'\.\.\%5c',
            r'etc/passwd',
        ]
        
        # Combine all patterns
        all_patterns = sql_patterns + xss_patterns + path_traversal_patterns
        
        # Check URL path
        for pattern in all_patterns:
            if re.search(pattern, request.path, re.IGNORECASE):
                return True
        
        # Check query parameters
        for key, value in request.GET.items():
            for pattern in all_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
        
        # Check request body
        if request.body:
            try:
                body_content = request.body.decode('utf-8')
                for pattern in all_patterns:
                    if re.search(pattern, body_content, re.IGNORECASE):
                        return True
            except:
                # If we can't decode the body, just skip this check
                pass
        
        # Check HTTP headers for suspicious content
        suspicious_headers = ['X-Forwarded-Host', 'X-Host', 'X-Original-URL', 'X-Rewrite-URL']
        for header in suspicious_headers:
            if header in request.headers:
                return True
        
        return False
    
    def sanitize_sensitive_data(self, request):
        """Sanitize sensitive data in request for logging"""
        if not request.body:
            return None
        
        try:
            # Try to parse as JSON
            body = json.loads(request.body)
            
            # Deep copy and sanitize
            sanitized = self._sanitize_dict(body)
            
            return sanitized
        except:
            # If not JSON or error, return sanitized string
            body_str = request.body.decode('utf-8', errors='ignore')
            for pattern in self.sensitive_patterns:
                body_str = pattern.sub(r'\1: ***REDACTED***', body_str)
            return body_str
    
    def _sanitize_dict(self, data):
        """Recursively sanitize a dictionary"""
        if not isinstance(data, dict):
            return data
        
        result = {}
        for key, value in data.items():
            # Check if this key matches any sensitive patterns
            is_sensitive = any(pattern.search(key) for pattern in self.sensitive_patterns)
            
            if is_sensitive:
                result[key] = '***REDACTED***'
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = [self._sanitize_dict(item) if isinstance(item, dict) else item for item in value]
            else:
                result[key] = value
        
        return result
    
    def is_sensitive_endpoint(self, path):
        """Determine if an endpoint is sensitive for logging purposes"""
        sensitive_patterns = [
            r'/api/auth/',
            r'/api/v1/auth/',  # Added v1 prefix for API versioning
            r'/api/accounts/',
            r'/api/transactions/',
            r'/admin/',
            r'/api/admin/',
        ]
        
        return any(re.search(pattern, path) for pattern in sensitive_patterns)
    
    def log_security_event(self, request, event_type, description, ip_address, severity='medium', additional_data=None):
        """Log security events to the database"""
        try:
            # Get user agent information
            user_agent_string = request.META.get('HTTP_USER_AGENT', '')
            user_agent = parse_user_agent(user_agent_string)
            
            # Build additional data
            data = additional_data or {}
            data.update({
                'method': request.method,
                'path': request.path,
                'user_agent': user_agent_string,
                'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
                'os': f"{user_agent.os.family} {user_agent.os.version_string}",
                'is_mobile': user_agent.is_mobile,
                'is_bot': user_agent.is_bot,
            })
            
            # Log to the database
            SecurityAuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                event_type=event_type,
                event_description=description,
                ip_address=ip_address,
                user_agent=user_agent_string,
                severity=severity,
                additional_data=data
            )
        except (OperationalError, ProgrammingError) as e:
            # Log the error but don't break the application
            logger.error(f"Could not log security event due to database error: {str(e)}")

class MaliciousRequestMiddleware:
    """Middleware specialized in detecting and blocking malicious requests"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Known attack signatures
        self.attack_signatures = {
            'sql_injection': [
                r'SELECT\s+.*\s+FROM\s+',
                r'INSERT\s+INTO\s+',
                r'UPDATE\s+.*\s+SET\s+',
                r'DELETE\s+FROM\s+',
                r'DROP\s+TABLE',
                r'UNION\s+SELECT',
                r'OR\s+1\s*=\s*1',
                r'AND\s+1\s*=\s*1',
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:.*\(.*\)',
                r'<img[^>]*\s+on\w+\s*=',
                r'<\w+[^>]*\s+on\w+\s*=',
                r'document\.cookie',
            ],
            'command_injection': [
                r';\s*rm\s+-rf',
                r';\s*wget\s+',
                r';\s*curl\s+',
                r';\s*bash',
                r';\s*sh\s+-c',
                r'\|\s*bash',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\./\.\.',
                r'/etc/passwd',
                r'/etc/shadow',
                r'C:\\Windows\\system32',
                r'cmd\.exe',
                r'system32',
            ],
            'log4j': [
                r'\$\{jndi:ldap://',
                r'\$\{jndi:rmi://',
                r'\$\{jndi:',
            ]
        }
        
        # Auth endpoints that need special handling
        self.auth_endpoints = [
            '/api/auth/login/',
            '/api/auth/register/',
            '/api/v1/auth/login/',
            '/api/v1/auth/register/',
        ]
    
    def __call__(self, request):
        # Skip detailed attack signature checks for auth endpoints
        # as they may contain password patterns etc.
        if any(request.path.endswith(endpoint) for endpoint in self.auth_endpoints):
            # For auth endpoints, do minimal validation
            attack_type = self.check_auth_attack_signatures(request)
        else:
            # For regular endpoints, do full validation
            attack_type = self.check_attack_signatures(request)
            
        if attack_type:
            # Get client IP
            ip_address, _ = get_client_ip(request)
            if ip_address is None:
                ip_address = '0.0.0.0'
            
            try:
                # Log the attack
                user = request.user if request.user.is_authenticated else None
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='security_violation',
                    event_description=f"Potential {attack_type} attack detected",
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    severity='high',
                    additional_data={
                        'attack_type': attack_type,
                        'method': request.method,
                        'path': request.path,
                        'query_params': dict(request.GET.items())
                    }
                )
                
                # Consider auto-banning for repeated attacks
                try:
                    recent_attacks = SecurityAuditLog.objects.filter(
                        ip_address=ip_address,
                        event_type='security_violation',
                        timestamp__gte=timezone.now() - timezone.timedelta(hours=1)
                    ).count()
                    
                    if recent_attacks >= 3:
                        # Ban the IP temporarily
                        BannedIP.objects.get_or_create(
                            ip_address=ip_address,
                            defaults={
                                'reason': f"Repeated {attack_type} attack attempts",
                                'banned_until': timezone.now() + timezone.timedelta(hours=24),
                                'is_active': True
                            }
                        )
                except (OperationalError, ProgrammingError) as e:
                    logger.error(f"Database error when checking recent attacks: {str(e)}")
            except (OperationalError, ProgrammingError) as e:
                logger.error(f"Database error when logging attack: {str(e)}")
            
            # Return access denied response
            return JsonResponse(
                {'error': 'Access denied.', 'message': 'Malicious request detected.'},
                status=403
            )
        
        # Continue with the request if no attack detected
        return self.get_response(request)
    
    def check_auth_attack_signatures(self, request):
        """
        Lightweight signature checking for auth endpoints
        Focuses only on the most critical attack patterns
        """
        # Limited set of patterns for auth endpoints
        critical_patterns = {
            'sql_injection': [
                r'UNION\s+SELECT',
                r'OR\s+1\s*=\s*1',
                r'--\s',
                r';\s*--',
                r'DROP\s+TABLE',
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:.*\(.*\)',
            ],
            'command_injection': [
                r';\s*rm\s+-rf',
                r';\s*wget\s+',
                r';\s*curl\s+',
            ],
        }
        
        # Check only specific components, not the entire request
        components_to_check = []
        
        # Add URL path
        components_to_check.append(request.path)
        
        # Add query parameters
        for key, value in request.GET.items():
            components_to_check.append(f"{key}={value}")
        
        # For POST body, we'll be more careful since it can contain passwords
        # We won't check the entire body, just look for specific attack patterns
        
        # Join components for checking
        content_to_check = ' '.join(components_to_check)
        
        # Check against critical patterns
        for attack_type, patterns in critical_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    return attack_type
        
        return None
    
    def check_attack_signatures(self, request):
        """Check if the request matches known attack signatures"""
        # Create a combined string of all request components to check
        components_to_check = []
        
        # Add URL path
        components_to_check.append(request.path)
        
        # Add query parameters
        for key, value in request.GET.items():
            components_to_check.append(f"{key}={value}")
        
        # Add request body if present
        if request.body:
            try:
                body_str = request.body.decode('utf-8')
                components_to_check.append(body_str)
            except:
                pass
        
        # Add headers that might be used in attacks
        for header_name in ['User-Agent', 'Referer', 'X-Forwarded-For']:
            if header_name in request.headers:
                components_to_check.append(request.headers[header_name])
        
        # Join all components into a single string for efficient checking
        content_to_check = ' '.join(components_to_check)
        
        # Check against each attack type
        for attack_type, patterns in self.attack_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    return attack_type
        
        return None