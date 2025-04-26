# Modern Banking System - Backend

This is the backend for the Modern Banking System application. It provides secure API endpoints for the frontend application.

## Technology Stack
- Django Rest Framework for the API
- PostgreSQL for database
- Redis for caching and session management
- Argon2 for password hashing
- JWT for authentication
- AES-256-GCM for sensitive data encryption
- HTTPS/TLS 1.3 for secure communication
- 2FA/OTP for enhanced security

## Directory Structure
```
backend/
├── banking_api/               # Django project directory
│   ├── accounts/              # User account management
│   ├── transactions/          # Transaction processing
│   ├── auth/                  # Authentication handling
│   ├── notifications/         # User notifications
│   ├── admin_panel/           # Admin dashboard functionality
│   └── security/              # Security utilities
├── config/                    # Configuration files
├── requirements.txt           # Python dependencies
└── scripts/                   # Utility scripts
```

## Setup Instructions
1. Install dependencies: `pip install -r requirements.txt`
2. Configure database settings in `.env`
3. Run migrations: `python manage.py migrate`
4. Create superuser: `python manage.py createsuperuser`
5. Run server: `python manage.py runserver`