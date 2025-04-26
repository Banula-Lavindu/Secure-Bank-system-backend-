from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re

class PasswordStrengthValidator:
    """
    Validate that the password meets high security standards for banking applications:
    - At least 10 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    
    def validate(self, password, user=None):
        if len(password) < 10:
            raise ValidationError(
                _("Password must be at least 10 characters long."),
                code='password_too_short',
            )
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            )
        
        if not re.search(r'[a-z]', password):
            raise ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            )
        
        if not re.search(r'\d', password):
            raise ValidationError(
                _("Password must contain at least one digit."),
                code='password_no_digit',
            )
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            raise ValidationError(
                _("Password must contain at least one special character."),
                code='password_no_special',
            )
        
    def get_help_text(self):
        return _(
            "Your password must be at least 10 characters long and contain uppercase letters, "
            "lowercase letters, digits, and special characters."
        )