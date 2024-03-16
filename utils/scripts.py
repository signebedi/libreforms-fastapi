from passlib.context import CryptContext

# Create a password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_password_hash(password: str):
    return pwd_context.hash(password)

def check_password_hash(hash: str, password: str):
    return pwd_context.verify(password, hash)


# Wrote an exception for configuration errors
class ConfigurationError(Exception):
    """Exception raised for errors in the flask app configuration."""
    def __init__(self, message):
        super().__init__(message)


# Individual validation functions
def validate_domain(config):
    if not config.DOMAIN:
        raise ConfigurationError("The 'DOMAIN' configuration must be set. Please check your configuration.")

def validate_email_verification(config):
    if config.REQUIRE_EMAIL_VERIFICATION and not config.SMTP_ENABLED:
        raise ConfigurationError("SMTP must be enabled ('SMTP_ENABLED' = True) when email verification is required ('REQUIRE_EMAIL_VERIFICATION' = True).")

def validate_help_emails_set(config):
    if config.HELP_PAGE_ENABLED and not config.HELP_EMAIL:
        raise ConfigurationError("Help email must be provided('HELP_EMAIL' = 'someone@somewhere') when enabling the user help page ('HELP_PAGE_ENABLED' = True).")

def validate_help_smtp_enabled(config):
    if config.HELP_PAGE_ENABLED and not config.SMTP_ENABLED:
        raise ConfigurationError("SMTP must be enabled ('SMTP_ENABLED' = True) when enabling the user help page ('HELP_PAGE_ENABLED' = True).")

# Main function to check all configurations
def check_configuration_assumptions(config):
    validations = [validate_domain, 
                    validate_email_verification, 
                    validate_help_emails_set,
                    validate_help_smtp_enabled,                    
    ]

    for validation in validations:
        validation(config)

    return True