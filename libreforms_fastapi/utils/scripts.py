import re, random, string, os
from passlib.context import CryptContext
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


# Create a password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def old_generate_password_hash(password: str):
    return pwd_context.hash(password)

def old_check_password_hash(hash: str, password: str):
    return pwd_context.verify(password, hash)

def generate_password_hash(password: str):

    # Generate a random salt
    salt = os.urandom(16)

    # Create Scrypt object
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )

    # Derive the password and return the salt and key combined
    key = kdf.derive(password.encode())  
    return salt + key

def check_password_hash(hash: bytes, password: str):

    # The salt is the first 16 bytes, the rest is the key
    salt = hash[:16]  
    key = hash[16:]
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), key)
        return True
    except Exception:
        return False

# this is a password generation script that takes a password length
# and regex, returning a password string. It also takes a alphanumeric_percentage
# parameter, between 0 and 1, which scopes the percentage of alphanumeric
# chars that will be used in the password generated
def percentage_alphanumeric_generate_password(
    regex:str, 
    length:int, 
    alphanumeric_percentage:float
):
    def random_char_from_class(class_name):
        if class_name == '\\d':
            return random.choice(string.digits)
        elif class_name == '\\w':
            return random.choice(string.ascii_letters + string.digits)
        elif class_name == '\\s':
            return random.choice(string.whitespace)
        else:
            return random.choice(string.printable)

    # here we validate that `alphanumeric_percentage` is a float between 0 and 1
    if not ( 0 <= alphanumeric_percentage <= 1 ):
        raise Exception("You must pass an alphanumeric percentage between 0 and 1, inclusive")

    pattern = re.compile(regex)

    alphanumeric_count = int(length * alphanumeric_percentage)
    non_alphanumeric_count = length - alphanumeric_count

    while True:
        alphanumeric_part = [random_char_from_class('\\w') for _ in range(alphanumeric_count)]
        non_alphanumeric_part = [random_char_from_class(c) if c in ('\\d', '\\w', '\\s') else c for c in random.choices(regex, k=non_alphanumeric_count)]
        password = ''.join(random.sample(alphanumeric_part + non_alphanumeric_part, length))
        if pattern.fullmatch(password):
            return password



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

def validate_mongodb_configuration(config):
    # If MongoDB is enabled, ensure the URI is not an empty string
    if config.MONGODB_ENABLED and config.MONGODB_URI == '':
        raise ConfigurationError("MongoDB URI cannot be an empty string ('MONGODB_URI') when MongoDB is enabled ('MONGODB_ENABLED' = True).")

# Main function to check all configurations
def check_configuration_assumptions(config):
    validations = [
        validate_domain, 
        validate_email_verification, 
        validate_help_emails_set,
        validate_help_smtp_enabled,
        validate_mongodb_configuration,                
    ]

    for validation in validations:
        validation(config)

    return True