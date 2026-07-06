import re, random, string, os, secrets, hashlib, time, mimetypes, json, zipfile
from pathlib import Path
from typing import List, Literal
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes



class MimeTypeValidationError(Exception):
    """Raised when file mime type validation fails."""
    pass


def validate_file_type(
    filepath: str | Path,
    allowed_types: List[str],
    method: Literal["magic", "extension", "both"] = "both",
    strict: bool = True
) -> bool:
    """
    Validate a file's MIME type against a list of allowed types.
    
    Args:
        filepath: Path to the file to validate
        allowed_types: List of allowed MIME types (e.g., ['image/jpeg', 'application/pdf'])
        method: Validation method - 'magic' (byte signatures), 'extension' (filename),
                or 'both' (must match on both methods)
        strict: If True, raise exception on validation failure. If False, return False.
    
    Returns:
        bool: True if validation passes
        
    Raises:
        MimeTypeValidationError: If validation fails and strict=True
        FileNotFoundError: If file doesn't exist
    """
    
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    if not filepath.is_file():
        raise MimeTypeValidationError(f"Path is not a file: {filepath}")
    
    # Normalize allowed types to lowercase
    allowed_types = [t.lower() for t in allowed_types]
    
    magic_mime = None
    extension_mime = None
    
    # Method 1: Magic byte detection
    if method in ("magic", "both"):
        magic_mime = _guess_mime_from_magic(filepath)
    
    # Method 2: Extension-based detection
    if method in ("extension", "both"):
        extension_mime = _guess_mime_from_extension(filepath)
    
    # Validation logic
    if method == "both":
        # Both methods must agree and be in allowed list
        if magic_mime is None or extension_mime is None:
            error_msg = "Could not determine MIME type using both methods"
            if strict:
                raise MimeTypeValidationError(error_msg)
            return False
        
        # Check if they match
        if magic_mime != extension_mime:
            error_msg = (
                f"MIME type mismatch: magic bytes suggest '{magic_mime}' "
                f"but extension suggests '{extension_mime}'"
            )
            if strict:
                raise MimeTypeValidationError(error_msg)
            return False
        
        # Check if in allowed list
        if magic_mime not in allowed_types:
            error_msg = f"File type '{magic_mime}' not in allowed types: {allowed_types}"
            if strict:
                raise MimeTypeValidationError(error_msg)
            return False
            
    elif method == "magic":
        if magic_mime is None or magic_mime not in allowed_types:
            error_msg = f"File type '{magic_mime}' not in allowed types: {allowed_types}"
            if strict:
                raise MimeTypeValidationError(error_msg)
            return False
            
    elif method == "extension":
        if extension_mime is None or extension_mime not in allowed_types:
            error_msg = f"File type '{extension_mime}' not in allowed types: {allowed_types}"
            if strict:
                raise MimeTypeValidationError(error_msg)
            return False
    
    return True


def _guess_mime_from_magic(filepath: Path) -> str | None:
    """Guess MIME type from magic bytes."""
    
    # Expanded signatures dictionary
    signatures = {
        # Images
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'BM': 'image/bmp',
        b'\x00\x00\x01\x00': 'image/x-icon',
        b'\x00\x00\x02\x00': 'image/x-icon',
        b'RIFF': 'image/webp',  # Need to check for WEBP
        b'II*\x00': 'image/tiff',
        b'MM\x00*': 'image/tiff',
        
        # Documents
        b'%PDF-': 'application/pdf',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/msword',  # .doc
        b'PK\x03\x04': 'application/zip',  # Also docx, xlsx, etc.
        
        # Archives
        b'\x1f\x8b': 'application/gzip',
        b'Rar!\x1a\x07': 'application/x-rar-compressed',
        b'7z\xbc\xaf\x27\x1c': 'application/x-7z-compressed',
        
        # Audio/Video
        b'ID3': 'audio/mpeg',  # MP3
        b'\xff\xfb': 'audio/mpeg',  # MP3 (alternative)
        b'ftyp': 'video/mp4',  # At offset 4
        b'\x00\x00\x00\x18ftypmp42': 'video/mp4',
        b'\x00\x00\x00\x1cftypmp42': 'video/mp4',
        
        # Text formats
        b'<!DOCTYPE html': 'text/html',
        b'<html': 'text/html',
        b'<?xml': 'text/xml',
    }
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(64)  # Read more bytes for better detection
            
        if len(header) == 0:
            return 'application/x-empty'
        
        # Check against signatures
        for magic, mime in signatures.items():
            if header.startswith(magic):
                # Special cases
                if magic == b'RIFF':
                    if header[8:12] == b'WAVE':
                        return 'audio/wav'
                    elif header[8:12] == b'WEBP':
                        return 'image/webp'
                    else:
                        return 'application/octet-stream'
                
                # PK zip files need more inspection for Office docs
                if magic == b'PK\x03\x04':
                    return _detect_zip_variant(filepath)
                
                return mime
        
        # Check for MP4 with ftyp at offset 4
        if len(header) >= 12 and header[4:8] == b'ftyp':
            return 'video/mp4'
        
        # Try to detect JSON
        if header.lstrip().startswith((b'{', b'[')):
            try:
                # Quick validation
                with open(filepath, 'r', encoding='utf-8') as f:
                    json.load(f)
                return 'application/json'
            except:
                pass
        
        # Fallback: check if it's valid UTF-8 text
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(1024)
            return 'text/plain'
        except:
            return 'application/octet-stream'
            
    except Exception:
        return None


def _detect_zip_variant(filepath: Path) -> str:
    """Detect specific type of ZIP-based file (docx, xlsx, etc.)."""
    
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            filenames = zf.namelist()
            
            # Office Open XML detection
            if 'word/' in ''.join(filenames):
                return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            elif 'xl/' in ''.join(filenames):
                return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            elif 'ppt/' in ''.join(filenames):
                return 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            elif 'META-INF/' in ''.join(filenames):
                return 'application/java-archive'  # JAR file
            
        return 'application/zip'
    except:
        return 'application/zip'

def _extensions_to_mime_types(extensions: List[str]) -> List[str]:
    """Convert file extensions to MIME types for validation."""
    extension_map = {
        'pdf': 'application/pdf',
        'html': 'text/html',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'svg': 'image/svg+xml',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'txt': 'text/plain',
        'csv': 'text/csv',
    }
    return [extension_map.get(ext.lower(), f'application/{ext}') for ext in extensions]

def _guess_mime_from_extension(filepath: Path) -> str | None:
    """Guess MIME type from file extension."""
    mime_type, _ = mimetypes.guess_type(str(filepath))
    return mime_type.lower() if mime_type else None

"""
# Example usage
allowed_images = ['image/jpeg', 'image/png', 'image/gif']
allowed_docs = ['application/pdf', 'text/plain']

try:
    # This will pass if file is a valid image
    validate_file_type('photo.jpg', allowed_images, method='both')
    print("✓ File validated successfully")
except MimeTypeValidationError as e:
    print(f"✗ Validation failed: {e}")

# Non-strict mode returns False instead of raising
is_valid = validate_file_type(
    'document.pdf',
    allowed_images,
    method='magic',
    strict=False
    )
    print(f"Is valid: {is_valid}")
"""


def generate_unique_username(base_username):
    timestamp = str(int(time.time()))
    unique_string = hashlib.sha256((base_username + timestamp).encode()).hexdigest()[:6]
    return f"{base_username}{unique_string}"

def generate_dummy_password_hash():
    """
    The point here is to generate a password for eg. when saml auth 
    is enabled, so the user is not expected to use passwords... but
    how do we plan to integrate this with req'd password changes in:
    https://github.com/signebedi/libreforms-fastapi/issues/231 and
    https://github.com/signebedi/libreforms-fastapi/issues/237
    """
    password = secrets.token_urlsafe(24)
    hashed_password = generate_password_hash(password)

    return hashed_password

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



def prettify_time_diff(time:float):
    if time < 3600:
        if (time / 60) < 1:
            return "less than a minute ago"
        elif (time / 90) < 1 <= (time / 60):
            return "about a minute ago"
        elif (time / 420) < 1 <= (time / 90):
            return "a few minutes ago"
        elif (time / 900) < 1 <= (time / 420):
            return "about ten minutes ago"
        elif (time / 1500) < 1 <= (time / 900):
            return "about twenty minutes ago"
        elif (time / 2100) < 1 <= (time / 1500):
            return "about thirty minutes ago"
        elif (time / 2700) < 1 <= (time / 2100):
            return "about thirty minutes ago"
        elif (time / 3300) < 1 <= (time / 2700):
            return "about forty minutes ago"
        elif (time / 3600) < 1 <= (time / 3300):
            return "about fifty minutes ago"
    elif 7200 > time >= 3600: 
        return f"about an hour ago"
    elif 84600 > time >= 7200: # we short 86400 seconds by 1800 seconds to manage rounding issues
        return f"about {round(time / 3600)} hours ago"
    elif 84600 <= time <= 171000: # we short 172800 seconds by 1800 seconds to manage rounding issues
        return f"about a day ago"
    elif 171000 <= time: # we short 172800 seconds by 1800 seconds to manage rounding issues
        return f"about {round(time / 86400)} days ago"
    else:
        return ""



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

def validate_api_configuration(config):
    if not config.API_ENABLED:
        if not config.REMOTE_API_ADDR:
            raise ConfigurationError("The 'REMOTE_API_ADDR' configuration must be set when 'API_ENABLED' is False. Please check your configuration.")
        if not config.REMOTE_API_KEY:
            raise ConfigurationError("The 'REMOTE_API_KEY' configuration must be set when 'API_ENABLED' is False. Please check your configuration.")

# Main function to check all configurations
def check_configuration_assumptions(config):
    validations = [
        validate_domain, 
        validate_email_verification, 
        validate_help_emails_set,
        validate_help_smtp_enabled,
        validate_mongodb_configuration,
        validate_api_configuration,
    ]

    for validation in validations:
        validation(config)

    return True