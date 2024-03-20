""" 
app/utils/config.py: sets the general configs for an app with REST and UI
Note: application-specific logic and configurations SHOULD come from a 
separate source to help preserve the generalizability of this logic.
"""

import os, shutil
from markupsafe import Markup
from dotenv import (
    load_dotenv, 
    dotenv_values, 
    set_key
)

from datetime import timedelta, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic_settings import BaseSettings
from pydantic import validator, ValidationError, constr
from pydantic.networks import MongoDsn

from libreforms_fastapi.utils.scripts import check_configuration_assumptions

# Determine environment
env = os.getenv('ENVIRONMENT', 'development')

if not env == 'testing':
    env_file = 'prod.env' if env == 'production' else 'dev.env'
    instance_directory = os.path.join(os.getcwd(), 'instance')
    log_directory = os.path.join(os.getcwd(), 'instance', 'log')
    
    # Ensure the instance directory exists
    os.makedirs(instance_directory, exist_ok=True)

    # Ensure the log directory exists
    os.makedirs(log_directory, exist_ok=True)

    env_file_path = os.path.join(instance_directory, env_file)

    if not os.path.exists(env_file_path):
        # Create a blank env file and warn the user
        with open(env_file_path, 'w') as f:
            pass

        print(f"Warning: {env_file} not found. A blank file has been created. Please configure your environment variables.")

        # raise Exception("Error: env file not found. Did you run 'app-init config'?")

    load_dotenv(env_file_path)

else: env_file_path=""

def yield_config(_env=env):
    if _env == 'production':
        return ProductionConfig()
    elif _env == 'testing':
        return TestingConfig()
    return DevelopmentConfig()

# We employ a pydantic settings class to manage dotenv settings, see 
# https://fastapi.tiangolo.com/advanced/settings/#create-the-settings-object.
# class Config(BaseSettings):
class Config(BaseSettings):
    ENVIRONMENT:str = env
    CONFIG_FILE_PATH:str = env_file_path
    SITE_NAME:str = os.getenv('SITE_NAME', 'libreforms_fastapi')
    SITE_SOURCE_URL:str = os.getenv('SITE_SOURCE_URL', 'https://github.com/signebedi/libreforms-fastapi')
    HOMEPAGE_CONTENT:str = Markup(os.getenv('HOMEPAGE_CONTENT', ''))
    PRIVACY_MESSAGE:str = Markup(os.getenv('PRIVACY_MESSAGE', ''))
    DOMAIN:str = os.getenv('DOMAIN', 'http://127.0.0.1:5000')
    DEBUG:bool = os.getenv('DEBUG', 'False') == 'True'
    SECRET_KEY:str = os.getenv('SECRET_KEY', 'supersecret_dev_key')

    TIMEZONE: constr(strip_whitespace=True) = os.getenv('TIMEZONE', 'America/New_York')

    @validator('TIMEZONE')
    def validate_timezone(cls, v):
        try:
            # Attempt to create a ZoneInfo object to validate the timezone
            tz = ZoneInfo(v)
        except ZoneInfoNotFoundError:
            # If the timezone is not found, raise a ValueError
            raise ValueError(f'Invalid timezone: {v}')
        # Return the original string value, or you could return ZoneInfo(v) to store the object
        return tz

    SQLALCHEMY_DATABASE_URI:str = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{os.path.join(os.getcwd(), "instance", "app.sqlite")}')
    SQLALCHEMY_TRACK_MODIFICATIONS:bool = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'

    USERNAME_REGEX: str = os.getenv('USERNAME_REGEX', r"^\w\w\w\w+$")
    USERNAME_HELPER_TEXT: str = os.getenv('USERNAME_HELPER_TEXT', "Username must be 4-36 alphanumeric characters")
    PASSWORD_REGEX: str = os.getenv('PASSWORD_REGEX', r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+[\]{};\'\\:"|,.<>/?])[A-Za-z\d!@#$%^&*()_+[\]{};\'\\:"|,.<>/?]{8,}$')
    PASSWORD_HELPER_TEXT: str = os.getenv('PASSWORD_HELPER_TEXT', "Password must be 8+ characters, must include uppercase, lowercase, digit, and special character")

    # Here we allow the application to be run headlessly, but default to an enabled UI,
    # see https://github.com/signebedi/libreforms-fastapi/issues/18.
    UI_ENABLED:bool = os.getenv('UI_ENABLED', 'True') == 'True'

    SMTP_ENABLED:bool = os.getenv('SMTP_ENABLED', 'False') == 'True'
    SMTP_MAIL_SERVER:str = os.getenv('SMTP_MAIL_SERVER', "")
    SMTP_PORT:int = int(os.getenv('SMTP_PORT', 25))    
    SMTP_USERNAME:str = os.getenv('SMTP_USERNAME', "")
    SMTP_PASSWORD:str = os.getenv('SMTP_PASSWORD', "")
    SMTP_FROM_ADDRESS:str = os.getenv('SMTP_FROM_ADDRESS', "")

    RATE_LIMITS_ENABLED:bool = os.getenv('RATE_LIMITS_ENABLED', 'False') == 'True'
    # Rate limiting period should be an int corresponding to the number of minutes
    RATE_LIMITS_MAX_REQUESTS:int = int(os.getenv('RATE_LIMITS_MAX_REQUESTS', 15))
    RATE_LIMITS_PERIOD: timedelta = timedelta(minutes=1)  # First we set a default value

    @validator('RATE_LIMITS_PERIOD', pre=True, always=True)
    def set_rate_limits_period(cls, v):
        # Next we dectorate
        minutes = int(os.getenv('RATE_LIMITS_PERIOD', '1'))
        return timedelta(minutes=minutes)

    MAX_LOGIN_ATTEMPTS:int = int(os.getenv('MAX_LOGIN_ATTEMPTS', "0"))
    REQUIRE_EMAIL_VERIFICATION:bool = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'False') == 'True'

    # Permanent session lifetime should be an int corresponding to the number of minutes
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=6)  # Again we set a default value

    @validator('PERMANENT_SESSION_LIFETIME', pre=True, always=True)
    def set_permanent_session_lifetime(cls, v):
        hours = int(os.getenv('PERMANENT_SESSION_LIFETIME', '6'))
        return timedelta(hours=hours)

    COLLECT_USAGE_STATISTICS:bool = os.getenv('COLLECT_USAGE_STATISTICS', 'False') == 'True'
    DISABLE_NEW_USERS:bool = os.getenv('DISABLE_NEW_USERS', 'False') == 'True'

    # Set help page information
    HELP_PAGE_ENABLED:bool = os.getenv('HELP_PAGE_ENABLED', 'False') == 'True'
    HELP_EMAIL:str = os.getenv('HELP_EMAIL', "")

    # Set site cookie configs, see https://github.com/signebedi/gita-api/issues/109
    SESSION_COOKIE_SECURE:bool = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    SESSION_COOKIE_SAMESITE:str = os.getenv('SESSION_COOKIE_SAMESITE', "None")

    MONGODB_ENABLED:bool = os.getenv('MONGODB_ENABLED:', 'False') == 'True'
    MONGODB_URI: str = "" # Default to empty string

    @validator('MONGODB_URI', pre=True, always=True)
    def validate_mongodb_uri(cls, v):
        # Attempt to read from environment variable if not set
        uri = os.getenv('MONGODB_URI', '')
        if uri == '':
            return uri  # Allow empty strings
        # Utilize MongoDsn for validation if not empty
        return MongoDsn.validate(uri)

class ProductionConfig(Config):
    # The DOMAIN is meant to fail in production if you have not set it
    DOMAIN:str = os.getenv('DOMAIN', None)
    
    # Defaults to True in production
    SMTP_ENABLED:bool = os.getenv('SMTP_ENABLED', 'True') == 'True'

    # Defaults to True / Enabled in production, inheriting the other default settings
    RATE_LIMITS_ENABLED:bool = os.getenv('RATE_LIMITS_ENABLED', 'True') == 'True'

    MAX_LOGIN_ATTEMPTS:int = int(os.getenv('MAX_LOGIN_ATTEMPTS', "5")) 
    REQUIRE_EMAIL_VERIFICATION:bool = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'True') == 'True'

    # Set site cookie configs, see https://github.com/signebedi/gita-api/issues/109
    SESSION_COOKIE_SECURE:bool = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_SAMESITE:str = os.getenv('SESSION_COOKIE_SAMESITE', "None")


class DevelopmentConfig(Config):
    DEBUG:bool = True
    SQLALCHEMY_DATABASE_URI:str = f'sqlite:///{os.path.join(os.getcwd(), "instance", "DEV_app.sqlite")}'

class TestingConfig(Config):
    TESTING:bool = True
    DOMAIN:str = 'http://127.0.0.1:5000'
    SECRET_KEY:str = 'supersecret_test_key'
    SQLALCHEMY_DATABASE_URI:str = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS:bool = False
    
    SMTP_ENABLED:bool = False

    RATE_LIMITS_ENABLED:bool = False
    MAX_LOGIN_ATTEMPTS:int = 0
    REQUIRE_EMAIL_VERIFICATION:bool = False



# View functions should pass config changes as kwargs to the function below
def validate_and_write_configs(app_config, **kwargs):


    # First check assumptions

    app_config_copy = app_config.copy()
    for key in kwargs.keys():
        app_config_copy[key] = kwargs[key]

    try:
        assert check_configuration_assumptions(config=app_config_copy)

    except Exception as e:
        return

    config_file_path = app_config['CONFIG_FILE_PATH']
    
    # Ensure the .env file exists
    if not os.path.isfile(config_file_path):
        print(f"The file at {config_file_path} does not exist. Creating a new one.")
        with open(config_file_path, 'w'): pass
    else:
        datetime_format = datetime.now(app_config.TIMEZONE).strftime("%Y%m%d%H%M%S") # This can be adjusted as needed
        backup_file_path = f"{config_file_path}.{datetime_format}"
        shutil.copy(config_file_path, backup_file_path)
        print(f"Backup of the current config file created at {backup_file_path}")

    # Load current configurations from .env file
    current_configs = dotenv_values(config_file_path)
    
    for config_name, config_value in kwargs.items():
        if config_name not in app_config.keys():
            print(f"{config_name} not found in app config.")
            continue

        # Convert boolean values to strings to ensure compatibility with .env files
        config_value_str = str(config_value)

        # First we check if the config exists in the config file
        if current_configs.get(config_name) != config_value_str:

            # Then we check if the config is set this way in the app
            # config (if we reach this stage, it effectively means we
            # are in default values territory)
            if app_config[config_name] != config_value:

                # This function updates the .env file directly
                set_key(config_file_path, config_name, config_value_str)
                print(f"Updated {config_name} in your env file.")