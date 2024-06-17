""" 
app/utils/config.py: sets the general configs for an app with REST and UI
Note: application-specific logic and configurations SHOULD come from a 
separate source to help preserve the generalizability of this logic.
"""

import os, shutil
from pathlib import Path
from markupsafe import Markup
from typing import (
    List,
)

from dotenv import (
    load_dotenv, 
    dotenv_values, 
    set_key
)

from datetime import timedelta, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic_settings import BaseSettings
from pydantic import (
    validator, 
    ValidationError, 
    constr,
    EmailStr,
)
from pydantic.networks import MongoDsn
from pydantic.functional_validators import field_validator

from libreforms_fastapi.utils.scripts import check_configuration_assumptions

def get_config(env):

    instance_directory = os.path.join(os.getcwd(), 'instance')
        
    # Ensure the instance directory exists
    os.makedirs(instance_directory, exist_ok=True)

    if env == 'production':
        # Reload the prod config here, see
        # https://github.com/signebedi/libreforms-fastapi/issues/182
        env_file_path = os.path.join(instance_directory, "prod.env")
                
        if not os.path.exists(env_file_path):
            with open(env_file_path, 'w') as f: pass

    # Here we return the corresponding model based on the env
    elif env == 'testing':
        env_file_path = ""

    else:
        # Else, just return the development config, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/182
        env_file_path = os.path.join(instance_directory, "dev.env")
                
        if not os.path.exists(env_file_path):
            with open(env_file_path, 'w') as f: pass

    load_dotenv(env_file_path)

    # We employ a pydantic settings class to manage dotenv settings, see 
    # https://fastapi.tiangolo.com/advanced/settings/#create-the-settings-object.
    # class Config(BaseSettings):
    class Config(BaseSettings):
        ENVIRONMENT:str = env
        CONFIG_FILE_PATH:str = env_file_path
        SITE_NAME:str = os.getenv('SITE_NAME', 'libreForms')
        SITE_SOURCE_URL:str = os.getenv('SITE_SOURCE_URL', 'https://github.com/signebedi/libreforms-fastapi')


        HOMEPAGE_MESSAGE:str | Markup = os.getenv('HOMEPAGE_MESSAGE', 'Welcome to `libreforms-fastapi`, an open-source form management application based on the [libreForms API](https://github.com/libreForms/spec) and built using FastAPI.')


        # @field_validator('HOMEPAGE_MESSAGE')
        # def validate_homepage_content(cls, v):
        #     try:
        #         # Attempt to create a Markup object to validate the privacy message
        #         m = Markup(v)
        #     except:
        #         # If there is an issue, raise a ValueError
        #         raise ValueError(f'Issue converting to markup: {v}')
        #     return m

        PRIVACY_MESSAGE:str | Markup = os.getenv('PRIVACY_MESSAGE', '')

        # @field_validator('PRIVACY_MESSAGE')
        # def validate_privacy_message(cls, v):
        #     try:
        #         # Attempt to create a Markup object to validate the privacy message
        #         m = Markup(v)
        #     except:
        #         # If there is an issue, raise a ValueError
        #         raise ValueError(f'Issue converting to markup: {v}')
        #     return m


        DOMAIN:str = os.getenv('DOMAIN', 'http://127.0.0.1:5000')
        DEBUG:bool = os.getenv('DEBUG', 'False') == 'True'
        SECRET_KEY:str = os.getenv('SECRET_KEY', 'supersecret_dev_key')

        TIMEZONE: ZoneInfo | str = os.getenv('TIMEZONE', 'America/New_York')

        @field_validator('TIMEZONE')
        def validate_timezone(cls, v):
            try:
                # Attempt to create a ZoneInfo object to validate the timezone
                tz = ZoneInfo(v)
            except ZoneInfoNotFoundError:
                # If the timezone is not found, raise a ValueError
                raise ValueError(f'Invalid timezone: {v}')
            # Return the original string value, or you could return ZoneInfo(v) to store the object
            return tz

        # APP_STARTUP_TIME: datetime = datetime.now(ZoneInfo(os.getenv('TIMEZONE', 'America/New_York')))

        SQLALCHEMY_DATABASE_URI:str = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{os.path.join(os.getcwd(), "instance", "app.sqlite")}')
        SQLALCHEMY_TRACK_MODIFICATIONS:bool = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'

        USERNAME_REGEX: str = os.getenv('USERNAME_REGEX', r"^\w\w\w\w+$")
        USERNAME_HELPER_TEXT: str = os.getenv('USERNAME_HELPER_TEXT', "Username must be 4-36 alphanumeric characters and underscores")
        PASSWORD_REGEX: str = os.getenv('PASSWORD_REGEX', r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+[\]{};\'\\:"|,.<>/?])[A-Za-z\d!@#$%^&*()_+[\]{};\'\\:"|,.<>/?]{8,}$')
        PASSWORD_HELPER_TEXT: str = os.getenv('PASSWORD_HELPER_TEXT', "Password must be 8+ characters, must include uppercase, lowercase, digit, and special character")

        # Here we allow the application to be run headlessly, but default to an enabled UI,
        # see https://github.com/signebedi/libreforms-fastapi/issues/18.
        UI_ENABLED:bool = os.getenv('UI_ENABLED', 'True') == 'True'


        # This config is used to determine whether to permit edits to the form config in the 
        # web UI. Often, especially in production, admins may want to introduce additional process
        # when making changes to the form config to ensure changes are deliberate and thoughtful. 
        # See https://github.com/signebedi/libreforms-fastapi/issues/206.
        FORM_CONFIG_EDITS_ENABLED:bool = os.getenv('FORM_CONFIG_EDITS_ENABLED', 'True') == 'True'

        # Here we allow admins to decide whether users should be able to see each other's 
        # profile data, see https://github.com/signebedi/libreforms-fastapi/issues/54.
        OTHER_PROFILES_ENABLED:bool = os.getenv('OTHER_PROFILES_ENABLED', 'True') == 'True'

        # Here we determine whether the search bar will show in the UI, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/164.
        SEARCH_BAR_ENABLED:bool = os.getenv('SEARCH_BAR_ENABLED', 'True') == 'True'

        # Here we determine whether the footer will show in the UI, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/188.
        DISABLE_FOOTER:bool = os.getenv('DISABLE_FOOTER', 'False') == 'True'

        # Here we allow admins to enable the "Recent Activity" table on the homepage,
        # see https://github.com/signebedi/libreforms-fastapi/issues/227
        RECENT_ACTIVITY_ENABLED:bool = os.getenv('RECENT_ACTIVITY_ENABLED', 'False') == 'True'

        # Here we specify a path to our JSON form config representation, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/37.
        FORM_CONFIG_PATH:str = os.getenv('FORM_CONFIG_PATH', os.path.join(os.path.join(os.getcwd(), "instance", "form_config.yml")))

        # Here we allow admins to decide whether to enable site documentation 
        DOCS_ENABLED:bool = os.getenv('DOCS_ENABLED', 'False') == 'True'
        DOCS_PATH:str = os.getenv('DOCS_PATH', os.path.join(os.path.join(os.getcwd(), "instance", "docs.md")))

        # Here we allow users to export form data as excel, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/215. 
        # Note that this will require the installation of openpyxl, which 
        # can be done by running `pip install libreforms_fastapi[data]`.
        EXCEL_EXPORT_ENABLED:bool = os.getenv('EXCEL_EXPORT_ENABLED', 'False') == 'True'

        SMTP_ENABLED:bool = os.getenv('SMTP_ENABLED', 'False') == 'True'
        SMTP_MAIL_SERVER:str = os.getenv('SMTP_MAIL_SERVER', "")
        SMTP_PORT:int = int(os.getenv('SMTP_PORT', 25))    
        SMTP_USERNAME:str = os.getenv('SMTP_USERNAME', "")
        SMTP_PASSWORD:str = os.getenv('SMTP_PASSWORD', "")
        SMTP_FROM_ADDRESS:str = os.getenv('SMTP_FROM_ADDRESS', "")

        RATE_LIMITS_ENABLED:bool = os.getenv('RATE_LIMITS_ENABLED', 'False') == 'True'
        # Rate limiting period should be an int corresponding to the number of minutes
        RATE_LIMITS_MAX_REQUESTS: int = int(os.getenv('RATE_LIMITS_MAX_REQUESTS', 15))
        RATE_LIMITS_PERIOD: str | int | timedelta = timedelta(minutes=1)  # First we set a default value

        @field_validator('RATE_LIMITS_PERIOD')
        def set_rate_limits_period(cls, v):
            # Next we dectorate
            minutes = int(os.getenv('RATE_LIMITS_PERIOD', '1'))
            return timedelta(minutes=minutes)


        MAX_LOGIN_ATTEMPTS:int = int(os.getenv('MAX_LOGIN_ATTEMPTS', "0"))
        REQUIRE_EMAIL_VERIFICATION:bool = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'False') == 'True'

        # Permanent session lifetime should be an int corresponding to the number of minutes
        PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=6)  # Again we set a default value

        @field_validator('PERMANENT_SESSION_LIFETIME')
        def set_permanent_session_lifetime(cls, v):
            hours = int(os.getenv('PERMANENT_SESSION_LIFETIME', '6'))
            return timedelta(hours=hours)

        # In development we do not force HTTPS, see
        # https://github.com/signebedi/libreforms-fastapi/issues/183
        FORCE_HTTPS:bool = os.getenv('FORCE_HTTPS', 'False') == 'True'

        # For some environments we need to enable a proxy pass middleware, see
        # https://github.com/signebedi/libreforms-fastapi/issues/248
        ENABLE_PROXY_PASS:bool = os.getenv('ENABLE_PROXY_PASS', 'False') == 'True'

        COLLECT_USAGE_STATISTICS:bool = os.getenv('COLLECT_USAGE_STATISTICS', 'True') == 'True'

        # This config will prevent users from self registering. It's a bit misleadingly named,
        # unfortunately. The crux is that we want admins to be able able to prevent abuse of 
        # unsecured endpoints - of which there are two: create user, and forgot password.
        DISABLE_NEW_USERS:bool = os.getenv('DISABLE_NEW_USERS', 'False') == 'True'

        # See discussion for DISABLE_NEW_USERS above. This allows admins to turn off the
        # "forgot_password routes"
        DISABLE_FORGOT_PASSWORD:bool = os.getenv('DISABLE_FORGOT_PASSWORD', 'False') == 'True'


        # Set help page information
        HELP_PAGE_ENABLED:bool = os.getenv('HELP_PAGE_ENABLED', 'False') == 'True'
        HELP_EMAIL:EmailStr|None = os.getenv('HELP_EMAIL', None)
        # HELP_EMAIL:EmailStr|List[EmailStr] = os.getenv('HELP_EMAIL', "")

        # @validator('HELP_EMAIL', pre=True)
        # def split_str_to_list(cls, v):
        #     if isinstance(v, str) and "," in v:
        #         return v.split(",")
        #     return v


        LIMIT_PASSWORD_REUSE: bool = os.getenv('LIMIT_PASSWORD_REUSE', 'False') == 'True'
        PASSWORD_REUSE_PERIOD: str | int | timedelta = timedelta(days=1)  # First we set a default value

        @field_validator('PASSWORD_REUSE_PERIOD')
        def set_password_reuse_period(cls, v):
            # Next we dectorate
            days = int(os.getenv('PASSWORD_REUSE_PERIOD', '365'))
            return timedelta(days=days)
            

        # Set site cookie configs, see https://github.com/signebedi/gita-api/issues/109
        SESSION_COOKIE_SECURE:bool = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
        SESSION_COOKIE_SAMESITE:str = os.getenv('SESSION_COOKIE_SAMESITE', "None")

        MONGODB_ENABLED:bool = os.getenv('MONGODB_ENABLED:', 'False') == 'True'
        MONGODB_URI: str = "" # Default to empty string

        @field_validator('MONGODB_URI')
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

        # In production we force HTTPS, see
        # https://github.com/signebedi/libreforms-fastapi/issues/183
        FORCE_HTTPS:bool = os.getenv('FORCE_HTTPS', 'True') == 'True'


    class DevelopmentConfig(Config):
        DEBUG:bool = True
        SQLALCHEMY_DATABASE_URI:str = f'sqlite:///{os.path.join(os.getcwd(), "instance", "DEV_app.sqlite")}'

    class TestingConfig(Config):
        TESTING:bool = True
        DOMAIN:str = 'http://127.0.0.1:5000'
        SECRET_KEY:str = 'supersecret_test_key'
        # SQLALCHEMY_DATABASE_URI:str = "sqlite:///:memory:"
        SQLALCHEMY_DATABASE_URI:str = f'sqlite:///{os.path.join(os.getcwd(), "instance", "TEST_app.sqlite")}'
        SQLALCHEMY_TRACK_MODIFICATIONS:bool = False
        
        SMTP_ENABLED:bool = False

        RATE_LIMITS_ENABLED:bool = False
        MAX_LOGIN_ATTEMPTS:int = 0
        REQUIRE_EMAIL_VERIFICATION:bool = False
        COLLECT_USAGE_STATISTICS:bool = False


    if env == 'production':
        return ProductionConfig()

    if env == 'testing':
        return TestingConfig()

    return DevelopmentConfig()



# View functions should pass config changes as kwargs to the function below
def validate_and_write_configs(app_config, **kwargs):

    # First check assumptions
    app_config_copy = app_config.copy()
    for key in kwargs.keys():
        setattr(app_config_copy, key, kwargs[key])

    try:
        assert check_configuration_assumptions(config=app_config_copy)

    except Exception as e:
        raise Exception("Assumptions did not pass")

    config_file_path = app_config.CONFIG_FILE_PATH
    
    # Ensure the .env file exists
    if not os.path.isfile(config_file_path):
        print(f"The file at {config_file_path} does not exist. Creating a new one.")
        with open(config_file_path, 'w'): pass

    config_backup_directory = Path(os.getcwd()) / 'instance' / 'app_config_backups'
    config_backup_directory.mkdir(parents=True, exist_ok=True)

    datetime_format = datetime.now(app_config.TIMEZONE).strftime("%Y%m%d%H%M%S")

    # Separate filename from its directory
    config_file_name = Path(config_file_path).name

    # Construct the backup filename
    backup_file_name = f"{config_file_name}.{datetime_format}"

    # Construct the full backup file path
    backup_file_path = config_backup_directory / backup_file_name

    # print("\n\n\n\n", config_backup_directory, "\n", backup_file_path)
    shutil.copy(config_file_path, backup_file_path)

    print(f"Backup of the current config file created at {backup_file_path}")

    # Load current configurations from .env file
    current_configs = dotenv_values(config_file_path)
    
    for config_name, config_value in kwargs.items():
        if config_name not in app_config.__fields__.keys():
            print(f"{config_name} not found in app config.")
            continue

        # Convert boolean values to strings to ensure compatibility with .env files
        config_value_str = str(config_value)

        # First we check if the config exists in the config file
        if current_configs.get(config_name) != config_value_str:

            # Then we check if the config is set this way in the app
            # config (if we reach this stage, it effectively means we
            # are in default values territory)
            if getattr(app_config, config_name) != config_value:

                # This function updates the .env file directly
                set_key(config_file_path, config_name, config_value_str)
                print(f"Updated {config_name} in your env file.")
