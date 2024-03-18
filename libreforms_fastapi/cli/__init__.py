"""libreForms Click Interface - if you pip install this library, you can run this using `libreformsctl`."""

import re, os, json, tempfile, clickfile
from datetime import datetime, timedelta

from sqlalchemy import (
    create_engine, 
    desc,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy_signing import (
    Signatures,
    RateLimitExceeded, 
    KeyDoesNotExist, 
    KeyExpired,
)

from libreforms_fastapi.utils.smtp import Mailer

from libreforms_fastapi.utils.config import (
    DevelopmentConfig, 
    ProductionConfig, 
    TestingConfig,
    validate_and_write_configs,
)

from libreforms_fastapi.utils.sqlalchemy_models import (
    Base,
    User,
    UsageLog,
)

from libreforms_fastapi.utils.scripts import (
    check_configuration_assumptions,
    generate_password_hash,
    check_password_hash,
)


# Config

# Uvicorn

# Nginx
    # Be sure to handle /ui routes > root

# Useradd

# Usermod

# Id
