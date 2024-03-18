import re, os, json, tempfile
from datetime import datetime, timedelta
from markupsafe import escape

from fastapi import (
    FastAPI, 
    Request,
    HTTPException,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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

app = FastAPI()

# app.mount("/static", StaticFiles(directory="static"), name="static")
# templates = Jinja2Templates(directory="templates")

# Here we set the application config
with os.environ.get('ENVIRONMENT', 'development') as env:
    if env == 'production':
        config = ProductionConfig()
    elif env == 'testing':
        config = TestingConfig()
    else:
        config = DevelopmentConfig()

if config.DEBUG:
    print(config)


# Run our assumptions check
assert check_configuration_assumptions(config=config)


# Instantiate the Mailer object
mailer = Mailer(
    enabled = config.SMTP_ENABLED,
    mail_server = config.SMTP_MAIL_SERVER,
    port = config.SMTP_PORT,
    username = config.SMTP_USERNAME,
    password = config.SMTP_PASSWORD,
    from_address = config.SMTP_FROM_ADDRESS,
)

# Create the database engine, see
# https://fastapi.tiangolo.com/tutorial/sql-databases/#create-the-sqlalchemy-parts
engine = create_engine(
    config.SQLALCHEMY_DATABASE_URI,
    connect_args={"check_same_thread": False},
    # The following prevents caching from breaking our rate limitings system, 
    # see https://stackoverflow.com/a/18225372/13301284 
    isolation_level="READ UNCOMMITTED", 
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


# Initialize the signing table
signatures = Signatures(config.SQLALCHEMY_DATABASE_URI, byte_len=32, 
    # Pass the rate limiting settings from the app config
    rate_limiting=config.RATE_LIMITS_ENABLED,
    rate_limiting_period=config.RATE_LIMITS_PERIOD, 
    rate_limiting_max_requests=config.RATE_LIMITS_MAX_REQUESTS,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


### This is a dummy route to validate jinja2 templates
@app.get("/items/{id}", response_class=HTMLResponse)
async def read_item(request: Request, id: str):
    return templates.TemplateResponse(
        request=request, name="item.html", context={"id": id}
    )

### These are dummy routes to validate the sqlalchemy-signing library in development
@app.get("/create")
async def create_key():
    key = signatures.write_key()
    return {"key": key}

@app.get("/get")
async def get_key_details(key: str):
    key_details = signatures.get_key(key)
    return {"key": key_details}

@app.get("/verify")
async def verify_key_details(key: str):

    try:
        verify = signatures.verify_key(key, scope=[])

    except RateLimitExceeded:
        return {'error': 'Rate limit exceeded'}, 429

    except KeyDoesNotExist:
        return {'error': 'Invalid API key'}, 401

    except KeyExpired:
        return {'error': 'API key expired'}, 401

    return {"valid": verify}


##########################
### API Routes - Form
##########################

# Create form

# Read one form

# Read many forms

# Update form

# Delete form

# Approve form


##########################
### API Routes - Auth
##########################

# Create user

# Change user password

# Rotate user API key

##########################
### API Routes - Validators
##########################

# Validate form field

##########################
### UI Routes - Forms
##########################

# Create form
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")

# Read one form
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Read many forms
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Update form
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Delete form
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Approve form
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


##########################
### UI Routes - Auth
##########################

# Create user
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Forgot password
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Verify email
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


# Login
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


##########################
### UI Routes - Admin
##########################
    # if not config.UI_ENABLED:
    #     raise HTTPException(status_code=404, detail="This page does not exist")


    # This logic requires us to implement current_user logic, see
    # https://github.com/signebedi/libreforms-fastapi/issues/19.
    # if current_user.group != "admin":
    #     raise HTTPException(status_code=404, detail="This page does not exist")
