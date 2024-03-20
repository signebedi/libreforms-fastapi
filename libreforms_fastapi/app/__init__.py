import re, os, json, tempfile, logging, sys
from datetime import datetime, timedelta
from markupsafe import escape
from typing import Dict, Optional

from fastapi import (
    FastAPI,
    Body,
    Request,
    HTTPException,
    BackgroundTasks,
    Depends,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyHeader


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
    ScopeMismatch,
)

from libreforms_fastapi.__metadata__ import (
    __version__,
    __name__,
    __license__,
    __maintainer__,
    __email__,
    __url__,
)

from libreforms_fastapi.utils.smtp import Mailer

from libreforms_fastapi.utils.config import (
    yield_config,
    validate_and_write_configs,
)

from libreforms_fastapi.utils.sqlalchemy_models import (
    Base,
    User,
    TransactionLog,
)

from libreforms_fastapi.utils.scripts import (
    check_configuration_assumptions,
    generate_password_hash,
    check_password_hash,
)

from libreforms_fastapi.utils.document_database import (
    ManageTinyDB,
    ManageMongoDB,
    CollectionDoesNotExist,
)

from libreforms_fastapi.utils.pydantic_models import (
    example_form_config,
    generate_html_form,
    generate_pydantic_models,
    CreateUserRequest,
)

# Here we set the application config
_env = os.environ.get('ENVIRONMENT', 'development')
config = yield_config(_env)

if config.DEBUG:
    print(config)


# Run our assumptions check
assert check_configuration_assumptions(config=config)

# Built using instructions at https://fastapi.tiangolo.com/tutorial/metadata/,
# see https://github.com/signebedi/libreforms-fastapi/issues/31.
app = FastAPI(
    title=config.SITE_NAME,
    # description=description,
    summary="FastAPI implementation of the libreForms spec",
    version=__version__,
    # terms_of_service="http://example.com/terms/",
    contact={
        "name": __maintainer__,
        "url": __url__,
        "email": __email__,
    },
    license_info={
        "name": __license__,
        "url": "https://github.com/signebedi/libreforms-fastapi/blob/master/LICENSE",
    },
)


# Set up logger, see https://github.com/signebedi/libreforms-fastapi/issues/26,
# based on https://stackoverflow.com/a/77007723/13301284. See also:
# https://github.com/tiangolo/fastapi/issues/1508.

# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# stream_handler = logging.StreamHandler(sys.stdout)
# log_formatter = logging.Formatter("%(asctime)s [%(processName)s: %(process)d] [%(threadName)s: %(thread)d] [%(levelname)s] %(name)s: %(message)s")
# stream_handler.setFormatter(log_formatter)
# logger.addHandler(stream_handler)
logger = logging.getLogger('uvicorn.error')
# logger.info('API is starting up')


# app.mount("/static", StaticFiles(directory="static"), name="static")
# templates = Jinja2Templates(directory="templates")

# Instantiate the Mailer object
mailer = Mailer(
    enabled = config.SMTP_ENABLED,
    mail_server = config.SMTP_MAIL_SERVER,
    port = config.SMTP_PORT,
    username = config.SMTP_USERNAME,
    password = config.SMTP_PASSWORD,
    from_address = config.SMTP_FROM_ADDRESS,
)
if config.SMTP_ENABLED:
    logger.info('SMTP has been initialized')

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

logger.info('Relational database has been initialized')


# Yield the pydantic form model
form_config = example_form_config
FormModels = generate_pydantic_models(form_config)

# Initialize the document database
if config.MONGODB_ENABLED:
    DocumentDatabase = ManageMongoDB(config=form_config, timezone=config.TIMEZONE)
    logger.info('MongoDB has been initialized')
else: 
    DocumentDatabase = ManageTinyDB(config=form_config, timezone=config.TIMEZONE)
    logger.info('TinyDB has been initialized')

# Here we define an API key header for the api view functions.
X_API_KEY = APIKeyHeader(name="X-API-Key")

# See https://stackoverflow.com/a/72829690/13301284 and
# https://fastapi.tiangolo.com/reference/security/?h=apikeyheader
def api_key_auth(x_api_key: str = Depends(X_API_KEY)):
    """ takes the X-API-Key header and validates it"""
    try:
        verify = signatures.verify_key(x_api_key, scope=['api_key'])

    except RateLimitExceeded:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded"
        )

    except KeyDoesNotExist:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    except ScopeMismatch:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    except KeyExpired:
        raise HTTPException(
            status_code=401,
            detail="API key expired"
        )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if config.DEBUG:
    ### This is a dummy route to validate jinja2 templates
    @app.get("/debug/items/{id}", response_class=HTMLResponse, include_in_schema=False)
    async def read_item(request: Request, id: str):
        return templates.TemplateResponse(
            request=request, 
            name="item.html", 
            context={"id": id}
        )

    ### These are dummy routes to validate the sqlalchemy-signing library in development
    @app.get("/debug/create", include_in_schema=False)
    async def create_key():
        key = signatures.write_key()
        return {"key": key}

    @app.get("/debug/get", include_in_schema=False)
    async def get_key_details(key: str):
        key_details = signatures.get_key(key)
        return {"key": key_details}

    @app.get("/debug/verify", include_in_schema=False)
    async def verify_key_details(key: str = Depends(X_API_KEY)):

        try:
            verify = signatures.verify_key(key, scope=[])

        except RateLimitExceeded:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded"
            )

        except KeyDoesNotExist:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )

        except ScopeMismatch:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )

        except KeyExpired:
            raise HTTPException(
                status_code=401,
                detail="API key expired"
            )

        return {"valid": verify}


##########################
### API Routes - Form
##########################

# Create form
@app.post("/api/form/create/{form_name}", dependencies=[Depends(api_key_auth)])
async def api_form_create(form_name: str, key: str = Depends(X_API_KEY), body: Dict = Body(...)):

    if form_name not in form_config:
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    FormModel = FormModels[form_name]

    # # Here we validate and coerce data into its proper type
    form_data = FormModel.parse_obj(body)

    # print(form_data.model_dump_json())

    # Process the validated form submission as needed
    document_id = DocumentDatabase.create_document(form_name=form_name, json_data=form_data.model_dump_json())

    return {"message": "Form submission received and validated", "data": form_data.model_dump_json()}

# Read one form
    # @app.get("/api/form/read_one/{form_name}")
    # async def api_form_read_one():


# Read many forms
    # @app.get("/api/form/read_many/{form_name}")
    # async def api_form_read_many():

# Update form
# # *** Should we use PATCH instead of PUT? In libreForms-flask, we only pass 
# the changed details ... But maybe pydantic can handle  the journaling and 
# metadata. See https://github.com/signebedi/libreforms-fastapi/issues/20.
    # @app.put("/api/form/update/{form_name}") 
    # async def api_form_update():

# Delete form
    # @app.delete("/api/form/delete/{form_name}")
    # async def api_form_delete():

# Approve form
    # @app.patch("/api/form/approve/{form_name}")
    # async def api_form_approve():


##########################
### API Routes - Auth
##########################

# Create user
@app.post("/api/auth/create", include_in_schema=config.DISABLE_NEW_USERS==False)
# async def api_auth_create(username: str, password: str, verify_password: str, email: str, opt_out: Optional[bool]):
async def api_auth_create(user_request: CreateUserRequest, session: SessionLocal = Depends(get_db)):

    if config.DISABLE_NEW_USERS:
        raise HTTPException(status_code=404)

    # user_request = UserBase(username, password, email, opt_out)

    # if not user_request._passwords_match():
    #     # See https://stackoverflow.com/a/1364545/13301284 for HTTP Response    
    #     raise HTTPException(status_code=400, detail=f"Passwords do not match")

    # with SessionLocal() as session:
    # Check if user or email already exists
    # See https://stackoverflow.com/a/9270432/13301284 for HTTP Response
    existing_user = session.query(User).filter(User.username.ilike(user_request.username)).first()
    if existing_user:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register user {user_request.username} but user already exists')
    #     raise HTTPException(status_code=409, detail=f"Username {user_request.username} is already registered")

        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    existing_email = session.query(User).filter(User.email.ilike(user_request.email)).first()
    if existing_email:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register email {user_request.email} but email is already registered')
    #     raise HTTPException(status_code=409, detail=f"Email {user_request.email} is already registered")

        if config.SMTP_ENABLED:

            _subject=f"{config.SITE_NAME} Suspicious Activity"
            _content=f"This email serves to notify you that there was an attempt to register a user with the same username or email as the account registered to you at {config.DOMAIN}. If this was you, you may safely disregard this email. If it was not you, you should consider contacting your system administrator and changing your password."
            # Eventually, wrap this in an async function, see
            # https://github.com/signebedi/libreforms-fastapi/issues/25
            mailer.send_mail(subject=_subject, content=_content, to_address=user_request.email)

        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    new_user = User(
        email=user_request.email, 
        username=user_request.username, 
        password=generate_password_hash(user_request.password),
        active=config.REQUIRE_EMAIL_VERIFICATION == False,
        opt_out=opt_out if config.COLLECT_USAGE_STATISTICS else True,
    ) 

    # Create the users API key. If Celery disabled, never expire keys 
    expiration = 8760
    api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=user_request.email)
    new_user.api_key = api_key

    session.add(new_user)
    session.commit()

    # Email notification
    subject=f"{config.SITE_NAME} User Registered"

    if config.REQUIRE_EMAIL_VERIFICATION:

        key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=email)
        content=f"This email serves to notify you that the user {user_request.username} has just been registered for this email address at {config.DOMAIN}. Please verify your email by clicking the following link: {config.DOMAIN}/verify/{key}. Please note this link will expire after 48 hours."

    else:
        content=f"This email serves to notify you that the user {user_request.username} has just been registered for this email address at {config.DOMAIN}."

    if config.SMTP_ENABLED:
        # Eventually, wrap this in an async function, see
        # https://github.com/signebedi/libreforms-fastapi/issues/25
        mailer.send_mail(subject=subject, content=content, to_address=user_request.email)

    return {"status": "success", "message": f"Successfully created new user {user_request.username}"}

# Change user password / usermod
    # @app.patch("/api/auth/update")
    # async def api_auth_update():

# Rotate user API key
    # @app.patch("/api/auth/rotate_key")
    # async def api_auth_rotate_key():

##########################
### API Routes - Validators
##########################

# Validate form field
    # @app.get("/api/validate/field/{form_name}")
    # async def api_validate_field():


##########################
### API Routes - Admin
##########################

# Get all users
    # > paired with manage users admin UI route

# Add new user
    # > paired with add newadmin UI route


# Get Transaction Statistics
    # Paired with the Transaction Statistics

# Toggle user active status

# Update application config

# Trigger site reload

##########################
### UI Routes - Forms
##########################

# Create form
    # @app.get("/ui/form/create/{form_name}")
    # async def ui_form_create():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


# Read one form
    # @app.get("/ui/form/read_one/{form_name}")
    # async def ui_form_read_one():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


# Read many forms
    # @app.get("/ui/form/read_many/{form_name}")
    # async def ui_form_read_many():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")

# Update form
    # @app.get("/ui/form/update/{form_name}")
    # async def ui_form_update():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")

# Delete form
    # @app.get("/ui/form/delete/{form_name}")
    # async def ui_form_delete():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")

# Approve form
    # @app.get("/ui/form/approve/{form_name}")
    # async def ui_form_approve():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")



##########################
### UI Routes - Auth
##########################

# Create user
    # @app.get("/ui/auth/create")
    # async def ui_auth_create():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")



# Forgot password
    # @app.get("/ui/auth/forgot_password")
    # async def ui_auth_forgot_password():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


# Verify email
    # @app.get("/ui/auth/verify_email")
    # async def ui_auth_verify_email():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


# Login
    # @app.get("/ui/auth/login")
    # async def ui_auth_login():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


##########################
### UI Routes - Admin
##########################

# Admin logic requires us to implement current_user logic, see
# https://github.com/signebedi/libreforms-fastapi/issues/19.
# if current_user.group != "admin":
#     raise HTTPException(status_code=404, detail="This page does not exist")


# Manage users
    # @app.get("/ui/admin/manage_users")
    # async def ui_admin_manage_users():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")

# Add new user

# Transaction Statistics
# *** We would pull this from the TransactionLog. This can also be the basis 
# for a "recent activity" UI route.

# Toggle user active status

# Site Config

# SMTP Config

# Database Config

# Site Reload
