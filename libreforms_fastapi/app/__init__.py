import re, os, json, tempfile, logging, sys, asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional
from markupsafe import escape
from bson import ObjectId

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
from sqlalchemy.orm import sessionmaker, declarative_base
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
from libreforms_fastapi.utils.logging import set_logger

from libreforms_fastapi.utils.config import (
    yield_config,
    validate_and_write_configs,
)

from libreforms_fastapi.utils.sqlalchemy_models import (
    Base,
    User,
    TransactionLog,
    Signing,
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
logger = set_logger(
    environment=config.ENVIRONMENT, 
    log_file_name='uvicorn.log', 
    namespace='uvicorn.error'
)

sqlalchemy_logger = set_logger(
    environment=config.ENVIRONMENT, 
    log_file_name='sqlalchemy.log', 
    namespace='sqlalchemy.engine'
)


async def check_key_rotation(period: int):
    while True:
        await asyncio.sleep(period)

        # Query for signatures with scope 'api_key' that expire in the next hour
        keypairs = signatures.rotate_keys(time_until=1, scope="api_key")

        if len(keypairs) == 0:
            logger.info(f'Ran key rotation - 0 key/s rotated')
            continue
            
        # For each key that has just been rotated, update the user model with the new key
        for tup in keypairs:

            old_key, new_key = tup

            with SessionLocal() as session:
                user = session.query(User).filter_by(api_key=old_key).first()

                if not user:
                    continue

                user.api_key = new_key
                db.session.commit()

                if app.config['SMTP_ENABLED']:

                    subject=f"{config.SITE_NAME} API Key Rotated"
                    content=f"This email serves to notify you that an API key for user {user.username} has just rotated at {config.DOMAIN}. Please note that your past API key will no longer work if you are employing it in applications. Your new key will be active for 365 days. You can see your new key by visiting {config.DOMAIN}/profile."

                    mailer.send_mail(subject=subject, content=content, to_address=user.email)

        logger.info(f'Ran key rotation - {len(keypairs)} key/s rotated')

@app.on_event("startup")
async def start_check_key_rotation():
    task = asyncio.create_task(check_key_rotation(3600))


async def test_logger(period: int):
    while True:
        logger.info('This is a background task heartbeat')
        await asyncio.sleep(period)

@app.on_event("startup")
async def start_test_logger():
    task = asyncio.create_task(test_logger(6000))

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

# Initialize the signing table
signatures = Signatures(config.SQLALCHEMY_DATABASE_URI, byte_len=32, 
    # Pass the rate limiting settings from the app config
    rate_limiting=config.RATE_LIMITS_ENABLED,
    rate_limiting_period=config.RATE_LIMITS_PERIOD, 
    rate_limiting_max_requests=config.RATE_LIMITS_MAX_REQUESTS,
    Base=Base, # Here we pass the base
    Signing=Signing, # And Signing object we've overwritten
)

Base.metadata.create_all(bind=engine)

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

def get_column_length(model, column_name):
    column = getattr(model, column_name, None)
    if column is not None and hasattr(column.type, 'length'):
        return column.type.length
    return None

def write_api_call_to_transaction_log(api_key, endpoint, remote_addr=None, query_params:Optional[str]=None):
    """This function writes an API call to the TransactionLog"""

    if query_params is not None:

        # Get the max length of the query_params column
        max_length = get_column_length(TransactionLog, 'query_params')

        # Super hackish but I want to make sure we don't run into an issue where 
        if len(query_params) >= max_length:
            logger.error(f"Query params for {endpoint} exceeded max length of {max_length} characters")
            # Truncate to avoid unpredictable behavior
            query_params = query_params[:max_length]

    with SessionLocal() as session:
        user = session.query(User).filter_by(api_key=api_key).first()
        if user:
            new_log = TransactionLog(
                user_id=user.id if not user.opt_out else None,
                timestamp=datetime.now(config.TIMEZONE),
                endpoint=endpoint,
                query_params=query_params,
                remote_addr=remote_addr if not user.opt_out else None,
            )
            session.add(new_log)
            try:
                session.commit()
            except Exception as e:
                session.rollback()


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
        key = signatures.write_key(expiration=.5, scope="api_key")
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
async def api_form_create(form_name: str, background_tasks: BackgroundTasks, request: Request, session: SessionLocal = Depends(get_db), key: str = Depends(X_API_KEY), body: Dict = Body(...)):

    if form_name not in form_config:
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Pull this form model from the list of available models
    FormModel = FormModels[form_name]

    # # Here we validate and coerce data into its proper type
    form_data = FormModel.model_validate(body)
    json_data = form_data.model_dump_json()

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()
    
    # Get request details
    if config.COLLECT_USAGE_STATISTICS:
        endpoint = request.url.path
        remote_addr = request.client.host

    # Process the validated form submission as needed
    # document_id = DocumentDatabase.create_document(form_name=form_name, json_data=form_data.model_dump_json())
    document_id = str(ObjectId())
    background_tasks.add_task(
        DocumentDatabase.create_document, 
        form_name=form_name, 
        json_data=json_data, 
        metadata={
            DocumentDatabase.document_id_field: document_id,
            DocumentDatabase.created_by_field: user.username,
            DocumentDatabase.last_editor_field: user.username,
            # DocumentDatabase.ip_address_field: remote_addr,
        },
    )

    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Submitted", 
            content=document_id, 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params=json_data,
        )

    return {
        "message": "Form submission received and validated", 
        "document_id": document_id, 
        "data": json_data,
    }

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
async def api_auth_create(user_request: CreateUserRequest, background_tasks: BackgroundTasks, request: Request, session: SessionLocal = Depends(get_db)):

    if config.DISABLE_NEW_USERS:
        raise HTTPException(status_code=404)

    # Check if user or email already exists
    # See https://stackoverflow.com/a/9270432/13301284 for HTTP Response
    existing_user = session.query(User).filter(User.username.ilike(user_request.username)).first()
    if existing_user:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register user {user_request.username} but user already exists')

        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    existing_email = session.query(User).filter(User.email.ilike(user_request.email)).first()
    if existing_email:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register email {user_request.email} but email is already registered')

        if config.SMTP_ENABLED:

            _subject=f"{config.SITE_NAME} Suspicious Activity"
            _content=f"This email serves to notify you that there was an attempt to register a user with the same email as the account registered to you at {config.DOMAIN}. If this was you, you may safely disregard this email. If it was not you, you should consider contacting your system administrator and changing your password."
            # Eventually, wrap this in an async function, see
            # https://github.com/signebedi/libreforms-fastapi/issues/25
            # mailer.send_mail(subject=_subject, content=_content, to_address=user_request.email)
            background_tasks.add_task(
                mailer.send_mail, 
                subject=_subject, 
                content=_content, 
                to_address=user_request.email,
            )


        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    new_user = User(
        email=user_request.email, 
        username=user_request.username, 
        password=generate_password_hash(user_request.password),
        active=config.REQUIRE_EMAIL_VERIFICATION == False,
        opt_out=user_request.opt_out if config.COLLECT_USAGE_STATISTICS else True,
    ) 

    # Create the users API key with a 365 day expiry
    expiration = 8760
    api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=user_request.email)
    new_user.api_key = api_key

    session.add(new_user)
    session.commit()

    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Registered"

        if config.REQUIRE_EMAIL_VERIFICATION:

            key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=email)
            content=f"This email serves to notify you that the user {user_request.username} has just been registered for this email address at {config.DOMAIN}. Please verify your email by clicking the following link: {config.DOMAIN}/verify/{key}. Please note this link will expire after 48 hours."

        else:
            content=f"This email serves to notify you that the user {user_request.username} has just been registered for this email address at {config.DOMAIN}."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=user_request.email,
        )


    return {
        "status": "success", 
        "api_key": api_key,
        "message": f"Successfully created new user {user_request.username}"
    }

# Change user password / usermod
    # @app.patch("/api/auth/update")
    # async def api_auth_update(user_request: CreateUserRequest, session: SessionLocal = Depends(get_db)):

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
