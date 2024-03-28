import re, os, json, tempfile, logging, sys, asyncio, jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Annotated
from markupsafe import escape
from bson import ObjectId

from fastapi import (
    FastAPI,
    Body,
    Request,
    HTTPException,
    BackgroundTasks,
    Depends,
    Query,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)

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
    get_config,
    validate_and_write_configs,
)

from libreforms_fastapi.utils.sqlalchemy_models import (
    Base,
    User,
    TransactionLog,
    Signing,
    Group,
    ApprovalChains,
)

from libreforms_fastapi.utils.scripts import (
    check_configuration_assumptions,
    generate_password_hash,
    check_password_hash,
)

# Import the tools used to generate signatures
from libreforms_fastapi.utils.certificates import (
    verify_record_signature,
    sign_record,
    DigitalSignatureManager,
)
# Import the document database factory function and several
# Exceptions that can help with error handling / determining 
# HTTP response codes.
from libreforms_fastapi.utils.document_database import (
    get_document_database,
    CollectionDoesNotExist,
    DocumentDoesNotExist,
    DocumentIsDeleted,
    InsufficientPermissions,
    DocumentIsNotDeleted,
    SignatureError,
    DocumentAlreadyHasValidSignature,
    NoChangesProvided,
)

from libreforms_fastapi.utils.pydantic_models import (
    get_form_config,
    get_form_names,
    CreateUserRequest,
)

# Here we set the application config using the get_config
# factory pattern defined in libreforms_fastapi.utis.config.
_env = os.environ.get('ENVIRONMENT', 'development')
config = get_config(_env)

if config.DEBUG:
    print(config)

# Run our assumptions checks defined in
# libreforms_fastapi.utis.scripts
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


# Here we instantiate our oauth object, see
# https://github.com/signebedi/libreforms-fastapi/issues/19
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:

        # If the token is expired, raise an HTTP exception here, see
        # https://github.com/signebedi/libreforms-fastapi/issues/77. 
        # This is an effort to adhere to RFC 7519. see 
        # https://pyjwt.readthedocs.io/en/latest/usage.html#registered-claim-names
        payload = jwt.decode(
            token, 
            config.SECRET_KEY, 
            issuer=config.SITE_NAME, 
            audience=f"{config.SITE_NAME}WebUser", 
            algorithms=['HS256']
        )


        with SessionLocal() as session:
            user = session.query(User).filter_by(id=payload.get("id", None)).first()

    except:
        raise HTTPException(
            status_code=401,
            detail="Unable to login at this time"
        )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    if not user.active:
        raise HTTPException(
            status_code=401,
            detail="Unable to login at this time"
        )

    if not user.username == payload['sub']:
        raise HTTPException(
            status_code=401,
            detail="Unable to login at this time"
        )

    return user


# Set up logger, see https://github.com/signebedi/libreforms-fastapi/issues/26,
# again using a factory pattern defined in libreforms_fastapi.utis.logging.
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

app.mount("/static", StaticFiles(directory="libreforms_fastapi/app/static"), name="static")
templates = Jinja2Templates(directory="libreforms_fastapi/app/templates")



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

# Create default group if it does not exist
with SessionLocal() as session:
    # Check if a group with id 1 exists
    default_group = session.query(Group).get(1)

    if not default_group:
        # If not, create and add the new default group
        default_permissions = [
            "example_form:create",
            "example_form:read_own",
            "example_form:read_all",
            "example_form:update_own",
            "example_form:update_all",
            "example_form:delete_own",
            "example_form:delete_all",
            "example_form:sign_own"
        ]
        default_group = Group(id=1, name="default", permissions=default_permissions)
        session.add(default_group)
        session.commit()
        logger.info("Default group created")
    else:
        # print(default_group.get_permissions())
        logger.info("Default group already exists")


# Initialize the document database

doc_db = get_document_database(form_names_callable=get_form_names, timezone=config.TIMEZONE, env=config.ENVIRONMENT, use_mongodb=config.MONGODB_ENABLED, mongodb_uri=config.MONGODB_URI)
logger.info('Document Database has been initialized')

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

        # logger.info(api_key, endpoint, remote_addr, query_params)

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


# if config.DEBUG:
#     ### This is a dummy route to validate jinja2 templates
#     @app.get("/debug/items/{id}", response_class=HTMLResponse, include_in_schema=False)
#     async def read_item(request: Request, id: str):
#         return templates.TemplateResponse(
#             request=request, 
#             name="item.html", 
#             context={"id": id}
#         )

#     ### These are dummy routes to validate the sqlalchemy-signing library in development
#     @app.get("/debug/create", include_in_schema=False)
#     async def create_key():
#         key = signatures.write_key(expiration=.5, scope="api_key")
#         return {"key": key}

#     @app.get("/debug/get", include_in_schema=False)
#     async def get_key_details(key: str):
#         key_details = signatures.get_key(key)
#         return {"key": key_details}

#     @app.get("/debug/verify", include_in_schema=False)
#     async def verify_key_details(key: str = Depends(X_API_KEY)):

#         try:
#             verify = signatures.verify_key(key, scope=[])

#         except RateLimitExceeded:
#             raise HTTPException(
#                 status_code=429,
#                 detail="Rate limit exceeded"
#             )

#         except KeyDoesNotExist:
#             raise HTTPException(
#                 status_code=401,
#                 detail="Invalid API key"
#             )

#         except ScopeMismatch:
#             raise HTTPException(
#                 status_code=401,
#                 detail="Invalid API key"
#             )

#         except KeyExpired:
#             raise HTTPException(
#                 status_code=401,
#                 detail="API key expired"
#             )

#         return {"valid": verify}


##########################
### API Routes - Form
##########################

# Create form
@app.post("/api/form/create/{form_name}", dependencies=[Depends(api_key_auth)])
async def api_form_create(
    form_name: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY), 
    body: Dict = Body(...)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Yield the pydantic form model
    FormModel = get_form_config(form_name=form_name)

    # # Here we validate and coerce data into its proper type
    form_data = FormModel.model_validate(body)
    json_data = form_data.model_dump_json()
    data_dict = form_data.model_dump()

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="create")
        # print("\n\n\nUser has valid permissions\n\n\n")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Set the document_id here, and pass to the doc_db
    document_id = str(ObjectId())

    metadata={
        doc_db.document_id_field: document_id,
        doc_db.created_by_field: user.username,
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    # Process the validated form submission as needed
    # background_tasks.add_task(
        # doc_db.create_document,
    d = doc_db.create_document(
        form_name=form_name, 
        json_data=json_data, 
        # data_dict=data_dict, 
        metadata=metadata,
    )

    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject=f"Form Created", 
            content=f"This email servers to notify you that a form was submitted at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.", 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

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
        "data": d,
    }

# Read one form
@app.get("/api/form/read_one/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_read_one(
    form_name: str, 
    document_id: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit them to see their own forms, which they
    # should do as a matter of bureaucratic best practice, but might sometimes limit.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    document = doc_db.get_one_document(
        form_name=form_name, 
        document_id=document_id, 
        limit_users=limit_query_to
    )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params="{}",
        )

    if not document:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    return {
        "message": "Data successfully retrieved", 
        "document_id": document_id, 
        "data": document["data"],
        "metadata": document["metadata"],
    }


# Read all forms
@app.get("/api/form/read_all/{form_name}", dependencies=[Depends(api_key_auth)])
async def api_form_read_all(
    form_name: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit them to see their own forms, which they
    # should do as a matter of bureaucratic best practice, but might sometimes limit.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    documents = doc_db.get_all_documents(
        form_name=form_name, 
        limit_users=limit_query_to
    )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params="{}",
        )

    if not documents:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    return {
        "message": "Data successfully retrieved", 
        "documents": documents, 
    }

# Update form
# # *** Should we use PATCH instead of PUT? In libreForms-flask, we only pass 
# the changed details ... But maybe pydantic can handle  the journaling and 
# metadata. See https://github.com/signebedi/libreforms-fastapi/issues/20.
@app.patch("/api/form/update/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)]) 
async def api_form_update(
    form_name: str, 
    document_id: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY), 
    body: Dict = Body(...)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Yield the pydantic form model, setting update to True, which will mark
    # all fields as Optional. Nb. Maybe we should pass the full data payload,
    # including unchanged fields. The benefit is simplicity all over the 
    # application, because we can just pull the data, update fields as appropriate,
    # and pass the full payload to the document database to parse and clean up.
    FormModel = get_form_config(form_name=form_name, update=True)

    # # Here we validate and coerce data into its proper type
    form_data = FormModel.model_validate(body)
    json_data = form_data.model_dump_json()
    data_dict = form_data.model_dump()

    # print("\n\n\n", json_data)

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="update_own")
        # print("\n\n\nUser has valid permissions\n\n\n")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="update_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    metadata={
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the validated form submission as needed
        d = doc_db.update_document(
            form_name=form_name, 
            document_id=document_id,
            json_data=json_data,
            # updated_data_dict=data_dict, 
            metadata=metadata,
            limit_users=limit_query_to,
        )

    # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
    # it fails to ensure the user knows their operation was not successful.
    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except DocumentIsDeleted as e:
        raise HTTPException(status_code=410, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    except NoChangesProvided as e:
        raise HTTPException(status_code=200, detail=f"{e}")

    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Updated", 
            content=f"This email servers to notify you that an existing form was updated at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.", 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params=json_data,
        )

    return {
        "message": "Form successfully updated", 
        "document_id": document_id, 
        "data": d,
    }



# Delete form
@app.delete("/api/form/delete/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_delete(
    form_name: str, 
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="delete_own")
        # print("\n\n\nUser has valid permissions\n\n\n")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="delete_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    metadata={
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the request as needed
        success = doc_db.delete_document(
            form_name=form_name, 
            document_id=document_id,
            metadata=metadata,
            limit_users=limit_query_to,
        )

    # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
    # it fails to ensure the user knows their operation was not successful.
    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except DocumentIsDeleted as e:
        raise HTTPException(status_code=410, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")


    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Deleted", 
            content=f"This email servers to notify you that a form was deleted at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.", 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    return {
        "message": "Form successfully deleted", 
        "document_id": document_id, 
    }


@app.patch("/api/form/restore/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_restore(
    form_name: str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="update_own")
        # print("\n\n\nUser has valid permissions\n\n\n")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="update_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    metadata={
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the request as needed
        success = doc_db.restore_document(
            form_name=form_name, 
            document_id=document_id,
            metadata=metadata,
            limit_users=limit_query_to,
        )

    # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
    # it fails to ensure the user knows their operation was not successful.
    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except DocumentIsNotDeleted as e:
        raise HTTPException(status_code=200, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")


    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Restored", 
            content=f"This email servers to notify you that a deleted form was restored at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.", 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    return {
        "message": "Form successfully restored", 
        "document_id": document_id, 
    }



# Search forms
@app.get("/api/form/search/{form_name}")
async def api_form_search(
    form_name: str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
    search_term: str = Query(None, title="Search Term")
):

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    if search_term is None or len(search_term) == 0:
        return {"error": "No search term provided"}

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we are working to unpack permissions across multiple forms.
    user_group_permissions = user.compile_permissions()
    form_names = get_form_names()
    limit_query_to = {}

    for form_name in form_names:
        if "read_own" in user_group_permissions[form_name]:
            if "read_all" in user_group_permissions[form_name]:
                limit_query_to[form_name] = False
            else:
                limit_query_to[form_name] = user.username

    documents = doc_db.fuzzy_search_documents(
        search_term=search_term,
        form_name=form_name,
        limit_users=limit_query_to,
    )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params="{}",
        )

    if not documents or len(documents) == 0:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    return {
        "message": "Data successfully retrieved", 
        "documents": documents, 
    }




# Search ALL forms
@app.get("/api/form/search", dependencies=[Depends(api_key_auth)])
async def api_form_search_all(
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
    search_term: str = Query(None, title="Search Term")
):

    if search_term is None:
        return {"error": "No search term provided"}

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we are working to unpack permissions across multiple forms.
    user_group_permissions = user.compile_permissions()
    form_names = get_form_names()
    limit_query_to = {}

    for form_name in form_names:
        if "read_own" in user_group_permissions[form_name]:
            if "read_all" in user_group_permissions[form_name]:
                limit_query_to[form_name] = False
            else:
                limit_query_to[form_name] = user.username

    print("\n\n\n", limit_query_to)

    documents = doc_db.fuzzy_search_documents(
        search_term=search_term,
        limit_users=limit_query_to,
    )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params="{}",
        )

    if not documents or len(documents) == 0:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    return {
        "message": "Data successfully retrieved", 
        "documents": documents, 
    }

# Sign form
# This is a metadata-only field. It should not impact the data, just the metadata - namely, to afix 
# a digital signature to the form. See https://github.com/signebedi/libreforms-fastapi/issues/59.
@app.patch("/api/form/sign/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_sign(
    form_name:str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):

    # The underlying principle is that the user can only sign their own form. The question is what 
    # part of the application decides: the API, or the document database?

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        # for group in user.groups:
        #     print("\n\n", group.get_permissions()) 

        user.validate_permission(form_name=form_name, required_permission="sign_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")
        
            # "example_form:sign_own"

    metadata={
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the request as needed
        success = doc_db.sign_document(
            form_name=form_name, 
            document_id=document_id,
            metadata=metadata,
            username=user.username,
            public_key=user.public_key,
            private_key_path=user.private_key_ref,
        )

    # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
    # it fails to ensure the user knows their operation was not successful.
    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except DocumentIsDeleted as e:
        raise HTTPException(status_code=410, detail=f"{e}")

    except SignatureError as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    except DocumentAlreadyHasValidSignature as e:
        raise HTTPException(status_code=200, detail=f"{e}")

    except NoChangesProvided as e:
        raise HTTPException(status_code=200, detail=f"{e}")

    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Signed", 
            content=f"This email servers to notify you that a form was signed at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not intend to sign this form, please contact your system administrator.", 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    return {
        "message": "Form successfully signed", 
        "document_id": document_id, 
    }


@app.patch("/api/form/unsign/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_sign(
    form_name:str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):
    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="sign_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")
        
    metadata={
        doc_db.last_editor_field: user.username,
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the request as needed
        success = doc_db.sign_document(
            form_name=form_name, 
            document_id=document_id,
            metadata=metadata,
            username=user.username,
            public_key=user.public_key,
            private_key_path=user.private_key_ref,
            unsign=True,
        )

    # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
    # it fails to ensure the user knows their operation was not successful.
    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except DocumentIsDeleted as e:
        raise HTTPException(status_code=410, detail=f"{e}")

    except SignatureError as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    except NoChangesProvided as e:
        raise HTTPException(status_code=200, detail=f"{e}")

    # Send email
    if config.SMTP_ENABLED:
        background_tasks.add_task(
            mailer.send_mail, 
            subject="Form Unsigned", 
            content=f"This email servers to notify you that a form was unsigned at {config.DOMAIN} by the user registered at this email address. The form's document ID is '{document_id}'. If you believe this was a mistake, or did not intend to sign this form, please contact your system administrator.", 
            to_address=user.email,
        )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    return {
        "message": "Form successfully unsigned", 
        "document_id": document_id, 
    }


# Approve form
# This is a metadata-only field. It should not impact the data, just the metadata - namely, to afix 
# an approval - in the format of a digital signature - to the form. 
    # @app.patch("/api/form/approve/{form_name}/{document_id}")
    # async def api_form_approve():


##########################
### API Routes - Validators
##########################

# Validate form field
    # @app.get("/api/validate/field/{form_name}")
    # async def api_validate_field():

# Validate form signature, see https://github.com/signebedi/libreforms-fastapi/issues/72
@app.get("/api/validate/signature/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_validate_signature(
    form_name:str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request,
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):

    # The underlying principle is that the user can only sign their own form. The question is what 
    # part of the application decides: the API, or the document database?

    if form_name not in get_form_names():
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit them to see their own forms, which they
    # should do as a matter of bureaucratic best practice, but might sometimes limit.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    # Here, if the user is not able to see other user's data, then we denote the constraint.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    document = doc_db.get_one_document(
        form_name=form_name, 
        document_id=document_id, 
        limit_users=limit_query_to
    )

    if not document:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    # Here we get the user information for the user who created the document to validate their signature
    owner = session.query(User).filter_by(username=document['metadata'][doc_db.created_by_field]).first()
    if not owner:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    valid = verify_record_signature(record=document, username=owner.username, env=config.ENVIRONMENT, public_key=owner.public_key, private_key_path=owner.private_key_ref)

    return {
        "valid": valid, 
        "document_id": document_id, 
    }


##########################
### API Routes - Auth
##########################

# Create user
@app.post("/api/auth/create", include_in_schema=config.DISABLE_NEW_USERS==False)
async def api_auth_create(
    user_request: CreateUserRequest, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    session: SessionLocal = Depends(get_db)
):

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

    # Here we add user key pair information, namely, the path to the user private key, and the
    # contents of the public key, see https://github.com/signebedi/libreforms-fastapi/issues/71.
    ds_manager = DigitalSignatureManager(username=user_request.username, env=config.ENVIRONMENT)
    ds_manager.generate_rsa_key_pair()
    new_user.private_key_ref = ds_manager.get_private_key_file()
    new_user.public_key = ds_manager.public_key_bytes

    # Add the user to the default group
    group = session.query(Group).filter_by(name='default').first()
    new_user.groups.append(group)

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

# Get User / id
@app.get("/api/auth/get/{id}", dependencies=[Depends(api_key_auth)])
async def api_auth_get(
    id:int, 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    # We have already validated the API key, so if they have come this far, they have system access. As
    # such, if no user comes back (eh, that might happen if an admin hacks together an API key without a 
    # user account attached to it .. for system purposes) or if there is a user, but they are not a site
    # admin, then we check the OTHER_PROFILES_ENABLED app configuration. If disabled, then raise error; 
    # else, return the user data.
    user = session.query(User).filter_by(api_key=key).first() # This is the user making the request
    target = session.query(User).filter_by(id=id).first() # This is the user whose data has been requested

    # Return a 404 if the target user does not exist
    if not target:
        raise HTTPException(status_code=404)

    # Return a 404 error if the current user lacks permission
    if any([
        not user,
        not user.site_admin
    ]):
        # If the user is not requesting their own profile data and the app
        # config does not allow viewing other user's profiles, return a 404.
        if not config.OTHER_PROFILES_ENABLED and user.id != target.id:
            raise HTTPException(status_code=404)

    profile_data = {
        "id": target.id,
        "username": target.username,
        "email": target.email,
        "groups": [g.name for g in target.groups],
        "active": target.active,
        "created_date": target.created_date.strftime('%Y-%m-%d %H:%M:%S'),
        "last_login": target.last_login.strftime('%Y-%m-%d %H:%M:%S') if target.last_login else 'Never',
    }

    # If the user is requesting their own data, return additional information. 
    if user.id == target.id:
        profile_data["last_password_change"] = target.last_password_change
        profile_data["api_key"] = target.api_key
        profile_data["opt_out"] = target.opt_out
        profile_data["site_admin"] = target.site_admin

    return profile_data


# Update User - change user password / usermod
# @app.patch("/api/auth/update")
# async def api_auth_update(
#     user_request: CreateUserRequest, 
#     background_tasks: BackgroundTasks, 
#     request: Request, 
#     session: SessionLocal = Depends(get_db)
# ):
#     pass

# Rotate user API key
    # @app.patch("/api/auth/rotate_key")
    # async def api_auth_rotate_key():


# Request Password Reset - Forgot Password
    # @app.patch("/api/auth/forgot_password")
    # async def api_auth_forgot_password(user_request: CreateUserRequest, session: SessionLocal = Depends(get_db)):

# Confirm password reset
    # @app.patch("/api/auth/forgot_password/{single_use_token}")
    # async def api_auth_forgot_password_confirm(user_request: CreateUserRequest, session: SessionLocal = Depends(get_db)):

# Login, uses OAUTH and current_user functionality, see
# https://github.com/signebedi/libreforms-fastapi/issues/19
@app.post('/api/auth/login')
async def api_auth_login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=form_data.username.lower()).first()

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not user.active:
        raise HTTPException(status_code=400, detail="User authentication failed")


    # Placeholder, validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=400, detail="User authentication failed")

    if not check_password_hash(user.password, form_data.password):

        # Placeholder: implement failed_password_attempts, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/78
        user.failed_login_attempts += 1

        # If the user has exceeded their failed password attemps, set them
        # as inactive.
        if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS:
            _report_to_user = True
            user.active = False

        session.add(user)
        session.commit()

        raise HTTPException(status_code=400, detail=f"Incorrect username or password{'. Max password failures exceeded. User account locked.' if _report_to_user else ''}")

    # If the password IS correct, clear the user's failed password attempts, see
    # https://github.com/signebedi/libreforms-fastapi/issues/78.
    else:
        user.failed_login_attempts = 0

        session.add(user)
        session.commit()

    user_dict = {
        "id": user.id,
        "sub": user.username,
        "aud": f"{config.SITE_NAME}WebUser",
        "iss": config.SITE_NAME,
        # Set the expiration time based on the timedelta stored in the app config
        "exp": datetime.now(config.TIMEZONE) + config.PERMANENT_SESSION_LIFETIME,
        "email": user.email,
        "active": user.active,
    }


    token = jwt.encode(user_dict, config.SECRET_KEY)

    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user



##########################
### API Routes - Admin
##########################

# Get all users
    # > paired with manage users admin UI route

# Add new user
    # > paired with add newadmin UI route

# Modify user *** including disable user 

# Get Transaction Statistics
    # Paired with the Transaction Statistics admin UI route


# Update application config

# Trigger site reload


# Get all groups

# Add new group

# Update group

# Delete group

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


# Read all forms
    # @app.get("/ui/form/read_all/{form_name}")
    # async def ui_form_read_all():
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

# This is a standard callable that will generate the context
# for the UI routes and Jinja templates.
def build_ui_context():

    kwargs = {}

    kwargs["config"] = config.model_dump()
    kwargs["version"] = __version__

    return kwargs

# Homepage
@app.get("/ui/home", response_class=HTMLResponse)
async def ui_homepage(request: Request):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="about.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# Homepage
@app.get("/ui/privacy", response_class=HTMLResponse)
async def ui_privacy(request: Request):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="privacy.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

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


# View profile

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

# Edit form config

# Manage groups

# Manage approval chains