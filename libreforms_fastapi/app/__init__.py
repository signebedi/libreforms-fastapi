import re, os, json, tempfile, logging, sys, asyncio, jwt, difflib, importlib, platform
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Annotated
from markupsafe import escape
from bson import ObjectId
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


from pydantic import ValidationError, EmailStr
from fastapi import (
    FastAPI,
    Body,
    Request,
    Response,
    HTTPException,
    BackgroundTasks,
    Depends,
    Query,
    Form,
)
from fastapi.responses import (
    HTMLResponse, 
    FileResponse,
    JSONResponse, 
    RedirectResponse
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from fastapi.exceptions import RequestValidationError
from starlette.middleware.authentication import (
    AuthenticationMiddleware,
)
from starlette.authentication import (
    AuthCredentials, 
    AuthenticationBackend, 
    AuthenticationError, 
    # SimpleUser,
    BaseUser,
    UnauthenticatedUser,
    requires,
)
from starlette.requests import Request
from http.cookies import SimpleCookie

from sqlalchemy_signing import (
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
    get_sqlalchemy_models,
    test_relational_database_connection,
)

from libreforms_fastapi.utils.scripts import (
    check_configuration_assumptions,
    generate_password_hash,
    check_password_hash,
    percentage_alphanumeric_generate_password,
    prettify_time_diff,
)

# Import the tools used to generate signatures
from libreforms_fastapi.utils.certificates import (
    verify_record_signature,
    DigitalSignatureManager,
    RuntimeKeypair,
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
    HelpRequest,
    DocsEditRequest,
    GroupModel,
    RelationshipTypeModel,
    UserRelationshipModel,
    FormConfigUpdateRequest,
    SiteConfig,
    get_user_model,
    get_form_model,
    get_form_names,
    get_form_html,
    load_form_config,
    get_form_config_yaml,
    write_form_config_yaml,
    get_form_backups,
)

from libreforms_fastapi.utils.docs import (
    get_docs,
    write_docs,
    render_markdown_content,
)

from libreforms_fastapi.utils.custom_tinydb import CustomEncoder

# Here we set the application config using the get_config
# factory pattern defined in libreforms_fastapi.utis.config.
_env = os.environ.get('ENVIRONMENT', 'development')


class ConfigFileChangeHandler(FileSystemEventHandler):
    """
    I am adding this class to help manage caching for the application configuration, 
    which otherwise has a tendency to open too many file handles and run into a
    "too many open files" error that brings the site down, see 
    https://github.com/signebedi/libreforms-fastapi/issues/226.
    """

    def __init__(self, cache_clear_func, logger=None):
        self.cache_clear_func = cache_clear_func

        self.logger = logger


    def on_modified(self, event):
        if event.src_path.endswith(".env"):

            if self.logger:
                logger.info(f"Detected change in {event.src_path}, clearing config cache.")
            self.cache_clear_func()


@contextmanager
def get_config_context():
    original_environment = dict(os.environ)  # Make a copy of the current environment
    os.environ.clear()  # Clear all modifications

    # Clear the config cache, see https://github.com/signebedi/libreforms-fastapi/issues/226
    # get_config.cache_clear()
    get_config_depends.cache_clear()

    conf = get_config(_env)

    try:
        yield conf
    finally:
        os.environ.clear()  # Clear all modifications
        os.environ.update(original_environment)  # Restore original environment

@lru_cache()
def get_config_depends():
    os.environ.clear()
    return get_config(_env)


def clear_config_cache():
    os.environ.clear()
    get_config_depends.cache_clear()


def get_mailer():

    # with get_config_context() as config:

    config = get_config_depends()

    # Instantiate the Mailer object
    mailer = Mailer(
        enabled = config.SMTP_ENABLED,
        mail_server = config.SMTP_MAIL_SERVER,
        port = config.SMTP_PORT,
        username = config.SMTP_USERNAME,
        password = config.SMTP_PASSWORD,
        from_address = config.SMTP_FROM_ADDRESS,
    )

    return mailer


def get_doc_db():

    # with get_config_context() as config:

    config = get_config_depends()

    # Initialize the document database
    doc_db = get_document_database(
        form_names_callable=get_form_names,
        form_config_path=config.FORM_CONFIG_PATH,
        timezone=config.TIMEZONE, 
        env=config.ENVIRONMENT, 
        use_logger=False, # https://github.com/signebedi/libreforms-fastapi/issues/226
        # logger=document_database_logger,
        use_mongodb=config.MONGODB_ENABLED, 
        mongodb_uri=config.MONGODB_URI,
        use_excel=config.EXCEL_EXPORT_ENABLED,
    )

    return doc_db


# This is a remarkably ugly way to approach this, but necessary for the time being 
# to complete the requirements in https://github.com/signebedi/libreforms-fastapi/issues/5.
# In the long-run, we will encapsulate the majority of the components instantiated within the
# following `with` statement and add them as dependencies to each fastapi route.
with get_config_context() as config:

    if config.DEBUG:
        print(config.model_dump())

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
    # Here we read / generate an RSA keypair for this environment, see
    # https://github.com/signebedi/libreforms-fastapi/issues/79
    site_key_pair = RuntimeKeypair(env=config.ENVIRONMENT)


    # Here we instantiate the user model, which we are using a factory
    # function for to avoid needing to import the config to pydantic...
    CreateUserRequest = get_user_model(
        username_regex=config.USERNAME_REGEX,
        username_helper_text=config.USERNAME_HELPER_TEXT,
        password_regex=config.PASSWORD_REGEX,
        password_helper_text=config.PASSWORD_HELPER_TEXT,
    )

    AdminCreateUserRequest = get_user_model(
        username_regex=config.USERNAME_REGEX,
        username_helper_text=config.USERNAME_HELPER_TEXT,
        password_regex=config.PASSWORD_REGEX,
        password_helper_text=config.PASSWORD_HELPER_TEXT,
        admin=True,
    )

    PasswordChangeUserModel = get_user_model(
        username_regex=config.USERNAME_REGEX,
        username_helper_text=config.USERNAME_HELPER_TEXT,
        password_regex=config.PASSWORD_REGEX,
        password_helper_text=config.PASSWORD_HELPER_TEXT,
        password_change=True,
    )

    # This model is used to reset passwords when forgotten, see
    # https://github.com/signebedi/libreforms-fastapi/issues/56.
    ForgotPasswordUserModel = get_user_model(
        username_regex=config.USERNAME_REGEX,
        username_helper_text=config.USERNAME_HELPER_TEXT,
        password_regex=config.PASSWORD_REGEX,
        password_helper_text=config.PASSWORD_HELPER_TEXT,
        forgot_password=True,
    )


    class LibreFormsUser(BaseUser):
        def __init__(
            self, 
            username: str,
            id: int, 
            email: str,
            groups: list[str], 
            api_key: str,
            site_admin:bool,
            permissions: dict,
        ) -> None:
        
            self.username = username
            self.id = id
            self.email = email
            self.groups = groups
            self.api_key = api_key
            self.site_admin = site_admin
            self.permissions = permissions

        @property
        def is_authenticated(self) -> bool:
            return True

        @property
        def display_name(self) -> str:
            return self.username

        def __repr__(self) -> str:
            return f"LibreFormsUser(username={self.username}, id={self.id}, email={self.email}, groups={self.groups}, " \
                "api_key={self.api_key}, site_admin={self.site_admin}, permissions={self.permissions}"


    # Authentication Backend Class, see https://www.starlette.io/authentication,
    # https://github.com/tiangolo/fastapi/issues/3043#issuecomment-914316010, and
    # https://github.com/signebedi/libreforms-fastapi/issues/19. Is this redundant
    # with get_current_user?
    class BearerTokenAuthBackend(AuthenticationBackend):
        """
        This is a custom auth backend class that will allow you to authenticate your request and return auth and user as
        a tuple
        """
        async def authenticate(self, request):
            # This function is inherited from the base class and called by some other class
            if "cookie" not in request.headers:

                # print("\n\n\n\n,", request.headers)
                return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()

            cookie = SimpleCookie()
            cookie.load(request.headers["cookie"])

            auth = cookie['access_token'].value if 'access_token' in cookie else None

            try:
                scheme, token = auth.split()

                # print("\n\n\n", scheme)
                if scheme.strip().lower() != 'bearer':
                    return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()

                payload = jwt.decode(
                    token, 
                    site_key_pair.get_public_key(), 
                    issuer=config.SITE_NAME, 
                    audience=f"{config.SITE_NAME}WebUser", 
                    algorithms=['RS256']
                )

                with SessionLocal() as session:
                    user = session.query(User).filter_by(id=payload.get("id", None)).first()
                    _groups = [g.name for g in user.groups]

            except:
                return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()

            # If the user validation check fails or they don't exist, set them as unauthenticated
            if any ([not user, not user.active, not user.username == payload['sub']]):
                return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()

            user_to_return = LibreFormsUser(
                username=user.username,
                id=user.id,
                email=user.email,
                groups=_groups,
                api_key=user.api_key,
                site_admin=user.site_admin,
                permissions=user.compile_permissions(),
            )

            # print("\n\n\n", user_to_return)

            if user.site_admin:
                return AuthCredentials(["authenticated", "admin"]), user_to_return

            return AuthCredentials(["authenticated"]), user_to_return

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

    # document_database_logger = set_logger(
    #                 environment=config.ENVIRONMENT, 
    #                 log_file_name="document_db.log", 
    #                 namespace="document_db.log",
    # )

    def start_config_watcher():
        path_to_watch = config.CONFIG_FILE_PATH
        event_handler = ConfigFileChangeHandler(clear_config_cache, logger=logger)
        observer = Observer()
        observer.schedule(event_handler, path=path_to_watch, recursive=True)
        observer.start()
        return observer

    @app.on_event("startup")
    async def startup_event():
        observer = start_config_watcher()

        # Keep the observer in the app state
        app.state.config_observer = observer

    @app.on_event("shutdown")
    async def shutdown_event():
        app.state.config_observer.stop()
        app.state.config_observer.join()


    # Bug fix: https://github.com/signebedi/libreforms-fastapi/issues/113
    import importlib.resources as importlib_resources 

    with importlib_resources.path("libreforms_fastapi.app", "static") as static_dir:
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    with importlib_resources.path("libreforms_fastapi.app", "templates") as templates_dir:
        templates = Jinja2Templates(directory=str(templates_dir))
    
    app.add_middleware(AuthenticationMiddleware, backend=BearerTokenAuthBackend())


    # Added based on https://github.com/signebedi/libreforms-fastapi/issues/248
    if config.ENABLE_PROXY_PASS:
        from libreforms_fastapi.utils.middleware import ProxiedHeadersMiddleware
        app.add_middleware(ProxiedHeadersMiddleware)


    # Add obfuscating validation error handlers in production
    if not config.DEBUG:
        # Custom exception handler
        def validation_exception_handler(request: Request, exc: RequestValidationError):
            # For simplicity, we are returning a generic error message
            return JSONResponse(
                status_code=422,
                content={"detail": "Data validation error."},
            )

        # Override the default request validation error handler with your custom handler
        app.add_exception_handler(RequestValidationError, validation_exception_handler)

    # These are bool parameters used at runtime to determine to report an API route in
    # the docs. This is unfortunately fixed, so changes to these parameters will require
    # an app restart.
    schema_params = {
        "DISABLE_NEW_USERS": config.DISABLE_NEW_USERS,
        "DISABLE_FORGOT_PASSWORD": config.DISABLE_FORGOT_PASSWORD,
        "HELP_PAGE_ENABLED": config.HELP_PAGE_ENABLED,
        "DOCS_ENABLED": config.DOCS_ENABLED,
    }

    # Here we build our relational database model using a sqlalchemy factory, 
    # see https://github.com/signebedi/libreforms-fastapi/issues/136.
    models, SessionLocal, signatures, engine = get_sqlalchemy_models(
        sqlalchemy_database_uri = config.SQLALCHEMY_DATABASE_URI,
        set_timezone = config.TIMEZONE,
        create_all = True,
        rate_limiting=config.RATE_LIMITS_ENABLED,
        rate_limiting_period=config.RATE_LIMITS_PERIOD,
        rate_limiting_max_requests=config.RATE_LIMITS_MAX_REQUESTS,
    )


    User = models['User']
    PasswordReuse = models['PasswordReuse']
    Group = models['Group']
    TransactionLog = models['TransactionLog']
    SignatureRoles = models['SignatureRoles']
    Signing = models['Signing']

    # Adding user relationship models below, see
    # https://github.com/signebedi/libreforms-fastapi/issues/173
    RelationshipType = models['RelationshipType']
    UserRelationship = models['UserRelationship']

    logger.info('Relational database has been initialized')


    # Very temporary! Coerce usernames to lowercase at startup, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/239
    with SessionLocal() as session:
        # Fetch all users
        all_users = session.query(User).all()

        for user in all_users:
            # Coerce username and email to lowercase
            user.username = user.username.lower()
            user.email = user.email.lower()

        # Commit the changes to the database
        session.commit()


    # Create default group if it does not exist
    with SessionLocal() as session:
        # Check if a group with id 1 exists
        _default_group = session.query(Group).get(1)

        if not _default_group:
            # If not, create and add the new default group
            default_permissions = [
                "example_form:create",
                "example_form:read_own",
                "example_form:read_all",
                "example_form:update_own",
                "example_form:update_all",
                "example_form:delete_own",
                "example_form:delete_all",
                # "example_form:sign_own"
            ]
            _default_group = Group(id=1, name="default", permissions=default_permissions)
            session.add(_default_group)
            session.commit()
            logger.info("Default group created")
        else:
            # print(default_group.get_permissions())
            logger.info("Default group already exists")

        # Check if a signature role with id 1 exists
        _default_signature_role = session.query(SignatureRoles).get(1)

        if not _default_signature_role:
            # If not, create and add the new signature for the example_form
            _default_signature_role = SignatureRoles(
                id=1, 
                role_name="default signature role", 
                role_method="signature",
                form_name="example_form"
            )
            session.add(_default_signature_role)
            session.commit()
            logger.info("Default signature role created")
        else:
            logger.info("Default signature role already exists")



# Here we define an API key header for the api view functions.
X_API_KEY = APIKeyHeader(name="X-API-Key")

# See https://stackoverflow.com/a/72829690/13301284 and
# https://fastapi.tiangolo.com/reference/security/?h=apikeyheader
def api_key_auth(x_api_key: str = Depends(X_API_KEY)):
    """ takes the X-API-Key header and validates it"""

    # Do we want to have account locking also disable key use, or just limit
    # access to the UI, see https://github.com/signebedi/libreforms-fastapi/issues/231.

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

def write_api_call_to_transaction_log(
    api_key, 
    endpoint, 
    remote_addr=None, 
    query_params:Optional[dict]=None,
    # Adding option below per https://github.com/signebedi/libreforms-fastapi/issues/152
    send_mail_on_failure:bool=config.HELP_PAGE_ENABLED, 
    config=get_config(_env),
    mailer=get_mailer(),
):
    """This function writes an API call to the TransactionLog"""

    if not query_params:
        query_params={}

    with SessionLocal() as session:

        current_time = datetime.now(config.TIMEZONE)
        user = session.query(User).filter_by(api_key=api_key).first()
        if user:

            encoded_query_params = json.dumps(query_params, cls=CustomEncoder)

            new_log = TransactionLog(
                user_id=user.id if not user.opt_out else None,
                timestamp=current_time,
                endpoint=endpoint,
                query_params=encoded_query_params,
                remote_addr=remote_addr if not user.opt_out else None,
            )
            session.add(new_log)
            try:
                session.commit()
            except Exception as e:
                session.rollback()

                if send_mail_on_failure:
                    mailer.send_mail( 
                        subject=f"Transaction Log Error", 
                        content=f"You are receiving this message because you are the designated help email for {config.SITE_NAME}. This message is to notify you that there was an error when writing the following transaction to the transaction log for {config.SITE_NAME}:\n\n***\n\nUser: {user.username if not user.opt_out else 'N/A'}\nTimestamp: {current_time}\nEndpoint: {endpoint}\nQuery Params: {query_params if query_params else 'N/A'}\nRemote Address: {remote_addr if not user.opt_out else 'N/A'}", 
                        to_address=config.HELP_EMAIL,
                    )

async def check_key_rotation(
    period: int, 
    config=get_config(_env),
    mailer=get_mailer(),
):
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

                if config.SMTP_ENABLED:

                    subject=f"{config.SITE_NAME} API Key Rotated"
                    content=f"This email serves to notify you that an API key for user {user.username} has just rotated at {config.DOMAIN}. Please note that your past API key will no longer work if you are employing it in applications. Your new key will be active for 365 days. You can see your new key by visiting {config.DOMAIN}/profile."

                    mailer.send_mail(subject=subject, content=content, to_address=user.email)

        logger.info(f'Ran key rotation - {len(keypairs)} key/s rotated')

@app.on_event("startup")
async def start_check_key_rotation():
    task = asyncio.create_task(check_key_rotation(3600))

if config.DEBUG:

    # These routes help debug the auth backend

    @app.get("/test/auth", response_class=HTMLResponse, include_in_schema=False)
    @requires(['authenticated'], redirect="ui_auth_login")
    async def test_auth_scope(request: Request):
        return JSONResponse({"a": "blargh"})

    @app.get("/test/admin", response_class=HTMLResponse, include_in_schema=False)
    @requires(['authenticated', 'admin'], status_code=404)
    async def test_admin_scope(request: Request):
        return JSONResponse({"a": "blargh"})

##########################
### API Routes - Form
##########################


# Create form
@app.post("/api/form/create/{form_name}", dependencies=[Depends(api_key_auth)])
async def api_form_create(
    form_name: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY), 
    body: Dict = Body(...)
):
    """
    Creates and submits a form with given data. The form name is specified in the URL,
    and the data for the form should be provided in the request body. It checks for the
    form's existence, validates user permissions, writes it to db, and logs the submission.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Yield the pydantic form model
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # Here we validate and coerce data into its proper type
    # print("\n\n\n", body)
    try: 
        form_data = FormModel.model_validate(body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=f"There was an error with one of your fields: {e}")

    # Here we pull metadata on how to handle fields that link to
    # users and other forms.
    user_fields, form_fields = form_data.get_additional_metadata()


    json_data = form_data.model_dump_json()
    # print("\n\n\n", json_data)
    data_dict = form_data.model_dump()
    # print("\n\n\n", data_dict)

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
        doc_db.linked_to_user_field: user_fields, 
        doc_db.linked_to_form_field: form_fields,
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
            query_params=data_dict,
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Retrieves a specific form document by its name and document ID, provided in the URL.
    It checks for the form's existence, validates user permissions, fetches the document 
    from the database, and logs the access.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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
            query_params={},
        )

    if not document:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    return {
        "message": "Data successfully retrieved", 
        "document_id": document_id, 
        "data": document["data"],
        "metadata": document["metadata"],
    }

#

@app.get("/api/form/read_history/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_read_history(
    form_name: str, 
    document_id: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Retrieves the history of a specific form document by its name and document ID provided in the URL.
    It checks for the form's existence, validates user permissions, fetches the document history 
    from the database, and logs the access.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    user = session.query(User).filter_by(api_key=key).first()
    
    try:
        user.validate_permission(form_name=form_name, required_permission="read_own")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"{e}")

    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:
        limit_query_to = user.username

    history = doc_db.unpack_document_journal(
        document_id=document_id, 
        form_name=form_name
    )

    if not history:
        raise HTTPException(status_code=404, detail="No history found for the requested document")

    # Log the API call
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
        "message": "History successfully retrieved", 
        "document_id": document_id, 
        "history": history,
    }



# Here we define our available export formats
available_formats = ['json']

# export form
@app.get("/api/form/export/{form_name}/{document_id}", response_class=FileResponse, dependencies=[Depends(api_key_auth)])
async def api_form_export(
    form_name: str, 
    document_id: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    format: str = Query(default="json", enum=available_formats),
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Retrieves a specific form document by its name and document ID, provided in the URL.
    It checks for the form's existence, validates user permissions, fetches the document 
    from the database, and returns the form as a file after logging the access.
    """

    if not format in available_formats:
        raise HTTPException(status_code=404, detail=f"Invalid format. Must choose from {str(available_formats)}")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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

    document_path = doc_db.get_one_document(
        form_name=form_name, 
        document_id=document_id, 
        limit_users=limit_query_to,
        to_file=True,
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


    if not document_path:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    file_name = Path(document_path).name

    return FileResponse(path=document_path, filename=file_name, media_type='application/octet-stream')




# Read all forms
@app.get("/api/form/read_all/{form_name}", dependencies=[Depends(api_key_auth)])
async def api_form_read_all(
    form_name: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),
    flatten: bool = False,
    escape: bool = False,
    simple_response: bool = False,
    exclude_journal: bool = False,
    stringify_output: bool = False,
    sort_by_last_edited: bool = False,
    set_length: int = 0,
    newest_first: bool = False,
    return_when_empty: bool = False,
):
    """
    Retrieves all documents of a specified form type, identified by the form name in the URL.
    It verifies the form's existence, checks user permissions, retrieves documents from the 
    database, and logs the query. You can pass flatten=true to return data in a flat format.
    You can pass escape=true to escape output. You can pass simple_response=true to receive 
    just the data as a response. You can pass exclude_journal=true to exclude the document
    journal, which can sometimes complicate data handling because of its nested nature. You
    can pass stringify_output=true if you would like output types coerced into string format.
    You can pass sort_by_last_edited=True if you want to sort by most recent changes. You can
    pass set_length=some_int if you would like to limit the response to a certain number of
    documents. You can pass newest_first=True if you want the newest results at the top of
    the results. This applies to the created_at field, you can pair this option with the
    sort_by_last_edited=True param to get the most recently modified forms at the top. If
    you want the endpoint to return empty lists instead of raising an error, then pass
    return_when_empty=true.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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
        limit_users=limit_query_to,
        escape_output=escape,
        collapse_data=flatten,
        exclude_journal=exclude_journal,
        stringify_output=stringify_output,
        sort_by_last_edited=sort_by_last_edited,
        newest_first=newest_first,
    )

    # Here we limit the length of the response based on the set_length parameter, see
    # https://github.com/signebedi/libreforms-fastapi/issues/266. While TinyDB does
    # not seem to provide any efficiency benefits from limiting queryies (the all() 
    # method seems to be the preferred approach for getting more than one document),
    # other document databases may provide such efficiency benefits, and it may make
    # sense to build this into the doc_db.get_all_documents params. 
    # if isinstance(set_length, int):
    if set_length > 0:
        documents = documents[:set_length]

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

    if not documents and not return_when_empty:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")
    elif not documents and return_when_empty:
        documents = []

    if simple_response:
        return documents

    return {
        "message": "Data successfully retrieved", 
        "documents": documents, 
    }


@app.get("/api/form/export_excel/{form_name}", response_class=FileResponse, dependencies=[Depends(api_key_auth)])
async def api_form_export_excel(
    form_name: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Retrieves all documents of a specified form type, identified by the form name in the URL.
    It verifies the form's existence, checks user permissions, retrieves documents from the 
    database, and returns the form as an excel file before logging the query.
    """

    if not config.EXCEL_EXPORT_ENABLED:
        raise HTTPException(status_code=404)

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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


    document_path = doc_db.get_all_documents_as_excel(
        form_name, 
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
            query_params={},
        )

    if not document_path:
        raise HTTPException(status_code=404, detail=f"Requested data could not be found")

    file_name = Path(document_path).name

    return FileResponse(path=document_path, filename=file_name, media_type='application/octet-stream')



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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),  
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY), 
    body: Dict = Body(...)
):

    """
    Updates a specified document within a form. It checks the document's existence, validates user permissions, 
    updates the document with provided changes, and logs the operation.
    """


    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Yield the pydantic form model, setting update to True, which will mark
    # all fields as Optional. Nb. Maybe we should pass the full data payload,
    # including unchanged fields. The benefit is simplicity all over the 
    # application, because we can just pull the data, update fields as appropriate,
    # and pass the full payload to the document database to parse and clean up.
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH, 
        update=True,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )
    
    # Here we validate and coerce data into its proper type
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Deletes a specific document from a form based on the form name and document ID in the URL.
    Validates the existence of the document, user permissions, and logs the deletion.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        user.validate_permission(form_name=form_name, required_permission="delete_own")
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Restores a previously deleted document in a form, identified by form name and document ID in the URL.
    Checks document existence, validates user permissions, and logs the restoration.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
    search_term: str = Query(None, title="Search Term")
):
    """
    Performs a search for documents within a specific form based on a 
    search term. Validates form existence and user permissions.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    if search_term is None or len(search_term) < 1:
        return HTTPException(status_code=420, detail="No search term provided")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we are working to unpack permissions across multiple forms.
    user_group_permissions = user.compile_permissions()
    form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)
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
            query_params={},
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
    search_term: str = Query(None, title="Search Term")
):

    """
    Performs a global search across all forms using a provided search term. 
    Validates user permissions for each form.
    """


    if search_term is None or len(search_term) < 1:
        return HTTPException(status_code=420, detail="No search term provided")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we are working to unpack permissions across multiple forms.
    user_group_permissions = user.compile_permissions()
    form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)
    limit_query_to = {}

    for form_name in form_names:
        if "read_own" in user_group_permissions[form_name]:
            if "read_all" in user_group_permissions[form_name]:
                limit_query_to[form_name] = False
            else:
                limit_query_to[form_name] = user.username

    # print("\n\n\n", limit_query_to)

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
            query_params={},
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):
    """
    Digitally signs a specific document in a form, verifying user permissions 
    and form existence. Logs the signing action.
    """

    # The underlying principle is that the user can only sign their own form. The question is what 
    # part of the application decides: the API, or the document database?

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we validate the user groups permit this level of access to the form
    try:
        # for group in user.groups:
        #     print("\n\n", group.get_permissions()) 

        # user.validate_permission(form_name=form_name, required_permission="sign_own")
        assert (True) # Placeholder for SignatureRoles validation

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
            role_id=1,
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
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):
    """
    Removes a digital signature from a specific document, subject to user permissions 
    and form validation. Logs the unsigning action.
    """


    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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
@app.get("/api/validate/signatures/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_validate_signatures(
    form_name:str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
):

    """
    Validates the digital signatures of a document, confirming authenticity and integrity. 
    Logs the validation attempt.
    """


    # The underlying principle is that the user can only sign their own form. The question is what 
    # part of the application decides: the API, or the document database?

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
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

    # The validation step is somewhat complex. We'll start by getting the signatures 
    # object, which is a dict of tuples in the format of:
    # { username: (signature, timestamp, role_id), ... }
    signatures = document["metadata"].get(doc_db.signature_field)

    valid_signatures_check_dict = {}
    
    for _user in signatures.keys():

        # Here we get the user information for the user who created the document to validate their signature
        owner = session.query(User).filter_by(username=_user).first()
        if not owner:
            raise HTTPException(status_code=404, detail=f"Requested data could not be found")

        signature, _timestamp, _role_id = signatures.get(owner.username)

        valid = verify_record_signature(record=document.get("data"), signature=signature, username=owner.username, env=config.ENVIRONMENT, public_key=owner.public_key, private_key_path=owner.private_key_ref)

        valid_signatures_check_dict[_user] = valid

    # print("\n\n\n\n", len(valid_signatures_check_dict))

    return {
        # returns true if all are valid[len(valid_signatures_check_dict)>0]
        "valid": all(list(valid_signatures_check_dict.values())), 
        "signature_count": len(valid_signatures_check_dict),
        "results": valid_signatures_check_dict,
        "document_id": document_id, 
    }


# Not implemented. Unsecure.
# @app.get("/api/validate/signing_key")
# async def api_validate_signing_key(
#     key:str,
#     scope:str,
#     background_tasks: BackgroundTasks,
#     request: Request, 
#     config = Depends(get_config_depends),
#     session: SessionLocal = Depends(get_db),
# ):

#     """
#     Validates a signing key, confirming authenticity and integrity. 
#     Logs the validation attempt. Requires key and scope params.
#     """


#     try:
#         # Ugh, too many steps. We should simplify this to get key details and 
#         # verify in one step, if we can.
#         key_details = signatures.get_key(key)
#         verify = signatures.verify_key(key, scope=[scope])

#     except RateLimitExceeded:
#         raise HTTPException(
#             status_code=429,
#             detail="Rate limit exceeded"
#         )

#     except KeyDoesNotExist:
#         raise HTTPException(
#             status_code=401,
#             detail="Invalid Key"
#         )

#     except ScopeMismatch:
#         raise HTTPException(
#             status_code=401,
#             detail="Invalid Key"
#         )

#     except KeyExpired:
#         raise HTTPException(
#             status_code=401,
#             detail="Key expired"
#         )

#     # Write this query to the TransactionLog
#     if config.COLLECT_USAGE_STATISTICS:

#         endpoint = request.url.path
#         remote_addr = request.client.host

#         background_tasks.add_task(
#             write_api_call_to_transaction_log, 
#             api_key=key, 
#             endpoint=endpoint, 
#             remote_addr=remote_addr, 
#             query_params={'email': key_details['email'], 'scope': scope},
#         )


#     return {
#         "valid": verify, 
#     }



##########################
### API Routes - Auth
##########################


# Create user
@app.post("/api/auth/create", include_in_schema=schema_params["DISABLE_NEW_USERS"]==False)
async def api_auth_create(
    user_request: CreateUserRequest, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db)
):

    """
    Registers a new user with provided details, handling email uniqueness and optional user statistics. 
    Sends email confirmation when SMTP is enabled and configured.
    """


    if config.DISABLE_NEW_USERS:
        raise HTTPException(status_code=404)

    # In the future, consider coercing to lowercase, see
    # https://github.com/signebedi/libreforms-fastapi/issues/239
    new_username = user_request.username.lower()
    new_email = user_request.email.lower()

    # Check if user or email already exists
    # See https://stackoverflow.com/a/9270432/13301284 for HTTP Response
    existing_user = session.query(User).filter(User.username.ilike(new_username)).first()
    if existing_user:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register user {new_username} but user already exists')

        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    existing_email = session.query(User).filter(User.email.ilike(new_email)).first()
    if existing_email:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to register email {new_email} but email is already registered')

        if config.SMTP_ENABLED:

            _subject=f"{config.SITE_NAME} Suspicious Activity"
            _content=f"This email serves to notify you that there was an attempt to register a user with the same email as the account registered to you at {config.DOMAIN}. If this was you, you may safely disregard this email. If it was not you, you should consider contacting your system administrator and changing your password."

            background_tasks.add_task(
                mailer.send_mail, 
                subject=_subject, 
                content=_content, 
                to_address=new_email,
            )

        raise HTTPException(status_code=409, detail="Registration failed. The provided information cannot be used.")

    hashed_password = generate_password_hash(user_request.password.get_secret_value())

    new_user = User(
        email=new_email, 
        username=new_username, 
        password=hashed_password,
        active=config.REQUIRE_EMAIL_VERIFICATION == False,
        opt_out=user_request.opt_out if config.COLLECT_USAGE_STATISTICS else False,
    ) 

    # Create the users API key with a 365 day expiry
    expiration = 8760
    api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=new_email)
    new_user.api_key = api_key

    # Here we add user key pair information, namely, the path to the user private key, and the
    # contents of the public key, see https://github.com/signebedi/libreforms-fastapi/issues/71.
    ds_manager = DigitalSignatureManager(username=new_username, env=config.ENVIRONMENT)
    ds_manager.generate_rsa_key_pair()
    new_user.private_key_ref = ds_manager.get_private_key_file()
    new_user.public_key = ds_manager.public_key_bytes

    # Add the user to the default group
    group = session.query(Group).filter_by(id=1).first()
    new_user.groups.append(group)

    session.add(new_user)
    session.flush()

    # Monitor password use, seee https://github.com/signebedi/libreforms-fastapi/issues/230
    new_password = PasswordReuse(
        user_id=new_user.id,
        hashed_password=hashed_password,
        timestamp=datetime.now(config.TIMEZONE) 
    )
    session.add(new_password)
    session.commit()

    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Registered"

        if config.REQUIRE_EMAIL_VERIFICATION:

            key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=email)
            content=f"This email serves to notify you that the user {new_username} has just been registered for this email address at {config.DOMAIN}. Please verify your email by clicking the following link: {config.DOMAIN}/verify/{key}. Please note this link will expire after 48 hours."

        else:
            content=f"This email serves to notify you that the user {new_username} has just been registered for this email address at {config.DOMAIN}."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=new_email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=new_user.api_key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"user":new_username},
        )

    return {
        "status": "success", 
        "api_key": api_key,
        "message": f"Successfully created new user {new_username}"
    }



# Change password
@app.post("/api/auth/change_password")
async def api_auth_change_password(
    user_request: PasswordChangeUserModel, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Changes an existing user's password with provided details, writing optional user statistics to log. 
    Sends email confirmation when SMTP is enabled and configured.
    """


    user = session.query(User).filter_by(api_key=key).first()

    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")


    if not check_password_hash(user.password, user_request.old_password.get_secret_value()):

        # Implement failed_password_attempts, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/78
        user.failed_login_attempts += 1
        _report_to_user = False


        # If the user has exceeded their failed password attemps, set them
        # as inactive.
        if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
            _report_to_user = True
            user.active = False

        session.add(user)
        session.commit()

        raise HTTPException(status_code=400, detail=f"Incorrect username or password{'. Max password failures exceeded. User account locked.' if _report_to_user else ''}")

    if not user.active:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Hash the password
    hashed_password = generate_password_hash(user_request.new_password.get_secret_value())

    # If password reuse is limited by admins, check here, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/230.
    if config.LIMIT_PASSWORD_REUSE:

        # We set the threshold date. If the PASSWORD_REUSE_PERIOD is set to 0, check all passwords dated since the unix epoch.
        threshold_datetime = datetime.now(config.TIMEZONE) - config.PASSWORD_REUSE_PERIOD if config.PASSWORD_REUSE_PERIOD.days > 0 else datetime(1970, 1, 1, tzinfo=config.TIMEZONE)


        # print("\n\n\n",threshold_datetime)

        # Select past reuses
        # recent_password_reuses = session.query(PasswordReuse).filter_by(user_id=user.id).all()

        recent_password_reuses = session.query(PasswordReuse).filter(
            PasswordReuse.user_id == user.id,
            PasswordReuse.timestamp > threshold_datetime
        ).all()


        # print("\n\n\n", [x.to_dict() for x in session.query(PasswordReuse).all()])
        # print([x.to_dict()for x in recent_password_reuses])

        # If we find a hit, raise an error
        for reuse in recent_password_reuses:
            if check_password_hash(reuse.hashed_password, user_request.new_password.get_secret_value()):
                raise HTTPException(status_code=400, detail=f"You have tried to change your password to a value that you have used within the last {config.PASSWORD_REUSE_PERIOD.days} days. Please try a different password.")


    # If the password IS correct, clear the user's failed password attempts, see
    # https://github.com/signebedi/libreforms-fastapi/issues/78.
    user.failed_login_attempts = 0
    current_time = datetime.now(config.TIMEZONE)
    user.last_login = current_time


    # Set the users new password
    user.last_password_change = current_time
    user.password=hashed_password

    session.add(user)

    # Monitor password use, seee https://github.com/signebedi/libreforms-fastapi/issues/230
    new_password = PasswordReuse(
        user_id=user.id,
        hashed_password=hashed_password,
        timestamp=datetime.now(config.TIMEZONE) 
    )
    session.add(new_password)

    session.commit()


    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Password Changed"

        content=f"This email serves to notify you that the user {user.username} has just had their password changed at {config.DOMAIN}. If you believe this was a mistake, please contact your system adminstrator."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=user.api_key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"user":user.username},
        )

    return {
        "status": "success", 
        "message": f"Successfully changed password for user {user.username}"
    }


# Get User / id
@app.get("/api/auth/get/{id}", dependencies=[Depends(api_key_auth)])
async def api_auth_get(
    id:int, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Retrieves detailed profile information for a specified user ID, respecting privacy 
    settings and administrative permissions. When user is requesting their own details,
    more information is provided.
    """

    # We have already validated the API key, so if they have come this far, they have system access. As
    # such, if no user comes back (eh, that might happen if an admin hacks together an API key without a 
    # user account attached to it .. for system purposes) or if there is a user, but they are not a site
    # admin, then we check the OTHER_PROFILES_ENABLED app configuration. If disabled, then raise error; 
    # else, return the user data.
    requesting_user = session.query(User).filter_by(api_key=key).first() # This is the user making the request
    target_user = session.query(User).filter_by(id=id).first() # This is the user whose data has been requested

    # Return a 404 if the target user does not exist
    if not target_user:
        raise HTTPException(status_code=404)

    # Return a 404 error if the current user lacks permission
    if any([
        not requesting_user,
        not requesting_user.site_admin
    ]):
        # If the user is not requesting their own profile data and the app
        # config does not allow viewing other user's profiles, return a 404.
        if not config.OTHER_PROFILES_ENABLED and requesting_user.id != target_user.id:
            raise HTTPException(status_code=404)

    profile_data = {
        "id": target_user.id,
        "username": target_user.username,
        "email": target_user.email,
        "groups": [g.name for g in target_user.groups],
        "active": target_user.active,
        "created_date": target_user.created_date.strftime('%Y-%m-%d %H:%M:%S'),
        "last_login": target_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if target_user.last_login else 'Never',
    }

    # If the user is requesting their own data, return additional information. 
    if requesting_user.id == target_user.id:
        profile_data["last_password_change"] = target_user.last_password_change
        # Decided against adding API key to minimize private data in JWT
        # profile_data["api_key"] = target_user.api_key
        profile_data["opt_out"] = target_user.opt_out
        profile_data["site_admin"] = target_user.site_admin


    # Here we compile user relationships
    _relationships = [x.to_dict() for x in target_user.relationships]
    _received_relationships = [x.to_dict() for x in target_user.received_relationships]
    profile_data['relationships'] = [{
        'relationship': x['relationship_type']['name'],
        'related_user_username': x['related_user']['username'],
        'related_user_id': x['related_user']['id'],
    } for x in _relationships]

    profile_data['received_relationships'] = [{
        'relationship': x['relationship_type']['reciprocal_name'],
        'related_user_username': x['user']['username'],
        'related_user_id': x['user']['id'],
    } for x in _received_relationships]

    print("\n\n\n", profile_data['relationships'])
    print("\n\n\n", profile_data['received_relationships'])


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"id": id},
        )

    return profile_data


# Update User - change user password / usermod
# @app.patch("/api/auth/update")
# async def api_auth_update(
#     user_request: CreateUserRequest, 
#     background_tasks: BackgroundTasks, 
#     request: Request, 
#     config = Depends(get_config_depends),
#     mailer = Depends(get_mailer), 
#     session: SessionLocal = Depends(get_db)
# ):
#     pass

# Rotate user API key
    # @app.patch("/api/auth/rotate_key")
    # async def api_auth_rotate_key():



@app.post("/api/auth/forgot_password", include_in_schema=schema_params["DISABLE_FORGOT_PASSWORD"]==False)
async def api_auth_forgot_password(
    email: EmailStr,
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
):
    """
    Generates a one-time password and emails to user to permit them to change their password, 
    writing optional user statistics to log. Requires SMTP to be enabled and configured. User
    must pass an email parameter to link the request to a given account.
    """

    if not config.SMTP_ENABLED or config.DISABLE_FORGOT_PASSWORD:
        raise HTTPException(status_code=404, detail="Your system administrator has not enabled this feature")

    # if not email:
    #     raise HTTPException(status_code=422, detail="Please provide an email")


    user = session.query(User).filter_by(email=email).first()

    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")

    if not user.active:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Generate the user's one time password
    otp = signatures.write_key(scope=['forgot_password'], expiration=3, active=True, email=user.email)

    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Password Reset Instructions"

        content=f"This email serves to notify you that the user {user.username} has just requested to reset their password at {config.DOMAIN}. To do so, you may use the one-time password {otp}. This one-time password will expire in three hours. If you have access to the user interface, you may reset your password at the following link: {config.DOMAIN}/ui/auth/forgot_password/{otp}. If you believe this was a mistake, please contact your system adminstrator."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=user.api_key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"user":user.username},
        )

    return {
        "status": "success", 
        "message": f"Check your email for a password reset link"
    }



@app.post("/api/auth/forgot_password/{otp}", include_in_schema=schema_params["DISABLE_FORGOT_PASSWORD"]==False)
async def api_auth_forgot_password_confirm(
    user_request: ForgotPasswordUserModel, 
    otp: str,
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
):
    """
    After validating a user's valid one-time password, changes an existing user's password 
    with provided details, writing optional user statistics to log. Sends email confirmation 
    when SMTP is enabled and configured.
    """

    if not config.SMTP_ENABLED or config.DISABLE_FORGOT_PASSWORD:
        raise HTTPException(status_code=404, detail="Your system administrator has not enabled this feature")

    # Start by verifying the one time password.
    try:
        # Ugh, too many steps. We should simplify this to get key details and 
        # verify in one step, if we can.
        otp_key_details = signatures.get_key(otp)
        verify = signatures.verify_key(otp, scope=['forgot_password'])

    except RateLimitExceeded:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded"
        )

    except KeyDoesNotExist:
        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )

    except ScopeMismatch:
        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )

    except KeyExpired:
        raise HTTPException(
            status_code=401,
            detail="OTP expired"
        )

    user = session.query(User).filter_by(email=otp_key_details['email']).first()

    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")

    if not user.active:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Hash the password
    hashed_password = generate_password_hash(user_request.new_password.get_secret_value())

    # If password reuse is limited by admins, check here, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/230.
    if config.LIMIT_PASSWORD_REUSE:

        # We set the threshold date. If the PASSWORD_REUSE_PERIOD is set to 0, check all passwords dated since the unix epoch.
        threshold_datetime = datetime.now(config.TIMEZONE) - config.PASSWORD_REUSE_PERIOD if config.PASSWORD_REUSE_PERIOD.days > 0 else datetime(1970, 1, 1, tzinfo=config.TIMEZONE)

        # Filter the data set
        recent_password_reuses = session.query(PasswordReuse).filter(
            PasswordReuse.user_id == user.id,
            PasswordReuse.timestamp > threshold_datetime
        ).all()

        # If we find a hit, raise an error
        for reuse in recent_password_reuses:
            if check_password_hash(reuse.hashed_password, user_request.new_password.get_secret_value()):
                raise HTTPException(status_code=400, detail=f"You have tried to change your password to a value that you have used within the last {config.PASSWORD_REUSE_PERIOD.days} days. Please try a different password.")


    # If the password IS correct, clear the user's failed password attempts, see
    # https://github.com/signebedi/libreforms-fastapi/issues/78.
    user.failed_login_attempts = 0
    current_time = datetime.now(config.TIMEZONE)
    user.last_login = current_time

    # Set the user's new password
    user.last_password_change = current_time
    user.password=hashed_password

    session.add(user)

    # Monitor password use, seee https://github.com/signebedi/libreforms-fastapi/issues/230
    new_password = PasswordReuse(
        user_id=user.id,
        hashed_password=hashed_password,
        timestamp=datetime.now(config.TIMEZONE) 
    )
    session.add(new_password)

    session.commit()

    # Expire the OTP
    _ = signatures.expire_key(otp)

    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Password Reset"

        content=f"This email serves to notify you that the user {user.username} has just reset their password at {config.DOMAIN}. If you believe this was a mistake, please contact your system adminstrator."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=user.email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=user.api_key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"user":user.username},
        )

    return {
        "status": "success", 
        "message": f"Successfully reset password for user {user.username}"
    }




# Login, see https://github.com/signebedi/libreforms-fastapi/issues/19
@app.post('/api/auth/login')
async def api_auth_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
):

    """
    Authenticates a user based on username and password, issuing a JWT for session management. 
    Tracks and limits failed attempts.
    """


    user = session.query(User).filter_by(username=form_data.username.lower()).first()

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not check_password_hash(user.password, form_data.password):

        # Implement failed_password_attempts, see 
        # https://github.com/signebedi/libreforms-fastapi/issues/78
        user.failed_login_attempts += 1
        _report_to_user = False


        # If the user has exceeded their failed password attemps, set them
        # as inactive.
        if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
            _report_to_user = True
            user.active = False

        session.add(user)
        session.commit()

        raise HTTPException(status_code=400, detail=f"Incorrect username or password{'. Max password failures exceeded. User account locked.' if _report_to_user else ''}")

    if not user.active:
        raise HTTPException(status_code=400, detail="User authentication failed")

    # Validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
        raise HTTPException(status_code=400, detail="User authentication failed")

    # If the password IS correct, clear the user's failed password attempts, see
    # https://github.com/signebedi/libreforms-fastapi/issues/78.
    else:
        user.failed_login_attempts = 0
        user.last_login = datetime.now(config.TIMEZONE)

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
        # Decided against adding API key to minimize private data in JWT
        # "api_key": user.api_key,
        "admin": user.site_admin,
    }

    # Reimplementing to use RSA keypair, see
    # https://github.com/signebedi/libreforms-fastapi/issues/79
    token = jwt.encode(
        user_dict, 
        site_key_pair.get_private_key(), 
        algorithm='RS256'
    )

    # Set the HTTP-only cookie with the token
    response = JSONResponse({"access_token": token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        max_age=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
        expires=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
    )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=user.api_key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"user": user.username},
        )

    return response



@app.post('/api/auth/refresh')
async def api_auth_refresh(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
):
    """
    Refreshes user tokens based on username and password, issuing a JWT for session management. 
    Tracks and limits failed attempts.
    """

    try:

        cookie = SimpleCookie()
        cookie.load(request.headers["cookie"])

        auth = cookie['access_token'].value if 'access_token' in cookie else None

        scheme, token = auth.split()

        if scheme.strip().lower() != 'bearer':
            # return JSONResponse(status_code=200, content={'message': "Token was not updated"})
            raise HTTPException(status_code=401)

        # Expiration time is automatically verified in jwt.decode() and raises 
        # jwt.ExpiredSignatureError if the expiration time is in the past.
        payload = jwt.decode(
            token, 
            site_key_pair.get_public_key(), 
            issuer=config.SITE_NAME, 
            audience=f"{config.SITE_NAME}WebUser", 
            algorithms=['RS256']
        )

    except:
        # return JSONResponse(status_code=200, content={'message': "Token was not updated"})
        raise HTTPException(status_code=401)

    # Here we set a refresh threshold... We could make
    # this configurable if we really wanted to. Maybe 
    # something that defaults to 1/3 the session lifetime.
    refresh_threshold = ( datetime.now(config.TIMEZONE) + ( config.PERMANENT_SESSION_LIFETIME / 3 ) ).timestamp()
    # refresh_threshold = ( datetime.now(config.TIMEZONE) + timedelta(minutes=6000) ).timestamp()


    if payload.get("exp") > refresh_threshold:
        
        # If we are outside the request threshold, then we return here
        # return JSONResponse(status_code=204, content={'message': "Token was not updated"})

        # I am trying to decide whether to raise an error (so, a 4xx response code is logged every 
        # time an authenticated user tries to refresh their token too soon) or some other response.
        raise HTTPException(status_code=401) 

    user_dict = {
        "id": payload['id'],
        "sub": payload['sub'],
        "aud": payload['aud'],
        "iss": payload['iss'],
        "email": payload['email'],
        "active": payload['active'],
        "admin": payload['admin'],
        # Decided against adding API key to minimize private data in JWT
        # "api_key": payload['api_key'],
        "exp": datetime.now(config.TIMEZONE) + config.PERMANENT_SESSION_LIFETIME,
    }

    # Reimplementing to use RSA keypair, see
    # https://github.com/signebedi/libreforms-fastapi/issues/79
    token = jwt.encode(
        user_dict, 
        site_key_pair.get_private_key(), 
        algorithm='RS256'
    )

    # Set the HTTP-only cookie with the token
    response = JSONResponse({"access_token": token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        max_age=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
        expires=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
    )

    return response


# This is a help route to submit a help request to the sysadmin
@app.post("/api/auth/help", dependencies=[Depends(api_key_auth)], response_class=JSONResponse, include_in_schema=schema_params["HELP_PAGE_ENABLED"])
async def api_auth_help(
    request: Request, 
    background_tasks: BackgroundTasks,
    help_request: HelpRequest,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Submits a help request from a user to the system administrator via email, including user details 
    and the message content.
    """


    if not config.HELP_PAGE_ENABLED or not config.SMTP_ENABLED:
        raise HTTPException(status_code=404)

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user:
        raise HTTPException(status_code=404)

    time_str = datetime.now(config.TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")

    # We escape and shorten the message contents as needed
    safe_subject = escape(help_request.subject)
    shortened_safe_subject = safe_subject[:50]

    safe_message = escape(help_request.message)
    safe_category = escape(help_request.category)
    shortened_safe_category = safe_category[:50]

    full_safe_subject = f"[{config.SITE_NAME}][{user.username}][{shortened_safe_category}] {shortened_safe_subject}"

    full_safe_message = f"You are receiving this message because a user has submitted " \
        f"a request for help at {config.DOMAIN}. You can see the request details below." \
        f"\n\n****\nUser: {user.username}\nEmail: {user.email}\nTime of Submission:" \
        f"{time_str}\nCategory: {shortened_safe_category}\nSubject: {safe_subject}\n" \
        f"Message: {safe_message}\n****\n\nYou may reply directly to the user who " \
        f"submitted this request by replying to this email."

    background_tasks.add_task(
        mailer.send_mail, 
        subject=full_safe_subject, 
        content=full_safe_message, 
        to_address=config.HELP_EMAIL,
        reply_to_addr=user.email
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
            query_params={"category": shortened_safe_category},
        )

    return JSONResponse(
        status_code=202,
        content={"status": "success"},
    )

##########################
### API Routes - Admin
##########################

# Get all users
# > paired with manage users admin UI route
@app.get(
    "/api/admin/get_users", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_users(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists all users in the system for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    users = [x.to_dict() for x in session.query(User).all()]

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "users": users},
    )


# Add new user as an admin
@app.post(
    "/api/admin/create_user", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_create_user(
    user_request: AdminCreateUserRequest, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Create a user, as an admin. Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # In the future, consider coercing to lowercase, see
    # https://github.com/signebedi/libreforms-fastapi/issues/239
    new_username = user_request.username.lower()
    # See https://github.com/signebedi/libreforms-fastapi/issues/267
    new_email = user_request.email.lower()

    existing_user = session.query(User).filter(User.username.ilike(new_username)).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Registration failed. Username already exists.")

    existing_email = session.query(User).filter(User.email.ilike(new_email)).first()
    if existing_email:
        raise HTTPException(status_code=409, detail="Registration failed. Email already in use.")

    new_user = User(
        email=new_email, 
        username=new_username, 
        active=True,
    ) 

    # Create the users API key with a 365 day expiry
    expiration = 8760
    api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=new_email)
    new_user.api_key = api_key

    if not user_request.password:
        password = percentage_alphanumeric_generate_password(config.PASSWORD_REGEX, 16, .65)
        hashed_password = generate_password_hash(password)

    # If the admin passes a password, then we use that instead of auto-generating one, see
    # https://github.com/signebedi/libreforms-fastapi/issues/251.
    else:
        password = user_request.password.get_secret_value()
        hashed_password = generate_password_hash(password)

    new_user.password = hashed_password

    # Here we add user key pair information, namely, the path to the user private key, and the
    # contents of the public key, see https://github.com/signebedi/libreforms-fastapi/issues/71.
    ds_manager = DigitalSignatureManager(username=new_username, env=config.ENVIRONMENT)
    ds_manager.generate_rsa_key_pair()
    new_user.private_key_ref = ds_manager.get_private_key_file()
    new_user.public_key = ds_manager.public_key_bytes

    # Add the user to the default group
    for group_str in user_request.groups:
        group = session.query(Group).filter_by(name=group_str).first()
        if group:
            new_user.groups.append(group)

    session.add(new_user)
    session.flush()

    # Monitor password use, seee https://github.com/signebedi/libreforms-fastapi/issues/230
    new_password = PasswordReuse(
        user_id=new_user.id,
        hashed_password=hashed_password,
        timestamp=datetime.now(config.TIMEZONE) 
    )
    session.add(new_password)
    session.commit()

    # Email notification
    if config.SMTP_ENABLED:

        subject=f"{config.SITE_NAME} User Registered"
        content=f"This email serves to notify you that the user {new_username} has just been registered for this email address at {config.DOMAIN}. Your user has been given the following temporary password:\n\n{password}\n\nPlease login to the system and update this password at your earliest convenience."

        background_tasks.add_task(
            mailer.send_mail, 
            subject=subject, 
            content=content, 
            to_address=new_email,
        )


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=request.url.path, 
            remote_addr=request.client.host, 
            query_params={"user":new_username},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"New user '{new_username}' created with the temporary password {password}"},
    )

# This is a glorified "update groups" route..
@app.put(
    "/api/admin/update_user/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_update_user(
    id: str,
    user_request: AdminCreateUserRequest, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Update a user, as an admin. Mainly for modifying groups. Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    user_to_change = session.query(User).get(id)

    # Really, it's just groups we want to change
    user_to_change.groups = []
    for group_str in user_request.groups:
        group = session.query(Group).filter_by(name=group_str).first()
        if group:
            user_to_change.groups.append(group)

    session.add(user_to_change)
    session.commit()

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=request.url.path, 
            remote_addr=request.client.host, 
            query_params={"user":user.username, "groups":user.groups},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully modified user with id {id}"},
    )


# User setting toggles
@app.patch(
    "/api/admin/toggle/{field}/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_modify_user(
    field:str,
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Toggles a user field by ID. In the case of passwords, it resets them. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    if field not in ["active", "site_admin", "password", "api_key"]:
        raise HTTPException(status_code=404)

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)


    user_to_change = session.query(User).get(id)
    if not user_to_change:
        raise HTTPException(status_code=404, detail="Could not find user. Are you sure they exist?")

    # Here we set the relevant value to change
    if field in ["active", "site_admin"]:
        if user.id == user_to_change.id:
            raise HTTPException(status_code=418, detail=f"You really shouldn't be performing these operations against yourself...")
        new_value = not getattr(user_to_change, field)
        setattr(user_to_change, field, new_value)
    elif field == "password":
        new_value = percentage_alphanumeric_generate_password(config.PASSWORD_REGEX, 16, .65)
        hashed_password = generate_password_hash(new_value)
        user_to_change.password = hashed_password

        # Fix for https://github.com/signebedi/libreforms-fastapi/issues/240
        current_time = datetime.now(config.TIMEZONE)
        user_to_change.last_password_change = current_time
        user_to_change.last_login = current_time

        user_to_change.failed_login_attempts = 0

        # Monitor password use, seee https://github.com/signebedi/libreforms-fastapi/issues/230
        new_password = PasswordReuse(
            user_id=user_to_change.id,
            hashed_password=hashed_password,
            timestamp=datetime.now(config.TIMEZONE) 
        )
        session.add(new_password)

    elif field == "api_key":
        # Rotate the user's API key 
        new_value = signatures.rotate_key(user_to_change.api_key)
        user_to_change.api_key = new_value

    session.add(user_to_change)
    session.commit()

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=request.url.path, 
            remote_addr=request.client.host, 
            query_params={},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"{field} set to {new_value} for user id {id}"},
    )




# Get Transaction Log
    # Paired with the Transaction Data admin UI route

# Update application config

# Trigger site reload

# Get group
@app.get(
    "/api/admin/get_group/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_group(
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists single group by ID for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    group = session.query(Group).filter_by(id=id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Could not find group. Does not exist.")

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "group": group.to_dict()},
    )


# Get all groups
@app.get(
    "/api/admin/get_groups", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_groups(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists all groups in the system for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    groups = [x.to_dict() for x in session.query(Group).all()]

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "groups": groups},
    )



# Get all form submissions
@app.get(
    "/api/admin/get_submissions", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_submissions(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists all documents in the system for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    documents = []

    for form_name in get_form_names(config_path=config.FORM_CONFIG_PATH):
        _new_docs = doc_db.get_all_documents(form_name=form_name, exclude_deleted=False)
        if _new_docs:
            documents.extend(_new_docs)


    # print("\n\n\n", documents)

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "submissions": documents},
    )




# Delete form
@app.delete("/api/admin/delete_form/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_delete(
    form_name: str, 
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Deletes a specific document from a form based on the form name and document ID in the URL.
    Validates the existence of the document, user permissions, and logs the deletion.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

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


@app.patch("/api/admin/restore_form/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_restore(
    form_name: str,
    document_id:str,
    background_tasks: BackgroundTasks,
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Restores a previously deleted document in a form, identified by form name and document ID in the URL.
    Checks document existence, validates user permissions, and logs the restoration.
    """

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

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


# Add new group
@app.post(
    "/api/admin/create_group", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_create_group(
    group_request: GroupModel, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Creates a new group with provided details, handling group validation using a predefined pydantic
    model as middleware between the data and the ORM. 
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    existing_group = session.query(Group).filter_by(name=group_request.name).first()
    if existing_group:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to create group {group_request.name} but group already exists. Did you mean to modify the group?')

        raise HTTPException(status_code=409, detail="Could not create group. Already exists.")
    
    # Create and write the new group
    new_group = Group(
        name=escape(group_request.name), 
        permissions=group_request.permissions,
    )
    session.add(new_group)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully created new group {group_request.name}"},
    )



# Update group
@app.put(
    "/api/admin/update_group/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_update_group(
    group_request: GroupModel, 
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),
):
    """
    Updates existing group with provided details, handling group validation using a predefined pydantic
    model as middleware between the data and the ORM. 
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    existing_group = session.query(Group).filter_by(id=id).first()
    if not existing_group:
        raise HTTPException(status_code=404, detail="Could not update group. Does not exist.")
    
    if all ([
        existing_group.name == group_request.name,
        existing_group.permissions == group_request.permissions,
    ]):
        # If no change has been passed, return
        return JSONResponse(
            status_code=200,
            content={"status": "no change", "message": f"No change made to group with id {id}"},
        )
        # raise HTTPException(status_code=304, detail=f"No change made to group with id {id}")


    # Updating group fields
    existing_group.name=group_request.name
    existing_group.permissions=group_request.permissions
    
    session.add(existing_group)
    session.commit()

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=request.url.path, 
            remote_addr=request.client.host, 
            query_params={},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully modified group {group_request.name} with id {id}"},
    )

# Delete group
@app.delete(
    "/api/admin/delete_group/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_delete_group(
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Deletes single group by ID. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    group_to_delete = session.query(Group).filter_by(id=id).first()
    if not group_to_delete:
        raise HTTPException(status_code=404, detail="Could not find group. Does not exist.")

    session.delete(group_to_delete)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Group with id {id} successfully deleted"},
    )


# Create relationship type
@app.post(
    "/api/admin/create_relationship_type", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_relationship_type(
    new_relationship_request: RelationshipTypeModel, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Creates a new relationship type with provided details, handling payload validation using a predefined pydantic
    model as middleware between the data and the ORM. See https://github.com/signebedi/libreforms-fastapi/issues/173.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    existing_relationship_type = session.query(RelationshipType).filter_by(name=new_relationship_request.name).first()
    if existing_relationship_type:
        # Consider adding IP tracking to failed attempt
        logger.warning(f'Attempt to create relationship type {new_relationship_request.name} but relationship type already exists. Did you mean to modify the relationship type?')

        raise HTTPException(status_code=409, detail="Could not create relationship type. Already exists.")
    
    # Create and write the new Relationship Type
    new_relationship_type = RelationshipType(
        name=escape(new_relationship_request.name),
        description=escape(new_relationship_request.description), 
        exclusive=new_relationship_request.exclusive_relationship,
    )

    # Assign a reciprocal name / title if one was passed
    if new_relationship_request.reciprocal_name:
        new_relationship_type.reciprocal_name = new_relationship_request.reciprocal_name

    session.add(new_relationship_type)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully created new relationship type {new_relationship_request.name}"},
    )

# Get all relationship types
@app.get(
    "/api/admin/get_relationship_types", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_relationship_types(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists all relationship types in the system for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    relationship_types = [x.to_dict() for x in session.query(RelationshipType).all()]

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "relationship_types": relationship_types},
    )

# Edit a relationship type
@app.put(
    "/api/admin/update_relationship_type/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_update_relationship_type(
    relationship_request: RelationshipTypeModel, 
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),
):
    """
    Updates existing relationship type with provided details, handling payload validation using a predefined pydantic
    model as middleware between the data and the ORM. See https://github.com/signebedi/libreforms-fastapi/issues/173.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    existing_relationship_type = session.query(RelationshipType).filter_by(id=id).first()
    if not existing_relationship_type:
        raise HTTPException(status_code=404, detail="Could not update relationship type. Does not exist.")
    
    if all ([
        existing_relationship_type.name == relationship_request.name,
        existing_relationship_type.description == relationship_request.description,
        existing_relationship_type.exclusive == relationship_request.exclusive_relationship,
        existing_relationship_type.reciprocal_name == relationship_request.reciprocal_name,
    ]):
        # If no change has been passed, return
        return JSONResponse(
            status_code=200,
            content={"status": "no change", "message": f"No change made to relationship with id {id}"},
        )
        # raise HTTPException(status_code=304, detail=f"No change made to group with id {id}")


    # Updating fields
    existing_relationship_type.name=relationship_request.name
    existing_relationship_type.description=relationship_request.description
    existing_relationship_type.exclusive=relationship_request.exclusive_relationship

    # Assign a reciprocal name / title if one was passed
    if relationship_request.reciprocal_name:
        existing_relationship_type.reciprocal_name = relationship_request.reciprocal_name


    session.add(existing_relationship_type)
    session.commit()

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=request.url.path, 
            remote_addr=request.client.host, 
            query_params=existing_relationship_type.to_dict(),
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully modified relationship type {relationship_request.name} with id {id}"},
    )



# Delete group
@app.delete(
    "/api/admin/delete_relationship_type/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_delete_relationship_type(
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Deletes single relationship type by ID. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    type_to_delete = session.query(RelationshipType).filter_by(id=id).first()
    if not type_to_delete:
        raise HTTPException(status_code=404, detail="Could not find relationship type. Does not exist.")

    session.delete(type_to_delete)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Relationship type with id {id} successfully deleted"},
    )




# Create relationship type
@app.post(
    "/api/admin/create_user_relationship", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_create_user_relationship(
    new_relationship_request: UserRelationshipModel, 
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Creates a new relationship with provided details, handling payload validation using a predefined pydantic
    model as middleware between the data and the ORM. See https://github.com/signebedi/libreforms-fastapi/issues/173.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # A user cannot have a relationship with themselves
    if new_relationship_request.user_id == new_relationship_request.related_user_id:
        raise HTTPException(status_code=400, detail="Users cannot have a relationship with themselves")

    # We need to check whether each of these exist
    _user = session.query(User).filter_by(id=new_relationship_request.user_id).first()
    _related_user = session.query(User).filter_by(id=new_relationship_request.related_user_id).first()
    _relationship_type = session.query(User).filter_by(id=new_relationship_request.relationship_type_id).first()

    if not all([
        _user,
        _related_user,
        _relationship_type,
    ]):
        raise HTTPException(status_code=400, detail="You must pass users and relationship types that exist")


    # We need to check if there is an exact duplicate of the three values.
    existing_user_relationship = session.query(UserRelationship).filter_by(
        user_id=new_relationship_request.user_id,
        related_user_id=new_relationship_request.related_user_id,
        relationship_type_id=new_relationship_request.relationship_type_id
    ).first() 
    if existing_user_relationship:
        # Consider adding IP tracking to failed attempt
        raise HTTPException(status_code=409, detail="Could not create user relationship. Already exists.")


    # We check the relationship type and verify that it is not exclusive. If it is, then we validate whether the 
    # the user already has an existing relationship. If so, raise and exception and suggest they delete the relationship 
    # before proceeding.
    # [PLACEHOLDER]


    # Create and write the new Relationship Type
    new_user_relationship = UserRelationship(
        user_id=new_relationship_request.user_id,
        related_user_id=new_relationship_request.related_user_id,
        relationship_type_id=new_relationship_request.relationship_type_id,
    )
    session.add(new_user_relationship)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully created new relationship"},
    )

# Get all relationship types
@app.get(
    "/api/admin/get_user_relationships", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_user_relationships(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Lists all relationships in the system for administrative purposes. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    user_relationships = [x.to_dict() for x in session.query(UserRelationship).all()]

    # print("\n\n\n", user_relationships)

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "user_relationships": user_relationships},
    )


# Delete group
@app.delete(
    "/api/admin/delete_user_relationship/{id}", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_delete_user_relationship(
    id:str,
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):

    """
    Deletes single relationship type by ID. Requires site admin permissions. 
    Logs the action for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    relationship_to_delete = session.query(UserRelationship).filter_by(id=id).first()
    if not relationship_to_delete:
        raise HTTPException(status_code=404, detail="Could not find relationship type. Does not exist.")

    session.delete(relationship_to_delete)
    session.commit()

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Relationship with id {id} successfully deleted"},
    )

# This is for comparing changes on docs and form config writes
def get_string_differences(str1, str2):
    # Split the strings into lines to handle line breaks properly
    lines1 = str1.splitlines(keepends=True)
    lines2 = str2.splitlines(keepends=True)
    
    # print(lines1, lines2)

    # Generate the diff
    diff = list(difflib.ndiff(lines1, lines2))
        
    # Filter the diff to keep only changed lines ('+' or '-')
    changes = [line for line in diff if line.startswith('+ ') or line.startswith('- ')]

    # join the changes into a single string for easier reading
    readable_changes = ' '.join(changes)
    return readable_changes



# Edit docs
@app.post(
    "/api/admin/edit_docs", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
    include_in_schema=schema_params["DOCS_ENABLED"],
)
async def api_admin_edit_docs(
    request: Request, 
    background_tasks: BackgroundTasks,
    docs: DocsEditRequest,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Allows site administrators to edit system documentation. This operation is logged for audit purposes.
    """

    if not config.DOCS_ENABLED:
        raise HTTPException(status_code=404)

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    old_docs_markdown = get_docs(docs_path=config.DOCS_PATH, render_markdown=False)

    background_tasks.add_task(
        write_docs, 
            docs_path=config.DOCS_PATH, 
            content=docs.content, 
            scrub_unsafe=True,
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
            query_params={"changes": get_string_differences(old_docs_markdown, docs.content)},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success"},
    )


# Get form config string
@app.get(
    "/api/admin/get_form_config", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_form_config(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Allows site administrators to view the site form config as yaml. This operation is logged for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)


    _form_config = _get_form_config_yaml(config_path=config.FORM_CONFIG_PATH)

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

    return JSONResponse(
        status_code=200,
        content={"status": "success", "content": _form_config},
    )


# Update form config string
@app.post(
    "/api/admin/write_form_config", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_write_form_config(
    request: Request, 
    _form_config: FormConfigUpdateRequest,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Allows site administrators to update the site form config as yaml. This operation is logged for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)


    old_form_config_str = get_form_config_yaml(config_path=config.FORM_CONFIG_PATH).strip()

    try:
        write_form_config_yaml(
            config_path=config.FORM_CONFIG_PATH, 
            form_config_str=_form_config.content, 
            # validate=True,
            timezone=config.TIMEZONE,
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"{e}")

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"changes": get_string_differences(old_form_config_str, _form_config.content)},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success"},
    )



# Update form config string
@app.post(
    "/api/admin/update_site_config", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_update_site_config(
    request: Request, 
    _site_config: SiteConfig,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Allows site administrators to update the site config. This operation is logged for audit purposes.
    """

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    print(_site_config.content)


    with get_config_context() as _c:
        # config = _c
        pass

    try:
        _ = validate_and_write_configs(config, **_site_config.content)

    except Exception as e:
        raise HTTPException(status_code=422, detail=f"{e}")


    # # Clear the config cache, see https://github.com/signebedi/libreforms-fastapi/issues/226
    # get_config.cache_clear()


    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:

        endpoint = request.url.path
        remote_addr = request.client.host

        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"changes": {**_site_config.content}},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success"},
    )


@app.post(
    "/api/admin/test_smtp", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_test_smtp(
    request: Request, 
    _site_config: SiteConfig,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Tests SMTP server connectivity and authentication to ensure that email services can operate correctly.
    Requires site admin permissions and logs the action for audit purposes.
    """

    # Authenticate the requesting user
    user = session.query(User).filter_by(api_key=key).first()
    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # print("\n\n\n", _site_config.model_dump())

    # Perform the SMTP connection test
    smtp_test_result = mailer.test_connection(
        enabled=_site_config.content['SMTP_ENABLED'],
        mail_server=_site_config.content['SMTP_MAIL_SERVER'],
        port=_site_config.content['SMTP_PORT'],
        username=_site_config.content['SMTP_USERNAME'],
        password=_site_config.content['SMTP_PASSWORD'],
    )

    # Log the SMTP test attempt
    if config.COLLECT_USAGE_STATISTICS:
        endpoint = request.url.path
        remote_addr = request.client.host
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"test_result": "success" if smtp_test_result else "failure"},
        )

    # Respond with the result of the SMTP test
    return JSONResponse(
        status_code=200,
        content={
            "status": "success" if smtp_test_result else "failure",
            "message": "SMTP connection successful" if smtp_test_result else "SMTP connection failed"
        },
    )


@app.post(
    "/api/admin/test_relational_database", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_test_relational_database(
    request: Request, 
    _site_config: SiteConfig,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Tests relational database connectivity and authentication to ensure that services can operate correctly.
    Requires site admin permissions and logs the action for audit purposes.
    """

    # Authenticate the requesting user
    user = session.query(User).filter_by(api_key=key).first()
    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # print("\n\n\n", _site_config.model_dump())

    # Perform the database connection test
    db_test_result = test_relational_database_connection(_site_config.content['SQLALCHEMY_DATABASE_URI'])

    # Log the test attempt
    if config.COLLECT_USAGE_STATISTICS:
        endpoint = request.url.path
        remote_addr = request.client.host
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"test_result": "success" if db_test_result else "failure"},
        )

    # Respond with the result of the SMTP test
    return JSONResponse(
        status_code=200,
        content={
            "status": "success" if db_test_result else "failure",
            "message": "Relational database connection successful" if db_test_result else "Relational database connection failed"
        },
    )



@app.post(
    "/api/admin/test_document_database", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_test_document_database(
    request: Request, 
    _site_config: SiteConfig,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Tests document database connectivity and authentication to ensure that services can operate correctly.
    Requires site admin permissions and logs the action for audit purposes.
    """

    # Authenticate the requesting user
    user = session.query(User).filter_by(api_key=key).first()
    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # print("\n\n\n", _site_config.model_dump())


    # Initialize the document database
    _doc_db = get_document_database(
        form_names_callable=get_form_names,
        form_config_path=config.FORM_CONFIG_PATH,
        timezone=config.TIMEZONE, 
        env=config.ENVIRONMENT, 
        use_mongodb=_site_config.content['MONGODB_ENABLED'], 
        mongodb_uri=_site_config.content['MONGODB_URI'],
        use_excel=config.EXCEL_EXPORT_ENABLED,
    )

    # Perform the database connection test
    db_test_result = _doc_db._test_connection()

    # Log the test attempt
    if config.COLLECT_USAGE_STATISTICS:
        endpoint = request.url.path
        remote_addr = request.client.host
        background_tasks.add_task(
            write_api_call_to_transaction_log, 
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={"test_result": "success" if db_test_result else "failure"},
        )

    # Respond with the result of the SMTP test
    return JSONResponse(
        status_code=200,
        content={
            "status": "success" if db_test_result else "failure",
            "message": "Document database connection successful" if db_test_result else "Document database connection failed"
        },
    )



##########################
### UI Routes - Forms
##########################


# This is a standard callable that will generate the context
# for the UI routes and Jinja templates.
def build_ui_context():

    kwargs = {}

    # with get_config_context() as _c:
    #     kwargs["config"] = _c.model_dump()

    # I am modifying this to use the default, now cached get_config function instead of the
    # context managed one, which is called in only a subset of circumstances... including when 
    # changes to the app config are published through the admin rest api. Hopefully this reduces 
    # the number of open file handles by a critical amount, along with running the dependencies 
    # as async.
    _c = get_config(_env)
    kwargs["config"] = _c.model_dump()

    kwargs["version"] = __version__
    kwargs["available_forms"] = get_form_names(config_path=config.FORM_CONFIG_PATH)
    kwargs["current_year"] = datetime.now().year
    kwargs["render_markdown_content"] = render_markdown_content

    return kwargs

# Create form
@app.get("/ui/form/create/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_create(form_name:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    return templates.TemplateResponse(
        request=request, 
        name="create_form.html.jinja", 
        context={
            "form_name": form_name,
            "form_html": form_html,
            **build_ui_context(),
        }
    )



# Read one form
@app.get("/ui/form/read_one/{form_name}/{document_id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_read_one(form_name:str, document_id:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404)

    if document_id not in doc_db._get_existing_document_ids(form_name):
        raise HTTPException(status_code=404)

    # Here we create a mask of metadata field names for the UI
    metadata_field_mask = {
        x: x.replace("_", " ").title() for x in doc_db.metadata_fields 
        if x not in [doc_db.journal_field, doc_db.linked_to_user_field, doc_db.linked_to_form_field]
    }

    # # Here we load the form config in order to mask data field names correctly
    form_config = load_form_config(config.FORM_CONFIG_PATH)
    this_form = form_config[form_name]
    form_field_mask = {x: y.get("field_label", x.replace("_", " ").title()) for x, y in this_form.items()}



    return templates.TemplateResponse(
        request=request, 
        name="read_one_form.html.jinja", 
        context={
            "form_name": form_name,
            "document_id": document_id,
            "metadata_field_mask": metadata_field_mask,
            "form_field_mask": form_field_mask,
            **build_ui_context(),
        }
    )


@app.get("/ui/form/read_one/{form_name}/{document_id}/printer_friendly", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_printer_friedly(form_name:str, document_id:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404)

    if document_id not in doc_db._get_existing_document_ids(form_name):
        raise HTTPException(status_code=404)

    # Here we create a mask of metadata field names for the UI
    metadata_field_mask = {x: x.replace("_", " ").title() for x in doc_db.metadata_fields if x not in [doc_db.journal_field]}

    # # Here we load the form config in order to mask data field names correctly
    form_config = load_form_config(config.FORM_CONFIG_PATH)
    this_form = form_config[form_name]
    form_field_mask = {x: y.get("field_label", x.replace("_", " ").title()) for x, y in this_form.items()}



    return templates.TemplateResponse(
        request=request, 
        name="printer_friendly.html.jinja", 
        context={
            "form_name": form_name,
            "document_id": document_id,
            "metadata_field_mask": metadata_field_mask,
            "form_field_mask": form_field_mask,
            **build_ui_context(),
        }
    )



# Read all forms
@app.get("/ui/form/read_all", include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_read_all(request: Request, config = Depends(get_config_depends)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="read_all_forms.html.jinja", 
        context={
            "form_names": list(get_form_names(config_path=config.FORM_CONFIG_PATH)),
            **build_ui_context(),
        }
    )

# Update form
@app.get("/ui/form/update/{form_name}/{document_id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_update(form_name:str, document_id:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        update=True,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    return templates.TemplateResponse(
        request=request, 
        name="update_form.html.jinja", 
        context={
            "form_name": form_name,
            "document_id": document_id,
            "form_html": form_html,
            **build_ui_context(),
        }
    )


@app.get("/ui/form/duplicate/{form_name}/{document_id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_duplicate(form_name:str, document_id:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        update=True,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    return templates.TemplateResponse(
        request=request, 
        name="duplicate_form.html.jinja", 
        context={
            "form_name": form_name,
            "document_id": document_id,
            "form_html": form_html,
            **build_ui_context(),
        }
    )



# Approve form
    # @app.get("/ui/form/approve/{form_name}", include_in_schema=False)
    # async def ui_form_approve():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")



# Search forms
@app.get("/ui/form/search", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_admin_form_search(
    request: Request, 
    config = Depends(get_config_depends),
    search_term: str = Query(None, title="Search Term"),
):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # search_term = body.get('search_term', None)
    if not search_term:
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        request=request, 
        name="search_forms.html.jinja", 
        context={
            "search_term": search_term,
            **build_ui_context(),
        }
    )

##########################
### UI Routes - Default Routes
##########################

@app.get("/", response_class=RedirectResponse, include_in_schema=False)
async def ui_redirect_to_home(response: Response, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Redirect to the homepage
    response = RedirectResponse(request.url_for("ui_home"), status_code=303)
    return response

# Homepage
@app.get("/ui/home", response_class=HTMLResponse, include_in_schema=False)
async def ui_home(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="home.html.jinja", 
        context={
            "form_names": list(get_form_names(config_path=config.FORM_CONFIG_PATH)),
            **build_ui_context(),
        }
    )

# Privacy policy
@app.get("/ui/privacy", response_class=HTMLResponse, include_in_schema=False)
async def ui_privacy(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="privacy.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

@app.get("/ui/help", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_auth_help(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.HELP_PAGE_ENABLED or not config.SMTP_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="help.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


@app.get("/ui/docs", response_class=HTMLResponse, include_in_schema=False)
# @requires(['authenticated'], redirect="ui_auth_login")
async def ui_docs(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.DOCS_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    docs_markdown = get_docs(docs_path=config.DOCS_PATH)

    return templates.TemplateResponse(
        request=request, 
        name="docs.html.jinja", 
        context={
            **build_ui_context(),
            "docs_markdown": docs_markdown,
        }
    )


##########################
### UI Routes - Auth
##########################

@app.get("/ui/auth/login", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], status_code=404)
async def ui_auth_login(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="login.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

@app.get("/ui/auth/logout", response_class=RedirectResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
def ui_auth_logout(response: Response, request: Request, config = Depends(get_config_depends),):

    # Redirect to the homepage
    response = RedirectResponse(request.url_for("ui_home"), status_code=303)

    # Set the cookie to expire in the past, effectively removing it
    response.delete_cookie(key="access_token")

    return response


# Create user
@app.get("/ui/auth/create", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], status_code=404)
async def ui_auth_create(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if config.DISABLE_NEW_USERS:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="create_user.html.jinja", 
        context={
            **build_ui_context(),
        }
    )



# Forgot Password
@app.get("/ui/auth/forgot_password", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], status_code=404)
async def ui_auth_forgot_password(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SMTP_ENABLED or config.DISABLE_FORGOT_PASSWORD:
        raise HTTPException(status_code=404)


    return templates.TemplateResponse(
        request=request, 
        name="forgot_password.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Forgot Password Confirmation
@app.get("/ui/auth/forgot_password/{otp}", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], status_code=404)
async def ui_auth_forgot_password_confirm(otp: str, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SMTP_ENABLED or config.DISABLE_FORGOT_PASSWORD:
        raise HTTPException(status_code=404)

    try:
        # Start by verifying the one time password.
        verify = signatures.verify_key(otp, scope=['forgot_password'])
    except: 
        # Should we redirect or simply return an error response if the OTP validation fails?
        raise HTTPException(status_code=404)
        # return RedirectResponse(request.url_for("ui_auth_login"), status_code=303)

    return templates.TemplateResponse(
        request=request, 
        name="forgot_password_confirm.html.jinja", 
        context={
            'otp': otp,
            **build_ui_context(),
        }
    )

# Verify email
    # @app.get("/ui/auth/verify_email", include_in_schema=False)
    # async def ui_auth_verify_email():
    #     if not config.UI_ENABLED:
    #         raise HTTPException(status_code=404, detail="This page does not exist")


@app.get("/ui/auth/change_password", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_auth_change_password(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="change_password.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# View profile
@app.get("/ui/auth/profile/", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
def ui_auth_profile(request: Request, config = Depends(get_config_depends),):

    return templates.TemplateResponse(
        request=request, 
        name="profile.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

@app.get("/ui/auth/profile/{id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
def ui_auth_profile_other( 
    id: int, 
    request: Request, 
    config = Depends(get_config_depends),
):

    # If the user is requesting their own profile, redirect to the default profile view.
    if request.user.id == id:
        return RedirectResponse(request.url_for("ui_auth_profile"), status_code=303)

    # If other profile views are disabled or the requesting user is not an admin
    elif not config.OTHER_PROFILES_ENABLED and not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    user = session.query(User).get(id)
    if not user:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="profile_other.html.jinja", 
        context={
            **build_ui_context(),
            "target_user_id": id,
        }
    )



# Adding a bypass route to the user profile using usernames, see
# https://github.com/signebedi/libreforms-fastapi/issues/268
@app.get("/ui/auth/p/{username}", response_class=RedirectResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
def ui_auth_profile_bypass( 
    username: str, 
    request: Request, 
    config = Depends(get_config_depends),
):

    # If other profile views are disabled or the requesting user is not an admin
    if not config.OTHER_PROFILES_ENABLED and not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    user = session.query(User).filter(User.username.ilike(username)).first()

    if not user:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return RedirectResponse(request.url_for("ui_auth_profile_other", id=user.id), status_code=303)


##########################
### UI Routes - Admin
##########################


# Edit docs
@app.get("/ui/admin/edit_docs", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_edit_docs(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.DOCS_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    docs_markdown = get_docs(
        docs_path=config.DOCS_PATH, 
        render_markdown=False,
    ).strip()

    # print(docs_markdown)

    return templates.TemplateResponse(
        request=request, 
        name="admin_docs.html.jinja", 
        context={
            **build_ui_context(),
            "docs_markdown": docs_markdown,
        }
    )


# Update form config
@app.get("/ui/admin/write_form_config", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_write_form_config(request: Request, config = Depends(get_config_depends),):
    
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    form_config_str = get_form_config_yaml(config_path=config.FORM_CONFIG_PATH).strip()

    past_versions = get_form_backups()

    # print(form_config_str)

    return templates.TemplateResponse(
        request=request, 
        name="admin_form_config.html.jinja", 
        context={
            **build_ui_context(),
            "form_config_str": form_config_str,
            "past_versions": past_versions,            
        }
    )




# Edit privacy policy
@app.get("/ui/admin/config_privacy", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_privacy(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_privacy.html.jinja", 
        context={
            **build_ui_context(),
        }
    )



# Edit homepage message
@app.get("/ui/admin/config_homepage_message", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_homepage_message(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_homepage_message.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# form config lock
@app.get("/ui/admin/form_config_lock", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_form_config_lock(
    request: Request, 
    config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_form_config_lock.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Edit site config
@app.get("/ui/admin/config_site", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_site(request: Request, config = Depends(get_config_depends)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_site.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Edit relational database config
@app.get("/ui/admin/config_relational_db", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_relational_db(request: Request, config = Depends(get_config_depends)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_relational_db.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Edit document database config
@app.get("/ui/admin/config_document_db", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_document_db(request: Request, config = Depends(get_config_depends)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_document_db.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# Edit smtp config
@app.get("/ui/admin/config_smtp", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_config_smtp(request: Request, config = Depends(get_config_depends)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_config_smtp.html.jinja", 
        context={
            **build_ui_context(),
        }
    )




# Schedule application reboot
# @app.get("/ui/admin/reload_application", response_class=HTMLResponse, include_in_schema=False)
# @requires(['admin'], redirect="ui_home")
# async def ui_admin_reload_application(request: Request, config = Depends(get_config_depends)):
#     if not config.UI_ENABLED:
#         raise HTTPException(status_code=404, detail="This page does not exist")

#     if not request.user.site_admin:
#         raise HTTPException(status_code=404, detail="This page does not exist")

#     return templates.TemplateResponse(
#         request=request, 
#         name="admin_reload_application.html.jinja", 
#         context={
#             **build_ui_context(),
#         }
#     )


# Manage users
@app.get("/ui/admin/manage_users", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_manage_users(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_manage_users.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Add new user
@app.get("/ui/admin/create_user", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_create_user(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    available_groups = [g.name for g in session.query(Group).all()]

    return templates.TemplateResponse(
        request=request, 
        name="admin_create_user.html.jinja", 
        context={
            "available_groups": available_groups,
            **build_ui_context(),
        }
    )


# Edit user
@app.get("/ui/admin/update_user/{id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_update_user(id: str, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    available_groups = [g.name for g in session.query(Group).all()]
    existing_user = session.query(User).get(id)

    return templates.TemplateResponse(
        request=request, 
        name="admin_update_user.html.jinja", 
        context={
            "available_groups": available_groups,
            "existing_user": existing_user.to_dict(),
            "id": id,
            **build_ui_context(),
        }
    )


# Transaction Statistics / Logs
# *** We would pull this from the TransactionLog. This can also be the basis 
# for a "recent activity" UI route.
@app.get("/ui/admin/log", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_log(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    log_list = session.query(TransactionLog).all()

    log_list_as_dict = [l.to_dict() for l in log_list]


    # log_list_as_dict = log_list_as_dict[::-1] # If we want to reverse the order...
    # log_list_as_dict = log_list_as_dict[:10000] # Limit to the last 10,000 items...    log_list_as_dict = log_list_as_dict[:10000] # Limit to the 


    return templates.TemplateResponse(
        request=request, 
        name="admin_log.html.jinja", 
        context={
            "log": log_list_as_dict,
            **build_ui_context(),
        }
    )

# Manage groups
@app.get("/ui/admin/manage_groups", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_manage_groups(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_manage_groups.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# Create group
@app.get("/ui/admin/create_group", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_create_group(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)
    available_permissions = [
        "create",
        "read_own",
        "read_all",
        "update_own",
        "update_all",
        "delete_own",
        "delete_all",
        # "sign_own",
    ]


    return templates.TemplateResponse(
        request=request, 
        name="admin_create_group.html.jinja", 
        context={
            "form_names": form_names,
            "available_permissions": available_permissions,
            **build_ui_context(),
        }
    )

# Edit Group
@app.get("/ui/admin/update_group/{id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_update_group(id:str, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    group = session.query(Group).get(id)
    if not group:
        raise HTTPException(status_code=404, detail="This page does not exist")

    form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)
    available_permissions = [
        "create",
        "read_own",
        "read_all",
        "update_own",
        "update_all",
        "delete_own",
        "delete_all",
        # "sign_own",
    ]

    # These are the permissions already assigned to the group
    group_details = group.to_dict()

    return templates.TemplateResponse(
        request=request, 
        name="admin_update_group.html.jinja", 
        context={
            "form_names": form_names,
            "available_permissions": available_permissions,
            "group_details": group_details,
            **build_ui_context(),
        }
    )



# Create relationship
@app.get("/ui/admin/create_relationship_type", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_create_relationship_type(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")


    return templates.TemplateResponse(
        request=request, 
        name="admin_create_relationship_type.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# Manage relationship types
@app.get("/ui/admin/manage_relationship_types", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_manage_relationship_types(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_manage_relationship_types.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


# Edit Group
@app.get("/ui/admin/update_relationship_type/{id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_update_group(id:str, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    relationship_type = session.query(RelationshipType).get(id)
    if not relationship_type:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # These are the relationship details
    relationship_details = relationship_type.to_dict()

    return templates.TemplateResponse(
        request=request, 
        name="admin_update_relationship_type.html.jinja", 
        context={
            "relationship_details": relationship_details,
            **build_ui_context(),
        }
    )


# Create user relationship pairing
@app.get("/ui/admin/create_user_relationship", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_create_user_relationship(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # user_list = [x.to_dict(just_the_basics=True) for x in session.query(User).all()]
    user_list = [x.to_dict(just_the_basics=True) for x in session.query(User).order_by(User.username).all()]
    relationship_type_list = [x.to_dict() for x in session.query(RelationshipType).order_by(RelationshipType.name).all()]

    return templates.TemplateResponse(
        request=request, 
        name="admin_create_user_relationship.html.jinja", 
        context={
            "user_list": user_list,
            "relationship_type_list": relationship_type_list,
            **build_ui_context(),
        }
    )

# Manage user relationship pairings
@app.get("/ui/admin/manage_user_relationships", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_manage_user_relationships(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_manage_user_relationships.html.jinja", 
        context={
            **build_ui_context(),
        }
    )


@app.get("/ui/admin/manage_submissions", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_manage_submissions(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")


    return templates.TemplateResponse(
        request=request, 
        name="admin_manage_submissions.html.jinja", 
        context={
            **build_ui_context(),
        }
    )




@app.get("/ui/admin/system_information", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_system_information(
    request: Request, 
    config = Depends(get_config_depends),
):


    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")




    _config_dict = []

    _config_dict.append(("Site Name", config.SITE_NAME))
    _config_dict.append(("libreForms Version", __version__))
    _config_dict.append(("FastAPI Version", importlib.metadata.version("fastapi")))
    _config_dict.append(("Environment", config.ENVIRONMENT))
    _config_dict.append(("Domain", config.DOMAIN))
    _config_dict.append(("Timezone", str(config.TIMEZONE)))

    # uptime = datetime.now(config.TIMEZONE) - config.APP_STARTUP_TIME
    # _config_dict.append(("Up Since", config.APP_STARTUP_TIME))
    _config_dict.append(("UI Enabled", "Yes" if config.UI_ENABLED else "No"))
    _config_dict.append(("UI Other Profile Views Enabled", "Yes" if config.OTHER_PROFILES_ENABLED else "No"))
    _config_dict.append(("UI Search Bar Enabled", "Yes" if config.SEARCH_BAR_ENABLED else "No"))
    _config_dict.append(("UI Footer Enabled", "No" if config.DISABLE_FOOTER else "Yes"))
    _config_dict.append(("Excel Exports Enabled", "Yes" if config.EXCEL_EXPORT_ENABLED else "No"))
    _config_dict.append(("SMTP Enabled", "Yes" if config.SMTP_ENABLED else "No"))
    _config_dict.append(("Rate Limits on API Enabled", "Yes" if config.RATE_LIMITS_ENABLED else "No"))
    _config_dict.append(("Require New Users to Verify Email", "Yes" if config.REQUIRE_EMAIL_VERIFICATION else "No"))
    _config_dict.append(("Help Page Enabled", "Yes" if config.HELP_PAGE_ENABLED else "No"))
    _config_dict.append(("Docs Page Enabled", "Yes" if config.DOCS_ENABLED else "No"))
    _config_dict.append(("MongoDB Enabled", "Yes" if config.MONGODB_ENABLED else "No"))
    _config_dict.append(("Form Config Edits Enabled", "Yes" if config.FORM_CONFIG_EDITS_ENABLED else "No"))

    try:
        _config_dict.append(("Operating System", platform.platform()))
        _config_dict.append(("Architecture", platform.machine()))
        # _config_dict.append(("Memory Usage", psutil.virtual_memory().percent))
        # _config_dict.append(("CPU Usage", psutil.cpu_percent(interval=1)))


    except: pass


    return templates.TemplateResponse(
        request=request, 
        name="admin_system_information.html.jinja", 
        context={
            "config_dict": _config_dict,
            **build_ui_context(),
        }
    )


# Manage approval chains

