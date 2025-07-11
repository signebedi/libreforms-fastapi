import re, os, json, tempfile, logging, sys
import asyncio, jwt, difflib, importlib, platform
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from immutables import Map
from typing import Dict, Optional, Annotated, Any
from urllib.parse import urlparse
from markupsafe import escape
from bson import ObjectId
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from enum import Enum
import requests

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
    File,
    UploadFile,
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
    generate_dummy_password_hash,
    generate_unique_username,
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
    EmailConfigUpdateRequest,
    RequestUnregisteredForm,
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

# This import is used for caching with selective invalidation
from libreforms_fastapi.utils.parameterized_caching import parameterized_lru_cache

# Import to render more powerful email content
from libreforms_fastapi.utils.jinja_emails import ( 
    render_email_message_from_jinja,
    write_email_config_yaml,
    test_email_config,
    get_email_yaml,
)
from jinja2 import Environment, select_autoescape


# Here we set the application config using the get_config
# factory pattern defined in libreforms_fastapi.utis.config.
_env = os.environ.get('ENVIRONMENT', 'development')



# The following functions will be used to cache form stage data, 
# see https://github.com/signebedi/libreforms-fastapi/issues/62

def make_immutable_map(nested_dict):
    # Recursively convert all nested dictionaries to immutable maps
    return Map({
        k: make_immutable_map(v) if isinstance(v, dict) else v
        for k, v in nested_dict.items()
    })

@parameterized_lru_cache(maxsize=128)
def cache_form_stage_data(
    form_name: str,
    form_stages: Map,
    doc_db,  # Because this is produced using a dependency injection, it may not cache correctly... will need to test and/or modify caching behavior
):
    """
    This function wraps ManageDocumentDB.get_all_documents_by_stage() so we can cache values 
    outside the class scope, since we are using it largely as a dependency injection...
    """ 

    # We begin be instantiating an empty container to store document_id values for each stage
    stage_dict = {}

    # Then we iterate through each stage and collect each of the items 
    for stage_name, _stage_conf in form_stages.items(): # _stage_conf is not important in this function

        document_ids = [] # Reset this variable... perhaps redundant
        document_ids, created_by_list = doc_db.get_all_documents_by_stage(form_name, stage_name) # Get all values with the current stage

        # Add these values to stage_dict
        stage_dict[stage_name] = document_ids

        # We create a somewhat hackish list of created_by data as it will be needed later, but highly redundant... that said, 
        # we cannot afford to modify this interface too much...
        stage_dict[f"__created_by__{stage_name}"] = created_by_list

    return stage_dict

# @parameterized_lru_cache(maxsize=128)
@lru_cache() # Opt for a standard cache because we probably need to rebuild this entire cache when there are changes
def cache_form_stage_data_for_specified_user(
    form_name: str,
    form_stages: Map,
    current_user, # This is a sqlalchemy row

    doc_db,  # Because this is produced using a dependency injection, it may not cache correctly... will need to test and/or modify caching behavior
):
    """
    This function wraps extends cache_form_stage_data to get a list of documents that a given 
    user is eligible to approve.
    """ 

    # Get the list of documents in each stage from cached data
    all_stage_data = cache_form_stage_data(form_name, form_stages, doc_db)

    user_specific_data = []

    # Iterate through each form stage in form_stages
    for stage_name, stage_conf in form_stages.items():

        stage_specific_data = all_stage_data[stage_name]
        stage_method = stage_conf.get('method', None)
        # Start with the static form approval method
        if stage_method == "static":
            # If this user is the specified approver, then append all the stage-
            # specific data to the user's list of documents needing their action
            if current_user.email == stage_conf.target:
                user_specific_data.extend(stage_specific_data)

        # Then do group based approval
        elif stage_method == "group":
            # If the user is a member of the approving group, then add all the stage-
            # specific data to the user's list of docs needing their action
            if stage_conf.get('target', None) in current_user.to_dict(just_the_basics=True)['groups']:
                user_specific_data.extend(stage_specific_data)

        elif stage_method == "self":
            # If the user is the creator of the submission, then add all the stage-
            # specific data to the user's list of docs needing their action

            for index,item in enumerate(stage_specific_data):

                if current_user.username == all_stage_data[f"__created_by__{stage_name}"][index]:
                    user_specific_data.append(item)

        # Relationship-based approval is... complex, to say the least. This will remain unimplemented
        # for now, see https://github.com/signebedi/libreforms-fastapi/issues/332

        # We may need to add some logic here to handle or drop duplicates...

    return user_specific_data



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
            relationships: list,
        ) -> None:
        
            self.username = username
            self.id = id
            self.email = email
            self.groups = groups
            self.api_key = api_key
            self.site_admin = site_admin
            self.permissions = permissions
            self.relationships = relationships

        @property
        def is_authenticated(self) -> bool:
            return True

        @property
        def display_name(self) -> str:
            return self.username

        def __repr__(self) -> str:
            return f"LibreFormsUser(username={self.username}, id={self.id}, email={self.email}, groups={self.groups}, " \
                "api_key={self.api_key}, site_admin={self.site_admin}, permissions={self.permissions}"

        def to_dict(self): 
            return {
                'username':self.username,
                'id':self.id,
                'email':self.email,
                'groups':self.groups,
                'api_key':self.api_key,
                'site_admin':self.site_admin,
                'permissions':self.permissions,
                'relationships':self.relationships,
            }


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
                    _relationships = [x.to_dict() for x in user.relationships] + [x.to_dict() for x in user.received_relationships]


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
                relationships=_relationships,
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
        namespace='uvicorn.error',
    )

    sqlalchemy_logger = set_logger(
        environment=config.ENVIRONMENT, 
        log_file_name='sqlalchemy.log', 
        namespace='sqlalchemy.engine',
        log_level=logging.ERROR,
    )

    # document_database_logger = set_logger(
    #                 environment=config.ENVIRONMENT, 
    #                 log_file_name="document_db.log", 
    #                 namespace="document_db.log",
    # )

    # If saml is enabled, create the auth payload here, see
    # https://github.com/signebedi/libreforms-fastapi/issues/80.
    if config.SAML_ENABLED:

        # import saml dependencies 
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.utils import OneLogin_Saml2_Utils

        from libreforms_fastapi.utils.saml import generate_saml_config, verify_metadata
        
        APP_SAML_AUTH = generate_saml_config(
            domain=config.DOMAIN, 
            saml_idp_entity_id=config.SAML_IDP_ENTITY_ID, 
            saml_idp_sso_url=config.SAML_IDP_SSO_URL, 
            saml_idp_slo_url=config.SAML_IDP_SLO_URL, 
            saml_idp_x509_cert=config.SAML_IDP_X509_CERT,
            strict=config.SAML_STRICT, 
            debug=config.SAML_DEBUG, 
            saml_name_id_format=config.SAML_NAME_ID_FORMAT,
            saml_sp_x509_cert=config.SAML_SP_X509_CERT, 
            saml_sp_private_key=config.SAML_SP_PRIVATE_KEY,
        )

        # here we pull for any errors to help with logging
        metadata, errors = verify_metadata(APP_SAML_AUTH)

        if len(errors) == 0:
            logger.info("Successfully loaded SAML config")

        else:
            for error in errors:
                logger.warning(f"SAML config error: {error}")
                raise Exception ("SAML configuration error")


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
        "API_KEY_SELF_ROTATION_ENABLED": config.API_KEY_SELF_ROTATION_ENABLED,
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
    # SignatureRoles = models['SignatureRoles']
    Signing = models['Signing']

    # Adding user relationship models below, see
    # https://github.com/signebedi/libreforms-fastapi/issues/173
    RelationshipType = models['RelationshipType']
    UserRelationship = models['UserRelationship']

    logger.info('Relational database has been initialized')


    with SessionLocal() as session:
        # Here we build our initial form_stage cache... see 
        # https://github.com/signebedi/libreforms-fastapi/issues/62
        __form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)
        __doc_db = get_doc_db()

        for form_name in __form_names:

            __form_model = get_form_model(
                form_name=form_name, 
                config_path=config.FORM_CONFIG_PATH,
                session=session,
                User=User,
                Group=Group,
                doc_db=__doc_db,
            )

            # Create a recursive Map of the form_stages
            __mapped_form_stages = make_immutable_map(__form_model.form_stages)

            _ = cache_form_stage_data(
                form_name=form_name,
                form_stages=Map(__mapped_form_stages), # Need this to be immutable so it can be hashed and cached
                doc_db=__doc_db,
            )

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
        # _default_signature_role = session.query(SignatureRoles).get(1)

        # if not _default_signature_role:
        #     # If not, create and add the new signature for the example_form
        #     _default_signature_role = SignatureRoles(
        #         id=1, 
        #         role_name="default signature role", 
        #         role_method="signature",
        #         form_name="example_form"
        #     )
        #     session.add(_default_signature_role)
        #     session.commit()
        #     logger.info("Default signature role created")
        # else:
        #     logger.info("Default signature role already exists")



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
        # Cowabunga! We'll see if this causes log handler issues. Added in
        # https://github.com/signebedi/libreforms-fastapi/issues/326. We
        # should implement a singleton pattern for log objects used in dependency
        # injections, see https://github.com/signebedi/libreforms-fastapi/issues/330.
        logger=logger if config.ENVIRONMENT == "development" else None,
    )

    return mailer

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
# Here we define an API key header for the api view functions.
X_API_KEY = APIKeyHeader(name="X-API-KEY")



# This is a reimplementation of api_key_auth(), see below. This is implemented so 
# we can selectively permit additional scopes, specifically an api_key_single_use
# scope, see https://github.com/signebedi/libreforms-fastapi/issues/357.
def api_key_auth_allow_single_use(x_api_key: str = Depends(X_API_KEY)):
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

        # Add this here as part of https://github.com/signebedi/libreforms-fastapi/issues/357. 
        # The crux is that we may sometimes have single-use API keys under the `api_key_single_use`
        # scope. These, we want to validate and expire immediately on the core assumption that, once 
        # used, they cannot be used again. We add it here under an exception handler because we
        # assume the majority of requests will NOT be single use API keys. This should work because
        # ScopeMismatch is the last check that the sqlalchemy_signing library does, so all the other
        # exceptions have precedence, and a ScopeMismatch will only occur if all other aspects of a
        # signing key are already valid. ***THERE ARE RISKS TO THIS METHOD*** and, as a result of these
        # risks, we've limited its use SOLELY to the api_form_create view function.

        try: 
            verify = signatures.verify_key(x_api_key, scope=['api_key_single_use'])
            
            # If it's valid, we expire the key immediately, outside the scope of the API route
            _ = signatures.expire_key(x_api_key)

        except:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )

    except KeyExpired:
        raise HTTPException(
            status_code=401,
            detail="API key expired"
        )

    # This logic is implemented in most API routes. Adding it here would reduce
    # boilerplate, but I am going to hold off on doing so for right now. However,
    # we can also use this to update the last_login field ... if we want the API
    # to count toward that, since we are adding auto-lock after inactive periods,
    # see https://github.com/signebedi/libreforms-fastapi/issues/231.
    # with get_db() as session:
    #     user = session.query(User).filter_by(api_key=x_api_key).first()
    #     if not user:
    #         raise Exception("User does not exist")
    #     if not user.active:
    #         raise Exception("User is not active")



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

    # This logic is implemented in most API routes. Adding it here would reduce
    # boilerplate, but I am going to hold off on doing so for right now. However,
    # we can also use this to update the last_login field ... if we want the API
    # to count toward that, since we are adding auto-lock after inactive periods,
    # see https://github.com/signebedi/libreforms-fastapi/issues/231.
    # with get_db() as session:
    #     user = session.query(User).filter_by(api_key=x_api_key).first()
    #     if not user:
    #         raise Exception("User does not exist")
    #     if not user.active:
    #         raise Exception("User is not active")


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
                    subject, content = render_email_message_from_jinja(
                        'transaction_log_error', 
                        config.EMAIL_CONFIG_PATH,
                        config=config, 
                        user=user, 
                        current_time=current_time, 
                        endpoint=endpoint, 
                        query_params=query_params, 
                        remote_addr=remote_addr
                    )

                    # print(subject, content)

                    mailer.send_mail( 
                        subject=subject, 
                        content=content, 
                        to_address=config.HELP_EMAIL,
                    )

async def check_key_rotation(
    period: int = 21600, 
    time_until: int = 24,
    config = get_config(_env),
    mailer = get_mailer(),
):

    while True:
        await asyncio.sleep(period)

        # Generally, the behavior we are looking for when the expiration date has been reached 
        # for each given scope for this applicataion conforms to the following logic:
        # api_key < rotate
        # api_key_single_use < disable
        # email_verification < disable
        # forgot_password < disable

        with SessionLocal() as session:

            # all_keys_debug = signatures.query_keys()
            # logger.info(f'Key rotation started. {all_keys_debug}')

            # Query for signatures of all scopes that expire in the next hour
            keypairs = signatures.rotate_keys(time_until=time_until, scope=['api_key'])

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
                session.commit()

                if config.SMTP_ENABLED:

                    subject, content = render_email_message_from_jinja(
                        'api_key_rotation', 
                        config.EMAIL_CONFIG_PATH,
                        config=config, 
                        user=user, 
                    )

                    # print(subject, content)
                    mailer.send_mail(subject=subject, content=content, to_address=user.email)

        logger.info(f'Ran key rotation - {len(keypairs)} key/s rotated')

@app.on_event("startup")
async def start_check_key_rotation():
    # We've increased the overall period associated with this cycle to 
    # six hours, while the function itself rotates keys that will expire 
    # in the next 24 hours. Because
    task = asyncio.create_task(check_key_rotation())

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


def run_event_hooks(
    document_id:str,
    document:dict,
    form_name:str,
    event_hooks: list[dict[str, Any]],
    config,
    doc_db,
    mailer,
    session,
    user,
):

    # print("\n\n\n", event_hooks)

    for event in event_hooks:

        # Implemented in https://github.com/signebedi/libreforms-fastapi/issues/373
        if event['type'] == "http_request":
            """
            This will submit an http request to the designated target and include 
            the relevant headers and body passed by the system. You also need to 
            specify the HTTP method (get, post, patch, put, delete) for the request. 
            There are three ways to pass data: static, from_form, and jinja2. Jinja2 
            will allow you to embed values from within the form itself into a jinja2 
            string.
            """


            class HTTPMethod(str, Enum):
                """An Enum encapsulating the set of supported HTTP methods"""
                get = "get"
                post = "post"
                put = "put"
                patch = "patch"
                delete = "delete"

            url = event.get('target', None)
            if not url:
                continue
            method: HTTPMethod = event.get('method', HTTPMethod.post).lower() # Put this in lowercase, assess against an Enum

            """
            Supported options:
                params - (optional) Dictionary, list of tuples or bytes to send in the query string for the Request.
                data - (optional) Dictionary, list of tuples, bytes, or file-like object to send in the body of the Request.
                json - (optional) A JSON serializable Python object to send in the body of the Request.
                headers - (optional) Dictionary of HTTP Headers to send with the Request.
            """

            headers = event.get('headers', {})
            data = event.get('data', {})
            _json = event.get('json', {})
            params = event.get('params', {})


            # Here we create a jinja env
            env = Environment(
                autoescape=select_autoescape(['html', 'xml']),
            )

            processed_headers = {} 
            for key,data_conf in headers.items():
                value_method = data_conf.get('value_method', "static")
                value_placeholder = data_conf.get('value', "")
                
                if value_method == "static":
                    value = value_placeholder
                elif value_method == "from_form":
                    if value_placeholder.startswith("__metadata__"):
                        value = document["metadata"].get(value_placeholder[12:], "")
                    else:
                        value = document["data"].get(value_placeholder, "")
                elif value_method == "jinja2":
                    template_str = env.from_string(value_placeholder)
                    try:
                        value = template_str.render(**document)
                    except (UndefinedError, TemplateError) as e:
                        # Log the error and either use a default value or skip
                        value = ""  #  Eg, this seems like a good enough default for now

                elif value_method == "jinja2_dict":
                    template_str = env.from_string(value_placeholder)
                    on_error = data_conf.get('on_error', 'skip_field')
                    default_value = data_conf.get('default', {})
                    
                    try:
                        rendered = template_str.render(**document)
                        value = json.loads(rendered)
                        if not isinstance(value, dict):
                            # Handle case where JSON is valid but result is not a dict
                            raise ValueError("Rendered template did not produce a dictionary")
                    except (UndefinedError, TemplateError, json.JSONDecodeError, ValueError) as e:
                        if on_error == "skip_field":
                            continue  # Skip to next field in the loop
                        elif on_error == "empty_dict":
                            value = {}
                        elif on_error == "use_default":
                            value = default_value
                        elif on_error == "fail":
                            raise  # Re-raise the original exception
                        else:
                            # Default fallback if on_error value is invalid
                            continue  # Skip field as default behavior

                else:
                    value = ""

                processed_headers[key] = value

            processed_data = {} 
            for key,data_conf in data.items():
                value_method = data_conf.get('value_method', "static")
                value_placeholder = data_conf.get('value', "")
                
                if value_method == "static":
                    value = value_placeholder
                elif value_method == "from_form":
                    if value_placeholder.startswith("__metadata__"):
                        value = document["metadata"].get(value_placeholder[12:], "")
                    else:
                        value = document["data"].get(value_placeholder, "")
                elif value_method == "jinja2":
                    template_str = env.from_string(value_placeholder)
                    value = template_str.render(**document)
                elif value_method == "jinja2_dict":
                    template_str = env.from_string(value_placeholder)
                    try:
                        value = json.loads(template_str.render(**document))
                    except json.JSONDecodeError:
                        value = {}  # Default to empty dict if parsing fails
                else:
                    value = ""

                processed_data[key] = value

            processed_json = {} 
            for key,data_conf in _json.items():
                value_method = data_conf.get('value_method', "static")
                value_placeholder = data_conf.get('value', "")
                
                if value_method == "static":
                    value = value_placeholder
                elif value_method == "from_form":
                    if value_placeholder.startswith("__metadata__"):
                        value = document["metadata"].get(value_placeholder[12:], "")
                    else:
                        value = document["data"].get(value_placeholder, "")
                elif value_method == "jinja2":
                    template_str = env.from_string(value_placeholder)
                    value = template_str.render(**document)
                elif value_method == "jinja2_dict":
                    template_str = env.from_string(value_placeholder)
                    try:
                        value = json.loads(template_str.render(**document))
                    except json.JSONDecodeError:
                        value = {}  # Default to empty dict if parsing fails
                else:
                    value = ""

                processed_json[key] = value

            processed_params = {} 
            for key,data_conf in params.items():
                value_method = data_conf.get('value_method', "static")
                value_placeholder = data_conf.get('value', "")
                
                if value_method == "static":
                    value = value_placeholder
                elif value_method == "from_form":
                    if value_placeholder.startswith("__metadata__"):
                        value = document["metadata"].get(value_placeholder[12:], "")
                    else:
                        value = document["data"].get(value_placeholder, "")
                elif value_method == "jinja2":
                    template_str = env.from_string(value_placeholder)
                    value = template_str.render(**document)
                elif value_method == "jinja2_dict":
                    template_str = env.from_string(value_placeholder)
                    try:
                        value = json.loads(template_str.render(**document))
                    except json.JSONDecodeError:
                        value = {}  # Default to empty dict if parsing fails
                else:
                    value = ""

                processed_params[key] = value


            # Now we build our request... only including a field if it is not blank

            request_dict = {"method": method, "url":url,}

            if processed_headers:
                request_dict['headers'] = processed_headers
            if processed_data:
                request_dict['data'] = processed_data
            if processed_json:
                request_dict['json'] = processed_json
            if processed_params:
                request_dict['params'] = processed_params

            # And submit it. Should we check the response info?
            # >>>> Yes, I think so. This will help serve a logging function, if nothing else.
            response = requests.request(**request_dict)


            # Implemented in https://github.com/signebedi/libreforms-fastapi/issues/392
            # Record response to metadata if configured
            # if event.get('record_response', True):
                
            #     # Capture response data
            #     response_data = {
            #         "timestamp": datetime.utcnow().isoformat() + "Z",
            #         "url": url,
            #         "method": method.upper(),
            #         "status_code": response.status_code,
            #         "headers": dict(response.headers),
            #         "success": 200 <= response.status_code < 300,
            #     }
                
            #     # Optionally capture response body for small text/JSON responses
            #     try:
            #         content_type = response.headers.get('content-type', '').lower()
            #         if ('json' in content_type or 'text' in content_type) and len(response.content) < 10000:
            #             if 'json' in content_type:
            #                 try:
            #                     response_data["body"] = response.json()
            #                 except json.JSONDecodeError:
            #                     response_data["body"] = response.text
            #             else:
            #                 response_data["body"] = response.text
            #         else:
            #             response_data["body_truncated"] = True
            #             response_data["content_length"] = len(response.content)
            #     except Exception:
            #         response_data["body_error"] = True
                
            #     # Get current http_responses or initialize empty list
            #     current_responses = document.get("metadata", {}).get("http_responses", [])
            #     current_responses.append(response_data)
                
            #     # Limit to most recent 50 responses
            #     if len(current_responses) > 50:
            #         current_responses = current_responses[-50:]
                
            #     # Update document metadata using doc_db
            #     metadata_update = {
            #         "http_responses": current_responses,
            #     }
                
            #     doc_db.update_document(
            #         form_name=form_name,
            #         document_id=document_id,
            #         json_data="{}",  # Empty JSON data since we're only updating metadata
            #         metadata=metadata_update,
            #         exclude_deleted=False,
            #         allow_unchanged_data=True,
            #     )


            # print(document)
            # print(request_dict)
            # print(repr(response))
            # print(response.status_code)

            
            """
            - type: http_request
            target: https://api.jira.com/api/v1/create/
            method: post
            headers:
                X-API-KEY:
                value_method: static
                value: laksjdfhkjasdhfwj2317-sas-d
            data:
                request_type:
                    value_method: from_form
                    value: request_type
                description:
                    value_method: jinja2
                    value: "This is the description of a {{data.request_type}} submitted by {{metadata.created_by}}"
            """

        # Implemented in https://github.com/signebedi/libreforms-fastapi/issues/313
        if event['type'] == "send_mail":

            if not config.SMTP_ENABLED:
                continue

            template = event.get('template', None)
            target = event.get('target', None)
            if not template or not target:
                continue

            method = event.get('method', None)

            if method == "static":
                emails = [target]

            elif method == "from_user_field":

                if target.startswith("__metadata__"):
                        _username = document['metadata'].get(target[12:], None)
                else:
                    _username = document['data'].get(target, None)

                _user = session.query(User).filter_by(username=_username).first()
                if not _user:
                    continue

                emails = [_user.email]

            elif method == "group":
                group = session.query(Group).filter(Group.name == target).one_or_none()

                if not group:
                    continue

                # https://stackoverflow.com/a/12422921
                # emails = ", ".join([x.email for x in group.users])
                # The formulation above was causing errors when sending mail, see 
                # https://github.com/signebedi/libreforms-fastapi/issues/326.
                emails = [x.email for x in group.users]

            elif method == "relationship":

                # Here we let admins set this as a reciprocal relationship, but it defaults to 
                # a regular one.
                use_reciprocal_relationship = event.get('use_reciprocal_relationship', False)

                if use_reciprocal_relationship:

                    # Query the UserRelationship model to get the recprocal relationship instances
                    relationships = session.query(UserRelationship).join(RelationshipType).filter(
                        UserRelationship.related_user_id == user.id,
                        RelationshipType.reciprocal_name == target
                    ).all()

                    if not relationships:
                        continue 

                    # Retrieve all related users ... need to think through whether this will
                    # run into type-1 and type-2 errors; selecting reciprocal relationships
                    # for the wrong users, or failing to select from reciprical relationships
                    # when we want it to...
                    related_users = [relationship.user for relationship in relationships]

                else:
                    # Query the UserRelationship model to get the relationship instances
                    relationships = session.query(UserRelationship).join(RelationshipType).filter(
                        UserRelationship.user_id == user.id,
                        RelationshipType.name == target
                    ).all()
                    
                    if not relationships:
                        continue 

                    related_users = [relationship.related_user for relationship in relationships]

                # https://stackoverflow.com/a/12422921
                # emails = ", ".join([x.email for x in related_users])
                # The formulation above was causing errors when sending mail, see 
                # https://github.com/signebedi/libreforms-fastapi/issues/326.
                emails = [x.email for x in related_users]



            else:
                continue

            # print("\n\n\n\n\n\n", method, "\n\n\n\n", emails)

                
            subject, content = render_email_message_from_jinja(
                template, 
                config.EMAIL_CONFIG_PATH,
                config=config, 
                form_name=form_name,
                document_id=document_id,
                document=document,
            )

            mailer.send_mail(
                subject=subject, 
                content=content,
                to_address=emails,
            )

            # Ugh .. until we can figure out how to send to multiple email targets, 
            # which has been giving difficulty, we will send each individually. See
            # https://github.com/signebedi/libreforms-fastapi/issues/326.
            # for _email_target in emails:
            #     mailer.send_mail(
            #         subject=subject, 
            #         content=content,
            #         to_address=_email_target,
            #     )


        # Implemented in https://github.com/signebedi/libreforms-fastapi/issues/314
        elif event['type'] == "set_value":

            permitted_methods = ['static', 'from_field']

            selector_method = event.get('selector_method', None)
            value_method = event.get('value_method', None)

            target_form_name = event.get('target_form_name', None)
            target_field_name = event.get('target_field_name', None)
            target_document_id = event.get('target_document_id', None)

            value = event.get('value', None)

            if not selector_method or not value_method or not target_field_name:
                continue

            if selector_method not in permitted_methods or value_method not in permitted_methods:
                continue

            if target_form_name not in doc_db._get_form_names():
                continue

            # This has likely been rendered obsolete by https://github.com/signebedi/libreforms-fastapi/issues/311
            # document = doc_db.get_one_document(
            #     form_name=form_name,
            #     document_id=document_id, 
            # )

            if not document:
                continue


            metadata = {
                doc_db.last_editor_field: user.username,
            }

            # Identify the value, parsing metadata fields
            if value_method == "static":
                _value = value
            
            elif value_method == "from_field":
                # Get the current form's value of a given field
                if value.startswith("__metadata__"):
                    _value = document['metadata'].get(value[12:], None)
                else:
                    _value = document['data'].get(value, None)

            else:
                continue

            data = {}

            if target_field_name.startswith("__metadata__"):
                metadata[target_field_name[12:]] = _value
            else: 
                data[target_field_name] = _value

            # Dump to JSON
            json_data = json.dumps(data)

            # Determine the target document_id

            if selector_method == "static":
                _target_document_id = target_document_id

            elif selector_method == "from_field":
                if target_document_id.startswith("__metadata__"):
                    _target_document_id = document['metadata'].get(target_document_id[12:], None)
                else:
                    _target_document_id = document['data'].get(target_document_id, None)

            else:
                continue

            if not _target_document_id:
                continue


            # print("\n\n\n\n", _target_document_id, "\n\n\n", _value)

            # Write to the target
            d = doc_db.update_document(
                form_name = target_form_name, 
                document_id = _target_document_id, 
                json_data=json_data,
                metadata=metadata, 
                exclude_deleted=False,
                allow_unchanged_data=True,
            )



        elif event['type'] == "create_submission":


            # This value is distinguishable from the regular form_name, which
            # corresponds to the source form. This is the target form.
            target_form_name = event.get('form_name', None)
            values = event.get('values', {})

            if not target_form_name or not values:
                continue

            # This has likely been rendered obsolete by https://github.com/signebedi/libreforms-fastapi/issues/311
            # document = doc_db.get_one_document(
            #     form_name=form_name,
            #     document_id=document_id, 
            # )

            if not document:
                continue

            # Yield the pydantic form model
            FormModel = get_form_model(
                form_name=target_form_name, 
                config_path=config.FORM_CONFIG_PATH,
                session=session,
                User=User,
                Group=Group,
                doc_db=doc_db,
            )

            # Prepare data for the new submission
            data = {}
            metadata = {
                doc_db.created_by_field: user.username,  # Set the creator as the current user
                doc_db.last_editor_field: user.username,  # Set the last editor as the current user
                doc_db.linked_to_user_field: FormModel.user_fields, # We need to pass this info to link fields to external users
                doc_db.linked_to_form_field: FormModel.form_fields, # We need to pass this info to link fields to external submission

            }

            for field_name, field_config in values.items():
                method = field_config.get('method', None)
                value = field_config.get('value', None)

                if not method or not value:
                    continue

                # Handle static value
                if method == 'static':
                    data[field_name] = value

                # Handle value from another field
                elif method == 'from_field':
                    # Check if it's a metadata field
                    if value.startswith("__metadata__"):
                        data[field_name] = document['metadata'].get(value[12:], None)
                    else:
                        data[field_name] = document['data'].get(value, None)

            # Insert the new document into the target form
            new_document = doc_db.create_document(
                form_name=target_form_name,
                json_data=json.dumps(data),
                metadata=metadata
            )

"""
EXAMPLES:
on_create:
  - type: send_mail
    template: form_message
    method: static
    target: bob@hr.example.com

  - type: send_mail
    template: form_message2
    method: group
    target: default

  - type: send_mail
    use_reciprocal_relationship: false
    template: form_message3
    method: relationship
    target: some_relationship

  - type: send_mail
    use_reciprocal_relationship: true
    template: form_message4
    method: relationship
    target: some_reciprical relationship_name

    # Here we set a from_field target document, with a static value
  - type: set_value
    selector_method: from_field
    value_method: static
    target_form_name: leave_requests
    target_field_name: approval_status
    target_document_id: request_id
    value: "approved"

    # Here we set a from_field target document, with a from_field value
  - type: set_value
    selector_method: from_field
    value_method: from_field
    target_form_name: leave_requests
    target_field_name: approver
    target_document_id: request_id
    value: __metadata__created_by

    # Here we set a static target document, with a from_field value
  - type: set_value
    selector_method: static
    value_method: from_field
    target_form_name: master_leave_record
    target_field_name: approver
    target_document_id: 664eab5c46c99199a7b22ab7
    value: __metadata__created_by

    # Here we create new example_form with both static and from_field values, which include __metadata__ fields
  - type: create_submission
    form_name: example_form
    values:
      field_name_1:
        method: static
        value: "This is a static value"
      field_name_2:
        method: from_field
        value: some_field_name
      field_name_3:
        method: from_field
        value: __metadata__created_by

"""


# Request anonymous / unregistered form submission link
@app.post("/api/form/request_unregistered/{form_name}")
async def api_form_request_unregistered(
    form_name: str, 
    request_data: RequestUnregisteredForm,
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db), 
):
    """
    This API route allows unregistered users (or existing users who are unauthenticated) 
    to request single use links to submit a given form. This will be linked with their 
    user accounts, if one exists or is created for them.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    # If form submission is not enabled, raise an HTTP error
    if not FormModel.unregistered_submission_enabled:
        raise HTTPException(status_code=404)

    # The 'open' method is not implemented yet but will be implemented 
    # by https://github.com/signebedi/libreforms-fastapi/issues/358
    if FormModel.unregistered_submission_method == "open":
        raise HTTPException(status_code=501)

    # If the method is not open, we can assume it will be either 
    # 'email_validated_create_user' or 'email_validated'.


    # If SMTP is not enabled, raise an HTTP exception because, other than
    # 'open', all unregistered form submission methods require email.
    if not config.SMTP_ENABLED:
        raise HTTPException(status_code=404)

    # Check if a user is associated with the email address given.
    user = session.query(User).filter_by(email=request_data.email).first()

    # If there is not an existing user but the unregistered form submission method 
    # is 'email_validated_create_user', then create a new user.
    if FormModel.unregistered_submission_method == 'email_validated_create_user':

        # If we've gotten to this stage, then we will use the email template describing a newly created user 
        # and submission link
        email_template_name = "unregistered_submission_request_new_user"

        if not user:

            base_username = request_data.email.split('@')[0]
            new_username = base_username
            # I'm not sure how I feel about the whole "random number appended to the end" approach
            # but it works for now.
            while session.query(User).filter_by(username=new_username).first() is not None:
                new_username = generate_unique_username(base_username)

            user = User(
                email=request_data.email, 
                username=new_username,
                password=generate_dummy_password_hash(),
                active=True,
                opt_out=False,
            )

            # Add to the default group
            _group = session.query(Group).filter_by(id=1).first()
            user.groups.append(_group)

            # Create the users API key with a 365 day expiry
            expiration = 8760
            api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=request_data.email)
            user.api_key = api_key

            # Here we add user key pair information, namely, the path to the user private key, and the
            # contents of the public key, see https://github.com/signebedi/libreforms-fastapi/issues/71.
            ds_manager = DigitalSignatureManager(username=new_username, env=config.ENVIRONMENT)
            ds_manager.generate_rsa_key_pair()
            user.private_key_ref = ds_manager.get_private_key_file()
            user.public_key = ds_manager.public_key_bytes

            session.add(user)
            session.commit()
        
        api_key = user.api_key

    # Now, if there is a user, we send an email with their API key, not a single use key. 
    # If not, we generate a single use key.
    if not user:

        # If we've gotten to this stage, then we will use the email template describing single use keys
        email_template_name = "unregistered_submission_request_single_use_key"

        # If the unregistered form submission method is not 'email_validated', then there has been a logic failure
        if FormModel.unregistered_submission_method != "email_validated":
            raise HTTPException(status_code=500)

        api_key = signatures.write_key(scope=['api_key_single_use'], expiration=4, active=True, email=request_data.email)

    # Send an email
    subject, content = render_email_message_from_jinja(
        email_template_name,
        config.EMAIL_CONFIG_PATH,
        config=config,
        user=user,
        api_key=api_key,
        form_name=form_name, 
    )

    background_tasks.add_task(
        mailer.send_mail,
        subject=subject, 
        content=content, 
        to_address=request_data.email,
    )

    return {'status': "success"} # Simple return

# Create form
@app.post("/api/form/create/{form_name}", dependencies=[Depends(api_key_auth_allow_single_use)])
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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
    # user_fields, form_fields = form_data.get_additional_metadata()


    json_data = form_data.model_dump_json()
    # print("\n\n\n", json_data)
    data_dict = form_data.model_dump()
    # print("\n\n\n", data_dict)

    # If this form permits unregistered form submission, then we validate the API key scope
    # and determine whether there is a user account linked to the request.
    unregistered_submission = False
    if FormModel.unregistered_submission_enabled:
        
        key_data = signatures.get_key(key)
        key_scope = key_data['scope']

        # When the unregistered form is submitted using an existing user, then
        # that user's API key is used automatically, meaning that the scope
        # of that key will simply be 'api_key'... as such, we can assume that,
        # when a key scope is 'api_key_single_use', that there is no user 
        # associated with the request and that the form is being submitted 
        # unregistered. This approach is very useful but creates a phenomenon 
        # where users can use their API key to directly submit a form without 
        # logging in... this might not be any more or less secure than password
        # based authentication, but can have security implications...
        if key_scope == 'api_key_single_use':
            unregistered_submission = True
            key_email = key_data['email']


    # See comments above. Only check the user permissions if the user exists. This COULD
    # create a situation where a user is created during the unregistered form submission 
    # process, but the default group they are added to does not have requisite permissions...
    if not unregistered_submission:
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
        # Because unregistered form submission that does not link to a user account will cause the
        # created_by and last_editor field to become unreadable, admins should be careful about 
        # enabling this when form approval processes are being carried out. 
        doc_db.created_by_field: user.username if not unregistered_submission else key_email,
        doc_db.last_editor_field: user.username if not unregistered_submission else key_email,
        # doc_db.linked_to_user_field: user_fields, 
        # doc_db.linked_to_form_field: form_fields,
        # Pull these directly from the model attrs:
        doc_db.linked_to_user_field: FormModel.user_fields, 
        doc_db.linked_to_form_field: FormModel.form_fields,
        doc_db.unregistered_form_field: unregistered_submission,
    }

    # print("\n\n\n\n\n\n", form_data.form_stages)

    # Get the initial form stage, see https://github.com/signebedi/libreforms-fastapi/issues/62
    initial_form_stage = None
    for form_stage, form_conf in form_data.form_stages.items():
        if form_conf.get('initial_stage', False):
            initial_form_stage = form_stage


    # print("\n", initial_form_stage)

    # Add our initial form stage, if it exists
    if initial_form_stage is not None:
        metadata[doc_db.form_stage_field] = initial_form_stage

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


    # Validate whether default background emails should be sent for this form. 
    # See https://github.com/signebedi/libreforms-fastapi/issues/356
    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_created' not in FormModel.disable_default_emails)

    # Send email
    if config.SMTP_ENABLED and check_background_email:

        subject, content = render_email_message_from_jinja(
            'form_created', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )

        # print(subject, content)

        background_tasks.add_task(
            mailer.send_mail,
            subject=subject, 
            content=content,
            to_address=user.email if not unregistered_submission else key_email,
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

    # run_event_hooks(
    background_tasks.add_task(
        run_event_hooks,
        document_id=document_id, 
        document=d,
        form_name=form_name,
        event_hooks=form_data.event_hooks['on_create'],
        config=config,
        doc_db=doc_db,
        mailer=mailer,
        session=session,
        user=user, # WARNING: This will probably break when forms are submitted unregistered
    )

    return {
        "message": "Form submission received and validated", 
        "document_id": document_id, 
        "data": d,
    }



# Read all forms that need action
@app.get("/api/form/read_all_needing_action", dependencies=[Depends(api_key_auth)])
async def api_form_read_all_needing_action(
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),
    return_full_records_flat: bool = False,
    return_count_only: bool = False,

):
    """
    This method returns a dict of all the documents needing action from the current user. Pass the 
    `return_full_records_flat` option to get all the records in full, and to flatten these into a 
    list of documents. Pass the `return_count_only` option to return an int count of actions needed.
    """


    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()


    # Here we build our form_stage cache... see 
    # https://github.com/signebedi/libreforms-fastapi/issues/62
    __form_names = get_form_names(config_path=config.FORM_CONFIG_PATH)

    dict_of_return_values = {}

    for _form_name in __form_names:

        __form_model = get_form_model(
            form_name=_form_name, 
            config_path=config.FORM_CONFIG_PATH,
            session=session,
            User=User,
            Group=Group,
            doc_db=doc_db,
        )


        # Create a recursive Map of the form_stages
        __mapped_form_stages = make_immutable_map(__form_model.form_stages)

        # print ('\n\n\n', __mapped_form_stages)

        __documents = cache_form_stage_data_for_specified_user(
            form_name=_form_name,
            form_stages=__mapped_form_stages, # Need this to be immutable so it can be hashed and cached
            current_user=user,
            doc_db=doc_db,
        )

        dict_of_return_values[_form_name] = __documents


    if return_count_only:

        __record_count = sum(len(records) for records in dict_of_return_values.values())

        return {"record_count": __record_count}

    if return_full_records_flat:

        __temp = []
        seen_records = set()

        for __form_name, __records in dict_of_return_values.items():
            for __record_id in __records:
                if __record_id not in seen_records:
                    __record = doc_db.get_one_document(
                        form_name=__form_name, 
                        document_id=__record_id, 
                    )
                    __temp.append(__record)
                    seen_records.add(__record_id)

        return {"documents": __temp}


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


    return {"documents": dict_of_return_values}


# Read all forms that reference the given form_name and document_id
@app.get("/api/form/get_linked_refs/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
async def api_form_get_linked_references(
    form_name: str, 
    document_id: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),

):
    """
    This method returns a list of forms that reference the given form_name and document_id
    in one of their fields. These are sometimes called linked references, or backrefs. It 
    returns full records by default.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Here we build a full structure containing all the form field links for each form
    dict_of_fields_linked_to_forms = {} # This might not be relevant ... We will see.

    # Now we build a dict for linked fields _applicable_ to the given form_name
    dict_of_relevant_links = {}

    for _form_name in get_form_names(config_path=config.FORM_CONFIG_PATH):

        dict_of_relevant_links[_form_name] = []

        __form_model = get_form_model(
            form_name=_form_name, 
            config_path=config.FORM_CONFIG_PATH,
            session=session,
            User=User,
            Group=Group,
            doc_db=doc_db,
        )

        dict_of_fields_linked_to_forms[_form_name] = __form_model.form_fields

        for field_name, linked_form in __form_model.form_fields.items():
            # If this field links to the form that this query is concerned with, then add it to the list
            if linked_form == form_name:
                dict_of_relevant_links[_form_name].append(field_name)


    documents = []

    for _form_name, _linked_fields in dict_of_relevant_links.items():

        # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
        # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
        try:
            user.validate_permission(form_name=_form_name, required_permission="read_all")
            limit_query_to = False
        except Exception as e:

            try:
                user.validate_permission(form_name=_form_name, required_permission="read_own")
                limit_query_to = user.username

            except Exception as e:
                raise HTTPException(status_code=403, detail=f"{e}")


        for _linked_field in _linked_fields:
            _documents = []
            # This query param will only return that matches the given document_id
            query_params = {"data":{_linked_field: {"operator": "==","value": document_id}}}

            _documents = doc_db.get_all_documents(
                form_name=_form_name, 
                limit_users=limit_query_to,
                exclude_journal=True,
                # collapse_data=True,
                # sort_by_last_edited=True,
                # newest_first=True,
                query_params=query_params,
            )

            documents.extend(_documents) 
        
    # Drop duplicates and sort!
    unique_documents = {}
    for doc in documents:
        doc_id = doc['metadata']['document_id']

        # Replace the document if this one is newer
        if doc_id not in unique_documents:
            unique_documents[doc_id] = doc

    # Now we have a dictionary of unique documents; we need to sort them by 'last_modified'
    sorted_documents = sorted(
        unique_documents.values(), 
        key=lambda x: datetime.fromisoformat(x['metadata']['last_modified'].replace('Z', '+00:00')),
        reverse=True
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

    return sorted_documents




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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


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


    # Yield the pydantic form model, solely for the event hooks
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # Here we implement event hooks, see
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    # run_event_hooks(
    background_tasks.add_task(
        run_event_hooks,
        document_id=document_id, 
        document=document,
        form_name=form_name,
        event_hooks=FormModel.event_hooks['on_read'],
        config=config,
        doc_db=doc_db,
        mailer=mailer,
        session=session,
        user=user,
    )


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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    user = session.query(User).filter_by(api_key=key).first()
    

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not format in available_formats:
        raise HTTPException(status_code=404, detail=f"Invalid format. Must choose from {str(available_formats)}")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


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


class SortMethod(str, Enum):
    ascending = "ascending"
    descending = "descending"

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
    set_length: int = 0,
    return_when_empty: bool = False,
    query_params: Optional[str] = Query(None),
    sort_by: str = "__metadata__created_date",
    sort_method: SortMethod = SortMethod.ascending, # Make this an enum of options
    # Deprecated in https://github.com/signebedi/libreforms-fastapi/issues/374
    sort_by_last_edited: bool = False, # Deprecated
    newest_first: bool = False, # Deprecated
):
    """
    Retrieves all documents of a specified form type, identified by the form name in the URL.
    It verifies the form's existence, checks user permissions, retrieves documents from the 
    database, and logs the query. 
    
    You can pass `flatten`=true to return data in a flat format.

    You can pass `escape`=true to escape output. 
    
    You can pass `simple_response`=true to receive just the data as a response. 
    
    You can pass `exclude_journal`=true to exclude the document journal, which can sometimes 
    complicate data handling because of its nested nature. 
    
    You can pass `stringify_output`=true if you would like output types coerced into string 
    format.
    
    You can pass `set_length`=some_int if you want to limit the response to a certain number of 
    documents. 
    
    If you want the endpoint to return empty lists instead of raising an error, then pass 
    `return_when_empty`=true. 
    
    You can pass `query_params` as a url-encoded dict to filter data using the ==, !=, >, >=, 
    <, <=, in, and nin operators. Example usage of this param: {"data":{"age": {"operator": 
    ">=", "value": 21},"name": {"operator": "==","value": "John"}}}.

    You can pass `sort_by` to specify the field to sort by. The default is __metadata__created_date. 
    Valid options include any sortable field in the document.

    You can pass `sort_method` to determine the sort order. Use "ascending" to order from 
    oldest to newest, or "descending" for the reverse. The default is "ascending".

    Deprecated params:
        You can pass `sort_by_last_edited`=True if you want to sort by most recent changes. You can 
        pass `newest_first`=True if you want the newest results at the top of the results. This 
        applies to the created_at field, you can pair this option with the `sort_by_last_edited`=True 
        param to get the most recently modified forms at the top.
        
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


    # print("\n\n\n",query_params)

    # Decode the JSON string to a dictionary
    if query_params:
        try:
            query_params = json.loads(query_params)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid query_params format. Must be a JSON string.")

    documents = doc_db.get_all_documents(
        form_name=form_name, 
        limit_users=limit_query_to,
        escape_output=escape,
        collapse_data=flatten,
        exclude_journal=exclude_journal,
        stringify_output=stringify_output,
        sort_by=sort_by,
        sort_method=sort_method,
        # sort_by_last_edited=sort_by_last_edited,
        # newest_first=newest_first,
        query_params=query_params,
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.EXCEL_EXPORT_ENABLED:
        raise HTTPException(status_code=404)

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")



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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    # update_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES update_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="update_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="update_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


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


    # Validate whether default background emails should be sent for this form. 
    # See https://github.com/signebedi/libreforms-fastapi/issues/356
    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_updated' not in FormModel.disable_default_emails)

    # Send email
    if config.SMTP_ENABLED and check_background_email:

        subject, content = render_email_message_from_jinja(
            'form_updated', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )

    # Here we implement event hooks, see
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    # run_event_hooks(
    background_tasks.add_task(
        run_event_hooks,
        document_id=document_id, 
        document=d,
        form_name=form_name,
        event_hooks=form_data.event_hooks['on_update'],
        config=config,
        doc_db=doc_db,
        mailer=mailer,
        session=session,
        user=user,
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # delete_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES delete_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="delete_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="delete_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


    # Yield the pydantic form model
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

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


    # Validate whether default background emails should be sent for this form. 
    # See https://github.com/signebedi/libreforms-fastapi/issues/356
    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_deleted' not in FormModel.disable_default_emails)

    # Send email
    if config.SMTP_ENABLED and check_background_email:


        subject, content = render_email_message_from_jinja(
            'form_deleted', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )


    # Yield the pydantic form model, solely for the event hooks
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # Here we implement event hooks, see
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    # run_event_hooks(
    background_tasks.add_task(
        run_event_hooks,
        document_id=document_id, 
        document=success,
        form_name=form_name,
        event_hooks=FormModel.event_hooks['on_delete'],
        config=config,
        doc_db=doc_db,
        mailer=mailer,
        session=session,
        user=user,
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # update_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES update_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="update_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="update_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")


    # Yield the pydantic form model
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

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



    # Validate whether default background emails should be sent for this form. 
    # See https://github.com/signebedi/libreforms-fastapi/issues/356
    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_restored' not in FormModel.disable_default_emails
)
    # Send email
    if config.SMTP_ENABLED and check_background_email:

        subject, content = render_email_message_from_jinja(
            'form_restored', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

# Sign/Approve form
# This is a metadata-only field. It should not impact the data, just the metadata - namely, to afix 
# a digital signature to the form. See https://github.com/signebedi/libreforms-fastapi/issues/59.
# We have since modified this API route to be the "approve" route, not just a general "sign" route, 
# see https://github.com/signebedi/libreforms-fastapi/issues/335.
@app.patch("/api/form/sign/{form_name}/{document_id}/{action}", dependencies=[Depends(api_key_auth)])
async def api_form_sign(
    form_name:str,
    document_id:str,
    action:str,
    background_tasks: BackgroundTasks,
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY),
    reviewer_comments: str = "",
):
    """
    Digitally signs a specific document in a form that requires approval and routes 
    to the next form stage. Logs the signing action. You can pass a `reviewer_comments`
    query param to associate comments with the review action that is taking place. This
    field has a max length of 300 characters.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    permitted_actions = ['approve', 'deny', 'pushback', 'confirm']

    if action not in permitted_actions:
        raise HTTPException(status_code=404, detail=f"Form '{action}' not permitted")

   # Ensure reviewer_comments does not exceed 300 characters
    if len(reviewer_comments) > 300:
        raise HTTPException(status_code=400, detail="Reviewer comments cannot exceed 300 characters.")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # Yield the pydantic form model, for form stages and event hooks
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # We start by verifying that the form is in the list of forms needing the user's approval
    list_of_documents_this_user_can_approve = cache_form_stage_data_for_specified_user(
        form_name=form_name,
        form_stages=make_immutable_map(FormModel.form_stages),
        current_user=user,
        doc_db=doc_db,
    )

    if not document_id in list_of_documents_this_user_can_approve:
        raise HTTPException(status_code=403, detail=f"This user is not eligible to approve this document")

    # Now we need to read the form data (ugh, RIP efficiency) and get the current stage
    __temp_get_doc = doc_db.get_one_document(
        form_name=form_name, 
        document_id=document_id, 
    )

    form_stage = __temp_get_doc["metadata"]["form_stage"]

    # And then pull the next stage... there MUST be a better way to do this, mais helas
    # that we must proceed with this approach for now. If there is not a next_stage, then 
    # we must treat this as a terminal stage.
    next_form_stage = FormModel.form_stages[form_stage].get(f'on_{action}', None)
    if not next_form_stage:
        raise HTTPException(status_code=404, detail=f"This form lacks an eligible next stage designated under the 'on_{action}' key. Are you sure this isn't a terminal stage?")

    # Build the metadata field
    metadata={
        doc_db.last_editor_field: user.username,
        doc_db.reviewer_comments_field: reviewer_comments
    }

    # Add the remote addr host if enabled
    if config.COLLECT_USAGE_STATISTICS:
        metadata[doc_db.ip_address_field] = request.client.host

    try:
        # Process the request as needed
        success = doc_db.advance_document_stage(
            form_name=form_name, 
            document_id=document_id,
            metadata=metadata,
            username=user.username,
            form_stage=form_stage,
            next_form_stage=next_form_stage,
            action=action, # Here we specify which action to perform on the form
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





    # Validate whether default background emails should be sent for this form. 
    # See https://github.com/signebedi/libreforms-fastapi/issues/356
    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_stage_changed' not in FormModel.disable_default_emails)

    # Send email
    if config.SMTP_ENABLED and check_background_email:

        subject, content = render_email_message_from_jinja(
            'form_stage_changed', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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
            api_key=key, 
            endpoint=endpoint, 
            remote_addr=remote_addr, 
            query_params={},
        )


    # Here we implement event hooks, see
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    # run_event_hooks(
    background_tasks.add_task(
        run_event_hooks,
        document_id=document_id, 
        document=success,
        form_name=form_name,
        event_hooks=FormModel.event_hooks.get(f'on_{action}', []),
        config=config,
        doc_db=doc_db,
        mailer=mailer,
        session=session,
        user=user,
    )

    # Clear the caches for the action_needed functions
    cache_form_stage_data.invalidate(form_name)
    cache_form_stage_data_for_specified_user.cache_clear()


    return {
        "message": "Form successfully signed", 
        "document_id": document_id, 
    }


# @app.patch("/api/form/unsign/{form_name}/{document_id}", dependencies=[Depends(api_key_auth)])
# async def api_form_sign(
#     form_name:str,
#     document_id:str,
#     background_tasks: BackgroundTasks,
#     request: Request, 
#     config = Depends(get_config_depends),
#     mailer = Depends(get_mailer), 
#     doc_db = Depends(get_doc_db), 
#     session: SessionLocal = Depends(get_db),
#     key: str = Depends(X_API_KEY),
# ):
#     """
#     Removes a digital signature from a specific document, subject to user permissions 
#     and form validation. Logs the unsigning action.
#     """

#    if not config.API_ENABLED:
#        raise HTTPException(status_code=404, detail="This page does not exist")


#     if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
#         raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

#     # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
#     # the sqlalchemy-signing table is not optimized alongside the user model...
#     user = session.query(User).filter_by(api_key=key).first()

#     # Here we validate the user groups permit this level of access to the form
#     try:
#         user.validate_permission(form_name=form_name, required_permission="sign_own")
#     except Exception as e:
#         raise HTTPException(status_code=403, detail=f"{e}")
        
#     metadata={
#         doc_db.last_editor_field: user.username,
#     }

#     # Add the remote addr host if enabled
#     if config.COLLECT_USAGE_STATISTICS:
#         metadata[doc_db.ip_address_field] = request.client.host

#     try:
#         # Process the request as needed
#         success = doc_db.advance_document_stage(
#             form_name=form_name, 
#             document_id=document_id,
#             metadata=metadata,
#             username=user.username,
#             public_key=user.public_key,
#             private_key_path=user.private_key_ref,
#             unsign=True,
#         )

#     # Unlike other methods, like get_one_document or fuzzy_search_documents, this method raises exceptions when 
#     # it fails to ensure the user knows their operation was not successful.
#     except DocumentDoesNotExist as e:
#         raise HTTPException(status_code=404, detail=f"{e}")

#     except DocumentIsDeleted as e:
#         raise HTTPException(status_code=410, detail=f"{e}")

#     except SignatureError as e:
#         raise HTTPException(status_code=403, detail=f"{e}")

#     except InsufficientPermissions as e:
#         raise HTTPException(status_code=403, detail=f"{e}")

#     except NoChangesProvided as e:
#         raise HTTPException(status_code=200, detail=f"{e}")

#    # Validate whether default background emails should be sent for this form. 
#    # See https://github.com/signebedi/libreforms-fastapi/issues/356
#    check_background_email = not FormModel.disable_default_emails or (isinstance(FormModel.disable_default_emails, list) and 'form_unsigned' not in FormModel.disable_default_emails)
#
#    # Send email
#    if config.SMTP_ENABLED and check_background_email:

#         subject, content = render_email_message_from_jinja(
#             'form_unsigned', 
#             config.EMAIL_CONFIG_PATH,
#             config=config, 
#             form_name=form_name,
#             document_id=document_id
#         )
#         # print(subject, content)

#         background_tasks.add_task(
#             mailer.send_mail,
#             subject=subject, 
#             content=content,
#             to_address=user.email,
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
#             query_params={},
#         )

#     return {
#         "message": "Form successfully unsigned", 
#         "document_id": document_id, 
#     }



##########################
### API Routes - Validators
##########################


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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()

    # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
    # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
    try:
        user.validate_permission(form_name=form_name, required_permission="read_all")
        limit_query_to = False
    except Exception as e:

        try:
            user.validate_permission(form_name=form_name, required_permission="read_own")
            limit_query_to = user.username

        except Exception as e:
            raise HTTPException(status_code=403, detail=f"{e}")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

            subject, content = render_email_message_from_jinja(
                'suspicious_activity', 
                config.EMAIL_CONFIG_PATH,
                config=config, 
            )
            # print(subject, content)

            background_tasks.add_task(
                mailer.send_mail,
                subject=subject, 
                content=content, 
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

        if config.REQUIRE_EMAIL_VERIFICATION:

            _key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=email)

            subject, content = render_email_message_from_jinja(
                'user_registered_verification', 
                config.EMAIL_CONFIG_PATH,
                config=config,
                username=new_username, 
                key=_key,
            )

        else:

            subject, content = render_email_message_from_jinja(
                'user_registered', 
                config.EMAIL_CONFIG_PATH,
                config=config,
                username=new_username, 
            )
        # print(subject, content)


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




# Rotate own API key, implemented in https://github.com/signebedi/libreforms-fastapi/issues/386.
@app.post("/api/auth/rotate_api_key", include_in_schema=schema_params["API_KEY_SELF_ROTATION_ENABLED"])
async def api_auth_rotate_api_key(
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Rotates an existing user's API key, writing optional user statistics to log. 
    Sends email confirmation when SMTP is enabled and configured. 

    *** Warning! When user uses this endpoint, their API calls will become unusable
    using their old API key. They MUST (a) capture the new API key in the response,
    (b) check their email for their new API key if SMTP is enabled & admins have modified 
    the default jinja2 email template to include the API key in plaintext, or (c) check
    their user profile in the UI for the new API key if the UI is enabled.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.API_KEY_SELF_ROTATION_ENABLED:
        raise HTTPException(status_code=400, detail="Users are not permitted to rotate their own API keys")

    user = session.query(User).filter_by(api_key=key).first()

    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")

    if not user.active:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Validate that user has not exceeded the max failed login attempts,
    # see https://github.com/signebedi/libreforms-fastapi/issues/78
    if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS and config.MAX_LOGIN_ATTEMPTS != 0:
        raise HTTPException(status_code=400, detail="User account is inactive")

    # Rotate the user's API key 
    new_value = signatures.rotate_key(user.api_key)
    user.api_key = new_value

    # Commit n flush
    session.add(user)
    session.commit()


    # Email notification
    if config.SMTP_ENABLED:

        subject, content = render_email_message_from_jinja(
            'api_key_rotation', 
            config.EMAIL_CONFIG_PATH,
            config=config,
            user=user, 
        )
        # print(subject, content)

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
            query_params={"user": user.username},
        )

    return {
        "status": "success", 
        "api_key": new_value,
        "message": f"Successfully rotated API key for user {user.username}"
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        subject, content = render_email_message_from_jinja(
            'user_password_changed', 
            config.EMAIL_CONFIG_PATH,
            config=config,
            user=user, 
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    # print("\n\n\n", profile_data['relationships'])
    # print("\n\n\n", profile_data['received_relationships'])


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




# Read all forms that reference the given form_name and document_id
@app.get("/api/auth/get_linked_refs/{passed_username}", dependencies=[Depends(api_key_auth)])
async def api_auth_get_linked_references(
    passed_username: str, 
    background_tasks: BackgroundTasks, 
    request: Request, 
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db),
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),

):
    """
    This method returns a list of forms that reference the given `username` in the 
    URL params in one of their fields. These are sometimes called linked references, 
    or backrefs. It returns full records by default.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Ugh, I'd like to find a more efficient way to get the user data. But alas, that
    # the sqlalchemy-signing table is not optimized alongside the user model...
    user = session.query(User).filter_by(api_key=key).first()


    # Now that we've verified the current user, let's also verify the passed_username
    passed_user = session.query(User).filter_by(username=passed_username).first()

    # Return a 404 if the target user does not exist
    if not passed_user:
        raise HTTPException(status_code=404)

    # Now we build a dict for linked fields _applicable_ to the given form_name
    dict_of_relevant_links = {}

    for _form_name in get_form_names(config_path=config.FORM_CONFIG_PATH):

        __form_model = get_form_model(
            form_name=_form_name, 
            config_path=config.FORM_CONFIG_PATH,
            session=session,
            User=User,
            Group=Group,
            doc_db=doc_db,
        )

        # Here we add the list of fields that point to users
        dict_of_relevant_links[_form_name] = __form_model.user_fields



    documents = []

    for _form_name, _linked_fields in dict_of_relevant_links.items():

        # read_all IS THE HIGHER PRIVILEGE OF THE TWO - SO WE SHOULD CHECK FOR THAT FIRST, AS IT 
        # INCLUDES read_own. https://github.com/signebedi/libreforms-fastapi/issues/307.
        try:
            user.validate_permission(form_name=_form_name, required_permission="read_all")
            limit_query_to = False
        except Exception as e:

            try:
                user.validate_permission(form_name=_form_name, required_permission="read_own")
                limit_query_to = user.username

            except Exception as e:
                raise HTTPException(status_code=403, detail=f"{e}")


        for _linked_field in _linked_fields:
            _documents = []
            # This query param will only return that matches the given username
            query_params = {"data":{_linked_field: {"operator": "==","value": passed_username}}}

            _documents = doc_db.get_all_documents(
                form_name=_form_name, 
                limit_users=limit_query_to,
                exclude_journal=True,
                # collapse_data=True,
                # sort_by_last_edited=True,
                # newest_first=True,
                query_params=query_params,
            )

            documents.extend(_documents) 
        
    # Drop duplicates and sort!
    unique_documents = {}
    for doc in documents:
        doc_id = doc['metadata']['document_id']

        # Replace the document if this one is newer
        if doc_id not in unique_documents:
            unique_documents[doc_id] = doc

    # Now we have a dictionary of unique documents; we need to sort them by 'last_modified'
    sorted_documents = sorted(
        unique_documents.values(), 
        key=lambda x: datetime.fromisoformat(x['metadata']['last_modified'].replace('Z', '+00:00')),
        reverse=True
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

    return sorted_documents




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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        subject, content = render_email_message_from_jinja(
            'password_reset_instructions', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            otp=otp, 
            user=user
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        subject, content = render_email_message_from_jinja(
            'password_reset_complete', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            user=user
        )
        
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    user = session.query(User).filter_by(username=form_data.username.lower()).first()

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Added to support no_login service accounts, see
    # https://github.com/signebedi/libreforms-fastapi/issues/305
    if user.no_login:
        raise HTTPException(status_code=403, detail="Login not permitted for this account")

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

    if config.MAX_INACTIVITY_PERIOD is not False:

        inactivity_period = datetime.now() - user.last_login

        if inactivity_period > config.MAX_INACTIVITY_PERIOD:
            user.active = False
            session.add(user)
            session.commit()


            raise HTTPException(status_code=400, detail=f"User {user.username} has exceeded the maximum inactivity period of {config.MAX_INACTIVITY_PERIOD.days} days. Please contact your system administrator to reactivate the account.")


    if config.MAX_PASSWORD_AGE is not False:
        password_age = datetime.now() - user.last_password_change

        if password_age > config.MAX_PASSWORD_AGE:
            user.active = False
            session.add(user)
            session.commit()

            raise HTTPException(status_code=400, detail=f"User {user.username} has a password that exceeds the maximum password age of {config.MAX_PASSWORD_AGE.days} days. Please contact your system administrator to reactivate the account.")



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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    subject, content = render_email_message_from_jinja(
        'help_request', 
        config.EMAIL_CONFIG_PATH,
        user=user, 
        config=config, 
        time=time_str, 
        subject=safe_subject,
        category=shortened_safe_category,
        message=safe_message,
    )
    # print(subject, content)

    background_tasks.add_task(
        mailer.send_mail,
        subject=full_safe_subject, 
        content=content, 
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


# SAML auth routes
def load_user_by_email(
    session: SessionLocal, 
    config,
    email: str, 
    username: str|None = None, 
    group: str|None = None
):
    user = session.query(User).filter(User.email.ilike(email)).first()
    
    if not user:
        base_username = username if username else email.split('@')[0]
        new_username = base_username
        # I'm not sure how I feel about the whole "random number appended to the end" approach
        # but it works for now.
        while session.query(User).filter_by(username=new_username).first() is not None:
            new_username = generate_unique_username(base_username)


        user = User(
            email=email, 
            username=new_username,
            password=generate_dummy_password_hash(),
            active=True,
            opt_out=False,
        )

        # Add to the default group, unless a specific group is specified
        if group:
            _group = session.query(Group).filter_by(name=group).first()

        else:
            _group = session.query(Group).filter_by(id=1).first()

        user.groups.append(_group)

        # Create the users API key with a 365 day expiry
        expiration = 8760
        api_key = signatures.write_key(scope=['api_key'], expiration=expiration, active=True, email=email)
        user.api_key = api_key

        # Here we add user key pair information, namely, the path to the user private key, and the
        # contents of the public key, see https://github.com/signebedi/libreforms-fastapi/issues/71.
        ds_manager = DigitalSignatureManager(username=new_username, env=config.ENVIRONMENT)
        ds_manager.generate_rsa_key_pair()
        user.private_key_ref = ds_manager.get_private_key_file()
        user.public_key = ds_manager.public_key_bytes

        session.add(user)
        session.commit()
    
    return user


async def prepare_saml_request(request: Request, config):
    parsed_url = urlparse(config.DOMAIN)
    host = parsed_url.netloc + parsed_url.path

    return {
        'https': 'on' if config.DOMAIN.startswith('https://') else 'off',
        'http_host': host,
        'server_port': None,
        'script_name': request.url.path,
        'get_data': request.query_params,
        'post_data': await request.form(),
        'query_string': request.url.query
    }


@app.post('/api/auth/sso', include_in_schema=False)
async def api_auth_sso(background_tasks: BackgroundTasks, request: Request, config = Depends(get_config_depends), session: SessionLocal = Depends(get_db)):

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SAML_ENABLED:
        raise HTTPException(status_code=404)

    try:
        req_data = await prepare_saml_request(request, config)
        saml_auth = OneLogin_Saml2_Auth(req_data, APP_SAML_AUTH)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
        
    return RedirectResponse(saml_auth.login())



@app.post('/api/auth/acs', include_in_schema=False)
async def api_auth_acs(background_tasks: BackgroundTasks, request: Request, config = Depends(get_config_depends), session: SessionLocal = Depends(get_db)):

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SAML_ENABLED:
        raise HTTPException(status_code=404)

    try:
        req_data = await prepare_saml_request(request, config)
        saml_auth = OneLogin_Saml2_Auth(req_data, APP_SAML_AUTH)
        saml_auth.process_response()
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    errors = saml_auth.get_errors()
    if errors:
        error_reason = saml_auth.get_last_error_reason()
        detailed_error = f"SAML authentication error: {errors}. Reason: {error_reason}"
        raise HTTPException(status_code=401, detail=detailed_error)

    if not saml_auth.is_authenticated():
        return RedirectResponse(request.url_for("ui_auth_login"), status_code=303)
    
    email = saml_auth.get_attributes().get('email', [None])[0]
    if email:
        user = load_user_by_email(session, config, email=email)
        if not user.active:
            raise HTTPException(status_code=400, detail="User authentication failed")

        if user.no_login:
            raise HTTPException(status_code=403, detail="Login not permitted for this account")


        # Clear failed login attempts and set last login time
        user.failed_login_attempts = 0
        user.last_login = datetime.now(config.TIMEZONE)
        session.add(user)
        session.commit()

        # Generate JWT token
        user_dict = {
            "id": user.id,
            "sub": user.username,
            "aud": f"{config.SITE_NAME}WebUser",
            "iss": config.SITE_NAME,
            "exp": datetime.now(config.TIMEZONE) + config.PERMANENT_SESSION_LIFETIME,
            "email": user.email,
            "active": user.active,
            "admin": user.site_admin,
        }

        token = jwt.encode(
            user_dict, 
            site_key_pair.get_private_key(), 
            algorithm='RS256'
        )

        # Set the HTTP-only cookie with the token
        # response = JSONResponse({"access_token": token, "token_type": "bearer"})
        response = RedirectResponse(request.url_for("ui_home"), status_code=303)

        response.set_cookie(
            key="access_token",
            value=f"Bearer {token}",
            httponly=True,
            max_age=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
            expires=config.PERMANENT_SESSION_LIFETIME.total_seconds(),
        )

        # Log transaction if applicable
        if config.COLLECT_USAGE_STATISTICS:
            background_tasks.add_task(
                write_api_call_to_transaction_log, 
                api_key=user.api_key, 
                endpoint=request.url.path,
                remote_addr=request.client.host,
                query_params={"user": user.username},
            )


        return response

    else:
        raise HTTPException(status_code=401, detail="SAML response doesn't contain an email attribute.")


@app.get('/api/auth/metadata', include_in_schema=False)
async def api_auth_metadata(background_tasks: BackgroundTasks, request: Request, config = Depends(get_config_depends), session: SessionLocal = Depends(get_db)):

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SAML_ENABLED:
        raise HTTPException(status_code=404)

    try:
        req_data = await prepare_saml_request(request, config)
        saml_auth = OneLogin_Saml2_Auth(req_data, APP_SAML_AUTH)
        metadata = saml_auth.get_settings().get_sp_metadata()
        errors = saml_auth.get_errors()
        if errors:
            raise Exception('Errors in generating metadata')
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    return Response(content=metadata, media_type='application/xml')



@app.post('/api/auth/sls', include_in_schema=False)
async def api_auth_sls(background_tasks: BackgroundTasks, request: Request, response: Response, config = Depends(get_config_depends), session: SessionLocal = Depends(get_db)):

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SAML_ENABLED:
        raise HTTPException(status_code=404)

    try:
        req_data = await prepare_saml_request(request, config)
        saml_auth = OneLogin_Saml2_Auth(req_data, APP_SAML_AUTH)
        saml_auth.process_slo()
        errors = saml_auth.get_errors()
        if errors:
            raise Exception('SAML logout error')
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    if not saml_auth.is_authenticated():

        # Redirect to the homepage
        response = RedirectResponse(request.url_for("ui_home"), status_code=303)

        # If the user is still authenticated, log them out locally by
        # setting the cookie to expire in the past, effectively removing it
        response.delete_cookie(key="access_token")

        return response

    # Redirect the user to the home page after successful logout
    return RedirectResponse(request.url_for("ui_home"), status_code=303)


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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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
        no_login=user_request.no_login,
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

        subject, content = render_email_message_from_jinja(
            'user_registered_admin', 
            config.EMAIL_CONFIG_PATH,
            config=config,
            username=new_username, 
            password=password,
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if field not in ["active", "site_admin", "no_login", "password", "api_key"]:
        raise HTTPException(status_code=404)

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)


    user_to_change = session.query(User).get(id)
    if not user_to_change:
        raise HTTPException(status_code=404, detail="Could not find user. Are you sure they exist?")

    # Here we set the relevant value to change
    if field in ["active", "site_admin", "no_login"]:
        if user.id == user_to_change.id:
            raise HTTPException(status_code=418, detail=f"You really shouldn't be performing these operations on yourself...")
        new_value = not getattr(user_to_change, field)
        setattr(user_to_change, field, new_value)

        # When we toggle users back to active or make them admins, let's clear their failed logins
        user_to_change.failed_login_attempts = 0
        
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
        content={"status": "success", "message": f"Updated {field} for user id {id}"},
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        subject, content = render_email_message_from_jinja(
            'form_deleted', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        subject, content = render_email_message_from_jinja(
            'form_restored', 
            config.EMAIL_CONFIG_PATH,
            config=config, 
            form_name=form_name,
            document_id=document_id
        )
        # print(subject, content)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

        existing_relationship_type_reciprocal = session.query(RelationshipType).filter_by(
            reciprocal_name=new_relationship_request.reciprocal_name
        ).first()

        if existing_relationship_type_reciprocal:
            # Consider adding IP tracking to failed attempt
            logger.warning(f'Attempt to create relationship type {new_relationship_request.reciprocal_name} but relationship with this reciprocal type already exists. Did you mean to modify the reciprocal type?')

            raise HTTPException(status_code=409, detail="Could not create relationship type. Reciprocal type already exists.")


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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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
            query_params={},
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

# Upload favicon
@app.post(
    "/api/admin/upload_favicon",
    dependencies=[Depends(api_key_auth)],
    response_class=JSONResponse,
    include_in_schema=False,
)
async def api_admin_upload_favicon(
    request: Request,
    background_tasks: BackgroundTasks,
    favicon: UploadFile = File(...), 
    config = Depends(get_config_depends),
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    user = session.query(User).filter_by(api_key=key).first()
    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    file_path = f"instance/{config.ENVIRONMENT}_favicon.ico"

    try:
        contents = favicon.file.read()

        with open(file_path, 'wb') as f:
            f.write(contents)

    except Exception:
        raise HTTPException(status_code=422)

    finally:
        favicon.file.close()

    # print("\n\n\n", chardet.detect(favicon.file.file))
    # print("\n\n\n", favicon.file.content_type)

    # if contents.content_type != 'image/x-icon':
    #     raise HTTPException(status_code=400, detail="Invalid file type. Only ICO files are accepted.")


    # file_path = f"static/instance/{config.ENVIRONMENT}_favicon.ico"
    # with open(file_path, "wb") as file_object:
    #     shutil.copyfileobj(favicon.file.file, file_object)


    
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
        content={"message": "Favicon uploaded successfully", "path": file_path}
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    _form_config = get_form_config_yaml(config_path=config.FORM_CONFIG_PATH)

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)


    # old_form_config_str = get_form_config_yaml(config_path=config.FORM_CONFIG_PATH).strip()

    try:
        write_form_config_yaml(
            config_path=config.FORM_CONFIG_PATH, 
            form_config_str=_form_config.content, 
            env=config.ENVIRONMENT,
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
            query_params={},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success"},
    )



# Get email yaml
@app.get(
    "/api/admin/get_email_config", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_get_email_config(
    request: Request, 
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY),
    return_as_yaml_str: bool = False,
):
    """
    Allows site administrators to view the site email config as yaml. This operation is logged for audit purposes. Set
    `return_as_yaml_str` to True to receive back a string of the yaml config file.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    email_config = get_email_yaml(config_path=config.EMAIL_CONFIG_PATH, return_as_yaml_str=return_as_yaml_str)

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
        content={"status": "success", "content": email_config},
    )


# Update email config string
@app.post(
    "/api/admin/write_email_config", 
    dependencies=[Depends(api_key_auth)], 
    response_class=JSONResponse, 
)
async def api_admin_write_email_config(
    request: Request, 
    _email_config: EmailConfigUpdateRequest,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Allows site administrators to update the site email config as yaml. This operation is logged for audit purposes.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    # old_config_str = get_email_yaml(config_path=config.EMAIL_CONFIG_PATH, return_as_yaml_str=return_as_yaml_str).strip()


    try:
        write_email_config_yaml(
            config_path=config.EMAIL_CONFIG_PATH, 
            email_config_str=_email_config.content, 
            env=config.ENVIRONMENT,
            timezone=config.TIMEZONE,
            config=config, user=user, # Add'l kwargs to validate with better data
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
            query_params={},
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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
            query_params={**_site_config.content},
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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

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
    kwargs["visible_form_names"] = get_form_names(config_path=config.FORM_CONFIG_PATH, prefer_label=True)
    kwargs["current_year"] = datetime.now().year
    kwargs["render_markdown_content"] = render_markdown_content


    # def convert_python_regex_to_js(python_regex: str, embed_in_js_string=True):
    #     js_regex = re.sub(r"\(\?P<([a-zA-Z_][a-zA-Z0-9_]*)>", r"(?<\1>", python_regex)
    #     js_regex = re.sub(r'\\(?![dwsDSW])', r'\\\\', js_regex)  # Handle backslashes for JS
    #     if embed_in_js_string:
    #         js_regex = js_regex.replace('"', '\\"')  # Escape quotes for JS strings
    #     return js_regex

    def convert_python_regex_to_js(python_regex: str, embed_in_js_string=True):
        # Replace Python-style named groups with JavaScript-style named groups
        js_regex = re.sub(r"\(\?P<([a-zA-Z_][a-zA-Z0-9_]*)>", r"(?<\1>", python_regex)
        
        # Escape only necessary backslashes for JavaScript, ignoring \d, \w, \s, etc.
        # Match a backslash that is not followed by special regex characters.
        js_regex = re.sub(r'\\(?![dwsDSWbB])', r'\\\\', js_regex)

        # Optionally escape double quotes if embedding inside a JS string delimited by double quotes
        if embed_in_js_string:
            js_regex = js_regex.replace('"', '\\"')

        return js_regex


    # We want to render these regexes in a way that javascript can handle them, see
    # https://github.com/signebedi/libreforms-fastapi/issues/349
    kwargs["js_friendly_username_regex"] = convert_python_regex_to_js(_c.USERNAME_REGEX)
    kwargs["js_friendly_password_regex"] = convert_python_regex_to_js(_c.PASSWORD_REGEX)


    return kwargs


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

    if not config.VIEW_ALL_PAGE_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")


    return templates.TemplateResponse(
        request=request, 
        name="read_all_forms.html.jinja", 
        context={
            "form_names": list(get_form_names(config_path=config.FORM_CONFIG_PATH)),
            **build_ui_context(),
        }
    )


@app.get("/ui/form/request_unregistered/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], status_code=404)
async def ui_form_request_unregistered(form_name:str, request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not config.SMTP_ENABLED:
        raise HTTPException(status_code=404)


    return templates.TemplateResponse(
        request=request, 
        name="request_unregistered.html.jinja", 
        context={
            'form_name': form_name,
            **build_ui_context(),
        }
    )


# Added in https://github.com/signebedi/libreforms-fastapi/issues/365
@app.get("/ui/form/invite_submission/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], status_code=404)
async def ui_form_invite_submission(form_name:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404)

    if not config.SMTP_ENABLED:
        raise HTTPException(status_code=404)

    # Since this is an authenticated-only route, we don't worry 
    # about abuse of expensive processes too much
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    if not FormModel.invitations_enabled:
        raise HTTPException(status_code=404)


    return templates.TemplateResponse(
        request=request, 
        name="request_unregistered.html.jinja", 
        context={
            'form_name': form_name,
            **build_ui_context(),
        }
    )



# Create form unregistered user, see https://github.com/signebedi/libreforms-fastapi/issues/357
@app.get("/ui/form/create_unregistered/{form_name}/{api_key}", response_class=HTMLResponse, include_in_schema=False)
@requires(['unauthenticated'], redirect="ui_home")
async def ui_form_create_unregistered(form_name:str, api_key:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    verify = signatures.verify_key(api_key, scope=['api_key', 'api_key_single_use'])
    if not verify:
        raise HTTPException(status_code=401)

    key_data = signatures.get_key(api_key)
    key_scope = key_data['scope']
    key_email = key_data['email']

    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # If unregistered form submission not enabled for this form, then return an error
    if not FormModel.unregistered_submission_enabled:
        raise HTTPException(status_code=404)

    # If there is not an associated user with the request, we need to render a pared down request...
    # WARNING: this may break some form configs. Proceed with caution!
    if key_scope == "api_key":
        _user = session.query(User).filter_by(api_key=api_key).first()
        user = _user.to_dict()
    else:
        user = {
            "email": key_email,
            "api_key": api_key, 
        }

    _context = {
        'user': user,
        'config': config.model_dump()
    }

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
        context=_context,
    )

    return templates.TemplateResponse(
        request=request, 
        name="create_form.html.jinja", 
        context={
            "form_name": form_name,
            "form_html": form_html,
            "unregistered_form": True,
            "api_key": api_key,
            **build_ui_context(),
        }
    )



# Create form
@app.get("/ui/form/create/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_create(form_name:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if form_name not in get_form_names(config_path=config.FORM_CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Form '{form_name}' not found")

    _context = {
        'user': request.user.to_dict(),
        'config': config.model_dump()
    }

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
        context=_context,
    )

    return templates.TemplateResponse(
        request=request, 
        name="create_form.html.jinja", 
        context={
            "form_name": form_name,
            "form_html": form_html,
            "unregistered_form": False,
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


    _context = {
        'user': request.user.to_dict(),
        'config': config.model_dump()
    }

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        update=True,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
        context=_context,
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

    _context = {
        'user': request.user.to_dict(),
        'config': config.model_dump()
    }

    # generate_html_form
    form_html = get_form_html(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        duplicate=True,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
        context=_context,
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



# Search forms
@app.get("/ui/form/search", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_search(
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


# Form review and approval - general UI page
@app.get("/ui/form/review_and_approval", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_review_and_approval(request: Request, config = Depends(get_config_depends)):

    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="review_and_approval.html.jinja", 
        context={
            "form_names": list(get_form_names(config_path=config.FORM_CONFIG_PATH)),
            **build_ui_context(),
        }
    )

@app.get("/ui/form/review_and_approval/{form_name}/{document_id}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_review_and_approval_individual(form_name:str, document_id:str, request: Request, config = Depends(get_config_depends), doc_db = Depends(get_doc_db), session: SessionLocal = Depends(get_db)):

    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Placeholder: if this form is not in the user's approval chain currently, then return a 404

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

    #### UGH! Tons of server/client coupling with the logic below but, alas, that there is not right now a more 
    # straightforward way without an API route that yields key configuration data between server and client. This 
    # could be an admin route and executed within the scope of this view function... future thought.

    # Yield the pydantic form model, for form stages and event hooks
    FormModel = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    # Now we need to read the form data (ugh, RIP efficiency) and get the current stage
    __temp_get_doc = doc_db.get_one_document(
        form_name=form_name, 
        document_id=document_id, 
    )

    form_stage = __temp_get_doc["metadata"]["form_stage"]
    stage_conf = FormModel.form_stages.get(form_stage, {})

    return templates.TemplateResponse(
        request=request, 
        name="review_and_approval_individual.html.jinja", 
        context={
            "form_name": form_name,
            "document_id": document_id,
            "metadata_field_mask": metadata_field_mask,
            "form_field_mask": form_field_mask,
            "form_stage": form_stage,
            "stage_conf": stage_conf,
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

@app.get("/alive", response_class=JSONResponse, include_in_schema=False)
async def ui_alive(response: Response, request: Request, config = Depends(get_config_depends),):

    if not config.HEALTH_CHECKS_ENABLED:
        raise HTTPException(status_code=404)

    return JSONResponse(
        status_code=200,
        content={"status": "alive"},
    )


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
@requires(['unauthenticated'], redirect="ui_home")
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

    past_versions = get_form_backups(config_path=config.FORM_CONFIG_PATH, env=config.ENVIRONMENT)

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


@app.get("/ui/admin/write_email_config", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_write_email_config(request: Request, config = Depends(get_config_depends),):
    
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    config_str = get_email_yaml(config_path=config.EMAIL_CONFIG_PATH, return_as_yaml_str=True).strip()

    return templates.TemplateResponse(
        request=request, 
        name="admin_email_config.html.jinja", 
        context={
            **build_ui_context(),
            "config_str": config_str,
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




# Upload favicon
@app.get("/ui/admin/upload_favicon", response_class=HTMLResponse, include_in_schema=False)
@requires(['admin'], redirect="ui_home")
async def ui_admin_upload_favicon(request: Request, config = Depends(get_config_depends),):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    if not request.user.site_admin:
        raise HTTPException(status_code=404, detail="This page does not exist")

    return templates.TemplateResponse(
        request=request, 
        name="admin_upload_favicon.html.jinja", 
        context={
            **build_ui_context(),
        }
    )

# @app.get("/favicon.ico", include_in_schema=False)
# async def favicon():
#     return RedirectResponse(url="/instance/favicon.ico")

# Define the path to your instance directory

# Serve the favicon from the instance directory
@app.get("/favicon.ico", include_in_schema=False)
async def favicon(request: Request, config = Depends(get_config_depends)):
    favicon_path = os.path.join('instance', f'{config.ENVIRONMENT}_favicon.ico')
    if not os.path.exists(favicon_path):
        return RedirectResponse(request.url_for('static', path='favicon.ico'), status_code=303)
    return FileResponse(favicon_path)
