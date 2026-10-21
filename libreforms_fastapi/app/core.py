import re, os, json, logging
import asyncio, jwt
from datetime import datetime
from contextlib import contextmanager
from functools import lru_cache
from immutables import Map
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
)
from fastapi.exceptions import RequestValidationError
from starlette.middleware.authentication import (
    AuthenticationMiddleware,
)
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
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
    __license__,
    __maintainer__,
    __email__,
    __url__,
)

from libreforms_fastapi.utils.smtp import Mailer
from libreforms_fastapi.utils.logging import set_logger

from libreforms_fastapi.utils.config import get_config

from libreforms_fastapi.utils.sqlalchemy_models import get_sqlalchemy_models

from libreforms_fastapi.utils.scripts import check_configuration_assumptions

# Import the tools used to generate signatures
from libreforms_fastapi.utils.certificates import RuntimeKeypair
# Import the document database factory function and several
# Exceptions that can help with error handling / determining 
# HTTP response codes.
from libreforms_fastapi.utils.document_database import get_document_database

from libreforms_fastapi.utils.pydantic_models import (
    get_user_model,
    get_form_model,
    get_form_names,
)

from libreforms_fastapi.utils.docs import render_markdown_content

from libreforms_fastapi.utils.custom_tinydb import CustomEncoder

# This import is used for caching with selective invalidation
from libreforms_fastapi.utils.parameterized_caching import parameterized_lru_cache

# Import to render more powerful email content
from libreforms_fastapi.utils.jinja_emails import render_email_message_from_jinja


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
