import jwt
from datetime import datetime
from typing import Annotated
from urllib.parse import urlparse
from markupsafe import escape
from pydantic import EmailStr
from fastapi import Response, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from starlette.requests import Request
from http.cookies import SimpleCookie
from sqlalchemy_signing import RateLimitExceeded, KeyDoesNotExist, KeyExpired, ScopeMismatch
from libreforms_fastapi.utils.scripts import (
    generate_password_hash, generate_dummy_password_hash, generate_unique_username,
    check_password_hash,
)
from libreforms_fastapi.utils.certificates import DigitalSignatureManager
from libreforms_fastapi.utils.pydantic_models import HelpRequest, get_form_model, get_form_names
from libreforms_fastapi.utils.jinja_emails import render_email_message_from_jinja

from libreforms_fastapi.app.core import (
    api_key_auth, app, config, CreateUserRequest, ForgotPasswordUserModel, get_config_depends,
    get_db, get_doc_db, get_mailer, Group, logger, PasswordChangeUserModel, PasswordReuse,
    schema_params, SessionLocal, signatures, site_key_pair, User,
    write_api_call_to_transaction_log, X_API_KEY,
)

if config.SAML_ENABLED:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from libreforms_fastapi.app.core import APP_SAML_AUTH


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

            _key = signatures.write_key(scope=['email_verification'], expiration=48, active=True, email=new_email)

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
