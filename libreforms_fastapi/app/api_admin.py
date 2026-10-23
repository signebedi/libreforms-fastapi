import difflib
from datetime import datetime
from markupsafe import escape
from fastapi import HTTPException, BackgroundTasks, Depends, File, UploadFile
from fastapi.responses import JSONResponse
from starlette.requests import Request
from libreforms_fastapi.utils.config import validate_and_write_configs
from libreforms_fastapi.utils.sqlalchemy_models import test_relational_database_connection
from libreforms_fastapi.utils.scripts import (
    generate_password_hash, percentage_alphanumeric_generate_password,
)
from libreforms_fastapi.utils.certificates import DigitalSignatureManager
from libreforms_fastapi.utils.document_database import (
    get_document_database, DocumentDoesNotExist, DocumentIsDeleted, InsufficientPermissions,
    DocumentIsNotDeleted,
)
from libreforms_fastapi.utils.pydantic_models import (
    DocsEditRequest, AdminChangePasswordRequest, GroupModel, RelationshipTypeModel,
    UserRelationshipModel, FormConfigUpdateRequest, EmailConfigUpdateRequest, SiteConfig,
    get_form_names, get_form_config_yaml, write_form_config_yaml,
)
from libreforms_fastapi.utils.docs import get_docs, write_docs
from libreforms_fastapi.utils.jinja_emails import (
    render_email_message_from_jinja, write_email_config_yaml, get_email_yaml,
)

from libreforms_fastapi.app.core import (
    AdminCreateUserRequest, api_key_auth, app, get_config_context, get_config_depends, get_db,
    get_doc_db, get_mailer, Group, logger, PasswordReuse, RelationshipType, schema_params,
    SessionLocal, signatures, User, UserRelationship, write_api_call_to_transaction_log,
    X_API_KEY,
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

    # For a password reset we generate a random password but, historically, never
    # delivered it to anyone - locking the user out. Notify the user by email (matching
    # the dedicated change-password flow) and return the generated temporary password to
    # the admin so it can be conveyed to the user. See excludes/issues.md 9.
    if field == "password":
        if config.SMTP_ENABLED:
            subject, content = render_email_message_from_jinja(
                'user_password_changed',
                config.EMAIL_CONFIG_PATH,
                config=config,
                user=user_to_change,
            )
            background_tasks.add_task(
                mailer.send_mail,
                subject=subject,
                content=content,
                to_address=user_to_change.email,
            )
        response_message = f"Reset password for user id {id}. Temporary password: {new_value}"
    else:
        response_message = f"Updated {field} for user id {id}"

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
        content={"status": "success", "message": response_message},
    )


# Admin-initiated password change, paired with the manage users admin UI route
@app.patch(
    "/api/admin/change_password/{id}",
    dependencies=[Depends(api_key_auth)],
    response_class=JSONResponse,
)
async def api_admin_change_password(
    id:str,
    user_request: AdminChangePasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer),
    session: SessionLocal = Depends(get_db),
    key: str = Depends(X_API_KEY)
):
    """
    Sets a new password, provided by the admin, for the given user. Requires site admin
    permissions. Notifies the user by email and logs the action for audit purposes.
    """

    if not config.API_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Get the requesting user details
    user = session.query(User).filter_by(api_key=key).first()

    if not user or not user.site_admin:
        raise HTTPException(status_code=404)

    user_to_change = session.query(User).get(id)
    if not user_to_change:
        raise HTTPException(status_code=404, detail="Could not find user. Are you sure they exist?")

    hashed_password = generate_password_hash(user_request.new_password.get_secret_value())
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

    session.add(user_to_change)
    session.commit()

    # Email notification
    if config.SMTP_ENABLED:

        subject, content = render_email_message_from_jinja(
            'user_password_changed',
            config.EMAIL_CONFIG_PATH,
            config=config,
            user=user_to_change,
        )

        background_tasks.add_task(
            mailer.send_mail,
            subject=subject,
            content=content,
            to_address=user_to_change.email,
        )

    # Write this query to the TransactionLog
    if config.COLLECT_USAGE_STATISTICS:
        background_tasks.add_task(
            write_api_call_to_transaction_log,
            api_key=key,
            endpoint=request.url.path,
            remote_addr=request.client.host,
            query_params={"user":user_to_change.username},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": f"Successfully changed password for user {user_to_change.username}"},
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
async def api_admin_delete_form(
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
async def api_admin_restore_form(
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
    _relationship_type = session.query(RelationshipType).filter_by(id=new_relationship_request.relationship_type_id).first()

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
