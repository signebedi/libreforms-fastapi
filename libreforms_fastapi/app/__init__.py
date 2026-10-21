# The app is split into modules by area. core.py creates the app and holds the shared config,
# database, auth backend and dependencies, and each of the other modules registers its routes on
# that app when imported, so the order of the imports below is the order routes are registered in.
import os
import difflib, importlib, platform
from datetime import datetime
from typing import Optional
from markupsafe import escape
from fastapi import Response, HTTPException, BackgroundTasks, Depends, Query, File, UploadFile
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.authentication import requires
from starlette.requests import Request
from libreforms_fastapi.__metadata__ import __version__
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
    get_form_model, get_form_names, get_form_html, load_form_config, get_form_config_yaml,
    write_form_config_yaml, get_form_backups,
)
from libreforms_fastapi.utils.docs import get_docs, write_docs
from libreforms_fastapi.utils.jinja_emails import (
    render_email_message_from_jinja, write_email_config_yaml, get_email_yaml,
)

from libreforms_fastapi.app.core import (
    AdminCreateUserRequest, api_key_auth, app, build_ui_context, config, engine,
    get_config_context, get_config_depends, get_db, get_doc_db, get_mailer, Group, logger,
    models, PasswordReuse, RelationshipType, schema_params, session, SessionLocal, signatures,
    Signing, templates, TransactionLog, User, UserRelationship,
    write_api_call_to_transaction_log, X_API_KEY,
)

from libreforms_fastapi.app import (  # noqa: F401
    api_form,
    api_auth,
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

# Read all forms, for a given form name
# Added by https://github.com/signebedi/libreforms-fastapi/issues/398
@app.get("/ui/form/read_all/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_read_all_single_form(
    form_name: str, 
    request: Request, 
    fields: Optional[str] = None,  # Comma-separated list of fields
    config = Depends(get_config_depends)
):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")
    
    form_names = list(get_form_names(config_path=config.FORM_CONFIG_PATH))
    if not form_name in form_names:
        raise HTTPException(status_code=404, detail="This page does not exist")
    
    # Parse fields parameter if provided
    selected_fields = None
    if fields:
        # Expected format: "data:field1,data:field2,metadata:field3"
        # or simplified: "field1,field2,metadata:field3" (assumes data if no prefix)
        selected_fields = [f.strip() for f in fields.split(',') if f.strip()]
    
    return templates.TemplateResponse(
        request=request, 
        name="read_all_forms_single_form.html.jinja", 
        context={
            "form_name": form_name,
            "selected_fields": selected_fields,
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



# Form review and approval - form-specific UI page
# Added by https://github.com/signebedi/libreforms-fastapi/issues/399
@app.get("/ui/form/review_and_approval/{form_name}", response_class=HTMLResponse, include_in_schema=False)
@requires(['authenticated'], redirect="ui_auth_login")
async def ui_form_review_and_approval_single_form(
    form_name: str, 
    request: Request, 
    fields: Optional[str] = None,  # Comma-separated list of fields
    config = Depends(get_config_depends),
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db),
):
    if not config.UI_ENABLED:
        raise HTTPException(status_code=404, detail="This page does not exist")
    
    form_names = list(get_form_names(config_path=config.FORM_CONFIG_PATH))
    # Really, we should be down-selecting to forms that have a valid approval chain defined...
    if not form_name in form_names:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # We instantiate merely to deny the UI in instances where a form has no form stages defined
    __form_model = get_form_model(
        form_name=form_name, 
        config_path=config.FORM_CONFIG_PATH,
        session=session,
        User=User,
        Group=Group,
        doc_db=doc_db,
    )

    if __form_model.form_stages == {}:
        raise HTTPException(status_code=404, detail="This page does not exist")

    # Parse fields parameter if provided
    selected_fields = None
    if fields:
        # Expected format: "data:field1,data:field2,metadata:field3"
        # or simplified: "field1,field2,metadata:field3" (assumes data if no prefix)
        selected_fields = [f.strip() for f in fields.split(',') if f.strip()]
    
    return templates.TemplateResponse(
        request=request, 
        name="review_and_approval_single_form.html.jinja", 
        context={
            "form_names": form_names,
            "form_name": form_name,
            "selected_fields": selected_fields,
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
async def ui_admin_update_relationship_type(id:str, request: Request, config = Depends(get_config_depends),):
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
