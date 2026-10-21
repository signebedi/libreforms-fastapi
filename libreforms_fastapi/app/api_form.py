import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any
from bson import ObjectId
from enum import Enum
import requests
from pydantic import ValidationError
from fastapi import Body, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import FileResponse
from starlette.requests import Request
from libreforms_fastapi.utils.scripts import generate_dummy_password_hash, generate_unique_username
from libreforms_fastapi.utils.certificates import verify_record_signature, DigitalSignatureManager
from libreforms_fastapi.utils.document_database import (
    DocumentDoesNotExist, DocumentIsDeleted, InsufficientPermissions, DocumentIsNotDeleted,
    SignatureError, DocumentAlreadyHasValidSignature, NoChangesProvided,
)
from libreforms_fastapi.utils.pydantic_models import (
    RequestUnregisteredForm, get_form_model, get_form_names,
)
from libreforms_fastapi.utils.jinja_emails import render_email_message_from_jinja
from jinja2 import Environment, select_autoescape, TemplateError, UndefinedError

from libreforms_fastapi.app.core import (
    api_key_auth, api_key_auth_allow_single_use, app, cache_form_stage_data,
    cache_form_stage_data_for_specified_user, get_config_depends, get_db, get_doc_db,
    get_mailer, Group, make_immutable_map, RelationshipType, SessionLocal, signatures, User,
    UserRelationship, write_api_call_to_transaction_log, X_API_KEY,
)


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


    try:
        history = doc_db.unpack_document_journal(
            document_id=document_id,
            form_name=form_name,
            limit_users=limit_query_to,
        )

    except DocumentDoesNotExist as e:
        raise HTTPException(status_code=404, detail=f"{e}")

    except InsufficientPermissions as e:
        raise HTTPException(status_code=403, detail=f"{e}")

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
    sort_by: str = "__metadata__created_at",
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

    You can pass `sort_by` to specify the field to sort by. The default is __metadata__created_at. 
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
    fields: Optional[str] = None,  # Comma-separated list of fields
    config = Depends(get_config_depends),
    mailer = Depends(get_mailer), 
    doc_db = Depends(get_doc_db), 
    session: SessionLocal = Depends(get_db), 
    key: str = Depends(X_API_KEY)
):
    """
    Retrieves all documents of a specified form type, identified by the form name in the URL.
    It verifies the form's existence, checks user permissions, retrieves documents from the 
    database, and returns the form as an excel file before logging the query. Optionally, 
    the `fields` query param may be passed to limit the export to a subset of columns, using
    the same format as the read_all UI page, eg. `data:field1,metadata:created_by`.
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



    # Parse fields parameter if provided, using the same format as the read_all UI page
    selected_fields = None
    if fields:
        selected_fields = [f.strip() for f in fields.split(',') if f.strip()]

    document_path = doc_db.get_all_documents_as_excel(
        form_name, 
        limit_users=limit_query_to,
        fields=selected_fields if selected_fields else False,
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
            query_params={"fields": fields} if fields else {},
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
@app.get("/api/form/search/{form_name}", dependencies=[Depends(api_key_auth)])
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

    for _form_name in form_names:
        if "read_own" in user_group_permissions[_form_name]:
            if "read_all" in user_group_permissions[_form_name]:
                limit_query_to[_form_name] = False
            else:
                limit_query_to[_form_name] = user.username

    documents = doc_db.fuzzy_search_documents(
        search_term=search_term,
        form_name=form_name,
        limit_users=limit_query_to,
        escape_output=True,
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
        escape_output=True,
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
