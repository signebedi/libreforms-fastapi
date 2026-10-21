# The app is split into modules by area. core.py creates the app and holds the shared config,
# database, auth backend and dependencies, and each of the other modules registers its routes on
# that app when imported, so the order of the imports below is the order routes are registered in.
import os
import importlib, platform
from typing import Optional
from fastapi import Response, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.authentication import requires
from starlette.requests import Request
from libreforms_fastapi.__metadata__ import __version__
from libreforms_fastapi.utils.pydantic_models import (
    get_form_model, get_form_names, get_form_html, load_form_config, get_form_config_yaml,
    get_form_backups,
)
from libreforms_fastapi.utils.docs import get_docs
from libreforms_fastapi.utils.jinja_emails import get_email_yaml

from libreforms_fastapi.app.core import (
    api_key_auth, app, build_ui_context, config, engine, get_config_depends, get_db, get_doc_db,
    get_mailer, Group, logger, models, PasswordReuse, RelationshipType, session, SessionLocal,
    signatures, Signing, templates, TransactionLog, User, UserRelationship,
)

from libreforms_fastapi.app import (  # noqa: F401
    api_form,
    api_auth,
    api_admin,
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
