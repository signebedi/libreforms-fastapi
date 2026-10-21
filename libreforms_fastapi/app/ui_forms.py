from typing import Optional
from fastapi import HTTPException, Depends, Query
from fastapi.responses import HTMLResponse
from starlette.authentication import requires
from starlette.requests import Request
from libreforms_fastapi.utils.pydantic_models import (
    get_form_model, get_form_names, get_form_html, load_form_config,
)

from libreforms_fastapi.app.core import (
    app, build_ui_context, get_config_depends, get_db, get_doc_db, Group, SessionLocal,
    signatures, templates, User,
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
