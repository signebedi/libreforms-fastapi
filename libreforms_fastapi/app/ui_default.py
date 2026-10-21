import os
from fastapi import Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.authentication import requires
from starlette.requests import Request
from libreforms_fastapi.utils.pydantic_models import get_form_names
from libreforms_fastapi.utils.docs import get_docs

from libreforms_fastapi.app.core import app, build_ui_context, get_config_depends, templates


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
