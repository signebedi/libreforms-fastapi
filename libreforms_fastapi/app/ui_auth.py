from fastapi import Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.authentication import requires
from starlette.requests import Request

from libreforms_fastapi.app.core import (
    app, build_ui_context, get_config_depends, session, signatures, templates, User,
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
