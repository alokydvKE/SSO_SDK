"""Ready-made FastAPI routers.

App launch: `add_sso(app, on_login=..., current_user_email=...)` mounts
POST /sso/redeem and POST /sso/launch in one call.

Legacy cookie flow: mounting create_sso_router gives a project the two
endpoints it would otherwise hand-code:

    GET /auth/sso/start        (step 2)  -> set state cookie, redirect to authorize
    GET /projects/callback     (steps 6-9) -> CSRF check, assertion, exchange, session

A new project wires this up in ~3 lines (see example/app.py). No JWT, no CSRF,
no cookie-flag handling to get wrong.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from starlette import status

from . import core
from .config import SSOClientConfig
from .launch import (
    Identity,
    InvalidLaunchCode,
    LaunchClient,
    LaunchConfigError,
    LaunchRejected,
    OrchestratorUnavailable,
    load_env_file,
)


def create_sso_router(config: SSOClientConfig, *, prefix: str = "") -> APIRouter:
    router = APIRouter(prefix=prefix)

    @router.get("/auth/sso/start")
    def sso_start():
        # --- step 2: generate state, stash it in an HttpOnly cookie, redirect ---
        state = core.new_state()
        response = RedirectResponse(
            url=core.build_authorize_url(config, state),
            status_code=status.HTTP_302_FOUND,
        )
        response.set_cookie(
            key=config.state_cookie_name,
            value=state,
            httponly=True,
            secure=config.cookie_secure,
            samesite=config.cookie_samesite,
            max_age=config.state_cookie_ttl_seconds,
            path="/",
        )
        return response

    @router.get("/projects/callback")
    def sso_callback(request: Request, code: str, state: str):
        # --- step 6: CSRF check (compare returned state to the cookie) ---
        expected_state = request.cookies.get(config.state_cookie_name)
        if not expected_state or expected_state != state:
            raise HTTPException(status_code=400, detail="State mismatch")

        # --- step 7: build assertion + exchange the code for a user token ---
        try:
            access_token = core.exchange_code(config, code)
        except Exception as exc:  # surface the orchestrator's rejection cleanly
            raise HTTPException(status_code=401, detail=f"Token exchange failed: {exc}")

        # --- steps 8-9: set the project session cookie, clear state, go to app ---
        response = RedirectResponse(
            url=config.dashboard_url, status_code=status.HTTP_302_FOUND
        )
        response.set_cookie(
            key=config.session_cookie_name,
            value=access_token,
            httponly=True,
            secure=config.cookie_secure,
            samesite=config.cookie_samesite,
            max_age=config.session_cookie_max_age,
            path="/",
        )
        response.delete_cookie(config.state_cookie_name, path="/")
        return response

    return router


class RedeemCodeBody(BaseModel):
    """Body your landing page POSTs to the redeem endpoint."""
    code: str = Field(min_length=1, max_length=256)


def create_launch_redeem_router(
    client: "LaunchClient",
    on_login: Callable[[Identity, Request], Any],
    *,
    path: str = "/sso/redeem",
    prefix: str = "",
) -> APIRouter:
    """Target side of the cookie-free app launch, as one POST endpoint.

    Your landing page reads the code from the URL fragment and POSTs
    {"code": "..."} here. The SDK redeems it and verifies the identity; you only
    write `on_login(identity, request)`, which signs `identity.email` in with
    your app's normal session and returns whatever your login endpoint returns.
    """
    router = APIRouter(prefix=prefix)

    @router.post(path)
    def redeem_launch_code(body: RedeemCodeBody, request: Request):
        try:
            identity = client.redeem(body.code)
        except InvalidLaunchCode as exc:
            raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})
        except OrchestratorUnavailable as exc:
            raise HTTPException(status_code=503, detail={"code": exc.code, "message": "Sign-in is temporarily unavailable"})
        except LaunchConfigError as exc:
            raise HTTPException(status_code=503, detail={"code": exc.code, "message": "SSO is not configured on this server"})
        except LaunchRejected as exc:
            raise HTTPException(status_code=401, detail={"code": exc.code, "message": exc.message})
        return on_login(identity, request)

    return router


class LaunchAppBody(BaseModel):
    """Body your frontend POSTs to open another app."""
    target: str = Field(min_length=1, max_length=100)
    context: Optional[Dict[str, Any]] = None


def create_launch_router(
    client: "LaunchClient",
    current_user_email: Callable[..., str],
    *,
    path: str = "/sso/launch",
    prefix: str = "",
) -> APIRouter:
    """Source side of the cookie-free app launch, as one POST endpoint.

    Your frontend POSTs {"target": "<client_id>", "context": {...}} and opens
    the returned launch_url in a new tab. `current_user_email` is a FastAPI
    dependency that returns the signed-in user's email and rejects anonymous
    callers, like your other protected routes do.
    """
    router = APIRouter(prefix=prefix)

    @router.post(path)
    def launch_app(body: LaunchAppBody, email: str = Depends(current_user_email)):
        try:
            result = client.create_launch(body.target, email, body.context)
        except OrchestratorUnavailable as exc:
            raise HTTPException(status_code=503, detail={"code": exc.code, "message": "Sign-in is temporarily unavailable"})
        except LaunchConfigError as exc:
            raise HTTPException(status_code=503, detail={"code": exc.code, "message": "SSO is not configured on this server"})
        except LaunchRejected as exc:
            # The orchestrator refused (e.g. this app isn't an allowed source).
            # Not 401: the user's own session is fine.
            raise HTTPException(status_code=502, detail={"code": exc.code, "message": exc.message})
        return {"launch_url": result.launch_url, "expires_in": result.expires_in}

    return router


def add_sso(
    app: Any,
    on_login: Optional[Callable[[Identity, Request], Any]] = None,
    *,
    current_user_email: Optional[Callable[..., str]] = None,
    prefix: str = "",
    env_file: str = ".env",
    client: Optional[LaunchClient] = None,
) -> LaunchClient:
    """Everything a FastAPI app needs for app launch, in one call.

    Reads the SSO_* settings `sso-client setup` wrote to `env_file`, then mounts
      POST {prefix}/sso/redeem  if `on_login` is given: other apps can open this one
      POST {prefix}/sso/launch  if `current_user_email` is given: this app can open others
    and returns the LaunchClient, for calling launch_url() yourself.
    `app` is your FastAPI app or an APIRouter.
    """
    if on_login is None and current_user_email is None:
        raise TypeError("add_sso() needs on_login, current_user_email, or both")
    if client is None:
        load_env_file(env_file)
        client = LaunchClient.from_env()
    if on_login is not None:
        app.include_router(create_launch_redeem_router(client, on_login, prefix=prefix))
    if current_user_email is not None:
        app.include_router(create_launch_router(client, current_user_email, prefix=prefix))
    return client
