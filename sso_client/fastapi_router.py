"""Ready-made FastAPI router implementing the client half of the SSO flow.

Mounting this gives a project the two endpoints it would otherwise hand-code:

    GET /auth/sso/start        (step 2)  -> set state cookie, redirect to authorize
    GET /projects/callback     (steps 6-9) -> CSRF check, assertion, exchange, session

A new project wires this up in ~3 lines (see example/app.py). No JWT, no CSRF,
no cookie-flag handling to get wrong.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette import status

from . import core
from .config import SSOClientConfig


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
