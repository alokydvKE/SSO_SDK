"""Minimal SSO client using the sso-client SDK.

This file is the ENTIRE integration. Everything (endpoints, key paths, cookie
flags, session cookie name, dashboard URL) comes from the .env that
`sso-client init` generated.

Setup & run (from the sso-client-sdk folder):
    pip install -e .
    sso-client init \\
        --client-id demo_app \\
        --config-uri http://localhost:8000/auth_orchestrator/sso/config \\
        --redirect-uri http://localhost:8001/projects/callback
    uvicorn example.app:app --reload --port 8001
    # open http://localhost:8001/
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from sso_client import SSOClientConfig, create_sso_router, verify_access_token

# 1. Build config — from_env() reads every SSO_* value from .env.
config = SSOClientConfig.from_env()

app = FastAPI(title="SSO client example")

# 2. Mount the router -> adds GET /auth/sso/start and GET /projects/callback.
app.include_router(create_sso_router(config))


@app.get("/", response_class=HTMLResponse)
def home():
    return (
        "<h2>SSO client example</h2>"
        '<p><a href="/auth/sso/start">Login with SSO</a> &middot; '
        '<a href="/dashboard">Dashboard</a></p>'
    )


# 3. Protect a route: read the session cookie and verify the token.
@app.get("/dashboard")
def dashboard(request: Request):
    token = request.cookies.get(config.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    claims = verify_access_token(config, token)
    # Equivalent without the SDK helper (plain PyJWT):
    #   import jwt, os
    #   from pathlib import Path
    #   key = Path(os.environ["SSO_ORCHESTRATOR_PUBLIC_KEY_PATH"]).read_text()
    #   claims = jwt.decode(token, key, algorithms=["RS256"], issuer="orchestrator",
    #                       options={"require": ["exp", "iss", "user_id", "token_id"]})

    return {"message": "You are authenticated", "user": claims}
