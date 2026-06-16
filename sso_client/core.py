"""Framework-agnostic SSO client logic.

These pure functions are the boilerplate that is IDENTICAL for every client in
the flow diagram. They map 1:1 onto the numbered steps so the behaviour is easy
to audit:

    step 2  -> new_state() + build_authorize_url()
    step 6  -> build_client_assertion()  (CSRF check lives in the router)
    step 7  -> exchange_code()
    (token validation) -> verify_access_token()
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from .config import SSOClientConfig


def new_state() -> str:
    """A random, opaque CSRF/state value (step 2)."""
    return secrets.token_urlsafe(32)


def build_authorize_url(config: SSOClientConfig, state: str) -> str:
    """The orchestrator redirect URL the browser is sent to (step 2)."""
    from urllib.parse import urlencode

    query = urlencode({
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "state": state,
    })
    return f"{config.authorize_endpoint}?{query}"


def build_client_assertion(config: SSOClientConfig) -> str:
    """Sign the private_key_jwt client assertion (step 6).

    iss == sub == client_id, aud == orchestrator, short-lived, unique jti for
    replay protection — exactly what the orchestrator's /sso/token verifies.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": config.audience,
        "iat": now,
        "exp": now + timedelta(seconds=config.assertion_ttl_seconds),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, config.client_private_key, algorithm=config.signing_alg)


def exchange_code(config: SSOClientConfig, code: str) -> str:
    """Swap an auth code for a user access token (step 7). Returns the token."""
    response = httpx.post(
        config.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "client_id": config.client_id,
            "client_assertion_type": config.client_assertion_type,
            "client_assertion": build_client_assertion(config),
        },
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def verify_access_token(config: SSOClientConfig, token: str) -> dict:
    """Validate the RS256 user token locally and return its claims.

    Requires orchestrator_public_key to be set (from discovery or the packet).
    Lets the client protect its own routes without calling back to the SSO.
    """
    if not config.orchestrator_public_key:
        raise RuntimeError(
            "orchestrator_public_key is not set; fetch it from /sso/config or jwks."
        )
    return jwt.decode(
        token,
        config.orchestrator_public_key,
        algorithms=[config.signing_alg],
        issuer=config.orchestrator_issuer,
        options={"require": ["exp", "iss", "user_id", "token_id"]},
    )
