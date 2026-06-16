"""sso-client: drop-in SSO integration for orchestrator client projects.

Typical usage (FastAPI):

    from sso_client import SSOClientConfig, create_sso_router

    config = SSOClientConfig.from_env(dashboard_url="/dashboard")
    app.include_router(create_sso_router(config))
"""
from .config import SSOClientConfig
from .core import (
    build_authorize_url,
    build_client_assertion,
    exchange_code,
    new_state,
    verify_access_token,
)
from .fastapi_router import create_sso_router

__all__ = [
    "SSOClientConfig",
    "create_sso_router",
    "build_authorize_url",
    "build_client_assertion",
    "exchange_code",
    "new_state",
    "verify_access_token",
]
