"""sso-client: drop-in SSO integration for orchestrator client projects.

Cookie-free app launch (recommended):

    from sso_client import LaunchClient

    sso = LaunchClient.from_env()
    url = sso.launch_url(target="insignai", email=user_email, context={...})  # source app
    identity = sso.redeem(code)                                               # target app

Legacy cookie redirect flow (FastAPI):

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
from .launch import (
    Identity,
    InvalidLaunchCode,
    LaunchClient,
    LaunchConfigError,
    LaunchError,
    LaunchRejected,
    LaunchResult,
    OrchestratorUnavailable,
)

__version__ = "0.2.0"

__all__ = [
    # cookie-free app launch
    "LaunchClient",
    "LaunchResult",
    "Identity",
    "LaunchError",
    "LaunchConfigError",
    "LaunchRejected",
    "InvalidLaunchCode",
    "OrchestratorUnavailable",
    "create_launch_redeem_router",
    # legacy cookie redirect flow
    "SSOClientConfig",
    "create_sso_router",
    "build_authorize_url",
    "build_client_assertion",
    "exchange_code",
    "new_state",
    "verify_access_token",
]


def __getattr__(name):
    # The FastAPI helpers are imported lazily so the launch client works in
    # apps that don't use FastAPI.
    if name in ("create_sso_router", "create_launch_redeem_router"):
        from . import fastapi_router
        return getattr(fastapi_router, name)
    raise AttributeError(f"module 'sso_client' has no attribute {name!r}")
