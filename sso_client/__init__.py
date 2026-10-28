"""sso-client: app launch SSO for orchestrator client apps.

Open another app with the user already signed in, cookie-free and server to
server. After `sso-client setup`, in a FastAPI app:

    from sso_client import add_sso

    add_sso(app, on_login=login_by_email, current_user_email=get_user_email)

Any other Python app:

    from sso_client import LaunchClient, load_env_file

    load_env_file()                     # SSO_* lines of ./.env
    sso = LaunchClient.from_env()
    url = sso.launch_url(target="insignai", email=user_email, context={...})  # source app
    identity = sso.redeem(code)                                               # target app
"""
from .launch import (
    Identity,
    InvalidLaunchCode,
    LaunchClient,
    LaunchConfigError,
    LaunchError,
    LaunchRejected,
    LaunchResult,
    OrchestratorUnavailable,
    load_env_file,
)

__version__ = "0.4.0"

__all__ = [
    "add_sso",
    "LaunchClient",
    "LaunchResult",
    "Identity",
    "LaunchError",
    "LaunchConfigError",
    "LaunchRejected",
    "InvalidLaunchCode",
    "OrchestratorUnavailable",
    "load_env_file",
    "create_launch_redeem_router",
    "create_launch_router",
]


def __getattr__(name):
    # The FastAPI helpers are imported lazily so the launch client works in
    # apps that don't use FastAPI.
    if name in ("add_sso", "create_launch_redeem_router", "create_launch_router"):
        from . import fastapi_router
        return getattr(fastapi_router, name)
    raise AttributeError(f"module 'sso_client' has no attribute {name!r}")
