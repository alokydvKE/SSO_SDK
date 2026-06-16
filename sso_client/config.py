"""Client-side SSO configuration.

A client project provides a handful of values (mostly from the integration
packet / .env the orchestrator hands back at project creation). Everything else
about the flow is fixed boilerplate the SDK owns.
"""
from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

import httpx

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@dataclass
class SSOClientConfig:
    # ---- Identity & secret (from the integration packet) ----
    client_id: str
    client_private_key: str          # PEM; signs the client-assertion JWT (step 6)
    redirect_uri: str                # where the orchestrator sends the code back

    # ---- Orchestrator endpoints (filled from discovery or .env) ----
    authorize_endpoint: str
    token_endpoint: str

    # ---- Validation / protocol details (sane defaults match the orchestrator) ----
    audience: str = "orchestrator"
    orchestrator_issuer: str = "orchestrator"
    orchestrator_public_key: str = ""   # PEM; verify user tokens locally (optional)
    signing_alg: str = "RS256"
    client_assertion_type: str = CLIENT_ASSERTION_TYPE
    assertion_ttl_seconds: int = 300

    # ---- Cookies / routing on the CLIENT side ----
    state_cookie_name: str = "oauth_state"
    state_cookie_ttl_seconds: int = 300
    session_cookie_name: str = "project_session"
    session_cookie_max_age: int = 900
    dashboard_url: str = "/"
    cookie_secure: bool = True
    cookie_samesite: str = "none"

    @staticmethod
    def _load_private_key_from_env() -> str:
        """Prefer a key FILE (SSO_CLIENT_PRIVATE_KEY_PATH) over an inline value.

        The file path is the production-safe form: the PEM never lives in .env
        (no escaping, easy to gitignore). Inline SSO_CLIENT_PRIVATE_KEY stays
        supported for backwards compatibility.
        """
        key_path = os.getenv("SSO_CLIENT_PRIVATE_KEY_PATH")
        if key_path:
            return pathlib.Path(key_path).expanduser().read_text(encoding="utf-8")
        inline = os.getenv("SSO_CLIENT_PRIVATE_KEY")
        if inline:
            return inline.replace("\\n", "\n")
        raise KeyError(
            "Set SSO_CLIENT_PRIVATE_KEY_PATH (recommended) or SSO_CLIENT_PRIVATE_KEY"
        )

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        val = os.getenv(name)
        if val is None:
            return default
        return val.strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _load_orchestrator_public_key_from_env() -> str:
        """Optional: the orchestrator PUBLIC key, for validating tokens offline.

        `sso-client init` writes this to a file and sets
        SSO_ORCHESTRATOR_PUBLIC_KEY_PATH, so from_env() alone can power
        verify_access_token without a discovery call at runtime.
        """
        path = os.getenv("SSO_ORCHESTRATOR_PUBLIC_KEY_PATH")
        if path:
            return pathlib.Path(path).expanduser().read_text(encoding="utf-8")
        inline = os.getenv("SSO_ORCHESTRATOR_PUBLIC_KEY")
        return inline.replace("\\n", "\n") if inline else ""

    @classmethod
    def from_env(cls, **overrides) -> "SSOClientConfig":
        """Build entirely from SSO_* environment variables.

        Required:  SSO_CLIENT_ID, SSO_REDIRECT_URI, SSO_AUTHORIZE_ENDPOINT,
                   SSO_TOKEN_ENDPOINT, and a key (SSO_CLIENT_PRIVATE_KEY_PATH).
        Optional:  SSO_AUDIENCE, SSO_ORCHESTRATOR_PUBLIC_KEY_PATH, plus the
                   behavioural settings below. Keyword args override env.
        """
        cfg = cls(
            client_id=os.environ["SSO_CLIENT_ID"],
            client_private_key=cls._load_private_key_from_env(),
            redirect_uri=os.environ["SSO_REDIRECT_URI"],
            authorize_endpoint=os.environ["SSO_AUTHORIZE_ENDPOINT"],
            token_endpoint=os.environ["SSO_TOKEN_ENDPOINT"],
            audience=os.getenv("SSO_AUDIENCE", "orchestrator"),
            orchestrator_public_key=cls._load_orchestrator_public_key_from_env(),
        )

        # Optional behavioural settings — all read straight from .env.
        env_map = {
            "SSO_ORCHESTRATOR_ISSUER": "orchestrator_issuer",
            "SSO_DASHBOARD_URL": "dashboard_url",
            "SSO_SESSION_COOKIE_NAME": "session_cookie_name",
            "SSO_STATE_COOKIE_NAME": "state_cookie_name",
            "SSO_COOKIE_SAMESITE": "cookie_samesite",
        }
        for env_name, field_name in env_map.items():
            if os.getenv(env_name):
                setattr(cfg, field_name, os.environ[env_name])

        if os.getenv("SSO_SESSION_COOKIE_MAX_AGE"):
            cfg.session_cookie_max_age = int(os.environ["SSO_SESSION_COOKIE_MAX_AGE"])
        cfg.cookie_secure = cls._env_bool("SSO_COOKIE_SECURE", cfg.cookie_secure)

        for key, value in overrides.items():
            setattr(cfg, key, value)
        return cfg

    @classmethod
    def from_discovery(
        cls,
        config_uri: str,
        *,
        client_id: str,
        client_private_key: str,
        redirect_uri: str,
        **overrides,
    ) -> "SSOClientConfig":
        """Auto-configure endpoints + public key by fetching GET /sso/config.

        This is the most future-proof path: if the orchestrator rotates keys or
        moves endpoints, the client picks it up without a redeploy.
        """
        doc = httpx.get(config_uri, timeout=10.0).raise_for_status().json()
        cfg = cls(
            client_id=client_id,
            client_private_key=client_private_key.replace("\\n", "\n"),
            redirect_uri=redirect_uri,
            authorize_endpoint=doc["authorize_endpoint"],
            token_endpoint=doc["token_endpoint"],
            audience=doc.get("audience", "orchestrator"),
            orchestrator_issuer=doc.get("issuer", "orchestrator"),
            orchestrator_public_key=doc.get("orchestrator_public_key_pem", ""),
            signing_alg=doc.get("client_assertion_signing_alg", "RS256"),
            client_assertion_type=doc.get("client_assertion_type", CLIENT_ASSERTION_TYPE),
            assertion_ttl_seconds=doc.get("auth_code_ttl_seconds", 300),
        )
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return cfg
