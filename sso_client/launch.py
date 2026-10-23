"""Cookie-free app launch: open another app with the user already signed in.

Two calls, both made from your BACKEND (never the browser):

    source app:  url = client.launch_url(target="insignai", email=user_email,
                                         context={"action": "..."})
                 -> give `url` to your frontend, which opens it in a new tab.

    target app:  identity = client.redeem(code)      # code from your landing page
                 -> Identity(email, source, context); sign `identity.email` in
                    with your app's normal session.

The launch code is single use, valid for about a minute, and travels in the URL
fragment. Both calls authenticate your app to the orchestrator with a short JWT
signed by your private key; the orchestrator's answer to redeem() is an RS256
identity token, verified here against the orchestrator's public key before any
of it is trusted. Users are identified by email only.
"""
from __future__ import annotations

import os
import pathlib
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
import jwt

DEFAULT_TIMEOUT_SECONDS = 10.0
ASSERTION_TTL_SECONDS = 300
CLOCK_LEEWAY_SECONDS = 30

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")


# =============================================================================
# Results and errors
# =============================================================================

@dataclass(frozen=True)
class LaunchResult:
    launch_url: str
    expires_in: int


@dataclass(frozen=True)
class Identity:
    """Who the orchestrator says the user is. `email` is lower-case."""
    email: str
    source: str
    context: Dict[str, Any] = field(default_factory=dict)
    claims: Dict[str, Any] = field(default_factory=dict, repr=False)


class LaunchError(Exception):
    """Base class. `code` is a stable machine-readable reason."""

    def __init__(self, message: str, *, code: str = "launch_error", status: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class LaunchConfigError(LaunchError):
    """The client is missing configuration (keys, endpoints)."""


class LaunchRejected(LaunchError):
    """The orchestrator refused the request (4xx)."""


class InvalidLaunchCode(LaunchRejected):
    """The code is malformed, expired, already used, or meant for another app."""


class OrchestratorUnavailable(LaunchError):
    """Network error, timeout or 5xx from the orchestrator. Safe to retry later."""


# =============================================================================
# Client
# =============================================================================

def _read_file(path: Optional[str]) -> str:
    if not path:
        return ""
    return pathlib.Path(path).expanduser().read_text(encoding="utf-8")


def _endpoint(base: Optional[str], path: str) -> Optional[str]:
    return f"{base.rstrip('/')}/{path}" if base else None


class LaunchClient:
    """Talks to the orchestrator's /sso/launch and /sso/redeem endpoints."""

    def __init__(
        self,
        *,
        client_id: str,
        private_key: str,
        launch_endpoint: Optional[str] = None,
        redeem_endpoint: Optional[str] = None,
        orchestrator_public_key: str = "",
        config_uri: Optional[str] = None,
        audience: str = "orchestrator",
        orchestrator_issuer: str = "orchestrator",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: Optional[httpx.Client] = None,
    ):
        if not isinstance(client_id, str) or not _CLIENT_ID_RE.match(client_id):
            raise LaunchConfigError("client_id is missing or invalid", code="config_client_id")
        if not private_key or "PRIVATE KEY" not in private_key:
            raise LaunchConfigError("private_key must be a PEM private key", code="config_private_key")
        if not launch_endpoint and not redeem_endpoint:
            raise LaunchConfigError("Set launch_endpoint and/or redeem_endpoint", code="config_endpoints")
        self.client_id = client_id
        self._private_key = private_key.replace("\\n", "\n")
        self.launch_endpoint = launch_endpoint
        self.redeem_endpoint = redeem_endpoint
        self._orchestrator_public_key = (orchestrator_public_key or "").replace("\\n", "\n")
        # Where to fetch the orchestrator public key from (GET /sso/config) when
        # it isn't configured locally. Fetched once, on the first redeem().
        self.config_uri = config_uri
        self._key_lock = threading.Lock()
        self.audience = audience
        self.orchestrator_issuer = orchestrator_issuer
        self.timeout = timeout
        self._http = http_client

    def __repr__(self) -> str:  # never show key material
        return f"LaunchClient(client_id={self.client_id!r}, launch={self.launch_endpoint!r}, redeem={self.redeem_endpoint!r})"

    # ---- construction helpers ----

    @classmethod
    def from_settings(
        cls,
        *,
        client_id: str,
        private_key_path: Optional[str] = None,
        private_key: Optional[str] = None,
        orchestrator_url: Optional[str] = None,
        launch_endpoint: Optional[str] = None,
        redeem_endpoint: Optional[str] = None,
        orchestrator_public_key_path: Optional[str] = None,
        orchestrator_public_key: Optional[str] = None,
        **kwargs,
    ) -> "LaunchClient":
        """Build from plain values, e.g. your app's own config. `orchestrator_url`
        is the orchestrator's base URL including its root path, such as
        https://sso.example.com/auth_orchestrator."""
        try:
            key = private_key or _read_file(private_key_path)
            public = orchestrator_public_key or _read_file(orchestrator_public_key_path)
        except OSError as exc:
            raise LaunchConfigError(f"Could not read a key file: {exc}", code="config_key_file") from exc
        if not kwargs.get("config_uri"):
            kwargs["config_uri"] = _endpoint(orchestrator_url, "sso/config")
        return cls(
            client_id=client_id,
            private_key=key,
            launch_endpoint=launch_endpoint or _endpoint(orchestrator_url, "sso/launch"),
            redeem_endpoint=redeem_endpoint or _endpoint(orchestrator_url, "sso/redeem"),
            orchestrator_public_key=public,
            **kwargs,
        )

    @classmethod
    def from_env(cls, **overrides) -> "LaunchClient":
        """Reads SSO_CLIENT_ID, SSO_CLIENT_PRIVATE_KEY_PATH (or SSO_CLIENT_PRIVATE_KEY),
        SSO_LAUNCH_ENDPOINT / SSO_REDEEM_ENDPOINT (or SSO_ORCHESTRATOR_URL),
        SSO_ORCHESTRATOR_PUBLIC_KEY_PATH (or SSO_ORCHESTRATOR_PUBLIC_KEY),
        and optionally SSO_AUDIENCE, SSO_ORCHESTRATOR_ISSUER, SSO_HTTP_TIMEOUT_SECONDS."""
        values = dict(
            client_id=os.getenv("SSO_CLIENT_ID", ""),
            private_key_path=os.getenv("SSO_CLIENT_PRIVATE_KEY_PATH"),
            private_key=os.getenv("SSO_CLIENT_PRIVATE_KEY"),
            orchestrator_url=os.getenv("SSO_ORCHESTRATOR_URL"),
            launch_endpoint=os.getenv("SSO_LAUNCH_ENDPOINT"),
            redeem_endpoint=os.getenv("SSO_REDEEM_ENDPOINT"),
            orchestrator_public_key_path=os.getenv("SSO_ORCHESTRATOR_PUBLIC_KEY_PATH"),
            orchestrator_public_key=os.getenv("SSO_ORCHESTRATOR_PUBLIC_KEY"),
            config_uri=os.getenv("SSO_CONFIG_URI") or None,
            audience=os.getenv("SSO_AUDIENCE", "orchestrator"),
            orchestrator_issuer=os.getenv("SSO_ORCHESTRATOR_ISSUER", "orchestrator"),
        )
        timeout = os.getenv("SSO_HTTP_TIMEOUT_SECONDS")
        if timeout:
            try:
                values["timeout"] = float(timeout)
            except ValueError:
                raise LaunchConfigError("SSO_HTTP_TIMEOUT_SECONDS must be a number", code="config_timeout")
        values.update(overrides)
        return cls.from_settings(**values)

    # ---- client assertion ----

    def build_client_assertion(self) -> str:
        """Short-lived private_key_jwt proving this request comes from this app."""
        now = datetime.now(timezone.utc)
        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "iat": now,
            "exp": now + timedelta(seconds=ASSERTION_TTL_SECONDS),
            "jti": str(uuid.uuid4()),
        }
        try:
            return jwt.encode(payload, self._private_key, algorithm="RS256")
        except Exception as exc:  # bad key format
            raise LaunchConfigError(f"Could not sign the client assertion: {exc}", code="config_private_key") from exc

    # ---- source side ----

    def create_launch(self, target: str, email: str, context: Optional[Dict[str, Any]] = None) -> LaunchResult:
        """Ask for a one-time link that opens `target` signed in as `email`."""
        if not self.launch_endpoint:
            raise LaunchConfigError("launch_endpoint is not configured", code="config_endpoints")
        if not isinstance(target, str) or not _CLIENT_ID_RE.match(target):
            raise LaunchRejected("target is not a valid app id", code="invalid_target")
        if not isinstance(email, str) or "@" not in email:
            raise LaunchRejected("email is not a valid address", code="invalid_email")
        if context is not None and not isinstance(context, dict):
            raise LaunchRejected("context must be a dict", code="invalid_context")

        body = self._post(self.launch_endpoint, {
            "client_assertion": self.build_client_assertion(),
            "target": target,
            "email": email.strip(),
            "context": context,
        })
        launch_url, expires_in = body.get("launch_url"), body.get("expires_in")
        if not isinstance(launch_url, str) or not launch_url.startswith(("https://", "http://")):
            raise OrchestratorUnavailable("Orchestrator returned no launch URL", code="bad_response")
        return LaunchResult(launch_url=launch_url, expires_in=int(expires_in or 0))

    def launch_url(self, target: str, email: str, context: Optional[Dict[str, Any]] = None) -> str:
        return self.create_launch(target, email, context).launch_url

    # ---- target side ----

    def redeem(self, code: str) -> Identity:
        """Swap a launch code for the user's verified identity."""
        if not self.redeem_endpoint:
            raise LaunchConfigError("redeem_endpoint is not configured", code="config_endpoints")
        # Make sure we can verify the answer before the single-use code is spent.
        self._get_orchestrator_public_key()
        if not isinstance(code, str) or not _CODE_RE.match(code.strip()):
            raise InvalidLaunchCode("The sign-in link is not valid", code="invalid_or_expired_code", status=400)

        body = self._post(self.redeem_endpoint, {
            "client_assertion": self.build_client_assertion(),
            "code": code.strip(),
        })
        token = body.get("identity_token")
        if not isinstance(token, str) or not token:
            raise OrchestratorUnavailable("Orchestrator returned no identity token", code="bad_response")
        return self.verify_identity_token(token)

    def _get_orchestrator_public_key(self) -> str:
        if self._orchestrator_public_key:
            return self._orchestrator_public_key
        if not self.config_uri:
            raise LaunchConfigError(
                "orchestrator public key is not configured; set it or an orchestrator URL to fetch it from",
                code="config_public_key",
            )
        with self._key_lock:
            if not self._orchestrator_public_key:
                try:
                    if self._http is not None:
                        response = self._http.get(self.config_uri, timeout=self.timeout)
                    else:
                        response = httpx.get(self.config_uri, timeout=self.timeout)
                    response.raise_for_status()
                    pem = response.json().get("orchestrator_public_key_pem") or ""
                except (httpx.HTTPError, ValueError, AttributeError) as exc:
                    raise OrchestratorUnavailable(
                        f"Could not fetch the orchestrator public key: {exc}", code="unreachable"
                    ) from exc
                if "PUBLIC KEY" not in pem:
                    raise LaunchConfigError(
                        "The orchestrator did not publish a public key", code="config_public_key"
                    )
                self._orchestrator_public_key = pem
        return self._orchestrator_public_key

    def verify_identity_token(self, token: str) -> Identity:
        try:
            claims = jwt.decode(
                token,
                self._get_orchestrator_public_key(),
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.orchestrator_issuer,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "email", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise LaunchRejected(f"Identity token failed verification: {exc}", code="invalid_identity_token") from exc

        email = claims.get("email")
        if not isinstance(email, str) or "@" not in email or email != claims.get("sub"):
            raise LaunchRejected("Identity token has no valid email", code="invalid_identity_token")
        source = claims.get("src")
        context = claims.get("ctx") or {}
        if not isinstance(source, str) or not isinstance(context, dict):
            raise LaunchRejected("Identity token has invalid src/ctx", code="invalid_identity_token")
        return Identity(email=email.strip().lower(), source=source, context=context, claims=claims)

    # ---- HTTP ----

    def _post(self, url: str, payload: dict) -> dict:
        """POST JSON. A failed connection (request never sent) is retried once;
        anything else is not, because a launch code is single use."""
        attempts = 2
        for attempt in range(attempts):
            try:
                if self._http is not None:
                    response = self._http.post(url, json=payload, timeout=self.timeout)
                else:
                    response = httpx.post(url, json=payload, timeout=self.timeout)
                break
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if attempt + 1 == attempts:
                    raise OrchestratorUnavailable(f"Could not reach the orchestrator: {exc}", code="unreachable") from exc
                # Each attempt needs a fresh assertion (jti is single use).
                payload = {**payload, "client_assertion": self.build_client_assertion()}
            except httpx.HTTPError as exc:
                raise OrchestratorUnavailable(f"Orchestrator request failed: {exc}", code="unreachable") from exc

        if response.status_code >= 500:
            raise OrchestratorUnavailable(
                f"Orchestrator error ({response.status_code})", code="orchestrator_error", status=response.status_code,
            )
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 400:
            code, message = _error_from(body, response.status_code)
            error_cls = InvalidLaunchCode if code == "invalid_or_expired_code" else LaunchRejected
            raise error_cls(message, code=code, status=response.status_code)
        if not isinstance(body, dict):
            raise OrchestratorUnavailable("Orchestrator returned an unexpected body", code="bad_response")
        return body


def _error_from(body: Any, status: int):
    """Orchestrator errors look like {"detail": {"code", "message"}}, a plain
    {"detail": "..."} or FastAPI's 422 list; normalise all three."""
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return str(detail.get("code") or f"http_{status}"), str(detail.get("message") or "Request rejected")
    if isinstance(detail, str):
        return f"http_{status}", detail
    if isinstance(detail, list):
        return "invalid_request", "; ".join(str(d.get("msg", d)) for d in detail if isinstance(d, dict)) or "Invalid request"
    return f"http_{status}", "Request rejected"
