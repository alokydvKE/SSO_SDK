"""`sso-client` command line tool.

`sso-client setup` onboards an app for cookie-free app launch in one command
(safe to re-run; it reuses what already exists):

  1. logs in to the orchestrator as an admin (asks for the password)
  2. registers the project, if it isn't registered yet
  3. creates an RSA key pair LOCALLY, or reuses the existing one, and registers
     only the PUBLIC key (the private key never leaves the machine)
  4. sets the app's landing URL and allowed launch sources
  5. writes the SSO block of .env

`sso-client init` is the older onboarding for the legacy cookie redirect flow.
"""
from __future__ import annotations

import argparse
import getpass
import os
import pathlib
import sys

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .launch import _CLIENT_ID_RE

RSA_KEY_SIZE = 2048


def _generate_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


BEGIN_MARK = "# >>> sso-client init >>>"
END_MARK = "# <<< sso-client init <<<"


def _write_env_block(env_path: pathlib.Path, block: str) -> str:
    """Add/refresh the SSO block WITHOUT destroying an existing .env.

    The block is delimited by markers, so re-running init replaces only our
    section and leaves every other variable in the file untouched.
    """
    new_block = f"{BEGIN_MARK}\n{block.strip()}\n{END_MARK}\n"

    if not env_path.exists():
        env_path.write_text(new_block, encoding="utf-8")
        return "created"

    existing = env_path.read_text(encoding="utf-8")
    if BEGIN_MARK in existing and END_MARK in existing:
        head, rest = existing.split(BEGIN_MARK, 1)
        _, tail = rest.split(END_MARK, 1)
        updated = head.rstrip("\n") + "\n\n" + new_block + tail.lstrip("\n")
        env_path.write_text(updated, encoding="utf-8")
        return "updated existing SSO block in"

    updated = existing.rstrip("\n") + "\n\n" + new_block
    env_path.write_text(updated, encoding="utf-8")
    return "appended SSO block to"


def _render_env(client_id: str, redirect_uri: str, cfg: dict, key_path: str,
                orch_pub_path: str, dashboard_url: str) -> str:
    # Cookie flags follow the redirect scheme: https -> Secure+None (prod),
    # plain http (localhost dev) -> not-Secure + Lax so the cookie actually sticks.
    is_https = redirect_uri.lower().startswith("https://")
    cookie_secure = "true" if is_https else "false"
    cookie_samesite = "none" if is_https else "lax"

    lines = [
        "# --- SSO (written by `sso-client init`) ---",
        f"SSO_CLIENT_ID={client_id}",
        f"SSO_REDIRECT_URI={redirect_uri}",
        f"SSO_AUTHORIZE_ENDPOINT={cfg['authorize_endpoint']}",
        f"SSO_TOKEN_ENDPOINT={cfg['token_endpoint']}",
        f"SSO_CONFIG_URI={cfg['config_uri']}",
        f"SSO_AUDIENCE={cfg.get('audience', 'orchestrator')}",
        f"SSO_CLIENT_PRIVATE_KEY_PATH={key_path}",
    ]
    if orch_pub_path:
        # Lets from_env() power verify_access_token offline (no discovery call).
        lines.append(f"SSO_ORCHESTRATOR_PUBLIC_KEY_PATH={orch_pub_path}")
    if cfg.get("launch_endpoint") and cfg.get("redeem_endpoint"):
        # Cookie-free app launch (LaunchClient.from_env()).
        lines += [
            f"SSO_LAUNCH_ENDPOINT={cfg['launch_endpoint']}",
            f"SSO_REDEEM_ENDPOINT={cfg['redeem_endpoint']}",
            f"SSO_ORCHESTRATOR_ISSUER={cfg.get('identity_token_issuer', 'orchestrator')}",
        ]

    lines += [
        "",
        "# --- Client behaviour (edit as needed) ---",
        f"SSO_SESSION_COOKIE_NAME={client_id}_session",
        "SSO_SESSION_COOKIE_MAX_AGE=900",
        f"# Cookie flags auto-set from your redirect scheme "
        f"({'https -> prod' if is_https else 'http -> local dev'}):",
        f"SSO_COOKIE_SECURE={cookie_secure}",
        f"SSO_COOKIE_SAMESITE={cookie_samesite}",
    ]
    if dashboard_url:
        lines.append(f"SSO_DASHBOARD_URL={dashboard_url}")
    else:
        lines.append("# SSO_DASHBOARD_URL=/dashboard   # where to send users after login")

    return "\n".join(lines) + "\n"


def _fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def cmd_init(args: argparse.Namespace) -> None:
    config_uri = args.config_uri or os.getenv("SSO_CONFIG_URI")
    redirect_uri = args.redirect_uri or os.getenv("SSO_REDIRECT_URI")
    if not config_uri:
        _fail("provide --config-uri (or set SSO_CONFIG_URI)")
    if not redirect_uri:
        _fail("provide --redirect-uri (or set SSO_REDIRECT_URI)")

    try:
        cfg = httpx.get(config_uri, timeout=10.0).raise_for_status().json()
    except Exception as exc:  # network / bad URL / non-JSON
        _fail(f"could not fetch discovery doc from {config_uri}: {exc}")

    keys_dir = pathlib.Path(args.keys_dir)
    private_path = keys_dir / f"{args.client_id}_private.pem"
    public_path = keys_dir / f"{args.client_id}_public.pem"
    if private_path.exists() and not args.force:
        _fail(f"{private_path} already exists; pass --force to overwrite (rotates the key)")

    keys_dir.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = _generate_keypair()
    private_path.write_text(private_pem, encoding="utf-8")
    try:
        os.chmod(private_path, 0o600)  # best effort; no-op on some platforms
    except OSError:
        pass
    public_path.write_text(public_pem, encoding="utf-8")

    # Save the orchestrator public key too, so verify_access_token works offline
    # via from_env() (no runtime discovery call needed).
    orch_pub_path = ""
    orch_pub_pem = cfg.get("orchestrator_public_key_pem", "")
    if orch_pub_pem:
        orch_path = keys_dir / "orchestrator_public.pem"
        orch_path.write_text(orch_pub_pem, encoding="utf-8")
        orch_pub_path = "./" + orch_path.as_posix().lstrip("./")

    env_key_path = "./" + private_path.as_posix().lstrip("./")
    env_action = _write_env_block(
        pathlib.Path(args.env_file),
        _render_env(args.client_id, redirect_uri, cfg, env_key_path, orch_pub_path,
                    args.dashboard_url),
    )

    print(f"  generated {private_path}  (keep secret — gitignore it)")
    print(f"  generated {public_path}")
    if orch_pub_path:
        print(f"  generated {keys_dir / 'orchestrator_public.pem'}")
    print(f"  {env_action} {args.env_file}")

    # Register the PUBLIC key with the orchestrator, or print it for the UI.
    base = config_uri.rsplit("/sso/config", 1)[0]
    register_url = f"{base}/projects/{args.client_id}/keys"
    if args.admin_token:
        try:
            resp = httpx.post(
                register_url,
                headers={"Authorization": f"Bearer {args.admin_token}"},
                json={"public_key_pem": public_pem},
                timeout=10.0,
            )
            resp.raise_for_status()
            print(f"  registered public key -> fingerprint {resp.json().get('fingerprint')}")
        except Exception as exc:
            _fail(f"key generated but registration failed: {exc}")
    else:
        print("\nNext: register this PUBLIC key in the SSO admin UI (or pass --admin-token):\n")
        print(public_pem)

    print("Done. Mount the SDK router and you're set.")


# =============================================================================
# setup (app launch)
# =============================================================================

def _detail(resp: httpx.Response) -> str:
    """The orchestrator's error message, from {"detail": "..."} or {"detail": {"message": ...}}."""
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:200]
    detail = body.get("detail") if isinstance(body, dict) else body
    if isinstance(detail, dict):
        return str(detail.get("message") or detail.get("code") or detail)
    return str(detail)


def _admin_token(http: httpx.Client, base: str, args: argparse.Namespace) -> str:
    if args.admin_token:
        return args.admin_token
    user = args.admin_user or os.getenv("SSO_ADMIN_USER") or input("SSO admin email: ").strip()
    password = os.getenv("SSO_ADMIN_PASSWORD") or getpass.getpass("SSO admin password: ")
    resp = http.post(f"{base}/login", json={"username": user, "password": password})
    if resp.status_code != 200:
        _fail(f"admin login failed ({resp.status_code}): {_detail(resp)}")
    return resp.json()["access_token"]


def _load_or_create_keypair(keys_dir: pathlib.Path, client_id: str, rotate: bool) -> tuple[pathlib.Path, str, bool]:
    """Reuse the app's private key if there is one, so re-running setup changes
    nothing; otherwise (or with rotate) make a new pair. Returns (private key
    path, public key PEM, created)."""
    private_path = keys_dir / f"{client_id}_private.pem"
    if private_path.exists() and not rotate:
        key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_path, public_pem, False

    keys_dir.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = _generate_keypair()
    private_path.write_text(private_pem, encoding="utf-8")
    try:
        os.chmod(private_path, 0o600)  # best effort; no-op on some platforms
    except OSError:
        pass
    (keys_dir / f"{client_id}_public.pem").write_text(public_pem, encoding="utf-8")
    return private_path, public_pem, True


def _path_for_env(path: pathlib.Path, env_file: pathlib.Path) -> str:
    """`path` relative to the .env's folder, which is how load_env_file() reads it."""
    try:
        rel = pathlib.Path(os.path.relpath(path.resolve(), env_file.resolve().parent)).as_posix()
    except ValueError:  # another drive on Windows
        return path.resolve().as_posix()
    return rel if rel.startswith(".") else f"./{rel}"


def _render_launch_env(client_id: str, base: str, cfg: dict, key_path: str, orch_pub_path: str) -> str:
    lines = [
        "# --- SSO app launch (written by `sso-client setup`; re-run it to refresh) ---",
        f"SSO_CLIENT_ID={client_id}",
        f"SSO_CLIENT_PRIVATE_KEY_PATH={key_path}",
        f"SSO_CONFIG_URI={cfg.get('config_uri') or base + '/sso/config'}",
        f"SSO_LAUNCH_ENDPOINT={cfg['launch_endpoint']}",
        f"SSO_REDEEM_ENDPOINT={cfg['redeem_endpoint']}",
        f"SSO_AUDIENCE={cfg.get('audience', 'orchestrator')}",
        f"SSO_ORCHESTRATOR_ISSUER={cfg.get('identity_token_issuer', 'orchestrator')}",
    ]
    if orch_pub_path:
        lines.append(f"SSO_ORCHESTRATOR_PUBLIC_KEY_PATH={orch_pub_path}")
    return "\n".join(lines) + "\n"


def cmd_setup(args: argparse.Namespace, http: httpx.Client | None = None) -> None:
    if http is None:
        with httpx.Client(timeout=10.0) as own_http:
            return cmd_setup(args, own_http)

    base = (args.orchestrator or os.getenv("SSO_ORCHESTRATOR_URL") or "").rstrip("/")
    if not base:
        _fail("provide --orchestrator (or set SSO_ORCHESTRATOR_URL), e.g. http://localhost:8010/auth_orchestrator")
    client_id = args.client_id
    if not _CLIENT_ID_RE.match(client_id):
        _fail("--client-id may use letters, digits, '_', '.' and '-' only")
    app_url = args.app_url.rstrip("/")
    landing_url = f"{app_url}/{args.landing_path.lstrip('/')}"
    env_file = pathlib.Path(args.env_file)
    keys_dir = pathlib.Path(args.keys_dir)
    print(f"Setting up {client_id} on {base}")

    # 1. discovery: the endpoints and the orchestrator's public key
    try:
        cfg = http.get(f"{base}/sso/config").raise_for_status().json()
    except Exception as exc:
        _fail(f"could not read {base}/sso/config: {exc}")
    if not (cfg.get("launch_endpoint") and cfg.get("redeem_endpoint")):
        _fail("this orchestrator does not support app launch (no launch_endpoint in /sso/config)")

    auth = {"Authorization": f"Bearer {_admin_token(http, base, args)}"}

    # 2. the project
    resp = http.post(f"{base}/create_project", headers=auth, json={
        "client_id": client_id,
        "project_name": args.name or client_id,
        "launch_url": app_url,
        "allowed_redirect_uris": landing_url,
    })
    if resp.status_code == 200:
        print("  project registered")
    elif resp.status_code == 400 and "already exists" in _detail(resp):
        print("  project already registered")
    else:
        _fail(f"could not register the project ({resp.status_code}): {_detail(resp)}")

    # 3. key pair; only the public half is sent
    private_path, public_pem, created = _load_or_create_keypair(keys_dir, client_id, args.rotate_key)
    resp = http.post(f"{base}/projects/{client_id}/keys", headers=auth, json={"public_key_pem": public_pem})
    if resp.status_code != 200:
        _fail(f"could not register the public key ({resp.status_code}): {_detail(resp)}")
    print(f"  {'generated' if created else 'reused'} {private_path}  (secret: keep it out of git)")
    print(f"  public key registered, fingerprint {resp.json().get('fingerprint')}")

    # 4. where launch links open, and which apps may send users here
    if args.allowed_sources is None:
        current = http.get(f"{base}/projects/{client_id}/launch-settings", headers=auth)
        sources = current.json().get("allowed_sources", []) if current.status_code == 200 else []
    else:
        sources = [s.strip() for s in args.allowed_sources.split(",") if s.strip()]
    resp = http.put(f"{base}/projects/{client_id}/launch-settings", headers=auth,
                    json={"landing_url": landing_url, "allowed_sources": sources})
    if resp.status_code != 200:
        _fail(f"could not save the launch settings ({resp.status_code}): {_detail(resp)}")
    saved = resp.json()
    print(f"  landing URL {saved['landing_url']}")
    print(f"  can be opened from: {', '.join(['the SSO portal'] + saved['allowed_sources'])}")

    # 5. .env
    orch_pub_path = ""
    if cfg.get("orchestrator_public_key_pem"):
        orch_path = keys_dir / "orchestrator_public.pem"
        orch_path.write_text(cfg["orchestrator_public_key_pem"], encoding="utf-8")
        orch_pub_path = _path_for_env(orch_path, env_file)
    env_action = _write_env_block(
        env_file,
        _render_launch_env(client_id, base, cfg, _path_for_env(private_path, env_file), orch_pub_path),
    )
    print(f"  {env_action} {env_file}")

    print("\nDone. Next:")
    print("  backend:  add_sso(app, on_login=..., current_user_email=...)  (see the README)")
    print(f"  frontend: a page at {landing_url} that POSTs the #code to your /sso/redeem")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sso-client")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="onboard this app for app launch: project, keys, landing URL, .env (safe to re-run)")
    setup.add_argument("--client-id", required=True)
    setup.add_argument("--app-url", required=True, help="your frontend's base URL, e.g. http://localhost:5600")
    setup.add_argument("--orchestrator", help="orchestrator base URL (or env SSO_ORCHESTRATOR_URL), "
                                              "e.g. http://localhost:8010/auth_orchestrator")
    setup.add_argument("--landing-path", default="/sso",
                       help="landing page on your frontend (default /sso; hash-routed apps: '#/sso')")
    setup.add_argument("--name", help="name shown in the portal (default: the client id)")
    setup.add_argument("--allowed-sources", help="apps allowed to open this one, comma-separated "
                                                 "(default: keep the current list; the SSO portal is always allowed)")
    setup.add_argument("--admin-user", help="orchestrator admin email (or env SSO_ADMIN_USER; asked if missing)")
    setup.add_argument("--admin-token", help="an admin JWT, instead of logging in")
    setup.add_argument("--keys-dir", default="./keys")
    setup.add_argument("--env-file", default=".env")
    setup.add_argument("--rotate-key", action="store_true", help="make a new key pair instead of reusing the existing one")
    setup.set_defaults(func=cmd_setup)

    init = sub.add_parser("init", help="generate keys, write .env, register public key")
    init.add_argument("--client-id", required=True)
    init.add_argument("--config-uri", help="orchestrator /sso/config URL (or env SSO_CONFIG_URI)")
    init.add_argument("--redirect-uri", help="your callback URL (or env SSO_REDIRECT_URI)")
    init.add_argument("--dashboard-url", help="where to send users after login (optional)")
    init.add_argument("--keys-dir", default="./keys")
    init.add_argument("--env-file", default=".env")
    init.add_argument("--admin-token", help="admin JWT to auto-register the public key")
    init.add_argument("--force", action="store_true", help="overwrite an existing key (rotate)")
    init.set_defaults(func=cmd_init)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except httpx.HTTPError as exc:
        _fail(f"request to the orchestrator failed: {exc}")


if __name__ == "__main__":
    main()
