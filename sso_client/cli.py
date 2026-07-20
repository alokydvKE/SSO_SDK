"""`sso-client` command line tool.

`sso-client init` is the one command a project owner runs to onboard:

  1. generates an RSA keypair LOCALLY (the private key never leaves the machine)
  2. fetches the orchestrator's discovery doc and writes a ready .env
  3. registers the PUBLIC key with the orchestrator (or prints it to register
     via the admin UI)

After it runs, the owner only has to mount the SDK router.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sso-client")
    sub = parser.add_subparsers(dest="command", required=True)

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
    args.func(args)


if __name__ == "__main__":
    main()
