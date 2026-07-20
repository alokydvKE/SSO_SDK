# sso-client

Drop-in SSO integration for orchestrator client projects. It implements the
client half of the login flow (the state/CSRF dance, the signed `private_key_jwt`
client assertion, the code→token exchange, and session cookie handling) so a new
project never hand-codes it.

## Why

In the orchestrator flow, the **client** owns three steps that are identical for
every project except for a few config values:

| Step | What the client must do | Who owns it now |
|------|-------------------------|-----------------|
| 2 | Generate `state`, set cookie, redirect to `/sso/authorize` | **this SDK** |
| 6 | CSRF-check `state`, sign client-assertion JWT | **this SDK** |
| 7–8 | POST `/sso/token`, set session cookie | **this SDK** |

The only per-project inputs are: `client_id`, the private key, the redirect URI,
and the orchestrator endpoints — all delivered in the **integration packet** that
`POST /create_project` now returns.

## Onboard a project (3 steps)

```bash
# 1. install (from git — not on PyPI)
pip install "git+https://github.com/alokydvKE/SSO_SDK.git@main"
# private repo? use an SSH deploy key:
#   pip install "git+ssh://git@github.com/alokydvKE/SSO_SDK.git@main"

# 2. generate keys locally + write .env + register the PUBLIC key.
#    The PRIVATE key never leaves your machine.
sso-client init \
  --client-id logger_be \
  --config-uri http://localhost:8000/auth_orchestrator/sso/config \
  --redirect-uri http://localhost:8001/projects/callback
```

```python
# 3. mount the router
from sso_client import SSOClientConfig, create_sso_router

config = SSOClientConfig.from_env(dashboard_url="/dashboard")
app.include_router(create_sso_router(config))
```

You now have:

- `GET /auth/sso/start` — kicks off login (step 2)
- `GET /projects/callback` — handles the return (steps 6–9)

`sso-client init` writes a `.env` whose `SSO_CLIENT_PRIVATE_KEY_PATH` points at the
local key file — so the private key is never embedded in `.env` or sent anywhere.
Pass `--admin-token <jwt>` to auto-register the public key, or register it from the
SSO admin UI's **Integration** panel.

### Config sources

- **`SSOClientConfig.from_env()`** — reads the `SSO_*` vars and loads the private
  key from `SSO_CLIENT_PRIVATE_KEY_PATH` (a local file) — or inline
  `SSO_CLIENT_PRIVATE_KEY` for backwards compatibility.
- **`SSOClientConfig.from_discovery(config_uri, ...)`** — fetches `/sso/config`
  at startup so endpoints and the orchestrator public key stay current through
  key rotation.

### Protecting your own routes

```python
from sso_client import verify_access_token

claims = verify_access_token(config, request.cookies["project_session"])
# -> {"user_id": ..., "role": ..., "token_id": ..., ...}
```

## Run the example

```bash
# after `sso-client init` has written .env + ./keys in this folder
uvicorn example.app:app --reload --port 8001
# open http://localhost:8001/auth/sso/start
```
