# sso-client

## Cookie-free app launch (recommended)

Open another app with the user already signed in. No cookies; every trust
decision is made server to server, and users are identified by **email**.

```
source app BE --POST /sso/launch {assertion, target, email, context}--> orchestrator --> launch_url
browser opens launch_url  (= target's landing URL, one-time code in the # fragment, 60 s)
target app BE --POST /sso/redeem {assertion, code}--> orchestrator --> identity token (sub = email)
target app signs the email in with its own normal session
```

### Add an app in four steps

1. **Register** it in the orchestrator dashboard and run `sso-client init` to
   create its key pair and `.env`. As a target, set its **landing URL** and the
   apps allowed to launch into it (`PUT /projects/{client_id}/launch-settings`).
   The SSO portal can always launch into an app that has a landing URL.
2. **As a source**, add one endpoint behind your normal login:

   ```python
   from sso_client import LaunchClient, LaunchError

   sso = LaunchClient.from_env()          # or LaunchClient.from_settings(...)
   url = sso.launch_url(target="insignai", email=current_user.email,
                        context={"action": "optibot_prompt", "prompt": "..."})
   return {"launch_url": url}
   ```

   In the browser, open a blank tab inside the click handler first (popup
   blockers allow that), then point it at the URL:

   ```js
   const tab = window.open("about:blank", "_blank");
   const { launch_url } = await api.post("/my-app/launch", {...});
   tab.opener = null;
   tab.location.replace(launch_url);
   ```

3. **As a target**, add a public endpoint that redeems the code and signs the
   email in with your existing login code:

   ```python
   from sso_client import InvalidLaunchCode, LaunchClient
   from sso_client.fastapi_router import create_launch_redeem_router

   sso = LaunchClient.from_env()

   def login_by_email(identity, request):
       user = users.find_active_by_email(identity.email)   # your code
       return issue_normal_session(user)                   # your code

   app.include_router(create_launch_redeem_router(sso, login_by_email))  # POST /sso/redeem
   ```

   Your landing page reads `code` from the URL fragment, removes it from the
   address bar (`history.replaceState`), and POSTs `{"code": ...}` to that
   endpoint.
4. **Test**: launch, land signed in, and check that opening the same link again
   fails.

### Environment

| Variable | Needed by |
|---|---|
| `SSO_CLIENT_ID` | both |
| `SSO_CLIENT_PRIVATE_KEY_PATH` (or `SSO_CLIENT_PRIVATE_KEY`) | both |
| `SSO_LAUNCH_ENDPOINT`, `SSO_REDEEM_ENDPOINT` (or `SSO_ORCHESTRATOR_URL`) | source / target |
| `SSO_ORCHESTRATOR_PUBLIC_KEY_PATH` (or `SSO_ORCHESTRATOR_PUBLIC_KEY`) | target |
| `SSO_ORCHESTRATOR_ISSUER`, `SSO_AUDIENCE`, `SSO_HTTP_TIMEOUT_SECONDS` | optional |

### Errors

`LaunchConfigError` (missing keys or endpoints), `InvalidLaunchCode` (expired,
used or foreign code: ask the user to click again), `LaunchRejected` (the
orchestrator refused, e.g. the source isn't allowed), `OrchestratorUnavailable`
(network or 5xx: safe to retry). All have a stable `.code`.

### Raw HTTP contract (non-Python apps)

- `POST {orchestrator}/sso/launch` `{client_assertion, target, email, context?}` → `{launch_url, expires_in}`
- `POST {orchestrator}/sso/redeem` `{client_assertion, code}` → `{identity_token, email, source, context, expires_in}`
- `client_assertion`: RS256 JWT `{iss: client_id, sub: client_id, aud: "orchestrator", iat, exp (≤ 10 min), jti (unique)}` signed with your private key.
- `identity_token`: RS256 JWT `{iss: "orchestrator", aud: <your client_id>, sub: email, email, src, ctx, iat, exp, jti}`. Verify it with the orchestrator public key (`/sso/jwks.json`).
- Errors: `{"detail": {"code": "...", "message": "..."}}`.

---

## Legacy: cookie redirect flow

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
