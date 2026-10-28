# sso-client

## App launch

Open another app with the user already signed in. No cookies; every trust
decision is made server to server, and users are identified by **email**.

```
source app BE --POST /sso/launch {assertion, target, email, context}--> orchestrator --> launch_url
browser opens launch_url  (= target's landing URL, one-time code in the # fragment, 60 s)
target app BE --POST /sso/redeem {assertion, code}--> orchestrator --> identity token (sub = email)
target app signs the email in with its own normal session
```

### Add a FastAPI app

1. **Install** (from git; pin a tag once one is published):

   ```bash
   pip install "sso-client[fastapi] @ git+https://github.com/alokydvKE/SSO_SDK.git@main"
   ```

2. **Onboard** with one command, run in your backend folder. It asks for an
   orchestrator admin's password, registers the project (if new), creates a key
   pair locally and registers only its public key, sets the landing URL
   (`<app-url>/sso`) and writes the SSO block of `.env`. Re-running it is safe:
   it reuses the key and keeps the allowed sources unless you pass new ones.

   ```bash
   sso-client setup --client-id my_app --name "My App" \
     --app-url https://my-app.example.com \
     --orchestrator https://<orchestrator host>/auth_orchestrator
   ```

   Options: `--allowed-sources persona_ai,insignai` (apps that may open yours;
   the SSO portal always may), `--landing-path '#/sso'` for hash-routed
   frontends, `--admin-user`, `--rotate-key`. Keep `keys/` and `.env` out of git.

3. **Backend**: one call. You write the two parts only your app knows: how to
   sign a user in by email, and who the current user is.

   ```python
   from sso_client import add_sso

   def login_by_email(identity, request):         # identity.email / .source / .context
       return issue_normal_session(identity.email)  # your code; same response as your /login

   def get_user_email(user=Depends(current_user)):  # your auth dependency
       return user.email

   add_sso(app, on_login=login_by_email, current_user_email=get_user_email, prefix="/api")
   # POST /api/sso/redeem  {code}                 -> on_login(...)  (other apps open yours)
   # POST /api/sso/launch  {target, context?}     -> {launch_url}   (yours opens others)
   ```

   Leave out `current_user_email` if the app only receives users. `add_sso`
   reads the `SSO_*` lines of `./.env` itself (`env_file=` to change).

4. **Frontend**: a landing page at the landing URL, and, as a source, a button.

   ```js
   // landing page (/sso): the code is in the # fragment, never sent to a server
   const code = new URLSearchParams(location.hash.slice(1)).get("code");  // hash routing: location.hash.split("?")[1]
   history.replaceState(null, "", location.pathname);                      // remove it from the address bar
   const session = await post("/api/sso/redeem", { code });                // your API helper
   // store the session exactly as after a password login, then go to the home page

   // "Open Persona AI" button: open the tab inside the click handler (popup blockers allow that)
   const tab = window.open("about:blank", "_blank");
   const { launch_url } = await post("/api/sso/launch", { target: "persona_ai" });
   tab.opener = null;
   tab.location.replace(launch_url);
   ```

5. **Test**: open the app from the portal and land signed in; opening the same
   link again must fail.

### Without FastAPI

`sso-client setup` works for any app. Then, in Python, call the client directly:

1. **As a source**, add one endpoint behind your normal login:

   ```python
   from sso_client import LaunchClient, LaunchError, load_env_file

   load_env_file()                        # SSO_* lines of ./.env
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

2. **As a target**, add a public endpoint that redeems the code and signs the
   email in with your existing login code:

   ```python
   from sso_client import InvalidLaunchCode

   def sso_redeem(code):                                    # POST /sso/redeem {code}
       try:
           identity = sso.redeem(code)                      # identity.email / .source / .context
       except InvalidLaunchCode:
           return error(400, "This link has expired. Go back and click again.")
       user = users.find_active_by_email(identity.email)    # your code
       return issue_normal_session(user)                    # your code
   ```

   Your landing page reads `code` from the URL fragment, removes it from the
   address bar (`history.replaceState`), and POSTs `{"code": ...}` to that
   endpoint.
3. **Test**: launch, land signed in, and check that opening the same link again
   fails.

### Environment

`sso-client setup` writes these to `.env`; `add_sso()` and `load_env_file()` read them.

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
