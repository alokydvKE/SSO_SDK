"""End-to-end test of the client-generated-key flow against the real app + DB.

Proves: create (no key) -> register PUBLIC key -> integration .env (no secret)
-> client signs with its LOCAL private key -> /sso/token accepts it. Cleans up.
"""
import os
import pathlib
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

SDK = pathlib.Path(__file__).resolve().parent
APP = pathlib.Path(r"D:\GIT_projects\SSOgit\SSO-Orchestrator_BE\app")
sys.path.insert(0, str(APP))
sys.path.insert(0, str(SDK))
os.chdir(APP)
from dotenv import load_dotenv
load_dotenv(APP / ".env")

import jwt as _jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from core.database import SessionLocal
from core.settings import PUBLIC_KEYS_DIR, PUBLIC_KEY_FILENAME_TEMPLATE
from models import models
from security import security
from main import app

from sso_client import SSOClientConfig, core as sdk_core

client = TestClient(app)
db = SessionLocal()
CID = f"ckeys_test_{int(time.time())}"
REDIRECT = "http://localhost:8001/projects/callback"
admin, _, _ = security.create_user_access_token("ck-admin", "admin")
AUTH = {"Authorization": f"Bearer {admin}"}
created_pem = PUBLIC_KEYS_DIR / PUBLIC_KEY_FILENAME_TEMPLATE.format(issuer=CID)


def ok(m): print(f"  [PASS] {m}")


try:
    # 1. create project — should NOT mint or return any key
    r = client.post("/create_project", headers=AUTH, json={
        "client_id": CID, "project_name": "CKeys Test",
        "launch_url": "http://localhost:8001", "allowed_redirect_uris": REDIRECT,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "generated_private_key" not in body, "create must not return a private key"
    assert not created_pem.exists(), "create must not write a public key file"
    ok("create_project: no key generated, no secret returned")

    # 2. key status before registration
    assert client.get(f"/projects/{CID}/keys", headers=AUTH).json()["has_public_key"] is False
    ok("key status before registration: has_public_key=False")

    # 3. client generates its OWN keypair locally
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    pub = pk.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    # validation: a private key must be rejected
    bad = client.post(f"/projects/{CID}/keys", headers=AUTH, json={"public_key_pem": priv})
    assert bad.status_code == 400, "private key should be rejected"
    ok("register rejects a PRIVATE key (validation intact)")

    # register the PUBLIC key
    reg = client.post(f"/projects/{CID}/keys", headers=AUTH, json={"public_key_pem": pub})
    assert reg.status_code == 200, reg.text
    assert reg.json()["has_public_key"] and reg.json()["fingerprint"]
    ok(f"register PUBLIC key -> fingerprint {reg.json()['fingerprint'][:16]}…")

    # 4. integration .env is config-only (NO private key, has key PATH)
    env_text = client.get(f"/projects/{CID}/integration.env", headers=AUTH).text
    assert "PRIVATE KEY" not in env_text and "SSO_CLIENT_PRIVATE_KEY=" not in env_text
    assert "SSO_CLIENT_PRIVATE_KEY_PATH=" in env_text
    ok("integration.env is config-only (key path, no secret)")

    # 5. client signs an assertion with its LOCAL private key -> /sso/token accepts
    sdk_cfg = SSOClientConfig(
        client_id=CID, client_private_key=priv, redirect_uri=REDIRECT,
        authorize_endpoint="x", token_endpoint="x",
    )
    user = models.User(id="ck-user", role="user",
                       username=f"ck_user_{int(time.time())}", password_hash="x", is_active=True)
    db.add(user)
    code = "ck_code_" + os.urandom(6).hex()
    db.add(models.AuthorizationCode(
        code=code, user_id=user.id, client_id=CID, redirect_uri=REDIRECT,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5)))
    db.commit()
    assertion = sdk_core.build_client_assertion(sdk_cfg)
    jti = _jwt.decode(assertion, options={"verify_signature": False})["jti"]
    tok = client.post("/sso/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": CID, "client_assertion_type": sdk_cfg.client_assertion_type,
        "client_assertion": assertion,
    })
    assert tok.status_code == 200, tok.text
    ok("registered public key verifies the client's assertion -> token issued")

    # 6. SDK from_env reads the key from a FILE path
    keyfile = pathlib.Path(tempfile.gettempdir()) / f"{CID}_private.pem"
    keyfile.write_text(priv)
    for k in list(os.environ):
        if k.startswith("SSO_"):
            del os.environ[k]
    os.environ.update({
        "SSO_CLIENT_ID": CID, "SSO_REDIRECT_URI": REDIRECT,
        "SSO_AUTHORIZE_ENDPOINT": "x", "SSO_TOKEN_ENDPOINT": "x",
        "SSO_CLIENT_PRIVATE_KEY_PATH": str(keyfile),
    })
    cfg2 = SSOClientConfig.from_env()
    assert "BEGIN PRIVATE KEY" in cfg2.client_private_key
    keyfile.unlink()
    ok("SDK from_env loads the private key from SSO_CLIENT_PRIVATE_KEY_PATH")

    print("\nALL GREEN — client-generated-key flow works end to end.")
finally:
    try:
        db.query(models.AuthorizationCode).filter(models.AuthorizationCode.client_id == CID).delete()
        db.query(models.OAuthClient).filter(models.OAuthClient.client_id == CID).delete()
        db.query(models.User).filter(models.User.id == "ck-user").delete()
        if "jti" in dir():
            db.query(models.UsedJTI).filter(models.UsedJTI.jti == jti).delete()
        db.commit()
    except Exception as e:
        print("cleanup(db) warning:", e)
    db.close()
    if created_pem.exists():
        created_pem.unlink()
    print("cleanup done.")
