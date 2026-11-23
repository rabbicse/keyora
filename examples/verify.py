#!/usr/bin/env python3
"""Black-box check that an example application integrates Keyora correctly.

Every server example in this directory exposes the same small HTTP contract
(see examples/README.md). This script drives that contract against a running
example and a running Keyora, so all languages are held to the same bar.

    python3 examples/verify.py http://localhost:9001
    python3 examples/verify.py http://localhost:9001 --skip-expiry   # ~60s faster

Needs Python 3.8+ and nothing else. Reads examples/.env (written by setup.sh).
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

ENV = {}
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    for line in open(env_path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            ENV[k] = v
ENV.update({k: v for k, v in os.environ.items() if k.startswith("KEYORA_")})

args = [a for a in sys.argv[1:] if not a.startswith("--")]
if len(args) != 1:
    sys.exit(__doc__)
APP = args[0].rstrip("/")
SKIP_EXPIRY = "--skip-expiry" in sys.argv
# From the host, Keyora is always reachable here even if the example runs in a container.
KEYORA = ENV.get("KEYORA_VERIFY_URL", ENV.get("KEYORA_URL", "http://localhost:8080")).replace("host.docker.internal", "localhost")

passed = failed = 0


def call(method, url, body=None, token=None, basic=None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(":".join(basic).encode()).decode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            raw, status = res.read(), res.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {"_raw": raw.decode(errors="replace")[:200]}
    return status, parsed


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def expect(name, result, status, code=None):
    got_status, body = result
    got_code = (body.get("error") or {}).get("code") if isinstance(body, dict) and isinstance(body.get("error"), dict) else None
    ok = got_status == status and (code is None or got_code == code)
    check(name, ok, f"-> got {got_status} {json.dumps(body)[:160]}, want {status}" + (f" with error.code={code}" if code else ""))
    return body


def keyora_admin(method, path):
    status, body = call(method, KEYORA + path, token=ENV["KEYORA_ADMIN_KEY"])
    if status >= 300:
        sys.exit(f"setup problem: {method} {path} -> {status} {body}")


def tamper(token):
    head, payload, sig = token.split(".")
    flipped = ("A" if sig[10] != "A" else "B")
    return ".".join([head, payload, sig[:10] + flipped + sig[11:]])


for key in ("KEYORA_ADMIN_KEY", "KEYORA_TENANT_ID", "KEYORA_READER_ROLE_ID", "KEYORA_EDITOR_ROLE_ID", "KEYORA_OTHER_CLIENT_ID"):
    if key not in ENV:
        sys.exit(f"{key} is missing: run examples/setup.sh first")

email = f"user-{uuid.uuid4().hex[:12]}@example.com"
password = "correct horse battery staple"
print(f"Verifying {APP} against Keyora at {KEYORA}\n")

print("Public and unauthenticated access")
expect("GET /public needs no token", call("GET", APP + "/public"), 200)
expect("GET /me without a token is 401", call("GET", APP + "/me"), 401, "missing_token")
expect("GET /me with garbage is 401", call("GET", APP + "/me", token="not-a-token"), 401, "invalid_token")

print("Registration and login")
reg = expect("POST /register creates the user", call("POST", APP + "/register", {"email": email, "password": password, "name": "Example User"}), 201)
user_id = reg.get("id", "")
check("  registration returns the user id and no password", bool(user_id) and "password" not in json.dumps(reg), json.dumps(reg)[:160])
expect("POST /register twice is a conflict", call("POST", APP + "/register", {"email": email, "password": password}), 409, "email_taken")
expect("POST /login with a wrong password is 401", call("POST", APP + "/login", {"email": email, "password": "wrong password"}), 401, "invalid_credentials")
tokens = expect("POST /login returns tokens", call("POST", APP + "/login", {"email": email, "password": password}), 200)
access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")
check("  login returns access_token, refresh_token and expires_in", bool(access and refresh and tokens.get("expires_in")), json.dumps(tokens)[:160])

print("Token verification")
me = expect("GET /me with a valid token", call("GET", APP + "/me", token=access), 200)
check("  /me reports the token's subject and email", me.get("sub") == user_id and me.get("email") == email, json.dumps(me)[:200])
expect("a token with a tampered signature is 401", call("GET", APP + "/me", token=tamper(access)), 401, "invalid_token")
_, other = call("POST", KEYORA + "/api/v1/auth/register", {"email": email, "password": password},
                basic=(ENV["KEYORA_OTHER_CLIENT_ID"], ENV["KEYORA_OTHER_CLIENT_SECRET"]))
_, foreign = call("POST", KEYORA + "/api/v1/auth/login", {"email": email, "password": password},
                  basic=(ENV["KEYORA_OTHER_CLIENT_ID"], ENV["KEYORA_OTHER_CLIENT_SECRET"]))
foreign_token = (foreign.get("data") or {}).get("access_token", "")
if not foreign_token:
    sys.exit(f"setup problem: could not mint a token for the other application: {foreign}")
expect("a token issued to another application (wrong audience) is 401", call("GET", APP + "/me", token=foreign_token), 401, "invalid_token")

print("Authorization")
expect("GET /notes without the notes:read permission is 403", call("GET", APP + "/notes", token=access), 403, "forbidden")
base = f"/api/v1/tenants/{ENV['KEYORA_TENANT_ID']}/users/{user_id}/roles/"
keyora_admin("PUT", base + ENV["KEYORA_READER_ROLE_ID"])
tokens = expect("POST /refresh rotates the tokens", call("POST", APP + "/refresh", {"refresh_token": refresh}), 200)
first_refresh, access, refresh = refresh, tokens.get("access_token", ""), tokens.get("refresh_token", "")
check("  refresh returns a different refresh token", bool(refresh) and refresh != first_refresh)
expect("GET /notes with notes:read is 200", call("GET", APP + "/notes", token=access), 200)
expect("POST /notes without notes:write is 403", call("POST", APP + "/notes", {"text": "hello"}, token=access), 403, "forbidden")
expect("GET /reports without the editor role is 403", call("GET", APP + "/reports", token=access), 403, "forbidden")
keyora_admin("PUT", base + ENV["KEYORA_EDITOR_ROLE_ID"])
tokens = expect("POST /refresh picks up the new role", call("POST", APP + "/refresh", {"refresh_token": refresh}), 200)
access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")
expect("POST /notes with notes:write is 201", call("POST", APP + "/notes", {"text": "hello"}, token=access), 201)
expect("GET /reports with the editor role is 200", call("GET", APP + "/reports", token=access), 200)
live = expect("GET /me/live (remote introspection) is 200", call("GET", APP + "/me/live", token=access), 200)
check("  introspection reports the current permissions", sorted(live.get("permissions") or []) == ["notes:read", "notes:write"], json.dumps(live)[:200])

if SKIP_EXPIRY:
    print("Expired tokens (skipped)")
else:
    print("Expired tokens (waiting for the 60-second access token to expire)")
    payload = access.split(".")[1]
    exp = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"]
    time.sleep(max(0, exp - time.time()) + 3)
    expect("an expired access token is 401 token_expired", call("GET", APP + "/me", token=access), 401, "token_expired")
    tokens = expect("POST /refresh still works after the access token expired", call("POST", APP + "/refresh", {"refresh_token": refresh}), 200)
    access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")
    expect("the refreshed access token works", call("GET", APP + "/me", token=access), 200)

print("Logout and revocation")
status, _ = call("POST", APP + "/logout", {"refresh_token": refresh})
check("POST /logout succeeds", status in (200, 204), f"-> got {status}")
expect("POST /refresh after logout is 401", call("POST", APP + "/refresh", {"refresh_token": refresh}), 401)
expect("GET /me/live after logout is 401 (introspection sees the revocation)", call("GET", APP + "/me/live", token=access), 401, "invalid_token")
expect("GET /me after logout is still 200 until expiry (local verification cannot see it)", call("GET", APP + "/me", token=access), 200)

print("Refresh token reuse")
tokens = expect("login again", call("POST", APP + "/login", {"email": email, "password": password}), 200)
stolen = tokens.get("refresh_token", "")
expect("first use of a refresh token works", call("POST", APP + "/refresh", {"refresh_token": stolen}), 200)
expect("second use of the same refresh token is 401", call("POST", APP + "/refresh", {"refresh_token": stolen}), 401, "refresh_token_reused")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
