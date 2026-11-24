"""Everything that talks to Keyora: configuration, the REST client and token verification."""
import logging
import os
import sys

import jwt
import requests

KEYORA_URL = os.environ.get("KEYORA_URL", "http://localhost:8080").rstrip("/")
ISSUER = os.environ.get("KEYORA_ISSUER") or KEYORA_URL
CLIENT_ID = os.environ.get("KEYORA_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("KEYORA_CLIENT_SECRET", "")

log = logging.getLogger("keyora")

if not CLIENT_ID or not CLIENT_SECRET:
    sys.exit("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)")


class KeyoraUnavailable(Exception):
    """Keyora could not be reached or gave an unusable answer."""


class TokenExpired(Exception):
    """The token is genuine but past its `exp`. The client should refresh and retry."""


class TokenInvalid(Exception):
    """The token failed any other check, or the signing keys could not be fetched."""


# --- REST calls (server side only: they carry the client secret) -------------

def post(path: str, body: dict) -> tuple[int, dict]:
    """POST a JSON body to Keyora. Returns the status and the `{data|error, meta}` envelope.

    HTTP Basic with client_id:client_secret identifies this application to Keyora.
    Raises KeyoraUnavailable when Keyora cannot be reached or does not answer
    with its JSON envelope; app.py turns that into a 502.
    """
    try:
        res = requests.post(KEYORA_URL + path, json=body, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
        if not res.content:  # 204 No Content (logout)
            return res.status_code, {}
        envelope = res.json()
    except (requests.RequestException, ValueError) as exc:
        raise KeyoraUnavailable(str(exc)) from exc
    if not isinstance(envelope, dict):
        raise KeyoraUnavailable("unexpected response from keyora")
    return res.status_code, envelope


def introspect(token: str) -> dict:
    """Ask Keyora for the live state of an access token."""
    status, envelope = post("/api/v1/auth/introspect", {"token": token})
    if status != 200 or not isinstance(envelope.get("data"), dict):
        raise KeyoraUnavailable(f"introspection failed with status {status}")
    return envelope["data"]


# --- Local verification (no call to Keyora per request) ----------------------

# Fetches Keyora's public keys on first use and caches them (here for 5 minutes).
# A token signed with a key ID that is not cached triggers one re-fetch, so key
# rotation on the Keyora side needs no restart here.
_jwks = jwt.PyJWKClient(f"{KEYORA_URL}/.well-known/jwks.json", cache_keys=True, lifespan=300, timeout=5)


def verify_token(token: str) -> dict:
    """Verify an access token and return its claims.

    All six checks from examples/README.md happen here:
    algorithm pinned to RS256, signature, exp, iss, aud and token_use.
    """
    try:
        key = _jwks.get_signing_key_from_jwt(token)  # picks the key by the token's `kid`
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],  # never trust the algorithm named in the token
            issuer=ISSUER,
            audience=CLIENT_ID,  # refuse tokens issued to other applications
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except jwt.PyJWTError as exc:
        # Malformed token, bad signature, wrong issuer or audience, a missing
        # claim, an unknown key ID, or the JWKS could not be fetched. The reason
        # goes to the log only; the caller just learns that the token is invalid.
        log.warning("access token rejected: %s", exc)
        raise TokenInvalid(str(exc)) from exc
    # An OIDC ID token has the same issuer and audience as an access token, so
    # only this claim keeps it from being accepted as an API credential.
    if claims.get("token_use") != "access":
        log.warning("access token rejected: token_use is not 'access'")
        raise TokenInvalid("token_use is not 'access'")
    return claims
