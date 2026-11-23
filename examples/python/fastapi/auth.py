"""FastAPI dependencies for authentication and authorization.

    @app.get("/me")
    def me(claims: CurrentClaims): ...

    @app.get("/notes")
    def notes(claims: Annotated[Claims, Depends(require_permission("notes:read"))]): ...
"""
from typing import Annotated

from fastapi import Depends, Header
from pydantic import BaseModel, ValidationError

import keyora


class ApiError(Exception):
    """An error answered as `{"error": {"code", "message"}}` with the given status."""

    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


class Claims(BaseModel):
    """The parts of the access token this application uses."""

    sub: str
    email: str = ""
    roles: list[str] = []
    permissions: list[str] = []


def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    """Extract the token from `Authorization: Bearer <token>`."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "missing_token", "a bearer access token is required")
    return token.strip()


# A plain `def`: FastAPI runs it in a worker thread, so the (rare, blocking)
# JWKS fetch inside verify_token does not stall the event loop.
def current_claims(token: Annotated[str, Depends(bearer_token)]) -> Claims:
    """Verify the access token locally and return its claims."""
    try:
        return Claims.model_validate(keyora.verify_token(token))
    except keyora.TokenExpired:
        raise ApiError(401, "token_expired", "the access token has expired")
    except (keyora.TokenInvalid, ValidationError):
        raise ApiError(401, "invalid_token", "the access token is invalid")


CurrentClaims = Annotated[Claims, Depends(current_claims)]


def _forbidden() -> ApiError:
    return ApiError(403, "forbidden", "you do not have permission to perform this action")


def require_permission(*required: str):
    """The token must carry every listed permission."""

    def dependency(claims: CurrentClaims) -> Claims:
        if not set(required) <= set(claims.permissions):
            raise _forbidden()
        return claims

    return dependency


def require_role(*allowed: str):
    """The token must carry at least one of the listed roles."""

    def dependency(claims: CurrentClaims) -> Claims:
        if not set(allowed) & set(claims.roles):
            raise _forbidden()
        return claims

    return dependency
