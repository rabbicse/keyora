"""Flask decorators for authentication and authorization.

    @app.get("/notes")
    @require_permission("notes:read")
    def list_notes():
        g.claims["email"]
"""
from functools import wraps

from flask import g, request

import keyora


class ApiError(Exception):
    """An error answered as `{"error": {"code", "message"}}` with the given status."""

    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def bearer_token() -> str:
    """Extract the token from `Authorization: Bearer <token>`."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "missing_token", "a bearer access token is required")
    return token.strip()


def _string_list(value) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def authenticated(view):
    """Verify the access token locally and put its claims on `flask.g.claims`."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            claims = keyora.verify_token(bearer_token())
        except keyora.TokenExpired:
            raise ApiError(401, "token_expired", "the access token has expired")
        except keyora.TokenInvalid:
            raise ApiError(401, "invalid_token", "the access token is invalid")
        g.claims = {
            "sub": claims.get("sub", ""),
            "email": claims.get("email", ""),
            "roles": _string_list(claims.get("roles")),
            "permissions": _string_list(claims.get("permissions")),
        }
        return view(*args, **kwargs)

    return wrapper


def _forbidden() -> ApiError:
    return ApiError(403, "forbidden", "you do not have permission to perform this action")


def require_permission(*required: str):
    """Authenticate, then require every listed permission."""

    def decorator(view):
        @wraps(view)
        @authenticated
        def wrapper(*args, **kwargs):
            if not set(required) <= set(g.claims["permissions"]):
                raise _forbidden()
            return view(*args, **kwargs)

        return wrapper

    return decorator


def require_role(*allowed: str):
    """Authenticate, then require at least one of the listed roles."""

    def decorator(view):
        @wraps(view)
        @authenticated
        def wrapper(*args, **kwargs):
            if not set(allowed) & set(g.claims["roles"]):
                raise _forbidden()
            return view(*args, **kwargs)

        return wrapper

    return decorator
