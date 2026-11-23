"""A notes API protected by Keyora, written with FastAPI.

The application plays two roles:

  - Backend for a frontend: /register, /login, /refresh and /logout forward
    to Keyora with the application's client secret attached.
  - Resource server: /me, /notes and /reports verify the access token
    locally against Keyora's JWKS and check permissions and roles.
"""
import logging
import os
import threading
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

import keyora
from auth import ApiError, Claims, CurrentClaims, bearer_token, require_permission, require_role

log = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("notes API using Keyora at %s", keyora.KEYORA_URL)
    yield
    await keyora.http.aclose()


app = FastAPI(title="Keyora notes example", lifespan=lifespan)


# --- Errors: always {"error": {"code", "message"}} ---------------------------

def error_response(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


@app.exception_handler(ApiError)
async def on_api_error(_: Request, exc: ApiError):
    return error_response(exc.status, exc.code, exc.message)


@app.exception_handler(RequestValidationError)
async def on_validation_error(_: Request, exc: RequestValidationError):
    # FastAPI's default is 422 {"detail": [...]}; the contract wants 400.
    first = exc.errors()[0]
    if first["type"] == "json_invalid":
        return error_response(400, "invalid_json", "request body must be JSON")
    field = ".".join(str(part) for part in first["loc"] if part != "body")
    return error_response(400, "validation_failed", f"{field}: {first['msg']}" if field else first["msg"])


@app.exception_handler(StarletteHTTPException)
async def on_http_error(_: Request, exc: StarletteHTTPException):
    codes = {404: "not_found", 405: "method_not_allowed"}
    return error_response(exc.status_code, codes.get(exc.status_code, "http_error"), str(exc.detail))


@app.exception_handler(keyora.KeyoraUnavailable)
async def on_keyora_unavailable(_: Request, exc: keyora.KeyoraUnavailable):
    log.error("keyora call failed: %s", exc)
    return error_response(502, "identity_unavailable", "the identity service is unavailable")


@app.exception_handler(Exception)
async def on_unexpected_error(_: Request, exc: Exception):
    return error_response(500, "internal_error", "internal server error")


# --- Forwarded to Keyora ------------------------------------------------------
# The models only describe the shape. Keyora applies the real rules (password
# length, email format, ...) and its error codes are passed through unchanged.

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


async def forward(path: str, body: BaseModel) -> Response:
    """Relay a request to Keyora and unwrap its `{data|error, meta}` envelope."""
    status, envelope = await keyora.post(path, body.model_dump(exclude_none=True))
    if status >= 400:
        return JSONResponse({"error": envelope.get("error")}, status_code=status)
    if envelope.get("data") is None:
        return Response(status_code=status)
    return JSONResponse(envelope["data"], status_code=status)


@app.post("/register", status_code=201)
async def register(body: RegisterRequest):
    return await forward("/api/v1/auth/register", body)


@app.post("/login")
async def login(body: LoginRequest):
    return await forward("/api/v1/auth/login", body)


@app.post("/refresh")
async def refresh(body: RefreshTokenRequest):
    return await forward("/api/v1/auth/refresh", body)


@app.post("/logout", status_code=204)
async def logout(body: RefreshTokenRequest):
    return await forward("/api/v1/auth/logout", body)


# --- The application's own endpoints -----------------------------------------

class NoteIn(BaseModel):
    text: str = Field(min_length=1)


notes = [{"text": "Welcome to Keyora", "author": "system"}]
notes_lock = threading.Lock()


@app.get("/public")
def public():
    return {"message": "anyone can read this"}


# Authentication only: any valid token.
@app.get("/me")
def me(claims: CurrentClaims) -> Claims:
    return claims


# Remote introspection: one network call per request, but it sees logouts and
# role changes immediately.
@app.get("/me/live")
async def me_live(token: Annotated[str, Depends(bearer_token)]) -> Claims:
    state = await keyora.introspect(token)
    if not state.get("active"):
        raise ApiError(401, "invalid_token", "the access token is no longer active")
    return Claims.model_validate(state)


# Permission-based authorization.
@app.get("/notes", dependencies=[Depends(require_permission("notes:read"))])
def list_notes():
    with notes_lock:
        return {"notes": list(notes)}


@app.post("/notes", status_code=201)
def create_note(body: NoteIn, claims: Annotated[Claims, Depends(require_permission("notes:write"))]):
    note = {"text": body.text, "author": claims.email}
    with notes_lock:
        notes.append(note)
    return note


# Role-based authorization.
@app.get("/reports", dependencies=[Depends(require_role("editor"))])
def reports():
    with notes_lock:
        return {"total_notes": len(notes)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "9004")))
