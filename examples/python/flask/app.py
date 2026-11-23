"""A notes API protected by Keyora, written with Flask.

The application plays two roles:

  - Backend for a frontend: /register, /login, /refresh and /logout forward
    to Keyora with the application's client secret attached.
  - Resource server: /me, /notes and /reports verify the access token
    locally against Keyora's JWKS and check permissions and roles.
"""
import os
import threading

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

import keyora
from auth import ApiError, authenticated, bearer_token, require_permission, require_role

app = Flask(__name__)


# --- Errors: always {"error": {"code", "message"}} ---------------------------

def error_response(status: int, code: str, message: str):
    return jsonify(error={"code": code, "message": message}), status


@app.errorhandler(ApiError)
def on_api_error(exc: ApiError):
    return error_response(exc.status, exc.code, exc.message)


@app.errorhandler(HTTPException)
def on_http_error(exc: HTTPException):
    # Flask's default is an HTML page (404, 405, ...).
    return error_response(exc.code, exc.name.lower().replace(" ", "_"), exc.description)


@app.errorhandler(keyora.KeyoraUnavailable)
def on_keyora_unavailable(exc: keyora.KeyoraUnavailable):
    app.logger.error("keyora call failed: %s", exc)
    return error_response(502, "identity_unavailable", "the identity service is unavailable")


@app.errorhandler(Exception)
def on_unexpected_error(exc: Exception):
    app.logger.exception("unhandled error")
    return error_response(500, "internal_error", "internal server error")


def json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_json", "request body must be a JSON object")
    return body


# --- Forwarded to Keyora ------------------------------------------------------

def forward(path: str):
    """Relay the JSON request to Keyora and unwrap its `{data|error, meta}` envelope.

    Keyora validates the fields; its status and error code are passed through unchanged.
    """
    status, envelope = keyora.post(path, json_body())
    if status >= 400:
        return jsonify(error=envelope.get("error")), status
    if envelope.get("data") is None:
        return "", status
    return jsonify(envelope["data"]), status


@app.post("/register")
def register():
    return forward("/api/v1/auth/register")


@app.post("/login")
def login():
    return forward("/api/v1/auth/login")


@app.post("/refresh")
def refresh():
    return forward("/api/v1/auth/refresh")


@app.post("/logout")
def logout():
    return forward("/api/v1/auth/logout")


# --- The application's own endpoints -----------------------------------------

notes = [{"text": "Welcome to Keyora", "author": "system"}]
notes_lock = threading.Lock()


@app.get("/public")
def public():
    return jsonify(message="anyone can read this")


# Authentication only: any valid token.
@app.get("/me")
@authenticated
def me():
    return jsonify(g.claims)


# Remote introspection: one network call per request, but it sees logouts and
# role changes immediately.
@app.get("/me/live")
def me_live():
    state = keyora.introspect(bearer_token())
    if not state.get("active"):
        raise ApiError(401, "invalid_token", "the access token is no longer active")
    return jsonify(
        sub=state.get("sub", ""),
        email=state.get("email", ""),
        roles=state.get("roles") or [],
        permissions=state.get("permissions") or [],
    )


# Permission-based authorization.
@app.get("/notes")
@require_permission("notes:read")
def list_notes():
    with notes_lock:
        return jsonify(notes=list(notes))


@app.post("/notes")
@require_permission("notes:write")
def create_note():
    text = json_body().get("text")
    if not isinstance(text, str) or not text:
        raise ApiError(400, "validation_failed", "text is required")
    note = {"text": text, "author": g.claims["email"]}
    with notes_lock:
        notes.append(note)
    return jsonify(note), 201


# Role-based authorization.
@app.get("/reports")
@require_role("editor")
def reports():
    with notes_lock:
        return jsonify(total_notes=len(notes))


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "9005")))
