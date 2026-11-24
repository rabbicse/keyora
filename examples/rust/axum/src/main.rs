//! A notes API protected by Keyora, written with axum.
//!
//! The application plays two roles:
//!
//!   - Backend for a frontend: /register, /login, /refresh and /logout forward
//!     to Keyora with the application's client secret attached.
//!   - Resource server: /me, /notes and /reports verify the access token
//!     locally against Keyora's JWKS and check permissions and roles.

mod auth;
mod error;
mod keyora;

use std::env;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Map, Value};

use auth::{bearer_token, require_permission, require_role};
use error::ApiError;
use keyora::{Claims, Config, Keyora};

pub struct AppState {
    keyora: Keyora,
    /// The application's own data. Unrelated to Keyora.
    notes: Mutex<Vec<Note>>,
}

#[derive(Clone, Serialize)]
struct Note {
    text: String,
    author: String,
}

type App = State<Arc<AppState>>;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let state = Arc::new(AppState {
        keyora: Keyora::new(config),
        notes: Mutex::new(vec![Note { text: "Welcome to Keyora".into(), author: "system".into() }]),
    });

    let app = Router::new()
        .route("/public", get(public))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/me/live", get(me_live))
        .route("/notes", get(list_notes).post(create_note))
        .route("/reports", get(reports))
        // axum's defaults for these are empty bodies.
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint") })
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "method not allowed")
        })
        .with_state(state);

    let host = env::var("HOST").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "127.0.0.1".into());
    let port = env::var("PORT").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "9011".into());
    let addr = format!("{host}:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cannot listen on {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("listening on http://{addr}");
    match axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("server error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves on Ctrl-C or SIGTERM. A process running as PID 1 in a container
/// ignores SIGTERM unless it handles it, and `docker stop` would wait 10 seconds.
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}

fn json_object(body: &Bytes) -> Result<Map<String, Value>, ApiError> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_json", "request body must be a JSON object")),
    }
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY)
}

// --- Forwarded to Keyora -----------------------------------------------------

/// Relay the JSON request to Keyora and unwrap its `{data|error, meta}` envelope.
///
/// Keyora validates the fields; its status and error code are passed through unchanged.
async fn forward(state: &AppState, path: &str, body: &Bytes) -> Result<Response, ApiError> {
    let body = Value::Object(json_object(body)?);
    let (code, envelope) = state.keyora.post(path, &body).await.map_err(|e| {
        eprintln!("keyora call failed: {e}");
        ApiError::identity_unavailable()
    })?;
    let mut envelope = envelope.unwrap_or_default();
    Ok(if code >= 400 {
        (status(code), Json(json!({ "error": envelope.remove("error") }))).into_response()
    } else {
        match envelope.remove("data") {
            None | Some(Value::Null) => status(code).into_response(), // 204 No Content (logout)
            Some(data) => (status(code), Json(data)).into_response(),
        }
    })
}

async fn register(State(state): App, body: Bytes) -> Result<Response, ApiError> {
    forward(&state, "/api/v1/auth/register", &body).await
}

async fn login(State(state): App, body: Bytes) -> Result<Response, ApiError> {
    forward(&state, "/api/v1/auth/login", &body).await
}

async fn refresh(State(state): App, body: Bytes) -> Result<Response, ApiError> {
    forward(&state, "/api/v1/auth/refresh", &body).await
}

async fn logout(State(state): App, body: Bytes) -> Result<Response, ApiError> {
    forward(&state, "/api/v1/auth/logout", &body).await
}

// --- The application's own endpoints -----------------------------------------

async fn public() -> Json<Value> {
    Json(json!({ "message": "anyone can read this" }))
}

/// Authentication only: any valid access token. The `Claims` argument does the
/// verification (see auth.rs).
async fn me(claims: Claims) -> Json<Claims> {
    Json(claims)
}

/// Remote introspection: one network call per request, but it sees logouts and
/// role changes immediately.
async fn me_live(State(state): App, parts: Parts) -> Result<Json<Value>, ApiError> {
    let live = state.keyora.introspect(bearer_token(&parts)?).await.map_err(|e| {
        eprintln!("keyora call failed: {e}");
        ApiError::identity_unavailable()
    })?;
    if !live.active {
        return Err(ApiError::invalid_token("the access token is no longer active"));
    }
    Ok(Json(json!({
        "sub": live.sub,
        "email": live.email,
        "roles": live.roles.unwrap_or_default(),
        "permissions": live.permissions.unwrap_or_default(),
    })))
}

/// Permission-based authorization.
async fn list_notes(State(state): App, claims: Claims) -> Result<Json<Value>, ApiError> {
    require_permission(&claims, &["notes:read"])?;
    let notes = state.notes.lock().unwrap().clone();
    Ok(Json(json!({ "notes": notes })))
}

async fn create_note(State(state): App, claims: Claims, body: Bytes) -> Result<(StatusCode, Json<Note>), ApiError> {
    require_permission(&claims, &["notes:write"])?;
    let text = match json_object(&body)?.remove("text") {
        Some(Value::String(text)) if !text.is_empty() => text,
        _ => return Err(ApiError::new(StatusCode::BAD_REQUEST, "validation_failed", "text is required")),
    };
    let note = Note { text, author: claims.email };
    state.notes.lock().unwrap().push(note.clone());
    Ok((StatusCode::CREATED, Json(note)))
}

/// Role-based authorization.
async fn reports(State(state): App, claims: Claims) -> Result<Json<Value>, ApiError> {
    require_role(&claims, &["editor"])?;
    let total = state.notes.lock().unwrap().len();
    Ok(Json(json!({ "total_notes": total })))
}
