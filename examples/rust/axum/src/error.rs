//! The one error shape every endpoint answers with:
//! `{"error": {"code": "...", "message": "..."}}`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    pub fn missing_token() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "missing_token", "a bearer access token is required")
    }

    pub fn invalid_token(message: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", message)
    }

    pub fn token_expired() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "token_expired", "the access token has expired")
    }

    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "you do not have permission to perform this action")
    }

    pub fn identity_unavailable() -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "identity_unavailable", "the identity service is unavailable")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({"error": {"code": self.code, "message": self.message}});
        (self.status, Json(body)).into_response()
    }
}
