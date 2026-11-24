//! Authentication and authorization for handlers.
//!
//! ```ignore
//! async fn list_notes(claims: Claims) -> Result<Json<Value>, ApiError> {
//!     require_permission(&claims, &["notes:read"])?;
//!     ...
//! }
//! ```

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::keyora::{Claims, TokenError};
use crate::AppState;

/// Extract the token from `Authorization: Bearer <token>`.
pub fn bearer_token(parts: &Parts) -> Result<&str, ApiError> {
    let header = parts.headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    match header.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() => Ok(token.trim()),
        _ => Err(ApiError::missing_token()),
    }
}

/// A handler that takes `Claims` as an argument only runs for requests with a
/// valid access token; every other request is answered with 401 before it.
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)?;
        state.keyora.verify_token(token).await.map_err(|e| match e {
            TokenError::Expired => ApiError::token_expired(),
            TokenError::Invalid(reason) => {
                // The reason goes to the log only; the caller just learns that
                // the token is invalid.
                eprintln!("access token rejected: {reason}");
                ApiError::invalid_token("the access token is invalid")
            }
        })
    }
}

/// Require every listed permission.
pub fn require_permission(claims: &Claims, required: &[&str]) -> Result<(), ApiError> {
    let has = |p: &&str| claims.permissions.iter().any(|have| have == p);
    if required.iter().all(has) { Ok(()) } else { Err(ApiError::forbidden()) }
}

/// Require at least one of the listed roles.
pub fn require_role(claims: &Claims, allowed: &[&str]) -> Result<(), ApiError> {
    let has = |r: &&str| claims.roles.iter().any(|have| have == r);
    if allowed.iter().any(has) { Ok(()) } else { Err(ApiError::forbidden()) }
}
