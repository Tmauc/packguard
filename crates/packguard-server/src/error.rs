//! Typed API errors. Each variant maps to a stable HTTP status + a JSON
//! envelope of the shape `{ "error": { "code", "message", "detail" } }`
//! so the dashboard can branch on `code` rather than scrape strings.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Phase 14.5b — sandbox violation. Used by the `/api/fs/browse`
    /// endpoint when a request resolves to a path outside the server
    /// process's `$HOME`. Distinct from BadRequest so the dashboard can
    /// branch on `code === "forbidden"` and surface a clearer message.
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "not_found",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::Conflict(_) => "conflict",
            ApiError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let detail = match &self {
            ApiError::Internal(err) => Some(format!("{err:#}")),
            _ => None,
        };
        let body = json!({
            "error": {
                "code": code,
                "message": self.to_string(),
                "detail": detail,
            }
        });
        if matches!(self, ApiError::Internal(_)) {
            tracing::error!(?status, error = %self, "api error");
        } else {
            tracing::debug!(?status, error = %self, "api error");
        }
        (status, axum::Json(body)).into_response()
    }
}
