//! Embedded dashboard assets + the fallback axum handler that serves them.
//! Gated behind the `ui-embed` feature so debug builds (and anyone who
//! wants a tiny binary) can skip the embed entirely.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use rust_embed::RustEmbed;

/// The built Vite bundle. The path resolves relative to this crate's
/// `Cargo.toml` (rust-embed's `compression` feature requires a relative
/// path). `build.rs` makes sure `dashboard/dist` exists when the feature
/// is active.
#[derive(RustEmbed)]
#[folder = "../../dashboard/dist"]
struct Assets;

/// Serve GET `/` and any unmatched path as the embedded SPA. `/api/*` is
/// handled by the API router before this fallback fires. Missing assets
/// return 404; the index is reused for SPA routes so deep-linking to
/// `/packages/npm/lodash` works without a server-side rewrite.
pub async fn serve(req: Request<Body>) -> Response<Body> {
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        return respond_with("index.html");
    }
    if Assets::get(path).is_some() {
        return respond_with(path);
    }
    // SPA fallback — any unknown path defers to the React router.
    respond_with("index.html")
}

/// Handler used by the API sub-router for the exact root URL — `axum`
/// 0.8's fallback mechanism doesn't match `GET /` against the same
/// wildcard that catches `/packages/foo`.
pub async fn serve_root(_uri: Uri) -> Response<Body> {
    respond_with("index.html")
}

fn respond_with(path: &str) -> Response<Body> {
    match Assets::get(path) {
        Some(asset) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let immutable = path.starts_with("assets/");
            let cache_control = if immutable {
                // Vite hashes filenames under /assets/* — safe to cache forever.
                "public, max-age=31536000, immutable"
            } else {
                // index.html must always be revalidated so deploys aren't pinned.
                "no-cache"
            };
            let mut response = Response::new(Body::from(asset.data.into_owned()));
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref())
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            );
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
            response
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
