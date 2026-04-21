//! HTTP routing layer. Pure mapping of paths → service-layer calls; the
//! service crate keeps every endpoint testable without spinning up axum.

use crate::dto::{
    JobAccepted, JobKind, JobView, Overview, PackageDetail, PackagesPage, PackagesQuery,
    PolicyDocument, PolicyDryRun, PolicyDryRunResult, PolicyWrite,
};
use crate::error::ApiError;
use crate::jobs;
use crate::services;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use packguard_store::Store;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

pub struct ServerConfig {
    pub repo_path: PathBuf,
    pub store: Store,
}

pub fn router(cfg: ServerConfig) -> Router {
    let state = AppState {
        store: Arc::new(Mutex::new(cfg.store)),
        repo_path: cfg.repo_path,
    };
    Router::new()
        .route("/api/health", get(health))
        .route("/api/overview", get(overview))
        .route("/api/packages", get(packages_list))
        .route("/api/packages/{ecosystem}/{name}", get(package_detail))
        .route("/api/policies", get(policy_get).put(policy_put))
        .route("/api/policies/dry-run", post(policy_dry_run))
        .route("/api/scan", post(scan_create))
        .route("/api/sync", post(sync_create))
        .route("/api/jobs/{id}", get(job_get))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

async fn overview(State(s): State<AppState>) -> Result<Json<Overview>, ApiError> {
    let store = s.store.lock().await;
    Ok(Json(services::overview::build(&store)?))
}

async fn packages_list(
    State(s): State<AppState>,
    Query(q): Query<PackagesQuery>,
) -> Result<Json<PackagesPage>, ApiError> {
    let store = s.store.lock().await;
    Ok(Json(services::packages::list(&store, &q)?))
}

async fn package_detail(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
) -> Result<Json<PackageDetail>, ApiError> {
    let store = s.store.lock().await;
    services::packages::detail(&store, &ecosystem, &name)?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("{ecosystem}/{name} not in scan cache")))
}

async fn policy_get(State(s): State<AppState>) -> Result<Json<PolicyDocument>, ApiError> {
    Ok(Json(services::policies::read(&s.repo_path)?))
}

async fn policy_put(
    State(s): State<AppState>,
    Json(body): Json<PolicyWrite>,
) -> Result<Json<PolicyDocument>, ApiError> {
    services::policies::write(&s.repo_path, &body.yaml)
        .map(Json)
        .map_err(policy_error_to_api)
}

async fn policy_dry_run(
    State(s): State<AppState>,
    Json(body): Json<PolicyDryRun>,
) -> Result<Json<PolicyDryRunResult>, ApiError> {
    let store = s.store.lock().await;
    services::policies::dry_run(&store, &s.repo_path, &body.yaml)
        .map(Json)
        .map_err(policy_error_to_api)
}

fn policy_error_to_api(err: services::policies::PolicyError) -> ApiError {
    match err {
        services::policies::PolicyError::Yaml(msg) => ApiError::BadRequest(msg),
        services::policies::PolicyError::Internal(e) => ApiError::Internal(e),
    }
}

async fn scan_create(
    State(s): State<AppState>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let id = jobs::spawn(s, JobKind::Scan).await?;
    Ok((StatusCode::ACCEPTED, Json(JobAccepted { id })))
}

async fn sync_create(
    State(s): State<AppState>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let id = jobs::spawn(s, JobKind::Sync).await?;
    Ok((StatusCode::ACCEPTED, Json(JobAccepted { id })))
}

async fn job_get(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JobView>, ApiError> {
    let store = s.store.lock().await;
    store
        .load_job(&id)?
        .map(jobs::to_view)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("job {id} not found")))
}
