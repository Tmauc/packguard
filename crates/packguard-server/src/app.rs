//! HTTP routing layer. Pure mapping of paths → service-layer calls; the
//! service crate keeps every endpoint testable without spinning up axum.

use crate::dto::{
    CompatResponse, ContaminatedQuery, ContaminationResult, GraphQuery, GraphResponse, JobAccepted,
    JobKind, JobView, Overview, PackageDetail, PackagesPage, PackagesQuery, PolicyDocument,
    PolicyDryRun, PolicyDryRunResult, PolicyWrite, ProjectQuery, WorkspacesResponse,
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
    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/overview", get(overview))
        .route("/api/packages", get(packages_list))
        .route("/api/packages/{ecosystem}/{name}", get(package_detail))
        .route("/api/policies", get(policy_get).put(policy_put))
        .route("/api/policies/dry-run", post(policy_dry_run))
        .route("/api/graph", get(graph_get))
        .route("/api/graph/contaminated", get(graph_contaminated))
        .route(
            "/api/packages/{ecosystem}/{name}/compat",
            get(package_compat),
        )
        .route("/api/scan", post(scan_create))
        .route("/api/sync", post(sync_create))
        .route("/api/jobs/{id}", get(job_get))
        .route("/api/workspaces", get(workspaces_list))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    attach_ui(api)
}

#[cfg(feature = "ui-embed")]
fn attach_ui(api: Router) -> Router {
    use axum::routing::get;
    api.route("/", get(crate::embed::serve_root))
        .fallback(crate::embed::serve)
}

#[cfg(not(feature = "ui-embed"))]
fn attach_ui(api: Router) -> Router {
    api
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

async fn overview(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<Json<Overview>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::overview::build(&store, project.as_deref())?))
}

async fn packages_list(
    State(s): State<AppState>,
    Query(q): Query<PackagesQuery>,
) -> Result<Json<PackagesPage>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::packages::list(
        &store,
        &q,
        project.as_deref(),
    )?))
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

async fn policy_get(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<Json<PolicyDocument>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    let repo = project.as_deref().unwrap_or(&s.repo_path);
    Ok(Json(services::policies::read(repo)?))
}

async fn policy_put(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyWrite>,
) -> Result<Json<PolicyDocument>, ApiError> {
    let repo = {
        let store = s.store.lock().await;
        resolve_project_filter(&store, q.project.as_deref())?.unwrap_or_else(|| s.repo_path.clone())
    };
    services::policies::write(&repo, &body.yaml)
        .map(Json)
        .map_err(policy_error_to_api)
}

async fn graph_get(
    State(s): State<AppState>,
    Query(q): Query<GraphQuery>,
) -> Result<Json<GraphResponse>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::graph::build(
        &store,
        project.as_deref(),
        q.workspace.as_deref(),
        q.max_depth,
        q.kind.as_deref(),
    )?))
}

async fn graph_contaminated(
    State(s): State<AppState>,
    Query(q): Query<ContaminatedQuery>,
) -> Result<Json<ContaminationResult>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::graph::contaminated_chains(
        &store,
        project.as_deref(),
        &q.vuln_id,
    )?))
}

async fn package_compat(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
    Query(q): Query<ProjectQuery>,
) -> Result<Json<CompatResponse>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::graph::compat(
        &store,
        project.as_deref(),
        &ecosystem,
        &name,
    )?))
}

async fn policy_dry_run(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyDryRun>,
) -> Result<Json<PolicyDryRunResult>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    let repo = project.as_deref().unwrap_or(&s.repo_path);
    services::policies::dry_run(&store, repo, &body.yaml)
        .map(Json)
        .map_err(policy_error_to_api)
}

fn policy_error_to_api(err: services::policies::PolicyError) -> ApiError {
    match err {
        services::policies::PolicyError::Yaml(msg) => ApiError::BadRequest(msg),
        services::policies::PolicyError::Internal(e) => ApiError::Internal(e),
    }
}

/// Phase 7a: validate + canonicalize the `?project=<path>` query param.
///
/// - `None` → the caller runs the aggregate path (no workspace filter).
/// - `Some(raw)` → canonicalize through `normalize_repo_path`, assert
///   the result lives in `store.distinct_repo_paths()`, and hand back a
///   `PathBuf` the services can feed into their path-scoped lookups.
///
/// Unknown paths surface as 404 with the known-workspace list inline so
/// the CLI / dashboard can recover without a second round-trip.
fn resolve_project_filter(
    store: &packguard_store::Store,
    raw: Option<&str>,
) -> Result<Option<PathBuf>, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let candidate = PathBuf::from(raw);
    let canonical = packguard_store::normalize_repo_path(&candidate);
    let known: Vec<String> = store
        .distinct_repo_paths()
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|p| p.display().to_string())
        .collect();
    if known.iter().any(|p| p == &canonical) {
        Ok(Some(PathBuf::from(canonical)))
    } else {
        let listed = if known.is_empty() {
            "(no scans in store — run `packguard scan <path>` first)".to_string()
        } else {
            known
                .iter()
                .map(|p| format!("  - {p}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        Err(ApiError::NotFound(format!(
            "unknown workspace '{raw}'. Known workspaces:\n{listed}"
        )))
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

/// Phase 7a: every scanned repo as a workspace row the UI selector can
/// paint. Already sorted by `last_scan_at DESC` upstream (see
/// `store::scans_index`) — the most-recent scan lands at index 0, which
/// is also what `packguard ui` picks as the default workspace when no
/// path is passed (Polish-bis-2).
async fn workspaces_list(State(s): State<AppState>) -> Result<Json<WorkspacesResponse>, ApiError> {
    let store = s.store.lock().await;
    Ok(Json(services::workspaces::list(&store)?))
}
