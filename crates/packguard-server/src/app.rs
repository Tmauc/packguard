//! HTTP routing layer. Pure mapping of paths → service-layer calls; the
//! service crate keeps every endpoint testable without spinning up axum.

use crate::dto::{
    ActionDeferRequest, ActionDeferResponse, ActionDismissRequest, ActionDismissResponse,
    ActionsQuery, ActionsResponse, CompatResponse, ContaminatedQuery, ContaminationResult,
    GraphQuery, GraphResponse, GraphVulnerabilityList, JobAccepted, JobView, Overview,
    PackageDetail, PackagesPage, PackagesQuery, PolicyDocument, PolicyDryRun, PolicyDryRunResult,
    PolicyWrite, ProjectQuery, WorkspacesResponse,
};
use crate::error::ApiError;
use crate::jobs;
use crate::services;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
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
        .route("/api/graph/vulnerabilities", get(graph_vulnerabilities))
        .route(
            "/api/packages/{ecosystem}/{name}/compat",
            get(package_compat),
        )
        .route("/api/scan", post(scan_create))
        .route("/api/sync", post(sync_create))
        .route("/api/jobs/{id}", get(job_get))
        .route("/api/workspaces", get(workspaces_list))
        .route("/api/actions", get(actions_list))
        .route("/api/actions/{id}/dismiss", post(actions_dismiss))
        .route("/api/actions/{id}/defer", post(actions_defer))
        .route("/api/actions/{id}", delete(actions_restore))
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
    Query(q): Query<ProjectQuery>,
) -> Result<Json<PackageDetail>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    services::packages::detail(&store, &ecosystem, &name, project.as_deref())?
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

async fn graph_vulnerabilities(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<Json<GraphVulnerabilityList>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    Ok(Json(services::graph::vulnerabilities(
        &store,
        project.as_deref(),
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

#[derive(serde::Deserialize)]
struct ScanQuery {
    path: Option<PathBuf>,
}

async fn scan_create(
    State(s): State<AppState>,
    Query(q): Query<ScanQuery>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    // Phase 13.6: the dashboard's AddWorkspaceModal hands us a raw
    // absolute path typed by the user. Canonicalize + existence check
    // happen here so a typo surfaces as a 400 before we queue a job
    // that would fail 5s later with a cryptic scan-layer error.
    //
    // `None` keeps the pre-13.6 semantics intact — the CLI's
    // `packguard ui` without a user interaction still scans
    // `state.repo_path`.
    let target = match q.path {
        Some(p) => Some(validate_scan_target(&p)?),
        None => None,
    };
    let id = jobs::spawn(s, jobs::JobSpec::Scan(target)).await?;
    Ok((StatusCode::ACCEPTED, Json(JobAccepted { id })))
}

fn validate_scan_target(raw: &std::path::Path) -> Result<PathBuf, ApiError> {
    if !raw.is_absolute() {
        return Err(ApiError::BadRequest(format!(
            "path must be absolute: {}",
            raw.display()
        )));
    }
    let canonical = raw.canonicalize().map_err(|e| {
        ApiError::BadRequest(format!("path does not exist: {} ({e})", raw.display()))
    })?;
    if !canonical.is_dir() {
        return Err(ApiError::BadRequest(format!(
            "path is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

async fn sync_create(
    State(s): State<AppState>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let id = jobs::spawn(s, jobs::JobSpec::Sync).await?;
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

// ---- Phase 12a: Page Actions ----------------------------------------------

async fn actions_list(
    State(s): State<AppState>,
    Query(q): Query<ActionsQuery>,
) -> Result<Json<ActionsResponse>, ApiError> {
    let store = s.store.lock().await;
    let project = resolve_project_filter(&store, q.project.as_deref())?;
    let now = chrono::Utc::now();
    let include_dismissed = q.include_dismissed.unwrap_or(false);
    let include_deferred = q.include_deferred.unwrap_or(false);
    let mut actions = packguard_actions::collect_all(
        &store,
        project.as_deref(),
        now,
        include_dismissed,
        include_deferred,
    )
    .map_err(ApiError::Internal)?;
    let total = actions.len() as u32;
    if let Some(raw) = q.min_severity.as_deref() {
        if let Some(threshold) = packguard_actions::ActionSeverity::parse(raw) {
            packguard_actions::filter_min_severity(&mut actions, threshold);
        }
    }
    Ok(Json(ActionsResponse { actions, total }))
}

/// Locate an action by its stable id from the global (unfiltered) set.
/// Scoping by project would make the dismiss call coupled to the
/// dashboard's current filter, which would fail when the UI transitions
/// scope between the user seeing and clicking the action.
fn locate_action(
    store: &packguard_store::Store,
    id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<packguard_actions::Action, ApiError> {
    let all = packguard_actions::collect_all(store, None, now, false, false)
        .map_err(ApiError::Internal)?;
    all.into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("action {id} not found")))
}

async fn actions_dismiss(
    State(s): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ActionDismissRequest>>,
) -> Result<Json<ActionDismissResponse>, ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let mut store = s.store.lock().await;
    let now = chrono::Utc::now();
    let action = locate_action(&store, &id, now)?;
    packguard_actions::dismiss(&mut store, &action, req.reason.as_deref(), now)
        .map_err(ApiError::Internal)?;
    Ok(Json(ActionDismissResponse {
        dismissed_at: now.to_rfc3339(),
    }))
}

async fn actions_defer(
    State(s): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ActionDeferRequest>>,
) -> Result<Json<ActionDeferResponse>, ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let days = req.days.unwrap_or(7).clamp(1, 365);
    let mut store = s.store.lock().await;
    let now = chrono::Utc::now();
    let action = locate_action(&store, &id, now)?;
    let until = packguard_actions::defer(&mut store, &action, days, req.reason.as_deref(), now)
        .map_err(ApiError::Internal)?;
    Ok(Json(ActionDeferResponse {
        deferred_until: until.to_rfc3339(),
    }))
}

async fn actions_restore(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut store = s.store.lock().await;
    packguard_actions::restore(&mut store, &id).map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}
