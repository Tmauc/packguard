//! HTTP routing layer. Pure mapping of paths → service-layer calls; the
//! service crate keeps every endpoint testable without spinning up axum.

use crate::dto::{
    ActionDeferRequest, ActionDeferResponse, ActionDismissRequest, ActionDismissResponse,
    ActionsQuery, ActionsResponse, AddProjectRequest, ContaminatedQuery, GraphQuery, JobAccepted,
    JobView, PackagesQuery, PolicyDryRun, PolicyWrite, ProjectDto, ProjectQuery,
    WorkspacesResponse,
};
use crate::error::ApiError;
use crate::jobs;
use crate::services;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use packguard_store::{IntelStore, ProjectsRegistry, Store};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

pub struct ServerConfig {
    pub repo_path: PathBuf,
    pub store: Store,
    /// Cross-project intel catalog. Required by 14.1e.1 plumbing —
    /// even though no handler reads from it yet, AppState owns the
    /// connection so the cutover in 14.1e.2/.3 is a one-line swap.
    pub intel: IntelStore,
    /// Projects registry. Populated by the 14.1d migration; consumed
    /// by the upcoming `/api/projects` endpoints in 14.1f.
    pub projects: ProjectsRegistry,
}

pub fn router(cfg: ServerConfig) -> Router {
    let state = AppState {
        store: Arc::new(Mutex::new(cfg.store)),
        intel: Arc::new(Mutex::new(cfg.intel)),
        projects: Arc::new(Mutex::new(cfg.projects)),
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
        .route("/api/projects", get(projects_list).post(projects_create))
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
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::overview::build(&store, &intel, scope.path())?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn packages_list(
    State(s): State<AppState>,
    Query(q): Query<PackagesQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::packages::list(&store, &intel, &q, scope.path())?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn package_detail(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let detail = services::packages::detail(&store, &intel, &ecosystem, &name, scope.path())?
        .ok_or_else(|| ApiError::NotFound(format!("{ecosystem}/{name} not in scan cache")))?;
    Ok(with_deprecation_header(detail, scope.is_legacy()))
}

async fn policy_get(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let repo = scope.path().unwrap_or(&s.repo_path);
    let body = services::policies::read(repo)?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn policy_put(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyWrite>,
) -> Result<axum::response::Response, ApiError> {
    let (repo, deprecated) = {
        let store = s.store.lock().await;
        let registry = s.projects.lock().await;
        let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
        let path = scope
            .path()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| s.repo_path.clone());
        (path, scope.is_legacy())
    };
    let doc = services::policies::write(&repo, &body.yaml).map_err(policy_error_to_api)?;
    Ok(with_deprecation_header(doc, deprecated))
}

async fn graph_get(
    State(s): State<AppState>,
    Query(q): Query<GraphQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::graph::build(
        &store,
        &intel,
        scope.path(),
        q.workspace.as_deref(),
        q.max_depth,
        q.kind.as_deref(),
    )?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn graph_contaminated(
    State(s): State<AppState>,
    Query(q): Query<ContaminatedQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::graph::contaminated_chains(&store, &intel, scope.path(), &q.vuln_id)?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn graph_vulnerabilities(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::graph::vulnerabilities(&store, &intel, scope.path())?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn package_compat(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let body = services::graph::compat(&store, scope.path(), &ecosystem, &name)?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn policy_dry_run(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyDryRun>,
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let repo = scope.path().unwrap_or(&s.repo_path);
    let result = services::policies::dry_run(&store, &intel, repo, &body.yaml)
        .map_err(policy_error_to_api)?;
    Ok(with_deprecation_header(result, scope.is_legacy()))
}

fn policy_error_to_api(err: services::policies::PolicyError) -> ApiError {
    match err {
        services::policies::PolicyError::Yaml(msg) => ApiError::BadRequest(msg),
        services::policies::PolicyError::Internal(e) => ApiError::Internal(e),
    }
}

/// Phase 14.1f deprecation header value for legacy `?project=<path>`.
/// Surfaces on every response that resolved its scope from a path
/// rather than a slug. Callers in 14.3+ should pass slugs instead.
///
/// Visible-ASCII only — HTTP header values reject everything else, so
/// no em-dash / Unicode arrow even though they read better in prose.
const DEPRECATED_PATH_QUERY_HEADER: &str = "?project=<path> is deprecated, \
    use ?project=<slug> instead. \
    See https://packguard-docs.vercel.app/changelog/v0.6.0";

/// Phase 14.1f scope outcome. Returned by [`resolve_scope`] so handlers
/// know both *what* to filter by and *whether* the caller used the
/// deprecated path-style query param (so the response can carry
/// `X-PackGuard-Deprecated`).
///
/// The legacy `Option<PathBuf>` accessor is kept via [`Self::path`] so
/// existing services keep filtering on `repos.path = ?` for now —
/// project-aware SQL filtering lands in 14.2 alongside the per-project
/// store cutover.
#[derive(Debug, Clone)]
enum ResolvedScope {
    /// `?project` absent or empty → no filter.
    Aggregate,
    /// `?project=<absolute path>` (legacy form). Filter on this path
    /// and emit `X-PackGuard-Deprecated`.
    LegacyPath(PathBuf),
    /// `?project=<slug>` (new form). The slug is validated against the
    /// registry, but for 14.1f the SQL layer still treats this as
    /// aggregate — the project→workspace cascade is 14.2's job. The
    /// resolved [`Project`](packguard_store::projects_registry::Project)
    /// is kept on the variant so 14.2 has it without re-locking the
    /// registry.
    #[allow(dead_code)]
    Slug(packguard_store::projects_registry::Project),
}

impl ResolvedScope {
    /// Path passed to the per-path service-layer filters. Slug scopes
    /// fall through to `None` (aggregate) for 14.1f.
    fn path(&self) -> Option<&std::path::Path> {
        match self {
            ResolvedScope::Aggregate | ResolvedScope::Slug(_) => None,
            ResolvedScope::LegacyPath(p) => Some(p.as_path()),
        }
    }

    fn is_legacy(&self) -> bool {
        matches!(self, ResolvedScope::LegacyPath(_))
    }
}

/// Validate + canonicalize the `?project=<X>` query param. Accepts
/// either a slug (new form) or an absolute path (legacy form, kept
/// alive for the Phase 13 dashboard until 14.3 ships its slug-aware
/// `ProjectSelector`).
///
/// - `None` / empty → [`ResolvedScope::Aggregate`].
/// - Path (`/...`) → canonicalize, assert it lives in
///   `store.distinct_repo_paths()`, return [`ResolvedScope::LegacyPath`].
/// - Slug → look up in the registry, return [`ResolvedScope::Slug`].
///
/// Unknown paths or slugs surface as 404 so the CLI / dashboard can
/// recover without a second round-trip.
fn resolve_scope(
    store: &packguard_store::Store,
    registry: &ProjectsRegistry,
    raw: Option<&str>,
) -> Result<ResolvedScope, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ResolvedScope::Aggregate);
    };
    if raw.starts_with('/') {
        let candidate = PathBuf::from(raw);
        let canonical = packguard_store::normalize_repo_path(&candidate);
        let known: Vec<String> = store
            .distinct_repo_paths()
            .map_err(ApiError::Internal)?
            .into_iter()
            .map(|p| p.display().to_string())
            .collect();
        if known.iter().any(|p| p == &canonical) {
            Ok(ResolvedScope::LegacyPath(PathBuf::from(canonical)))
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
    } else {
        let project = registry.get_by_slug(raw).map_err(ApiError::Internal)?;
        match project {
            Some(p) => Ok(ResolvedScope::Slug(p)),
            None => {
                let known: Vec<String> = registry
                    .list_projects()
                    .map_err(ApiError::Internal)?
                    .into_iter()
                    .map(|p| p.slug)
                    .collect();
                let listed = if known.is_empty() {
                    "(no projects registered — POST /api/projects first)".to_string()
                } else {
                    known
                        .iter()
                        .map(|s| format!("  - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                Err(ApiError::NotFound(format!(
                    "unknown project slug '{raw}'. Known slugs:\n{listed}"
                )))
            }
        }
    }
}

/// Wrap a serializable body with `X-PackGuard-Deprecated` when the
/// caller used a legacy path-style `?project=<path>` scope.
fn with_deprecation_header<T: serde::Serialize>(
    body: T,
    deprecated: bool,
) -> axum::response::Response {
    let mut resp = Json(body).into_response();
    if deprecated {
        resp.headers_mut().insert(
            HeaderName::from_static("x-packguard-deprecated"),
            HeaderValue::from_static(DEPRECATED_PATH_QUERY_HEADER),
        );
    }
    resp
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
) -> Result<axum::response::Response, ApiError> {
    let store = s.store.lock().await;
    let intel = s.intel.lock().await;
    let registry = s.projects.lock().await;
    let scope = resolve_scope(&store, &registry, q.project.as_deref())?;
    let now = chrono::Utc::now();
    let include_dismissed = q.include_dismissed.unwrap_or(false);
    let include_deferred = q.include_deferred.unwrap_or(false);
    let mut actions = packguard_actions::collect_all(
        &store,
        &intel,
        scope.path(),
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
    Ok(with_deprecation_header(
        ActionsResponse { actions, total },
        scope.is_legacy(),
    ))
}

/// Locate an action by its stable id from the global (unfiltered) set.
/// Scoping by project would make the dismiss call coupled to the
/// dashboard's current filter, which would fail when the UI transitions
/// scope between the user seeing and clicking the action.
fn locate_action(
    store: &packguard_store::Store,
    intel: &packguard_store::IntelStore,
    id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<packguard_actions::Action, ApiError> {
    let all = packguard_actions::collect_all(store, intel, None, now, false, false)
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
    let intel = s.intel.lock().await;
    let now = chrono::Utc::now();
    let action = locate_action(&store, &intel, &id, now)?;
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
    let intel = s.intel.lock().await;
    let now = chrono::Utc::now();
    let action = locate_action(&store, &intel, &id, now)?;
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

// ---- Phase 14.1f: /api/projects --------------------------------------------

async fn projects_list(State(s): State<AppState>) -> Result<Json<Vec<ProjectDto>>, ApiError> {
    let registry = s.projects.lock().await;
    let projects = registry.list_projects().map_err(ApiError::Internal)?;
    Ok(Json(projects.into_iter().map(ProjectDto::from).collect()))
}

async fn projects_create(
    State(s): State<AppState>,
    Json(body): Json<AddProjectRequest>,
) -> Result<(StatusCode, Json<JobAccepted>), ApiError> {
    let raw = std::path::Path::new(&body.path);
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
    // Walk-up to find the enclosing git root. The job will repeat this
    // resolution inside `registry.create_project` (so the registry stays
    // the source of truth on slug derivation), but front-loading the
    // check here lets us 400 instead of failing the job a second later.
    let root = packguard_core::find_project_root(&canonical).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} is not inside a git repository (no .git/ ancestor below $HOME)",
            canonical.display()
        ))
    })?;
    let id = jobs::spawn(s, jobs::JobSpec::AddProject(root)).await?;
    Ok((StatusCode::ACCEPTED, Json(JobAccepted { id })))
}
