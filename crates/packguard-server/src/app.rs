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
use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

pub struct ServerConfig {
    /// Aggregate-fallback root — used by `policy_get/put/dry_run` when
    /// the request omits `?project=…`. The CLI sets this to the cwd
    /// it booted in.
    pub repo_path: PathBuf,
    /// Cross-project intel catalog (advisories + sync state + jobs).
    pub intel: IntelStore,
    /// Projects registry. Populated by the 14.1d migration and the
    /// 14.1f `POST /api/projects` handler.
    pub projects: ProjectsRegistry,
    /// Per-slug `Store` cache. Every project-scoped read/write goes
    /// through this handle.
    pub project_stores: Arc<ProjectStoreCache>,
}

pub fn router(cfg: ServerConfig) -> Router {
    let state = AppState {
        intel: Arc::new(Mutex::new(cfg.intel)),
        projects: Arc::new(Mutex::new(cfg.projects)),
        project_stores: cfg.project_stores,
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
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::Overview> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::overview::build(&pstore, &intel, scope.workspace_path())?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_overview(prev, part),
        });
    }
    let body = accum.unwrap_or_else(empty_overview);
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

fn empty_overview() -> crate::dto::Overview {
    crate::dto::Overview {
        health_score: None,
        last_scan_at: None,
        last_sync_at: None,
        packages_total: 0,
        packages_by_ecosystem: Vec::new(),
        vulnerabilities: crate::dto::VulnSummary::default(),
        malware: crate::dto::MalwareSummary::default(),
        compliance: crate::dto::ComplianceSummary::default(),
        top_risks: Vec::new(),
    }
}

async fn packages_list(
    State(s): State<AppState>,
    Query(q): Query<PackagesQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::PackagesPage> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::packages::list(&pstore, &intel, &q, scope.workspace_path())?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_packages_page(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| crate::dto::PackagesPage {
        total: 0,
        page: q.page.unwrap_or(1).max(1),
        per_page: q.per_page.unwrap_or(50).clamp(1, 500),
        rows: Vec::new(),
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn package_detail(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    // Take the first store that has the package — package detail is
    // single-row, no merge.
    let mut detail: Option<crate::dto::PackageDetail> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        if let Some(d) =
            services::packages::detail(&pstore, &intel, &ecosystem, &name, scope.workspace_path())?
        {
            detail = Some(d);
            break;
        }
    }
    let detail = detail
        .ok_or_else(|| ApiError::NotFound(format!("{ecosystem}/{name} not in scan cache")))?;
    Ok(with_deprecation_header(detail, scope.is_legacy()))
}

async fn policy_get(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    // Slug scope reads `<project_root>/.packguard.yml`. Path scope keeps
    // its 14.1f behaviour (the original workspace path). Aggregate falls
    // back to the server's repo_path.
    let repo: PathBuf = match &scope {
        ResolvedScope::Slug(project) => project.path.clone(),
        ResolvedScope::LegacyPath { workspace_path, .. } => workspace_path.clone(),
        ResolvedScope::Aggregate => s.repo_path.clone(),
    };
    let body = services::policies::read(&repo)?;
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn policy_put(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyWrite>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let repo: PathBuf = match &scope {
        ResolvedScope::Slug(project) => project.path.clone(),
        ResolvedScope::LegacyPath { workspace_path, .. } => workspace_path.clone(),
        ResolvedScope::Aggregate => s.repo_path.clone(),
    };
    let doc = services::policies::write(&repo, &body.yaml).map_err(policy_error_to_api)?;
    Ok(with_deprecation_header(doc, scope.is_legacy()))
}

async fn graph_get(
    State(s): State<AppState>,
    Query(q): Query<GraphQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::GraphResponse> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::graph::build(
            &pstore,
            &intel,
            scope.workspace_path(),
            q.workspace.as_deref(),
            q.max_depth,
            q.kind.as_deref(),
        )?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_graph_response(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| crate::dto::GraphResponse {
        nodes: Vec::new(),
        edges: Vec::new(),
        oversize_warning: None,
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn graph_contaminated(
    State(s): State<AppState>,
    Query(q): Query<ContaminatedQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::ContaminationResult> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::graph::contaminated_chains(
            &pstore,
            &intel,
            scope.workspace_path(),
            &q.vuln_id,
        )?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_contamination(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| crate::dto::ContaminationResult {
        hits: Vec::new(),
        chains: Vec::new(),
        from_cache: false,
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn graph_vulnerabilities(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::GraphVulnerabilityList> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::graph::vulnerabilities(&pstore, &intel, scope.workspace_path())?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_vuln_list(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| crate::dto::GraphVulnerabilityList {
        entries: Vec::new(),
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn package_compat(
    State(s): State<AppState>,
    Path((ecosystem, name)): Path<(String, String)>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<crate::dto::CompatResponse> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::graph::compat(&pstore, scope.workspace_path(), &ecosystem, &name)?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_compat(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| crate::dto::CompatResponse {
        ecosystem: ecosystem.clone(),
        name: name.clone(),
        installed: None,
        rows: Vec::new(),
        dependents: Vec::new(),
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

async fn policy_dry_run(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
    Json(body): Json<PolicyDryRun>,
) -> Result<axum::response::Response, ApiError> {
    // Validate the candidate YAML up-front so a malformed body
    // surfaces 400 even when the registry has zero slugs to fan out
    // (the per-store loop below is a no-op in that case and would
    // otherwise return an empty 200).
    services::policies::parse_candidate(&body.yaml).map_err(ApiError::BadRequest)?;
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let repo = scope_repo_path(&scope, &s.repo_path);
    let slugs = scope.slugs(&s.project_stores)?;
    let mut combined: Option<crate::dto::PolicyDryRunResult> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::policies::dry_run(&pstore, &intel, &repo, &body.yaml)
            .map_err(policy_error_to_api)?;
        combined = Some(match combined {
            None => part,
            Some(prev) => merge_dry_run(prev, part),
        });
    }
    let result = combined.unwrap_or_default();
    Ok(with_deprecation_header(result, scope.is_legacy()))
}

/// Choose the filesystem path the policy file lives at. Slug scope
/// uses the project root; legacy path scope uses the original
/// workspace path; aggregate / unknown falls back to the server's
/// `repo_path`.
fn scope_repo_path(scope: &ResolvedScope, fallback: &std::path::Path) -> PathBuf {
    match scope {
        ResolvedScope::Slug(project) => project.path.clone(),
        ResolvedScope::LegacyPath { workspace_path, .. } => workspace_path.clone(),
        ResolvedScope::Aggregate => fallback.to_path_buf(),
    }
}

// ---- Phase 14.2b.2: per-store result mergers ------------------------------

/// Sum two [`Overview`] payloads. Counts add, top_risks concat then
/// truncate to 5 (sorted by score desc), `last_*_at` take the max.
fn merge_overview(a: crate::dto::Overview, b: crate::dto::Overview) -> crate::dto::Overview {
    use std::collections::BTreeMap;
    let mut by_eco: BTreeMap<String, u32> = BTreeMap::new();
    for row in a
        .packages_by_ecosystem
        .into_iter()
        .chain(b.packages_by_ecosystem)
    {
        *by_eco.entry(row.ecosystem).or_default() += row.count;
    }
    let packages_by_ecosystem = by_eco
        .into_iter()
        .map(|(ecosystem, count)| crate::dto::EcoCount { ecosystem, count })
        .collect();
    let packages_total = a.packages_total + b.packages_total;
    let vulnerabilities = crate::dto::VulnSummary {
        critical: a.vulnerabilities.critical + b.vulnerabilities.critical,
        high: a.vulnerabilities.high + b.vulnerabilities.high,
        medium: a.vulnerabilities.medium + b.vulnerabilities.medium,
        low: a.vulnerabilities.low + b.vulnerabilities.low,
        unknown: a.vulnerabilities.unknown + b.vulnerabilities.unknown,
    };
    let malware = crate::dto::MalwareSummary {
        confirmed: a.malware.confirmed + b.malware.confirmed,
        typosquat_suspects: a.malware.typosquat_suspects + b.malware.typosquat_suspects,
    };
    let compliance = crate::dto::ComplianceSummary {
        compliant: a.compliance.compliant + b.compliance.compliant,
        warnings: a.compliance.warnings + b.compliance.warnings,
        violations: a.compliance.violations + b.compliance.violations,
        insufficient: a.compliance.insufficient + b.compliance.insufficient,
    };
    let mut top_risks = a.top_risks;
    top_risks.extend(b.top_risks);
    top_risks.sort_by_key(|r| std::cmp::Reverse(r.score));
    top_risks.truncate(5);
    let health_score = packages_total
        .checked_div(1)
        .and_then(|_| (compliance.compliant * 100).checked_div(packages_total));
    crate::dto::Overview {
        health_score,
        last_scan_at: max_opt(a.last_scan_at, b.last_scan_at),
        last_sync_at: max_opt(a.last_sync_at, b.last_sync_at),
        packages_total,
        packages_by_ecosystem,
        vulnerabilities,
        malware,
        compliance,
        top_risks,
    }
}

fn max_opt(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(if x >= y { x } else { y }),
    }
}

/// Concat two `PackagesPage` results. Pagination is naive — total =
/// sum of per-store totals, rows are appended. The dashboard reads
/// `total` and `rows` independently, so a 2-store aggregate may show
/// pagination boundaries that don't line up perfectly. v0.7.0's
/// cross-project view is the natural place to revisit this.
fn merge_packages_page(
    mut a: crate::dto::PackagesPage,
    b: crate::dto::PackagesPage,
) -> crate::dto::PackagesPage {
    a.total += b.total;
    a.rows.extend(b.rows);
    a
}

fn merge_graph_response(
    mut a: crate::dto::GraphResponse,
    b: crate::dto::GraphResponse,
) -> crate::dto::GraphResponse {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<String> = a.nodes.iter().map(|n| n.id.clone()).collect();
    for n in b.nodes {
        if seen.insert(n.id.clone()) {
            a.nodes.push(n);
        }
    }
    a.edges.extend(b.edges);
    if let Some(w) = b.oversize_warning {
        a.oversize_warning = Some(w);
    }
    a
}

fn merge_contamination(
    mut a: crate::dto::ContaminationResult,
    b: crate::dto::ContaminationResult,
) -> crate::dto::ContaminationResult {
    a.hits.extend(b.hits);
    a.chains.extend(b.chains);
    a.from_cache = a.from_cache && b.from_cache;
    a
}

fn merge_vuln_list(
    mut a: crate::dto::GraphVulnerabilityList,
    b: crate::dto::GraphVulnerabilityList,
) -> crate::dto::GraphVulnerabilityList {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<(String, String, String, String)> = a
        .entries
        .iter()
        .map(|e| {
            (
                e.advisory_id.clone(),
                e.ecosystem.clone(),
                e.package_name.clone(),
                e.package_version.clone(),
            )
        })
        .collect();
    for entry in b.entries {
        let key = (
            entry.advisory_id.clone(),
            entry.ecosystem.clone(),
            entry.package_name.clone(),
            entry.package_version.clone(),
        );
        if seen.insert(key) {
            a.entries.push(entry);
        }
    }
    a
}

fn merge_compat(
    mut a: crate::dto::CompatResponse,
    b: crate::dto::CompatResponse,
) -> crate::dto::CompatResponse {
    use std::collections::BTreeMap;
    let mut by_version: BTreeMap<String, crate::dto::CompatRow> =
        a.rows.into_iter().map(|r| (r.version.clone(), r)).collect();
    for r in b.rows {
        by_version.entry(r.version.clone()).or_insert(r);
    }
    a.rows = by_version.into_values().collect();
    if a.installed.is_none() {
        a.installed = b.installed;
    }
    a.dependents.extend(b.dependents);
    a
}

fn merge_workspaces(
    mut a: crate::dto::WorkspacesResponse,
    b: crate::dto::WorkspacesResponse,
) -> crate::dto::WorkspacesResponse {
    a.workspaces.extend(b.workspaces);
    a
}

fn merge_dry_run(
    mut a: crate::dto::PolicyDryRunResult,
    b: crate::dto::PolicyDryRunResult,
) -> crate::dto::PolicyDryRunResult {
    a.candidate.compliant += b.candidate.compliant;
    a.candidate.warnings += b.candidate.warnings;
    a.candidate.violations += b.candidate.violations;
    a.candidate.insufficient += b.candidate.insufficient;
    a.current.compliant += b.current.compliant;
    a.current.warnings += b.current.warnings;
    a.current.violations += b.current.violations;
    a.current.insufficient += b.current.insufficient;
    a.changed_packages.extend(b.changed_packages);
    a
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

/// Phase 14.2b.2 — outcome of resolving `?project=<X>`. Every variant
/// now resolves to a list of slugs the handler iterates against the
/// `ProjectStoreCache`; the legacy global `Store` is no longer read
/// by HTTP read handlers.
///
/// `LegacyPath` keeps the deprecation header alive for the Phase 13
/// dashboard's `?project=<workspace path>` call shape but routes
/// reads to the same per-project store as the slug form.
#[derive(Debug, Clone)]
enum ResolvedScope {
    /// `?project` absent or empty → fan out across every project the
    /// registry knows about (one read per per-project store under
    /// `~/.packguard/projects/<slug>/`).
    Aggregate,
    /// `?project=<slug>` (new form). Targets a single per-project
    /// store; no workspace-path filter inside it.
    Slug(packguard_store::projects_registry::Project),
    /// `?project=<absolute path>` (legacy form). The path resolves
    /// via `ProjectsRegistry::get_by_path` (walk up to a `.git/`
    /// ancestor) so reads land on the same per-project store as the
    /// slug form. Paths outside any git tree fall back to the
    /// `_default_` slug populated by the 14.1d migration. The
    /// original workspace path is retained as a per-store filter so
    /// the response stays scoped to the workspace the caller asked
    /// for. Triggers `X-PackGuard-Deprecated` on the response.
    LegacyPath {
        project: packguard_store::projects_registry::Project,
        workspace_path: PathBuf,
    },
}

impl ResolvedScope {
    /// Workspace-path filter passed to per-store services. Only
    /// `LegacyPath` carries one — the slug form wants every workspace
    /// under the project, and `Aggregate` fans out across every store.
    fn workspace_path(&self) -> Option<&std::path::Path> {
        match self {
            ResolvedScope::Aggregate | ResolvedScope::Slug(_) => None,
            ResolvedScope::LegacyPath { workspace_path, .. } => Some(workspace_path.as_path()),
        }
    }

    fn is_legacy(&self) -> bool {
        matches!(self, ResolvedScope::LegacyPath { .. })
    }

    /// Slugs to iterate when fanning a request across per-project
    /// stores. `Aggregate` returns every slug `slug_paths()` finds on
    /// disk (sorted, deterministic). `Slug` and `LegacyPath` return
    /// the single resolved slug.
    fn slugs(
        &self,
        project_stores: &packguard_store::ProjectStoreCache,
    ) -> Result<Vec<String>, ApiError> {
        match self {
            ResolvedScope::Aggregate => Ok(project_stores
                .slug_paths()
                .map_err(ApiError::Internal)?
                .into_iter()
                .map(|(s, _)| s)
                .collect()),
            ResolvedScope::Slug(p) => Ok(vec![p.slug.clone()]),
            ResolvedScope::LegacyPath { project, .. } => Ok(vec![project.slug.clone()]),
        }
    }
}

/// Validate + resolve the `?project=<X>` query param.
///
/// - `None` / empty → [`ResolvedScope::Aggregate`].
/// - Path (`/...`) → walk up via `ProjectsRegistry::get_by_path`
///   (looks for a `.git/` ancestor and matches the resulting slug).
///   On miss, fall back to the `_default_` slug populated by the
///   14.1d migration for paths outside any git tree. 404 if neither
///   resolves.
/// - Slug → `get_by_slug`. 404 if unknown.
fn resolve_scope(
    registry: &ProjectsRegistry,
    raw: Option<&str>,
) -> Result<ResolvedScope, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ResolvedScope::Aggregate);
    };
    if raw.starts_with('/') {
        let candidate = PathBuf::from(raw);
        // Refuse paths that don't exist on disk — `/nowhere` should
        // 404, not silently fall through to a `_default_` project.
        let canonical = match candidate.canonicalize() {
            Ok(c) => c,
            Err(_) => {
                return Err(ApiError::NotFound(format!(
                    "unknown workspace '{raw}': path does not exist"
                )));
            }
        };
        // Walk up to the project root. For paths outside any `.git/`
        // tree (test fixtures, scratch dirs), the 14.1d migration
        // groups them under `_default_` — match that fallback so the
        // legacy `?project=<workspace path>` query keeps resolving as
        // long as the path is a real directory on disk.
        let project = registry
            .get_by_path(&canonical)
            .ok()
            .flatten()
            .or_else(|| registry.get_by_slug("_default_").ok().flatten());
        match project {
            Some(p) => Ok(ResolvedScope::LegacyPath {
                project: p,
                workspace_path: canonical,
            }),
            None => {
                let known: Vec<String> = registry
                    .list_projects()
                    .map_err(ApiError::Internal)?
                    .into_iter()
                    .map(|p| p.path.display().to_string())
                    .collect();
                let listed = if known.is_empty() {
                    "(no projects registered — POST /api/projects first)".to_string()
                } else {
                    known
                        .iter()
                        .map(|p| format!("  - {p}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                Err(ApiError::NotFound(format!(
                    "unknown workspace '{raw}'. Known projects:\n{listed}"
                )))
            }
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

/// Lock-then-resolve helper. Acquires the legacy `Store` and the
/// projects registry lock, runs [`resolve_scope`], drops it before
/// returning. Handlers then iterate per-project stores via
/// [`ProjectStoreCache`] without keeping a registry guard alive
/// across the read.
async fn resolve_scope_locked(s: &AppState, raw: Option<&str>) -> Result<ResolvedScope, ApiError> {
    let registry = s.projects.lock().await;
    resolve_scope(&registry, raw)
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
    let intel = s.intel.lock().await;
    intel
        .load_job(&id)?
        .map(jobs::to_view)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("job {id} not found")))
}

/// Phase 7a / 14.2b.2 / 14.3b: every scanned workspace, optionally
/// scoped to a single project via `?project=<slug>`.
///
/// - No `?project=` → fan out across every registered project's store
///   (`slug_paths()` order).
/// - `?project=<slug>` → resolve via [`resolve_scope`] (404 with the
///   list of known slugs on a miss) and read only that store. Powers
///   the 14.3b `<ProjectSelector>` so swapping the active project also
///   narrows the workspace selector to that project's workspaces.
/// - `?project=<absolute path>` → still honored for v0.5 bookmarks via
///   the legacy-path branch in [`resolve_scope`]; the deprecation
///   header is emitted by `with_deprecation_header`.
///
/// Already-sorted-by-last-scan-DESC ordering holds within each store
/// but isn't globally re-sorted: the dashboard's selector tolerates
/// per-project clusters.
async fn workspaces_list(
    State(s): State<AppState>,
    Query(q): Query<ProjectQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let slugs = scope.slugs(&s.project_stores)?;
    let mut accum: Option<WorkspacesResponse> = None;
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = services::workspaces::list(&pstore)?;
        accum = Some(match accum {
            None => part,
            Some(prev) => merge_workspaces(prev, part),
        });
    }
    let body = accum.unwrap_or_else(|| WorkspacesResponse {
        workspaces: Vec::new(),
    });
    Ok(with_deprecation_header(body, scope.is_legacy()))
}

// ---- Phase 12a: Page Actions ----------------------------------------------

async fn actions_list(
    State(s): State<AppState>,
    Query(q): Query<ActionsQuery>,
) -> Result<axum::response::Response, ApiError> {
    let scope = resolve_scope_locked(&s, q.project.as_deref()).await?;
    let intel = s.intel.lock().await;
    let now = chrono::Utc::now();
    let include_dismissed = q.include_dismissed.unwrap_or(false);
    let include_deferred = q.include_deferred.unwrap_or(false);
    let slugs = scope.slugs(&s.project_stores)?;
    let mut actions: Vec<packguard_actions::Action> = Vec::new();
    for slug in &slugs {
        let pstore = s.project_stores.get_or_open(slug).await?;
        let pstore = pstore.lock().await;
        let part = packguard_actions::collect_all(
            &pstore,
            &intel,
            scope.workspace_path(),
            now,
            include_dismissed,
            include_deferred,
        )
        .map_err(ApiError::Internal)?;
        actions.extend(part);
    }
    // The single-store generator already orders by severity desc; the
    // multi-store concat preserves that ordering within each store
    // chunk. For v0.6.0 (1 project) the chunk count is 1; multi-
    // project re-sort is a 14.3+ concern.
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

/// Phase 14.2b.2 — locate an action across every per-project store
/// the registry knows about. Returns both the resolved [`Action`] and
/// the slug that produced it, so dismiss/defer can route their write
/// to the right per-project store without re-walking the registry.
///
/// The action carries `workspace`, but for a `_global` action like
/// `RefreshSync` the workspace string isn't a real path. Iterating
/// stores until one emits the id is the simplest correct approach;
/// it also handles the rare "same id observed in multiple slugs"
/// case (e.g. RefreshSync, which the generator emits per-store) by
/// landing the dismissal in the alphabetically-first slug. The
/// dashboard re-fetches actions after a dismissal, so the user sees
/// the row disappear from that slug's view immediately.
async fn locate_action(
    state: &AppState,
    id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(packguard_actions::Action, String), ApiError> {
    for (slug, _) in state.project_stores.slug_paths()? {
        let pstore = state.project_stores.get_or_open(&slug).await?;
        let pstore = pstore.lock().await;
        let intel = state.intel.lock().await;
        let actions = packguard_actions::collect_all(&pstore, &intel, None, now, true, true)
            .map_err(ApiError::Internal)?;
        if let Some(action) = actions.into_iter().find(|a| a.id == id) {
            return Ok((action, slug));
        }
    }
    Err(ApiError::NotFound(format!("action {id} not found")))
}

async fn actions_dismiss(
    State(s): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ActionDismissRequest>>,
) -> Result<Json<ActionDismissResponse>, ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let now = chrono::Utc::now();
    let (action, slug) = locate_action(&s, &id, now).await?;
    let pstore = s.project_stores.get_or_open(&slug).await?;
    let mut pstore = pstore.lock().await;
    packguard_actions::dismiss(&mut pstore, &action, req.reason.as_deref(), now)
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
    let now = chrono::Utc::now();
    let (action, slug) = locate_action(&s, &id, now).await?;
    let pstore = s.project_stores.get_or_open(&slug).await?;
    let mut pstore = pstore.lock().await;
    let until = packguard_actions::defer(&mut pstore, &action, days, req.reason.as_deref(), now)
        .map_err(ApiError::Internal)?;
    Ok(Json(ActionDeferResponse {
        deferred_until: until.to_rfc3339(),
    }))
}

/// Restore is id-only — the action's source slug isn't carried on
/// the URL, and resolving via `collect_all` doesn't help because the
/// row may have been dismissed long enough ago that the underlying
/// dependency is gone. So we fan out: call `restore` on every
/// per-project store. The DELETE is idempotent against missing rows,
/// so fanout is safe.
async fn actions_restore(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    for (slug, _) in s.project_stores.slug_paths()? {
        let pstore = s.project_stores.get_or_open(&slug).await?;
        let mut pstore = pstore.lock().await;
        packguard_actions::restore(&mut pstore, &id).map_err(ApiError::Internal)?;
    }
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
