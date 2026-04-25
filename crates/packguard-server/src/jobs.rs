//! Async job runner. The handler returns a `JobAccepted { id }` payload
//! immediately; the actual scan/sync runs on a tokio task that updates the
//! `jobs` table as it transitions pending → running → succeeded/failed.

use crate::dto::{JobKind, JobView};
use crate::services::{scan, sync_intel};
use crate::state::AppState;
use anyhow::Result;
use std::path::PathBuf;
use uuid::Uuid;

/// Internal runner spec. Decoupled from the wire-facing `JobKind` (which
/// is a ts-rs-exported flat enum) so the scan handler can attach an
/// optional custom path without breaking the DTO surface or leaking a
/// discriminated union into the dashboard.
///
/// `Scan(None)` reuses `AppState::repo_path` — the backcompat path that
/// existed before Phase 13.6 and that the CLI's `packguard ui` still
/// relies on when the operator hasn't picked a workspace from the
/// header selector.
pub enum JobSpec {
    Scan(Option<PathBuf>),
    Sync,
    /// Phase 14.1f — registers the canonical project root in the
    /// `ProjectsRegistry`, then runs a recursive scan against it. On
    /// success the registry's `last_scan` is bumped so the dashboard
    /// sorts the new project first.
    AddProject(PathBuf),
}

impl JobSpec {
    fn dto(&self) -> JobKind {
        match self {
            JobSpec::Scan(_) => JobKind::Scan,
            JobSpec::Sync => JobKind::Sync,
            JobSpec::AddProject(_) => JobKind::AddProject,
        }
    }
}

/// Spawn a job and persist it as `pending`. Returns the new id; callers
/// poll `GET /api/jobs/:id` to track progress.
pub async fn spawn(state: AppState, spec: JobSpec) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    {
        let mut store = state.store.lock().await;
        store.create_job(&id, spec.dto().as_str())?;
    }
    let id_clone = id.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        run_job(state_clone, id_clone, spec).await;
    });
    Ok(id)
}

async fn run_job(state: AppState, id: String, spec: JobSpec) {
    {
        let mut store = state.store.lock().await;
        let _ = store.update_job_status(&id, "running", None, None);
    }

    let outcome: Result<serde_json::Value> = match spec {
        JobSpec::Scan(target) => {
            let repo = target.unwrap_or_else(|| state.repo_path.clone());
            run_scan_job(&state, repo).await
        }
        JobSpec::Sync => run_sync_job(&state).await,
        JobSpec::AddProject(path) => run_add_project_job(&state, path).await,
    };

    let mut store = state.store.lock().await;
    match outcome {
        Ok(payload) => {
            let json = serde_json::to_string(&payload).unwrap_or_else(|_| "null".into());
            let _ = store.update_job_status(&id, "succeeded", Some(&json), None);
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let _ = store.update_job_status(&id, "failed", None, Some(&msg));
        }
    }
}

/// Phase 14.2b — scans now dual-write: the per-project store under
/// `<home>/projects/<slug>/store.db` (the runtime source of truth
/// post-bascule) AND the legacy global `Store` (kept fresh so the
/// not-yet-bascule'd surfaces — `?project=<path>`, aggregate, the CLI
/// `report/audit` commands — keep matching the dashboard until 14.2c
/// migrates them and 14.2d retires the legacy file).
///
/// Slug resolution: walk up from `repo` to find the project root,
/// look up the registry. If no entry exists, the dual-write skips the
/// per-project leg (a `packguard scan <path>` from outside any
/// registered project still works against the legacy store; the user
/// can `POST /api/projects` later to promote the path).
async fn run_scan_job(state: &AppState, repo: PathBuf) -> Result<serde_json::Value> {
    // Always write to the legacy store first. After 14.2d this branch
    // disappears.
    let report = {
        let mut store = state.store.lock().await;
        scan::run(&mut store, &repo).await?
    };

    // Best-effort per-project write. Resolve a slug; skip silently on
    // miss so a path outside any registered project doesn't fail the
    // job — the legacy write is still authoritative.
    let registered: Option<String> = {
        let registry = state.projects.lock().await;
        registry.get_by_path(&repo).ok().flatten().map(|p| p.slug)
    };
    if let Some(slug) = registered {
        let pstore = state.project_stores.get_or_open(&slug).await?;
        let mut pstore = pstore.lock().await;
        // Re-run the scan into the per-project store. Idempotent:
        // both stores get the same `save_project` payload from the
        // same registry+filesystem state.
        let _ = scan::run(&mut pstore, &repo).await?;
    }
    Ok(serde_json::to_value(report)?)
}

/// Phase 14.1f / 14.2b — register the project in the registry, run a
/// scan against its root (dual-write to legacy + per-project store),
/// then bump `last_scan`. The per-project store is created on first
/// `get_or_open` inside `run_scan_job` since the registry insert
/// already commits the slug.
async fn run_add_project_job(state: &AppState, path: PathBuf) -> Result<serde_json::Value> {
    let project_dto: crate::dto::ProjectDto = {
        let mut registry = state.projects.lock().await;
        registry.create_project(&path)?.into()
    };
    let scan_payload = run_scan_job(state, path).await?;
    {
        let mut registry = state.projects.lock().await;
        registry.touch_last_scan(&project_dto.slug)?;
    }
    Ok(serde_json::json!({
        "project": project_dto,
        "scan": scan_payload,
    }))
}

async fn run_sync_job(state: &AppState) -> Result<serde_json::Value> {
    // Phase 14.1e.2 — the sync flow now writes to IntelStore for every
    // intel-wide table (sync_log, vulnerabilities, malware_reports);
    // Store stays in the call only for `watched_packages()`, a
    // project-wide read that migrates with the project layer in 14.2.
    let mut intel = state.intel.lock().await;
    let mut store = state.store.lock().await;
    let report = sync_intel::run(&mut intel, &mut store).await?;
    Ok(serde_json::to_value(report)?)
}

pub fn to_view(stored: packguard_store::StoredJob) -> JobView {
    let kind = match stored.kind.as_str() {
        "scan" => JobKind::Scan,
        "add_project" => JobKind::AddProject,
        _ => JobKind::Sync,
    };
    let status =
        crate::dto::JobStatus::parse(&stored.status).unwrap_or(crate::dto::JobStatus::Pending);
    let result = stored
        .result_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    JobView {
        id: stored.id,
        kind,
        status,
        started_at: stored.started_at,
        finished_at: stored.finished_at,
        result,
        error: stored.error,
    }
}
