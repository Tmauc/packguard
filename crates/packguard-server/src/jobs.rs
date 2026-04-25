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
///
/// 14.2d.2 — the `jobs` table moved from the per-project `Store` to
/// `IntelStore` so the legacy `<home>/store.db` could be retired.
/// The schema + state machine are unchanged; only the backing handle
/// shifted.
pub async fn spawn(state: AppState, spec: JobSpec) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    {
        let mut intel = state.intel.lock().await;
        intel.create_job(&id, spec.dto().as_str())?;
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
        let mut intel = state.intel.lock().await;
        let _ = intel.update_job_status(&id, "running", None, None);
    }

    let outcome: Result<serde_json::Value> = match spec {
        JobSpec::Scan(target) => {
            let repo = target.unwrap_or_else(|| state.repo_path.clone());
            run_scan_job(&state, repo).await
        }
        JobSpec::Sync => run_sync_job(&state).await,
        JobSpec::AddProject(path) => run_add_project_job(&state, path).await,
    };

    let mut intel = state.intel.lock().await;
    match outcome {
        Ok(payload) => {
            let json = serde_json::to_string(&payload).unwrap_or_else(|_| "null".into());
            let _ = intel.update_job_status(&id, "succeeded", Some(&json), None);
        }
        Err(err) => {
            let msg = format!("{err:#}");
            let _ = intel.update_job_status(&id, "failed", None, Some(&msg));
        }
    }
}

/// Phase 14.2b.2.3 — per-project store only. The legacy global
/// `Store` is no longer written to by the scan path; the legacy file
/// becomes a frozen migration snapshot until 14.2d retires it.
///
/// Slug resolution: walk up from `repo` to find the project root.
/// On miss, fall back to `_default_` (matches the 14.1d migration's
/// fallback for paths outside any `.git/` tree). Auto-create
/// `_default_` if even that's missing so the per-project layer
/// always has a destination — the dashboard's aggregate read
/// requires `slug_paths()` to be non-empty, and `packguard scan`
/// from a fresh install is the canonical way to seed it.
async fn run_scan_job(state: &AppState, repo: PathBuf) -> Result<serde_json::Value> {
    let slug = {
        let mut registry = state.projects.lock().await;
        let resolved = registry
            .get_by_path(&repo)
            .ok()
            .flatten()
            .or_else(|| registry.get_by_slug("_default_").ok().flatten());
        match resolved {
            Some(p) => p.slug,
            None => {
                registry
                    .insert_with_slug("_default_", &repo, "_default_")?
                    .slug
            }
        }
    };
    let pstore = state.project_stores.get_or_open(&slug).await?;
    let mut pstore = pstore.lock().await;
    let report = scan::run(&mut pstore, &repo).await?;
    Ok(serde_json::to_value(report)?)
}

/// Phase 14.1f / 14.2b.2 — register the project in the registry,
/// run a scan against its root (writes only to the per-project store
/// post-bascule), then bump `last_scan`. The per-project store is
/// created on first `get_or_open` inside `run_scan_job` since the
/// registry insert already commits the slug.
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
    // Phase 14.2b.2.4 — sync no longer locks the legacy `Store`.
    // `watched_packages` reads union across every per-project store
    // via `ProjectStoreCache::slug_paths`; intel writes still flow
    // into [`IntelStore`].
    let mut intel = state.intel.lock().await;
    let report = sync_intel::run(&mut intel, &state.project_stores).await?;
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
