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
}

impl JobSpec {
    fn dto(&self) -> JobKind {
        match self {
            JobSpec::Scan(_) => JobKind::Scan,
            JobSpec::Sync => JobKind::Sync,
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

async fn run_scan_job(state: &AppState, repo: PathBuf) -> Result<serde_json::Value> {
    let mut store = state.store.lock().await;
    let report = scan::run(&mut store, &repo).await?;
    Ok(serde_json::to_value(report)?)
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
