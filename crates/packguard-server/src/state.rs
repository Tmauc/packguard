//! Shared application state. The handles are wrapped in tokio
//! `Mutex`es because `rusqlite::Connection` is not `Sync` — for a local
//! desktop dashboard this is fine (single-digit concurrent requests).
//! When the `serve` mode lands in v2 we'll switch to a connection pool.
//!
//! `repo_path` is the project root the aggregate read handlers fall
//! back to when no `?project=…` is supplied. Defaults to the cwd at
//! server start; the CLI override flows through `ServerConfig`.

use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    /// Cross-project intel catalog (`~/.packguard/intel/intel.db`).
    /// Holds advisories, malware reports, sync state — and since
    /// 14.2d.2, the global `jobs` table that backs the dashboard's
    /// async Scan / Sync / AddProject buttons.
    pub intel: Arc<Mutex<IntelStore>>,
    /// Projects registry (`~/.packguard/projects.db`). Populated by
    /// the 14.1d migration and the 14.1f `POST /api/projects` handler.
    pub projects: Arc<Mutex<ProjectsRegistry>>,
    /// Per-project SQLite handles, keyed by slug. Every read/write
    /// that depends on scan data goes through this cache.
    pub project_stores: Arc<ProjectStoreCache>,
    /// Aggregate fallback root — the path the policy / repo handlers
    /// reach for when the request omits `?project=…`. Set by the CLI
    /// to the cwd it booted in.
    pub repo_path: PathBuf,
}

impl AppState {
    pub fn new(
        intel: IntelStore,
        projects: ProjectsRegistry,
        project_stores: Arc<ProjectStoreCache>,
        repo_path: PathBuf,
    ) -> Self {
        Self {
            intel: Arc::new(Mutex::new(intel)),
            projects: Arc::new(Mutex::new(projects)),
            project_stores,
            repo_path,
        }
    }
}
