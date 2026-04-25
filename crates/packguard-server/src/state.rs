//! Shared application state. The store is wrapped in a `Mutex` because
//! `rusqlite::Connection` is not `Sync` — for a local desktop dashboard
//! this is fine (single-digit concurrent requests). When the `serve` mode
//! lands in v2 we'll switch to a connection pool.
//!
//! `repo_path` is the project root that scan operations will target.
//! Defaults to the cwd at server start; the CLI override flows through
//! `ServerConfig`.

use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry, Store};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    /// Legacy global `~/.packguard/store.db`. After the 14.2b bascule
    /// the runtime still falls back here for the `?project=<path>` and
    /// aggregate reads (the slug form alone routes through
    /// [`Self::project_stores`]). The legacy handle stays in
    /// `AppState` for three reasons:
    /// 1. The global `jobs` table still lives here (cross-project
    ///    state) — `jobs.rs` keeps using it for `create_job` and
    ///    `update_job_status`.
    /// 2. Path scope + aggregate reads still hit it; the smoke
    ///    contract requires aggregate parity through the transition.
    /// 3. The CLI's project-layer commands haven't been bascule'd
    ///    yet (14.2c). The legacy file remains the source of truth
    ///    for `packguard report/audit/scan` until that lands.
    ///
    /// 14.2d retires this field once both consumers are migrated.
    pub store: Arc<Mutex<Store>>,
    /// Cross-project intel catalog (`~/.packguard/intel/intel.db`).
    /// 14.1e detached every intel-wide read/write here.
    pub intel: Arc<Mutex<IntelStore>>,
    /// Projects registry (`~/.packguard/projects.db`). Populated by
    /// the 14.1d migration and the 14.1f `POST /api/projects` handler.
    pub projects: Arc<Mutex<ProjectsRegistry>>,
    /// Per-project SQLite handles, keyed by slug. 14.2a scaffolded
    /// the cache; 14.2b is the runtime bascule that wires it into the
    /// HTTP read handlers + scan/add-project job runners.
    pub project_stores: Arc<ProjectStoreCache>,
    pub repo_path: PathBuf,
}

impl AppState {
    pub fn new(
        store: Store,
        intel: IntelStore,
        projects: ProjectsRegistry,
        project_stores: Arc<ProjectStoreCache>,
        repo_path: PathBuf,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            intel: Arc::new(Mutex::new(intel)),
            projects: Arc::new(Mutex::new(projects)),
            project_stores,
            repo_path,
        }
    }
}
