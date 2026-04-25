//! Shared application state. The store is wrapped in a `Mutex` because
//! `rusqlite::Connection` is not `Sync` — for a local desktop dashboard
//! this is fine (single-digit concurrent requests). When the `serve` mode
//! lands in v2 we'll switch to a connection pool.
//!
//! `repo_path` is the project root that scan operations will target.
//! Defaults to the cwd at server start; the CLI override flows through
//! `ServerConfig`.

use packguard_store::{IntelStore, ProjectsRegistry, Store};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    /// Per-project store (legacy `~/.packguard/store.db` for now). Holds
    /// repos / workspaces / packages / dependencies / scan_history /
    /// action_dismissals — everything keyed to a specific project.
    pub store: Arc<Mutex<Store>>,
    /// Cross-project intel catalog (`~/.packguard/intel/intel.db`).
    /// Phase 14.1e.1 wires it into AppState but no handler reads from
    /// it yet — sync still writes to `Store`, audit still reads from
    /// `Store`. The cutover lands in 14.1e.2 (producers) and 14.1e.3
    /// (consumers).
    pub intel: Arc<Mutex<IntelStore>>,
    /// Projects registry (`~/.packguard/projects.db`). Populated by
    /// the 14.1d migration; consumed by the upcoming `/api/projects`
    /// endpoints in 14.1f. Held in AppState now so the boot path is
    /// identical to its eventual production shape.
    pub projects: Arc<Mutex<ProjectsRegistry>>,
    pub repo_path: PathBuf,
}

impl AppState {
    pub fn new(
        store: Store,
        intel: IntelStore,
        projects: ProjectsRegistry,
        repo_path: PathBuf,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            intel: Arc::new(Mutex::new(intel)),
            projects: Arc::new(Mutex::new(projects)),
            repo_path,
        }
    }
}
