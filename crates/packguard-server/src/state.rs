//! Shared application state. The store is wrapped in a `Mutex` because
//! `rusqlite::Connection` is not `Sync` — for a local desktop dashboard
//! this is fine (single-digit concurrent requests). When the `serve` mode
//! lands in v2 we'll switch to a connection pool.
//!
//! `repo_path` is the project root that scan operations will target.
//! Defaults to the cwd at server start; the CLI override flows through
//! `ServerConfig`.

use packguard_store::Store;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub repo_path: PathBuf,
}

impl AppState {
    pub fn new(store: Store, repo_path: PathBuf) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            repo_path,
        }
    }
}
