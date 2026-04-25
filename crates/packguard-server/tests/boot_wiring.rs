//! Phase 14.1e.1 / 14.2d.3 — verify the boot-time plumbing without
//! exercising any consumer code path. After 14.2d, `AppState` carries
//! `intel` + `projects` + `project_stores` only; the legacy global
//! `Store` is gone. These tests confirm:
//!
//!   1. The router constructs from the post-14.2d `ServerConfig`.
//!   2. `intel` and `projects` are independently lockable from handlers
//!      (no cross-locking, no panics).

use packguard_server::{router, AppState, ServerConfig};
use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

#[tokio::test]
async fn server_router_accepts_intel_and_projects_in_server_config() {
    let temp = TempDir::new().unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: temp.path().to_path_buf(),
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://{addr}/api/health");
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn app_state_intel_and_projects_are_independently_lockable() {
    let temp = TempDir::new().unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let state = AppState::new(intel, projects, project_stores, temp.path().to_path_buf());

    // 14.2d — the only handles left in `AppState` are intel + projects
    // (+ project_stores). Both Mutex-wrapped fields lock independently;
    // no deadlock between them.
    let intel_guard = state.intel.lock().await;
    let projects_guard = state.projects.lock().await;
    assert_eq!(intel_guard.count_vulnerabilities().unwrap(), 0);
    assert_eq!(projects_guard.list_projects().unwrap().len(), 0);
}
