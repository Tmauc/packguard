//! Phase 14.1e.1 — verify the boot-time plumbing without exercising
//! any consumer code path. AppState gains `intel` + `projects`; the
//! existing handlers are unchanged. These tests confirm:
//!
//!   1. AppState carries IntelStore + ProjectsRegistry alongside the
//!      legacy Store.
//!   2. Both new fields are independently lockable from handlers (no
//!      cross-locking, no panics).
//!   3. The plumbing keeps the existing Store handlers intact.

use packguard_server::{router, AppState, ServerConfig};
use packguard_store::{IntelStore, ProjectsRegistry, Store};
use tempfile::TempDir;
use tokio::net::TcpListener;

#[tokio::test]
async fn server_router_accepts_intel_and_projects_in_server_config() {
    // Smoke test for the new ServerConfig shape — if the wiring
    // breaks, the router won't construct.
    let temp = TempDir::new().unwrap();
    let store = Store::open(&temp.path().join("store.db")).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let app = router(ServerConfig {
        repo_path: temp.path().to_path_buf(),
        store,
        intel,
        projects,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Hit /api/health to prove the router booted with the new state.
    let url = format!("http://{addr}/api/health");
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn app_state_intel_and_projects_are_independently_lockable() {
    let temp = TempDir::new().unwrap();
    let store = Store::open(&temp.path().join("store.db")).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let state = AppState::new(store, intel, projects, temp.path().to_path_buf());

    // Both new fields are Mutex-wrapped and independently lockable —
    // no deadlock between them, and locking one doesn't observe the
    // other. The existing Store mutex is unaffected.
    let _ = state.store.lock().await;
    let intel_guard = state.intel.lock().await;
    let projects_guard = state.projects.lock().await;
    assert_eq!(intel_guard.count_vulnerabilities().unwrap(), 0);
    assert_eq!(projects_guard.list_projects().unwrap().len(), 0);
}
