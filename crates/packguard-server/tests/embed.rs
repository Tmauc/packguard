//! Only compiled when the `ui-embed` feature is on — verifies the router
//! hands back the embedded Vite bundle for `/` and SPA routes, and still
//! exposes the JSON API under `/api/*`.

#![cfg(feature = "ui-embed")]

use packguard_server::{router, ServerConfig};
use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry, Store};
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_harness() -> String {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("store.db")).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let repo = temp.path().to_path_buf();
    let app = router(ServerConfig {
        repo_path: repo,
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
        // `temp` is moved into this task so the store file stays alive for
        // the duration of the test.
        drop(temp);
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn root_serves_the_embedded_index_html() {
    let base = spawn_harness().await;
    let resp = reqwest::get(&base).await.unwrap();
    assert!(resp.status().is_success());
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/html"));
    let body = resp.text().await.unwrap();
    assert!(body.contains("<div id=\"root\">"));
}

#[tokio::test]
async fn deep_links_fall_back_to_index_html_for_spa_routing() {
    let base = spawn_harness().await;
    let resp = reqwest::get(format!("{base}/packages/npm/lodash"))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("<div id=\"root\">"));
}

#[tokio::test]
async fn api_routes_are_not_shadowed_by_the_spa_fallback() {
    let base = spawn_harness().await;
    let resp = reqwest::get(format!("{base}/api/health")).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["ok"], true);
}
