//! Integration tests for the REST API. Spawns the axum router on a random
//! port, seeds the in-memory store via the same library APIs the CLI uses,
//! and exercises every endpoint.

use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency,
    DependencyEdge, MalwareKind, MalwareReport, Project, RemotePackage, Severity, Vulnerability,
};
use packguard_server::{router, ServerConfig};
use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry, Store};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

struct Harness {
    base: String,
    _temp: tempfile::TempDir,
}

async fn spawn(setup: impl FnOnce(&mut Store, &mut IntelStore, &Path)) -> Harness {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let mut store = Store::open(&store_path).unwrap();
    let mut intel = IntelStore::open(temp.path()).unwrap();
    setup(&mut store, &mut intel, &repo_path);
    drop(store);

    // Phase 14.2b — run the 14.1d migration so the per-project store
    // gets the same data the closure just seeded into the legacy
    // store. Slug ends up as `_default_` for fixtures without a
    // `.git/` ancestor, which is what the smoke surface expects.
    // Skipped (no-op) when the closure didn't seed anything.
    packguard_store::migration::migrate_legacy_if_present(temp.path()).unwrap();

    let store = Store::open(&store_path).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Harness {
        base: format!("http://{addr}"),
        _temp: temp,
    }
}

async fn get_json(harness: &Harness, path: &str) -> serde_json::Value {
    let url = format!("{}{}", harness.base, path);
    reqwest::get(&url).await.unwrap().json().await.unwrap()
}

async fn post_json(harness: &Harness, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let url = format!("{}{}", harness.base, path);
    let resp = reqwest::Client::new().post(&url).send().await.unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn seed_lodash_with_high_cve(store: &mut Store, intel: &mut IntelStore, repo: &Path) {
    let project = Project {
        ecosystem: "npm",
        root: repo.to_path_buf(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![
            Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            },
            Dependency {
                name: "react".into(),
                declared_range: "^18.0.0".into(),
                installed: Some("18.3.1".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            },
        ],
        edges: Vec::new(),
        compatibility: Vec::new(),
    };
    let mut remotes = BTreeMap::new();
    remotes.insert(
        "lodash".into(),
        RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: Some("2024-06-01T00:00:00Z".into()),
            versions: vec![],
        },
    );
    remotes.insert(
        "react".into(),
        RemotePackage {
            name: "react".into(),
            latest: Some("19.0.0".into()),
            latest_published_at: Some("2024-12-01T00:00:00Z".into()),
            versions: vec![],
        },
    );
    store
        .save_project(repo, &project, &remotes, "fp-test")
        .unwrap();

    let vuln = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-test".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec!["CVE-2021-23337".into()],
        summary: Some("Command Injection in lodash".into()),
        url: Some("https://example/CVE-2021-23337".into()),
        affected: AffectedSpec {
            ranges: vec![AffectedRange {
                kind: AffectedRangeKind::Semver,
                events: vec![
                    AffectedEvent::Introduced("0.0.0".into()),
                    AffectedEvent::Fixed("4.17.21".into()),
                ],
            }],
            versions: vec![],
        },
        fixed_versions: vec!["4.17.21".into()],
        published_at: Some("2021-02-15T00:00:00Z".into()),
        modified_at: None,
    };
    intel
        .persist_vulnerabilities(std::slice::from_ref(&vuln))
        .unwrap();

    let malware = MalwareReport {
        source: "osv-mal".into(),
        ref_id: "MAL-2024-42".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        version: "9.9.9".into(), // a version Nalo isn't running
        kind: MalwareKind::Malware,
        summary: Some("Demo malicious release".into()),
        url: None,
        evidence: serde_json::json!({"id": "MAL-2024-42"}),
        reported_at: None,
    };
    intel
        .persist_malware_reports(std::slice::from_ref(&malware))
        .unwrap();
}

// ---------- /api/health -----------------------------------------------------

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/health").await;
    assert_eq!(body, serde_json::json!({ "ok": true }));
}

// ---------- /api/overview --------------------------------------------------

#[tokio::test]
async fn overview_with_empty_store_returns_zeroed_payload() {
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/overview").await;
    assert_eq!(body["packages_total"], 0);
    assert!(body["health_score"].is_null());
}

#[tokio::test]
async fn overview_with_seeded_store_aggregates_correctly() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/overview").await;
    assert_eq!(body["packages_total"], 2);
    assert_eq!(body["vulnerabilities"]["high"], 1);
    // Conservative defaults block high CVE → lodash counts as a violation.
    assert!(body["compliance"]["violations"].as_u64().unwrap() >= 1);
    let top = body["top_risks"].as_array().unwrap();
    assert!(!top.is_empty());
    assert_eq!(top[0]["name"], "lodash");
}

// ---------- /api/packages ---------------------------------------------------

#[tokio::test]
async fn packages_list_returns_paginated_rows() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages").await;
    assert_eq!(body["total"], 2);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn packages_list_filters_by_ecosystem() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages?ecosystem=pypi").await;
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn packages_list_filters_by_status() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages?status=cve-violation").await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["rows"][0]["name"], "lodash");
}

#[tokio::test]
async fn packages_list_search_query_filters_by_name() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages?q=react").await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["rows"][0]["name"], "react");
}

#[tokio::test]
async fn packages_list_pagination_clamps_per_page() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages?per_page=1&page=2").await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["page"], 2);
    assert_eq!(body["per_page"], 1);
    assert_eq!(body["rows"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn package_detail_returns_versions() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages/npm/lodash").await;
    assert_eq!(body["name"], "lodash");
    assert_eq!(body["installed"], "4.17.20");
    assert!(body["versions"].is_array());
}

#[tokio::test]
async fn package_detail_exposes_vulnerabilities_for_installed_version() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages/npm/lodash").await;
    let vulns = body["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["cve_id"], "CVE-2021-23337");
    assert_eq!(vulns[0]["severity"], "high");
    assert_eq!(vulns[0]["affects_installed"], true);
    let fixed = vulns[0]["fixed_versions"].as_array().unwrap();
    assert_eq!(fixed[0], "4.17.21");
}

#[tokio::test]
async fn package_detail_exposes_malware_even_when_version_is_different() {
    let h = spawn(seed_lodash_with_high_cve).await;
    // The malware record targets 9.9.9 but the detail tab still surfaces it
    // so users can see the historical record for the package.
    let body = get_json(&h, "/api/packages/npm/lodash").await;
    let mw = body["malware"].as_array().unwrap();
    assert_eq!(mw.len(), 1);
    assert_eq!(mw[0]["ref_id"], "MAL-2024-42");
    assert_eq!(mw[0]["kind"], "malware");
}

#[tokio::test]
async fn package_detail_policy_trace_recommends_a_safe_upgrade() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/packages/npm/lodash").await;
    // Installed (4.17.20) is affected; 4.17.21 is the only fix we seeded and
    // the registry didn't publish it, so policy recommends `None`. We still
    // want the reason string to mention the CVE so users know why.
    let trace = &body["policy_trace"];
    // Phase 9b — offset is a three-axis object.
    let offset = &trace["offset"];
    assert!(offset.is_object(), "expected offset object: {offset}");
    assert!(offset["major"].is_number());
    assert!(offset["minor"].is_number());
    assert!(offset["patch"].is_number());
    assert_eq!(trace["stability"], "stable");
    // Cascade lines surface the resolver's decision for the UI.
    assert!(
        trace["cascade"].is_array(),
        "cascade must be an array: {}",
        trace["cascade"]
    );
    let reason = trace["reason"].as_str().unwrap();
    assert!(
        reason.contains("CVE") || reason.contains("blocked") || reason.contains("candidate"),
        "unexpected trace reason: {reason}"
    );
}

#[tokio::test]
async fn package_detail_version_rows_carry_severity_when_affected() {
    // Seed a package whose registry advertises both an affected and a fixed
    // version; confirm the severity field lines up with the matcher.
    let h = spawn(|store, intel, repo| {
        let project = Project {
            ecosystem: "npm",
            root: repo.to_path_buf(),
            manifest_path: repo.join("package.json"),
            name: Some("demo".into()),
            workspace: None,
            dependencies: vec![Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            }],
            edges: Vec::new(),
            compatibility: Vec::new(),
        };
        let remote = RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: Some("2024-06-01T00:00:00Z".into()),
            versions: vec![
                packguard_core::RemoteVersion {
                    version: "4.17.20".into(),
                    published_at: Some("2024-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
                packguard_core::RemoteVersion {
                    version: "4.17.21".into(),
                    published_at: Some("2024-06-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
            ],
        };
        let mut remotes = BTreeMap::new();
        remotes.insert("lodash".into(), remote);
        store.save_project(repo, &project, &remotes, "fp").unwrap();

        let vuln = Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-test".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            severity: Severity::High,
            cve_id: Some("CVE-2021-23337".into()),
            aliases: vec![],
            summary: None,
            url: None,
            affected: AffectedSpec {
                ranges: vec![AffectedRange {
                    kind: AffectedRangeKind::Semver,
                    events: vec![
                        AffectedEvent::Introduced("0.0.0".into()),
                        AffectedEvent::Fixed("4.17.21".into()),
                    ],
                }],
                versions: vec![],
            },
            fixed_versions: vec!["4.17.21".into()],
            published_at: None,
            modified_at: None,
        };
        intel
            .persist_vulnerabilities(std::slice::from_ref(&vuln))
            .unwrap();
    })
    .await;
    let body = get_json(&h, "/api/packages/npm/lodash").await;
    let versions = body["versions"].as_array().unwrap();
    let find = |v: &str| {
        versions
            .iter()
            .find(|r| r["version"] == v)
            .unwrap_or_else(|| panic!("version {v} missing from response"))
            .clone()
    };
    assert_eq!(find("4.17.20")["severity"], "high");
    assert!(find("4.17.21")["severity"].is_null());
}

#[tokio::test]
async fn package_detail_unknown_returns_404() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let url = format!("{}/api/packages/npm/never-heard-of", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");
}

// ---------- /api/policies ---------------------------------------------------

#[tokio::test]
async fn policies_returns_conservative_defaults_when_no_file() {
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/policies").await;
    assert_eq!(body["from_file"], false);
    let yaml = body["yaml"].as_str().unwrap();
    assert!(yaml.contains("offset:"));
}

#[tokio::test]
async fn policies_returns_repo_file_when_present() {
    let h = spawn(|_, _, repo| {
        std::fs::write(
            repo.join(".packguard.yml"),
            "defaults:\n  offset: { major: 0 }\n",
        )
        .unwrap();
    })
    .await;
    let body = get_json(&h, "/api/policies").await;
    assert_eq!(body["from_file"], true);
    assert!(body["yaml"].as_str().unwrap().contains("major: 0"));
}

// ---------- /api/policies/dry-run + PUT /api/policies -----------------------

async fn put_json(
    harness: &Harness,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let url = format!("{}{}", harness.base, path);
    let resp = reqwest::Client::new()
        .put(&url)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn post_json_body(
    harness: &Harness,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let url = format!("{}{}", harness.base, path);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn policies_dry_run_returns_counts_against_current_and_candidate() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let candidate =
        "defaults:\n  offset: { major: 0 }\n  block:\n    cve_severity: [critical, high]\n";
    let (status, body) = post_json_body(
        &h,
        "/api/policies/dry-run",
        serde_json::json!({ "yaml": candidate }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(body["candidate"]["violations"].as_u64().unwrap() >= 1);
    assert!(body["current"]["violations"].as_u64().unwrap() >= 1);
    // `changed_packages` may be empty — both policies block the high CVE —
    // but the field must be present so the UI can render "no deltas".
    assert!(body["changed_packages"].is_array());
}

#[tokio::test]
async fn policies_dry_run_surfaces_compliance_delta_when_policy_relaxes() {
    let h = spawn(seed_lodash_with_high_cve).await;
    // Candidate policy removes the CVE block → lodash flips from violation to
    // whatever the non-CVE evaluation returns (warning, most likely).
    let candidate = "defaults:\n  offset: { major: 0 }\n  block: {}\n";
    let (_, body) = post_json_body(
        &h,
        "/api/policies/dry-run",
        serde_json::json!({ "yaml": candidate }),
    )
    .await;
    let changed = body["changed_packages"].as_array().unwrap();
    let lodash = changed
        .iter()
        .find(|c| c["name"] == "lodash")
        .expect("lodash should flip category when CVE block is removed");
    assert_eq!(lodash["from"], "cve-violation");
}

#[tokio::test]
async fn policies_dry_run_rejects_bad_yaml_with_line_info() {
    let h = spawn(|_, _, _| {}).await;
    let (status, body) = post_json_body(
        &h,
        "/api/policies/dry-run",
        // Missing close-brace → YAML parse error with line info.
        serde_json::json!({
            "yaml": "defaults:\n  offset: { major: -1\n  stability: stable\n"
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "bad_request");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("line") || msg.contains("YAML"),
        "error should mention a line or the YAML tag: {msg}"
    );
}

#[tokio::test]
async fn policies_put_writes_the_file_and_returns_the_new_document() {
    let h = spawn(|_, _, _| {}).await;
    let yaml = "defaults:\n  offset: { major: 0 }\n  min_age_days: 3\n";
    let (status, body) = put_json(&h, "/api/policies", serde_json::json!({ "yaml": yaml })).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["from_file"], true);
    assert!(body["yaml"].as_str().unwrap().contains("min_age_days: 3"));
    // Reading it back should now return the same content with from_file=true.
    let fresh = get_json(&h, "/api/policies").await;
    assert_eq!(fresh["from_file"], true);
    assert!(fresh["yaml"].as_str().unwrap().contains("min_age_days: 3"));
}

#[tokio::test]
async fn policies_put_rejects_invalid_yaml_without_clobbering_disk() {
    let h = spawn(|_, _, repo| {
        std::fs::write(
            repo.join(".packguard.yml"),
            "defaults:\n  offset: { major: 0 }\n",
        )
        .unwrap();
    })
    .await;
    let (status, _) = put_json(
        &h,
        "/api/policies",
        serde_json::json!({ "yaml": "defaults: not_an_object\n" }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    // Existing file must still be there.
    let fresh = get_json(&h, "/api/policies").await;
    assert!(fresh["yaml"].as_str().unwrap().contains("major: 0"));
}

// ---------- /api/scan + /api/jobs ------------------------------------------

#[tokio::test]
async fn scan_returns_job_id_and_eventually_fails_when_no_manifest() {
    let h = spawn(|_, _, _| {}).await;
    let (status, body) = post_json(&h, "/api/scan").await;
    assert_eq!(status, reqwest::StatusCode::ACCEPTED);
    let id = body["id"].as_str().unwrap().to_string();
    let final_state = poll_job(&h, &id).await;
    // Empty repo → scan flow bails with "no supported manifest".
    assert_eq!(final_state["status"], "failed");
    let err = final_state["error"].as_str().unwrap();
    assert!(err.contains("no supported manifest"));
    // Finding #5 + #1: honest guidance when the user triggered Scan on a
    // fresh store with no registered repos.
    assert!(
        err.contains("packguard scan"),
        "error should suggest the CLI fallback: {err}"
    );
}

/// Polish-4 regression: the Scan button used to run against the single
/// `ServerConfig.repo_path` — the CWD the server was launched in, which
/// often had no manifest. Now it walks `store.distinct_repo_paths()`
/// instead. Here we seed the store with a repo, trigger /api/scan, and
/// assert the job picks up *that* repo rather than the server's CWD
/// (which is just a scratch tempdir with no package.json).
#[tokio::test]
async fn scan_walks_every_registered_repo_not_just_server_cwd() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let server_cwd = temp.path().join("cwd");
    std::fs::create_dir_all(&server_cwd).unwrap();
    let scanned_repo = temp.path().join("nalo_like_repo");
    std::fs::create_dir_all(&scanned_repo).unwrap();
    std::fs::write(
        scanned_repo.join("package.json"),
        r#"{"name":"demo","dependencies":{"lodash":"^4.17.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        scanned_repo.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();

    // Seed a record for scanned_repo so `distinct_repo_paths()` includes it.
    {
        let mut store = Store::open(&store_path).unwrap();
        let project = Project {
            ecosystem: "npm",
            root: scanned_repo.clone(),
            manifest_path: scanned_repo.join("package.json"),
            name: Some("demo".into()),
            workspace: None,
            dependencies: vec![Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            }],
            edges: Vec::new(),
            compatibility: Vec::new(),
        };
        store
            .save_project(&scanned_repo, &project, &BTreeMap::new(), "fp-initial")
            .unwrap();
    }

    // 14.2b.2.3 — scan now writes to the per-project store only.
    // Migrate the legacy seed so `_default_` gets `scanned_repo` in
    // its `repos` table; otherwise `scan::run` on a fresh per-
    // project store falls back to the server_cwd repo_root and 404s
    // on the missing manifest.
    packguard_store::migration::migrate_legacy_if_present(temp.path()).unwrap();

    // Start the server pointed at the *scratch* server_cwd (no manifest).
    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: server_cwd.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    // Trigger /api/scan — offline-ish (network failures don't kill the job).
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/scan"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let job_id = body["id"].as_str().unwrap().to_string();

    // Poll until done. The scan must succeed (even if network fails for
    // registry queries, the manifest parse + save_project path is fine).
    let mut final_state = serde_json::Value::Null;
    for _ in 0..60 {
        let got: serde_json::Value = reqwest::get(format!("{base}/api/jobs/{job_id}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if matches!(got["status"].as_str(), Some("succeeded") | Some("failed")) {
            final_state = got;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        final_state["status"], "succeeded",
        "Scan should walk registered repos rather than bail on the server CWD: {final_state}",
    );
    assert!(
        final_state["result"]["projects_scanned"].as_u64().unwrap() >= 1,
        "at least one registered repo should have been scanned",
    );
}

#[tokio::test]
async fn job_unknown_returns_404() {
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/jobs/00000000-0000-0000-0000-000000000000", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---------- Phase 13.6: /api/scan?path=<abs> -------------------------------

#[tokio::test]
async fn scan_with_custom_path_returns_job_id_and_scans_that_path() {
    // The harness's default repo has no manifest. For this test we drop a
    // manifest into a *sibling* tempdir and hand it to /api/scan via the
    // new ?path= query. The job should accept it and — crucially — scan
    // that path rather than the server's configured repo_path.
    let alt = tempfile::tempdir().unwrap();
    std::fs::write(
        alt.path().join("package.json"),
        r#"{"name":"from-ui","dependencies":{"lodash":"^4.17.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        alt.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();

    let h = spawn(|_, _, _| {}).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/scan", h.base))
        .query(&[("path", alt.path().to_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    let final_state = poll_job(&h, &id).await;
    assert_eq!(
        final_state["status"], "succeeded",
        "custom-path scan should succeed: {final_state}"
    );
    // The new workspace row is now visible in /api/workspaces — which is
    // exactly what the dashboard relies on for the auto-switch-scope
    // hand-off after the modal submit.
    let workspaces = get_json(&h, "/api/workspaces").await;
    let paths: Vec<&str> = workspaces["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["path"].as_str())
        .collect();
    let canonical = alt.path().canonicalize().unwrap();
    assert!(
        paths.iter().any(|p| *p == canonical.to_str().unwrap()),
        "expected {} in {:?}",
        canonical.display(),
        paths
    );
}

#[tokio::test]
async fn scan_with_nonexistent_path_returns_400() {
    let h = spawn(|_, _, _| {}).await;
    // Use a path we know doesn't exist. Whatever tempdir randomness
    // there is, /tmp/packguard-dne-<uuid> won't collide.
    let phantom = format!("/tmp/packguard-dne-{}", uuid::Uuid::new_v4());
    let resp = reqwest::Client::new()
        .post(format!("{}/api/scan", h.base))
        .query(&[("path", phantom.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("does not exist"),
        "expected 'does not exist' in message, got: {msg}"
    );
    assert!(
        msg.contains(&phantom),
        "message should echo the bad path: {msg}"
    );
}

#[tokio::test]
async fn scan_with_file_path_returns_400() {
    // Canonicalizable path but it's a file, not a directory — scan
    // wants a repo root.
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("not-a-dir.txt");
    std::fs::write(&file_path, "hi").unwrap();

    let h = spawn(|_, _, _| {}).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/scan", h.base))
        .query(&[("path", file_path.to_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("not a directory"),
        "expected 'not a directory' in message, got: {msg}"
    );
}

async fn poll_job(harness: &Harness, id: &str) -> serde_json::Value {
    for _ in 0..40 {
        let body = get_json(harness, &format!("/api/jobs/{id}")).await;
        let status = body["status"].as_str().unwrap_or("");
        if matches!(status, "succeeded" | "failed") {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish in time");
}

// ---------- Phase 5: /api/graph + contamination + compat -------------------

fn seed_react_chain_with_lodash_cve(store: &mut Store, intel: &mut IntelStore, repo: &Path) {
    // `demo` depends on react@18.2.0. react depends on loose-envify@1.4.0.
    // loose-envify depends on lodash@4.17.20 (to line up with the CVE below).
    let project = Project {
        ecosystem: "npm",
        root: repo.to_path_buf(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "react".into(),
            declared_range: "^18.2.0".into(),
            installed: Some("18.2.0".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("package-lock.json".into()),
        }],
        edges: vec![
            DependencyEdge {
                source_name: "react".into(),
                source_version: "18.2.0".into(),
                target_name: "loose-envify".into(),
                target_range: "^1.1.0".into(),
                resolved_target_version: Some("1.4.0".into()),
                kind: DepKind::Runtime,
            },
            DependencyEdge {
                source_name: "loose-envify".into(),
                source_version: "1.4.0".into(),
                target_name: "lodash".into(),
                target_range: "^4.17.0".into(),
                resolved_target_version: Some("4.17.20".into()),
                kind: DepKind::Runtime,
            },
            DependencyEdge {
                source_name: "react".into(),
                source_version: "18.2.0".into(),
                target_name: "scheduler".into(),
                target_range: "^0.23.0".into(),
                resolved_target_version: None,
                kind: DepKind::Peer,
            },
        ],
        compatibility: vec![packguard_core::CompatibilityInfo {
            package_name: "react".into(),
            version: "18.2.0".into(),
            engines: [("node".to_string(), ">=14".to_string())]
                .into_iter()
                .collect(),
            peer_deps: BTreeMap::new(),
        }],
    };
    let remotes: BTreeMap<String, RemotePackage> = [
        (
            "react".into(),
            RemotePackage {
                name: "react".into(),
                latest: Some("18.2.0".into()),
                latest_published_at: Some("2024-01-01T00:00:00Z".into()),
                versions: vec![],
            },
        ),
        (
            "loose-envify".into(),
            RemotePackage {
                name: "loose-envify".into(),
                latest: Some("1.4.0".into()),
                latest_published_at: None,
                versions: vec![],
            },
        ),
        (
            "lodash".into(),
            RemotePackage {
                name: "lodash".into(),
                latest: Some("4.17.21".into()),
                latest_published_at: None,
                versions: vec![packguard_core::RemoteVersion {
                    version: "4.17.20".into(),
                    published_at: Some("2024-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                }],
            },
        ),
    ]
    .into_iter()
    .collect();
    store.save_project(repo, &project, &remotes, "fp").unwrap();

    // Seed a high CVE on lodash@4.17.20 so contamination BFS has a real
    // target to chase.
    let vuln = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-lodash".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec![],
        summary: Some("Command injection".into()),
        url: Some("https://example/cve".into()),
        affected: AffectedSpec {
            ranges: vec![AffectedRange {
                kind: AffectedRangeKind::Semver,
                events: vec![
                    AffectedEvent::Introduced("0.0.0".into()),
                    AffectedEvent::Fixed("4.17.21".into()),
                ],
            }],
            versions: vec![],
        },
        fixed_versions: vec!["4.17.21".into()],
        published_at: None,
        modified_at: None,
    };
    intel
        .persist_vulnerabilities(std::slice::from_ref(&vuln))
        .unwrap();
}

/// Regression for the dogfood finding #6: seed the store with a *raw*
/// (non-canonical) path and start the server with the *canonical* form of
/// the same directory (what `packguard ui` stashes in
/// `ServerConfig.repo_path`). Without the path-normalization fix in
/// `packguard-store`, the SQL join on `repos.path` returns zero rows and
/// `/api/graph` ships `{nodes:[], edges:[]}`. With the fix, both forms
/// normalize to the same canonical string and the response matches what
/// `packguard_server::services::graph::build` would return on the same
/// store.
#[tokio::test]
async fn api_graph_matches_service_output_when_repo_path_is_non_canonical() {
    // `tempdir()` returns `/var/folders/...` on macOS, which canonicalizes
    // to `/private/var/folders/...`. We seed with the first form and spin
    // the server with the second form — the divergence that caused the
    // Nalo dogfood bug.
    let temp = tempfile::tempdir().unwrap();
    let raw_repo = temp.path().join("repo");
    std::fs::create_dir_all(&raw_repo).unwrap();
    let canonical_repo = raw_repo.canonicalize().unwrap();
    let store_path = temp.path().join("store.db");
    {
        let mut store = Store::open(&store_path).unwrap();
        let mut intel = IntelStore::open(temp.path()).unwrap();
        seed_react_chain_with_lodash_cve(&mut store, &mut intel, &raw_repo);
    }
    // Phase 14.2b.2 — migrate so the per-project store sees the
    // legacy seed; aggregate fanout reads it back out.
    packguard_store::migration::migrate_legacy_if_present(temp.path()).unwrap();

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: canonical_repo.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    let api_body: serde_json::Value = reqwest::get(format!("{base}/api/graph"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_nodes = api_body["nodes"].as_array().unwrap().len();
    let api_edges = api_body["edges"].as_array().unwrap().len();
    assert!(
        api_nodes > 0,
        "API returned empty graph — path canonicalization regressed: {api_body:#}"
    );

    // Symmetry contract: the CLI's `packguard graph --format json` goes
    // through the very same `services::graph::build` call. We invoke it
    // directly here (avoiding a child-process spawn + its own path-
    // canonicalize), with the canonical path — same data, same JSON.
    let fresh_store = Store::open(&store_path).unwrap();
    let fresh_intel = IntelStore::open(temp.path()).unwrap();
    let service_response = packguard_server::services::graph::build(
        &fresh_store,
        &fresh_intel,
        Some(&canonical_repo),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        api_nodes,
        service_response.nodes.len(),
        "API vs service node count diverged — CLI/UI symmetry broken",
    );
    assert_eq!(
        api_edges,
        service_response.edges.len(),
        "API vs service edge count diverged — CLI/UI symmetry broken",
    );
}

#[tokio::test]
async fn graph_endpoint_returns_nodes_and_resolved_edges() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/graph").await;
    let nodes = body["nodes"].as_array().unwrap();
    let names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"react"));
    assert!(names.contains(&"loose-envify"));
    assert!(names.contains(&"lodash"));

    // The root react node carries is_root=true; lodash deeper down does not.
    let react = nodes.iter().find(|n| n["name"] == "react").unwrap();
    assert_eq!(react["is_root"], true);
    let lodash = nodes.iter().find(|n| n["name"] == "lodash").unwrap();
    assert_eq!(lodash["is_root"], false);
    // lodash@4.17.20 carries the high severity we seeded.
    assert_eq!(lodash["cve_severity"], "high");

    // Unresolved peer dep: edge carries `unresolved=true` AND the response
    // now includes a placeholder node so Cytoscape never receives an edge
    // pointing at a missing target (Polish-bis-1).
    let edges = body["edges"].as_array().unwrap();
    let unresolved_edge = edges.iter().find(|e| e["unresolved"] == true).unwrap();
    assert_eq!(unresolved_edge["kind"], "peer");
    let tgt_id = unresolved_edge["target"].as_str().unwrap();
    let placeholder = nodes
        .iter()
        .find(|n| n["id"] == tgt_id)
        .expect("unresolved edge target must have a placeholder node");
    assert_eq!(placeholder["is_unresolved"], true);
    assert_eq!(placeholder["name"], "scheduler");
}

/// Polish-bis-1 regression: every edge in the response must have its
/// source AND target listed in `nodes[]`. Without this invariant, the
/// `/graph` page used to crash at mount because Cytoscape rejects edges
/// whose endpoints aren't registered as elements. The rule applies
/// regardless of kind filter, depth, or whether the edge is unresolved.
#[tokio::test]
async fn graph_response_is_closed_every_edge_references_existing_nodes() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    for query in &["/api/graph", "/api/graph?kind=runtime,dev,peer,optional"] {
        let body = get_json(&h, query).await;
        let node_ids: std::collections::HashSet<&str> = body["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        for e in body["edges"].as_array().unwrap() {
            let src = e["source"].as_str().unwrap();
            let tgt = e["target"].as_str().unwrap();
            assert!(
                node_ids.contains(src),
                "edge source {src} missing from nodes (query={query})",
            );
            assert!(
                node_ids.contains(tgt),
                "edge target {tgt} missing from nodes (query={query}) — \
                 this used to crash Cytoscape at mount",
            );
        }
    }
}

#[tokio::test]
async fn graph_endpoint_filters_by_kind() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/graph?kind=runtime").await;
    let edges = body["edges"].as_array().unwrap();
    // With `kind=runtime` the peer edge should be filtered out.
    assert!(edges.iter().all(|e| e["kind"] == "runtime"));
}

#[tokio::test]
async fn contamination_endpoint_returns_chain_to_root_and_caches_result() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/graph/contaminated?vuln_id=CVE-2021-23337").await;
    let hits = body["hits"].as_array().unwrap();
    assert!(hits.iter().any(|h| h["name"] == "lodash"));
    let chains = body["chains"].as_array().unwrap();
    assert!(!chains.is_empty());
    let path = chains[0]["path"].as_array().unwrap();
    let first = path[0].as_str().unwrap();
    let last = path.last().unwrap().as_str().unwrap();
    assert!(first.contains("react@18.2.0"));
    assert!(last.contains("lodash@4.17.20"));
    assert_eq!(body["from_cache"], false);

    // Second call must hit the cache.
    let again = get_json(&h, "/api/graph/contaminated?vuln_id=CVE-2021-23337").await;
    assert_eq!(again["from_cache"], true);
}

#[tokio::test]
async fn vulnerabilities_endpoint_lists_cves_hit_in_scope() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/graph/vulnerabilities").await;
    let entries = body["entries"].as_array().unwrap();
    // The seeded CVE must land in the list with its package, version and
    // severity — these are the fields the palette renders.
    let entry = entries
        .iter()
        .find(|e| e["cve_id"] == "CVE-2021-23337")
        .expect("seeded CVE missing from palette feed");
    assert_eq!(entry["package_name"], "lodash");
    assert_eq!(entry["package_version"], "4.17.20");
    assert_eq!(entry["severity"], "high");
    assert_eq!(entry["advisory_id"], "GHSA-lodash");
    // Packages with no matching advisory must not bleed in — react is
    // in the scan but clean, so it must not produce an entry.
    assert!(entries.iter().all(|e| e["package_name"] != "react"));
}

#[tokio::test]
async fn vulnerabilities_endpoint_returns_empty_when_store_is_empty() {
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/graph/vulnerabilities").await;
    assert!(body["entries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn contamination_endpoint_returns_empty_for_unknown_advisory() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/graph/contaminated?vuln_id=GHSA-never-seen").await;
    assert!(body["hits"].as_array().unwrap().is_empty());
    assert!(body["chains"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn compat_endpoint_exposes_engines_peer_deps_and_dependents() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/packages/npm/react/compat").await;
    assert_eq!(body["name"], "react");
    assert_eq!(body["installed"], "18.2.0");
    let rows = body["rows"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|r| r["version"] == "18.2.0" && r["engines"]["node"] == ">=14"));

    // Dependents of loose-envify should at least include react.
    let le = get_json(&h, "/api/packages/npm/loose-envify/compat").await;
    let deps = le["dependents"].as_array().unwrap();
    assert!(deps.iter().any(|d| d["name"] == "react"));
}

// ---------- Phase 7a: /api/workspaces + ?project= filtering ---------------

#[tokio::test]
async fn workspaces_endpoint_lists_registered_scans_sorted_by_last_scan_desc() {
    // Empty store → empty list, not an error.
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/workspaces").await;
    assert_eq!(body["workspaces"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn workspaces_endpoint_surfaces_every_scanned_repo() {
    let h = spawn(seed_react_chain_with_lodash_cve).await;
    let body = get_json(&h, "/api/workspaces").await;
    let rows = body["workspaces"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["ecosystem"], "npm");
    assert!(row["dependency_count"].as_u64().unwrap() >= 1);
    assert!(row["path"].as_str().unwrap().contains("repo"));
    assert!(!row["fingerprint"].as_str().unwrap().is_empty());
}

/// Spawn a harness with TWO independent workspaces in the same store so
/// we can verify Phase 7a isolation + the parity invariant
/// (scoped ⊆ unscoped) across overview, packages, graph, compat, and
/// policies. The fixture is deliberately generic — library names from
/// the common npm ecosystem, no product-specific hardcoding.
async fn spawn_two_workspaces() -> (Harness, String, String) {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_a_raw = temp.path().join("workspace_alpha");
    let repo_b_raw = temp.path().join("workspace_beta");
    std::fs::create_dir_all(&repo_a_raw).unwrap();
    std::fs::create_dir_all(&repo_b_raw).unwrap();
    let repo_a = repo_a_raw.canonicalize().unwrap();
    let repo_b = repo_b_raw.canonicalize().unwrap();

    {
        let mut store = Store::open(&store_path).unwrap();
        let project_a = Project {
            ecosystem: "npm",
            root: repo_a.clone(),
            manifest_path: repo_a.join("package.json"),
            name: Some("alpha".into()),
            workspace: None,
            dependencies: vec![Dependency {
                name: "lodash".into(),
                declared_range: "^4".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            }],
            edges: Vec::new(),
            compatibility: Vec::new(),
        };
        let project_b = Project {
            ecosystem: "npm",
            root: repo_b.clone(),
            manifest_path: repo_b.join("package.json"),
            name: Some("beta".into()),
            workspace: None,
            dependencies: vec![Dependency {
                name: "express".into(),
                declared_range: "^4".into(),
                installed: Some("4.19.2".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            }],
            edges: Vec::new(),
            compatibility: Vec::new(),
        };
        store
            .save_project(&repo_a, &project_a, &BTreeMap::new(), "fp-alpha")
            .unwrap();
        store
            .save_project(&repo_b, &project_b, &BTreeMap::new(), "fp-beta")
            .unwrap();
    }

    // Phase 14.2b.2 — run the 14.1d migration so the per-project
    // store gets the same data the closure just seeded into legacy.
    // Both alpha and beta paths land under `_default_` (no `.git/`
    // ancestor in the temp dir), with the workspace path filter
    // doing the alpha-vs-beta isolation post-fanout.
    packguard_store::migration::migrate_legacy_if_present(temp.path()).unwrap();

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: repo_a.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let harness = Harness {
        base: format!("http://{addr}"),
        _temp: temp,
    };
    (
        harness,
        repo_a.display().to_string(),
        repo_b.display().to_string(),
    )
}

#[tokio::test]
async fn overview_project_filter_isolates_workspaces_and_parity_holds() {
    let (h, alpha, beta) = spawn_two_workspaces().await;

    let all = get_json(&h, "/api/overview").await;
    let alpha_body = get_json(&h, &format!("/api/overview?project={alpha}")).await;
    let beta_body = get_json(&h, &format!("/api/overview?project={beta}")).await;

    // Parity: scoped ≤ unscoped, and since the fixtures are disjoint the
    // two workspace counts sum to the aggregate.
    let all_v = all["packages_total"].as_u64().unwrap();
    let a_v = alpha_body["packages_total"].as_u64().unwrap();
    let b_v = beta_body["packages_total"].as_u64().unwrap();
    assert!(a_v <= all_v, "alpha {a_v} > all {all_v}");
    assert!(b_v <= all_v, "beta {b_v} > all {all_v}");
    assert_eq!(a_v + b_v, all_v, "a+b must equal aggregate");
}

#[tokio::test]
async fn packages_project_filter_isolates_workspaces() {
    let (h, alpha, beta) = spawn_two_workspaces().await;

    let a = get_json(&h, &format!("/api/packages?project={alpha}")).await;
    let b = get_json(&h, &format!("/api/packages?project={beta}")).await;

    let a_names: Vec<&str> = a["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    let b_names: Vec<&str> = b["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();

    assert!(a_names.contains(&"lodash"));
    assert!(!a_names.contains(&"express"));
    assert!(b_names.contains(&"express"));
    assert!(!b_names.contains(&"lodash"));
}

// ---- Phase 12a: /api/actions ----------------------------------------------

#[tokio::test]
async fn actions_list_returns_cve_violation_for_lodash() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/actions").await;
    let actions = body["actions"].as_array().unwrap();
    assert!(
        actions
            .iter()
            .any(|a| a["kind"] == "FixCveHigh" && a["target"]["name"] == "lodash"),
        "expected FixCveHigh for lodash: {actions:?}"
    );
    assert_eq!(body["total"], actions.len() as u64);
}

#[tokio::test]
async fn actions_list_respects_min_severity_filter() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/actions?min_severity=critical").await;
    let actions = body["actions"].as_array().unwrap();
    // Only malware + FixCveCritical qualify as critical. The fixture has
    // no critical advisory, so the filtered list should be empty. `total`
    // still reflects the pre-filter count.
    assert!(
        actions.iter().all(|a| a["severity"] == "critical"),
        "non-critical row leaked: {actions:?}"
    );
    assert!(body["total"].as_u64().unwrap() >= actions.len() as u64);
}

#[tokio::test]
async fn actions_dismiss_hides_action_until_restored() {
    let h = spawn(seed_lodash_with_high_cve).await;
    // 14.2b.2 — dismissals are written to the per-project store the
    // action came from. We probe via slug scope so the test exercises
    // the same store on read + write; aggregate fanout (commit 2)
    // makes the no-scope variant equivalent.
    let body = get_json(&h, "/api/actions?project=_default_").await;
    let first = body["actions"][0].clone();
    let id = first["id"].as_str().unwrap().to_string();

    // POST dismiss with a reason.
    let url = format!("{}/api/actions/{id}/dismiss", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"reason": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let dismissed: serde_json::Value = resp.json().await.unwrap();
    assert!(dismissed["dismissed_at"].is_string());

    // Re-GET (same scope) → action should be gone.
    let after = get_json(&h, "/api/actions?project=_default_").await;
    assert!(
        after["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["id"] != id),
        "dismissed action must not resurface"
    );

    // DELETE (restore) → action returns.
    let restore_url = format!("{}/api/actions/{id}", h.base);
    let resp = reqwest::Client::new()
        .delete(&restore_url)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    let restored = get_json(&h, "/api/actions?project=_default_").await;
    assert!(restored["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == id));
}

#[tokio::test]
async fn actions_defer_returns_deferred_until_and_hides_action() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/actions?project=_default_").await;
    let id = body["actions"][0]["id"].as_str().unwrap().to_string();

    let url = format!("{}/api/actions/{id}/defer", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"days": 7}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let defer_body: serde_json::Value = resp.json().await.unwrap();
    assert!(defer_body["deferred_until"].is_string());

    let after = get_json(&h, "/api/actions?project=_default_").await;
    assert!(after["actions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["id"] != id));
}

#[tokio::test]
async fn actions_dismiss_on_unknown_id_returns_404() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let url = format!("{}/api/actions/nonexistent/dismiss", h.base);
    let resp = reqwest::Client::new().post(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---- Phase 14.1e.3: IntelStore is the single read source for intel data ----

/// Phase 14.1e.3 negative contract: vulnerabilities written into the
/// legacy `Store` intel tables (the same tables migration V7 left in
/// place after copying their content into IntelStore) must NOT surface
/// in any consumer endpoint. Sync, audit, packages-detail, actions —
/// all read from IntelStore now. The legacy rows remain on disk until
/// 14.2 drops the columns; this test guards against an accidental
/// regression where one read path snaps back to the old store.
#[tokio::test]
async fn legacy_store_intel_tables_are_no_longer_read() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo_path.clone(),
        manifest_path: repo_path.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "lodash".into(),
            declared_range: "^4.17.0".into(),
            installed: Some("4.17.20".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("package-lock.json".into()),
        }],
        edges: Vec::new(),
        compatibility: Vec::new(),
    };
    let mut remotes = BTreeMap::new();
    remotes.insert(
        "lodash".into(),
        RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: Some("2024-06-01T00:00:00Z".into()),
            versions: vec![],
        },
    );
    {
        // 14.2d — V8 dropped intel tables from per-project schema; use
        // the V7 fixture opener so the legacy seed step still has the
        // `vulnerabilities` table to write into.
        let mut store = Store::open_legacy_for_tests(&store_path).unwrap();
        // Seed the project + a HIGH advisory, but ONLY in the legacy
        // store. Leave IntelStore empty.
        store
            .save_project(&repo_path, &project, &remotes, "fp")
            .unwrap();
        let vuln = Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-legacy-only".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            severity: Severity::High,
            cve_id: Some("CVE-2021-23337".into()),
            aliases: vec![],
            summary: Some("Legacy-only advisory".into()),
            url: None,
            affected: AffectedSpec {
                ranges: vec![AffectedRange {
                    kind: AffectedRangeKind::Semver,
                    events: vec![
                        AffectedEvent::Introduced("0.0.0".into()),
                        AffectedEvent::Fixed("4.17.21".into()),
                    ],
                }],
                versions: vec![],
            },
            fixed_versions: vec!["4.17.21".into()],
            published_at: None,
            modified_at: None,
        };
        store.persist_vulnerabilities(&[vuln]).unwrap();
    }

    // Phase 14.2b.2 — aggregate fanout iterates `slug_paths()`. To
    // surface the workspace under aggregate, save it into the
    // per-project store directly (bypassing the migration so the
    // legacy intel rows do NOT get copied — the test's contract
    // is "intel handle stays empty even though legacy intel tables
    // have a vuln"). Vuln stays only in the legacy `Store` intel
    // tables; after the bascule no read path touches them.
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    {
        let pstore = project_stores.get_or_open("_default_").await.unwrap();
        let mut pstore = pstore.lock().await;
        pstore
            .save_project(&repo_path, &project, &remotes, "fp")
            .unwrap();
    }
    {
        let mut registry = ProjectsRegistry::open(temp.path()).unwrap();
        let _ = registry.insert_with_slug("_default_", &repo_path, "_default_");
    }

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    assert_eq!(
        intel.count_vulnerabilities().unwrap(),
        0,
        "intel store must start empty for this contract"
    );
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    // /api/packages/{eco}/{name} must report zero vulnerabilities even
    // though the legacy store has one. If a read path regresses to
    // `Store::load_vulnerabilities` this assertion blows up.
    let detail: serde_json::Value = reqwest::get(format!("{base}/api/packages/npm/lodash"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vulns = detail["vulnerabilities"].as_array().unwrap();
    assert!(
        vulns.is_empty(),
        "intel-empty store must not surface legacy vulns: {vulns:?}"
    );

    // /api/graph/vulnerabilities (the palette endpoint) is the second
    // intel read path — same contract.
    let palette: serde_json::Value = reqwest::get(format!("{base}/api/graph/vulnerabilities"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = palette["entries"].as_array().unwrap();
    assert!(
        entries.is_empty(),
        "graph palette must not read from legacy intel tables: {entries:?}"
    );

    // /api/actions must not emit FixCveHigh — the generator now reads
    // its CVE rows from IntelStore.
    let actions: serde_json::Value = reqwest::get(format!("{base}/api/actions"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cve_actions: Vec<&serde_json::Value> = actions["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "FixCveHigh" || a["kind"] == "FixCveCritical")
        .collect();
    assert!(
        cve_actions.is_empty(),
        "actions generator must not emit CVE actions sourced from legacy store: {cve_actions:?}"
    );
}

/// Phase 14.1e.3 positive contract: a critical CVE seeded ONLY into
/// IntelStore must surface end-to-end through the `/api/actions`
/// generator path. This complements the legacy-only negative test
/// above — together they pin the read path to IntelStore.
#[tokio::test]
async fn actions_generator_reads_cve_from_intel_store() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo_path.clone(),
        manifest_path: repo_path.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "lodash".into(),
            declared_range: "^4.17.0".into(),
            installed: Some("4.17.20".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("package-lock.json".into()),
        }],
        edges: Vec::new(),
        compatibility: Vec::new(),
    };
    let mut remotes = BTreeMap::new();
    remotes.insert(
        "lodash".into(),
        RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: Some("2024-06-01T00:00:00Z".into()),
            versions: vec![],
        },
    );
    {
        let mut intel = IntelStore::open(temp.path()).unwrap();
        let vuln = Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-intel-only-crit".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            severity: Severity::Critical,
            cve_id: Some("CVE-2026-99999".into()),
            aliases: vec![],
            summary: Some("Critical-only-in-intel".into()),
            url: None,
            affected: AffectedSpec {
                ranges: vec![AffectedRange {
                    kind: AffectedRangeKind::Semver,
                    events: vec![
                        AffectedEvent::Introduced("0.0.0".into()),
                        AffectedEvent::Fixed("4.17.21".into()),
                    ],
                }],
                versions: vec![],
            },
            fixed_versions: vec!["4.17.21".into()],
            published_at: None,
            modified_at: None,
        };
        intel.persist_vulnerabilities(&[vuln]).unwrap();
    }
    // 14.2b.2 — aggregate fanout iterates `slug_paths()`. Save the
    // workspace into the per-project `_default_` store so the action
    // generator has a dependency to match the intel CVE against.
    // Legacy `Store` stays empty (we never opened it for project
    // data) — proves the action generator's read source is the
    // per-project store, not legacy.
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    {
        let pstore = project_stores.get_or_open("_default_").await.unwrap();
        let mut pstore = pstore.lock().await;
        pstore
            .save_project(&repo_path, &project, &remotes, "fp")
            .unwrap();
    }
    {
        let mut registry = ProjectsRegistry::open(temp.path()).unwrap();
        let _ = registry.insert_with_slug("_default_", &repo_path, "_default_");
    }

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    let actions: serde_json::Value = reqwest::get(format!("{base}/api/actions"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cve_critical_count = actions["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["kind"] == "FixCveCritical" && a["target"]["name"] == "lodash")
        .count();
    assert!(
        cve_critical_count >= 1,
        "FixCveCritical must surface for an intel-only critical CVE: {actions:?}"
    );
}

/// Phase 14.1e.3: `/api/overview` must read its `last_sync_at` from
/// IntelStore. After 14.1e.2 every sync write lands on IntelStore, so
/// the legacy `Store::sync_log` rows are stale — reading from them
/// would show "Synced N days ago" when in fact the sync just ran.
#[tokio::test]
async fn overview_last_sync_at_reads_from_intel_store() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let intel_synced_at = "2026-04-25T10:00:00+00:00".to_string();
    {
        // 14.2d — V8 dropped `sync_log` from per-project schema; use
        // the V7 fixture opener so the legacy seed step still has the
        // table available to write a "stale" marker into.
        let mut store = Store::open_legacy_for_tests(&store_path).unwrap();
        let mut intel = IntelStore::open(temp.path()).unwrap();
        // Stamp a sync row in IntelStore. Stamp a stale, easily
        // distinguishable timestamp on the legacy store too — if the
        // overview reads from there, we'll see this 2020 marker.
        intel
            .put_sync_state(
                "osv-npm",
                &packguard_store::SyncState {
                    etag: None,
                    last_modified: None,
                    last_commit: None,
                    synced_at: Some(intel_synced_at.clone()),
                    record_count: 0,
                },
            )
            .unwrap();
        store
            .put_sync_state(
                "osv-npm",
                &packguard_store::SyncState {
                    etag: None,
                    last_modified: None,
                    last_commit: None,
                    synced_at: Some("2020-01-01T00:00:00+00:00".into()),
                    record_count: 0,
                },
            )
            .unwrap();
    }

    // 14.2b.2 — aggregate fanout needs at least one per-project
    // store on disk to iterate. Create an empty `_default_` store +
    // registry row so the iteration runs once and overview::build
    // gets called (which reads `last_sync_at` from intel directly).
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let _ = project_stores.get_or_open("_default_").await.unwrap();
    {
        let mut registry = ProjectsRegistry::open(temp.path()).unwrap();
        let _ = registry.insert_with_slug("_default_", &repo_path, "_default_");
    }

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open(temp.path()).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");

    let overview: serde_json::Value = reqwest::get(format!("{base}/api/overview"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        overview["last_sync_at"].as_str(),
        Some(intel_synced_at.as_str()),
        "/api/overview must surface the IntelStore sync timestamp, \
         not the (now stale) legacy one: {overview}"
    );
}

#[tokio::test]
async fn unknown_project_query_returns_404_with_known_list() {
    let (h, _alpha, _beta) = spawn_two_workspaces().await;
    let url = format!("{}/api/overview?project=/nowhere", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap();
    // 14.2b.2 — `/nowhere` doesn't exist on disk, so `resolve_scope`
    // 404s with "path does not exist" without consulting the
    // registry. The error keeps the "unknown workspace" prefix so the
    // dashboard's existing copy ("workspace not found") still
    // matches.
    assert!(
        msg.contains("unknown workspace") && msg.contains("/nowhere"),
        "error should mention the rejected workspace path: {msg}",
    );
}

// ---- Phase 14.1f: GET / POST /api/projects + scope param backcompat -------

/// Spawn a harness with explicit control over ProjectsRegistry. The
/// `setup` closure receives all three stores plus the temp dir's repo
/// path so a test can pre-stage rows in either the legacy `Store`,
/// the IntelStore, or the registry before the server boots.
async fn spawn_with_registry(
    setup: impl FnOnce(&mut Store, &mut IntelStore, &mut ProjectsRegistry, &Path),
) -> Harness {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let mut store = Store::open(&store_path).unwrap();
    let mut intel = IntelStore::open(temp.path()).unwrap();
    let mut registry = ProjectsRegistry::open(temp.path()).unwrap();
    setup(&mut store, &mut intel, &mut registry, &repo_path);
    drop(store);
    drop(registry);

    let store = Store::open(&store_path).unwrap();
    let projects = ProjectsRegistry::open(temp.path()).unwrap();
    let project_stores = Arc::new(ProjectStoreCache::new(temp.path().to_path_buf()));
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
        project_stores,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Harness {
        base: format!("http://{addr}"),
        _temp: temp,
    }
}

/// Build a fixture git repo: a directory with a `.git/` child so
/// `find_project_root` succeeds. Returns the canonical path
/// `find_project_root` would resolve `path` to.
fn fixture_git_repo(under: &Path, name: &str) -> std::path::PathBuf {
    let repo = under.join(name);
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    repo.canonicalize().unwrap()
}

#[tokio::test]
async fn projects_list_returns_empty_when_no_project_registered() {
    let h = spawn(|_, _, _| {}).await;
    let body = get_json(&h, "/api/projects").await;
    let arr = body.as_array().unwrap();
    assert!(arr.is_empty(), "expected empty list, got {body}");
}

#[tokio::test]
async fn projects_list_returns_registered_projects_in_last_scan_order() {
    let h = spawn_with_registry(|_, _, registry, _repo| {
        // Two projects, second one explicitly bumped so it sorts first.
        let tmp = tempfile::tempdir().unwrap();
        let alpha = fixture_git_repo(tmp.path(), "alpha");
        let beta = fixture_git_repo(tmp.path(), "beta");
        // We have to lift the temp dir out of the closure before the
        // registry rows reference its paths — but registry stores the
        // canonical strings only, so dropping is fine after insert.
        registry.create_project(&alpha).unwrap();
        let beta_p = registry.create_project(&beta).unwrap();
        registry.touch_last_scan(&beta_p.slug).unwrap();
        std::mem::forget(tmp); // keep the .git dirs alive past closure
    })
    .await;
    let body = get_json(&h, "/api/projects").await;
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2, "expected 2 projects, got {body}");
    // beta has last_scan set, alpha does not — beta sorts first.
    assert!(
        arr[0]["slug"].as_str().unwrap().contains("beta"),
        "beta must sort first: {body}"
    );
    assert!(arr[0]["last_scan"].is_string());
    assert!(arr[1]["last_scan"].is_null());
}

#[tokio::test]
async fn projects_create_with_valid_path_returns_202_and_job_id() {
    let tmp_for_repo = tempfile::tempdir().unwrap();
    let repo = fixture_git_repo(tmp_for_repo.path(), "demo");
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/projects", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "path": repo.display().to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["id"].is_string(), "expected job id: {body}");
}

#[tokio::test]
async fn projects_create_with_nonexistent_path_returns_400() {
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/projects", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "path": "/this/does/not/exist/anywhere" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("does not exist") || msg.contains("path"),
        "error should mention the missing path: {msg}"
    );
}

#[tokio::test]
async fn projects_create_with_file_path_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("README.md");
    std::fs::write(&file, b"hello").unwrap();
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/projects", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "path": file.display().to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not a directory"));
}

#[tokio::test]
async fn projects_create_with_path_lacking_git_ancestor_returns_400() {
    let tmp = tempfile::tempdir().unwrap();
    let lone_dir = tmp.path().join("loose");
    std::fs::create_dir_all(&lone_dir).unwrap();
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/projects", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "path": lone_dir.display().to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not inside a git repository"));
}

#[tokio::test]
async fn projects_create_with_relative_path_returns_400() {
    let h = spawn(|_, _, _| {}).await;
    let url = format!("{}/api/projects", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "path": "relative/path" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("absolute"));
}

#[tokio::test]
async fn legacy_path_query_param_emits_deprecation_header() {
    // The Phase 13 dashboard still passes ?project=<absolute path>;
    // 14.3 will switch to slugs. Until then the legacy form must keep
    // working AND surface the deprecation header so the next dashboard
    // PR can detect it in code review / browser devtools.
    let h = spawn(seed_lodash_with_high_cve).await;
    let workspaces = get_json(&h, "/api/workspaces").await;
    let path = workspaces["workspaces"][0]["path"].as_str().unwrap();
    let url = format!("{}/api/overview?project={path}", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let header = resp
        .headers()
        .get("x-packguard-deprecated")
        .expect("deprecation header must be present on legacy path scope");
    let value = header.to_str().unwrap();
    assert!(
        value.contains("?project=<path> is deprecated") && value.contains("?project=<slug>"),
        "header should explain the migration path: {value}"
    );
}

#[tokio::test]
async fn slug_query_param_resolves_via_registry_without_deprecation_header() {
    // ?project=<slug> is the new form. For 14.1f the SQL filter still
    // falls back to aggregate (full project→workspace cascade is 14.2),
    // but the slug must validate against the registry — and the
    // response must NOT carry the deprecation header.
    let h = spawn_with_registry(|_, _, registry, _| {
        let tmp = tempfile::tempdir().unwrap();
        let repo = fixture_git_repo(tmp.path(), "monorepo");
        registry.create_project(&repo).unwrap();
        std::mem::forget(tmp);
    })
    .await;
    let projects = get_json(&h, "/api/projects").await;
    let slug = projects[0]["slug"].as_str().unwrap();
    let url = format!("{}/api/overview?project={slug}", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(
        resp.headers().get("x-packguard-deprecated").is_none(),
        "slug scope must not emit the deprecation header"
    );
}

// ---- Phase 14.2b.2.3: scan no longer writes to legacy ----------------------

/// Smoke #4 contract — `POST /api/scan` writes only to the per-project
/// store. The legacy file's md5 must be byte-identical before and
/// after a successful scan, even when the scan path falls back to
/// `_default_` (path outside any registered project).
#[tokio::test]
async fn scan_does_not_dual_write_to_legacy_store() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let alt = tempfile::tempdir().unwrap();
    std::fs::write(
        alt.path().join("package.json"),
        r#"{"name":"smoke","dependencies":{"lodash":"^4.17.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        alt.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();

    let h = spawn(|_, _, _| {}).await;
    // After spawn, legacy `store.db` exists with refinery migrations
    // applied but no project rows. Snapshot its bytes for the
    // post-scan comparison.
    let _ = (temp, store_path);
    let legacy_pre = std::fs::read(h._temp.path().join("store.db")).unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/scan", h.base))
        .query(&[("path", alt.path().to_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();
    let final_state = poll_job(&h, &id).await;
    assert_eq!(final_state["status"], "succeeded", "scan must succeed");

    // Per-project store has the workspace.
    let pdir = h._temp.path().join("projects/_default_/store.db");
    assert!(
        pdir.is_file(),
        "scan must create the _default_ per-project store"
    );

    // Legacy file content unchanged byte-for-byte. SQLite WAL is
    // committed by `Store::open`'s checkpoint when the connection
    // is dropped, so a no-op scan path leaves the main file frozen.
    let legacy_post = std::fs::read(h._temp.path().join("store.db")).unwrap();
    assert_eq!(
        legacy_pre, legacy_post,
        "scan must NOT write to the legacy global store after 14.2b.2.3"
    );
}

// ---- Phase 14.2b.2: action writes route to per-project store ---------------

/// Phase 14.2b.2 — dismiss writes hit the per-project store, not the
/// legacy global. We dismiss an action via the API, then probe both
/// stores' `action_dismissals` tables directly: the per-project copy
/// must have the row, the legacy copy must not.
#[tokio::test]
async fn actions_dismiss_writes_to_per_project_store_not_legacy() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/actions?project=_default_").await;
    let id = body["actions"][0]["id"].as_str().unwrap().to_string();

    let url = format!("{}/api/actions/{id}/dismiss", h.base);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "reason": "isolation probe" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let project_db = h._temp.path().join("projects/_default_/store.db");
    let legacy_db = h._temp.path().join("store.db");

    let project_count: i64 = rusqlite::Connection::open(&project_db)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM action_dismissals WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    let legacy_count: i64 = rusqlite::Connection::open(&legacy_db)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM action_dismissals WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(
        project_count, 1,
        "dismissal must be persisted in the per-project store"
    );
    assert_eq!(
        legacy_count, 0,
        "dismissal must NOT touch the legacy global store"
    );
}

// ---- Phase 14.2b: read handlers route slug-scope to per-project store ----

/// Phase 14.2b read-side contract: when the request scopes by slug,
/// the handler reads from `<home>/projects/<slug>/store.db` exclusively.
/// We prove that by spawning the harness (which runs the 14.1d
/// migration so per-project gets a copy of legacy), then mutating the
/// per-project store directly to a state the legacy store no longer
/// matches. A subsequent slug-scoped request must see the per-project
/// state, not the legacy one.
#[tokio::test]
async fn slug_scope_reads_from_per_project_store_not_legacy() {
    let h = spawn(seed_lodash_with_high_cve).await;

    // Spy in the per-project store: deleting every package row breaks
    // the read end-to-end. The legacy store still has the data, so if
    // any handler regressed to legacy reads we'd see it.
    let intel_db = h._temp.path().join("projects/_default_/store.db");
    assert!(
        intel_db.is_file(),
        "harness must have created the per-project store at {}",
        intel_db.display()
    );
    let conn = rusqlite::Connection::open(&intel_db).unwrap();
    // FK chain — drop the child rows before the parent. Replicates
    // what 14.1d migration would do during a project wipe.
    conn.execute("DELETE FROM dependencies", []).unwrap();
    conn.execute("DELETE FROM package_versions", []).unwrap();
    conn.execute("DELETE FROM packages", []).unwrap();
    drop(conn);

    let body = get_json(&h, "/api/packages?project=_default_").await;
    assert_eq!(
        body["total"], 0,
        "slug-scoped read must observe the per-project wipe — got {body}",
    );

    // 14.2b.2 — aggregate also fans out across per-project stores
    // now (slug_paths fanout). Wiping the only registered store's
    // packages turns the aggregate empty too. Legacy still has the
    // rows but nothing reads from there anymore.
    let body_aggregate = get_json(&h, "/api/packages").await;
    assert_eq!(
        body_aggregate["total"], 0,
        "aggregate scope must also reflect the per-project wipe: {body_aggregate}",
    );
}

#[tokio::test]
async fn unknown_slug_returns_404_with_known_slug_list() {
    let h = spawn_with_registry(|_, _, registry, _| {
        let tmp = tempfile::tempdir().unwrap();
        let a = fixture_git_repo(tmp.path(), "first");
        let b = fixture_git_repo(tmp.path(), "second");
        registry.create_project(&a).unwrap();
        registry.create_project(&b).unwrap();
        std::mem::forget(tmp);
    })
    .await;
    let url = format!("{}/api/overview?project=does-not-exist", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(msg.contains("unknown project slug"), "got: {msg}");
    // The error body should enumerate the registered slugs so the
    // dashboard can suggest next steps without a second round-trip.
    assert!(
        msg.contains("first") || msg.contains("second"),
        "expected known slugs in error: {msg}"
    );
}
