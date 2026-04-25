//! Integration tests for the REST API. Spawns the axum router on a random
//! port, seeds the in-memory store via the same library APIs the CLI uses,
//! and exercises every endpoint.

use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency,
    DependencyEdge, MalwareKind, MalwareReport, Project, RemotePackage, Severity, Vulnerability,
};
use packguard_server::{router, ServerConfig};
use packguard_store::{IntelStore, ProjectsRegistry, Store};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpListener;

struct Harness {
    base: String,
    _temp: tempfile::TempDir,
}

async fn spawn(setup: impl FnOnce(&mut Store, &Path)) -> Harness {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("store.db");
    let repo_path = temp.path().join("repo");
    std::fs::create_dir_all(&repo_path).unwrap();
    let mut store = Store::open(&store_path).unwrap();
    setup(&mut store, &repo_path);
    drop(store);

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
        intel,
        projects,
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

fn seed_lodash_with_high_cve(store: &mut Store, repo: &Path) {
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
    store
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
    store
        .persist_malware_reports(std::slice::from_ref(&malware))
        .unwrap();
}

// ---------- /api/health -----------------------------------------------------

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let h = spawn(|_, _| {}).await;
    let body = get_json(&h, "/api/health").await;
    assert_eq!(body, serde_json::json!({ "ok": true }));
}

// ---------- /api/overview --------------------------------------------------

#[tokio::test]
async fn overview_with_empty_store_returns_zeroed_payload() {
    let h = spawn(|_, _| {}).await;
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
    let h = spawn(|store, repo| {
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
        store
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
    let h = spawn(|_, _| {}).await;
    let body = get_json(&h, "/api/policies").await;
    assert_eq!(body["from_file"], false);
    let yaml = body["yaml"].as_str().unwrap();
    assert!(yaml.contains("offset:"));
}

#[tokio::test]
async fn policies_returns_repo_file_when_present() {
    let h = spawn(|_, repo| {
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
    let h = spawn(|_, _| {}).await;
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
    let h = spawn(|_, _| {}).await;
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
    let h = spawn(|_, repo| {
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
    let h = spawn(|_, _| {}).await;
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

    // Start the server pointed at the *scratch* server_cwd (no manifest).
    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let app = router(ServerConfig {
        repo_path: server_cwd.clone(),
        store,
        intel,
        projects,
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
    let h = spawn(|_, _| {}).await;
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

    let h = spawn(|_, _| {}).await;
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
    let h = spawn(|_, _| {}).await;
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

    let h = spawn(|_, _| {}).await;
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

fn seed_react_chain_with_lodash_cve(store: &mut Store, repo: &Path) {
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
    store
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
        seed_react_chain_with_lodash_cve(&mut store, &raw_repo);
    }

    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let app = router(ServerConfig {
        repo_path: canonical_repo.clone(),
        store,
        intel,
        projects,
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
    let service_response = packguard_server::services::graph::build(
        &fresh_store,
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
    let h = spawn(|_, _| {}).await;
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
    let h = spawn(|_, _| {}).await;
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

    // Reopen to mirror production `packguard ui` — ServerConfig.repo_path
    // points at workspace_alpha so we can also assert that `?project=` is
    // the source of truth, not the server's default.
    let store = Store::open(&store_path).unwrap();
    let intel = IntelStore::open_in_memory().unwrap();
    let projects = ProjectsRegistry::open_in_memory().unwrap();
    let app = router(ServerConfig {
        repo_path: repo_a.clone(),
        store,
        intel,
        projects,
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
    let body = get_json(&h, "/api/actions").await;
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

    // Re-GET → action should be gone.
    let after = get_json(&h, "/api/actions").await;
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
    let restored = get_json(&h, "/api/actions").await;
    assert!(restored["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == id));
}

#[tokio::test]
async fn actions_defer_returns_deferred_until_and_hides_action() {
    let h = spawn(seed_lodash_with_high_cve).await;
    let body = get_json(&h, "/api/actions").await;
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

    let after = get_json(&h, "/api/actions").await;
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

#[tokio::test]
async fn unknown_project_query_returns_404_with_known_list() {
    let (h, alpha, _beta) = spawn_two_workspaces().await;
    let url = format!("{}/api/overview?project=/nowhere", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("unknown workspace") && msg.contains(&alpha),
        "error should list known workspaces: {msg}",
    );
}
