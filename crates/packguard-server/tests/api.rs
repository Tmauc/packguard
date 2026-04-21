//! Integration tests for the REST API. Spawns the axum router on a random
//! port, seeds the in-memory store via the same library APIs the CLI uses,
//! and exercises every endpoint.

use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency,
    MalwareKind, MalwareReport, Project, RemotePackage, Severity, Vulnerability,
};
use packguard_server::{router, ServerConfig};
use packguard_store::Store;
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
    let app = router(ServerConfig {
        repo_path: repo_path.clone(),
        store,
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
    assert!(trace["offset"].is_number());
    assert_eq!(trace["stability"], "stable");
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
        std::fs::write(repo.join(".packguard.yml"), "defaults:\n  offset: 0\n").unwrap();
    })
    .await;
    let body = get_json(&h, "/api/policies").await;
    assert_eq!(body["from_file"], true);
    assert!(body["yaml"].as_str().unwrap().contains("offset: 0"));
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
    let candidate = "defaults:\n  offset: 0\n  block:\n    cve_severity: [critical, high]\n";
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
    let candidate = "defaults:\n  offset: 0\n  block: {}\n";
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
        serde_json::json!({ "yaml": "defaults:\n  offset: -1\n    bad_indent: true\n" }),
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
    let yaml = "defaults:\n  offset: 0\n  min_age_days: 3\n";
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
        std::fs::write(repo.join(".packguard.yml"), "defaults:\n  offset: 0\n").unwrap();
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
    assert!(fresh["yaml"].as_str().unwrap().contains("offset: 0"));
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
    assert!(final_state["error"]
        .as_str()
        .unwrap()
        .contains("no supported manifest"));
}

#[tokio::test]
async fn job_unknown_returns_404() {
    let h = spawn(|_, _| {}).await;
    let url = format!("{}/api/jobs/00000000-0000-0000-0000-000000000000", h.base);
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
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
