//! Integration tests for `packguard audit`. Seeds the store with a fake
//! scan + advisories via the library API, then invokes the CLI binary.

use packguard_core::model::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency, Project,
    RemotePackage, Severity, Vulnerability,
};
use packguard_store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn seed(store_path: &Path, repo: &Path) {
    let mut store = Store::open(store_path).unwrap();
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
    store
        .save_project(repo, &project, &remotes, "fp-1")
        .unwrap();

    // Seed one HIGH severity advisory affecting 4.17.20.
    let vuln = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-35jh-r3h4-6jhm".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec!["CVE-2021-23337".into()],
        summary: Some("Command Injection in lodash".into()),
        url: Some("https://github.com/advisories/GHSA-35jh-r3h4-6jhm".into()),
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
}

struct Env {
    _tmp: tempfile::TempDir,
    store: PathBuf,
    repo: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    seed(&store, &repo);
    Env {
        _tmp: tmp,
        store,
        repo,
    }
}

#[test]
fn audit_table_lists_the_match_with_severity_badge() {
    let env = env();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("lodash"), "stdout: {s}");
    assert!(s.contains("CVE-2021-23337"), "stdout: {s}");
    assert!(s.contains("high"), "stdout: {s}");
    assert!(s.contains("4.17.21"), "fix version missing: {s}");
    assert!(s.contains("Summary:"));
}

#[test]
fn audit_json_has_summary_and_matches() {
    let env = env();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // Phase 2.5: audit JSON splits into cve / malware / typosquat sections.
    assert_eq!(parsed["cve"]["summary"]["high"], 1);
    let matches = parsed["cve"]["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["cve_id"], "CVE-2021-23337");
    assert_eq!(matches[0]["fixed_versions"][0], "4.17.21");
}

#[test]
fn audit_severity_filter_excludes_low() {
    let env = env();
    // Ask for critical only — our seed is HIGH → no matches expected.
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback", "--severity", "critical"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("no matched vulnerabilities"),
        "expected the clear-screen banner when filter excludes everything; got: {s}"
    );
}

#[test]
fn audit_fail_on_high_exits_nonzero() {
    let env = env();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback", "--fail-on", "high"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn audit_fail_on_critical_exits_zero_when_only_high_present() {
    let env = env();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback", "--fail-on", "critical"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn audit_sarif_emits_results() {
    let env = env();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["audit", "--no-live-fallback", "--format", "sarif"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let sarif: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "packguard.cve");
    assert_eq!(results[0]["level"], "error");
}

#[test]
fn report_includes_cve_column_and_footer() {
    let env = env();
    // Default policy already blocks high severity CVEs → compliance row will
    // be "cve-violation" and footer will count vulnerabilities.
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    // Phase 2.5 renamed the column from "CVE" to "Risk" so the same cell
    // can carry malware / typosquat icons too.
    assert!(s.contains("Risk"), "Risk column missing: {s}");
    // Footer surfaces vuln counts.
    assert!(s.contains("Vulnerabilities:"), "vuln footer missing: {s}");
    // Compliance column = cve-violation.
    assert!(
        s.contains("cve-violation"),
        "expected cve-violation badge: {s}"
    );
}
