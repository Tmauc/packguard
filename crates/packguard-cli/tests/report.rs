//! Integration tests for `packguard report`. No network — the store is
//! seeded directly via `packguard-store` APIs, then the CLI binary is
//! invoked and its output inspected.

use packguard_core::model::{DepKind, Dependency, Project, RemotePackage};
use packguard_store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn seed_store(store_path: &Path, repo: &Path) {
    let mut store = Store::open(store_path).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo.to_path_buf(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![
            Dependency {
                name: "react".into(),
                declared_range: "^18.2.0".into(),
                installed: Some("18.2.0".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            },
            Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("package-lock.json".into()),
            },
            Dependency {
                name: "typescript".into(),
                declared_range: "^5.0.0".into(),
                installed: Some("5.4.5".into()),
                kind: DepKind::Dev,
                source_lockfile: Some("package-lock.json".into()),
            },
        ],
        edges: Vec::new(),
        compatibility: Vec::new(),
    };
    let mut remotes = BTreeMap::new();
    remotes.insert(
        "react".into(),
        RemotePackage {
            name: "react".into(),
            latest: Some("19.2.5".into()),
            latest_published_at: Some("2026-04-08T00:00:00Z".into()),
            versions: vec![],
        },
    );
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
        "typescript".into(),
        RemotePackage {
            name: "typescript".into(),
            latest: Some("5.4.5".into()),
            latest_published_at: Some("2026-04-16T00:00:00Z".into()),
            versions: vec![],
        },
    );
    store
        .save_project(repo, &project, &remotes, "fingerprint-1")
        .unwrap();
}

struct Env {
    _tmp: tempfile::TempDir,
    store: PathBuf,
    repo: PathBuf,
}

fn env_with_store() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    seed_store(&store, &repo);
    Env {
        _tmp: tmp,
        store,
        repo,
    }
}

#[test]
fn report_table_includes_ecosystem_and_policy_column() {
    let env = env_with_store();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[npm]"), "stdout: {stdout}");
    assert!(stdout.contains("react"), "stdout: {stdout}");
    assert!(stdout.contains("Policy"), "stdout: {stdout}");
    assert!(stdout.contains("Summary"), "stdout: {stdout}");
}

#[test]
fn report_json_format_is_valid() {
    let env = env_with_store();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report", "--format", "json"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(parsed["summary"].is_object());
    assert!(parsed["rows"].is_array());
    assert!(parsed["rows"].as_array().unwrap().len() >= 3);
}

#[test]
fn report_sarif_only_emits_violations() {
    let env = env_with_store();
    // Policy with a pin that will mismatch → triggers a violation.
    std::fs::write(
        env.repo.join(".packguard.yml"),
        r#"
defaults: { offset: -1 }
overrides:
  - match: lodash
    pin: "4.17.21"
"#,
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report", "--format", "sarif"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty(), "expected a violation; sarif: {stdout}");
    assert!(results
        .iter()
        .any(|r| r["message"]["text"].as_str().unwrap().contains("lodash")));
}

#[test]
fn report_fail_on_violation_exits_nonzero() {
    let env = env_with_store();
    std::fs::write(
        env.repo.join(".packguard.yml"),
        r#"
overrides:
  - match: lodash
    pin: "4.17.21"
"#,
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report", "--fail-on-violation"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn report_without_violations_exits_zero_even_with_fail_flag() {
    let env = env_with_store();
    // No policy file → built-in conservative defaults (offset: -1).
    // With our seed: react 18 vs latest 19 → compliant (within offset-1).
    //                lodash 4.17.20 vs latest 4.17.21 → compliant (major OK).
    //                typescript 5.4.5 == 5.4.5 → compliant.
    let out = Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .args(["report", "--fail-on-violation"])
        .arg(&env.repo)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn report_errors_cleanly_without_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let out = Command::new(bin())
        .arg("--store")
        .arg(&store)
        .args(["report"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no cached scan"), "stderr: {stderr}");
}
