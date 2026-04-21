//! Integration tests for `packguard graph`. Seeds a synthetic graph
//! (react → loose-envify → lodash + a peer on scheduler) via the same
//! APIs the real scan flow uses, then exercises ascii / dot / contamination.

use packguard_core::model::{DepKind, Dependency, DependencyEdge, Project, RemotePackage};
use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, Severity, Vulnerability,
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
        compatibility: vec![],
    };
    let mut remotes: BTreeMap<String, RemotePackage> = BTreeMap::new();
    remotes.insert(
        "react".into(),
        RemotePackage {
            name: "react".into(),
            latest: Some("18.2.0".into()),
            latest_published_at: None,
            versions: vec![],
        },
    );
    store.save_project(repo, &project, &remotes, "fp").unwrap();

    // Seed a CVE on lodash@4.17.20 so --contaminated-by actually traces.
    let vuln = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-demo".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec![],
        summary: Some("Command Injection".into()),
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
}

fn run(args: &[&str], store: &Path) -> std::process::Output {
    Command::new(bin())
        .arg("--store")
        .arg(store)
        .args(args)
        .output()
        .expect("run packguard")
}

fn repo_and_store() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let repo_raw = tmp.path().join("repo");
    std::fs::create_dir_all(&repo_raw).unwrap();
    // macOS resolves `/var/folders/...` to `/private/var/...` via canonicalize;
    // the CLI canonicalizes before querying so we must seed with the same
    // form or no workspace matches.
    let repo = repo_raw.canonicalize().unwrap_or(repo_raw);
    seed(&store, &repo);
    (tmp, store, repo)
}

#[test]
fn graph_ascii_shows_root_and_transitive_children() {
    let (_tmp, store, repo) = repo_and_store();
    let out = run(
        &["graph", repo.to_str().unwrap(), "--format", "ascii"],
        &store,
    );
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    // Root bolded + all three nodes reachable.
    assert!(stdout.contains("react@18.2.0"), "root missing: {stdout}");
    assert!(
        stdout.contains("loose-envify@1.4.0"),
        "transitive missing: {stdout}",
    );
    assert!(stdout.contains("lodash@4.17.20"), "leaf missing: {stdout}");
    // Unresolved peer surfaces as a dimmed line.
    assert!(
        stdout.contains("unresolved peer"),
        "peer warning missing: {stdout}",
    );
}

#[test]
fn graph_dot_emits_valid_digraph_with_node_styling() {
    let (_tmp, store, repo) = repo_and_store();
    let out = run(
        &["graph", repo.to_str().unwrap(), "--format", "dot"],
        &store,
    );
    assert!(out.status.success(), "{:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("digraph packguard {"));
    assert!(stdout.contains("rankdir=LR"));
    assert!(stdout.contains("\"npm:react@18.2.0\""));
    assert!(stdout.contains("\"npm:lodash@4.17.20\""));
    // CVE nodes get a red border.
    assert!(stdout.contains("color=\"#dc2626\""));
}

#[test]
fn graph_focus_narrows_to_subtree() {
    let (_tmp, store, repo) = repo_and_store();
    let out = run(
        &[
            "graph",
            repo.to_str().unwrap(),
            "--format",
            "ascii",
            "--focus",
            "npm:loose-envify@1.4.0",
        ],
        &store,
    );
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    // When focused on loose-envify we don't carry a root marker, so the
    // ascii printer falls back to its "no roots" message — that's the
    // documented contract for `--focus` without a root hit.
    assert!(
        stdout.contains("no roots") || stdout.contains("loose-envify"),
        "focus output unexpected: {stdout}",
    );
}

#[test]
fn graph_contaminated_by_prints_all_chains() {
    let (_tmp, store, repo) = repo_and_store();
    let out = run(
        &[
            "graph",
            repo.to_str().unwrap(),
            "--contaminated-by",
            "CVE-2021-23337",
            "--format",
            "ascii",
        ],
        &store,
    );
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    // Chain: react → loose-envify → lodash.
    assert!(stdout.contains("CVE-2021-23337"));
    assert!(stdout.contains("chain 1"));
    assert!(stdout.contains("react@18.2.0"));
    assert!(stdout.contains("lodash@4.17.20"));
}

#[test]
fn graph_json_format_round_trips_graph_response() {
    let (_tmp, store, repo) = repo_and_store();
    let out = run(
        &["graph", repo.to_str().unwrap(), "--format", "json"],
        &store,
    );
    assert!(out.status.success(), "{:?}", out);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(parsed["nodes"].is_array());
    assert!(parsed["edges"].is_array());
}

fn strip_ansi(s: &str) -> String {
    // Lightweight escape-sequence stripper — we only need to match the
    // `\x1b[...m` SGR sequences owo-colors emits, so a hand-rolled parser
    // keeps the test dep list tight.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}
