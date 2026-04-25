//! Integration tests for Polish-2 — `packguard scans`, actionable errors
//! when a command lands on an unknown path, fingerprint skip guidance,
//! and schema-drift auto-force.

use packguard_core::model::{DepKind, Dependency, Project, RemotePackage};
use packguard_store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn strip_ansi(s: &str) -> String {
    // Hand-rolled SGR-sequence stripper — same approach as graph.rs tests.
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
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
    let mut remotes: BTreeMap<String, RemotePackage> = BTreeMap::new();
    remotes.insert(
        "lodash".into(),
        RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: None,
            versions: vec![],
        },
    );
    store
        .save_project(repo, &project, &remotes, "fp-1")
        .unwrap();
}

fn tmp_with_store() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("store.db");
    let repo = tmp.path().join("repo").canonicalize().unwrap_or_else(|_| {
        std::fs::create_dir_all(tmp.path().join("repo")).unwrap();
        tmp.path().join("repo").canonicalize().unwrap()
    });
    seed(&store_path, &repo);
    (tmp, store_path, repo)
}

#[test]
fn scans_lists_registered_repos_in_a_table() {
    let (_tmp, store, repo) = tmp_with_store();
    let out = Command::new(bin())
        .args(["--store", store.to_str().unwrap(), "scans"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    assert!(
        stdout.contains(&repo.display().to_string()),
        "repo path not listed: {stdout}",
    );
    assert!(stdout.contains("npm"));
    assert!(stdout.contains("1"));
}

#[test]
fn scans_json_mode_emits_machine_readable_array() {
    let (_tmp, store, _repo) = tmp_with_store();
    let out = Command::new(bin())
        .args(["--store", store.to_str().unwrap(), "scans", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ecosystem"], "npm");
    assert_eq!(arr[0]["dependency_count"], 1);
}

#[test]
fn scans_empty_store_prints_actionable_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    // Touch the store so migrations run — otherwise `scans` creates it.
    Store::open(&store).unwrap();
    let out = Command::new(bin())
        .args(["--store", store.to_str().unwrap(), "scans"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    assert!(
        stdout.contains("no scans in store") && stdout.contains("packguard scan"),
        "expected actionable hint, got: {stdout}",
    );
}

#[test]
fn scan_fingerprint_skip_message_mentions_force() {
    // Build a real manifest so `packguard scan` has something to hash,
    // then run scan twice — the second should hit the skip path + mention
    // `--force` per Polish-2 finding #4a.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let repo = tmp.path().join("nalo_like");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"demo","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();

    // First scan (offline since no manifest deps → no registry queries).
    let _ = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            repo.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Second scan on the same manifest — fingerprint matches.
    let out = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "scan",
            repo.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    assert!(
        stdout.contains("no changes since last scan"),
        "expected skip message: {stdout}",
    );
    assert!(
        stdout.contains("--force"),
        "skip message should recommend --force: {stdout}",
    );
}

#[test]
fn scan_forces_rescan_when_schema_drifted_after_last_scan() {
    // Reproduce the Polish-2 finding #4b: last_scan_at < MAX(applied_on)
    // → scan re-runs even though the fingerprint matches. We simulate by
    // seeding the store with an older `last_scan_at` and confirming the
    // CLI says "store schema evolved".
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("store.db");
    let repo = tmp.path().join("nalo_like");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"demo","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();

    // Prime the store + seed a normal scan so we have a repos row.
    // 14.2c — the per-project store the CLI writes to lives under
    // `<home>/projects/<slug>/store.db`. With cwd pinned to a non-git
    // dir and the `repo` path also outside any git repo, the resolver
    // falls through to the `_default_` slug.
    {
        let _ = Command::new(bin())
            .args([
                "--store",
                store_path.to_str().unwrap(),
                "scan",
                repo.to_str().unwrap(),
            ])
            .current_dir(tmp.path())
            .env_remove("PACKGUARD_PROJECT")
            .output()
            .unwrap();
    }

    // Backdate the repo's last_scan_at + backdate the manifest file so the
    // fingerprint round-trips unchanged. The migration history stays at
    // its original time (newer) so `latest_migration_at > last_scan_at`.
    let project_db = tmp.path().join("projects/_default_/store.db");
    {
        let conn = rusqlite::Connection::open(&project_db).unwrap();
        conn.execute(
            "UPDATE repos SET last_scan_at = '2020-01-01T00:00:00+00:00'",
            [],
        )
        .unwrap();
    }

    let out = Command::new(bin())
        .args([
            "--store",
            store_path.to_str().unwrap(),
            "scan",
            repo.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    let stdout = strip_ansi(&String::from_utf8(out.stdout).unwrap());
    assert!(
        stdout.contains("store schema evolved"),
        "expected schema-drift rescan notice: {stdout}",
    );
}

/// Spawn `packguard ui` in a thread, collect stdout lines as they
/// arrive, give it up to `deadline_ms` to emit the full banner, kill the
/// child. `child.kill()` is SIGKILL on macOS which drops buffered
/// output — reading incrementally lets us capture the banner before we
/// shut the server down. Pin `cwd` to a non-git dir so the 14.2c slug
/// auto-detection lands on `_default_` instead of the host repo's slug.
fn run_ui_collect_banner_in(cwd: &Path, args: &[&str], deadline_ms: u64) -> String {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let mut child = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .env_remove("PACKGUARD_PROJECT")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().expect("stdout captured");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(deadline_ms);
    let mut collected = Vec::new();
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(line) => {
                collected.push(line);
                // The banner is 3 lines (server URL, resolution note,
                // dashboard line) + a press-Ctrl+C footer. Once we have
                // those four we can safely kill the child.
                if collected.len() >= 4 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    strip_ansi(&collected.join("\n"))
}

#[test]
fn report_accepts_project_flag_as_alias_of_path_arg() {
    // Phase 7a: `--project` must behave exactly like the positional
    // path on `report` / `audit` / `graph`. We run both forms on the
    // same store and assert the stdout is identical so future command
    // additions can follow the same pattern.
    let (_tmp, store, repo) = tmp_with_store();
    let positional = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "report",
            repo.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let aliased = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "report",
            "--project",
            repo.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(positional.status.success(), "positional: {:?}", positional);
    assert!(aliased.status.success(), "--project: {:?}", aliased);
    let a = strip_ansi(&String::from_utf8(positional.stdout).unwrap());
    let b = strip_ansi(&String::from_utf8(aliased.stdout).unwrap());
    assert_eq!(a, b, "positional vs --project stdout mismatched");
}

#[test]
fn report_without_arg_falls_back_to_most_recent_scan_with_banner() {
    // Phase 7a: matching `packguard ui` (Polish-bis-2), running a
    // project-scoped command with no argument should default to the
    // most recent scan and surface a stderr banner so the user never
    // confuses "most-recent" fallback with a silent CWD default.
    let (tmp, store, repo) = tmp_with_store();
    let out = Command::new(bin())
        .args(["--store", store.to_str().unwrap(), "report"])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("most recent scan") && stderr.contains(&repo.display().to_string()),
        "expected most-recent banner in stderr, got: {stderr}",
    );
}

#[test]
fn report_without_arg_on_empty_store_exits_with_actionable_error() {
    // And the empty-store branch must bail with a message that names
    // the escape hatch — never crash into a blank scan error the user
    // has to decode.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    Store::open(&store).unwrap();
    let out = Command::new(bin())
        .args(["--store", store.to_str().unwrap(), "report"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("no cached scan") && stderr.contains("packguard scan"),
        "expected actionable empty-store error, got: {stderr}",
    );
}

#[test]
fn ui_without_path_on_empty_store_prints_no_scans_yet_banner() {
    // Polish-bis-2: `packguard ui` must never silently fall back to the
    // process CWD anymore. On an empty store we want an honest banner
    // that tells the user to run `packguard scan` first.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let stdout = run_ui_collect_banner_in(
        tmp.path(),
        &[
            "--store",
            store.to_str().unwrap(),
            "ui",
            "--port",
            "0",
            "--host",
            "127.0.0.1",
            "--no-open",
        ],
        3000,
    );
    assert!(
        stdout.contains("no scans yet") && stdout.contains("packguard scan"),
        "expected empty-store banner, got: {stdout}",
    );
}

#[test]
fn ui_without_path_on_populated_store_picks_most_recent_scan() {
    // Polish-bis-2 happy path: when the store has at least one scan,
    // `packguard ui` with no arg falls back to the most-recent
    // `last_scan_at` entry and calls that out in the banner.
    let (tmp, store, repo) = tmp_with_store();
    let stdout = run_ui_collect_banner_in(
        tmp.path(),
        &[
            "--store",
            store.to_str().unwrap(),
            "ui",
            "--port",
            "0",
            "--host",
            "127.0.0.1",
            "--no-open",
        ],
        3000,
    );
    let repo_str = repo.display().to_string();
    assert!(
        stdout.contains(&repo_str),
        "banner should mention the auto-picked workspace {repo_str}: {stdout}",
    );
    assert!(
        stdout.contains("most recent scan"),
        "banner should flag auto-selection: {stdout}",
    );
    assert!(
        stdout.contains("override with `packguard ui <path>`"),
        "banner should surface the override hint: {stdout}",
    );
}

#[test]
fn report_on_unknown_path_lists_available_scans() {
    let (_tmp, store, _repo) = tmp_with_store();
    let elsewhere = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "report",
            elsewhere.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("no cached scan"),
        "expected error to include scan hint: {stderr}",
    );
    assert!(
        stderr.contains("Available scans") && stderr.contains("packguard scans"),
        "expected available-scans hint in: {stderr}",
    );
}
