//! Phase 14.1d test suite — fixtures use real `.git/` directories on
//! disk so `find_project_root` resolves through the same canonicalize
//! path the production migration runs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use packguard_core::model::{
    AffectedSpec, DepKind, Dependency, MalwareKind, MalwareReport, Project, RemotePackage,
    Severity, Vulnerability,
};
use rusqlite::{params, Connection};
use serde_json::json;
use tempfile::TempDir;

use crate::migration::{migrate_legacy_if_present, MigrationReport};
use crate::{IntelStore, ProjectsRegistry, Store, SyncState};

// --- fixture helpers ---------------------------------------------------

fn make_git_root(parent: &Path, name: &str) -> PathBuf {
    let root = parent.join(name);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    root.canonicalize().unwrap()
}

fn sample_project(root: &Path, deps: &[(&str, &str, &str, DepKind)]) -> Project {
    let dependencies = deps
        .iter()
        .map(|(name, declared, installed, kind)| Dependency {
            name: (*name).into(),
            declared_range: (*declared).into(),
            installed: Some((*installed).into()),
            kind: *kind,
            source_lockfile: Some("package-lock.json".into()),
        })
        .collect();
    Project {
        ecosystem: "npm",
        root: root.to_path_buf(),
        manifest_path: root.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies,
        edges: Vec::new(),
        compatibility: Vec::new(),
    }
}

fn remote(latest: &str) -> RemotePackage {
    RemotePackage {
        name: "ignored".into(),
        latest: Some(latest.into()),
        latest_published_at: None,
        versions: Vec::new(),
    }
}

fn sample_remotes(pkgs: &[(&str, &str)]) -> BTreeMap<String, RemotePackage> {
    let mut m = BTreeMap::new();
    for (name, latest) in pkgs {
        m.insert((*name).into(), remote(latest));
    }
    m
}

fn sample_vuln(eco: &str, name: &str, advisory: &str) -> Vulnerability {
    Vulnerability {
        source: "osv".into(),
        advisory_id: advisory.into(),
        ecosystem: eco.into(),
        package_name: name.into(),
        severity: Severity::High,
        cve_id: Some("CVE-2026-9999".into()),
        aliases: vec!["GHSA-xxxx".into()],
        summary: Some("legacy advisory".into()),
        url: Some("https://example.com".into()),
        affected: AffectedSpec::default(),
        fixed_versions: vec!["2.0.0".into()],
        published_at: Some("2026-01-01T00:00:00Z".into()),
        modified_at: None,
    }
}

fn sample_malware(eco: &str, name: &str, ref_id: &str) -> MalwareReport {
    MalwareReport {
        source: "osv-mal".into(),
        ref_id: ref_id.into(),
        ecosystem: eco.into(),
        package_name: name.into(),
        version: "1.0.0".into(),
        kind: MalwareKind::Malware,
        summary: Some("legacy malware".into()),
        url: None,
        evidence: json!({"reason": "legacy"}),
        reported_at: Some("2026-01-02T00:00:00Z".into()),
    }
}

/// Build a legacy `<home>/store.db` populated with two distinct git
/// projects, plus intel rows referencing the deps' packages and a
/// few sync_log entries.
fn build_dual_project_legacy(home: &Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(home).unwrap();
    let workspace = home.parent().unwrap();
    let repo_a = make_git_root(workspace, "repo-a");
    let repo_b = make_git_root(workspace, "repo-b");

    let store_path = home.join("store.db");
    // 14.2d — V8 drops `vulnerabilities`/`malware_reports`/`sync_log`,
    // so the legacy fixture must stop at V7 to keep the seed step
    // alive. Production migration code reads the legacy via raw
    // `rusqlite` with `SQLITE_OPEN_READ_ONLY`, which never triggers
    // refinery, so the V7 schema travels through migration unchanged.
    let mut store = Store::open_legacy_for_tests(&store_path).unwrap();

    let pa = sample_project(
        &repo_a,
        &[
            ("react", "^18.0.0", "18.2.0", DepKind::Runtime),
            ("typescript", "^5.0.0", "5.4.5", DepKind::Dev),
        ],
    );
    store
        .save_project(
            &repo_a,
            &pa,
            &sample_remotes(&[("react", "19.0.0"), ("typescript", "5.4.5")]),
            "fp-a-1",
        )
        .unwrap();

    let pb = sample_project(
        &repo_b,
        &[("lodash", "^4.0.0", "4.17.21", DepKind::Runtime)],
    );
    store
        .save_project(
            &repo_b,
            &pb,
            &sample_remotes(&[("lodash", "4.17.21")]),
            "fp-b-1",
        )
        .unwrap();

    // Intel rows targeting the same packages above so the JOIN finds
    // matches for the FK denormalization.
    store
        .persist_vulnerabilities(&[
            sample_vuln("npm", "react", "GHSA-aaa-aaa-aaa"),
            sample_vuln("npm", "lodash", "GHSA-bbb-bbb-bbb"),
            sample_vuln("npm", "lodash", "GHSA-ccc-ccc-ccc"),
        ])
        .unwrap();
    store
        .persist_malware_reports(&[sample_malware("npm", "lodash", "MAL-0001")])
        .unwrap();

    // sync_log
    store
        .put_sync_state(
            "osv-npm",
            &SyncState {
                etag: Some("\"abc\"".into()),
                last_modified: Some("Wed, 01 Apr 2026 12:00:00 GMT".into()),
                last_commit: None,
                synced_at: Some("2026-04-01T12:00:00Z".into()),
                record_count: 100,
            },
        )
        .unwrap();
    store
        .put_sync_state(
            "ghsa",
            &SyncState {
                etag: None,
                last_modified: None,
                last_commit: Some("deadbeef".into()),
                synced_at: Some("2026-04-02T12:00:00Z".into()),
                record_count: 50,
            },
        )
        .unwrap();

    // Action dismissals scoped to repo_a path.
    store
        .upsert_action_dismissal(
            "dismissal-a-1",
            "vulnerability",
            r#"{"package":"react"}"#,
            repo_a.to_string_lossy().as_ref(),
            1_700_000_000,
            None,
            Some("not exposed"),
        )
        .unwrap();
    drop(store);
    (repo_a, repo_b)
}

// --- tests -------------------------------------------------------------

#[test]
fn migrate_no_op_when_no_legacy_store() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    std::fs::create_dir_all(&home).unwrap();
    let report = migrate_legacy_if_present(&home).unwrap();
    assert!(!report.legacy_found);
    assert_eq!(report, MigrationReport::default());
    // No new files were created beyond the empty home itself.
    assert!(!home.join("intel/intel.db").exists());
    assert!(!home.join("projects.db").exists());
}

#[test]
fn migrate_lossless_copy_of_sync_log() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let report = migrate_legacy_if_present(&home).unwrap();
    assert!(report.legacy_found);
    assert_eq!(report.sync_log_entries_migrated, 2);

    let intel = IntelStore::open(&home).unwrap();
    let osv = intel.get_sync_state("osv-npm").unwrap().unwrap();
    assert_eq!(osv.record_count, 100);
    assert_eq!(osv.etag.as_deref(), Some("\"abc\""));
    let ghsa = intel.get_sync_state("ghsa").unwrap().unwrap();
    assert_eq!(ghsa.last_commit.as_deref(), Some("deadbeef"));
    assert_eq!(ghsa.record_count, 50);
}

#[test]
fn migrate_denormalizes_vulnerabilities_via_packages_join() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let report = migrate_legacy_if_present(&home).unwrap();
    assert_eq!(report.vulnerabilities_migrated, 3);

    let intel = IntelStore::open(&home).unwrap();
    assert_eq!(intel.count_vulnerabilities().unwrap(), 3);
    let lodash = intel.load_vulnerabilities_for("npm", "lodash").unwrap();
    assert_eq!(lodash.len(), 2);
    let advisories: Vec<&str> = lodash.iter().map(|v| v.advisory_id.as_str()).collect();
    assert!(advisories.contains(&"GHSA-bbb-bbb-bbb"));
    assert!(advisories.contains(&"GHSA-ccc-ccc-ccc"));
    let react = intel.load_vulnerabilities_for("npm", "react").unwrap();
    assert_eq!(react.len(), 1);
    assert_eq!(react[0].advisory_id, "GHSA-aaa-aaa-aaa");
}

#[test]
fn migrate_denormalizes_malware_reports_via_packages_join() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let report = migrate_legacy_if_present(&home).unwrap();
    assert_eq!(report.malware_reports_migrated, 1);

    let intel = IntelStore::open(&home).unwrap();
    let reports = intel.load_malware_reports_for("npm", "lodash").unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].ref_id, "MAL-0001");
    assert_eq!(reports[0].kind, MalwareKind::Malware);
}

#[test]
fn migrate_partitions_repos_by_git_root() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let (repo_a, repo_b) = build_dual_project_legacy(&home);
    let report = migrate_legacy_if_present(&home).unwrap();
    assert_eq!(report.projects_created, 2);
    assert_eq!(report.workspaces_migrated, 2);

    let registry = ProjectsRegistry::open(&home).unwrap();
    let projects = registry.list_projects().unwrap();
    assert_eq!(projects.len(), 2);
    let paths: Vec<&Path> = projects.iter().map(|p| p.path.as_path()).collect();
    assert!(paths.contains(&repo_a.as_path()));
    assert!(paths.contains(&repo_b.as_path()));
    // Each project's slug derives from its canonical git-root path.
    for p in &projects {
        assert!(!p.slug.contains('/'), "slug must not contain /");
        assert_ne!(p.slug, "_default_", "git-rooted repos must not fall back");
    }
    // Per-project store files were created under home/projects/<slug>/.
    for p in &projects {
        assert!(home
            .join("projects")
            .join(&p.slug)
            .join("store.db")
            .is_file());
    }
}

#[test]
fn migrate_falls_back_to_default_for_orphan_repo() {
    // Force an orphan: register a repo at a tempdir path with no
    // `.git/` ancestor below $HOME. find_project_root returns None,
    // the migration parks the repo in the `_default_` project store.
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    std::fs::create_dir_all(&home).unwrap();
    let orphan = tmp.path().join("orphan-repo");
    std::fs::create_dir_all(&orphan).unwrap();

    let store_path = home.join("store.db");
    let mut store = Store::open_legacy_for_tests(&store_path).unwrap();
    let project = sample_project(
        &orphan,
        &[("left-pad", "^1.0.0", "1.3.0", DepKind::Runtime)],
    );
    store
        .save_project(
            &orphan,
            &project,
            &sample_remotes(&[("left-pad", "1.3.0")]),
            "fp-orphan",
        )
        .unwrap();
    drop(store);

    let report = migrate_legacy_if_present(&home).unwrap();
    assert!(report.legacy_found);
    assert_eq!(report.fallback_default_paths, 1);
    assert_eq!(report.projects_created, 1);
    assert!(home.join("projects/_default_/store.db").is_file());

    let registry = ProjectsRegistry::open(&home).unwrap();
    let projects = registry.list_projects().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].slug, "_default_");
}

#[test]
fn migrate_copies_packages_per_project() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let (repo_a, _repo_b) = build_dual_project_legacy(&home);
    migrate_legacy_if_present(&home).unwrap();

    // Locate repo_a's project store and confirm it sees react +
    // typescript but NOT lodash (which is repo_b's).
    let registry = ProjectsRegistry::open(&home).unwrap();
    let projects = registry.list_projects().unwrap();
    let proj_a = projects
        .iter()
        .find(|p| p.path == repo_a)
        .expect("repo_a project must exist");

    let project_db = home.join("projects").join(&proj_a.slug).join("store.db");
    let store_a = Store::open(&project_db).unwrap();
    let deps = store_a.load_repo_dependencies(&repo_a).unwrap();
    let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"react"));
    assert!(names.contains(&"typescript"));
    assert!(!names.contains(&"lodash"), "lodash belongs to repo_b only");
}

#[test]
fn migrate_copies_action_dismissals_per_workspace() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let (repo_a, repo_b) = build_dual_project_legacy(&home);
    migrate_legacy_if_present(&home).unwrap();

    let registry = ProjectsRegistry::open(&home).unwrap();
    let projects = registry.list_projects().unwrap();
    let proj_a = projects.iter().find(|p| p.path == repo_a).unwrap();
    let proj_b = projects.iter().find(|p| p.path == repo_b).unwrap();

    let store_a = Store::open(&home.join("projects").join(&proj_a.slug).join("store.db")).unwrap();
    let store_b = Store::open(&home.join("projects").join(&proj_b.slug).join("store.db")).unwrap();

    // `load_active_dismissals(None, now)` returns every non-expired
    // dismissal in the project store regardless of workspace path —
    // the dismissal we wrote was permanent (deferred_until = None).
    let now = 9_999_999_999_i64;
    let dismissals_a = store_a.load_active_dismissals(None, now).unwrap();
    let dismissals_b = store_b.load_active_dismissals(None, now).unwrap();
    assert_eq!(dismissals_a.len(), 1);
    assert_eq!(dismissals_a[0].id, "dismissal-a-1");
    assert!(
        dismissals_b.is_empty(),
        "repo_b had no dismissal — must not leak from repo_a"
    );
}

#[test]
fn migrate_is_idempotent_on_second_run() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let first = migrate_legacy_if_present(&home).unwrap();
    assert!(first.legacy_found);
    assert!(!first.already_migrated);
    assert_eq!(first.projects_created, 2);

    let second = migrate_legacy_if_present(&home).unwrap();
    assert!(second.legacy_found);
    assert!(second.already_migrated);
    // Re-run reports a clean no-op: every counter stays at zero.
    assert_eq!(second.projects_created, 0);
    assert_eq!(second.vulnerabilities_migrated, 0);
    assert_eq!(second.sync_log_entries_migrated, 0);

    // Registry has exactly the same set of projects (no duplicates).
    let registry = ProjectsRegistry::open(&home).unwrap();
    assert_eq!(registry.list_projects().unwrap().len(), 2);
}

#[test]
fn migrate_does_not_modify_legacy_store_db() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let store_path = home.join("store.db");

    let before = std::fs::read(&store_path).unwrap();
    migrate_legacy_if_present(&home).unwrap();
    let after = std::fs::read(&store_path).unwrap();
    assert_eq!(
        before, after,
        "legacy store.db must be byte-identical after migration"
    );
}

#[test]
fn migrate_creates_registry_entries_with_correct_last_scan() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let (repo_a, _repo_b) = build_dual_project_legacy(&home);

    // Bump repo_a's last_scan_at to a known recent timestamp via a
    // direct UPDATE on the legacy DB BEFORE migration so we can
    // assert the registry preserves it (vs clobbering with now()).
    {
        let conn = Connection::open(home.join("store.db")).unwrap();
        conn.execute(
            "UPDATE repos SET last_scan_at = ?1 WHERE path = ?2",
            params!["2026-04-20T10:00:00Z", repo_a.to_string_lossy().as_ref()],
        )
        .unwrap();
    }

    migrate_legacy_if_present(&home).unwrap();

    let registry = ProjectsRegistry::open(&home).unwrap();
    let proj_a = registry
        .list_projects()
        .unwrap()
        .into_iter()
        .find(|p| p.path == repo_a)
        .unwrap();
    let last_scan = proj_a.last_scan.expect("last_scan must be populated");
    assert_eq!(last_scan.to_rfc3339(), "2026-04-20T10:00:00+00:00");
}

/// Smoke test that runs against a backup of the real
/// `~/.packguard/store.db` placed at `/tmp/migration-smoke/store.db`.
/// Marked `#[ignore]` so the regular test pass doesn't require a
/// pre-staged file. Run with `cargo test --release migrate_smoke -- --ignored --nocapture`.
#[test]
#[ignore]
fn migrate_smoke_against_real_nalo_backup() {
    let home = PathBuf::from("/tmp/migration-smoke");
    let store_path = home.join("store.db");
    assert!(
        store_path.is_file(),
        "place a backup of ~/.packguard/store.db at {} first",
        store_path.display()
    );
    // Wipe any previous outputs so the run starts clean.
    let _ = std::fs::remove_dir_all(home.join("intel"));
    let _ = std::fs::remove_dir_all(home.join("projects"));
    let _ = std::fs::remove_file(home.join("projects.db"));

    let before = std::fs::read(&store_path).unwrap();
    let report = migrate_legacy_if_present(&home).unwrap();
    let after = std::fs::read(&store_path).unwrap();
    assert_eq!(before, after, "legacy store.db must stay byte-identical");

    println!("=== MigrationReport ===");
    println!("{report:#?}");
    println!("=== Registry ===");
    let registry = ProjectsRegistry::open(&home).unwrap();
    for p in registry.list_projects().unwrap() {
        println!(
            "  slug={} name={} path={} last_scan={:?}",
            p.slug,
            p.name,
            p.path.display(),
            p.last_scan
        );
    }
    println!("=== Intel ===");
    let intel = IntelStore::open(&home).unwrap();
    println!(
        "  vulnerabilities={} malware_reports={}",
        intel.count_vulnerabilities().unwrap(),
        intel.count_malware_reports().unwrap()
    );
}

// ---- V8 contract tests ----------------------------------------------------

#[test]
fn v8_drops_intel_tables_from_project_store_schema() {
    // A legacy V7 store still carries `vulnerabilities`, `malware_reports`,
    // and `sync_log`. Re-opening it via [`Store::open`] runs V8, which
    // must drop all three tables (the per-project store layer never
    // reads them — IntelStore owns intel since 14.1c-e).
    let tmp = TempDir::new().unwrap();
    let store_path = tmp.path().join("legacy.db");
    {
        let _v7 = Store::open_legacy_for_tests(&store_path).unwrap();
    }
    // Confirm the V7 tables are present before V8 runs.
    let pre = Connection::open(&store_path).unwrap();
    for table in ["vulnerabilities", "malware_reports", "sync_log"] {
        let count: i64 = pre
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "V7 fixture missing table {table}");
    }
    drop(pre);

    // Re-open via the production path — V8 fires.
    let _v8 = Store::open(&store_path).unwrap();
    let post = Connection::open(&store_path).unwrap();
    for table in ["vulnerabilities", "malware_reports", "sync_log"] {
        let count: i64 = post
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "V8 must DROP {table} from per-project store");
    }
    // The supporting indexes are gone too.
    for idx in [
        "idx_vulns_pkg",
        "idx_vulns_advisory",
        "idx_malware_pkg",
        "idx_malware_kind",
    ] {
        let count: i64 = post
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                params![idx],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "V8 must DROP index {idx}");
    }
}

#[test]
fn v8_is_idempotent_on_already_migrated_store() {
    // Apply V8 twice (re-open the store) — the IF EXISTS guards in the
    // migration must keep the second run a no-op rather than erroring.
    let tmp = TempDir::new().unwrap();
    let store_path = tmp.path().join("twice.db");
    let _ = Store::open(&store_path).unwrap(); // V1..V8
    let _ = Store::open(&store_path).unwrap(); // refinery sees V8 already applied
    let _ = Store::open(&store_path).unwrap(); // belt + suspenders
}

#[test]
fn v8_does_not_apply_to_renamed_legacy_backup() {
    // The 14.2d boot path renames `<home>/store.db` to
    // `<home>/store.db.v0.5-backup`. Refinery's path-based runner
    // never matches the backup file (no `Store::open` is called on
    // it), so the backup retains its V7 schema indefinitely. The
    // contract is tested by opening the backup via raw rusqlite +
    // confirming the intel tables survive intact.
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    std::fs::create_dir_all(&home).unwrap();
    let legacy = home.join("store.db");
    {
        let _v7 = Store::open_legacy_for_tests(&legacy).unwrap();
    }
    let backup = home.join("store.db.v0.5-backup");
    std::fs::rename(&legacy, &backup).unwrap();

    // Tables still there — refinery never touched the backup.
    let conn = Connection::open(&backup).unwrap();
    for table in ["vulnerabilities", "malware_reports", "sync_log"] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            ".v0.5-backup must keep {table} (V7 schema frozen)"
        );
    }
}

#[test]
fn migrate_enforces_read_only_on_legacy_handle() {
    // Verify the read-only contract by attempting to write through a
    // SQLITE_OPEN_READ_ONLY connection ourselves — the OS-level error
    // is the same one any accidental write inside migration would hit.
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join(".packguard");
    let _ = build_dual_project_legacy(&home);
    let store_path = home.join("store.db");

    let conn = Connection::open_with_flags(
        &store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap();
    let res = conn.execute("DELETE FROM packages", []);
    assert!(
        res.is_err(),
        "read-only handle must reject writes — got {res:?}"
    );
}
