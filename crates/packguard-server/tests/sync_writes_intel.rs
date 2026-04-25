//! Phase 14.1e.2 / 14.2b.2.4 — regression guard for the sync
//! cutover.
//!
//! `sync_intel::run` writes intel-wide tables (sync_log,
//! vulnerabilities, malware_reports) to [`IntelStore`] only and
//! sources `watched_packages` via [`ProjectStoreCache::slug_paths`]
//! across every per-project store. The legacy [`Store`] is no
//! longer touched by sync — neither for reads nor for writes.

use packguard_server::services::sync_intel;
use packguard_store::{IntelStore, ProjectStoreCache, Store};
use tempfile::TempDir;

/// 14.2d follow-up: now that V8 drops `vulnerabilities` and
/// `malware_reports` from every per-project store schema, the only
/// way a stray legacy write could land somewhere is into a V7-shaped
/// fixture — i.e. exactly the file we keep as `.v0.5-backup`. Seed
/// such a fixture, run sync, and confirm the V7 counts stay at zero.
#[tokio::test]
async fn sync_run_never_writes_intel_tables_to_legacy_store() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    // V7 fixture so the intel tables exist + are queryable; otherwise
    // the test would be tautologically guaranteed by V8.
    let store = Store::open_legacy_for_tests(&home.join("store.db")).unwrap();
    let mut intel = IntelStore::open(&home).unwrap();
    let project_stores = ProjectStoreCache::new(home.clone());

    let legacy_v_before = store.count_vulnerabilities().unwrap();
    let legacy_m_before = store.count_malware_reports().unwrap();
    assert_eq!(legacy_v_before, 0);
    assert_eq!(legacy_m_before, 0);

    let _ = sync_intel::run(&mut intel, &project_stores).await;

    let legacy_v_after = store.count_vulnerabilities().unwrap();
    let legacy_m_after = store.count_malware_reports().unwrap();
    assert_eq!(
        legacy_v_after, legacy_v_before,
        "legacy vulnerabilities count must stay unchanged after sync"
    );
    assert_eq!(
        legacy_m_after, legacy_m_before,
        "legacy malware_reports count must stay unchanged after sync"
    );
}

/// Phase 14.2b.2.4 — `watched_packages` reads union across every
/// per-project store under `<home>/projects/<slug>/store.db`. Seed
/// two stores with disjoint workspaces; the sync's typosquat
/// scorer should observe both (proven indirectly via the
/// `WatchedPackages` value, but here we exercise the helper that
/// builds it).
#[tokio::test]
async fn sync_watched_packages_unions_across_project_stores() {
    use packguard_core::model::{DepKind, Dependency, Project};
    use std::collections::BTreeMap;

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let project_stores = ProjectStoreCache::new(home.clone());

    // Slug A: tracks lodash.
    let repo_a = home.join("projects/alpha-root");
    std::fs::create_dir_all(&repo_a).unwrap();
    {
        let pstore = project_stores.get_or_open("alpha").await.unwrap();
        let mut pstore = pstore.lock().await;
        let p = Project {
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
        pstore
            .save_project(&repo_a, &p, &BTreeMap::new(), "fp-a")
            .unwrap();
    }
    // Slug B: tracks express. Disjoint from alpha — proves union.
    let repo_b = home.join("projects/beta-root");
    std::fs::create_dir_all(&repo_b).unwrap();
    {
        let pstore = project_stores.get_or_open("beta").await.unwrap();
        let mut pstore = pstore.lock().await;
        let p = Project {
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
        pstore
            .save_project(&repo_b, &p, &BTreeMap::new(), "fp-b")
            .unwrap();
    }

    // Run the sync flow end-to-end. Network failures are tolerated;
    // we only care that `watched_packages` was unioned correctly.
    let mut intel = IntelStore::open(&home).unwrap();
    let _ = sync_intel::run(&mut intel, &project_stores).await;

    // Indirectly: the typosquat scorer fans across the union and
    // tags either lodash or express if its name lands close to a
    // top-N legitimate package — which it doesn't. The assertion is
    // weaker but exercises the union path: the run must not panic.
    // For a stronger check on `slug_paths` correctness, see
    // `project_store_cache::tests::slug_paths_lists_directories…`.
    let paths = project_stores.slug_paths().unwrap();
    let slugs: Vec<&str> = paths.iter().map(|(s, _)| s.as_str()).collect();
    assert!(slugs.contains(&"alpha"));
    assert!(slugs.contains(&"beta"));
}

/// Companion test: simulating what a successful network fetch
/// would do (manual `persist_vulnerabilities` on IntelStore)
/// confirms the catalog accepts the writes and the legacy stays
/// at zero. Decouples the contract guard from network availability.
#[tokio::test]
async fn intel_writes_through_intel_store_leave_legacy_at_zero() {
    use packguard_core::model::{AffectedSpec, Severity, Vulnerability};

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    // V7 legacy so `count_vulnerabilities` is queryable post-V8.
    let store = Store::open_legacy_for_tests(&home.join("store.db")).unwrap();
    let mut intel = IntelStore::open(&home).unwrap();

    intel
        .persist_vulnerabilities(&[Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-test".into(),
            ecosystem: "npm".into(),
            package_name: "left-pad".into(),
            severity: Severity::Medium,
            cve_id: None,
            aliases: vec![],
            summary: None,
            url: None,
            affected: AffectedSpec::default(),
            fixed_versions: vec![],
            published_at: None,
            modified_at: None,
        }])
        .unwrap();

    assert_eq!(intel.count_vulnerabilities().unwrap(), 1);
    assert_eq!(store.count_vulnerabilities().unwrap(), 0);
    assert_eq!(store.count_malware_reports().unwrap(), 0);
}
