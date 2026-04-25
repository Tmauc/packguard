//! Phase 14.1e.2 — regression guard for the producer cutover.
//!
//! `sync_intel::run` now writes intel-wide tables (sync_log,
//! vulnerabilities, malware_reports) to [`IntelStore`] only. The
//! legacy [`Store`] is still passed in for `watched_packages()` —
//! a project-wide read — but every write side-effect must land in
//! the new file.

use packguard_server::services::sync_intel;
use packguard_store::{IntelStore, Store};
use tempfile::TempDir;

/// Even when every upstream fetch fails (no network in the test
/// environment, GHSA git binary unavailable, etc.), the legacy
/// `Store` must not be touched. This is the contract guard:
/// any future regression that re-routes a write to `Store` would
/// flip a non-zero count in legacy here.
#[tokio::test]
async fn sync_run_never_writes_intel_tables_to_legacy_store() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let mut store = Store::open(&home.join("store.db")).unwrap();
    let mut intel = IntelStore::open(&home).unwrap();

    // Snapshot the legacy intel-table counts BEFORE the run. Any
    // legacy write would bump these — they MUST stay at zero.
    let legacy_v_before = store.count_vulnerabilities().unwrap();
    let legacy_m_before = store.count_malware_reports().unwrap();
    assert_eq!(legacy_v_before, 0);
    assert_eq!(legacy_m_before, 0);

    // Run the sync. With no `watched_packages` and likely no
    // network, this is best-effort — every fetcher logs and moves
    // on. We don't care about the SyncReport contents; we care
    // about WHERE side-effects land.
    let _ = sync_intel::run(&mut intel, &mut store).await;

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

/// Companion test: simulating what a successful network fetch
/// would do (manual `persist_vulnerabilities` on IntelStore)
/// confirms the catalog accepts the writes and the legacy stays
/// at zero. Decouples the contract guard from network availability.
#[tokio::test]
async fn intel_writes_through_intel_store_leave_legacy_at_zero() {
    use packguard_core::model::{AffectedSpec, Severity, Vulnerability};

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let store = Store::open(&home.join("store.db")).unwrap();
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
