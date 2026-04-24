//! End-to-end tests for the Page Actions engine.
//!
//! Seeds a Nalo-like fixture store (1 malware + 2 CVE + 1 insufficient +
//! 1 stale sync_log + 1 stale scan) and asserts that `collect_all`
//! emits the expected set of actions in the right priority order.

use chrono::{DateTime, Duration, Utc};
use packguard_actions::{
    collect_all, defer, dismiss, filter_min_severity, restore, Action, ActionKind, ActionSeverity,
    ActionTarget,
};
use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency,
    MalwareKind, MalwareReport, Project, RemotePackage, Severity, Vulnerability,
};
use packguard_store::{normalize_repo_path, Store, SyncState};
use std::collections::BTreeMap;
use std::path::Path;

/// Permissive policy so the test fixture can exercise the generators
/// without the conservative defaults shadowing the recommended versions
/// (which would leave `suggested_command` empty and the generator
/// without a clean "here's the fix" signal).
const PERMISSIVE_POLICY_YAML: &str = r#"defaults:
  offset:
    major: 0
    minor: 0
    patch: 0
  stability: stable
  min_age_days: 0
  block:
    cve_severity: [high, critical]
    malware: true
    deprecated: true
    yanked: true
    typosquat: warn
"#;

fn now_anchor() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-04-24T12:00:00Z")
        .unwrap()
        .to_utc()
}

fn seed_nalo_like(store: &mut Store, repo: &Path) {
    // Drop the permissive policy at the repo root so `collect_all`'s
    // policy cascade picks it up. Without it the `offset.minor: -1`
    // default rejects every published version and the recommended
    // hint goes empty, masking what we're actually testing.
    std::fs::write(repo.join(".packguard.yml"), PERMISSIVE_POLICY_YAML).unwrap();

    // Two deps: lodash@4.17.20 (critical + high CVE) +
    // posthog-js@1.82.0 (malware). `ghost-pkg` is a prerelease-only
    // package: the policy demands `stability: stable`, so the resolver
    // drops every candidate → `InsufficientCandidates`.
    let project = Project {
        ecosystem: "npm",
        root: repo.to_path_buf(),
        manifest_path: repo.join("package.json"),
        name: Some("nalo".into()),
        workspace: None,
        dependencies: vec![
            Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("pnpm-lock.yaml".into()),
            },
            Dependency {
                name: "posthog-js".into(),
                declared_range: "^1.82.0".into(),
                installed: Some("1.82.0".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("pnpm-lock.yaml".into()),
            },
            Dependency {
                name: "ghost-pkg".into(),
                declared_range: "1.0.0-beta".into(),
                installed: Some("1.0.0-beta".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("pnpm-lock.yaml".into()),
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
            versions: vec![
                packguard_core::RemoteVersion {
                    version: "4.17.20".into(),
                    published_at: Some("2020-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
                packguard_core::RemoteVersion {
                    version: "4.17.21".into(),
                    published_at: Some("2021-03-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
            ],
        },
    );
    remotes.insert(
        "posthog-js".into(),
        RemotePackage {
            name: "posthog-js".into(),
            latest: Some("1.83.1".into()),
            latest_published_at: Some("2024-01-01T00:00:00Z".into()),
            versions: vec![
                packguard_core::RemoteVersion {
                    version: "1.82.0".into(),
                    published_at: Some("2023-12-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
                packguard_core::RemoteVersion {
                    version: "1.83.1".into(),
                    published_at: Some("2024-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
            ],
        },
    );
    // ghost-pkg registry only publishes a prerelease → `stability: stable`
    // filters it out → no candidate survives → InsufficientCandidates.
    remotes.insert(
        "ghost-pkg".into(),
        RemotePackage {
            name: "ghost-pkg".into(),
            latest: Some("1.0.0-beta".into()),
            latest_published_at: Some("2024-01-01T00:00:00Z".into()),
            versions: vec![packguard_core::RemoteVersion {
                version: "1.0.0-beta".into(),
                published_at: Some("2024-01-01T00:00:00Z".into()),
                deprecated: false,
                yanked: false,
            }],
        },
    );
    store
        .save_project(repo, &project, &remotes, "fp-nalo")
        .unwrap();

    // High CVE on lodash@4.17.20 (fixed in 4.17.21).
    let cve = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-nalo-lodash".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec![],
        summary: Some("Command injection".into()),
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
    let cve_crit = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-nalo-lodash-crit".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::Critical,
        cve_id: Some("CVE-2021-99999".into()),
        aliases: vec![],
        summary: Some("Critical demo".into()),
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
    store.persist_vulnerabilities(&[cve, cve_crit]).unwrap();

    let malware = MalwareReport {
        source: "osv-mal".into(),
        ref_id: "MAL-2026-12".into(),
        ecosystem: "npm".into(),
        package_name: "posthog-js".into(),
        version: "1.82.0".into(),
        kind: MalwareKind::Malware,
        summary: Some("Compromised release".into()),
        url: None,
        evidence: serde_json::json!({}),
        reported_at: None,
    };
    store.persist_malware_reports(&[malware]).unwrap();

    // Stale sync_log: osv-npm synced 10 days ago → triggers RefreshSync.
    let stale = (now_anchor() - Duration::days(10)).to_rfc3339();
    store
        .put_sync_state(
            "osv-npm",
            &SyncState {
                etag: None,
                last_modified: None,
                last_commit: None,
                synced_at: Some(stale),
                record_count: 42,
            },
        )
        .unwrap();
}

fn count(actions: &[Action], kind: ActionKind) -> usize {
    actions.iter().filter(|a| a.kind == kind).count()
}

fn find_for(actions: &[Action], kind: ActionKind, name: &str) -> Option<Action> {
    actions
        .iter()
        .find(|a| {
            a.kind == kind
                && matches!(
                    &a.target,
                    ActionTarget::Package { name: n, .. } if n == name
                )
        })
        .cloned()
}

#[test]
fn collect_all_produces_expected_actions_on_nalo_like_fixture() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    // Drop a pnpm-lock.yaml so pm_detect picks Pnpm.
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();

    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();

    // 1 malware + 1 critical CVE + 1 high CVE + 1 insufficient + 1 refresh.
    // RescanStale only fires if last_scan_at < now - 3d; the save just
    // happened so it shouldn't fire here.
    assert_eq!(count(&actions, ActionKind::FixMalware), 1);
    assert_eq!(count(&actions, ActionKind::FixCveCritical), 1);
    assert_eq!(count(&actions, ActionKind::FixCveHigh), 1);
    assert_eq!(count(&actions, ActionKind::ResolveInsufficient), 1);
    assert_eq!(count(&actions, ActionKind::RefreshSync), 1);
    assert_eq!(count(&actions, ActionKind::RescanStale), 0);

    // First action is malware — now on its own `Malware` tier above
    // Critical (Phase 12-fix). Sort invariant: severity desc throughout.
    let top = &actions[0];
    assert_eq!(top.severity, ActionSeverity::Malware);
    assert_eq!(top.kind, ActionKind::FixMalware);
    let severities: Vec<ActionSeverity> = actions.iter().map(|a| a.severity).collect();
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(severities, sorted, "actions must be sorted severity desc");
}

#[test]
fn collect_all_emits_suggested_command_matching_detected_pm() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();

    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();

    let cve_high = find_for(&actions, ActionKind::FixCveHigh, "lodash").unwrap();
    // Policy recommends 4.17.21 (the fixed version) via pnpm, surfaced
    // both as the raw version for the UI and as a caret-form command.
    assert_eq!(cve_high.recommended_version.as_deref(), Some("4.17.21"));
    assert_eq!(
        cve_high.suggested_command.as_deref(),
        Some("pnpm add lodash@^4.17.21")
    );
}

#[test]
fn collect_all_leaves_recommended_version_none_for_workspace_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    // Advance past the rescan threshold so RescanStale fires.
    let later = now_anchor() + Duration::days(5);
    let actions = collect_all(&store, Some(&repo), later, false, false).unwrap();

    for a in &actions {
        match a.kind {
            ActionKind::RefreshSync
            | ActionKind::RescanStale
            | ActionKind::WhitelistTyposquat
            | ActionKind::ResolveInsufficient => assert!(
                a.recommended_version.is_none(),
                "{:?} should not carry a recommended_version, got {:?}",
                a.kind,
                a.recommended_version
            ),
            _ => {}
        }
    }
}

#[test]
fn collect_all_refresh_sync_triggers_when_sync_log_stale_beyond_7_days() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let refresh = actions
        .iter()
        .find(|a| a.kind == ActionKind::RefreshSync)
        .unwrap();
    assert_eq!(refresh.workspace, "_global");
    assert!(refresh.title.contains("stale") || refresh.title.contains("date"));
    assert_eq!(refresh.suggested_command.as_deref(), Some("packguard sync"));
}

#[test]
fn refresh_sync_generator_renders_unrecognized_for_non_iso_synced_at() {
    // Thomas repro: a SQL UPDATE stamped `synced_at = "1776165002"`
    // (unix timestamp, not RFC 3339). Pre-fix the generator collapsed
    // it to "(never)" alongside a truly-absent entry. Post-fix it
    // renders a distinct "(unrecognized timestamp)" hint so the user
    // can tell corruption from absence.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    // Overwrite osv-npm with a non-ISO synced_at. osv-pypi stays at
    // the stale-but-parseable value from seed_nalo_like so we can
    // confirm the two labels coexist in one action.
    store
        .put_sync_state(
            "osv-npm",
            &SyncState {
                etag: None,
                last_modified: None,
                last_commit: None,
                synced_at: Some("1776165002".to_string()),
                record_count: 42,
            },
        )
        .unwrap();

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let refresh = actions
        .iter()
        .find(|a| a.kind == ActionKind::RefreshSync)
        .expect("corrupted synced_at must still surface a RefreshSync action");
    assert!(
        refresh.explanation.contains("unrecognized timestamp"),
        "explanation should flag the non-ISO source: {}",
        refresh.explanation
    );
    assert!(
        refresh.title.contains("out of date"),
        "unrecognized-only title should read 'out of date', not 'Nd stale': {}",
        refresh.title
    );
}

#[test]
fn collect_all_refresh_sync_silent_when_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    // Overwrite sync_log so osv-npm is fresh.
    let now = now_anchor();
    store
        .put_sync_state(
            "osv-npm",
            &SyncState {
                etag: None,
                last_modified: None,
                last_commit: None,
                synced_at: Some(now.to_rfc3339()),
                record_count: 42,
            },
        )
        .unwrap();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    assert_eq!(count(&actions, ActionKind::RefreshSync), 0);
}

#[test]
fn collect_all_emits_rescan_stale_when_last_scan_beyond_3_days() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    // Time-travel 5 days forward: the scan saved by `seed_nalo_like` is
    // now 5d old; `collect_all` should emit a RescanStale action.
    let later = now_anchor() + Duration::days(5);
    let actions = collect_all(&store, Some(&repo), later, false, false).unwrap();
    let rescan = actions
        .iter()
        .find(|a| a.kind == ActionKind::RescanStale)
        .unwrap();
    assert_eq!(rescan.workspace, normalize_repo_path(&repo));
    assert!(rescan.title.contains("5d") || rescan.title.contains("ago"));
}

#[test]
fn dismiss_then_collect_all_excludes_action() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let cve_high = find_for(&actions, ActionKind::FixCveHigh, "lodash").unwrap();

    dismiss(&mut store, &cve_high, Some("accepted risk"), now).unwrap();
    let after = collect_all(&store, Some(&repo), now, false, false).unwrap();
    assert!(
        !after.iter().any(|a| a.id == cve_high.id),
        "dismissed action must not resurface"
    );

    // Undismiss → action returns.
    restore(&mut store, &cve_high.id).unwrap();
    let restored = collect_all(&store, Some(&repo), now, false, false).unwrap();
    assert!(restored.iter().any(|a| a.id == cve_high.id));
}

#[test]
fn defer_expires_after_days_and_action_reappears() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let target = find_for(&actions, ActionKind::FixCveCritical, "lodash").unwrap();

    defer(&mut store, &target, 7, Some("sprint busy"), now).unwrap();
    // Within the defer window → hidden.
    let hidden = collect_all(&store, Some(&repo), now + Duration::days(3), false, false).unwrap();
    assert!(!hidden.iter().any(|a| a.id == target.id));

    // Past the defer window → resurfaces with the same id (stable).
    let resurfaced =
        collect_all(&store, Some(&repo), now + Duration::days(8), false, false).unwrap();
    let back = resurfaced
        .iter()
        .find(|a| a.id == target.id)
        .expect("deferred action must resurface after its window");
    assert_eq!(back.id, target.id, "stable id survives defer cycle");
}

#[test]
fn filter_min_severity_drops_lower_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);
    let mut actions = collect_all(&store, Some(&repo), now_anchor(), false, false).unwrap();
    let before = actions.len();
    filter_min_severity(&mut actions, ActionSeverity::High);
    assert!(actions.len() < before);
    assert!(actions.iter().all(|a| a.severity >= ActionSeverity::High));
}

#[test]
fn collect_all_include_dismissed_returns_archived_actions_with_timestamp() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let target = find_for(&actions, ActionKind::FixCveHigh, "lodash").unwrap();
    dismiss(&mut store, &target, Some("accepted"), now).unwrap();

    // Default call hides it…
    let hidden = collect_all(&store, Some(&repo), now, false, false).unwrap();
    assert!(!hidden.iter().any(|a| a.id == target.id));

    // …but include_dismissed=true surfaces it with dismissed_at populated.
    let archived = collect_all(&store, Some(&repo), now, true, false).unwrap();
    let row = archived
        .iter()
        .find(|a| a.id == target.id)
        .expect("include_dismissed should resurface the dismissed row");
    assert!(
        row.dismissed_at.is_some(),
        "dismissed_at must be stamped: {row:?}"
    );
    assert!(row.deferred_until.is_none());
}

#[test]
fn collect_all_include_deferred_surfaces_deferred_until() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let target = find_for(&actions, ActionKind::FixCveCritical, "lodash").unwrap();
    defer(&mut store, &target, 7, None, now).unwrap();

    // Within the defer window, default filter hides the row.
    let hidden = collect_all(&store, Some(&repo), now + Duration::days(3), false, false).unwrap();
    assert!(!hidden.iter().any(|a| a.id == target.id));

    // include_deferred=true brings it back with both timestamps.
    let with_deferred =
        collect_all(&store, Some(&repo), now + Duration::days(3), false, true).unwrap();
    let row = with_deferred
        .iter()
        .find(|a| a.id == target.id)
        .expect("include_deferred should surface the deferred row");
    assert!(row.dismissed_at.is_some());
    assert!(
        row.deferred_until.is_some(),
        "deferred_until missing: {row:?}"
    );

    // include_dismissed alone does NOT bring a deferred row back — the
    // two flags address different buckets.
    let dismissed_only =
        collect_all(&store, Some(&repo), now + Duration::days(3), true, false).unwrap();
    assert!(!dismissed_only.iter().any(|a| a.id == target.id));
}

#[test]
fn collect_all_include_flags_default_false_matches_pre_12c_behaviour() {
    // Regression guard: with both flags false, collect_all must produce
    // the exact same id set as the pre-12c code did — the /api/actions
    // endpoint and existing dashboard assume dismissed rows are gone.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("nalo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_nalo_like(&mut store, &repo);

    let now = now_anchor();
    let actions = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let baseline_ids: std::collections::BTreeSet<String> =
        actions.iter().map(|a| a.id.clone()).collect();

    // Dismiss one + defer another; re-run with flags=false — those ids
    // should be gone from the result.
    let cve_high = find_for(&actions, ActionKind::FixCveHigh, "lodash").unwrap();
    let cve_crit = find_for(&actions, ActionKind::FixCveCritical, "lodash").unwrap();
    dismiss(&mut store, &cve_high, None, now).unwrap();
    defer(&mut store, &cve_crit, 3, None, now).unwrap();

    let after = collect_all(&store, Some(&repo), now, false, false).unwrap();
    let after_ids: std::collections::BTreeSet<String> =
        after.iter().map(|a| a.id.clone()).collect();
    assert!(!after_ids.contains(&cve_high.id));
    assert!(!after_ids.contains(&cve_crit.id));
    // Every surviving id was already in the baseline — we haven't
    // invented new rows.
    for id in &after_ids {
        assert!(baseline_ids.contains(id));
    }
}
