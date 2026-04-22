//! Snapshot tests for the resolver against realistic registry histories.
//! Each test builds a (policy, fixture) pair and snapshots the resolver's
//! output — either the recommended version or the compliance verdict.

use packguard_policy::{
    compute_recommended_version, evaluate_dependency, parse_policy, Compliance, Dialect,
    ReleaseInfo,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct Fixture {
    #[allow(dead_code)]
    name: String,
    dialect: FixtureDialect,
    #[allow(dead_code)]
    latest: String,
    versions: Vec<FixtureVersion>,
}

#[derive(Debug, Deserialize)]
enum FixtureDialect {
    Semver,
    Pep440,
}

impl From<FixtureDialect> for Dialect {
    fn from(d: FixtureDialect) -> Self {
        match d {
            FixtureDialect::Semver => Dialect::Semver,
            FixtureDialect::Pep440 => Dialect::Pep440,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FixtureVersion {
    version: String,
    published_at: Option<String>,
    #[serde(default)]
    deprecated: bool,
    #[serde(default)]
    yanked: bool,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("registries")
}

fn load(name: &str) -> (Dialect, Vec<ReleaseInfo>) {
    let path = fixtures_dir().join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let fix: Fixture =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));
    let releases = fix
        .versions
        .into_iter()
        .map(|v| ReleaseInfo {
            version: v.version,
            published_at: v.published_at,
            deprecated: v.deprecated,
            yanked: v.yanked,
        })
        .collect();
    (fix.dialect.into(), releases)
}

/// A fixed "now" keeps the snapshots stable across days.
fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-04-20T00:00:00Z")
        .unwrap()
        .to_utc()
}

fn verdict(c: &Compliance) -> String {
    match c {
        Compliance::Compliant => "compliant".into(),
        Compliance::Warning(m) => format!("warning: {m}"),
        Compliance::Violation(m) => format!("violation: {m}"),
        Compliance::VulnerabilityViolation(v) => format!("cve-violation: {} vulns", v.len()),
        Compliance::MalwareViolation(m) => format!("malware: {} report(s)", m.len()),
        Compliance::TyposquatWarning(t) => format!("typosquat: {} suspect(s)", t.len()),
        Compliance::InsufficientCandidates(m) => format!("insufficient: {m}"),
    }
}

#[test]
fn react_offset_minus_one_lands_on_18() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { major: -1 }, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_zero_picks_latest_tip() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { major: 0 }, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_minus_two_lands_on_17() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { major: -2 } }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_minus_four_exhausts_history_to_insufficient() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { major: -4 } }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    let installed = Some("16.14.0");
    let c = evaluate_dependency(
        "react",
        installed,
        &policy.resolve("react"),
        &releases,
        dialect,
        now(),
    );
    insta::assert_yaml_snapshot!("react_offset_minus_four", (rec, verdict(&c)));
}

#[test]
fn react_stability_stable_excludes_19_0_0_rc_1() {
    let (dialect, releases) = load("react");
    // Prerelease variant picks the rc; stable skips it and returns 19.2.5.
    let stable = parse_policy("defaults: { offset: { major: 0 }, stability: stable }").unwrap();
    let prerelease =
        parse_policy("defaults: { offset: { major: 0 }, stability: prerelease }").unwrap();
    let pair = (
        compute_recommended_version(&stable.resolve("react"), &releases, dialect, now()),
        compute_recommended_version(&prerelease.resolve("react"), &releases, dialect, now()),
    );
    insta::assert_yaml_snapshot!("react_stability", pair);
}

#[test]
fn django_pep440_offset_minus_one_lands_on_5_1_4() {
    let (dialect, releases) = load("django");
    let policy = parse_policy("defaults: { offset: { major: -1 }, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn django_min_age_days_28_pushes_recommendation_back() {
    let (dialect, releases) = load("django");
    // Relative to 2026-04-20, min_age=28 days excludes 6.0.4 (2026-04-07),
    // 6.0.0 (2026-03-28), 5.1.4 (2026-02-28). Last qualifying 5.x is 5.0.11.
    let policy = parse_policy("defaults: { offset: { major: 0 }, min_age_days: 28 }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn django_offset_minus_four_insufficient() {
    let (dialect, releases) = load("django");
    let policy = parse_policy("defaults: { offset: { major: -4 } }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn babel_pin_override_wins_over_offset() {
    let (dialect, releases) = load("babel-core");
    let policy = parse_policy(
        r#"
defaults: { offset: { major: -1 } }
overrides:
  - match: "@babel/core"
    pin: "7.24.0"
"#,
    )
    .unwrap();
    let rec =
        compute_recommended_version(&policy.resolve("@babel/core"), &releases, dialect, now());
    let c = evaluate_dependency(
        "@babel/core",
        Some("7.20.0"),
        &policy.resolve("@babel/core"),
        &releases,
        dialect,
        now(),
    );
    insta::assert_yaml_snapshot!("babel_pin", (rec, verdict(&c)));
}

#[test]
fn babel_group_raises_offset_for_scoped_glob() {
    let (dialect, releases) = load("babel-core");
    let policy = parse_policy(
        r#"
defaults: { offset: { major: 0 } }
groups:
  - name: babel
    match: ["@babel/*"]
    offset: { major: -1 }
"#,
    )
    .unwrap();
    let rec =
        compute_recommended_version(&policy.resolve("@babel/core"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn node_ipc_yanked_version_is_flagged_as_violation() {
    let (dialect, releases) = load("node-ipc");
    let policy = parse_policy(
        r#"
defaults:
  offset: { major: 0 }
  block:
    yanked: true
    deprecated: true
"#,
    )
    .unwrap();
    // Installed is 10.1.2 — marked yanked + deprecated in the fixture.
    let c = evaluate_dependency(
        "node-ipc",
        Some("10.1.2"),
        &policy.resolve("node-ipc"),
        &releases,
        dialect,
        now(),
    );
    insta::assert_yaml_snapshot!("node_ipc_yanked", verdict(&c));
}

#[test]
fn node_ipc_clean_version_not_blocked() {
    let (dialect, releases) = load("node-ipc");
    let policy = parse_policy(
        r#"
defaults:
  offset: { major: 0 }
  block:
    yanked: true
    deprecated: true
"#,
    )
    .unwrap();
    // 11.1.0 is clean.
    let c = evaluate_dependency(
        "node-ipc",
        Some("11.1.0"),
        &policy.resolve("node-ipc"),
        &releases,
        dialect,
        now(),
    );
    insta::assert_yaml_snapshot!("node_ipc_clean", verdict(&c));
}

#[test]
fn node_ipc_yanked_ignored_when_block_disabled() {
    let (dialect, releases) = load("node-ipc");
    let policy = parse_policy("defaults: { offset: { major: 0 } }").unwrap();
    let c = evaluate_dependency(
        "node-ipc",
        Some("10.1.2"),
        &policy.resolve("node-ipc"),
        &releases,
        dialect,
        now(),
    );
    // block.yanked defaults to false → yanked install surfaces as a normal
    // "behind" verdict, not a violation.
    insta::assert_yaml_snapshot!("node_ipc_yanked_passthrough", verdict(&c));
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 9b — three-axis offset truth table.
//
// React fixture history (12 versions across majors 16/17/18/19):
//   16.14.0  17.0.0  17.0.2  18.0.0  18.2.0  18.3.1
//   19.0.0-rc.1  19.0.0  19.1.0  19.2.0  19.2.5  19.3.0-beta.1
// Latest stable = 19.2.5. Prereleases excluded by default stability.
// ─────────────────────────────────────────────────────────────────────────

fn rec_for(policy_yaml: &str) -> Option<String> {
    let (dialect, releases) = load("react");
    let policy = parse_policy(policy_yaml).unwrap();
    compute_recommended_version(&policy.resolve("react"), &releases, dialect, now())
}

#[test]
fn offset_3axes_all_zero_picks_19_2_5() {
    let rec = rec_for("defaults: { offset: { major: 0, minor: 0, patch: 0 } }");
    insta::assert_yaml_snapshot!("offset_all_zero", rec);
}

#[test]
fn offset_3axes_minor_minus_one_picks_19_1_0() {
    // {major:0, minor:-1} = "latest patches, one minor behind" (the
    // canonical security posture). Max minor on major 19 is 2 → target
    // minor = 1 → highest 19.1.x is 19.1.0.
    let rec = rec_for("defaults: { offset: { major: 0, minor: -1 } }");
    insta::assert_yaml_snapshot!("offset_minor_minus_one", rec);
}

#[test]
fn offset_3axes_patch_minus_one_picks_latest_non_final_patch() {
    // {major:0, minor:0, patch:-1}: target major 19, target minor 2
    // (max), target patch = max patch on 19.2 (which is 5) - 1 = 4.
    // No 19.2.4 in the fixture → InsufficientCandidates.
    let rec = rec_for("defaults: { offset: { major: 0, minor: 0, patch: -1 } }");
    insta::assert_yaml_snapshot!("offset_patch_minus_one", rec);
}

#[test]
fn offset_3axes_major_minus_one_picks_18_3_1() {
    // {major:-1}: target major 18, keep max minor (3) → 18.3.1.
    let rec = rec_for("defaults: { offset: { major: -1 } }");
    insta::assert_yaml_snapshot!("offset_major_minus_one", rec);
}

#[test]
fn offset_3axes_all_minus_one_picks_18() {
    // {major:-1, minor:-1, patch:-1}: target major 18, target minor =
    // (max minor 3) - 1 = 2, target patch = (max patch on 18.2 which is
    // 0) - 1 → underflow → InsufficientCandidates.
    let rec = rec_for("defaults: { offset: { major: -1, minor: -1, patch: -1 } }");
    insta::assert_yaml_snapshot!("offset_all_minus_one", rec);
}

#[test]
fn offset_3axes_minor_way_too_big_is_insufficient() {
    // {minor: -99} → offset.minor > max_minor → InsufficientCandidates
    // with a precise reason.
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { minor: -99 } }").unwrap();
    let c = evaluate_dependency(
        "react",
        Some("18.3.1"),
        &policy.resolve("react"),
        &releases,
        dialect,
        now(),
    );
    match &c {
        Compliance::InsufficientCandidates(msg) => {
            assert!(
                msg.contains("offset.minor")
                    && msg.contains("exceeds")
                    && msg.contains("latest minor"),
                "message didn't name the culprit axis: {msg}"
            );
        }
        other => panic!("expected InsufficientCandidates, got {other:?}"),
    }
    insta::assert_yaml_snapshot!("offset_minor_way_too_big", verdict(&c));
}

#[test]
fn offset_3axes_major_zero_patch_minus_one_variant_on_18() {
    // Combined axes drill: {major:-1, patch:-1}. Target major=18, max
    // minor=3 (keep), max patch on 18.3 is 1 → target patch=0 → pick
    // 18.3.0. No 18.3.0 in the fixture (only 18.3.1), so Insufficient.
    let rec = rec_for("defaults: { offset: { major: -1, patch: -1 } }");
    insta::assert_yaml_snapshot!("offset_major_minus_one_patch_minus_one", rec);
}

#[test]
fn offset_3axes_evaluation_trace_lines_are_informative() {
    // Cascade trace with the killer-combo policy produces 3 readable
    // lines naming each axis' target.
    use packguard_policy::build_offset_cascade_trace;
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: { major: 0, minor: -1 } }").unwrap();
    let trace = build_offset_cascade_trace(
        &policy.resolve("react"),
        &releases,
        &Default::default(),
        &[],
        dialect,
        now(),
    );
    assert_eq!(trace.recommended.as_deref(), Some("19.1.0"));
    assert!(
        trace.lines.iter().any(|l| l.contains("offset.major=0")),
        "lines: {:?}",
        trace.lines
    );
    assert!(
        trace
            .lines
            .iter()
            .any(|l| l.contains("offset.minor=1") && l.contains("target minor=1")),
        "lines: {:?}",
        trace.lines
    );
    assert!(
        trace.lines.iter().any(|l| l.contains("offset.patch=0")),
        "lines: {:?}",
        trace.lines
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Parse error tests — scalar form must produce a migration hint.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn scalar_offset_at_defaults_fails_with_migration_hint() {
    let err = parse_policy("defaults:\n  offset: -1\n").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("major/minor/patch"), "{msg}");
    assert!(msg.contains("offset-policy"), "{msg}");
}

#[test]
fn scalar_offset_in_override_fails_with_migration_hint() {
    let err = parse_policy(
        r#"
overrides:
  - match: "react"
    offset: 0
"#,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("major/minor/patch"), "{err:#}");
}

#[test]
fn scalar_offset_in_group_fails_with_migration_hint() {
    let err = parse_policy(
        r#"
groups:
  - name: g
    match: ["lodash"]
    offset: -2
"#,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("major/minor/patch"), "{err:#}");
}

#[test]
fn positive_axis_is_rejected() {
    let err = parse_policy("defaults:\n  offset: { major: 1 }\n").unwrap_err();
    assert!(
        format!("{err:#}").contains("offset.major must be 0 or negative"),
        "{err:#}"
    );
}

#[test]
fn unknown_axis_key_is_rejected() {
    let err = parse_policy("defaults:\n  offset:\n    semver: -1\n").unwrap_err();
    assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
}
