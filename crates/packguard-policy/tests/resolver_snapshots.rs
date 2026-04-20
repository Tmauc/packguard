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
        Compliance::InsufficientCandidates(m) => format!("insufficient: {m}"),
    }
}

#[test]
fn react_offset_minus_one_lands_on_18() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: -1, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_zero_picks_latest_tip() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: 0, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_minus_two_lands_on_17() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: -2 }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("react"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn react_offset_minus_four_exhausts_history_to_insufficient() {
    let (dialect, releases) = load("react");
    let policy = parse_policy("defaults: { offset: -4 }").unwrap();
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
    let stable = parse_policy("defaults: { offset: 0, stability: stable }").unwrap();
    let prerelease = parse_policy("defaults: { offset: 0, stability: prerelease }").unwrap();
    let pair = (
        compute_recommended_version(&stable.resolve("react"), &releases, dialect, now()),
        compute_recommended_version(&prerelease.resolve("react"), &releases, dialect, now()),
    );
    insta::assert_yaml_snapshot!("react_stability", pair);
}

#[test]
fn django_pep440_offset_minus_one_lands_on_5_1_4() {
    let (dialect, releases) = load("django");
    let policy = parse_policy("defaults: { offset: -1, stability: stable }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn django_min_age_days_28_pushes_recommendation_back() {
    let (dialect, releases) = load("django");
    // Relative to 2026-04-20, min_age=28 days excludes 6.0.4 (2026-04-07),
    // 6.0.0 (2026-03-28), 5.1.4 (2026-02-28). Last qualifying 5.x is 5.0.11.
    let policy = parse_policy("defaults: { offset: 0, min_age_days: 28 }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn django_offset_minus_four_insufficient() {
    let (dialect, releases) = load("django");
    let policy = parse_policy("defaults: { offset: -4 }").unwrap();
    let rec = compute_recommended_version(&policy.resolve("django"), &releases, dialect, now());
    insta::assert_yaml_snapshot!(rec);
}

#[test]
fn babel_pin_override_wins_over_offset() {
    let (dialect, releases) = load("babel-core");
    let policy = parse_policy(
        r#"
defaults: { offset: -1 }
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
defaults: { offset: 0 }
groups:
  - name: babel
    match: ["@babel/*"]
    offset: -1
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
  offset: 0
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
  offset: 0
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
    let policy = parse_policy("defaults: { offset: 0 }").unwrap();
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
