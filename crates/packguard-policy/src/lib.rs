//! PackGuard policy engine — parses `.packguard.yml`, resolves per-package
//! rules (defaults + groups + overrides), and computes a recommended version
//! from the set of versions advertised by a registry.
//!
//! Phase 1 scope: offset, pin, stability, min_age_days. The `block` section
//! is parsed and stored but evaluated in Phase 2 once vuln intel lands.

mod dialect;
mod model;
mod parse;
mod resolve;

pub use dialect::{Dialect, VersionMeta};
pub use model::{
    BlockRule, Compliance, GroupRule, Offset, OverrideRule, Policy, PolicyDefaults, ReleaseInfo,
    ResolvedPolicy, Stability, TyposquatPolicy,
};
pub use parse::{load_policy, parse_policy, CONSERVATIVE_DEFAULTS_YAML};
pub use resolve::{
    build_offset_cascade_trace, compute_recommended_version, compute_recommended_version_full,
    compute_recommended_version_with_vulns, evaluate_dependency, evaluate_dependency_full,
    evaluate_dependency_with_vulns, OffsetCascadeTrace, VulnsByVersion,
};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rels(pairs: &[(&str, &str)]) -> Vec<ReleaseInfo> {
        pairs
            .iter()
            .map(|(v, t)| ReleaseInfo {
                version: (*v).to_string(),
                published_at: Some((*t).to_string()),
                deprecated: false,
                yanked: false,
            })
            .collect()
    }

    const NOW: &str = "2026-04-20T00:00:00Z";

    fn now() -> chrono::DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339(NOW).unwrap().to_utc()
    }

    #[test]
    fn offset_zero_recommends_latest_minor_patch() {
        let p = parse_policy("defaults:\n  offset: { major: 0 }\n  stability: stable\n").unwrap();
        let r = compute_recommended_version(
            &p.resolve("react"),
            &rels(&[
                ("18.2.0", "2024-01-01T00:00:00Z"),
                ("18.3.0", "2024-06-01T00:00:00Z"),
                ("19.0.0", "2025-06-01T00:00:00Z"),
                ("19.2.5", "2026-04-08T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert_eq!(r.as_deref(), Some("19.2.5"));
    }

    #[test]
    fn offset_one_stays_one_major_behind() {
        let p = parse_policy("defaults:\n  offset: { major: -1 }\n  stability: stable\n").unwrap();
        let r = compute_recommended_version(
            &p.resolve("react"),
            &rels(&[
                ("18.2.0", "2024-01-01T00:00:00Z"),
                ("18.3.0", "2024-06-01T00:00:00Z"),
                ("19.0.0", "2025-06-01T00:00:00Z"),
                ("19.2.5", "2026-04-08T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert_eq!(r.as_deref(), Some("18.3.0"));
    }

    #[test]
    fn pin_wins_over_offset() {
        let p = parse_policy(
            r#"
defaults: { offset: { major: -1 } }
overrides:
  - match: lodash
    pin: 4.17.21
"#,
        )
        .unwrap();
        let r = compute_recommended_version(
            &p.resolve("lodash"),
            &rels(&[
                ("4.17.20", "2024-01-01T00:00:00Z"),
                ("4.17.21", "2024-06-01T00:00:00Z"),
                ("5.0.0", "2025-01-01T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert_eq!(r.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn stability_stable_excludes_prereleases() {
        let p = parse_policy("defaults: { offset: { major: 0 }, stability: stable }").unwrap();
        let r = compute_recommended_version(
            &p.resolve("foo"),
            &rels(&[
                ("2.0.0-beta.1", "2026-04-01T00:00:00Z"),
                ("1.9.0", "2025-01-01T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert_eq!(r.as_deref(), Some("1.9.0"));
    }

    #[test]
    fn min_age_days_excludes_fresh_releases() {
        let p = parse_policy("defaults: { offset: { major: 0 }, min_age_days: 7 }").unwrap();
        let r = compute_recommended_version(
            &p.resolve("foo"),
            &rels(&[
                ("1.0.0", "2026-01-01T00:00:00Z"),
                ("1.1.0", "2026-04-17T00:00:00Z"), // 3 days ago → excluded
            ]),
            Dialect::Semver,
            now(),
        );
        assert_eq!(r.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn glob_overrides_select_the_right_rule() {
        let p = parse_policy(
            r#"
defaults: { offset: { major: -1 } }
overrides:
  - match: "@babel/*"
    offset: { major: -2 }
"#,
        )
        .unwrap();
        let resolved = p.resolve("@babel/core");
        assert_eq!(resolved.offset, Offset::from_axes(-2, 0, 0));
        let resolved_other = p.resolve("react");
        assert_eq!(resolved_other.offset, Offset::from_axes(-1, 0, 0));
    }

    #[test]
    fn group_rule_applies_when_name_matches() {
        let p = parse_policy(
            r#"
defaults: { offset: { major: -1 }, min_age_days: 7 }
groups:
  - name: security-critical
    match: ["jsonwebtoken", "bcrypt*", "@auth/*"]
    offset: { major: 0 }
    min_age_days: 0
"#,
        )
        .unwrap();
        let r = p.resolve("bcrypt-node");
        assert_eq!(r.offset, Offset::ZERO);
        assert_eq!(r.min_age_days, 0);
        let r = p.resolve("react");
        assert_eq!(r.offset, Offset::from_axes(-1, 0, 0));
        assert_eq!(r.min_age_days, 7);
    }

    #[test]
    fn overrides_beat_groups() {
        let p = parse_policy(
            r#"
defaults: { offset: { major: -1 } }
groups:
  - name: g
    match: ["lodash"]
    offset: { major: 0 }
overrides:
  - match: lodash
    offset: { major: -3 }
"#,
        )
        .unwrap();
        assert_eq!(p.resolve("lodash").offset, Offset::from_axes(-3, 0, 0));
    }

    #[test]
    fn evaluate_reports_violation_on_pin_mismatch() {
        let p = parse_policy(
            r#"
overrides:
  - match: lodash
    pin: 4.17.21
"#,
        )
        .unwrap();
        let c = evaluate_dependency(
            "lodash",
            Some("4.17.20"),
            &p.resolve("lodash"),
            &rels(&[
                ("4.17.20", "2024-01-01T00:00:00Z"),
                ("4.17.21", "2024-02-01T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert!(matches!(c, Compliance::Violation(_)));
    }

    #[test]
    fn evaluate_reports_warning_on_behind() {
        let p = parse_policy("defaults: { offset: { major: 0 } }").unwrap();
        let c = evaluate_dependency(
            "foo",
            Some("1.0.0"),
            &p.resolve("foo"),
            &rels(&[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("1.1.0", "2024-06-01T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert!(matches!(c, Compliance::Warning(_)), "got {c:?}");
    }

    #[test]
    fn evaluate_is_compliant_when_installed_matches_recommendation() {
        let p = parse_policy("defaults: { offset: { major: -1 } }").unwrap();
        let c = evaluate_dependency(
            "react",
            Some("18.3.0"),
            &p.resolve("react"),
            &rels(&[
                ("18.3.0", "2024-06-01T00:00:00Z"),
                ("19.0.0", "2025-06-01T00:00:00Z"),
            ]),
            Dialect::Semver,
            now(),
        );
        assert!(matches!(c, Compliance::Compliant), "got {c:?}");
    }

    #[test]
    fn empty_yaml_produces_conservative_defaults() {
        let p = parse_policy("").unwrap();
        assert_eq!(p.defaults.offset, Offset::ZERO);
    }

    #[test]
    fn conservative_defaults_yaml_parses() {
        let p = parse_policy(CONSERVATIVE_DEFAULTS_YAML).unwrap();
        // Phase 9b default: stay on latest major, one minor behind, always
        // pick the latest patch — the canonical security posture.
        assert_eq!(p.defaults.offset, Offset::from_axes(0, -1, 0));
        assert_eq!(p.defaults.stability, Stability::Stable);
        assert_eq!(p.defaults.min_age_days, 7);
    }

    #[test]
    fn pep440_dialect_computes_recommended() {
        let p = parse_policy("defaults: { offset: { major: 0 } }").unwrap();
        let r = compute_recommended_version(
            &p.resolve("django"),
            &rels(&[
                ("4.2.7", "2024-01-01T00:00:00Z"),
                ("5.0.0", "2024-06-01T00:00:00Z"),
                ("5.0.1", "2024-07-01T00:00:00Z"),
            ]),
            Dialect::Pep440,
            now(),
        );
        assert_eq!(r.as_deref(), Some("5.0.1"));
    }

    #[test]
    fn insufficient_candidates_when_history_too_narrow_for_offset() {
        // offset=-1 asks for the major *below* the latest one. If the store
        // only holds the latest version, no candidate survives → the new
        // status variant tells the user to rescan for history.
        let p = parse_policy("defaults: { offset: { major: -1 } }").unwrap();
        let c = evaluate_dependency(
            "react",
            Some("18.3.0"),
            &p.resolve("react"),
            &rels(&[("19.2.5", "2026-04-08T00:00:00Z")]),
            Dialect::Semver,
            now(),
        );
        assert!(
            matches!(c, Compliance::InsufficientCandidates(_)),
            "got {c:?}"
        );
    }

    #[test]
    fn insufficient_candidates_on_empty_history() {
        let p = parse_policy("defaults: { offset: { major: 0 } }").unwrap();
        let c = evaluate_dependency(
            "react",
            Some("18.3.0"),
            &p.resolve("react"),
            &[],
            Dialect::Semver,
            now(),
        );
        match c {
            Compliance::InsufficientCandidates(msg) => {
                assert!(msg.contains("no version history"), "msg: {msg}");
            }
            other => panic!("expected InsufficientCandidates, got {other:?}"),
        }
    }

    fn vuln(advisory: &str, severity: packguard_core::Severity) -> packguard_intel::MatchedVuln {
        packguard_intel::MatchedVuln {
            advisory_id: advisory.to_string(),
            source: "osv".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            version: String::new(),
            severity,
            cve_id: Some(format!("CVE-FAKE-{advisory}")),
            aliases: vec![],
            summary: None,
            url: None,
            fixed_versions: vec!["4.17.21".into()],
            published_at: None,
        }
    }

    #[test]
    fn cve_severity_on_installed_triggers_vulnerability_violation() {
        let p = parse_policy(
            r#"
defaults:
  offset: { major: 0 }
  block:
    cve_severity: [high, critical]
"#,
        )
        .unwrap();
        let mut vulns: crate::VulnsByVersion = Default::default();
        vulns.insert(
            "4.17.20".into(),
            vec![vuln("GHSA-bad", packguard_core::Severity::High)],
        );
        let c = evaluate_dependency_with_vulns(
            "lodash",
            Some("4.17.20"),
            &p.resolve("lodash"),
            &rels(&[
                ("4.17.20", "2024-01-01T00:00:00Z"),
                ("4.17.21", "2024-02-01T00:00:00Z"),
            ]),
            &vulns,
            Dialect::Semver,
            now(),
        );
        match c {
            Compliance::VulnerabilityViolation(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].advisory_id, "GHSA-bad");
            }
            other => panic!("expected VulnerabilityViolation, got {other:?}"),
        }
    }

    #[test]
    fn cve_severity_below_block_threshold_does_not_violate() {
        let p = parse_policy(
            r#"
defaults:
  offset: { major: 0 }
  block:
    cve_severity: [critical]
"#,
        )
        .unwrap();
        let mut vulns: crate::VulnsByVersion = Default::default();
        vulns.insert(
            "4.17.20".into(),
            vec![vuln("GHSA-mid", packguard_core::Severity::High)],
        );
        let c = evaluate_dependency_with_vulns(
            "lodash",
            Some("4.17.20"),
            &p.resolve("lodash"),
            &rels(&[
                ("4.17.20", "2024-01-01T00:00:00Z"),
                ("4.17.21", "2024-02-01T00:00:00Z"),
            ]),
            &vulns,
            Dialect::Semver,
            now(),
        );
        // High isn't in the block list (only `critical` is) → falls through
        // to the normal "behind the recommended" warning.
        assert!(matches!(c, Compliance::Warning(_)), "got {c:?}");
    }

    #[test]
    fn remediation_skips_vulnerable_recommendation() {
        // offset=0 normally recommends 4.17.21. When that tip has a blocking
        // CVE, the resolver falls back to 4.17.20.
        let p = parse_policy(
            r#"
defaults:
  offset: { major: 0 }
  block:
    cve_severity: [high, critical]
"#,
        )
        .unwrap();
        let releases = rels(&[
            ("4.17.18", "2024-01-01T00:00:00Z"),
            ("4.17.20", "2024-02-01T00:00:00Z"),
            ("4.17.21", "2024-03-01T00:00:00Z"),
        ]);

        let mut vulns_tip: crate::VulnsByVersion = Default::default();
        vulns_tip.insert(
            "4.17.21".into(),
            vec![vuln("GHSA-at-tip", packguard_core::Severity::High)],
        );
        let rec_tip = compute_recommended_version_with_vulns(
            &p.resolve("lodash"),
            &releases,
            &vulns_tip,
            Dialect::Semver,
            now(),
        );
        assert_eq!(rec_tip.as_deref(), Some("4.17.20"));

        // All three candidates vulnerable → None.
        let mut vulns_all = vulns_tip.clone();
        vulns_all.insert(
            "4.17.20".into(),
            vec![vuln("GHSA-2", packguard_core::Severity::High)],
        );
        vulns_all.insert(
            "4.17.18".into(),
            vec![vuln("GHSA-3", packguard_core::Severity::High)],
        );
        let rec_all = compute_recommended_version_with_vulns(
            &p.resolve("lodash"),
            &releases,
            &vulns_all,
            Dialect::Semver,
            now(),
        );
        assert!(rec_all.is_none());
    }

    #[test]
    fn pep440_prerelease_excluded_by_default() {
        let p = parse_policy("defaults: { offset: { major: 0 }, stability: stable }").unwrap();
        let r = compute_recommended_version(
            &p.resolve("foo"),
            &rels(&[
                ("1.0.0", "2024-01-01T00:00:00Z"),
                ("2.0.0a1", "2024-06-01T00:00:00Z"),
            ]),
            Dialect::Pep440,
            now(),
        );
        assert_eq!(r.as_deref(), Some("1.0.0"));
    }
}
