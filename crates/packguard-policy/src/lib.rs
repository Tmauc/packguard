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
    BlockRule, Compliance, GroupRule, OverrideRule, Policy, PolicyDefaults, ReleaseInfo,
    ResolvedPolicy, Stability,
};
pub use parse::{load_policy, parse_policy, CONSERVATIVE_DEFAULTS_YAML};
pub use resolve::{compute_recommended_version, evaluate_dependency};

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
        let p = parse_policy("defaults:\n  offset: 0\n  stability: stable\n").unwrap();
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
        let p = parse_policy("defaults:\n  offset: -1\n  stability: stable\n").unwrap();
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
defaults: { offset: -1 }
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
        let p = parse_policy("defaults: { offset: 0, stability: stable }").unwrap();
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
        let p = parse_policy("defaults: { offset: 0, min_age_days: 7 }").unwrap();
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
defaults: { offset: -1 }
overrides:
  - match: "@babel/*"
    offset: -2
"#,
        )
        .unwrap();
        let resolved = p.resolve("@babel/core");
        assert_eq!(resolved.offset, 2);
        let resolved_other = p.resolve("react");
        assert_eq!(resolved_other.offset, 1);
    }

    #[test]
    fn group_rule_applies_when_name_matches() {
        let p = parse_policy(
            r#"
defaults: { offset: -1, min_age_days: 7 }
groups:
  - name: security-critical
    match: ["jsonwebtoken", "bcrypt*", "@auth/*"]
    offset: 0
    min_age_days: 0
"#,
        )
        .unwrap();
        let r = p.resolve("bcrypt-node");
        assert_eq!(r.offset, 0);
        assert_eq!(r.min_age_days, 0);
        let r = p.resolve("react");
        assert_eq!(r.offset, 1);
        assert_eq!(r.min_age_days, 7);
    }

    #[test]
    fn overrides_beat_groups() {
        let p = parse_policy(
            r#"
defaults: { offset: -1 }
groups:
  - name: g
    match: ["lodash"]
    offset: 0
overrides:
  - match: lodash
    offset: -3
"#,
        )
        .unwrap();
        assert_eq!(p.resolve("lodash").offset, 3);
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
        let p = parse_policy("defaults: { offset: 0 }").unwrap();
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
        let p = parse_policy("defaults: { offset: -1 }").unwrap();
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
        assert_eq!(p.defaults.offset, 0);
    }

    #[test]
    fn conservative_defaults_yaml_parses() {
        let p = parse_policy(CONSERVATIVE_DEFAULTS_YAML).unwrap();
        assert_eq!(p.defaults.offset, 1);
        assert_eq!(p.defaults.stability, Stability::Stable);
        assert_eq!(p.defaults.min_age_days, 7);
    }

    #[test]
    fn pep440_dialect_computes_recommended() {
        let p = parse_policy("defaults: { offset: 0 }").unwrap();
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
    fn fallback_uses_major_distance_when_only_latest_is_known() {
        // offset=-1 (one major behind) with *only* the latest release visible.
        // compute_recommended_version correctly returns None (offset window
        // excludes the latest), so evaluate falls back to major-distance.
        let p = parse_policy("defaults: { offset: -1 }").unwrap();
        // installed is in the allowed major-1 window → Compliant.
        let c = evaluate_dependency(
            "react",
            Some("18.3.0"),
            &p.resolve("react"),
            &rels(&[("19.2.5", "2026-04-08T00:00:00Z")]),
            Dialect::Semver,
            now(),
        );
        assert!(matches!(c, Compliance::Compliant), "got {c:?}");

        // installed two majors behind → Violation.
        let c = evaluate_dependency(
            "react",
            Some("17.0.0"),
            &p.resolve("react"),
            &rels(&[("19.2.5", "2026-04-08T00:00:00Z")]),
            Dialect::Semver,
            now(),
        );
        assert!(matches!(c, Compliance::Violation(_)), "got {c:?}");
    }

    #[test]
    fn pep440_prerelease_excluded_by_default() {
        let p = parse_policy("defaults: { offset: 0, stability: stable }").unwrap();
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
