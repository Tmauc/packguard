//! Dialect-aware matching of installed versions against OSV ranges.
//!
//! OSV advisories describe "affected" windows as ordered event streams:
//! `introduced` opens a window, then `fixed` / `last_affected` / `limit`
//! closes it. A version is affected when at least one window contains it.
//!
//! Per-ecosystem ordering:
//! - npm — `semver::Version`
//! - PyPI — `pep440_rs::Version`
//!
//! Anything else returns `false` (we don't ship other ecosystems yet).

use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, Severity, Vulnerability,
};
use std::cmp::Ordering;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedVuln {
    pub advisory_id: String,
    pub source: String,
    pub ecosystem: String,
    pub package_name: String,
    pub version: String,
    pub severity: Severity,
    pub cve_id: Option<String>,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub fixed_versions: Vec<String>,
    pub published_at: Option<String>,
}

/// Return every advisory in `advisories` that matches the given `version`,
/// deduplicated across OSV and GHSA via shared aliases (highest severity
/// wins). Order of `advisories` is preserved for ties.
pub fn match_vulnerabilities(
    ecosystem: &str,
    package_name: &str,
    version: &str,
    advisories: &[Vulnerability],
) -> Vec<MatchedVuln> {
    let mut raw = Vec::new();
    for adv in advisories {
        if adv.ecosystem != ecosystem || adv.package_name != package_name {
            continue;
        }
        if !version_matches_spec(ecosystem, version, &adv.affected) {
            continue;
        }
        raw.push(to_matched(adv, version));
    }
    dedup_by_aliases(raw)
}

fn to_matched(adv: &Vulnerability, version: &str) -> MatchedVuln {
    MatchedVuln {
        advisory_id: adv.advisory_id.clone(),
        source: adv.source.clone(),
        ecosystem: adv.ecosystem.clone(),
        package_name: adv.package_name.clone(),
        version: version.to_string(),
        severity: adv.severity,
        cve_id: adv.cve_id.clone(),
        aliases: adv.aliases.clone(),
        summary: adv.summary.clone(),
        url: adv.url.clone(),
        fixed_versions: adv.fixed_versions.clone(),
        published_at: adv.published_at.clone(),
    }
}

/// A version matches an `AffectedSpec` if either:
/// 1. The `versions` list explicitly contains it (string equality after
///    trivial normalization), OR
/// 2. At least one `ranges` entry contains it under its dialect.
pub fn version_matches_spec(ecosystem: &str, version: &str, spec: &AffectedSpec) -> bool {
    if spec
        .versions
        .iter()
        .any(|v| string_eq_version(ecosystem, v, version))
    {
        return true;
    }
    spec.ranges
        .iter()
        .any(|r| range_contains(ecosystem, version, r))
}

fn string_eq_version(ecosystem: &str, a: &str, b: &str) -> bool {
    match compare(ecosystem, a, b) {
        Some(Ordering::Equal) => true,
        _ => a == b,
    }
}

fn range_contains(ecosystem: &str, version: &str, range: &AffectedRange) -> bool {
    // GIT ranges are commit-based — version matching isn't meaningful.
    if matches!(range.kind, AffectedRangeKind::Git) {
        return false;
    }

    // Walk the ordered events and track whether we're currently "inside" a
    // window. An empty introduced keeps the window open from "-∞"; events
    // are processed in order so nested windows fold naturally.
    let mut inside = false;
    let mut introduced: Option<&str> = None;
    for ev in &range.events {
        match ev {
            AffectedEvent::Introduced(v) => {
                if is_introduced_zero(v) {
                    inside = true;
                    introduced = None;
                } else if cmp_ge(ecosystem, version, v) {
                    inside = true;
                    introduced = Some(v);
                } else {
                    inside = false;
                    introduced = Some(v);
                }
            }
            AffectedEvent::Fixed(v) => {
                if inside && cmp_lt(ecosystem, version, v) {
                    return true;
                }
                if introduced.is_some()
                    && cmp_ge(ecosystem, version, introduced.unwrap())
                    && cmp_lt(ecosystem, version, v)
                {
                    return true;
                }
                inside = false;
            }
            AffectedEvent::LastAffected(v) => {
                if inside && cmp_le(ecosystem, version, v) {
                    return true;
                }
                if introduced.is_some()
                    && cmp_ge(ecosystem, version, introduced.unwrap())
                    && cmp_le(ecosystem, version, v)
                {
                    return true;
                }
                inside = false;
            }
            AffectedEvent::Limit(v) => {
                if inside && cmp_lt(ecosystem, version, v) {
                    // Limit acts like a hard ceiling — below it we're still
                    // inside, above it we leave.
                    return true;
                }
                inside = false;
            }
        }
    }
    // Window still open at end-of-stream = everything after `introduced` is
    // affected.
    inside
}

fn is_introduced_zero(v: &str) -> bool {
    matches!(v, "0" | "0.0.0" | "0.0.0.0")
}

fn cmp(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    compare(ecosystem, a, b)
}

fn compare(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    match ecosystem {
        "npm" => {
            let a = semver::Version::parse(a).ok()?;
            let b = semver::Version::parse(b).ok()?;
            Some(a.cmp(&b))
        }
        "pypi" => {
            let a = pep440_rs::Version::from_str(a).ok()?;
            let b = pep440_rs::Version::from_str(b).ok()?;
            Some(a.cmp(&b))
        }
        _ => None,
    }
}

fn cmp_ge(ecosystem: &str, a: &str, b: &str) -> bool {
    matches!(
        cmp(ecosystem, a, b),
        Some(Ordering::Greater) | Some(Ordering::Equal)
    )
}

fn cmp_le(ecosystem: &str, a: &str, b: &str) -> bool {
    matches!(
        cmp(ecosystem, a, b),
        Some(Ordering::Less) | Some(Ordering::Equal)
    )
}

fn cmp_lt(ecosystem: &str, a: &str, b: &str) -> bool {
    matches!(cmp(ecosystem, a, b), Some(Ordering::Less))
}

/// Group matches whose alias sets overlap (including each other's
/// `advisory_id`). Keep the highest-severity representative per group,
/// preferring OSV when the severity is tied so the natural source wins.
fn dedup_by_aliases(matches: Vec<MatchedVuln>) -> Vec<MatchedVuln> {
    if matches.len() < 2 {
        return matches;
    }
    let n = matches.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut cur = x;
        while parent[cur] != cur {
            parent[cur] = parent[parent[cur]];
            cur = parent[cur];
        }
        cur
    }

    fn union(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }

    for i in 0..n {
        for j in (i + 1)..n {
            if share_ids(&matches[i], &matches[j]) {
                union(&mut parent, i, j);
            }
        }
    }

    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut out = Vec::with_capacity(groups.len());
    for (_, indices) in groups {
        let best = indices
            .iter()
            .map(|&i| &matches[i])
            .max_by(|a, b| {
                a.severity.cmp(&b.severity).then_with(|| {
                    // Tie-break: prefer OSV (alphabetical: ghsa < osv).
                    a.source.cmp(&b.source)
                })
            })
            .cloned()
            .expect("group is non-empty");
        out.push(best);
    }
    // Preserve input order for stable snapshots: re-sort by original index.
    out.sort_by_key(|m| {
        matches
            .iter()
            .position(|x| x.advisory_id == m.advisory_id && x.source == m.source)
            .unwrap_or(usize::MAX)
    });
    out
}

fn share_ids(a: &MatchedVuln, b: &MatchedVuln) -> bool {
    let a_ids: std::collections::BTreeSet<&String> = std::iter::once(&a.advisory_id)
        .chain(a.aliases.iter())
        .collect();
    let b_ids: std::collections::BTreeSet<&String> = std::iter::once(&b.advisory_id)
        .chain(b.aliases.iter())
        .collect();
    a_ids.intersection(&b_ids).next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::parse_advisory_json;

    fn parse(raw: &str) -> Vec<Vulnerability> {
        parse_advisory_json(raw.as_bytes(), "osv").unwrap()
    }

    #[test]
    fn npm_semver_range_matches_introduced_fixed() {
        let adv = parse(
            r#"{
                "id": "GHSA-x", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                              "ranges": [{"type": "SEMVER", "events": [
                                  {"introduced": "0.0.0"}, {"fixed": "4.17.21"}
                              ]}]}]
            }"#,
        );
        assert_eq!(
            match_vulnerabilities("npm", "lodash", "4.17.20", &adv).len(),
            1
        );
        assert_eq!(
            match_vulnerabilities("npm", "lodash", "4.17.21", &adv).len(),
            0
        );
        assert_eq!(
            match_vulnerabilities("npm", "lodash", "4.18.0", &adv).len(),
            0
        );
    }

    #[test]
    fn npm_explicit_versions_list_matches() {
        let adv = parse(
            r#"{
                "id": "COLORS-BAD", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "npm", "name": "colors"},
                              "versions": ["1.4.1", "1.4.2"]}]
            }"#,
        );
        assert_eq!(
            match_vulnerabilities("npm", "colors", "1.4.1", &adv).len(),
            1
        );
        assert_eq!(
            match_vulnerabilities("npm", "colors", "1.4.0", &adv).len(),
            0
        );
    }

    #[test]
    fn pypi_ecosystem_range_matches_via_pep440() {
        let adv = parse(
            r#"{
                "id": "PYSEC-1", "database_specific": {"severity": "MODERATE"},
                "affected": [{"package": {"ecosystem": "PyPI", "name": "django"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [
                                  {"introduced": "4.0"}, {"fixed": "4.2.7"}
                              ]}]}]
            }"#,
        );
        assert_eq!(
            match_vulnerabilities("pypi", "django", "4.2.6", &adv).len(),
            1
        );
        assert_eq!(
            match_vulnerabilities("pypi", "django", "4.2.7", &adv).len(),
            0
        );
        // Below the introduced boundary.
        assert_eq!(
            match_vulnerabilities("pypi", "django", "3.2.25", &adv).len(),
            0
        );
    }

    #[test]
    fn last_affected_closes_window_inclusively() {
        let adv = parse(
            r#"{
                "id": "X", "database_specific": {"severity": "LOW"},
                "affected": [{"package": {"ecosystem": "npm", "name": "p"},
                              "ranges": [{"type": "SEMVER", "events": [
                                  {"introduced": "1.0.0"}, {"last_affected": "1.5.0"}
                              ]}]}]
            }"#,
        );
        assert_eq!(match_vulnerabilities("npm", "p", "1.5.0", &adv).len(), 1);
        assert_eq!(match_vulnerabilities("npm", "p", "1.5.1", &adv).len(), 0);
    }

    #[test]
    fn git_ranges_never_match() {
        let adv = parse(
            r#"{
                "id": "X", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "npm", "name": "p"},
                              "ranges": [{"type": "GIT",
                                          "events": [{"introduced": "abc"}, {"fixed": "def"}]}]}]
            }"#,
        );
        assert!(match_vulnerabilities("npm", "p", "1.0.0", &adv).is_empty());
    }

    #[test]
    fn dedup_merges_osv_and_ghsa_sharing_cve_keeps_highest_severity() {
        // Two advisories for the same CVE — OSV claims MEDIUM, GHSA claims HIGH.
        // Dedup must return one match with HIGH severity.
        let matches = vec![
            MatchedVuln {
                advisory_id: "PYSEC-123".into(),
                source: "osv".into(),
                ecosystem: "pypi".into(),
                package_name: "foo".into(),
                version: "1.0.0".into(),
                severity: Severity::Medium,
                cve_id: Some("CVE-2024-0001".into()),
                aliases: vec!["CVE-2024-0001".into()],
                summary: None,
                url: None,
                fixed_versions: vec!["1.0.1".into()],
                published_at: None,
            },
            MatchedVuln {
                advisory_id: "GHSA-aaaa-bbbb-cccc".into(),
                source: "ghsa".into(),
                ecosystem: "pypi".into(),
                package_name: "foo".into(),
                version: "1.0.0".into(),
                severity: Severity::High,
                cve_id: Some("CVE-2024-0001".into()),
                aliases: vec!["CVE-2024-0001".into()],
                summary: None,
                url: None,
                fixed_versions: vec!["1.0.1".into()],
                published_at: None,
            },
        ];
        let out = dedup_by_aliases(matches);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].source, "ghsa");
    }

    #[test]
    fn dedup_keeps_independent_advisories() {
        let matches = vec![
            MatchedVuln {
                advisory_id: "A".into(),
                source: "osv".into(),
                ecosystem: "npm".into(),
                package_name: "p".into(),
                version: "1.0.0".into(),
                severity: Severity::High,
                cve_id: None,
                aliases: vec![],
                summary: None,
                url: None,
                fixed_versions: vec![],
                published_at: None,
            },
            MatchedVuln {
                advisory_id: "B".into(),
                source: "osv".into(),
                ecosystem: "npm".into(),
                package_name: "p".into(),
                version: "1.0.0".into(),
                severity: Severity::Medium,
                cve_id: None,
                aliases: vec![],
                summary: None,
                url: None,
                fixed_versions: vec![],
                published_at: None,
            },
        ];
        assert_eq!(dedup_by_aliases(matches).len(), 2);
    }
}
