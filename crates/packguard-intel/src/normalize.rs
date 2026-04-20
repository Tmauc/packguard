//! OSV advisory JSON → `packguard_core::Vulnerability`.
//!
//! GHSA publishes advisories in the exact same schema, so this module serves
//! both sources. Anything we can't interpret falls back to defaults rather
//! than erroring — a half-parsed advisory is still useful signal.

use anyhow::{Context, Result};
use packguard_core::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, Severity, Vulnerability,
};
use serde::Deserialize;

/// Raw OSV advisory, trimmed to the fields we actually read.
#[derive(Debug, Deserialize)]
pub struct RawAdvisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub severity: Vec<RawSeverity>,
    #[serde(default)]
    pub affected: Vec<RawAffected>,
    #[serde(default)]
    pub references: Vec<RawReference>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawSeverity {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub score: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawAffected {
    pub package: RawPackage,
    #[serde(default)]
    pub ranges: Vec<RawRange>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawPackage {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawRange {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawReference {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// Normalize one OSV/GHSA advisory into one `Vulnerability` per affected
/// package. Advisories touching unsupported ecosystems are dropped.
pub fn normalize(raw: RawAdvisory, source: &'static str) -> Vec<Vulnerability> {
    let severity = derive_severity(&raw);
    let cve_id = raw.aliases.iter().find(|a| a.starts_with("CVE-")).cloned();
    let primary_url = raw
        .references
        .iter()
        .find(|r| r.kind.as_deref() == Some("ADVISORY"))
        .and_then(|r| r.url.clone())
        .or_else(|| raw.references.iter().find_map(|r| r.url.clone()));

    let mut out = Vec::with_capacity(raw.affected.len());
    for aff in raw.affected {
        let Some(ecosystem) = normalize_ecosystem(&aff.package.ecosystem) else {
            continue;
        };
        let package_name = normalize_name(ecosystem, &aff.package.name);

        let ranges = aff
            .ranges
            .into_iter()
            .filter_map(parse_range)
            .collect::<Vec<_>>();
        let affected_spec = AffectedSpec {
            ranges,
            versions: aff.versions,
        };

        let fixed_versions = affected_spec
            .ranges
            .iter()
            .flat_map(|r| r.events.iter())
            .filter_map(|e| match e {
                AffectedEvent::Fixed(v) => Some(v.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        out.push(Vulnerability {
            source: source.to_string(),
            advisory_id: raw.id.clone(),
            ecosystem: ecosystem.to_string(),
            package_name,
            severity,
            cve_id: cve_id.clone(),
            aliases: raw.aliases.clone(),
            summary: raw.summary.clone(),
            url: primary_url.clone(),
            affected: affected_spec,
            fixed_versions,
            published_at: raw.published.clone(),
            modified_at: raw.modified.clone(),
        });
    }
    out
}

fn parse_range(raw: RawRange) -> Option<AffectedRange> {
    let kind = match raw.kind.to_ascii_uppercase().as_str() {
        "SEMVER" => AffectedRangeKind::Semver,
        "ECOSYSTEM" => AffectedRangeKind::Ecosystem,
        "GIT" => AffectedRangeKind::Git,
        _ => return None,
    };
    let events = raw
        .events
        .into_iter()
        .filter_map(parse_event)
        .collect::<Vec<_>>();
    if events.is_empty() {
        return None;
    }
    Some(AffectedRange { kind, events })
}

fn parse_event(raw: serde_json::Value) -> Option<AffectedEvent> {
    // OSV events are `{ "introduced": "x" }` one-key objects — take the first
    // key we can recognise.
    let obj = raw.as_object()?;
    let (key, val) = obj.iter().next()?;
    let version = val.as_str()?.to_string();
    match key.as_str() {
        "introduced" => Some(AffectedEvent::Introduced(version)),
        "fixed" => Some(AffectedEvent::Fixed(version)),
        "last_affected" => Some(AffectedEvent::LastAffected(version)),
        "limit" => Some(AffectedEvent::Limit(version)),
        _ => None,
    }
}

/// Map OSV ecosystem strings to the identifiers used in our `packages` rows.
/// Returns `None` for ecosystems we don't support in Phase 2 (`Go`, `Maven`,
/// `RubyGems`, …).
fn normalize_ecosystem(raw: &str) -> Option<&'static str> {
    // OSV suffixes an ecosystem sometimes (e.g. `Go:stdlib`). Strip it.
    let base = raw.split(':').next().unwrap_or(raw);
    match base {
        "npm" => Some("npm"),
        "PyPI" => Some("pypi"),
        _ => None,
    }
}

fn normalize_name(ecosystem: &str, raw: &str) -> String {
    if ecosystem == "pypi" {
        packguard_core::normalize_name(raw)
    } else {
        raw.to_string()
    }
}

/// Severity ladder:
/// 1. `database_specific.severity` (GitHub / OSV npm style) — a string.
/// 2. CVSS v3/v4 `score`, either a numeric string or a vector string.
/// 3. Default → Unknown.
fn derive_severity(raw: &RawAdvisory) -> Severity {
    if let Some(obj) = raw.database_specific.as_ref().and_then(|v| v.as_object()) {
        if let Some(s) = obj.get("severity").and_then(|v| v.as_str()) {
            let parsed = Severity::parse(s);
            if !matches!(parsed, Severity::Unknown) {
                return parsed;
            }
        }
    }
    for sev in &raw.severity {
        if let Some(score) = &sev.score {
            if let Some(parsed) = parse_cvss_score(score) {
                return parsed;
            }
        }
    }
    Severity::Unknown
}

/// Parse a CVSS score — either just a base score (`"7.5"`) or a full
/// vector starting with `CVSS:…`.
pub fn parse_cvss_score(raw: &str) -> Option<Severity> {
    let raw = raw.trim();
    if let Ok(score) = raw.parse::<f64>() {
        return Some(cvss_bucket(score));
    }
    // CVSS vector — we don't evaluate the metrics, but tools usually append
    // the base score on the RHS of an `/S:U/C:...` suffix. Short of a real
    // CVSS parser, fall back to Unknown when we can't read a numeric score.
    if raw.starts_with("CVSS:") {
        // Some tools append a numeric score after the vector separated by
        // whitespace. Harvest it when present.
        let tail = raw.split_whitespace().last().unwrap_or("");
        if let Ok(score) = tail.parse::<f64>() {
            return Some(cvss_bucket(score));
        }
    }
    None
}

fn cvss_bucket(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

/// Convenience: parse an advisory JSON document and normalize it.
pub fn parse_advisory_json(bytes: &[u8], source: &'static str) -> Result<Vec<Vulnerability>> {
    let raw: RawAdvisory = serde_json::from_slice(bytes).context("parsing OSV/GHSA advisory")?;
    Ok(normalize(raw, source))
}

/// Like `parse_advisory_json` but stops at the raw representation — used by
/// the malware harvester so it can re-route MAL entries before they hit the
/// vulnerability pipeline.
pub fn parse_advisory_json_raw(bytes: &[u8]) -> Result<RawAdvisory> {
    serde_json::from_slice(bytes).context("parsing OSV/GHSA advisory (raw)")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LODASH_ADVISORY: &str = r#"{
        "id": "GHSA-35jh-r3h4-6jhm",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "published": "2021-02-15T00:00:00Z",
        "modified": "2023-07-18T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0.0.0"}, {"fixed": "4.17.21"}]
            }]
        }],
        "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}],
        "database_specific": {"severity": "HIGH"}
    }"#;

    #[test]
    fn normalize_lodash_advisory() {
        let v = parse_advisory_json(LODASH_ADVISORY.as_bytes(), "osv").unwrap();
        assert_eq!(v.len(), 1);
        let v = &v[0];
        assert_eq!(v.advisory_id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(v.ecosystem, "npm");
        assert_eq!(v.package_name, "lodash");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.cve_id.as_deref(), Some("CVE-2021-23337"));
        assert_eq!(v.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(v.affected.ranges.len(), 1);
        assert_eq!(v.affected.ranges[0].kind, AffectedRangeKind::Semver);
    }

    #[test]
    fn normalize_pypi_advisory_lowercases_name_via_pep503() {
        let body = r#"{
            "id": "PYSEC-2023-12345",
            "aliases": [],
            "summary": "Django security fix",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "Django"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.2.7"}]}]
            }],
            "database_specific": {"severity": "MODERATE"}
        }"#;
        let v = parse_advisory_json(body.as_bytes(), "osv").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecosystem, "pypi");
        assert_eq!(v[0].package_name, "django");
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn normalize_drops_unsupported_ecosystems() {
        let body = r#"{
            "id": "GHSA-gogogo",
            "affected": [{"package": {"ecosystem": "Go", "name": "foo"}}]
        }"#;
        let v = parse_advisory_json(body.as_bytes(), "osv").unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn advisory_with_multiple_packages_fans_out() {
        let body = r#"{
            "id": "MULTI",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {"package": {"ecosystem": "npm", "name": "a"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
                {"package": {"ecosystem": "npm", "name": "b"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
            ]
        }"#;
        let v = parse_advisory_json(body.as_bytes(), "osv").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].package_name, "a");
        assert_eq!(v[1].package_name, "b");
    }

    #[test]
    fn cvss_bucket_boundaries() {
        assert_eq!(cvss_bucket(10.0), Severity::Critical);
        assert_eq!(cvss_bucket(9.0), Severity::Critical);
        assert_eq!(cvss_bucket(7.5), Severity::High);
        assert_eq!(cvss_bucket(4.0), Severity::Medium);
        assert_eq!(cvss_bucket(3.9), Severity::Low);
        assert_eq!(cvss_bucket(0.0), Severity::Unknown);
    }

    #[test]
    fn severity_falls_back_to_cvss_score_when_database_specific_missing() {
        let body = r#"{
            "id": "X",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "p"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.0.0"}]}]}]
        }"#;
        let v = parse_advisory_json(body.as_bytes(), "osv").unwrap();
        assert_eq!(v[0].severity, Severity::Critical);
    }
}
