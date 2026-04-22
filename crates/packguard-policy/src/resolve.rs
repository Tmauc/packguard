//! Rule resolution + recommended-version + compliance evaluation.
//!
//! # Phase 9b — three-axis offset cascade
//!
//! Given `latest = X.Y.Z` and `offset = { major, minor, patch }` (each
//! non-positive), the resolver walks three axes in order:
//!
//! ```text
//! target_major = X - abs(offset.major)
//! candidates   = versions where version.major == target_major
//!
//! if offset.minor != 0:
//!   max_minor_on_target_major = max(minor over candidates)
//!   target_minor = max_minor - abs(offset.minor)
//!   candidates   = candidates where version.minor == target_minor
//! else:
//!   candidates   = candidates where version.minor == max_minor
//!
//! if offset.patch != 0:
//!   max_patch = max(patch over candidates)
//!   target_patch = max_patch - abs(offset.patch)
//!   pick the highest version at (target_major, target_minor, target_patch)
//! else:
//!   pick the highest version at (target_major, target_minor, *)
//! ```
//!
//! Any axis can exhaust the pool → `InsufficientCandidates` with a message
//! naming the culprit ("offset.minor requested 2 below, only 1 minor
//! exists on major 19").

use crate::dialect::{Dialect, VersionMeta};
use crate::model::TyposquatPolicy;
use crate::model::{
    Compliance, GroupRule, Offset, OverrideRule, Policy, PolicyDefaults, ReleaseInfo,
    ResolvedPolicy,
};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobMatcher};
use packguard_core::{MalwareKind, MalwareReport, Severity};
use packguard_intel::MatchedVuln;
use std::collections::{BTreeMap, BTreeSet};

/// Convenience alias — the resolver only ever looks at the installed version
/// and the candidate pool, so a per-version map is the cheapest shape.
pub type VulnsByVersion = BTreeMap<String, Vec<MatchedVuln>>;

/// Resolve defaults → groups → overrides for a given package name. Later
/// layers strictly override earlier ones on a per-field basis.
pub fn resolve_policy(policy: &Policy, name: &str) -> ResolvedPolicy {
    let mut resolved = defaults_to_resolved(&policy.defaults);

    for group in &policy.groups {
        if group.match_globs.iter().any(|g| matches_glob(g, name)) {
            apply_group(&mut resolved, group);
        }
    }
    for over in &policy.overrides {
        if matches_glob(&over.match_glob, name) {
            apply_override(&mut resolved, over);
        }
    }
    resolved
}

fn defaults_to_resolved(d: &PolicyDefaults) -> ResolvedPolicy {
    ResolvedPolicy {
        offset: d.offset,
        pin: d.pin.clone(),
        allow_patch: d.allow_patch,
        allow_security_patch: d.allow_security_patch,
        stability: d.stability,
        min_age_days: d.min_age_days,
        block: d.block.clone(),
    }
}

fn apply_group(out: &mut ResolvedPolicy, g: &GroupRule) {
    if let Some(v) = g.offset {
        out.offset = v;
    }
    if let Some(v) = &g.pin {
        out.pin = Some(v.clone());
    }
    if let Some(v) = g.allow_patch {
        out.allow_patch = v;
    }
    if let Some(v) = g.stability {
        out.stability = v;
    }
    if let Some(v) = g.min_age_days {
        out.min_age_days = v;
    }
}

fn apply_override(out: &mut ResolvedPolicy, o: &OverrideRule) {
    if let Some(v) = o.offset {
        out.offset = v;
    }
    if let Some(v) = &o.pin {
        out.pin = Some(v.clone());
    }
    if let Some(v) = o.allow_patch {
        out.allow_patch = v;
    }
    if let Some(v) = o.stability {
        out.stability = v;
    }
    if let Some(v) = o.min_age_days {
        out.min_age_days = v;
    }
}

fn matches_glob(pattern: &str, name: &str) -> bool {
    build_matcher(pattern)
        .map(|m| m.is_match(name))
        .unwrap_or_else(|| pattern == name)
}

fn build_matcher(pattern: &str) -> Option<GlobMatcher> {
    Glob::new(pattern).ok().map(|g| g.compile_matcher())
}

/// Outcome of the offset cascade. `Ok` — pool narrowed to the versions
/// matching `(target_major, target_minor, optional target_patch)`.
/// `Err` — message explaining which axis exhausted the pool.
enum OffsetOutcome<'a> {
    Ok {
        pool: Vec<(&'a ReleaseInfo, VersionMeta)>,
    },
    /// The cascade bailed out. The payload exists for future callers
    /// (e.g. richer error propagation into `Compliance`) — the current
    /// resolver maps it to `None`.
    #[allow(dead_code)]
    Insufficient(String),
}

/// Walk the three axes on a pre-filtered pool (stability + min_age_days
/// already applied). The caller picks the highest surviving version.
fn apply_offset_cascade<'a>(
    pool: Vec<(&'a ReleaseInfo, VersionMeta)>,
    offset: Offset,
) -> OffsetOutcome<'a> {
    if pool.is_empty() {
        return OffsetOutcome::Insufficient(
            "no versions survived the stability + min_age filters".to_string(),
        );
    }

    // --- major ---
    let latest_major = pool.iter().map(|(_, m)| m.major).max().unwrap();
    if (offset.major as u64) > latest_major {
        return OffsetOutcome::Insufficient(format!(
            "offset.major requested {} below latest major {}, \
             only majors [0..={}] exist",
            offset.major, latest_major, latest_major,
        ));
    }
    let target_major = latest_major - offset.major as u64;
    let pool: Vec<_> = pool
        .into_iter()
        .filter(|(_, m)| m.major == target_major)
        .collect();
    if pool.is_empty() {
        return OffsetOutcome::Insufficient(format!(
            "offset.major targeted major {target_major} but no release exists on that major",
        ));
    }

    // --- minor ---
    let max_minor = pool.iter().map(|(_, m)| m.minor).max().unwrap();
    if (offset.minor as u64) > max_minor {
        return OffsetOutcome::Insufficient(format!(
            "offset.minor requested {} below latest minor on major {} (max {}), \
             only minors [0..={}] exist",
            offset.minor, target_major, max_minor, max_minor,
        ));
    }
    let target_minor = max_minor - offset.minor as u64;
    let pool: Vec<_> = pool
        .into_iter()
        .filter(|(_, m)| m.minor == target_minor)
        .collect();
    if pool.is_empty() {
        return OffsetOutcome::Insufficient(format!(
            "offset.minor targeted {target_major}.{target_minor} but no release exists there",
        ));
    }

    // --- patch ---
    if offset.patch != 0 {
        let max_patch = pool.iter().map(|(_, m)| m.patch).max().unwrap();
        if (offset.patch as u64) > max_patch {
            return OffsetOutcome::Insufficient(format!(
                "offset.patch requested {} below latest patch on {}.{} (max {}), \
                 only patches [0..={}] exist",
                offset.patch, target_major, target_minor, max_patch, max_patch,
            ));
        }
        let target_patch = max_patch - offset.patch as u64;
        let filtered: Vec<_> = pool
            .into_iter()
            .filter(|(_, m)| m.patch == target_patch)
            .collect();
        if filtered.is_empty() {
            return OffsetOutcome::Insufficient(format!(
                "offset.patch targeted {target_major}.{target_minor}.{target_patch} \
                 but no release exists there",
            ));
        }
        return OffsetOutcome::Ok { pool: filtered };
    }

    OffsetOutcome::Ok { pool }
}

/// Filter + pick the highest version that complies with `resolved`.
/// Phase 1.5 entry point — kept for callers that don't have vuln data yet
/// (snapshot tests, simple CLI invocations). Delegates to
/// [`compute_recommended_version_with_vulns`] with an empty vuln map.
pub fn compute_recommended_version(
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Option<String> {
    compute_recommended_version_with_vulns(resolved, releases, &BTreeMap::new(), dialect, now)
}

/// Filter + pick the highest version that complies with `resolved`.
///
/// Pipeline (each pass can empty the pool → `None`):
///
/// 1. `stability: stable` drops prereleases.
/// 2. `min_age_days` drops versions published less than N days ago.
/// 3. Offset cascade (major → minor → patch) — see module docs.
/// 4. **Remediation**: skip candidates whose vulns match `block.cve_severity`.
///
/// `pin` short-circuits everything: if the pin matches an entry in
/// `releases`, that entry wins — the filters above do not apply.
pub fn compute_recommended_version_with_vulns(
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    vulns_by_version: &VulnsByVersion,
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Option<String> {
    if let Some(pin) = &resolved.pin {
        return releases
            .iter()
            .find(|r| r.version == *pin)
            .map(|r| r.version.clone());
    }

    let pool = prefilter_pool(resolved, releases, dialect, now)?;
    let pool = match apply_offset_cascade(pool, resolved.offset) {
        OffsetOutcome::Ok { pool } => pool,
        OffsetOutcome::Insufficient(_) => return None,
    };

    pick_best(pool, resolved, vulns_by_version, dialect)
}

fn prefilter_pool<'a>(
    resolved: &ResolvedPolicy,
    releases: &'a [ReleaseInfo],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Option<Vec<(&'a ReleaseInfo, VersionMeta)>> {
    let mut pool: Vec<(&ReleaseInfo, VersionMeta)> = releases
        .iter()
        .filter_map(|r| dialect.meta(&r.version).map(|m| (r, m)))
        .collect();
    if pool.is_empty() {
        return None;
    }

    if !resolved.stability.allows_prerelease() {
        pool.retain(|(_, m)| !m.is_prerelease);
    }
    if pool.is_empty() {
        return None;
    }

    if resolved.min_age_days > 0 {
        pool.retain(|(r, _)| {
            match r
                .published_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            {
                Some(ts) => {
                    let age = now.signed_duration_since(ts.to_utc());
                    age.num_days() >= resolved.min_age_days as i64
                }
                None => true,
            }
        });
    }
    if pool.is_empty() {
        return None;
    }
    Some(pool)
}

fn pick_best(
    mut pool: Vec<(&ReleaseInfo, VersionMeta)>,
    resolved: &ResolvedPolicy,
    vulns_by_version: &VulnsByVersion,
    dialect: Dialect,
) -> Option<String> {
    pool.sort_by(|a, b| {
        dialect
            .compare(&b.0.version, &a.0.version)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let block_sev = block_severity_set(resolved);
    for (release, _) in &pool {
        if !is_blocking_version(&release.version, vulns_by_version, &block_sev) {
            return Some(release.version.clone());
        }
    }
    None
}

/// Phase 2.5 remediation extension — also skip versions a malware-flagged
/// MAL/GHSA/scanner record matches when `block.malware` is on. Wraps
/// [`compute_recommended_version_with_vulns`] with an extra filter pass.
pub fn compute_recommended_version_full(
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    vulns_by_version: &VulnsByVersion,
    malware_reports: &[MalwareReport],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Option<String> {
    if !resolved.block.malware
        || !malware_reports
            .iter()
            .any(|r| matches!(r.kind, MalwareKind::Malware))
    {
        return compute_recommended_version_with_vulns(
            resolved,
            releases,
            vulns_by_version,
            dialect,
            now,
        );
    }
    let bad_versions: BTreeSet<&str> = malware_reports
        .iter()
        .filter(|r| matches!(r.kind, MalwareKind::Malware))
        .filter(|r| !r.version.is_empty())
        .map(|r| r.version.as_str())
        .collect();
    let filtered: Vec<ReleaseInfo> = releases
        .iter()
        .filter(|r| !bad_versions.contains(r.version.as_str()))
        .cloned()
        .collect();
    compute_recommended_version_with_vulns(resolved, &filtered, vulns_by_version, dialect, now)
}

/// `block.cve_severity` values expressed as the strongly-typed enum. Skipped
/// values (typos, empty strings) become `Severity::Unknown` and therefore
/// never block anything they weren't already pointing at.
fn block_severity_set(resolved: &ResolvedPolicy) -> Vec<Severity> {
    resolved
        .block
        .cve_severity
        .iter()
        .map(|s| Severity::parse(s))
        .filter(|s| !matches!(s, Severity::Unknown))
        .collect()
}

/// Does `version` carry at least one vuln that the policy blocks?
fn is_blocking_version(
    version: &str,
    vulns_by_version: &VulnsByVersion,
    block_sev: &[Severity],
) -> bool {
    if block_sev.is_empty() {
        return false;
    }
    vulns_by_version
        .get(version)
        .map(|vs| vs.iter().any(|v| block_sev.contains(&v.severity)))
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────
// Rich evaluation trace — used by the server to render the 3-axis decision
// path in the "Policy eval" tab on the dashboard.
// ─────────────────────────────────────────────────────────────────────────

/// Human-readable breakdown of how the resolver walked major → minor →
/// patch. One line per axis, always in order. The UI renders these as
/// bullet points.
#[derive(Debug, Clone)]
pub struct OffsetCascadeTrace {
    pub lines: Vec<String>,
    /// `Some(version)` when the cascade produced a candidate pool and
    /// remediation picked one; `None` on `InsufficientCandidates` or when
    /// `pin` / empty-history short-circuits.
    pub recommended: Option<String>,
    /// Populated when the cascade bailed out early; always `None` on
    /// success.
    pub insufficient_reason: Option<String>,
}

/// Build the cascade trace without mutating anything. Strictly a
/// presentation helper — mirrors the logic of
/// [`compute_recommended_version_full`] so the two never drift.
pub fn build_offset_cascade_trace(
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    vulns_by_version: &VulnsByVersion,
    malware_reports: &[MalwareReport],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> OffsetCascadeTrace {
    let mut lines: Vec<String> = Vec::new();

    if let Some(pin) = &resolved.pin {
        let hit = releases.iter().find(|r| r.version == *pin).is_some();
        lines.push(format!(
            "pin = {pin} → {}",
            if hit {
                "exact match in registry history"
            } else {
                "not found in registry history"
            }
        ));
        return OffsetCascadeTrace {
            lines,
            recommended: hit.then(|| pin.clone()),
            insufficient_reason: (!hit).then(|| format!("pin {pin} not found")),
        };
    }

    // Mirror the malware filter from compute_recommended_version_full so
    // the trace describes the pool the resolver actually worked with.
    let filtered_owned: Option<Vec<ReleaseInfo>> = if resolved.block.malware
        && malware_reports
            .iter()
            .any(|r| matches!(r.kind, MalwareKind::Malware))
    {
        let bad_versions: BTreeSet<&str> = malware_reports
            .iter()
            .filter(|r| matches!(r.kind, MalwareKind::Malware))
            .filter(|r| !r.version.is_empty())
            .map(|r| r.version.as_str())
            .collect();
        Some(
            releases
                .iter()
                .filter(|r| !bad_versions.contains(r.version.as_str()))
                .cloned()
                .collect(),
        )
    } else {
        None
    };
    let effective_releases: &[ReleaseInfo] = filtered_owned.as_deref().unwrap_or(releases);

    let Some(pool) = prefilter_pool(resolved, effective_releases, dialect, now) else {
        let reason = if releases.is_empty() {
            "no version history on record".to_string()
        } else {
            "stability + min_age_days dropped every candidate".to_string()
        };
        lines.push(format!("pool empty → {reason}"));
        return OffsetCascadeTrace {
            lines,
            recommended: None,
            insufficient_reason: Some(reason),
        };
    };

    let o = resolved.offset;
    let latest_major = pool.iter().map(|(_, m)| m.major).max().unwrap();
    let target_major = latest_major.saturating_sub(o.major as u64);

    if (o.major as u64) > latest_major {
        let reason = format!(
            "offset.major={} exceeds latest major {latest_major}",
            o.major
        );
        lines.push(format!("major: {reason}"));
        return OffsetCascadeTrace {
            lines,
            recommended: None,
            insufficient_reason: Some(reason),
        };
    }
    lines.push(format!(
        "offset.major={} → target major={target_major} (latest={latest_major})",
        o.major
    ));

    let on_major: Vec<_> = pool
        .into_iter()
        .filter(|(_, m)| m.major == target_major)
        .collect();
    if on_major.is_empty() {
        let reason = format!("no release on major {target_major}");
        lines.push(format!("major: {reason}"));
        return OffsetCascadeTrace {
            lines,
            recommended: None,
            insufficient_reason: Some(reason),
        };
    }

    let max_minor = on_major.iter().map(|(_, m)| m.minor).max().unwrap();
    if (o.minor as u64) > max_minor {
        let reason = format!(
            "offset.minor={} exceeds latest minor {max_minor} on major {target_major}",
            o.minor
        );
        lines.push(format!("minor: {reason}"));
        return OffsetCascadeTrace {
            lines,
            recommended: None,
            insufficient_reason: Some(reason),
        };
    }
    let target_minor = max_minor - o.minor as u64;
    lines.push(format!(
        "offset.minor={} → target minor={target_minor} (max on major {target_major}: {max_minor})",
        o.minor
    ));

    let on_minor: Vec<_> = on_major
        .into_iter()
        .filter(|(_, m)| m.minor == target_minor)
        .collect();
    if on_minor.is_empty() {
        let reason = format!("no release at {target_major}.{target_minor}");
        lines.push(format!("minor: {reason}"));
        return OffsetCascadeTrace {
            lines,
            recommended: None,
            insufficient_reason: Some(reason),
        };
    }

    let on_patch = if o.patch != 0 {
        let max_patch = on_minor.iter().map(|(_, m)| m.patch).max().unwrap();
        if (o.patch as u64) > max_patch {
            let reason = format!(
                "offset.patch={} exceeds latest patch {max_patch} on {target_major}.{target_minor}",
                o.patch
            );
            lines.push(format!("patch: {reason}"));
            return OffsetCascadeTrace {
                lines,
                recommended: None,
                insufficient_reason: Some(reason),
            };
        }
        let target_patch = max_patch - o.patch as u64;
        lines.push(format!(
            "offset.patch={} → target patch={target_patch} (max on {target_major}.{target_minor}: {max_patch})",
            o.patch
        ));
        let filtered: Vec<_> = on_minor
            .into_iter()
            .filter(|(_, m)| m.patch == target_patch)
            .collect();
        if filtered.is_empty() {
            let reason = format!("no release at {target_major}.{target_minor}.{target_patch}");
            lines.push(format!("patch: {reason}"));
            return OffsetCascadeTrace {
                lines,
                recommended: None,
                insufficient_reason: Some(reason),
            };
        }
        filtered
    } else {
        lines.push(format!(
            "offset.patch=0 → keep latest patch on {target_major}.{target_minor}"
        ));
        on_minor
    };

    let recommended = pick_best(on_patch, resolved, vulns_by_version, dialect);
    match &recommended {
        Some(v) => lines.push(format!("remediation: picked {v}")),
        None => lines.push("remediation: every candidate blocked by CVE severity".to_string()),
    }

    OffsetCascadeTrace {
        lines,
        recommended: recommended.clone(),
        insufficient_reason: if recommended.is_some() {
            None
        } else {
            Some("every candidate blocked by remediation".to_string())
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Compliance evaluation (unchanged public surface — internally just calls
// the new cascade-based resolver).
// ─────────────────────────────────────────────────────────────────────────

/// Phase 1.5 entry point — kept for callers with no vuln/malware data.
pub fn evaluate_dependency(
    name: &str,
    installed: Option<&str>,
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Compliance {
    evaluate_dependency_with_vulns(
        name,
        installed,
        resolved,
        releases,
        &BTreeMap::new(),
        dialect,
        now,
    )
}

/// Reduce (installed, recommended, vulns) to a single compliance verdict.
pub fn evaluate_dependency_with_vulns(
    name: &str,
    installed: Option<&str>,
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    vulns_by_version: &VulnsByVersion,
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Compliance {
    evaluate_dependency_full(
        name,
        installed,
        resolved,
        releases,
        vulns_by_version,
        &[],
        dialect,
        now,
    )
}

/// Phase 2.5 entry point — accepts both vulnerabilities and malware
/// reports. See the module doc in `packages.rs` for the 7-check order.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_dependency_full(
    name: &str,
    installed: Option<&str>,
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    vulns_by_version: &VulnsByVersion,
    malware_reports: &[MalwareReport],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Compliance {
    if let Some(pin) = &resolved.pin {
        return match installed {
            Some(v) if v == pin => Compliance::Compliant,
            Some(v) => {
                Compliance::Violation(format!("{} pinned to {} but {} is installed", name, pin, v))
            }
            None => Compliance::Violation(format!(
                "{} pinned to {} but installed version unknown",
                name, pin
            )),
        };
    }

    let Some(installed) = installed else {
        return Compliance::Warning(format!("{}: no installed version resolved", name));
    };

    // Bonus 1.5 — block.yanked / block.deprecated on the installed version.
    if let Some(release_entry) = releases.iter().find(|r| r.version == installed) {
        if release_entry.yanked && resolved.block.yanked {
            return Compliance::Violation(format!(
                "{}: installed {} is yanked on the registry and policy blocks yanked",
                name, installed
            ));
        }
        if release_entry.deprecated && resolved.block.deprecated {
            return Compliance::Violation(format!(
                "{}: installed {} is deprecated on the registry and policy blocks deprecated",
                name, installed
            ));
        }
    }

    // Phase 2 — block.cve_severity on the installed version.
    let block_sev = block_severity_set(resolved);
    if !block_sev.is_empty() {
        if let Some(matched) = vulns_by_version.get(installed) {
            let blocking: Vec<MatchedVuln> = matched
                .iter()
                .filter(|v| block_sev.contains(&v.severity))
                .cloned()
                .collect();
            if !blocking.is_empty() {
                return Compliance::VulnerabilityViolation(blocking);
            }
        }
    }

    // Phase 2.5 — block.malware on the installed version.
    if resolved.block.malware {
        let mal: Vec<MalwareReport> = malware_reports
            .iter()
            .filter(|r| matches!(r.kind, MalwareKind::Malware))
            .filter(|r| r.version.is_empty() || r.version == installed)
            .cloned()
            .collect();
        if !mal.is_empty() {
            return Compliance::MalwareViolation(mal);
        }
    }

    // Phase 2.5 — typosquat: warn / strict / off (default warn).
    let typo: Vec<MalwareReport> = malware_reports
        .iter()
        .filter(|r| matches!(r.kind, MalwareKind::Typosquat))
        .cloned()
        .collect();
    if !typo.is_empty() {
        match resolved.block.typosquat {
            TyposquatPolicy::Strict => return Compliance::MalwareViolation(typo),
            TyposquatPolicy::Warn => return Compliance::TyposquatWarning(typo),
            TyposquatPolicy::Off => {}
        }
    }

    match compute_recommended_version_full(
        resolved,
        releases,
        vulns_by_version,
        malware_reports,
        dialect,
        now,
    ) {
        Some(recommended) => {
            compare_installed_to_recommended(name, installed, &recommended, dialect)
        }
        None if releases.is_empty() => Compliance::InsufficientCandidates(format!(
            "{}: no version history on record (run `packguard scan` first)",
            name
        )),
        None => {
            // The trace gives a precise per-axis reason; reuse it so
            // `InsufficientCandidates` carries more than a generic message.
            let trace = build_offset_cascade_trace(
                resolved,
                releases,
                vulns_by_version,
                malware_reports,
                dialect,
                now,
            );
            let why = trace
                .insufficient_reason
                .unwrap_or_else(|| "policy filters dropped all candidates".to_string());
            Compliance::InsufficientCandidates(format!("{name}: {why}"))
        }
    }
}

fn compare_installed_to_recommended(
    name: &str,
    installed: &str,
    recommended: &str,
    dialect: Dialect,
) -> Compliance {
    match dialect.compare(installed, recommended) {
        Some(std::cmp::Ordering::Equal) => Compliance::Compliant,
        Some(std::cmp::Ordering::Greater) => Compliance::Warning(format!(
            "{}: installed {} is ahead of policy-allowed {}",
            name, installed, recommended
        )),
        Some(std::cmp::Ordering::Less) => {
            let (im, rm) = (dialect.meta(installed), dialect.meta(recommended));
            let major_behind = matches!((im, rm), (Some(a), Some(b)) if a.major != b.major);
            let msg = format!(
                "{}: installed {} is behind policy-allowed {}",
                name, installed, recommended
            );
            if major_behind {
                Compliance::Violation(msg)
            } else {
                Compliance::Warning(msg)
            }
        }
        None => Compliance::Warning(format!(
            "{}: cannot compare {} to recommended {}",
            name, installed, recommended
        )),
    }
}
