//! Rule resolution + recommended-version + compliance evaluation.
//!
//! # Phase 10a — lexicographic offset bound
//!
//! Given `latest = X.Y.Z` (tip of the post-stability + min-age pool) and
//! `offset = { major, minor, patch }` (each a non-negative magnitude, since
//! YAML `-1` is stored as `1`), each axis contributes an **inclusive lex
//! upper bound** on the `(major, minor, patch)` triple:
//!
//! ```text
//! bound_major  = if a > 0: (X - a,     ∞, ∞)         ; infeasible when a > X
//! bound_minor  = if b > 0:
//!                  if b ≤ Y: (X,       Y - b, ∞)
//!                  else:     (X - 1,   ∞,    ∞)      ; cross-boundary
//!                                                    ; infeasible when X = 0
//! bound_patch  = if c > 0:
//!                  if c ≤ Z: (X,       Y,    Z - c)
//!                  elif Y ≥ 1: (X,     Y - 1, ∞)      ; spill to prev minor
//!                  elif X ≥ 1: (X - 1, ∞,    ∞)      ; spill to prev major
//!                  else:     infeasible
//! effective    = min_lex over all active axes (tightest bound wins)
//! candidates   = versions V with (V.maj, V.min, V.pat) ≤ effective,
//!                after stability + min_age + malware + CVE filters
//! recommended  = max(candidates) or InsufficientCandidates if empty
//! ```
//!
//! This is strictly more permissive than Phase 9b — `{minor:-1}` on a
//! latest `5.0` now naturally falls to `4.max.max` via cross-boundary
//! rather than surfacing `InsufficientCandidates`. The only way to get
//! `InsufficientCandidates` is:
//!
//! 1. every axis lex bound underflows past major 0 (user asked for
//!    something below the earliest possible release), or
//! 2. the registry has literally zero version ≤ the effective bound, or
//! 3. every candidate ≤ the bound is blocked by CVE / malware remediation.

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

/// Per-axis contribution to the effective lex bound. `Inactive` means the
/// axis magnitude is 0 (no constraint); `Infeasible` means the bound would
/// underflow past (0, …, …) — the request can never be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AxisBound {
    Inactive,
    Inclusive((u64, u64, u64)),
    Infeasible,
}

/// Merged lex bound. `Unbounded` means every axis is inactive (offset is
/// all-zeros, or a `pin` policy shortcut hasn't engaged yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveBound {
    Unbounded,
    Inclusive((u64, u64, u64)),
    Infeasible,
}

fn bound_major(latest: (u64, u64, u64), a: u64) -> AxisBound {
    if a == 0 {
        return AxisBound::Inactive;
    }
    let (x, _, _) = latest;
    match x.checked_sub(a) {
        Some(target) => AxisBound::Inclusive((target, u64::MAX, u64::MAX)),
        None => AxisBound::Infeasible,
    }
}

fn bound_minor(latest: (u64, u64, u64), b: u64) -> AxisBound {
    if b == 0 {
        return AxisBound::Inactive;
    }
    let (x, y, _) = latest;
    if let Some(target) = y.checked_sub(b) {
        return AxisBound::Inclusive((x, target, u64::MAX));
    }
    // Cross-boundary: step back one major.
    match x.checked_sub(1) {
        Some(prev_x) => AxisBound::Inclusive((prev_x, u64::MAX, u64::MAX)),
        None => AxisBound::Infeasible,
    }
}

fn bound_patch(latest: (u64, u64, u64), c: u64) -> AxisBound {
    if c == 0 {
        return AxisBound::Inactive;
    }
    let (x, y, z) = latest;
    if let Some(target) = z.checked_sub(c) {
        return AxisBound::Inclusive((x, y, target));
    }
    // Spill to previous minor, then previous major if minor is also 0.
    if let Some(prev_y) = y.checked_sub(1) {
        return AxisBound::Inclusive((x, prev_y, u64::MAX));
    }
    match x.checked_sub(1) {
        Some(prev_x) => AxisBound::Inclusive((prev_x, u64::MAX, u64::MAX)),
        None => AxisBound::Infeasible,
    }
}

/// Compute the three per-axis bounds and merge into the tightest inclusive
/// upper bound. Pure function: no access to the release pool, safe to
/// unit-test without fixtures.
fn compute_effective_bound(latest: (u64, u64, u64), offset: Offset) -> EffectiveBound {
    let axes = [
        bound_major(latest, offset.major as u64),
        bound_minor(latest, offset.minor as u64),
        bound_patch(latest, offset.patch as u64),
    ];
    if axes.iter().any(|a| matches!(a, AxisBound::Infeasible)) {
        return EffectiveBound::Infeasible;
    }
    let tightest = axes
        .iter()
        .filter_map(|a| match a {
            AxisBound::Inclusive(t) => Some(*t),
            _ => None,
        })
        .min();
    match tightest {
        Some(b) => EffectiveBound::Inclusive(b),
        None => EffectiveBound::Unbounded,
    }
}

fn latest_tuple(pool: &[(&ReleaseInfo, VersionMeta)]) -> Option<(u64, u64, u64)> {
    pool.iter().map(|(_, m)| (m.major, m.minor, m.patch)).max()
}

/// Narrow the pool to versions whose `(major, minor, patch)` triple is
/// lex-≤ the effective bound. `None` means "no candidate satisfies the
/// bound" and the caller should surface `InsufficientCandidates`.
fn apply_lex_bound(
    pool: Vec<(&ReleaseInfo, VersionMeta)>,
    bound: EffectiveBound,
) -> Option<Vec<(&ReleaseInfo, VersionMeta)>> {
    match bound {
        EffectiveBound::Infeasible => None,
        EffectiveBound::Unbounded => Some(pool),
        EffectiveBound::Inclusive(b) => {
            let kept: Vec<_> = pool
                .into_iter()
                .filter(|(_, m)| (m.major, m.minor, m.patch) <= b)
                .collect();
            if kept.is_empty() {
                None
            } else {
                Some(kept)
            }
        }
    }
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
/// 3. Lexicographic offset bound (see module docs) — keep only versions
///    whose `(major, minor, patch)` triple is ≤ the effective bound.
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
    let latest = latest_tuple(&pool)?;
    let bound = compute_effective_bound(latest, resolved.offset);
    let pool = apply_lex_bound(pool, bound)?;

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
// Rich evaluation trace — used by the server to render the lex-bound
// decision path in the "Policy eval" tab on the dashboard.
// ─────────────────────────────────────────────────────────────────────────

/// Human-readable breakdown of how the resolver derived the effective lex
/// bound from the three axes. The UI renders each string as one bullet.
#[derive(Debug, Clone)]
pub struct OffsetCascadeTrace {
    pub lines: Vec<String>,
    /// `Some(version)` when remediation picked a candidate; `None` on
    /// `InsufficientCandidates` or when `pin` / empty-history
    /// short-circuits.
    pub recommended: Option<String>,
    /// Populated when the resolver bailed out early; always `None` on
    /// success.
    pub insufficient_reason: Option<String>,
}

/// Build the lex-bound trace without mutating anything. Presentation
/// helper — mirrors the logic of [`compute_recommended_version_full`] so
/// the two never drift.
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
        let hit = releases.iter().any(|r| r.version == *pin);
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

    let latest = latest_tuple(&pool).unwrap();
    let o = resolved.offset;
    let axes = [
        ("major", bound_major(latest, o.major as u64), o.major),
        ("minor", bound_minor(latest, o.minor as u64), o.minor),
        ("patch", bound_patch(latest, o.patch as u64), o.patch),
    ];
    for (label, axis, mag) in axes {
        lines.push(format!(
            "offset.{label}={} → {}",
            signed(mag),
            axis_display(label, axis),
        ));
    }

    let bound = compute_effective_bound(latest, o);
    let bound_str = format!(
        "effective bound = {} (latest = {})",
        bound_display(bound),
        tuple_display(latest),
    );
    lines.push(bound_str);

    match apply_lex_bound(pool, bound) {
        None => {
            let reason = match bound {
                EffectiveBound::Infeasible => format!(
                    "offset underflows past major 0 (latest = {})",
                    tuple_display(latest)
                ),
                EffectiveBound::Inclusive(b) => {
                    format!("no release ≤ {}", tuple_display(b))
                }
                // Unbounded never produces an empty pool when the
                // prefilter has already handed us Some.
                EffectiveBound::Unbounded => "pool unexpectedly empty".to_string(),
            };
            lines.push(format!("→ {reason} → InsufficientCandidates"));
            OffsetCascadeTrace {
                lines,
                recommended: None,
                insufficient_reason: Some(reason),
            }
        }
        Some(bounded_pool) => {
            let recommended = pick_best(bounded_pool, resolved, vulns_by_version, dialect);
            match &recommended {
                Some(v) => lines.push(format!("max version ≤ bound = {v} → picked {v}")),
                None => {
                    lines.push("every candidate blocked by CVE / malware remediation".to_string())
                }
            }
            let insufficient_reason = if recommended.is_some() {
                None
            } else {
                Some("every candidate blocked by remediation".to_string())
            };
            OffsetCascadeTrace {
                lines,
                recommended,
                insufficient_reason,
            }
        }
    }
}

fn signed(magnitude: u32) -> String {
    if magnitude == 0 {
        "0".to_string()
    } else {
        format!("-{magnitude}")
    }
}

fn axis_display(label: &str, axis: AxisBound) -> String {
    match axis {
        AxisBound::Inactive => "inactive".to_string(),
        AxisBound::Inclusive(t) => {
            let tail = if is_cross_boundary(label, t) {
                " (cross-boundary)"
            } else {
                ""
            };
            format!("{}{tail}", tuple_display(t))
        }
        AxisBound::Infeasible => "infeasible (underflow past major 0)".to_string(),
    }
}

/// Did this axis fall back to a neighboring slot? `major` never crosses
/// (stepping back a major *is* its job). `minor` crosses when the minor
/// slot is `∞` — meaning the overshoot pushed back to the previous major.
/// `patch` crosses when the patch slot is `∞` — meaning patch overshoot
/// spilled to the previous minor (or further).
fn is_cross_boundary(label: &str, (_, minor, patch): (u64, u64, u64)) -> bool {
    match label {
        "minor" => minor == u64::MAX,
        "patch" => patch == u64::MAX,
        _ => false,
    }
}

fn tuple_display(t: (u64, u64, u64)) -> String {
    format!(
        "({}, {}, {})",
        axis_slot(t.0),
        axis_slot(t.1),
        axis_slot(t.2)
    )
}

fn axis_slot(n: u64) -> String {
    if n == u64::MAX {
        "∞".to_string()
    } else {
        n.to_string()
    }
}

fn bound_display(bound: EffectiveBound) -> String {
    match bound {
        EffectiveBound::Unbounded => "(∞, ∞, ∞) [all axes inactive]".to_string(),
        EffectiveBound::Inclusive(b) => tuple_display(b),
        EffectiveBound::Infeasible => "infeasible".to_string(),
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

#[cfg(test)]
mod bound_tests {
    //! Phase 10a — pure unit tests for the per-axis lex-bound builders
    //! and their merge. These don't touch fixtures or the policy model;
    //! they pin down the math.

    use super::*;

    fn off(m: u32, n: u32, p: u32) -> Offset {
        Offset {
            major: m,
            minor: n,
            patch: p,
        }
    }

    #[test]
    fn bound_major_zero_is_inactive() {
        assert_eq!(bound_major((19, 2, 5), 0), AxisBound::Inactive);
    }

    #[test]
    fn bound_major_minus_one_gives_prev_major_wildcard() {
        assert_eq!(
            bound_major((19, 2, 5), 1),
            AxisBound::Inclusive((18, u64::MAX, u64::MAX))
        );
    }

    #[test]
    fn bound_major_underflow_past_zero_is_infeasible() {
        assert_eq!(bound_major((0, 5, 3), 1), AxisBound::Infeasible);
        assert_eq!(bound_major((2, 0, 0), 5), AxisBound::Infeasible);
    }

    #[test]
    fn bound_minor_small_stays_on_same_major() {
        assert_eq!(
            bound_minor((19, 2, 5), 1),
            AxisBound::Inclusive((19, 1, u64::MAX))
        );
    }

    #[test]
    fn bound_minor_cross_boundary_when_overshoot() {
        // Y = 0, b = 1 → step back one major to (X-1, ∞, ∞).
        assert_eq!(
            bound_minor((5, 0, 0), 1),
            AxisBound::Inclusive((4, u64::MAX, u64::MAX))
        );
        // Deep overshoot: single step, not proportional.
        assert_eq!(
            bound_minor((19, 2, 5), 99),
            AxisBound::Inclusive((18, u64::MAX, u64::MAX))
        );
    }

    #[test]
    fn bound_minor_cross_boundary_infeasible_when_no_prev_major() {
        assert_eq!(bound_minor((0, 0, 3), 1), AxisBound::Infeasible);
    }

    #[test]
    fn bound_patch_small_stays_in_same_minor() {
        assert_eq!(bound_patch((19, 2, 5), 1), AxisBound::Inclusive((19, 2, 4)));
    }

    #[test]
    fn bound_patch_spills_to_prev_minor_then_prev_major() {
        // Z = 0, Y ≥ 1: spill to prev minor.
        assert_eq!(
            bound_patch((19, 2, 0), 1),
            AxisBound::Inclusive((19, 1, u64::MAX))
        );
        // Z = 0, Y = 0, X ≥ 1: spill to prev major.
        assert_eq!(
            bound_patch((5, 0, 0), 1),
            AxisBound::Inclusive((4, u64::MAX, u64::MAX))
        );
        // Z = 0, Y = 0, X = 0: nowhere to go.
        assert_eq!(bound_patch((0, 0, 0), 1), AxisBound::Infeasible);
    }

    #[test]
    fn compute_effective_bound_all_zero_is_unbounded() {
        assert_eq!(
            compute_effective_bound((19, 2, 5), off(0, 0, 0)),
            EffectiveBound::Unbounded
        );
    }

    #[test]
    fn compute_effective_bound_major_dominates_on_all_minus_one() {
        // {-1, -1, -1} on (19, 2, 5) gives three bounds:
        //   major → (18, ∞, ∞)
        //   minor → (19, 1, ∞)
        //   patch → (19, 2, 4)
        // min_lex picks (18, ∞, ∞).
        assert_eq!(
            compute_effective_bound((19, 2, 5), off(1, 1, 1)),
            EffectiveBound::Inclusive((18, u64::MAX, u64::MAX))
        );
    }

    #[test]
    fn compute_effective_bound_any_infeasible_axis_makes_whole_infeasible() {
        // major:-10 on latest 2.0.0 underflows → Infeasible even though
        // patch:-1 is perfectly reasonable.
        assert_eq!(
            compute_effective_bound((2, 0, 5), off(10, 0, 1)),
            EffectiveBound::Infeasible
        );
    }
}
