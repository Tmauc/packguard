//! Rule resolution + recommended-version + compliance evaluation.

use crate::dialect::{Dialect, VersionMeta};
use crate::model::{
    Compliance, GroupRule, OverrideRule, Policy, PolicyDefaults, ReleaseInfo, ResolvedPolicy,
};
use chrono::{DateTime, Utc};
use globset::{Glob, GlobMatcher};

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

/// Filter + pick the highest version that complies with `resolved`.
///
/// Strict Phase 1.5 semantics: `offset: -N` means the recommendation sits on
/// the major that is *exactly* `latest_major - |N|`. No fallback window.
/// Filter order (each pass can empty the pool → `None`):
///
/// 1. `stability: stable` drops prereleases.
/// 2. `min_age_days` drops versions published less than N days ago. Versions
///    without a publish date are kept (we don't have data to exclude them).
/// 3. Offset caps the pool to the exact target major, derived from the
///    highest surviving major post steps 1-2.
///
/// `pin` short-circuits everything: if the pin matches an entry in
/// `releases`, that entry wins — the filters above do not apply.
pub fn compute_recommended_version(
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
    dialect: Dialect,
    now: DateTime<Utc>,
) -> Option<String> {
    if let Some(pin) = &resolved.pin {
        return releases
            .iter()
            .find(|r| r.version == *pin)
            .map(|r| r.version.clone());
    }

    let mut pool: Vec<(&ReleaseInfo, VersionMeta)> = releases
        .iter()
        .filter_map(|r| dialect.meta(&r.version).map(|m| (r, m)))
        .collect();
    if pool.is_empty() {
        return None;
    }

    // 1. Stability.
    if !resolved.stability.allows_prerelease() {
        pool.retain(|(_, m)| !m.is_prerelease);
    }
    if pool.is_empty() {
        return None;
    }

    // 2. Minimum age.
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
                // No publish date → cannot prove it's too fresh, keep it.
                None => true,
            }
        });
    }
    if pool.is_empty() {
        return None;
    }

    // 3. Offset — strict exact-major match.
    let Some(latest_major) = pool.iter().map(|(_, m)| m.major).max() else {
        return None;
    };
    let target_major = latest_major.saturating_sub(resolved.offset as u64);
    pool.retain(|(_, m)| m.major == target_major);
    if pool.is_empty() {
        return None;
    }

    // Pick the max within the target major.
    pool.sort_by(|a, b| {
        dialect
            .compare(&b.0.version, &a.0.version)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    pool.first().map(|(r, _)| r.version.clone())
}

/// Reduce (installed, recommended) to a single compliance verdict. Requires
/// a non-empty version history to produce anything other than
/// `InsufficientCandidates`; the Phase-1 "major-distance fallback" is gone.
pub fn evaluate_dependency(
    name: &str,
    installed: Option<&str>,
    resolved: &ResolvedPolicy,
    releases: &[ReleaseInfo],
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

    match compute_recommended_version(resolved, releases, dialect, now) {
        Some(recommended) => {
            compare_installed_to_recommended(name, installed, &recommended, dialect)
        }
        None if releases.is_empty() => Compliance::InsufficientCandidates(format!(
            "{}: no version history on record (run `packguard scan` first)",
            name
        )),
        None => Compliance::InsufficientCandidates(format!(
            "{}: policy filters (stability / min_age_days / offset) dropped all {} known versions",
            name,
            releases.len()
        )),
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
