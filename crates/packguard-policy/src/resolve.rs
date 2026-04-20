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

/// Filter + pick the highest version that complies with `resolved`. Returns
/// the raw version string (untouched from `releases`) or `None` if nothing
/// qualifies.
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

    let mut parsed: Vec<(&ReleaseInfo, VersionMeta)> = releases
        .iter()
        .filter_map(|r| dialect.meta(&r.version).map(|m| (r, m)))
        .collect();
    if parsed.is_empty() {
        return None;
    }

    // Max major among all parseable releases → reference for `offset`.
    let latest_major = parsed
        .iter()
        .filter(|(_, m)| !m.is_prerelease || resolved.stability.allows_prerelease())
        .map(|(_, m)| m.major)
        .max()
        .unwrap_or(0);
    let max_allowed_major = latest_major.saturating_sub(resolved.offset as u64);

    parsed.retain(|(r, meta)| {
        // Stability.
        if meta.is_prerelease && !resolved.stability.allows_prerelease() {
            return false;
        }
        // Offset cap.
        if meta.major > max_allowed_major {
            return false;
        }
        // Min age.
        if resolved.min_age_days > 0 {
            if let Some(pub_ts) = r
                .published_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            {
                let age = now.signed_duration_since(pub_ts.to_utc());
                if age.num_days() < resolved.min_age_days as i64 {
                    return false;
                }
            }
        }
        true
    });

    // Sort descending by dialect-aware comparison, picking the first that parses.
    parsed.sort_by(|a, b| {
        dialect
            .compare(&b.0.version, &a.0.version)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    parsed.first().map(|(r, _)| r.version.clone())
}

/// Reduce (installed, recommended) to a single compliance verdict. When the
/// caller has full version history (`releases` covers many versions), the
/// check runs against the recommended version. When only `latest` is known
/// (Phase 1 store state), the evaluator falls back to a major-distance rule
/// so conservative defaults still produce actionable signal.
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

    if let Some(recommended) = compute_recommended_version(resolved, releases, dialect, now) {
        return compare_installed_to_recommended(name, installed, &recommended, dialect);
    }

    // Fallback: we couldn't compute a recommendation (either no history or
    // the offset window filtered everything out). Use the highest known
    // version to run a major-distance check against `installed`.
    let highest = releases
        .iter()
        .filter_map(|r| dialect.meta(&r.version).map(|m| (r, m)))
        .max_by(|(_, a), (_, b)| a.major.cmp(&b.major));
    let Some((_, latest_meta)) = highest else {
        return Compliance::Warning(format!("{}: no latest version available", name));
    };
    let Some(installed_meta) = dialect.meta(installed) else {
        return Compliance::Warning(format!(
            "{}: unparsable installed version {}",
            name, installed
        ));
    };
    let max_allowed_major = latest_meta.major.saturating_sub(resolved.offset as u64);
    if installed_meta.major > max_allowed_major {
        return Compliance::Warning(format!(
            "{}: installed {} is ahead of policy window (max major {})",
            name, installed, max_allowed_major
        ));
    }
    if installed_meta.major < max_allowed_major {
        return Compliance::Violation(format!(
            "{}: installed {} is {} major(s) behind policy window (max major {})",
            name,
            installed,
            max_allowed_major - installed_meta.major,
            max_allowed_major
        ));
    }
    Compliance::Compliant
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
