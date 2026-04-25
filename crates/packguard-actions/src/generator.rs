//! Action generators — one function per `ActionKind`, fused by
//! `collect_all`. Each generator is a pure read over the store: no
//! mutation, no network. The orchestrator also filters out actions that
//! match an active dismissal, so a dismiss persisted via
//! `/api/actions/:id/dismiss` quietly disappears on the next refresh.
//!
//! Ordering guarantee: the returned `Vec<Action>` is sorted by
//! `(severity desc, workspace asc, kind asc, target canonical asc)` so
//! the CLI and dashboard render the same order without extra logic.

use crate::model::{stable_action_id, Action, ActionKind, ActionSeverity, ActionTarget};
use crate::pm_detect::{detect_package_manager, suggest_upgrade, PackageManager};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use packguard_core::{MalwareKind, Severity};
use packguard_intel::match_vulnerabilities;
use packguard_policy::{
    compute_recommended_version_full, evaluate_dependency_full, Compliance, Dialect, Policy,
};
use packguard_store::{
    normalize_repo_path, IntelStore, Store, StoredActionDismissal, StoredDependency, StoredMalware,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Advisory staleness threshold for the `RefreshSync` action. Matches the
/// Phase 12a design matrix.
const SYNC_STALE_DAYS: i64 = 7;

/// Workspace rescan staleness threshold for the `RescanStale` action.
const SCAN_STALE_DAYS: i64 = 3;

/// Placeholder workspace value for actions that are not tied to any
/// specific repo (currently `RefreshSync`). Stable across calls so the
/// dismissal id stays deterministic.
const GLOBAL_WORKSPACE: &str = "_global";

/// Generate every action that applies at `now`. When `workspace_filter`
/// is `Some`, package-scoped and scan-scoped actions are restricted to
/// that repo; global actions (`RefreshSync`) are always included so the
/// UI surfaces advisory staleness regardless of the active scope.
///
/// `include_dismissed` surfaces permanently-dismissed rows (with
/// `dismissed_at` populated) so the dashboard / CLI can render an
/// "archived" view. `include_deferred` does the same for rows whose
/// defer window has not yet elapsed, with both `dismissed_at` and
/// `deferred_until` populated. Defaults for both are `false` — matches
/// the pre-12c behaviour the dashboard/CLI rely on.
pub fn collect_all(
    store: &Store,
    intel: &IntelStore,
    workspace_filter: Option<&Path>,
    now: DateTime<Utc>,
    include_dismissed: bool,
    include_deferred: bool,
) -> Result<Vec<Action>> {
    let now_unix = now.timestamp();
    let scope_key = workspace_filter.map(normalize_repo_path);
    let dismissals: BTreeMap<String, StoredActionDismissal> = store
        .load_active_dismissals(scope_key.as_deref(), now_unix)?
        .into_iter()
        .map(|d| (d.id.clone(), d))
        .collect();

    let workspaces: Vec<PathBuf> = match workspace_filter {
        Some(p) => vec![PathBuf::from(normalize_repo_path(p))],
        None => store
            .distinct_repo_paths()?
            .into_iter()
            .map(|p| PathBuf::from(normalize_repo_path(&p)))
            .collect(),
    };

    let mut actions: Vec<Action> = Vec::new();

    for ws in &workspaces {
        let ws_str = ws.display().to_string();
        let pm = detect_package_manager(ws, guess_ecosystem(store, ws).as_deref().unwrap_or("npm"));
        let policy = match packguard_policy::resolve_policy_cascade(ws) {
            Ok(r) => r.policy,
            Err(_) => packguard_policy::parse_policy(packguard_policy::CONSERVATIVE_DEFAULTS_YAML)?,
        };

        actions.extend(generate_for_workspace(
            store, intel, ws, &ws_str, pm, &policy, now,
        )?);
        actions.extend(generate_rescan_stale(store, ws, &ws_str, now)?);
    }

    actions.extend(generate_refresh_sync(intel, now)?);

    // Apply dismissal filter + annotation. A row in `dismissals` is
    // either a permanent dismissal (`deferred_until is None`) or a
    // still-active defer (`deferred_until > now`). We drop whichever
    // bucket the caller did not opt into, and stamp the timestamps on
    // the rest so the renderer can paint a `[dismissed]` /
    // `[deferred Nd]` marker.
    actions.retain_mut(|a| {
        let Some(d) = dismissals.get(&a.id) else {
            return true;
        };
        match d.deferred_until {
            Some(ts) => {
                if !include_deferred {
                    return false;
                }
                a.deferred_until = unix_to_rfc3339(ts);
                a.dismissed_at = unix_to_rfc3339(d.dismissed_at);
            }
            None => {
                if !include_dismissed {
                    return false;
                }
                a.dismissed_at = unix_to_rfc3339(d.dismissed_at);
            }
        }
        true
    });

    actions.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.workspace.cmp(&b.workspace))
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
            .then_with(|| a.target.canonical().cmp(&b.target.canonical()))
    });

    Ok(actions)
}

fn unix_to_rfc3339(ts: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339())
}

/// Best-effort ecosystem for `workspace` — picks the first scan row
/// matching this path. Used only to seed `detect_package_manager` so
/// the fallback (no lockfile, unknown ecosystem) still picks a
/// reasonable default.
fn guess_ecosystem(store: &Store, workspace: &Path) -> Option<String> {
    let canon = normalize_repo_path(workspace);
    store
        .scans_index()
        .ok()?
        .into_iter()
        .find(|row| row.path.display().to_string() == canon)
        .map(|r| r.ecosystem)
}

fn generate_for_workspace(
    store: &Store,
    intel: &IntelStore,
    workspace: &Path,
    ws_str: &str,
    pm: PackageManager,
    policy: &Policy,
    now: DateTime<Utc>,
) -> Result<Vec<Action>> {
    let deps = store.load_repo_dependencies(workspace)?;
    let mut out: Vec<Action> = Vec::new();

    // Dedup by (ecosystem, name): a workspace can list the same package
    // under both `runtime` and `dev` rows, and we only want one action.
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    for dep in deps {
        if !seen.insert((dep.ecosystem.clone(), dep.name.clone())) {
            continue;
        }
        let Some(installed) = dep.installed.clone() else {
            continue; // no installed version → no actionable target
        };

        let stored_vulns = intel.load_vulnerabilities_for(&dep.ecosystem, &dep.name)?;
        let stored_malware = intel.load_malware_reports_for(&dep.ecosystem, &dep.name)?;
        let releases: Vec<packguard_policy::ReleaseInfo> = store
            .load_package_versions(&dep.ecosystem, &dep.name)?
            .into_iter()
            .map(|v| packguard_policy::ReleaseInfo {
                version: v.version,
                published_at: v.published_at,
                deprecated: v.deprecated,
                yanked: v.yanked,
            })
            .collect();

        let advisories: Vec<packguard_core::Vulnerability> = stored_vulns
            .iter()
            .cloned()
            .map(stored_vuln_to_core)
            .collect();
        let malware_core: Vec<packguard_core::MalwareReport> =
            stored_malware.iter().map(stored_malware_to_core).collect();

        let installed_matches =
            match_vulnerabilities(&dep.ecosystem, &dep.name, &installed, &advisories);

        let mut vulns_by_version: packguard_policy::VulnsByVersion = Default::default();
        for r in &releases {
            let m = match_vulnerabilities(&dep.ecosystem, &dep.name, &r.version, &advisories);
            if !m.is_empty() {
                vulns_by_version.insert(r.version.clone(), m);
            }
        }
        if !vulns_by_version.contains_key(&installed) && !installed_matches.is_empty() {
            vulns_by_version.insert(installed.clone(), installed_matches.clone());
        }

        let resolved = policy.resolve(&dep.name);
        let dialect = Dialect::for_ecosystem(&dep.ecosystem);

        let compliance = evaluate_dependency_full(
            &dep.name,
            Some(installed.as_str()),
            &resolved,
            &releases,
            &vulns_by_version,
            &malware_core,
            dialect,
            now,
        );

        let recommended = compute_recommended_version_full(
            &resolved,
            &releases,
            &vulns_by_version,
            &malware_core,
            dialect,
            now,
        );
        // Don't surface a "move to X" when X is already what's installed.
        let recommended_version = recommended
            .as_deref()
            .filter(|v| *v != installed.as_str())
            .map(|v| v.to_string());
        let suggested = recommended_version
            .as_deref()
            .map(|v| suggest_upgrade(pm, &dep.name, v));

        // FixMalware — installed version flagged as malware on that
        // workspace. Emit regardless of `block.malware` so the dashboard
        // always surfaces the signal.
        for m in stored_malware
            .iter()
            .filter(|m| matches!(m.kind, MalwareKind::Malware))
            .filter(|m| m.version.is_none() || m.version.as_deref() == Some(installed.as_str()))
        {
            let target = package_target(&dep, &installed);
            let id = stable_action_id(ActionKind::FixMalware, &target, ws_str);
            let title = format!(
                "{}@{} flagged as malware ({})",
                dep.name, installed, m.ref_id
            );
            let explanation = m
                .summary
                .clone()
                .unwrap_or_else(|| "Installed version matches a malware advisory.".to_string());
            out.push(Action {
                id,
                kind: ActionKind::FixMalware,
                severity: ActionKind::FixMalware.severity(),
                workspace: ws_str.to_string(),
                target,
                title,
                explanation,
                suggested_command: suggested.clone(),
                recommended_version: recommended_version.clone(),
                dismissed_at: None,
                deferred_until: None,
            });
        }

        // FixCveCritical / FixCveHigh — installed is affected by an
        // advisory whose severity is at least `High`. We split
        // crit vs high so the dashboard can group them distinctly.
        let mut seen_severity_action = [false; 2]; // [critical, high]
        for m in &installed_matches {
            let (kind, idx) = match m.severity {
                Severity::Critical => (ActionKind::FixCveCritical, 0),
                Severity::High => (ActionKind::FixCveHigh, 1),
                _ => continue,
            };
            if seen_severity_action[idx] {
                continue;
            }
            seen_severity_action[idx] = true;
            let target = package_target(&dep, &installed);
            let id = stable_action_id(kind, &target, ws_str);
            let advisory_label = m.cve_id.clone().unwrap_or_else(|| m.advisory_id.clone());
            let title = format!("{}@{} → fix {}", dep.name, installed, advisory_label);
            let explanation = match m.severity {
                Severity::Critical => {
                    format!("Critical advisory {advisory_label} affects the installed version.")
                }
                _ => format!(
                    "High-severity advisory {advisory_label} affects the installed version."
                ),
            };
            out.push(Action {
                id,
                kind,
                severity: kind.severity(),
                workspace: ws_str.to_string(),
                target,
                title,
                explanation,
                suggested_command: suggested.clone(),
                recommended_version: recommended_version.clone(),
                dismissed_at: None,
                deferred_until: None,
            });
        }

        // ClearViolation / ResolveInsufficient / WhitelistTyposquat —
        // driven by the policy verdict on the installed version.
        match compliance {
            Compliance::Violation(msg) => {
                let target = package_target(&dep, &installed);
                let id = stable_action_id(ActionKind::ClearViolation, &target, ws_str);
                let title = format!("{}@{} breaks policy", dep.name, installed);
                out.push(Action {
                    id,
                    kind: ActionKind::ClearViolation,
                    severity: ActionKind::ClearViolation.severity(),
                    workspace: ws_str.to_string(),
                    target,
                    title,
                    explanation: msg,
                    suggested_command: suggested.clone(),
                    recommended_version: recommended_version.clone(),
                    dismissed_at: None,
                    deferred_until: None,
                });
            }
            Compliance::InsufficientCandidates(msg) => {
                let target = package_target(&dep, &installed);
                let id = stable_action_id(ActionKind::ResolveInsufficient, &target, ws_str);
                let title = format!("{} has no candidate under current policy", dep.name);
                out.push(Action {
                    id,
                    kind: ActionKind::ResolveInsufficient,
                    severity: ActionKind::ResolveInsufficient.severity(),
                    workspace: ws_str.to_string(),
                    target,
                    title,
                    explanation: msg,
                    suggested_command: None,
                    // Insufficient ⇒ by definition no candidate survives,
                    // so leave the version unset. The dashboard renders
                    // "loosen policy" guidance instead of a version bump.
                    recommended_version: None,
                    dismissed_at: None,
                    deferred_until: None,
                });
            }
            Compliance::TyposquatWarning(_) => {
                if let Some(ts) = stored_malware
                    .iter()
                    .find(|m| matches!(m.kind, MalwareKind::Typosquat))
                {
                    let target = package_target(&dep, &installed);
                    let id = stable_action_id(ActionKind::WhitelistTyposquat, &target, ws_str);
                    let title = format!("{} resembles a popular package", dep.name);
                    let explanation = ts.summary.clone().unwrap_or_else(|| {
                        "Name is close to a top-N legitimate package per the typosquat heuristic.".to_string()
                    });
                    // Pointer at the config, not an install command — the
                    // user decides whether this is a false positive to
                    // whitelist or an actual typosquat to avoid.
                    let command = Some(format!("packguard policy typosquat allow {}", dep.name));
                    out.push(Action {
                        id,
                        kind: ActionKind::WhitelistTyposquat,
                        severity: ActionKind::WhitelistTyposquat.severity(),
                        workspace: ws_str.to_string(),
                        target,
                        title,
                        explanation,
                        suggested_command: command,
                        recommended_version: None,
                        dismissed_at: None,
                        deferred_until: None,
                    });
                }
            }
            _ => {}
        }
    }

    Ok(out)
}

fn generate_rescan_stale(
    store: &Store,
    workspace: &Path,
    ws_str: &str,
    now: DateTime<Utc>,
) -> Result<Vec<Action>> {
    let canon = normalize_repo_path(workspace);
    let row = store
        .scans_index()?
        .into_iter()
        .find(|r| r.path.display().to_string() == canon);
    let Some(row) = row else {
        return Ok(Vec::new());
    };
    let last = match DateTime::parse_from_rfc3339(&row.last_scan_at) {
        Ok(t) => t.to_utc(),
        Err(_) => return Ok(Vec::new()),
    };
    let threshold = now - Duration::days(SCAN_STALE_DAYS);
    if last > threshold {
        return Ok(Vec::new());
    }
    let age_days = (now - last).num_days();
    let target = ActionTarget::Workspace;
    let id = stable_action_id(ActionKind::RescanStale, &target, ws_str);
    Ok(vec![Action {
        id,
        kind: ActionKind::RescanStale,
        severity: ActionKind::RescanStale.severity(),
        workspace: ws_str.to_string(),
        target,
        title: format!("Workspace scanned {age_days}d ago — refresh"),
        explanation: format!(
            "Last scan for this workspace was {age_days} days ago (threshold: {SCAN_STALE_DAYS}d). Rerun `packguard scan` to pick up new advisories and version bumps."
        ),
        suggested_command: Some("packguard scan .".to_string()),
        recommended_version: None,
        dismissed_at: None,
        deferred_until: None,
    }])
}

fn generate_refresh_sync(intel: &IntelStore, now: DateTime<Utc>) -> Result<Vec<Action>> {
    let threshold = now - Duration::days(SYNC_STALE_DAYS);
    let sources = ["osv-npm", "osv-pypi", "ghsa"];
    let mut stale: Vec<(String, i64)> = Vec::new();
    let mut saw_any = false;
    for src in sources {
        if let Some(state) = intel.get_sync_state(src)? {
            saw_any = true;
            // Three buckets: parseable (days), absent (MAX → "never"),
            // non-ISO garbage (MIN → "unrecognized timestamp"). The
            // corruption path exists because a third-party UPDATE could
            // stamp a unix timestamp or junk; Bug 2 eliminates the
            // common case (304 flush) but we still want honest output
            // when it happens.
            match state.synced_at.as_deref() {
                None => stale.push((src.to_string(), i64::MAX)),
                Some(s) => match DateTime::parse_from_rfc3339(s) {
                    Ok(dt) if dt.to_utc() <= threshold => {
                        stale.push((src.to_string(), (now - dt.to_utc()).num_days()))
                    }
                    Ok(_) => {}
                    Err(_) => stale.push((src.to_string(), i64::MIN)),
                },
            }
        }
    }
    // Never synced at all — surface one action so new installs don't
    // silently run with empty advisory tables.
    if !saw_any {
        let target = ActionTarget::Workspace;
        let id = stable_action_id(ActionKind::RefreshSync, &target, GLOBAL_WORKSPACE);
        return Ok(vec![Action {
            id,
            kind: ActionKind::RefreshSync,
            severity: ActionKind::RefreshSync.severity(),
            workspace: GLOBAL_WORKSPACE.to_string(),
            target,
            title: "Advisory DB never synced".to_string(),
            explanation:
                "No sync_log entries found. Run `packguard sync` to seed the OSV + GHSA mirrors."
                    .to_string(),
            suggested_command: Some("packguard sync".to_string()),
            recommended_version: None,
            dismissed_at: None,
            deferred_until: None,
        }]);
    }
    if stale.is_empty() {
        return Ok(Vec::new());
    }
    let max_age = stale.iter().map(|(_, age)| *age).max().unwrap_or(0);
    let has_unrecognized = stale.iter().any(|(_, age)| *age == i64::MIN);
    let labels: Vec<String> = stale
        .iter()
        .map(|(src, age)| match *age {
            i64::MAX => format!("{src} (never)"),
            i64::MIN => format!("{src} (unrecognized timestamp)"),
            n => format!("{src} ({n}d)"),
        })
        .collect();
    let target = ActionTarget::Workspace;
    let id = stable_action_id(ActionKind::RefreshSync, &target, GLOBAL_WORKSPACE);
    Ok(vec![Action {
        id,
        kind: ActionKind::RefreshSync,
        severity: ActionKind::RefreshSync.severity(),
        workspace: GLOBAL_WORKSPACE.to_string(),
        target,
        title: if max_age == i64::MAX || has_unrecognized {
            "Advisory DB out of date — refresh".to_string()
        } else {
            format!("Advisory DB {max_age}d stale — refresh")
        },
        explanation: format!(
            "Stale sync sources: {}. Threshold: {SYNC_STALE_DAYS}d. Run `packguard sync`.",
            labels.join(", "),
        ),
        suggested_command: Some("packguard sync".to_string()),
        recommended_version: None,
        dismissed_at: None,
        deferred_until: None,
    }])
}

fn package_target(dep: &StoredDependency, installed: &str) -> ActionTarget {
    ActionTarget::Package {
        ecosystem: dep.ecosystem.clone(),
        name: dep.name.clone(),
        version: installed.to_string(),
    }
}

fn stored_vuln_to_core(s: packguard_store::StoredVulnerability) -> packguard_core::Vulnerability {
    packguard_core::Vulnerability {
        source: s.source,
        advisory_id: s.advisory_id,
        ecosystem: s.ecosystem,
        package_name: s.package_name,
        severity: s.severity,
        cve_id: s.cve_id,
        aliases: s.aliases,
        summary: s.summary,
        url: s.url,
        affected: s.affected,
        fixed_versions: s.fixed_versions,
        published_at: s.published_at,
        modified_at: s.modified_at,
    }
}

fn stored_malware_to_core(m: &StoredMalware) -> packguard_core::MalwareReport {
    packguard_core::MalwareReport {
        source: m.source.clone(),
        ref_id: m.ref_id.clone(),
        ecosystem: m.ecosystem.clone(),
        package_name: m.package_name.clone(),
        version: m.version.clone().unwrap_or_default(),
        kind: m.kind,
        summary: m.summary.clone(),
        url: m.url.clone(),
        evidence: m.evidence.clone(),
        reported_at: m.reported_at.clone(),
    }
}

/// Minimum severity filter for the dashboard/CLI. Retains actions whose
/// severity is at least `threshold`. Used by the HTTP endpoint's
/// `?min_severity=<level>` query param.
pub fn filter_min_severity(actions: &mut Vec<Action>, threshold: ActionSeverity) {
    actions.retain(|a| a.severity >= threshold);
}
