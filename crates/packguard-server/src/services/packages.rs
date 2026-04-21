//! Packages list + per-package detail. The list endpoint applies filters,
//! sort, and pagination on a fully-evaluated row set — Nalo-scale data
//! (~120 watched packages × ~260 advisories) fits comfortably in memory,
//! and SQL-side filtering against denormalized aggregates would be a much
//! bigger schema change for marginal benefit.

use crate::dto::{
    ComplianceTag, MalwareEntry, PackageDetail, PackageRisk, PackageRow, PackagesPage,
    PackagesQuery, PolicyTrace, VersionRow, VulnerabilityEntry,
};
use anyhow::Result;
use packguard_core::{MalwareKind, Severity};
use packguard_intel::match_vulnerabilities;
use packguard_policy::{
    compute_recommended_version_full, evaluate_dependency_full, Compliance, Dialect, Policy,
    Stability,
};
use packguard_store::Store;

/// `PackageRow` + the dependency it came from so the overview service can
/// fold it into top-risk computation without re-querying.
pub struct PackageRowFull {
    pub row: PackageRow,
}

pub fn list(
    store: &Store,
    query: &PackagesQuery,
    project: Option<&std::path::Path>,
) -> Result<PackagesPage> {
    let policy = crate::services::policies::current_policy_or_default()?;
    let now = chrono::Utc::now();

    let watched = match project {
        Some(p) => store.watched_packages_for_path(p)?,
        None => store.watched_packages()?,
    };
    let mut rows: Vec<PackageRow> = Vec::with_capacity(watched.len());
    for (eco, name) in watched {
        if let Some(full) = evaluate_row(store, &policy, &now, &eco, &name)? {
            rows.push(full.row);
        }
    }

    apply_filters(&mut rows, query);
    apply_sort(&mut rows, query);

    let total = rows.len() as u32;
    let per_page = query.per_page.unwrap_or(50).clamp(1, 500);
    let page = query.page.unwrap_or(1).max(1);
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(rows.len());
    let page_rows = if start >= rows.len() {
        Vec::new()
    } else {
        rows[start..end].to_vec()
    };

    Ok(PackagesPage {
        total,
        page,
        per_page,
        rows: page_rows,
    })
}

pub fn detail(store: &Store, ecosystem: &str, name: &str) -> Result<Option<PackageDetail>> {
    let policy = crate::services::policies::current_policy_or_default()?;
    let now = chrono::Utc::now();

    let Some(full) = evaluate_row(store, &policy, &now, ecosystem, name)? else {
        return Ok(None);
    };

    let stored_versions = store.load_package_versions(ecosystem, name)?;
    let stored_vulns = store.load_vulnerabilities(ecosystem, name)?;
    let stored_malware = store.load_malware_reports(ecosystem, name)?;

    // Re-run the matcher per-version so we can colour each row by the
    // highest severity affecting it. The list stays small (<= 500 versions
    // in practice, including sentry-sdk's 329) so recomputing is fine.
    let advisories: Vec<packguard_core::Vulnerability> = stored_vulns
        .iter()
        .cloned()
        .map(stored_vuln_to_core)
        .collect();

    let versions: Vec<VersionRow> = stored_versions
        .iter()
        .map(|v| {
            let matches = match_vulnerabilities(ecosystem, name, &v.version, &advisories);
            let severity = matches
                .iter()
                .map(|m| m.severity)
                .max()
                .filter(|s| !matches!(s, Severity::Unknown))
                .map(|s| s.as_str().to_string());
            VersionRow {
                version: v.version.clone(),
                published_at: v.published_at.clone(),
                deprecated: v.deprecated,
                yanked: v.yanked,
                severity,
            }
        })
        .collect();

    let installed = full.row.installed.clone();
    let installed_matches: Vec<packguard_intel::MatchedVuln> = installed
        .as_deref()
        .map(|v| match_vulnerabilities(ecosystem, name, v, &advisories))
        .unwrap_or_default();

    let vulnerabilities: Vec<VulnerabilityEntry> = stored_vulns
        .iter()
        .map(|v| VulnerabilityEntry {
            source: v.source.clone(),
            advisory_id: v.advisory_id.clone(),
            cve_id: v.cve_id.clone(),
            severity: v.severity.as_str().to_string(),
            summary: v.summary.clone(),
            url: v.url.clone(),
            fixed_versions: v.fixed_versions.clone(),
            affects_installed: installed_matches
                .iter()
                .any(|m| m.advisory_id == v.advisory_id && m.source == v.source),
        })
        .collect();

    let malware: Vec<MalwareEntry> = stored_malware
        .iter()
        .map(|m| MalwareEntry {
            source: m.source.clone(),
            ref_id: m.ref_id.clone(),
            kind: match m.kind {
                MalwareKind::Malware => "malware",
                MalwareKind::Typosquat => "typosquat",
                MalwareKind::ScannerSignal => "scanner_signal",
            }
            .to_string(),
            version: m.version.clone(),
            summary: m.summary.clone(),
            url: m.url.clone(),
            reported_at: m.reported_at.clone(),
        })
        .collect();

    // Policy trace: the resolved rule + the version the policy would pick.
    let resolved = policy.resolve(name);
    let releases: Vec<packguard_policy::ReleaseInfo> = stored_versions
        .iter()
        .cloned()
        .map(|v| packguard_policy::ReleaseInfo {
            version: v.version,
            published_at: v.published_at,
            deprecated: v.deprecated,
            yanked: v.yanked,
        })
        .collect();
    let mut vulns_by_version: packguard_policy::VulnsByVersion = Default::default();
    for r in &releases {
        let m = match_vulnerabilities(ecosystem, name, &r.version, &advisories);
        if !m.is_empty() {
            vulns_by_version.insert(r.version.clone(), m);
        }
    }
    let malware_core: Vec<packguard_core::MalwareReport> = stored_malware
        .iter()
        .map(|m| packguard_core::MalwareReport {
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
        })
        .collect();
    let dialect = Dialect::for_ecosystem(ecosystem);
    let recommended = compute_recommended_version_full(
        &resolved,
        &releases,
        &vulns_by_version,
        &malware_core,
        dialect,
        now,
    );
    let policy_trace = PolicyTrace {
        offset: resolved.offset,
        pin: resolved.pin.clone(),
        stability: match resolved.stability {
            Stability::Stable => "stable",
            Stability::Prerelease => "pre",
        }
        .to_string(),
        min_age_days: resolved.min_age_days,
        recommended: recommended.clone(),
        reason: trace_reason(
            &full.row.compliance,
            installed.as_deref(),
            recommended.as_deref(),
        ),
    };

    Ok(Some(PackageDetail {
        ecosystem: full.row.ecosystem,
        name: full.row.name,
        installed: full.row.installed,
        latest: full.row.latest,
        last_scanned_at: full.row.last_scanned_at,
        compliance: full.row.compliance,
        risk: full.row.risk,
        versions,
        vulnerabilities,
        malware,
        policy_trace,
    }))
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

fn trace_reason(tag: &ComplianceTag, installed: Option<&str>, recommended: Option<&str>) -> String {
    let installed = installed.unwrap_or("—");
    match tag {
        ComplianceTag::Compliant => format!("{installed} is within policy."),
        ComplianceTag::Warning => match recommended {
            Some(r) if r != installed => format!("behind policy — recommend {r}"),
            _ => "behind policy".to_string(),
        },
        ComplianceTag::Violation => match recommended {
            Some(r) => format!("blocked by policy — recommend {r}"),
            None => "blocked by policy — no compliant candidate".to_string(),
        },
        ComplianceTag::CveViolation => match recommended {
            Some(r) => format!("installed {installed} has a blocking CVE — upgrade to {r}"),
            None => format!("installed {installed} has a blocking CVE — no safe candidate"),
        },
        ComplianceTag::Malware => "installed version flagged as malware".to_string(),
        ComplianceTag::Typosquat => "name resembles a top-N legitimate package".to_string(),
        ComplianceTag::Insufficient => {
            "no candidate survives the current policy filters".to_string()
        }
    }
}

/// Evaluate one (ecosystem, name) pair against the active policy, building
/// the full row used by both the list and overview views. Returns `None`
/// when the package isn't tracked under any workspace yet.
pub fn evaluate_row(
    store: &Store,
    policy: &Policy,
    now: &chrono::DateTime<chrono::Utc>,
    ecosystem: &str,
    name: &str,
) -> Result<Option<PackageRowFull>> {
    // Match this (eco, name) against the dependency rows that point at it.
    // Multiple repos / workspaces may pin the same package — for the row
    // view we collapse to the first occurrence; richer breakdowns are 4b.
    let dep = match dependency_for(store, ecosystem, name)? {
        Some(d) => d,
        None => return Ok(None),
    };

    let releases: Vec<packguard_policy::ReleaseInfo> = store
        .load_package_versions(ecosystem, name)?
        .into_iter()
        .map(|v| packguard_policy::ReleaseInfo {
            version: v.version,
            published_at: v.published_at,
            deprecated: v.deprecated,
            yanked: v.yanked,
        })
        .collect();

    let stored_vulns = store.load_vulnerabilities(ecosystem, name)?;
    let advisories: Vec<packguard_core::Vulnerability> = stored_vulns
        .into_iter()
        .map(|s| packguard_core::Vulnerability {
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
        })
        .collect();

    let installed_str = dep.installed.clone().unwrap_or_default();
    let mut vulns_by_version: packguard_policy::VulnsByVersion = Default::default();
    let mut version_keys: Vec<String> = releases.iter().map(|r| r.version.clone()).collect();
    if !installed_str.is_empty() && !version_keys.iter().any(|v| v == &installed_str) {
        version_keys.push(installed_str.clone());
    }
    for version in version_keys {
        let matches = match_vulnerabilities(ecosystem, name, &version, &advisories);
        if !matches.is_empty() {
            vulns_by_version.insert(version, matches);
        }
    }
    let cve_for_installed = vulns_by_version
        .get(installed_str.as_str())
        .cloned()
        .unwrap_or_default();

    let stored_malware = store.load_malware_reports(ecosystem, name)?;
    let malware_core: Vec<packguard_core::MalwareReport> = stored_malware
        .iter()
        .map(|m| packguard_core::MalwareReport {
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
        })
        .collect();

    let resolved = policy.resolve(name);
    let dialect = Dialect::for_ecosystem(ecosystem);
    let compliance = evaluate_dependency_full(
        name,
        dep.installed.as_deref(),
        &resolved,
        &releases,
        &vulns_by_version,
        &malware_core,
        dialect,
        *now,
    );

    let risk = PackageRisk {
        critical: count_severity(&cve_for_installed, Severity::Critical),
        high: count_severity(&cve_for_installed, Severity::High),
        medium: count_severity(&cve_for_installed, Severity::Medium),
        low: count_severity(&cve_for_installed, Severity::Low),
        malware_confirmed: stored_malware
            .iter()
            .filter(|m| matches!(m.kind, packguard_core::MalwareKind::Malware))
            .filter(|m| m.version.is_none() || m.version.as_deref() == Some(installed_str.as_str()))
            .count() as u32,
        typosquat_suspects: stored_malware
            .iter()
            .filter(|m| matches!(m.kind, packguard_core::MalwareKind::Typosquat))
            .count() as u32,
    };

    let row = PackageRow {
        ecosystem: dep.ecosystem.clone(),
        name: dep.name.clone(),
        installed: dep.installed.clone(),
        latest: dep.latest.clone(),
        kind: dep_kind_str(dep.kind),
        compliance: compliance_tag(&compliance),
        risk,
        last_scanned_at: dep.latest_published_at.clone(),
    };
    Ok(Some(PackageRowFull { row }))
}

fn count_severity(vulns: &[packguard_intel::MatchedVuln], target: Severity) -> u32 {
    vulns.iter().filter(|v| v.severity == target).count() as u32
}

fn dep_kind_str(k: packguard_core::DepKind) -> String {
    match k {
        packguard_core::DepKind::Runtime => "dep",
        packguard_core::DepKind::Dev => "dev",
        packguard_core::DepKind::Peer => "peer",
        packguard_core::DepKind::Optional => "opt",
    }
    .into()
}

fn compliance_tag(c: &Compliance) -> ComplianceTag {
    match c {
        Compliance::Compliant => ComplianceTag::Compliant,
        Compliance::Warning(_) => ComplianceTag::Warning,
        Compliance::Violation(_) => ComplianceTag::Violation,
        Compliance::VulnerabilityViolation(_) => ComplianceTag::CveViolation,
        Compliance::MalwareViolation(_) => ComplianceTag::Malware,
        Compliance::TyposquatWarning(_) => ComplianceTag::Typosquat,
        Compliance::InsufficientCandidates(_) => ComplianceTag::Insufficient,
    }
}

/// First StoredDependency row that points at this (ecosystem, name) — we
/// already JOIN packages in `load_repo_dependencies`, but we need the
/// per-package view, so a small ad-hoc helper.
fn dependency_for(
    store: &Store,
    ecosystem: &str,
    name: &str,
) -> Result<Option<packguard_store::StoredDependency>> {
    // Walk every repo's dependencies; the watched-package set is small.
    // Phase 4b might index this by package_id, not by repo path — for now
    // a single sweep is fine.
    let watched = store.watched_packages()?;
    if !watched.iter().any(|(e, n)| e == ecosystem && n == name) {
        return Ok(None);
    }
    // Walk every distinct repo path the store has scanned and pick the rows
    // that match our (ecosystem, name) pair. The dataset is small enough
    // (Nalo: 2 repos × ~120 deps) that a per-repo sweep is cheaper than a
    // schema change to index dependencies by package_id directly.
    let mut all_deps: Vec<packguard_store::StoredDependency> = Vec::new();
    for path in store.distinct_repo_paths()? {
        for d in store.load_repo_dependencies(&path)? {
            if d.ecosystem == ecosystem && d.name == name {
                all_deps.push(d);
            }
        }
    }
    // Prefer the first occurrence with an `installed` value when available.
    let with_installed = all_deps.iter().find(|d| d.installed.is_some()).cloned();
    Ok(with_installed.or_else(|| all_deps.into_iter().next()))
}

fn apply_filters(rows: &mut Vec<PackageRow>, q: &PackagesQuery) {
    if let Some(eco) = q.ecosystem.as_deref() {
        rows.retain(|r| r.ecosystem == eco);
    }
    if let Some(status) = q.status.as_deref() {
        rows.retain(|r| compliance_str(&r.compliance) == status);
    }
    if let Some(sev) = q.min_severity.as_deref() {
        let threshold = Severity::parse(sev);
        rows.retain(|r| meets_severity(&r.risk, threshold));
    }
    if matches!(q.has_malware, Some(true)) {
        rows.retain(|r| r.risk.malware_confirmed > 0);
    }
    if matches!(q.has_typosquat, Some(true)) {
        rows.retain(|r| r.risk.typosquat_suspects > 0);
    }
    if let Some(needle) = q.q.as_deref() {
        let needle = needle.to_ascii_lowercase();
        rows.retain(|r| r.name.to_ascii_lowercase().contains(&needle));
    }
}

fn meets_severity(risk: &PackageRisk, threshold: Severity) -> bool {
    let max = if risk.critical > 0 {
        Severity::Critical
    } else if risk.high > 0 {
        Severity::High
    } else if risk.medium > 0 {
        Severity::Medium
    } else if risk.low > 0 {
        Severity::Low
    } else {
        Severity::Unknown
    };
    max >= threshold
}

fn compliance_str(tag: &ComplianceTag) -> &'static str {
    match tag {
        ComplianceTag::Compliant => "compliant",
        ComplianceTag::Warning => "warning",
        ComplianceTag::Violation => "violation",
        ComplianceTag::CveViolation => "cve-violation",
        ComplianceTag::Malware => "malware",
        ComplianceTag::Typosquat => "typosquat",
        ComplianceTag::Insufficient => "insufficient",
    }
}

fn apply_sort(rows: &mut [PackageRow], q: &PackagesQuery) {
    let sort = q.sort.as_deref().unwrap_or("name");
    let asc = matches!(q.dir.as_deref(), Some("asc")) || q.dir.is_none() && sort != "risk";
    rows.sort_by(|a, b| {
        let ord = match sort {
            "ecosystem" => a.ecosystem.cmp(&b.ecosystem).then(a.name.cmp(&b.name)),
            "compliance" => compliance_rank(&a.compliance)
                .cmp(&compliance_rank(&b.compliance))
                .then(a.name.cmp(&b.name)),
            "risk" => risk_score(&a.risk).cmp(&risk_score(&b.risk)),
            _ => a.name.cmp(&b.name),
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn compliance_rank(tag: &ComplianceTag) -> u8 {
    match tag {
        ComplianceTag::Malware | ComplianceTag::CveViolation | ComplianceTag::Violation => 0,
        ComplianceTag::Insufficient => 1,
        ComplianceTag::Typosquat | ComplianceTag::Warning => 2,
        ComplianceTag::Compliant => 3,
    }
}

fn risk_score(risk: &PackageRisk) -> u32 {
    risk.critical * 10
        + risk.high * 5
        + risk.medium * 2
        + risk.low
        + risk.malware_confirmed * 20
        + risk.typosquat_suspects
}
