//! Overview endpoint backing the dashboard's home page.

use crate::dto::{
    ComplianceSummary, ComplianceTag, EcoCount, MalwareSummary, Overview, RiskRow, VulnSummary,
};
use crate::services::packages::{evaluate_row, PackageRowFull};
use anyhow::Result;
use packguard_store::Store;
use std::collections::BTreeMap;

pub fn build(store: &Store, project: Option<&std::path::Path>) -> Result<Overview> {
    let rows = evaluate_all(store, project)?;
    let packages_total = rows.len() as u32;

    // Per-ecosystem package counts (deterministic order via BTreeMap).
    let mut by_eco: BTreeMap<String, u32> = BTreeMap::new();
    for r in &rows {
        *by_eco.entry(r.row.ecosystem.clone()).or_default() += 1;
    }
    let packages_by_ecosystem: Vec<EcoCount> = by_eco
        .into_iter()
        .map(|(ecosystem, count)| EcoCount { ecosystem, count })
        .collect();

    // Sums.
    let mut vuln = VulnSummary::default();
    let mut malware = MalwareSummary::default();
    let mut compliance = ComplianceSummary::default();
    for r in &rows {
        vuln.critical += r.row.risk.critical;
        vuln.high += r.row.risk.high;
        vuln.medium += r.row.risk.medium;
        vuln.low += r.row.risk.low;
        malware.confirmed += r.row.risk.malware_confirmed;
        malware.typosquat_suspects += r.row.risk.typosquat_suspects;
        match r.row.compliance {
            ComplianceTag::Compliant => compliance.compliant += 1,
            ComplianceTag::Warning | ComplianceTag::Typosquat => compliance.warnings += 1,
            ComplianceTag::Violation | ComplianceTag::CveViolation | ComplianceTag::Malware => {
                compliance.violations += 1
            }
            ComplianceTag::Insufficient => compliance.insufficient += 1,
        }
    }

    let health_score = if packages_total == 0 {
        None
    } else {
        Some((compliance.compliant * 100) / packages_total)
    };

    // Top-5 risk: weighted CVE severity + malware bonus + typosquat tap.
    let mut scored: Vec<(u32, &PackageRowFull, String)> = rows
        .iter()
        .map(|r| {
            let s = r.row.risk.critical * 10
                + r.row.risk.high * 5
                + r.row.risk.medium * 2
                + r.row.risk.low
                + r.row.risk.malware_confirmed * 20
                + r.row.risk.typosquat_suspects;
            let mut bits: Vec<String> = Vec::new();
            if r.row.risk.critical + r.row.risk.high > 0 {
                bits.push(format!(
                    "{} crit/high CVE",
                    r.row.risk.critical + r.row.risk.high
                ));
            }
            if r.row.risk.malware_confirmed > 0 {
                bits.push(format!("{} malware", r.row.risk.malware_confirmed));
            }
            if r.row.risk.typosquat_suspects > 0 {
                bits.push("typosquat".into());
            }
            if bits.is_empty() {
                bits.push(match r.row.compliance {
                    ComplianceTag::Insufficient => "insufficient candidates".into(),
                    ComplianceTag::Warning => "behind policy".into(),
                    _ => "—".into(),
                });
            }
            (s, r, bits.join(", "))
        })
        .filter(|(s, ..)| *s > 0)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let top_risks: Vec<RiskRow> = scored
        .into_iter()
        .take(5)
        .map(|(score, full, reason)| RiskRow {
            ecosystem: full.row.ecosystem.clone(),
            name: full.row.name.clone(),
            installed: full.row.installed.clone(),
            score,
            reason,
        })
        .collect();

    let last_scan_at = rows
        .iter()
        .filter_map(|r| r.row.last_scanned_at.clone())
        .max();
    let last_sync_at = store
        .get_sync_state("osv-npm")
        .ok()
        .flatten()
        .and_then(|s| s.synced_at)
        .max(
            store
                .get_sync_state("osv-pypi")
                .ok()
                .flatten()
                .and_then(|s| s.synced_at),
        );

    Ok(Overview {
        health_score,
        last_scan_at,
        last_sync_at,
        packages_total,
        packages_by_ecosystem,
        vulnerabilities: vuln,
        malware,
        compliance,
        top_risks,
    })
}

fn evaluate_all(store: &Store, project: Option<&std::path::Path>) -> Result<Vec<PackageRowFull>> {
    let watched = match project {
        Some(p) => store.watched_packages_for_path(p)?,
        None => store.watched_packages()?,
    };
    let policy = crate::services::policies::current_policy_or_default()?;
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for (eco, name) in watched {
        if let Some(row) = evaluate_row(store, &policy, &now, &eco, &name)? {
            out.push(row);
        }
    }
    Ok(out)
}
