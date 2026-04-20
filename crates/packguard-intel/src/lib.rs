//! PackGuard vulnerability intel.
//!
//! Phase 2: pull OSV dumps (npm + PyPI) and the GitHub Advisory Database
//! git repo, parse each advisory into `packguard_core::Vulnerability`, and
//! hand the filtered list off to the caller (typically `packguard-store`).
//! Dedup of OSV×GHSA happens at match time in `packguard-policy` — the
//! store keeps one row per `(source, advisory_id, pkg_id)`.

pub mod ghsa;
pub mod malware;
pub mod matcher;
pub mod normalize;
pub mod osv;
pub mod osv_api;
pub mod socket;
pub mod typosquat;

pub use matcher::{match_vulnerabilities, version_matches_spec, MatchedVuln};
pub use osv_api::{osv_ecosystem, OsvApiClient};

use packguard_core::{MalwareReport, Vulnerability};
use std::collections::HashSet;

/// Aggregated outcome of a `sync` run, used by the CLI for the status line.
#[derive(Debug, Clone, Default)]
pub struct SyncSummary {
    pub osv_npm: SourceSummary,
    pub osv_pypi: SourceSummary,
    pub ghsa: SourceSummary,
}

#[derive(Debug, Clone, Default)]
pub struct SourceSummary {
    pub advisories_scanned: usize,
    pub advisories_persisted: usize,
    pub skipped_not_modified: bool,
    pub error: Option<String>,
}

/// A `(ecosystem, normalized_name)` filter. When present, only advisories
/// touching these packages survive the pipeline. `None` = keep all (useful
/// for a cold warm-up pass).
pub type WatchedPackages = Option<HashSet<(String, String)>>;

/// Apply the watched filter to a fresh batch of normalized advisories.
pub fn filter_watched(vulns: Vec<Vulnerability>, watched: &WatchedPackages) -> Vec<Vulnerability> {
    match watched {
        None => vulns,
        Some(set) => vulns
            .into_iter()
            .filter(|v| set.contains(&(v.ecosystem.clone(), v.package_name.clone())))
            .collect(),
    }
}

/// Same shape, applied to malware reports.
pub fn filter_watched_malware(
    reports: Vec<MalwareReport>,
    watched: &WatchedPackages,
) -> Vec<MalwareReport> {
    match watched {
        None => reports,
        Some(set) => reports
            .into_iter()
            .filter(|r| set.contains(&(r.ecosystem.clone(), r.package_name.clone())))
            .collect(),
    }
}
