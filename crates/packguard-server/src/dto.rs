//! Wire DTOs. All annotated with `ts_rs::TS` so a single export pass
//! produces the matching `dashboard/src/api/types/*.ts`. The drift test
//! lives in `tests/types_drift.rs`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

// ---- Overview --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "Overview.ts")]
pub struct Overview {
    /// 0..=100, computed as `compliant / total * 100` (no scan → null).
    pub health_score: Option<u32>,
    pub last_scan_at: Option<String>,
    pub last_sync_at: Option<String>,
    pub packages_total: u32,
    pub packages_by_ecosystem: Vec<EcoCount>,
    pub vulnerabilities: VulnSummary,
    pub malware: MalwareSummary,
    pub compliance: ComplianceSummary,
    pub top_risks: Vec<RiskRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "EcoCount.ts")]
pub struct EcoCount {
    pub ecosystem: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "VulnSummary.ts")]
pub struct VulnSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "MalwareSummary.ts")]
pub struct MalwareSummary {
    pub confirmed: u32,
    pub typosquat_suspects: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "ComplianceSummary.ts")]
pub struct ComplianceSummary {
    pub compliant: u32,
    pub warnings: u32,
    pub violations: u32,
    pub insufficient: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "RiskRow.ts")]
pub struct RiskRow {
    pub ecosystem: String,
    pub name: String,
    pub installed: Option<String>,
    /// Weighted: critical=10, high=5, medium=2, low=1, malware=20, typosquat=1.
    pub score: u32,
    pub reason: String,
}

// ---- Packages list ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PackagesQuery.ts")]
pub struct PackagesQuery {
    pub ecosystem: Option<String>,
    pub status: Option<String>,
    pub min_severity: Option<String>,
    pub has_malware: Option<bool>,
    pub has_typosquat: Option<bool>,
    pub q: Option<String>,
    pub sort: Option<String>, // "name" | "ecosystem" | "compliance" | "risk"
    pub dir: Option<String>,  // "asc" | "desc"
    pub page: Option<u32>,    // 1-based
    pub per_page: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PackageRow.ts")]
pub struct PackageRow {
    pub ecosystem: String,
    pub name: String,
    pub installed: Option<String>,
    pub latest: Option<String>,
    pub kind: String,
    pub compliance: ComplianceTag,
    pub risk: PackageRisk,
    pub last_scanned_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PackageRisk.ts")]
pub struct PackageRisk {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub malware_confirmed: u32,
    pub typosquat_suspects: u32,
}

/// Mirror of `packguard_policy::Compliance` flattened to a string tag — the
/// frontend only needs the kind, not the full payload.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "ComplianceTag.ts")]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceTag {
    Compliant,
    Warning,
    Violation,
    CveViolation,
    Malware,
    Typosquat,
    Insufficient,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PackagesPage.ts")]
pub struct PackagesPage {
    pub total: u32,
    pub page: u32,
    pub per_page: u32,
    pub rows: Vec<PackageRow>,
}

// ---- Package detail (4a: skeleton, 4b: enriched) ---------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PackageDetail.ts")]
pub struct PackageDetail {
    pub ecosystem: String,
    pub name: String,
    pub installed: Option<String>,
    pub latest: Option<String>,
    pub last_scanned_at: Option<String>,
    pub compliance: ComplianceTag,
    pub risk: PackageRisk,
    pub versions: Vec<VersionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "VersionRow.ts")]
pub struct VersionRow {
    pub version: String,
    pub published_at: Option<String>,
    pub deprecated: bool,
    pub yanked: bool,
}

// ---- Policy ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "PolicyDocument.ts")]
pub struct PolicyDocument {
    /// Raw `.packguard.yml` contents (or the conservative defaults when no
    /// file is present).
    pub yaml: String,
    /// `true` when the YAML lives on disk; `false` when we're returning the
    /// embedded conservative defaults.
    pub from_file: bool,
}

// ---- Jobs ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export, export_to = "JobStatus.ts")]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => JobStatus::Pending,
            "running" => JobStatus::Running,
            "succeeded" => JobStatus::Succeeded,
            "failed" => JobStatus::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export, export_to = "JobKind.ts")]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    Scan,
    Sync,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Scan => "scan",
            JobKind::Sync => "sync",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "JobView.ts")]
pub struct JobView {
    pub id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "JobAccepted.ts")]
pub struct JobAccepted {
    pub id: String,
}

// ---- Scan / Sync result payloads (stored in jobs.result_json) --------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "ScanReport.ts")]
pub struct ScanReport {
    pub projects_scanned: u32,
    pub packages_persisted: u32,
    pub registry_errors: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "SyncReport.ts")]
pub struct SyncReport {
    pub osv_npm_persisted: u32,
    pub osv_pypi_persisted: u32,
    pub ghsa_persisted: u32,
    pub typosquat_suspects: u32,
}
