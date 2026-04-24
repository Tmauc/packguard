//! ts-rs drift gate.
//!
//! Two passes (selected by the `PACKGUARD_REGEN_TYPES` env var):
//!
//! - **regen** (`PACKGUARD_REGEN_TYPES=1`): re-export every DTO into
//!   `dashboard/src/api/types/`, overwriting the committed copies. Use
//!   this after editing a struct that has `#[derive(TS)]`.
//! - **check** (default): export into a tempdir and diff against the
//!   committed files. Drift fails the test with a one-line reproducer.
//!
//! Plain `cargo test` catches drift — no extra CI step required.

use packguard_actions as actions;
use packguard_server::dto;
use std::path::{Path, PathBuf};
use ts_rs::TS;

fn dashboard_types_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("dashboard")
        .join("src")
        .join("api")
        .join("types")
}

/// Write every DTO to `target`. Each call clears the dir first so orphan
/// files (renamed structs, removed types) don't linger.
fn export_all(target: &Path) {
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("ts") {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    std::fs::create_dir_all(target).unwrap();
    macro_rules! flush { ($($t:ty),* $(,)?) => { $( <$t as TS>::export_all_to(target).unwrap(); )* }; }
    flush!(
        dto::Overview,
        dto::EcoCount,
        dto::VulnSummary,
        dto::MalwareSummary,
        dto::ComplianceSummary,
        dto::RiskRow,
        dto::PackagesQuery,
        dto::PackageRow,
        dto::PackageRisk,
        dto::ComplianceTag,
        dto::PackagesPage,
        dto::PackageDetail,
        dto::VersionRow,
        dto::VulnerabilityEntry,
        dto::MalwareEntry,
        dto::PolicyTrace,
        dto::PolicySourceDto,
        dto::PolicyProvenanceEntry,
        dto::PolicyDocument,
        dto::PolicyWrite,
        dto::PolicyDryRun,
        dto::PolicyDryRunResult,
        dto::PolicyDryRunChange,
        dto::YamlErrorLocation,
        dto::JobStatus,
        dto::JobKind,
        dto::JobView,
        dto::JobAccepted,
        dto::ScanReport,
        dto::SyncReport,
        dto::GraphQuery,
        dto::GraphResponse,
        dto::GraphNode,
        dto::GraphEdge,
        dto::ContaminatedQuery,
        dto::ContaminationResult,
        dto::ContaminationHit,
        dto::ContaminationChain,
        dto::GraphVulnerabilityEntry,
        dto::GraphVulnerabilityList,
        dto::CompatResponse,
        dto::CompatRow,
        dto::CompatPeerDep,
        dto::CompatDependent,
        dto::WorkspaceInfo,
        dto::WorkspacesResponse,
        dto::ProjectQuery,
        dto::ActionsQuery,
        dto::ActionsResponse,
        dto::ActionDismissRequest,
        dto::ActionDeferRequest,
        dto::ActionDismissResponse,
        dto::ActionDeferResponse,
        actions::Action,
        actions::ActionKind,
        actions::ActionSeverity,
        actions::ActionTarget,
    );
}

#[test]
fn ts_types_match_committed_or_can_be_regenerated() {
    let target = dashboard_types_dir();
    if std::env::var("PACKGUARD_REGEN_TYPES").is_ok() {
        export_all(&target);
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    export_all(temp.path());

    let mut diffs: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(temp.path()).unwrap().flatten() {
        let path = entry.path();
        let Some(name) = path.file_name() else {
            continue;
        };
        if path.extension().and_then(|s| s.to_str()) != Some("ts") {
            continue;
        }
        let committed = target.join(name);
        let fresh = std::fs::read(&path).unwrap();
        let stored = std::fs::read(&committed).unwrap_or_default();
        if fresh != stored {
            diffs.push(name.to_string_lossy().into_owned());
        }
    }
    if let Ok(entries) = std::fs::read_dir(&target) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name() else {
                continue;
            };
            if path.extension().and_then(|s| s.to_str()) != Some("ts") {
                continue;
            }
            if !temp.path().join(name).exists() {
                diffs.push(format!("{} (orphan)", name.to_string_lossy()));
            }
        }
    }

    assert!(
        diffs.is_empty(),
        "ts-rs drift detected: {}\n  → run `PACKGUARD_REGEN_TYPES=1 cargo test -p packguard-server --test types_drift` to refresh.",
        diffs.join(", ")
    );
}
