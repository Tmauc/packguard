//! Phase 7a: workspace enumeration for the header selector + the
//! "Available scans" hints surfaced by error messages. Thin translation
//! from `packguard_store::ScanIndexRow` to the wire DTO.

use crate::dto::{WorkspaceInfo, WorkspacesResponse};
use anyhow::Result;
use packguard_store::Store;

pub fn list(store: &Store) -> Result<WorkspacesResponse> {
    let rows = store.scans_index()?;
    let workspaces = rows
        .into_iter()
        .map(|r| WorkspaceInfo {
            path: r.path.display().to_string(),
            ecosystem: r.ecosystem,
            last_scan_at: r.last_scan_at,
            fingerprint: r.fingerprint,
            dependency_count: r.dependency_count,
        })
        .collect();
    Ok(WorkspacesResponse { workspaces })
}
