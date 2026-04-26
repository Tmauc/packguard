//! Wire DTOs. All annotated with `ts_rs::TS` so a single export pass
//! produces the matching `dashboard/src/api/types/*.ts`. The drift test
//! lives in `tests/types_drift.rs`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

// ---- Overview --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "Overview.ts")]
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
#[ts(export_to = "EcoCount.ts")]
pub struct EcoCount {
    pub ecosystem: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "VulnSummary.ts")]
pub struct VulnSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "MalwareSummary.ts")]
pub struct MalwareSummary {
    pub confirmed: u32,
    pub typosquat_suspects: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ComplianceSummary.ts")]
pub struct ComplianceSummary {
    pub compliant: u32,
    pub warnings: u32,
    pub violations: u32,
    pub insufficient: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "RiskRow.ts")]
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
#[ts(export_to = "PackagesQuery.ts")]
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
    /// Phase 7: scope the listing to a single workspace's dependencies
    /// (direct + transitive). Must match one of the paths returned by
    /// `/api/workspaces`. `None` returns the aggregate across every
    /// scanned repo.
    pub project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PackageRow.ts")]
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
#[ts(export_to = "PackageRisk.ts")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export_to = "ComplianceTag.ts")]
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
#[ts(export_to = "PackagesPage.ts")]
pub struct PackagesPage {
    pub total: u32,
    pub page: u32,
    pub per_page: u32,
    pub rows: Vec<PackageRow>,
}

// ---- Package detail --------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PackageDetail.ts")]
pub struct PackageDetail {
    pub ecosystem: String,
    pub name: String,
    pub installed: Option<String>,
    pub latest: Option<String>,
    pub last_scanned_at: Option<String>,
    pub compliance: ComplianceTag,
    pub risk: PackageRisk,
    pub versions: Vec<VersionRow>,
    /// Every advisory that matches *any* known version of this package — the
    /// `affects_installed` flag marks the subset that drives the compliance
    /// tag. The timeline uses the full list to colour individual markers.
    pub vulnerabilities: Vec<VulnerabilityEntry>,
    /// Malware + typosquat intel. Empty when the package is clean.
    pub malware: Vec<MalwareEntry>,
    /// Resolved policy + why the installed version is (not) compliant.
    pub policy_trace: PolicyTrace,
    /// Phase 10c — the cascade chain that produced the effective policy,
    /// in merge order (lowest priority first). Empty when the endpoint
    /// is called without a `project` query param (scope-less access
    /// falls back to built-in defaults).
    #[serde(default)]
    pub policy_sources: Vec<PolicySourceDto>,
    /// Phase 10c — per-key provenance map. Keys are dot-notation like
    /// `defaults.offset.major`; values point at the source in
    /// `policy_sources` that last set them. Empty alongside
    /// `policy_sources` when no `project` scope is passed.
    #[serde(default)]
    pub policy_provenance: Vec<PolicyProvenanceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicySourceDto.ts")]
pub struct PolicySourceDto {
    /// "built_in" | "user_wide" | "file" | "extends".
    pub kind: String,
    /// User-facing label: "built-in default", "~/.packguard.yml", or
    /// the absolute file path.
    pub label: String,
    /// Absolute path when the source is a file; `None` for built-in.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyProvenanceEntry.ts")]
pub struct PolicyProvenanceEntry {
    /// Dot-notation key (`defaults.offset.major`, …).
    pub key: String,
    /// Index into `policy_sources`.
    pub source_index: u32,
    /// Best-effort 1-based YAML line; `None` when not resolvable.
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "VersionRow.ts")]
pub struct VersionRow {
    pub version: String,
    pub published_at: Option<String>,
    pub deprecated: bool,
    pub yanked: bool,
    /// Highest severity of advisories matching this version; `None` when the
    /// version is clean. Drives the marker colour on the timeline.
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "VulnerabilityEntry.ts")]
pub struct VulnerabilityEntry {
    pub source: String,
    pub advisory_id: String,
    pub cve_id: Option<String>,
    /// "critical" | "high" | "medium" | "low" | "unknown".
    pub severity: String,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub fixed_versions: Vec<String>,
    /// `true` when the advisory's affected range includes the installed
    /// version — these are the rows surfaced in the "Installed is affected"
    /// callout at the top of the tab.
    pub affects_installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "MalwareEntry.ts")]
pub struct MalwareEntry {
    pub source: String,
    pub ref_id: String,
    /// "malware" | "typosquat" | "scanner_signal".
    pub kind: String,
    pub version: Option<String>,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub reported_at: Option<String>,
}

/// Three-axis offset, mirrors `packguard_policy::Offset`. Each axis is
/// a non-negative distance below the latest `{major,minor,patch}` — so
/// `-1` in YAML surfaces here as `1`. All zero means "always latest".
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyOffset.ts")]
pub struct PolicyOffset {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl From<packguard_policy::Offset> for PolicyOffset {
    fn from(o: packguard_policy::Offset) -> Self {
        Self {
            major: o.major,
            minor: o.minor,
            patch: o.patch,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyTrace.ts")]
pub struct PolicyTrace {
    /// Three-axis offset the resolver used for this package. Displayed in
    /// the dashboard "Policy eval" tab.
    pub offset: PolicyOffset,
    pub pin: Option<String>,
    /// "stable" | "pre" | "any".
    pub stability: String,
    pub min_age_days: u32,
    /// The version the resolver would recommend upgrading to, given the
    /// active policy + the known vuln/malware data. `None` when no candidate
    /// survives every filter.
    pub recommended: Option<String>,
    /// Human-readable one-liner — same wording as the CLI report uses.
    pub reason: String,
    /// Phase 10a — lex-bound trace: one line per axis describing its
    /// contribution to the effective inclusive upper bound, plus lines
    /// for the merged bound and the picked remediation. Example:
    /// `offset.major=-1 → (18, ∞, ∞)` / `offset.minor=0 → inactive` /
    /// `effective bound = (18, ∞, ∞)` / `max version ≤ bound = 18.3.1`.
    /// Empty when `pin` short-circuits.
    pub cascade: Vec<String>,
}

// ---- Policy ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyDocument.ts")]
pub struct PolicyDocument {
    /// Raw `.packguard.yml` contents (or the conservative defaults when no
    /// file is present).
    pub yaml: String,
    /// `true` when the YAML lives on disk; `false` when we're returning the
    /// embedded conservative defaults.
    pub from_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyWrite.ts")]
pub struct PolicyWrite {
    pub yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyDryRun.ts")]
pub struct PolicyDryRun {
    pub yaml: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyDryRunResult.ts")]
pub struct PolicyDryRunResult {
    /// Per-bucket totals when the candidate policy is applied to the last
    /// scan.
    pub candidate: ComplianceSummary,
    /// Same counts under the currently active policy — lets the UI show a
    /// side-by-side delta.
    pub current: ComplianceSummary,
    /// Packages whose compliance tag flipped between the two policies.
    /// Bounded to the first `max` entries the service decides to return
    /// (currently 50) so a pathological diff doesn't explode the payload.
    pub changed_packages: Vec<PolicyDryRunChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "PolicyDryRunChange.ts")]
pub struct PolicyDryRunChange {
    pub ecosystem: String,
    pub name: String,
    pub from: ComplianceTag,
    pub to: ComplianceTag,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "YamlErrorLocation.ts")]
pub struct YamlErrorLocation {
    /// 1-based line. `None` when the YAML parser couldn't recover a location
    /// (rare — mostly happens for pure I/O failures).
    pub line: Option<u32>,
    pub column: Option<u32>,
}

// ---- Jobs ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export_to = "JobStatus.ts")]
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
#[ts(export_to = "JobKind.ts")]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Scan,
    Sync,
    /// Phase 14.1f — kicks off `registry.create_project(path)` followed
    /// by a recursive scan, then bumps `last_scan` on success. Surfaced
    /// to the dashboard as the polling target for `POST /api/projects`.
    AddProject,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Scan => "scan",
            JobKind::Sync => "sync",
            JobKind::AddProject => "add_project",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "JobView.ts")]
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
#[ts(export_to = "JobAccepted.ts")]
pub struct JobAccepted {
    pub id: String,
}

// ---- Scan / Sync result payloads (stored in jobs.result_json) --------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ScanReport.ts")]
pub struct ScanReport {
    pub projects_scanned: u32,
    pub packages_persisted: u32,
    pub registry_errors: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "SyncReport.ts")]
pub struct SyncReport {
    pub osv_npm_persisted: u32,
    pub osv_pypi_persisted: u32,
    pub ghsa_persisted: u32,
    pub typosquat_suspects: u32,
}

// ---- Phase 5: graph / compatibility DTOs ---------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphQuery.ts")]
pub struct GraphQuery {
    /// Phase 7: scope to a single repo (path returned by
    /// `/api/workspaces`). `None` = aggregate across every scanned repo.
    pub project: Option<String>,
    /// Optional manifest path to narrow within the chosen repo. The
    /// string matches the stored `workspaces.manifest_path`. Only
    /// meaningful when `project` is also provided.
    pub workspace: Option<String>,
    /// Cap on BFS depth from direct deps. `None` = no cap. Clamped to
    /// `[0, 64]` server-side so a pathological client can't blow out
    /// memory on a cyclic graph.
    pub max_depth: Option<u32>,
    /// Comma-separated subset of `runtime,dev,peer,optional`. `None` =
    /// include everything.
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphResponse.ts")]
pub struct GraphResponse {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Emitted when the node count exceeds the Cytoscape-native sweet
    /// spot (~2000). The dashboard shows the warning and prompts the user
    /// to tighten filters.
    pub oversize_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphNode.ts")]
pub struct GraphNode {
    /// `ecosystem:name@version` — unique id across ecosystems. Also the
    /// anchor the detail page links use.
    pub id: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// `true` when this node is a direct dep of at least one workspace,
    /// so the UI can tint roots differently.
    pub is_root: bool,
    /// Highest CVE severity hitting this version, `None` when clean.
    pub cve_severity: Option<String>,
    pub has_malware: bool,
    pub has_typosquat: bool,
    pub compliance: Option<ComplianceTag>,
    /// `true` when this node is a synthetic placeholder emitted so every
    /// edge has a landing point — the actual package (an unresolved peer
    /// / optional dep) isn't in the lockfile. Frontend renders it with a
    /// dashed outline + reduced opacity. Without this, Cytoscape crashes
    /// at mount when it finds an edge whose target is missing from the
    /// node set (Polish-bis-1, finding #8).
    pub is_unresolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphEdge.ts")]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    /// Declared range from the source side (what the parent asked for).
    pub range: String,
    /// "runtime" | "dev" | "peer" | "optional".
    pub kind: String,
    /// `true` when the target didn't resolve — peer deps can legitimately
    /// stay unresolved; the UI renders them as a dashed halo.
    pub unresolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ContaminatedQuery.ts")]
pub struct ContaminatedQuery {
    /// Advisory id to trace back (GHSA-/CVE-/MAL-…). Matching is by
    /// `cve_id` first, then by `source:advisory_id`.
    pub vuln_id: String,
    /// Phase 7: scope the BFS to a single workspace. `None` = aggregate
    /// across every scanned repo.
    pub project: Option<String>,
}

/// Simple `?project=<path>` query for endpoints that only need the scope
/// filter (overview, policy get, compat).
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ProjectQuery.ts")]
pub struct ProjectQuery {
    pub project: Option<String>,
}

/// Phase 14.1f — wire shape returned by `GET /api/projects` and the
/// `succeeded` payload of an `AddProject` job. Mirrors
/// [`packguard_store::projects_registry::Project`] but flattens
/// `created_at` / `last_scan` to RFC 3339 strings so the dashboard
/// doesn't have to learn about chrono.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ProjectDto.ts")]
pub struct ProjectDto {
    pub id: i64,
    /// Filesystem-safe identifier derived from the canonical project
    /// root path (see `packguard_core::slugify`). Stable across
    /// restarts and the only handle the dashboard needs to scope
    /// requests in 14.3+.
    pub slug: String,
    /// Canonical absolute path of the project root (the directory that
    /// contains the `.git/` ancestor). Surfaced for the UI's tooltip
    /// only — internally always identify projects by `slug`.
    pub path: String,
    /// Human-friendly label, defaults to the project root's
    /// `file_name()`.
    pub name: String,
    pub created_at: String,
    pub last_scan: Option<String>,
}

impl From<packguard_store::projects_registry::Project> for ProjectDto {
    fn from(p: packguard_store::projects_registry::Project) -> Self {
        Self {
            id: p.id,
            slug: p.slug,
            path: p.path.display().to_string(),
            name: p.name,
            created_at: p.created_at.to_rfc3339(),
            last_scan: p.last_scan.map(|t| t.to_rfc3339()),
        }
    }
}

/// `POST /api/projects` body. The `path` field is taken at face value
/// (no env-var expansion); validation happens in the handler.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "AddProjectRequest.ts")]
pub struct AddProjectRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ContaminationResult.ts")]
pub struct ContaminationResult {
    /// Every `(package, version)` the advisory hits directly, so the UI
    /// can highlight them as the "patient zero" set.
    pub hits: Vec<ContaminationHit>,
    /// Sorted, deduplicated chains: each chain starts at a direct dep and
    /// ends at one of the hits. Capped server-side (see
    /// `services::graph::MAX_CHAINS`).
    pub chains: Vec<ContaminationChain>,
    /// `true` when the BFS was answered from the cache.
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ContaminationHit.ts")]
pub struct ContaminationHit {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ContaminationChain.ts")]
pub struct ContaminationChain {
    /// Ordered root-first list of `ecosystem:name@version` node ids.
    pub path: Vec<String>,
    pub workspace: String,
}

/// One row per (advisory, affected package version) pair observed in the
/// scoped graph. Powers the `/graph` Focus-CVE command palette so the
/// user can pick a CVE from a list instead of typing an id they don't
/// know. `cve_id` is preferred when present; callers fall back to
/// `advisory_id` (GHSA-/MAL-) otherwise — both are accepted downstream
/// by `/api/graph/contaminated?vuln_id=...`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphVulnerabilityEntry.ts")]
pub struct GraphVulnerabilityEntry {
    pub advisory_id: String,
    pub cve_id: Option<String>,
    pub ecosystem: String,
    pub package_name: String,
    pub package_version: String,
    /// "critical" | "high" | "medium" | "low" | "unknown" — the same
    /// flattened lexicon the rest of the dashboard uses.
    pub severity: String,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "GraphVulnerabilityList.ts")]
pub struct GraphVulnerabilityList {
    /// Sorted by severity desc, then by `cve_id.unwrap_or(advisory_id)`,
    /// then by `package_name` — stable palette ordering across refetches.
    pub entries: Vec<GraphVulnerabilityEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "CompatResponse.ts")]
pub struct CompatResponse {
    pub ecosystem: String,
    pub name: String,
    pub installed: Option<String>,
    /// One row per known version, ordered oldest → newest. Engines is a
    /// `{ runtime → required_range }` map (e.g. `{"node": ">=14"}`).
    pub rows: Vec<CompatRow>,
    /// Direct dependents within the scanned repos — count + sample list,
    /// so the UI can show "used by 12 packages" + a preview.
    pub dependents: Vec<CompatDependent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "CompatRow.ts")]
pub struct CompatRow {
    pub version: String,
    pub engines: std::collections::BTreeMap<String, String>,
    pub peer_deps: std::collections::BTreeMap<String, CompatPeerDep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "CompatPeerDep.ts")]
pub struct CompatPeerDep {
    pub range: String,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "CompatDependent.ts")]
pub struct CompatDependent {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub range: String,
    pub kind: String,
    /// Phase 7b: repo path the dependent was observed in. Canonicalized
    /// exactly like `WorkspaceInfo.path` so the UI can group the "Used
    /// by" list per workspace and cross-reference the header selector.
    pub workspace: String,
}

// ---- Phase 7: workspaces ---------------------------------------------------

/// One row for the workspace selector in the dashboard header and for the
/// `packguard scans` CLI output that drives the "Available scans" error
/// hints. Sourced from `packguard_store::ScanIndexRow` (already sorted by
/// `last_scan_at DESC`); path strings are the canonicalized forms
/// persisted since Polish-1.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "WorkspaceInfo.ts")]
pub struct WorkspaceInfo {
    pub path: String,
    pub ecosystem: String,
    pub last_scan_at: String,
    pub fingerprint: String,
    pub dependency_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "WorkspacesResponse.ts")]
pub struct WorkspacesResponse {
    pub workspaces: Vec<WorkspaceInfo>,
}

// ---- Phase 12a: Page Actions ----------------------------------------------

/// Query string for `GET /api/actions`. `min_severity` accepts the same
/// lexicon as the rest of the dashboard (`critical` / `high` / `medium`
/// / `low` / `info`); unknown values are ignored (no 400 — keeps the
/// URL forgiving when the CLI and dashboard drift).
///
/// `include_dismissed` / `include_deferred` default to `false` — the
/// dashboard's default list hides archived rows. Setting either to
/// `true` surfaces them with `dismissed_at` / `deferred_until`
/// populated so the UI can render an "archived" tab.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionsQuery.ts")]
pub struct ActionsQuery {
    pub project: Option<String>,
    pub min_severity: Option<String>,
    #[serde(default)]
    pub include_dismissed: Option<bool>,
    #[serde(default)]
    pub include_deferred: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionsResponse.ts")]
pub struct ActionsResponse {
    pub actions: Vec<packguard_actions::Action>,
    /// Count *before* the `min_severity` filter — lets the dashboard
    /// render "showing 3 of 12" without a second request.
    pub total: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionDismissRequest.ts")]
pub struct ActionDismissRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionDeferRequest.ts")]
pub struct ActionDeferRequest {
    /// Days to defer for. Clamped server-side to `[1, 365]` so a
    /// pathological client can't push the dismissal 200 years into
    /// the future.
    pub days: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionDismissResponse.ts")]
pub struct ActionDismissResponse {
    /// RFC 3339 timestamp at which the dismissal was recorded.
    pub dismissed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionDeferResponse.ts")]
pub struct ActionDeferResponse {
    /// RFC 3339 deadline; the action resurfaces once `now >= deferred_until`.
    pub deferred_until: String,
}

// ---- Phase 14.5b — filesystem browser DTOs --------------------------------

/// Wire shape for `GET /api/fs/roots`. Returns conventional starting
/// points for the AddProjectModal directory picker. `entries[0]` is
/// always `$HOME`; the remainder are conventional repo dirs that exist
/// on disk (`Repo`, `Projects`, `Code`, `Workspace`, `Documents`, `src`).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "FsRootsResponse.ts")]
pub struct FsRootsResponse {
    /// Canonical absolute path of the user's home directory.
    pub home: String,
    pub entries: Vec<FsRootEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "FsRootEntry.ts")]
pub struct FsRootEntry {
    /// Display label, e.g. `"$HOME"` or `"$HOME/Repo"`.
    pub label: String,
    /// Absolute canonical path on disk.
    pub path: String,
}

/// Wire shape for `GET /api/fs/browse?path=<absolute>`. Sandboxed to
/// `$HOME`: requests for paths whose canonical form lies outside `$HOME`
/// are rejected with HTTP 403. Only directories are listed — file
/// content is irrelevant for a directory picker.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "FsBrowseResponse.ts")]
pub struct FsBrowseResponse {
    /// Canonical absolute path of the directory listed.
    pub path: String,
    /// Canonical absolute path of the parent directory. `None` when
    /// `path == $HOME` so the picker can hide the up-one-level button
    /// at the sandbox boundary.
    pub parent: Option<String>,
    pub entries: Vec<FsEntry>,
    /// `true` when the response was capped at the per-directory limit
    /// (default 500). The frontend should surface a "refine your
    /// search" hint when this is set.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export_to = "FsEntry.ts")]
pub struct FsEntry {
    /// Entry name only (no path separators). Hidden entries (leading
    /// `.`) are filtered out before serialization, except that `.git/`
    /// surfaces via the parent's `has_git` flag — never as an entry.
    pub name: String,
    /// Absolute canonical path of the entry.
    pub path: String,
    /// `true` when the entry contains a `.git/` subdirectory directly.
    pub has_git: bool,
    /// `true` when the entry contains at least one supported manifest
    /// directly (`package.json`, `pyproject.toml`, `poetry.lock`,
    /// `uv.lock`, `pnpm-lock.yaml`, `yarn.lock`, `package-lock.json`,
    /// or any `requirements*.txt`).
    pub has_manifest: bool,
}
