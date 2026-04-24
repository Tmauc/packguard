//! Data model for the Page Actions engine. Every type derives `ts_rs::TS`
//! so the dashboard (Phase 12b) and CLI JSON output share a single shape.
//!
//! The `id` on `Action` is the SHA-256 hex of `(kind_str, canonical_target,
//! workspace)` — deterministic so a dismissal survives rescans: if the
//! same finding re-appears on the same `(package, version, workspace)` it
//! keeps the same id and stays dismissed; if the installed version
//! changes, the id changes and the action resurfaces on purpose.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

/// Every kind of action the generator can emit. Ordered roughly by the
/// Phase 12a design matrix — callers sort by `ActionSeverity` first, then
/// use `ActionKind` only for display grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionKind.ts")]
pub enum ActionKind {
    FixMalware,
    FixCveCritical,
    FixCveHigh,
    ClearViolation,
    ResolveInsufficient,
    WhitelistTyposquat,
    RefreshSync,
    RescanStale,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::FixMalware => "FixMalware",
            ActionKind::FixCveCritical => "FixCveCritical",
            ActionKind::FixCveHigh => "FixCveHigh",
            ActionKind::ClearViolation => "ClearViolation",
            ActionKind::ResolveInsufficient => "ResolveInsufficient",
            ActionKind::WhitelistTyposquat => "WhitelistTyposquat",
            ActionKind::RefreshSync => "RefreshSync",
            ActionKind::RescanStale => "RescanStale",
        }
    }

    /// Canonical severity for each kind. Kept in one place so callers
    /// (generator + UI) can't disagree on whether a typosquat suggestion
    /// is `Low` or `Info`, for instance.
    pub fn severity(self) -> ActionSeverity {
        match self {
            // Malware gets its own top-level severity so CI gates can
            // distinguish "critical CVE" from "known-malicious release"
            // via `--fail-on-severity malware`. Phase 12a pragmatically
            // collapsed this into `Critical`; Phase 12-fix restores the
            // distinction.
            ActionKind::FixMalware => ActionSeverity::Malware,
            ActionKind::FixCveCritical => ActionSeverity::Critical,
            ActionKind::FixCveHigh => ActionSeverity::High,
            ActionKind::ClearViolation => ActionSeverity::Medium,
            ActionKind::ResolveInsufficient => ActionSeverity::Medium,
            ActionKind::WhitelistTyposquat => ActionSeverity::Low,
            ActionKind::RefreshSync => ActionSeverity::Info,
            ActionKind::RescanStale => ActionSeverity::Info,
        }
    }
}

/// Severity ladder. Declaration order matters — `derive(PartialOrd, Ord)`
/// uses it, so filters like `actions.retain(|a| a.severity >= threshold)`
/// and the sort in `collect_all` depend on `Malware > Critical > High >
/// Medium > Low > Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionSeverity.ts")]
pub enum ActionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Malware,
}

impl ActionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionSeverity::Malware => "malware",
            ActionSeverity::Critical => "critical",
            ActionSeverity::High => "high",
            ActionSeverity::Medium => "medium",
            ActionSeverity::Low => "low",
            ActionSeverity::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "malware" => ActionSeverity::Malware,
            "critical" => ActionSeverity::Critical,
            "high" => ActionSeverity::High,
            "medium" | "med" => ActionSeverity::Medium,
            "low" => ActionSeverity::Low,
            "info" => ActionSeverity::Info,
            _ => return None,
        })
    }
}

/// Internally tagged enum — ts-rs emits a discriminated union with a
/// `kind` tag, matching the rest of the dashboard API style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export_to = "ActionTarget.ts")]
#[serde(tag = "kind")]
pub enum ActionTarget {
    /// A package version pinned in the workspace. `version` is the
    /// installed version (which is what we want to move away from);
    /// `suggested_command` names the upgrade target separately.
    Package {
        ecosystem: String,
        name: String,
        version: String,
    },
    /// The action applies to the workspace itself (RefreshSync,
    /// RescanStale). Callers render the workspace row header.
    Workspace,
}

impl ActionTarget {
    /// Stable single-line form used both for the stable-id hash and for
    /// debug output. Kept deterministic — do **not** change without
    /// migrating existing dismissal rows, since the id derivation embeds
    /// this string.
    pub fn canonical(&self) -> String {
        match self {
            ActionTarget::Package {
                ecosystem,
                name,
                version,
            } => format!("pkg:{ecosystem}:{name}@{version}"),
            ActionTarget::Workspace => "workspace".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export_to = "Action.ts")]
pub struct Action {
    pub id: String,
    pub kind: ActionKind,
    pub severity: ActionSeverity,
    /// Canonicalized workspace path — matches the strings used across
    /// `/api/workspaces` and `ContaminationChain.workspace` so the
    /// dashboard can join freely.
    pub workspace: String,
    pub target: ActionTarget,
    pub title: String,
    pub explanation: String,
    /// When present, the CLI + dashboard show a "Copy fix" button. Exact
    /// command depends on the detected package manager (`pm_detect`
    /// module); empty for workspace-level actions like RefreshSync.
    pub suggested_command: Option<String>,
    /// Version the policy would move the dep to, as a raw string. Split
    /// out from `suggested_command` so the dashboard can render ranges /
    /// badges / diffs without parsing pm-specific command strings
    /// (`pnpm add x@^1`, `uv add 'x>=1,<2'`, etc.). `None` for actions
    /// that don't move a package version (RefreshSync, RescanStale,
    /// WhitelistTyposquat).
    pub recommended_version: Option<String>,
    /// RFC 3339 timestamp — `Some` when the action was dismissed but
    /// `collect_all` decided to surface it anyway (currently we filter
    /// them out so this stays `None` in the default read path; kept in
    /// the DTO so Phase 12b can render a "recently dismissed" tab later
    /// without a schema change).
    pub dismissed_at: Option<String>,
    /// RFC 3339 deadline after which a deferred action resurfaces. Same
    /// caveat as `dismissed_at` — filtered upstream today, but exposed
    /// on the DTO for forward compatibility.
    pub deferred_until: Option<String>,
}

/// Deterministic id for `(kind, target, workspace)`. SHA-256 hex chosen
/// over blake3/other to avoid adding a new workspace dep — `sha2` is
/// already in the tree (refinery, uuid). The kind discriminant comes
/// from `ActionKind::as_str()` so renames surface as id churn if anyone
/// forgets to migrate.
pub fn stable_action_id(kind: ActionKind, target: &ActionTarget, workspace: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(target.canonical().as_bytes());
    hasher.update(b"|");
    hasher.update(workspace.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_id_is_deterministic() {
        let target = ActionTarget::Package {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.20".into(),
        };
        let a = stable_action_id(ActionKind::FixCveHigh, &target, "/repo/app");
        let b = stable_action_id(ActionKind::FixCveHigh, &target, "/repo/app");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn stable_id_diverges_when_version_changes() {
        let v1 = ActionTarget::Package {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.20".into(),
        };
        let v2 = ActionTarget::Package {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.21".into(),
        };
        assert_ne!(
            stable_action_id(ActionKind::FixCveHigh, &v1, "/repo/app"),
            stable_action_id(ActionKind::FixCveHigh, &v2, "/repo/app"),
        );
    }

    #[test]
    fn stable_id_diverges_when_kind_changes() {
        let target = ActionTarget::Package {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.20".into(),
        };
        assert_ne!(
            stable_action_id(ActionKind::FixCveHigh, &target, "/repo/app"),
            stable_action_id(ActionKind::FixCveCritical, &target, "/repo/app"),
        );
    }

    #[test]
    fn action_kind_severity_mapping_is_stable() {
        // Phase 12-fix: FixMalware lives on its own top tier now, not
        // collapsed into Critical.
        assert_eq!(ActionKind::FixMalware.severity(), ActionSeverity::Malware);
        assert_eq!(
            ActionKind::FixCveCritical.severity(),
            ActionSeverity::Critical
        );
        assert_eq!(ActionKind::FixCveHigh.severity(), ActionSeverity::High);
        assert_eq!(
            ActionKind::ClearViolation.severity(),
            ActionSeverity::Medium
        );
        assert_eq!(ActionKind::RefreshSync.severity(), ActionSeverity::Info);
    }

    #[test]
    fn severity_orders_malware_highest() {
        assert!(ActionSeverity::Malware > ActionSeverity::Critical);
        assert!(ActionSeverity::Critical > ActionSeverity::High);
        assert!(ActionSeverity::High > ActionSeverity::Medium);
        assert!(ActionSeverity::Medium > ActionSeverity::Low);
        assert!(ActionSeverity::Low > ActionSeverity::Info);
    }

    #[test]
    fn severity_parse_accepts_malware() {
        assert_eq!(
            ActionSeverity::parse("malware"),
            Some(ActionSeverity::Malware)
        );
        assert_eq!(
            ActionSeverity::parse("MALWARE"),
            Some(ActionSeverity::Malware)
        );
        // Unknown tokens still return None.
        assert_eq!(ActionSeverity::parse("deadly"), None);
    }
}
