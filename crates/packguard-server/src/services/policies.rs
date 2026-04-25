//! Policy fetch + write + dry-run. Phase 4b promotes the 4a read-only
//! endpoint into a small editor backend: dry-run evaluates a candidate
//! YAML against the last scan without persisting anything, write swaps the
//! on-disk `.packguard.yml` atomically.

use crate::dto::{
    ComplianceSummary, ComplianceTag, PolicyDocument, PolicyDryRunChange, PolicyDryRunResult,
};
use anyhow::{Context, Result};
use packguard_policy::{parse_policy, Policy, CONSERVATIVE_DEFAULTS_YAML};
use packguard_store::{IntelStore, Store};
use std::path::Path;

const MAX_CHANGED_PACKAGES: usize = 50;

pub fn read(repo_path: &Path) -> Result<PolicyDocument> {
    let candidate = repo_path.join(".packguard.yml");
    if candidate.exists() {
        let yaml = std::fs::read_to_string(&candidate)
            .with_context(|| format!("reading {}", candidate.display()))?;
        Ok(PolicyDocument {
            yaml,
            from_file: true,
        })
    } else {
        Ok(PolicyDocument {
            yaml: CONSERVATIVE_DEFAULTS_YAML.to_string(),
            from_file: false,
        })
    }
}

/// Used internally by the overview / packages services; reads the active
/// `.packguard.yml` if present, otherwise falls back to the conservative
/// defaults baked into `packguard-policy`. Errors from disk fall back to
/// the default rather than poisoning every endpoint.
pub fn current_policy_or_default() -> Result<Policy> {
    parse_policy(CONSERVATIVE_DEFAULTS_YAML)
}

/// Same as `current_policy_or_default` but honours the full Phase 10b
/// cascade — built-in → ~/.packguard.yml → <repo root>/.packguard.yml →
/// intermediate dirs → <repo_path>/.packguard.yml, deep-merged. The caller
/// gets only the resolved `Policy`; if they need provenance, use the
/// `packguard-policy::resolve_policy_cascade` helper directly.
pub fn current_policy_for(repo_path: &Path) -> Result<Policy> {
    let resolved = packguard_policy::resolve_policy_cascade(repo_path)
        .with_context(|| format!("resolving policy cascade for {}", repo_path.display()))?;
    Ok(resolved.policy)
}

/// Parse `yaml` and return a user-facing error string (including the 1-based
/// line, when the YAML parser exposes one) on failure. We go through
/// `serde_yaml` directly rather than `parse_policy` so we can surface the
/// location before `anyhow` erases it.
pub fn parse_candidate(yaml: &str) -> std::result::Result<Policy, String> {
    if yaml.trim().is_empty() {
        return parse_policy(yaml).map_err(|e| e.to_string());
    }
    // First, verify the YAML itself is well-formed. `serde_yaml::Error`
    // carries an optional `location()` we can pin-point the error at.
    let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(err) => {
            let mut msg = format!("invalid YAML: {err}");
            if let Some(loc) = err.location() {
                msg = format!(
                    "invalid YAML at line {}, column {}: {err}",
                    loc.line(),
                    loc.column()
                );
            }
            return Err(msg);
        }
    };
    // Then delegate to the policy-crate parser so schema validation errors
    // (empty match globs, etc.) stay identical to the CLI path.
    let reserialized =
        serde_yaml::to_string(&value).map_err(|e| format!("re-serialising YAML: {e}"))?;
    parse_policy(&reserialized).map_err(|e| e.to_string())
}

/// Two-variant error so the handler can choose the right HTTP status.
pub enum PolicyError {
    /// The user-supplied YAML failed to parse or validate — 400.
    Yaml(String),
    /// Anything else (disk / store / policy engine bugs) — 500.
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for PolicyError {
    fn from(e: anyhow::Error) -> Self {
        PolicyError::Internal(e)
    }
}

/// Run `candidate_yaml` and the current on-disk policy against every watched
/// package in the store, returning per-bucket counts + the first
/// `MAX_CHANGED_PACKAGES` packages whose compliance tag flipped.
pub fn dry_run(
    store: &Store,
    intel: &IntelStore,
    repo_path: &Path,
    candidate_yaml: &str,
) -> std::result::Result<PolicyDryRunResult, PolicyError> {
    let candidate = parse_candidate(candidate_yaml).map_err(PolicyError::Yaml)?;
    let current = current_policy_for(repo_path)?;
    let now = chrono::Utc::now();

    let watched = store.watched_packages()?;

    let mut candidate_summary = ComplianceSummary::default();
    let mut current_summary = ComplianceSummary::default();
    let mut changed: Vec<PolicyDryRunChange> = Vec::new();

    for (eco, name) in watched {
        let Some(cand_row) =
            crate::services::packages::evaluate_row(store, intel, &candidate, &now, &eco, &name)?
        else {
            continue;
        };
        let Some(cur_row) =
            crate::services::packages::evaluate_row(store, intel, &current, &now, &eco, &name)?
        else {
            continue;
        };
        bump(&mut candidate_summary, &cand_row.row.compliance);
        bump(&mut current_summary, &cur_row.row.compliance);
        if cand_row.row.compliance != cur_row.row.compliance && changed.len() < MAX_CHANGED_PACKAGES
        {
            changed.push(PolicyDryRunChange {
                ecosystem: eco.clone(),
                name: name.clone(),
                from: cur_row.row.compliance,
                to: cand_row.row.compliance,
            });
        }
    }

    Ok(PolicyDryRunResult {
        candidate: candidate_summary,
        current: current_summary,
        changed_packages: changed,
    })
}

/// Write `yaml` to `<repo>/.packguard.yml`, after confirming it parses
/// cleanly. Atomic: we write to a sibling temp file then `rename` into place
/// so the dashboard can never observe a half-written file.
pub fn write(repo_path: &Path, yaml: &str) -> std::result::Result<PolicyDocument, PolicyError> {
    parse_candidate(yaml).map_err(PolicyError::Yaml)?;
    let target = repo_path.join(".packguard.yml");
    let tmp = repo_path.join(".packguard.yml.tmp");
    std::fs::write(&tmp, yaml)
        .with_context(|| format!("writing {}", tmp.display()))
        .map_err(PolicyError::Internal)?;
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("renaming {} → {}", tmp.display(), target.display()))
        .map_err(PolicyError::Internal)?;
    Ok(PolicyDocument {
        yaml: yaml.to_string(),
        from_file: true,
    })
}

fn bump(summary: &mut ComplianceSummary, tag: &ComplianceTag) {
    match tag {
        ComplianceTag::Compliant => summary.compliant += 1,
        ComplianceTag::Warning | ComplianceTag::Typosquat => summary.warnings += 1,
        ComplianceTag::Violation | ComplianceTag::CveViolation | ComplianceTag::Malware => {
            summary.violations += 1
        }
        ComplianceTag::Insufficient => summary.insufficient += 1,
    }
}
