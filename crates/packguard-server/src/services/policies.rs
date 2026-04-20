//! Policy fetch — Phase 4a is read-only; the editor + write endpoint
//! lands in 4b. We resolve the file to whatever
//! `packguard-policy::CONSERVATIVE_DEFAULTS_YAML` provides when no file
//! exists at the repo root.

use crate::dto::PolicyDocument;
use anyhow::{Context, Result};
use packguard_policy::{parse_policy, Policy, CONSERVATIVE_DEFAULTS_YAML};
use std::path::Path;

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

/// Same as `current_policy_or_default` but honoured the on-disk file when
/// present. Reserved for the per-repo evaluation path.
pub fn current_policy_for(repo_path: &Path) -> Result<Policy> {
    let candidate = repo_path.join(".packguard.yml");
    if candidate.exists() {
        let yaml = std::fs::read_to_string(&candidate)
            .with_context(|| format!("reading {}", candidate.display()))?;
        return parse_policy(&yaml);
    }
    current_policy_or_default()
}
