//! Policy data model. Names and shapes mirror the `.packguard.yml` format
//! documented in CONTEXT.md §6.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stability {
    #[default]
    Stable,
    Prerelease,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockRule {
    #[serde(default)]
    pub cve_severity: Vec<String>,
    #[serde(default)]
    pub malware: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub yanked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Distance from `latest.major`. Stored as a positive u32 (e.g. YAML
    /// `offset: -1` parses to 1). 0 means "latest major is allowed".
    #[serde(default, deserialize_with = "crate::parse::deserialize_offset")]
    pub offset: u32,
    #[serde(default = "default_true")]
    pub allow_patch: bool,
    #[serde(default = "default_true")]
    pub allow_security_patch: bool,
    #[serde(default)]
    pub stability: Stability,
    #[serde(default)]
    pub min_age_days: u32,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub block: BlockRule,
}

fn default_true() -> bool {
    true
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            offset: 0,
            allow_patch: true,
            allow_security_patch: true,
            stability: Stability::Stable,
            min_age_days: 0,
            pin: None,
            block: BlockRule::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideRule {
    /// Glob pattern matched against the package name. `*` matches any chars
    /// except `/`; `@babel/*` behaves like `globset`'s default semantics.
    #[serde(rename = "match")]
    pub match_glob: String,
    #[serde(default, deserialize_with = "crate::parse::deserialize_offset_opt")]
    pub offset: Option<u32>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub allow_patch: Option<bool>,
    #[serde(default)]
    pub stability: Option<Stability>,
    #[serde(default)]
    pub min_age_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRule {
    pub name: String,
    #[serde(
        rename = "match",
        default,
        deserialize_with = "crate::parse::deserialize_match_list"
    )]
    pub match_globs: Vec<String>,
    #[serde(default, deserialize_with = "crate::parse::deserialize_offset_opt")]
    pub offset: Option<u32>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub allow_patch: Option<bool>,
    #[serde(default)]
    pub stability: Option<Stability>,
    #[serde(default)]
    pub min_age_days: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub defaults: PolicyDefaults,
    #[serde(default)]
    pub overrides: Vec<OverrideRule>,
    #[serde(default)]
    pub groups: Vec<GroupRule>,
}

/// Effective rule after defaults → group → override merging.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub offset: u32,
    pub pin: Option<String>,
    pub allow_patch: bool,
    pub allow_security_patch: bool,
    pub stability: Stability,
    pub min_age_days: u32,
    pub block: BlockRule,
}

#[derive(Debug, Clone)]
pub enum Compliance {
    Compliant,
    Warning(String),
    Violation(String),
    /// The installed version is affected by at least one advisory whose
    /// severity is listed in `block.cve_severity`. Blocking (counted under
    /// `--fail-on-violation`), with the raw match records attached so the
    /// CLI can render CVE ids, urls, fix versions, etc.
    VulnerabilityViolation(Vec<packguard_intel::MatchedVuln>),
    /// The resolver couldn't pick a recommended version because filters
    /// (stability / min_age_days / offset / vulnerability remediation)
    /// dropped every candidate. Neither compliant nor blocking — surfaced
    /// so users know the policy can't be evaluated against this dep.
    InsufficientCandidates(String),
}

/// Version info fed to the policy engine. Phase 1 uses `published_at`; the
/// `deprecated` / `yanked` flags stay unused until Phase 2 vuln intel lands.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: String,
    pub published_at: Option<String>,
    pub deprecated: bool,
    pub yanked: bool,
}
