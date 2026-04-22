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

/// Phase 9b — offset is a three-axis object: one distance below the latest
/// major, minor, and patch respectively. Non-positive integers only (0 or
/// negative). Stored as unsigned magnitudes because "ahead of latest"
/// doesn't make sense.
///
/// YAML shape (object-only — scalar `offset: -1` is rejected at parse time):
///
/// ```yaml
/// offset:
///   major: 0
///   minor: -1
///   patch: 0
/// ```
///
/// Each key is optional; missing keys default to 0. The field order in
/// the struct is the cascade order the resolver walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Offset {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Offset {
    pub const ZERO: Offset = Offset {
        major: 0,
        minor: 0,
        patch: 0,
    };

    /// Convenience for tests / internal use — construction from the three
    /// signed axes, taking the absolute value exactly like the parser.
    pub fn from_axes(major: i64, minor: i64, patch: i64) -> Self {
        Self {
            major: major.unsigned_abs().min(u32::MAX as u64) as u32,
            minor: minor.unsigned_abs().min(u32::MAX as u64) as u32,
            patch: patch.unsigned_abs().min(u32::MAX as u64) as u32,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.major == 0 && self.minor == 0 && self.patch == 0
    }
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
    #[serde(default)]
    pub typosquat: TyposquatPolicy,
}

/// How aggressively to react to typosquat heuristic hits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TyposquatPolicy {
    /// Suspects become blocking violations. Use only when the false-positive
    /// rate is acceptable for your organisation.
    Strict,
    /// Default: surface as warnings, don't fail builds.
    #[default]
    Warn,
    /// Don't even surface them.
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Three-axis distance from `latest.{major,minor,patch}`. Each axis is
    /// stored as a positive u32 (YAML `-1` → `1`); all zero means
    /// "always pick the very latest".
    #[serde(default, deserialize_with = "crate::parse::deserialize_offset")]
    pub offset: Offset,
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
            offset: Offset::ZERO,
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
    pub offset: Option<Offset>,
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
    pub offset: Option<Offset>,
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
    pub offset: Offset,
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
    /// The installed version (or the package overall) was flagged as
    /// malicious by OSV-MAL, GHSA, or a scanner (Socket/Phylum). Blocking
    /// when `block.malware: true` (default off).
    MalwareViolation(Vec<packguard_core::MalwareReport>),
    /// The package name resembles a top-N legitimate package per the
    /// typosquat heuristic. Non-blocking by default
    /// (`block.typosquat: warn`); promoted to MalwareViolation when
    /// `strict`; suppressed when `off`.
    TyposquatWarning(Vec<packguard_core::MalwareReport>),
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
