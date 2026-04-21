use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DepKind {
    Runtime,
    Dev,
    Peer,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delta {
    Current,
    Patch,
    Minor,
    Major,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub declared_range: String,
    pub installed: Option<String>,
    pub kind: DepKind,
    /// Which lockfile (or manifest, when declared-only) provided `installed`.
    pub source_lockfile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub ecosystem: &'static str,
    /// Directory containing the manifest.
    pub root: PathBuf,
    /// Path to the primary manifest (e.g. `package.json`, `pyproject.toml`).
    pub manifest_path: PathBuf,
    /// Optional workspace / package name (from the manifest).
    pub name: Option<String>,
    /// `None` = top-level project; `Some` = nested workspace under a monorepo.
    pub workspace: Option<String>,
    pub dependencies: Vec<Dependency>,
    /// Transitive dependency edges harvested from the lockfile (`pnpm-lock`
    /// `packages:`, `package-lock.json` full `packages:` tree, `[[package]]`
    /// `dependencies` tables in `poetry.lock` / `uv.lock`). Empty when the
    /// parser doesn't emit transitive data yet; callers must treat it as
    /// additive to `dependencies`, not replacing it.
    #[doc(alias = "transitive")]
    pub edges: Vec<DependencyEdge>,
    /// Per-(package, version) compatibility metadata: peer deps + engines.
    /// One entry per node the parser resolved; entries are keyed by
    /// `(package_name, version)` tuples upstream in `packguard-store`.
    pub compatibility: Vec<CompatibilityInfo>,
}

/// One parent → child dependency relationship from a lockfile. Parent is
/// identified by name + resolved version (both non-empty). Child may be
/// unresolved (peer deps can be declared without a matching entry in the
/// lockfile); that shows up in the graph view as a warning halo rather
/// than an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdge {
    pub source_name: String,
    pub source_version: String,
    pub target_name: String,
    pub target_range: String,
    pub resolved_target_version: Option<String>,
    pub kind: DepKind,
}

/// `engines` + peer deps for a concrete (package, version). `peer_deps`
/// mirrors npm's `peerDependencies` / PyPI's implicit optional extras;
/// `engines` captures `node`, `npm`, `python`, etc. Stored as pre-built
/// maps so the persistence layer can serialize them to JSON columns
/// without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompatibilityInfo {
    pub package_name: String,
    pub version: String,
    pub engines: std::collections::BTreeMap<String, String>,
    pub peer_deps: std::collections::BTreeMap<String, PeerDepSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerDepSpec {
    pub range: String,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePackage {
    pub name: String,
    pub latest: Option<String>,
    pub latest_published_at: Option<String>,
    /// Every version the registry advertises for this package, in no
    /// particular order. Phase 1.5+: consumed by the policy resolver for
    /// strict offset / stability / min_age_days filtering.
    pub versions: Vec<RemoteVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVersion {
    pub version: String,
    pub published_at: Option<String>,
    pub deprecated: bool,
    pub yanked: bool,
}

/// Normalized severity. OSV npm advisories use
/// `database_specific.severity = "CRITICAL|HIGH|MODERATE|LOW"`; PyPI
/// advisories usually carry CVSS. We flatten everything to this enum so
/// policy comparisons stay dialect-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Catch-all for malformed / missing / unrecognised severity fields.
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Unknown => "unknown",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "high" => Severity::High,
            "moderate" | "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

/// One affected-range event from an OSV advisory. Events are ordered within
/// a range such that `Introduced` opens a window and `Fixed` / `LastAffected`
/// closes it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "version")]
pub enum AffectedEvent {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AffectedRangeKind {
    Semver,
    Ecosystem,
    Git,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AffectedRange {
    pub kind: AffectedRangeKind,
    pub events: Vec<AffectedEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct AffectedSpec {
    #[serde(default)]
    pub ranges: Vec<AffectedRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

/// What a `MalwareReport` represents — drives the policy semantics:
/// `Malware` is blocking when `block.malware` is on; `Typosquat` is a
/// warning unless `block.typosquat: strict`; `ScannerSignal` is whatever
/// Socket/Phylum reports beyond malware (obfuscation, install scripts, …)
/// — we surface it but treat it as informational by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MalwareKind {
    Malware,
    Typosquat,
    ScannerSignal,
}

impl MalwareKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MalwareKind::Malware => "malware",
            MalwareKind::Typosquat => "typosquat",
            MalwareKind::ScannerSignal => "scanner_signal",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw {
            "malware" => MalwareKind::Malware,
            "typosquat" => MalwareKind::Typosquat,
            _ => MalwareKind::ScannerSignal,
        }
    }
}

/// A malware/typosquat/scanner finding — Phase 2.5 stores this alongside
/// (but separate from) the OSV-style `Vulnerability` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalwareReport {
    pub source: String,
    pub ref_id: String,
    pub ecosystem: String,
    pub package_name: String,
    /// Empty string ⇒ the whole package is suspicious (typosquat case).
    pub version: String,
    pub kind: MalwareKind,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub evidence: serde_json::Value,
    pub reported_at: Option<String>,
}

/// A normalized advisory record — what the fetchers produce and what the
/// store persists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    pub source: String,
    pub advisory_id: String,
    pub ecosystem: String,
    pub package_name: String,
    pub severity: Severity,
    pub cve_id: Option<String>,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub affected: AffectedSpec,
    pub fixed_versions: Vec<String>,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
}
