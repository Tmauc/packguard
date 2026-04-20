use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
