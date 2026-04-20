//! The `Ecosystem` trait — one implementation per package manager family
//! (npm, pypi, …). The CLI iterates a fixed set of ecosystems and never
//! branches on `id()` directly.
//!
//! Phase 1 scope (cf. CONTEXT.md §5): `detect`, `fetch_latest`, `classify`.
//! `changelog` and registry-level helpers land in later phases.

use crate::model::{Delta, Project, RemotePackage};
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

#[async_trait]
pub trait Ecosystem: Send + Sync {
    /// Stable short identifier (matches the column value in SQLite).
    fn id(&self) -> &'static str;

    /// Scan `root` for projects belonging to this ecosystem. Returns an empty
    /// vector when no manifest is found — errors are reserved for genuine
    /// parse failures on files that *are* present.
    fn detect(&self, root: &Path) -> Result<Vec<Project>>;

    /// Query the registry for the `latest` dist-tag of each name. Implementations
    /// are expected to bound concurrency and apply timeouts internally.
    async fn fetch_latest(&self, names: Vec<String>) -> Vec<(String, Result<RemotePackage>)>;

    /// Dialect-aware comparison between an installed version and the registry
    /// `latest`. `Unknown` covers missing data or unparsable strings.
    fn classify(&self, installed: Option<&str>, latest: Option<&str>) -> Delta;
}
