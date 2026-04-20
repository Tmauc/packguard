//! PyPI ecosystem — pip + poetry + uv.
//!
//! Phase 1 scope:
//! - Parse `pyproject.toml` (PEP 621 `[project]` and/or `[tool.poetry]`).
//! - Parse `requirements*.txt` (pip declared-only: no native lockfile,
//!   so versions come from `==` pins when present).
//! - Parse `poetry.lock` and `uv.lock` for resolved versions.
//! - Classify via PEP 440 (crate `pep440_rs`).
//!
//! Name normalization follows PEP 503 (lowercase; `_`, `.` → `-`).
//!
//! **Limitation (documented):** pip without a lockfile only reports exact
//! pins (`pkg==x.y.z`). Unpinned requirements get `installed = None` and
//! classify as `Unknown`. See README § "pip declared-only mode".

pub mod lockfile;
pub mod manifest;

use crate::ecosystem::Ecosystem;
use crate::model::{Delta, Dependency, Project, RemotePackage};
use crate::registry::pypi::PypiClient;
use anyhow::Result;
use async_trait::async_trait;
use pep440_rs::Version;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// PEP 503 canonical form. Used for cross-file matching; the first-declared
/// human-readable name is kept for display.
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for c in name.chars() {
        let mapped = match c {
            '_' | '.' => '-',
            other => other.to_ascii_lowercase(),
        };
        if mapped == '-' {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(mapped);
            prev_dash = false;
        }
    }
    out
}

/// PEP 440 classifier — mirrors `classify_semver` but uses release-tuple
/// comparison for "major/minor/patch" semantics, since PEP 440 does not
/// formally define those.
pub fn classify_pep440(installed: Option<&str>, latest: Option<&str>) -> Delta {
    let (Some(inst), Some(lat)) = (installed, latest) else {
        return Delta::Unknown;
    };
    let (Ok(i), Ok(l)) = (Version::from_str(inst), Version::from_str(lat)) else {
        return Delta::Unknown;
    };
    if i >= l {
        return Delta::Current;
    }
    // An epoch bump is always treated as a Major — a new versioning scheme by definition.
    if i.epoch() != l.epoch() {
        return Delta::Major;
    }
    let ir = i.release();
    let lr = l.release();
    if component(ir, 0) != component(lr, 0) {
        Delta::Major
    } else if component(ir, 1) != component(lr, 1) {
        Delta::Minor
    } else {
        Delta::Patch
    }
}

fn component(rel: &[u64], idx: usize) -> u64 {
    rel.get(idx).copied().unwrap_or(0)
}

/// Parse a single PyPI project rooted at `root`. Returns `Ok(None)` if
/// no `pyproject.toml` or `requirements*.txt` is present.
pub fn parse(root: &Path) -> Result<Option<Project>> {
    let pyproject_path = root.join("pyproject.toml");
    let req_files = manifest::find_requirements_files(root)?;

    let has_pyproject = pyproject_path.exists();
    if !has_pyproject && req_files.is_empty() {
        return Ok(None);
    }

    // Resolved versions: try uv.lock then poetry.lock then ==pins from requirements.
    let (resolved, lock_source) = resolve_installed(root, &req_files)?;

    // Declared deps: pyproject first (authoritative), then fall back to
    // requirements files if no pyproject section yielded deps.
    let mut declared: Vec<Dependency> = Vec::new();
    let mut project_name: Option<String> = None;

    if has_pyproject {
        let parsed = manifest::parse_pyproject(&pyproject_path)?;
        project_name = parsed.name;
        declared.extend(parsed.dependencies);
    }

    if declared.is_empty() && !req_files.is_empty() {
        for req in &req_files {
            declared.extend(manifest::parse_requirements_file(req)?);
        }
    }

    // Fill `installed` + `source_lockfile` from resolved map (keyed by normalized name).
    for dep in &mut declared {
        let key = normalize_name(&dep.name);
        if let Some(v) = resolved.get(&key) {
            // Already set via == pin when declared-only — don't overwrite a
            // lockfile value with a pin and vice-versa (first writer wins).
            if dep.installed.is_none() {
                dep.installed = Some(v.clone());
                dep.source_lockfile = lock_source.clone();
            }
        }
    }

    // Dedup by normalized name (keeps first occurrence).
    let mut seen = std::collections::BTreeSet::new();
    declared.retain(|d| seen.insert(normalize_name(&d.name)));
    declared.sort_by(|a, b| normalize_name(&a.name).cmp(&normalize_name(&b.name)));

    let manifest_path = if has_pyproject {
        pyproject_path
    } else {
        req_files[0].clone()
    };

    Ok(Some(Project {
        ecosystem: "pypi",
        root: PathBuf::from(root),
        manifest_path,
        name: project_name,
        workspace: None,
        dependencies: declared,
    }))
}

fn resolve_installed(
    root: &Path,
    req_files: &[PathBuf],
) -> Result<(BTreeMap<String, String>, Option<String>)> {
    let uv_lock = root.join("uv.lock");
    if uv_lock.exists() {
        let map = lockfile::parse_uv_lock(&uv_lock)?;
        return Ok((map, Some("uv.lock".to_string())));
    }
    let poetry_lock = root.join("poetry.lock");
    if poetry_lock.exists() {
        let map = lockfile::parse_poetry_lock(&poetry_lock)?;
        return Ok((map, Some("poetry.lock".to_string())));
    }
    // Declared-only: harvest `==` pins from requirements.txt files.
    let mut pinned = BTreeMap::new();
    let mut source: Option<String> = None;
    for req in req_files {
        for dep in manifest::parse_requirements_file(req)? {
            if let Some(v) = dep.installed {
                let key = normalize_name(&dep.name);
                pinned.insert(key, v);
                if source.is_none() {
                    source = req
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(str::to_string);
                }
            }
        }
    }
    Ok((pinned, source))
}

pub struct Pypi {
    client: PypiClient,
}

impl Pypi {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: PypiClient::new()?,
        })
    }
}

#[async_trait]
impl Ecosystem for Pypi {
    fn id(&self) -> &'static str {
        "pypi"
    }

    fn detect(&self, root: &Path) -> Result<Vec<Project>> {
        Ok(parse(root)?.into_iter().collect())
    }

    async fn fetch_latest(&self, names: Vec<String>) -> Vec<(String, Result<RemotePackage>)> {
        self.client.fetch_many(names).await
    }

    fn classify(&self, installed: Option<&str>, latest: Option<&str>) -> Delta {
        classify_pep440(installed, latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_is_pep503() {
        assert_eq!(normalize_name("Django"), "django");
        assert_eq!(normalize_name("my_pkg"), "my-pkg");
        assert_eq!(normalize_name("My.Pkg"), "my-pkg");
        assert_eq!(normalize_name("A__B..C"), "a-b-c");
        assert_eq!(normalize_name("friendly-bard"), "friendly-bard");
    }

    #[test]
    fn classify_basics() {
        assert_eq!(classify_pep440(Some("1.2.3"), Some("1.2.3")), Delta::Current);
        assert_eq!(classify_pep440(Some("1.2.3"), Some("1.2.4")), Delta::Patch);
        assert_eq!(classify_pep440(Some("1.2.3"), Some("1.3.0")), Delta::Minor);
        assert_eq!(classify_pep440(Some("1.2.3"), Some("2.0.0")), Delta::Major);
    }

    #[test]
    fn classify_handles_epoch_and_short_releases() {
        // Shorter release tuples are zero-padded — 1.0 and 1.0.0 compare equal.
        assert_eq!(classify_pep440(Some("1.0"), Some("1.0.0")), Delta::Current);
        // Epoch makes 1!0 > 99.0
        assert_eq!(classify_pep440(Some("0.1"), Some("1!0.1")), Delta::Major);
    }

    #[test]
    fn classify_unknown_on_garbage() {
        assert_eq!(classify_pep440(Some("not-a-version"), Some("1.0")), Delta::Unknown);
        assert_eq!(classify_pep440(None, Some("1.0")), Delta::Unknown);
    }
}
