//! npm manifest + lockfile parsing.
//!
//! Phase 1: direct deps from `package.json`, resolved versions from
//! `package-lock.json` v2/v3. Nested transitive entries are ignored.

use crate::ecosystem::Ecosystem;
use crate::model::{Delta, DepKind, Dependency, Project, RemotePackage};
use crate::registry::npm::NpmClient;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct PackageJson {
    name: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    optional_dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PackageLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    #[serde(default)]
    packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Deserialize)]
struct LockedPackage {
    version: Option<String>,
}

/// Parse a single npm project rooted at `root`. Returns `Ok(None)` if no
/// `package.json` exists at that path.
pub fn parse(root: &Path) -> Result<Option<Project>> {
    let manifest_path = root.join("package.json");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: PackageJson = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    let (installed, lock_source) = load_installed_versions(root)?;

    let mut deps = Vec::new();
    push(
        &mut deps,
        &manifest.dependencies,
        DepKind::Runtime,
        &installed,
        lock_source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.dev_dependencies,
        DepKind::Dev,
        &installed,
        lock_source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.peer_dependencies,
        DepKind::Peer,
        &installed,
        lock_source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.optional_dependencies,
        DepKind::Optional,
        &installed,
        lock_source.as_deref(),
    );

    deps.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Some(Project {
        ecosystem: "npm",
        root: PathBuf::from(root),
        manifest_path,
        name: manifest.name,
        workspace: None,
        dependencies: deps,
    }))
}

fn push(
    out: &mut Vec<Dependency>,
    src: &BTreeMap<String, String>,
    kind: DepKind,
    installed: &BTreeMap<String, String>,
    source_lockfile: Option<&str>,
) {
    for (name, range) in src {
        let resolved = installed.get(name).cloned();
        let source = resolved.as_ref().and(source_lockfile).map(str::to_string);
        out.push(Dependency {
            name: name.clone(),
            declared_range: range.clone(),
            installed: resolved,
            kind,
            source_lockfile: source,
        });
    }
}

fn load_installed_versions(root: &Path) -> Result<(BTreeMap<String, String>, Option<String>)> {
    let lock_path = root.join("package-lock.json");
    if !lock_path.exists() {
        return Ok((BTreeMap::new(), None));
    }
    let bytes = std::fs::read(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock: PackageLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {}", lock_path.display()))?;

    if lock.lockfile_version < 2 {
        bail!(
            "package-lock.json lockfileVersion={} is not supported (need >= 2)",
            lock.lockfile_version
        );
    }

    let mut out = BTreeMap::new();
    for (path, pkg) in lock.packages {
        if let Some(name) = direct_dep_name(&path) {
            if let Some(ver) = pkg.version {
                out.insert(name.to_string(), ver);
            }
        }
    }
    Ok((out, Some("package-lock.json".to_string())))
}

/// Top-level deps live at `node_modules/<name>` or `node_modules/@scope/<name>`.
/// Nested entries (`node_modules/foo/node_modules/bar`) are skipped.
fn direct_dep_name(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("node_modules/")?;
    if rest.contains("/node_modules/") {
        return None;
    }
    if let Some(scoped) = rest.strip_prefix('@') {
        let (scope, pkg) = scoped.split_once('/')?;
        if pkg.contains('/') {
            return None;
        }
        let start = "node_modules/".len();
        let end = start + 1 + scope.len() + 1 + pkg.len();
        Some(&path[start..end])
    } else {
        if rest.contains('/') {
            return None;
        }
        Some(rest)
    }
}

/// Concrete `Ecosystem` implementation for npm.
pub struct Npm {
    client: NpmClient,
}

impl Npm {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: NpmClient::new()?,
        })
    }

    pub fn with_client(client: NpmClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Ecosystem for Npm {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, root: &Path) -> Result<Vec<Project>> {
        Ok(parse(root)?.into_iter().collect())
    }

    async fn fetch_latest(&self, names: Vec<String>) -> Vec<(String, Result<RemotePackage>)> {
        self.client.fetch_many(names).await
    }

    fn classify(&self, installed: Option<&str>, latest: Option<&str>) -> Delta {
        crate::classify::classify_semver(installed, latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn direct_dep_name_unscoped() {
        assert_eq!(direct_dep_name("node_modules/react"), Some("react"));
    }

    #[test]
    fn direct_dep_name_scoped() {
        assert_eq!(direct_dep_name("node_modules/@babel/core"), Some("@babel/core"));
    }

    #[test]
    fn direct_dep_name_skips_nested() {
        assert_eq!(direct_dep_name("node_modules/react/node_modules/foo"), None);
        assert_eq!(
            direct_dep_name("node_modules/@babel/core/node_modules/foo"),
            None
        );
    }

    #[test]
    fn direct_dep_name_rejects_root_and_others() {
        assert_eq!(direct_dep_name(""), None);
        assert_eq!(direct_dep_name("src/foo.js"), None);
    }

    #[test]
    fn parse_returns_none_without_manifest() {
        let tmp = tempdir().unwrap();
        assert!(parse(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn parse_reads_manifest_and_lockfile() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{
                "name": "demo",
                "dependencies": { "react": "^18.2.0", "@babel/core": "^7.0.0" },
                "devDependencies": { "typescript": "^5.0.0" }
            }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/react": { "version": "18.2.0" },
                    "node_modules/@babel/core": { "version": "7.24.0" },
                    "node_modules/typescript": { "version": "5.4.5" },
                    "node_modules/react/node_modules/loose-envify": { "version": "1.4.0" }
                }
            }"#,
        )
        .unwrap();

        let project = parse(root).unwrap().unwrap();
        assert_eq!(project.ecosystem, "npm");
        assert_eq!(project.name.as_deref(), Some("demo"));
        assert_eq!(project.dependencies.len(), 3);

        let by_name: BTreeMap<_, _> = project
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d))
            .collect();
        assert_eq!(by_name["react"].installed.as_deref(), Some("18.2.0"));
        assert_eq!(by_name["@babel/core"].installed.as_deref(), Some("7.24.0"));
        assert_eq!(by_name["react"].kind, DepKind::Runtime);
        assert_eq!(by_name["typescript"].kind, DepKind::Dev);
        assert_eq!(
            by_name["react"].source_lockfile.as_deref(),
            Some("package-lock.json"),
        );
    }

    #[test]
    fn parse_without_lockfile_returns_unresolved() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{ "dependencies": { "react": "^18.2.0" } }"#,
        )
        .unwrap();
        let project = parse(tmp.path()).unwrap().unwrap();
        assert_eq!(project.dependencies[0].installed, None);
        assert_eq!(project.dependencies[0].source_lockfile, None);
    }

    #[test]
    fn rejects_lockfile_v1() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"a":"1"}}"#).unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"packages":{}}"#,
        )
        .unwrap();
        let err = parse(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("lockfileVersion"));
    }
}
