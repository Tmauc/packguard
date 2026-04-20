//! npm manifest + lockfile parsing.
//!
//! Phase 1: direct deps from `package.json`, resolved versions from
//! `package-lock.json` v2/v3. Nested transitive entries are ignored.

use crate::ecosystem::Ecosystem;
use crate::model::{Delta, DepKind, Dependency, Project, RemotePackage};
use crate::registry::npm::NpmClient;
use anyhow::{bail, Context, Result};
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
    // npm (package-lock.json) first, then pnpm (pnpm-lock.yaml). yarn.lock
    // parsing lands when someone actually hits it — see Phase 1 follow-ups.
    let pkg_lock = root.join("package-lock.json");
    if pkg_lock.exists() {
        return Ok((
            parse_package_lock(&pkg_lock)?,
            Some("package-lock.json".to_string()),
        ));
    }
    let pnpm_lock = root.join("pnpm-lock.yaml");
    if pnpm_lock.exists() {
        return Ok((
            parse_pnpm_lock(&pnpm_lock)?,
            Some("pnpm-lock.yaml".to_string()),
        ));
    }
    Ok((BTreeMap::new(), None))
}

fn parse_package_lock(path: &Path) -> Result<BTreeMap<String, String>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PackageLock =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
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
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct PnpmLock {
    #[serde(default)]
    importers: BTreeMap<String, PnpmImporter>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PnpmImporter {
    #[serde(default)]
    dependencies: BTreeMap<String, PnpmEntry>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, PnpmEntry>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, PnpmEntry>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, PnpmEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct PnpmEntry {
    version: String,
}

/// Parses pnpm-lock.yaml v6 / v7 / v9. Multi-importer workspaces use the
/// root importer (`"."`) only — nested workspaces are Phase 1 follow-up.
fn parse_pnpm_lock(path: &Path) -> Result<BTreeMap<String, String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PnpmLock =
        serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let importer = lock
        .importers
        .get(".")
        .cloned()
        .or_else(|| lock.importers.values().next().cloned())
        .unwrap_or_default();

    let mut out = BTreeMap::new();
    let groups = [
        &importer.dependencies,
        &importer.dev_dependencies,
        &importer.optional_dependencies,
        &importer.peer_dependencies,
    ];
    for group in groups {
        for (name, entry) in group.iter() {
            out.insert(name.clone(), strip_pnpm_peer_decoration(&entry.version));
        }
    }
    Ok(out)
}

/// pnpm appends peer-dep resolution to the version (`18.2.0(react@18.2.0)`).
/// Strip everything from the first `(` so plain semver comparisons work.
fn strip_pnpm_peer_decoration(v: &str) -> String {
    match v.find('(') {
        Some(i) => v[..i].trim().to_string(),
        None => v.trim().to_string(),
    }
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
        assert_eq!(
            direct_dep_name("node_modules/@babel/core"),
            Some("@babel/core")
        );
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
    fn parse_reads_pnpm_lockfile() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{ "name": "demo", "dependencies": { "react": "^18.2.0" },
                  "devDependencies": { "typescript": "^5.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.2.0
        version: 18.2.0
    devDependencies:
      typescript:
        specifier: ^5.0.0
        version: 5.4.5
"#,
        )
        .unwrap();

        let project = parse(root).unwrap().unwrap();
        let by: BTreeMap<_, _> = project
            .dependencies
            .iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        assert_eq!(by["react"].installed.as_deref(), Some("18.2.0"));
        assert_eq!(by["typescript"].installed.as_deref(), Some("5.4.5"));
        assert_eq!(
            by["react"].source_lockfile.as_deref(),
            Some("pnpm-lock.yaml")
        );
    }

    #[test]
    fn pnpm_strip_peer_decoration() {
        assert_eq!(strip_pnpm_peer_decoration("18.2.0(react@18.2.0)"), "18.2.0");
        assert_eq!(strip_pnpm_peer_decoration("1.2.3"), "1.2.3");
    }

    #[test]
    fn rejects_lockfile_v1() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"a":"1"}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"packages":{}}"#,
        )
        .unwrap();
        let err = parse(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("lockfileVersion"));
    }
}
