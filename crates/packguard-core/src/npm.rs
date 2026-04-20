//! npm manifest + lockfile parsing.
//!
//! Phase 0: direct deps only (root `package.json`), resolved versions from
//! `package-lock.json` v2/v3. Nested transitive entries are ignored.

use crate::model::{DepKind, Dependency, Project};
use anyhow::{Context, Result, bail};
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

pub fn scan(root: &Path) -> Result<Project> {
    let manifest_path = root.join("package.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: PackageJson = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    let installed = load_installed_versions(root)?;

    let mut deps = Vec::new();
    push(&mut deps, &manifest.dependencies, DepKind::Runtime, &installed);
    push(&mut deps, &manifest.dev_dependencies, DepKind::Dev, &installed);
    push(&mut deps, &manifest.peer_dependencies, DepKind::Peer, &installed);
    push(&mut deps, &manifest.optional_dependencies, DepKind::Optional, &installed);

    deps.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Project {
        ecosystem: "npm",
        root: PathBuf::from(root),
        name: manifest.name,
        dependencies: deps,
    })
}

fn push(
    out: &mut Vec<Dependency>,
    src: &BTreeMap<String, String>,
    kind: DepKind,
    installed: &BTreeMap<String, String>,
) {
    for (name, range) in src {
        out.push(Dependency {
            name: name.clone(),
            declared_range: range.clone(),
            installed: installed.get(name).cloned(),
            kind,
        });
    }
}

fn load_installed_versions(root: &Path) -> Result<BTreeMap<String, String>> {
    let lock_path = root.join("package-lock.json");
    if !lock_path.exists() {
        return Ok(BTreeMap::new());
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
    Ok(out)
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
        // Return the full "@scope/pkg" slice from the original string.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn scan_parses_manifest_and_lockfile() {
        let tmp = tempdir();
        std::fs::write(
            tmp.join("package.json"),
            r#"{
                "name": "demo",
                "dependencies": { "react": "^18.2.0", "@babel/core": "^7.0.0" },
                "devDependencies": { "typescript": "^5.0.0" }
            }"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("package-lock.json"),
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

        let project = scan(&tmp).unwrap();
        assert_eq!(project.ecosystem, "npm");
        assert_eq!(project.name.as_deref(), Some("demo"));
        assert_eq!(project.dependencies.len(), 3);

        let by_name: BTreeMap<_, _> = project
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d))
            .collect();
        assert_eq!(
            by_name["react"].installed.as_deref(),
            Some("18.2.0")
        );
        assert_eq!(
            by_name["@babel/core"].installed.as_deref(),
            Some("7.24.0")
        );
        assert_eq!(by_name["react"].kind, DepKind::Runtime);
        assert_eq!(by_name["typescript"].kind, DepKind::Dev);
    }

    #[test]
    fn scan_without_lockfile_returns_unresolved() {
        let tmp = tempdir();
        std::fs::write(
            tmp.join("package.json"),
            r#"{ "dependencies": { "react": "^18.2.0" } }"#,
        )
        .unwrap();
        let project = scan(&tmp).unwrap();
        assert_eq!(project.dependencies[0].installed, None);
    }

    #[test]
    fn rejects_lockfile_v1() {
        let tmp = tempdir();
        std::fs::write(tmp.join("package.json"), r#"{"dependencies":{"a":"1"}}"#).unwrap();
        std::fs::write(
            tmp.join("package-lock.json"),
            r#"{"lockfileVersion":1,"packages":{}}"#,
        )
        .unwrap();
        let err = scan(&tmp).unwrap_err();
        assert!(err.to_string().contains("lockfileVersion"));
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("packguard-test-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
