//! npm manifest + lockfile parsing.
//!
//! Phase 5: direct deps from `package.json`, resolved versions from
//! `package-lock.json` v2/v3 **and** transitive edges + per-package
//! compatibility metadata harvested from the full `packages:` tree.
//! pnpm-lock.yaml grows the same transitive pass (`packages:` section).

use crate::ecosystem::Ecosystem;
use crate::model::{
    CompatibilityInfo, Delta, DepKind, Dependency, DependencyEdge, PeerDepSpec, Project,
    RemotePackage,
};
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

#[derive(Debug, Default, Deserialize)]
struct LockedPackage {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: BTreeMap<String, PeerMeta>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    engines: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct PeerMeta {
    #[serde(default)]
    optional: bool,
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

    let graph = load_graph(root)?;

    let mut deps = Vec::new();
    push(
        &mut deps,
        &manifest.dependencies,
        DepKind::Runtime,
        &graph.installed,
        graph.source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.dev_dependencies,
        DepKind::Dev,
        &graph.installed,
        graph.source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.peer_dependencies,
        DepKind::Peer,
        &graph.installed,
        graph.source.as_deref(),
    );
    push(
        &mut deps,
        &manifest.optional_dependencies,
        DepKind::Optional,
        &graph.installed,
        graph.source.as_deref(),
    );

    deps.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Some(Project {
        ecosystem: "npm",
        root: PathBuf::from(root),
        manifest_path,
        name: manifest.name,
        workspace: None,
        dependencies: deps,
        edges: graph.edges,
        compatibility: graph.compatibility,
    }))
}

/// Bundle of everything a lockfile contributes to a `Project`: the flat
/// `(name → resolved_version)` map used to fill `Dependency.installed`,
/// plus the transitive edges + compat rows persisted by `save_project`.
#[derive(Debug, Default)]
struct LockfileGraph {
    installed: BTreeMap<String, String>,
    edges: Vec<DependencyEdge>,
    compatibility: Vec<CompatibilityInfo>,
    source: Option<String>,
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

fn load_graph(root: &Path) -> Result<LockfileGraph> {
    // npm (package-lock.json) first, then pnpm (pnpm-lock.yaml). yarn.lock
    // parsing lands when someone actually hits it — see Phase 1 follow-ups.
    let pkg_lock = root.join("package-lock.json");
    if pkg_lock.exists() {
        let mut graph = parse_package_lock(&pkg_lock)?;
        graph.source = Some("package-lock.json".to_string());
        return Ok(graph);
    }
    let pnpm_lock = root.join("pnpm-lock.yaml");
    if pnpm_lock.exists() {
        let mut graph = parse_pnpm_lock(&pnpm_lock)?;
        graph.source = Some("pnpm-lock.yaml".to_string());
        return Ok(graph);
    }
    Ok(LockfileGraph::default())
}

/// Walk the full `packages:` tree of a `package-lock.json` v2/v3. Each
/// non-root entry contributes a resolved (name, version) pair and — via its
/// own `dependencies` / `peerDependencies` / `optionalDependencies` — zero
/// or more transitive edges. Peer deps without a resolved version stay as
/// edges with `resolved_target_version = None` (warning halo in the UI).
fn parse_package_lock(path: &Path) -> Result<LockfileGraph> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PackageLock =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    if lock.lockfile_version < 2 {
        bail!(
            "package-lock.json lockfileVersion={} is not supported (need >= 2)",
            lock.lockfile_version
        );
    }

    // Pass 1 — map `path -> (name, version)` for every node in the tree so
    // we can resolve the children of each parent by scanning its
    // `node_modules/<name>` subtree.
    let mut resolved_by_path: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (p, pkg) in &lock.packages {
        if p.is_empty() {
            continue;
        }
        let Some(name) = pkg.name.clone().or_else(|| leaf_name(p)) else {
            continue;
        };
        let Some(ver) = pkg.version.clone() else {
            continue;
        };
        resolved_by_path.insert(p.clone(), (name, ver));
    }

    // Pass 2 — installed versions (flat, top-level only) + transitive edges
    // + compat metadata.
    let mut graph = LockfileGraph::default();
    for (p, pkg) in &lock.packages {
        if p.is_empty() {
            continue;
        }
        let Some((src_name, src_version)) = resolved_by_path.get(p).cloned() else {
            continue;
        };

        // Surface top-level resolutions so the direct Dependency rows still
        // get their `installed` field filled.
        if direct_dep_name(p).is_some() {
            graph
                .installed
                .insert(src_name.clone(), src_version.clone());
        }

        // Transitive edges — child resolution runs against this node's own
        // `node_modules/<child>` subtree first, then falls back to the
        // top-level one (npm's hoist semantics).
        for (child_name, range) in &pkg.dependencies {
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_child(p, child_name, &resolved_by_path),
                kind: DepKind::Runtime,
            });
        }
        for (child_name, range) in &pkg.dev_dependencies {
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_child(p, child_name, &resolved_by_path),
                kind: DepKind::Dev,
            });
        }
        for (child_name, range) in &pkg.peer_dependencies {
            let optional = pkg
                .peer_dependencies_meta
                .get(child_name)
                .map(|m| m.optional)
                .unwrap_or(false);
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_child(p, child_name, &resolved_by_path),
                kind: if optional {
                    DepKind::Optional
                } else {
                    DepKind::Peer
                },
            });
        }
        for (child_name, range) in &pkg.optional_dependencies {
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_child(p, child_name, &resolved_by_path),
                kind: DepKind::Optional,
            });
        }

        if !pkg.engines.is_empty() || !pkg.peer_dependencies.is_empty() {
            let mut peer_deps = BTreeMap::new();
            for (child_name, range) in &pkg.peer_dependencies {
                peer_deps.insert(
                    child_name.clone(),
                    PeerDepSpec {
                        range: range.clone(),
                        optional: pkg
                            .peer_dependencies_meta
                            .get(child_name)
                            .map(|m| m.optional)
                            .unwrap_or(false),
                    },
                );
            }
            graph.compatibility.push(CompatibilityInfo {
                package_name: src_name,
                version: src_version,
                engines: pkg.engines.clone(),
                peer_deps,
            });
        }
    }

    Ok(graph)
}

/// Resolve the child of a `package-lock.json` entry against npm's
/// `node_modules` hoist rules: look under `<parent>/node_modules/<child>`
/// first, then walk outward to the top-level `node_modules/<child>`.
/// Returns `None` when nothing matches — peer deps that weren't hoisted
/// end up unresolved, which is fine (the graph marks them as a warning).
fn resolve_child(
    parent_path: &str,
    child: &str,
    resolved: &BTreeMap<String, (String, String)>,
) -> Option<String> {
    let mut probe = format!("{parent_path}/node_modules/{child}");
    loop {
        if let Some((_, ver)) = resolved.get(&probe) {
            return Some(ver.clone());
        }
        // Walk one directory up in the `node_modules/` hierarchy.
        let Some(stripped) = probe
            .rsplit_once("/node_modules/")
            .and_then(|(before, _)| before.rsplit_once("/node_modules/"))
            .map(|(before, _)| before.to_string())
        else {
            break;
        };
        probe = format!("{stripped}/node_modules/{child}");
    }
    // Final check at the top level.
    let top = format!("node_modules/{child}");
    resolved.get(&top).map(|(_, ver)| ver.clone())
}

/// Strip every `node_modules/` prefix off a lockfile path and return the
/// last remaining segment — e.g. `node_modules/a/node_modules/b` → `b`.
fn leaf_name(path: &str) -> Option<String> {
    let last = path.rsplit_once("node_modules/").map(|(_, tail)| tail)?;
    if last.is_empty() {
        return None;
    }
    Some(last.trim_end_matches('/').to_string())
}

#[derive(Debug, Deserialize)]
struct PnpmLock {
    #[serde(default)]
    importers: BTreeMap<String, PnpmImporter>,
    /// pnpm v6–v8 lockfiles keep the resolved runtime graph here (each
    /// entry declares its `dependencies` / `peerDependencies`). pnpm v9
    /// split the data: `packages:` carries metadata (engines, peer-dep
    /// schema) while `snapshots:` carries the actual resolved edges. We
    /// read both and merge.
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackage>,
    #[serde(default)]
    snapshots: BTreeMap<String, PnpmSnapshot>,
}

/// Per-instance resolved graph row from pnpm v9's `snapshots:` section.
/// Keys look like `name@version(peer-resolution)`. The `dependencies:`
/// sub-field stores already-resolved `child_name → child_version`
/// mappings (the child_version may carry its own peer-decoration tail).
#[derive(Debug, Default, Deserialize)]
struct PnpmSnapshot {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "transitivePeerDependencies")]
    #[allow(dead_code)]
    transitive_peer_dependencies: Vec<String>,
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

#[derive(Debug, Default, Deserialize)]
struct PnpmPackage {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: BTreeMap<String, PeerMeta>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    engines: BTreeMap<String, String>,
}

/// Parse pnpm-lock.yaml v6 / v7 / v9. Emits the importer's direct deps as
/// the flat (name → version) map plus transitive edges + compat rows.
///
/// Two lockfile shapes coexist:
///
/// - v6/v7: `packages:` carries both metadata and the resolved
///   `dependencies:` per node.
/// - v9: `packages:` only carries metadata (engines, peer schema);
///   resolved runtime edges live in `snapshots:` keyed by the
///   post-resolution instance id.
///
/// We read both paths so either format produces a populated graph.
/// Multi-importer workspaces still fall back to the root importer
/// (`"."`); nested workspaces are Phase 1 follow-up.
fn parse_pnpm_lock(path: &Path) -> Result<LockfileGraph> {
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

    let mut graph = LockfileGraph::default();
    let groups = [
        &importer.dependencies,
        &importer.dev_dependencies,
        &importer.optional_dependencies,
        &importer.peer_dependencies,
    ];
    for group in groups {
        for (name, entry) in group.iter() {
            graph
                .installed
                .insert(name.clone(), strip_pnpm_peer_decoration(&entry.version));
        }
    }

    // `packages:` pass — compat metadata + v6/v7 runtime edges.
    for (key, pkg) in &lock.packages {
        let Some((src_name, src_version)) = parse_pnpm_package_key(key) else {
            continue;
        };
        let mut peer_specs: BTreeMap<String, PeerDepSpec> = BTreeMap::new();

        // v6/v7 carries the resolved runtime deps here; v9 leaves the map
        // empty (snapshots: carries them instead).
        for (child_name, range) in &pkg.dependencies {
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_pnpm_child(&lock.packages, child_name),
                kind: DepKind::Runtime,
            });
        }
        for (child_name, range) in &pkg.peer_dependencies {
            let optional = pkg
                .peer_dependencies_meta
                .get(child_name)
                .map(|m| m.optional)
                .unwrap_or(false);
            peer_specs.insert(
                child_name.clone(),
                PeerDepSpec {
                    range: range.clone(),
                    optional,
                },
            );
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_pnpm_child(&lock.packages, child_name),
                kind: if optional {
                    DepKind::Optional
                } else {
                    DepKind::Peer
                },
            });
        }
        for (child_name, range) in &pkg.optional_dependencies {
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: range.clone(),
                resolved_target_version: resolve_pnpm_child(&lock.packages, child_name),
                kind: DepKind::Optional,
            });
        }

        if !pkg.engines.is_empty() || !peer_specs.is_empty() {
            graph.compatibility.push(CompatibilityInfo {
                package_name: src_name,
                version: src_version,
                engines: pkg.engines.clone(),
                peer_deps: peer_specs,
            });
        }
    }

    // `snapshots:` pass — v9 resolved runtime graph. Each key is a
    // `name@version(peer)` instance id; children are already-resolved
    // `child_name → child_version(peer)` pairs.
    for (key, snap) in &lock.snapshots {
        let Some((src_name, src_version)) = parse_pnpm_package_key(key) else {
            continue;
        };
        for (child_name, resolved) in &snap.dependencies {
            let resolved_clean = strip_pnpm_peer_decoration(resolved);
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: resolved_clean.clone(),
                resolved_target_version: Some(resolved_clean),
                kind: DepKind::Runtime,
            });
        }
        for (child_name, resolved) in &snap.optional_dependencies {
            let resolved_clean = strip_pnpm_peer_decoration(resolved);
            graph.edges.push(DependencyEdge {
                source_name: src_name.clone(),
                source_version: src_version.clone(),
                target_name: child_name.clone(),
                target_range: resolved_clean.clone(),
                resolved_target_version: Some(resolved_clean),
                kind: DepKind::Optional,
            });
        }
    }

    Ok(graph)
}

/// pnpm package keys look like `/react@18.2.0` or `/@babel/core@7.24.0(peer)`.
/// Peer-decoration tails are dropped before we pick the name/version split;
/// scopes (starting with `@`) are preserved.
fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let rest = key.strip_prefix('/').unwrap_or(key);
    let without_peer = match rest.find('(') {
        Some(i) => &rest[..i],
        None => rest,
    };
    // The split `@` is the LAST one in the string (scoped packages carry an
    // earlier `@` that is part of the name, not the version separator).
    let at = without_peer.rfind('@')?;
    if at == 0 {
        return None;
    }
    let (name, ver) = without_peer.split_at(at);
    let ver = ver.strip_prefix('@')?;
    Some((name.to_string(), ver.to_string()))
}

/// Best-effort resolution for v6/v7 lockfiles: scan `packages:` for a key
/// whose name matches `child` and return the first concrete version. The
/// declared range stays on the edge, so consumers still see the original.
/// v9 lockfiles skip this path entirely — the `snapshots:` entries already
/// carry the resolved child version.
fn resolve_pnpm_child(packages: &BTreeMap<String, PnpmPackage>, child: &str) -> Option<String> {
    for key in packages.keys() {
        if let Some((name, ver)) = parse_pnpm_package_key(key) {
            if name == child {
                return Some(ver);
            }
        }
    }
    None
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

    // ---- Phase 5: transitive edges + compat from package-lock / pnpm-lock

    #[test]
    fn package_lock_emits_transitive_edges_for_nested_entries() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{ "dependencies": { "react": "^18.2.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/react": {
                        "version": "18.2.0",
                        "dependencies": { "loose-envify": "^1.1.0" },
                        "peerDependencies": { "scheduler": "^0.23.0" }
                    },
                    "node_modules/loose-envify": {
                        "version": "1.4.0",
                        "dependencies": { "js-tokens": "^4.0.0" }
                    },
                    "node_modules/js-tokens": { "version": "4.0.0" }
                }
            }"#,
        )
        .unwrap();
        let project = parse(root).unwrap().unwrap();
        let by = |src: &str, target: &str| {
            project
                .edges
                .iter()
                .find(|e| e.source_name == src && e.target_name == target)
                .cloned()
                .unwrap_or_else(|| panic!("missing edge {src} → {target}"))
        };
        assert_eq!(
            by("react", "loose-envify")
                .resolved_target_version
                .as_deref(),
            Some("1.4.0")
        );
        assert_eq!(
            by("loose-envify", "js-tokens")
                .resolved_target_version
                .as_deref(),
            Some("4.0.0")
        );
        // Peer dep that nothing in this lockfile resolves must still emit an
        // edge — the graph view surfaces it as a warning, but never as a
        // violation (standard package-manager semantics).
        let peer = by("react", "scheduler");
        assert_eq!(peer.resolved_target_version, None);
        assert_eq!(peer.kind, DepKind::Peer);
    }

    #[test]
    fn package_lock_captures_engines_as_compat_row() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{ "dependencies": { "react": "^18.2.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/react": {
                        "version": "18.2.0",
                        "engines": { "node": ">=14" }
                    }
                }
            }"#,
        )
        .unwrap();
        let project = parse(root).unwrap().unwrap();
        let compat = project
            .compatibility
            .iter()
            .find(|c| c.package_name == "react")
            .expect("react should carry compat metadata");
        assert_eq!(compat.engines.get("node").unwrap(), ">=14");
    }

    #[test]
    fn pnpm_lock_emits_edges_from_packages_section() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{ "dependencies": { "react": "^18.2.0" } }"#,
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
packages:
  /react@18.2.0:
    engines: { node: '>=14' }
    dependencies:
      loose-envify: ^1.1.0
    peerDependencies:
      scheduler: ^0.23.0
    peerDependenciesMeta:
      scheduler:
        optional: true
  /loose-envify@1.4.0:
    dependencies:
      js-tokens: ^4.0.0
  /js-tokens@4.0.0: {}
"#,
        )
        .unwrap();
        let project = parse(root).unwrap().unwrap();
        let react_to = |target: &str| {
            project
                .edges
                .iter()
                .find(|e| e.source_name == "react" && e.target_name == target)
                .cloned()
                .unwrap_or_else(|| panic!("missing react → {target}"))
        };
        assert_eq!(
            react_to("loose-envify").resolved_target_version.as_deref(),
            Some("1.4.0")
        );
        // Scheduler is declared optional — kind should downgrade to Optional.
        assert_eq!(react_to("scheduler").kind, DepKind::Optional);
        // Engines attach to react's compat row.
        assert!(project
            .compatibility
            .iter()
            .any(|c| c.package_name == "react" && c.engines.get("node").unwrap() == ">=14"));
    }

    #[test]
    fn pnpm_package_key_splits_scoped_name() {
        assert_eq!(
            parse_pnpm_package_key("/@babel/core@7.24.0").unwrap(),
            ("@babel/core".to_string(), "7.24.0".to_string())
        );
        assert_eq!(
            parse_pnpm_package_key("/react@18.2.0(react@18.2.0)").unwrap(),
            ("react".to_string(), "18.2.0".to_string())
        );
        // pnpm v9 drops the leading slash.
        assert_eq!(
            parse_pnpm_package_key("react@18.3.1").unwrap(),
            ("react".to_string(), "18.3.1".to_string())
        );
    }

    #[test]
    fn pnpm_v9_snapshots_section_populates_runtime_edges() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{ "dependencies": { "react-dom": "^18.3.1" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.3.1
        version: 18.3.1(react@18.3.1)
packages:
  react-dom@18.3.1:
    engines: { node: '>=0.10' }
    peerDependencies:
      react: ^18.3.1
  react@18.3.1:
    engines: { node: '>=0.10' }
  scheduler@0.23.2: {}
  loose-envify@1.4.0: {}
  js-tokens@4.0.0: {}
snapshots:
  'react-dom@18.3.1(react@18.3.1)':
    dependencies:
      loose-envify: 1.4.0
      scheduler: 0.23.2
      react: 18.3.1
  'react@18.3.1':
    dependencies:
      loose-envify: 1.4.0
  'loose-envify@1.4.0':
    dependencies:
      js-tokens: 4.0.0
  'js-tokens@4.0.0': {}
  'scheduler@0.23.2':
    dependencies:
      loose-envify: 1.4.0
"#,
        )
        .unwrap();
        let project = parse(root).unwrap().unwrap();
        let edge = project
            .edges
            .iter()
            .find(|e| e.source_name == "react-dom" && e.target_name == "scheduler")
            .expect("react-dom → scheduler runtime edge");
        assert_eq!(edge.kind, DepKind::Runtime);
        assert_eq!(edge.resolved_target_version.as_deref(), Some("0.23.2"));

        // Transitive: react → loose-envify → js-tokens, both runtime.
        assert!(project.edges.iter().any(|e| e.source_name == "react"
            && e.target_name == "loose-envify"
            && e.kind == DepKind::Runtime));
        assert!(project.edges.iter().any(|e| e.source_name == "loose-envify"
            && e.target_name == "js-tokens"
            && e.kind == DepKind::Runtime));
    }
}
