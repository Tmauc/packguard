//! Resolved-version parsers for `poetry.lock` and `uv.lock`. Both are TOML
//! with `[[package]]` arrays exposing at least `name` + `version`.
//! Phase 5 extends them with transitive edge + compatibility extraction.

use crate::model::{CompatibilityInfo, DepKind, DependencyEdge};
use crate::pypi::normalize_name;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Everything a PyPI lockfile can tell us in a single pass: the flat
/// `(name → version)` map used to fill direct `Dependency.installed`
/// fields, plus the transitive edges + compatibility rows that feed the
/// graph + compat tabs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LockfileGraph {
    pub installed: BTreeMap<String, String>,
    pub edges: Vec<DependencyEdge>,
    pub compatibility: Vec<CompatibilityInfo>,
}

pub fn parse_poetry_lock(path: &Path) -> Result<LockfileGraph> {
    parse_generic(path)
}

pub fn parse_uv_lock(path: &Path) -> Result<LockfileGraph> {
    parse_generic(path)
}

fn parse_generic(path: &Path) -> Result<LockfileGraph> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // Pre-pass: detect uv-style inline `dependencies` arrays under each
    // `[[package]]`. uv uses a distinct TOML shape so we deserialise into
    // a side struct that captures it, then merge both forms.
    #[derive(Debug, serde::Deserialize)]
    struct RawLock {
        #[serde(default)]
        package: Vec<toml::Value>,
    }
    let raw: RawLock =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let mut graph = LockfileGraph::default();
    for pkg_val in &raw.package {
        let Some(pkg_table) = pkg_val.as_table() else {
            continue;
        };
        let Some(name) = pkg_table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = pkg_table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let normalized = normalize_name(name);
        graph
            .installed
            .insert(normalized.clone(), version.to_string());

        // poetry style: `[package.dependencies]` table of name → spec.
        if let Some(deps_table) = pkg_table.get("dependencies").and_then(|v| v.as_table()) {
            for (child, spec) in deps_table {
                let (range, optional) = parse_poetry_dep_spec(spec);
                graph.edges.push(DependencyEdge {
                    source_name: normalized.clone(),
                    source_version: version.to_string(),
                    target_name: normalize_name(child),
                    target_range: range,
                    resolved_target_version: None, // filled in post-pass
                    kind: if optional {
                        DepKind::Optional
                    } else {
                        DepKind::Runtime
                    },
                });
            }
        }
        // uv style: `dependencies = [{name = "foo", specifier = ">=1"} …]`.
        if let Some(deps_array) = pkg_table.get("dependencies").and_then(|v| v.as_array()) {
            for entry in deps_array {
                if let Some(t) = entry.as_table() {
                    let Some(child) = t.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let range = t
                        .get("specifier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    graph.edges.push(DependencyEdge {
                        source_name: normalized.clone(),
                        source_version: version.to_string(),
                        target_name: normalize_name(child),
                        target_range: range,
                        resolved_target_version: None,
                        kind: DepKind::Runtime,
                    });
                }
            }
        }

        // Compatibility row — engines["python"] holds the requires-python
        // constraint when present. Peer deps don't apply to PyPI; the map
        // stays empty.
        let python = pkg_table
            .get("python-versions")
            .and_then(|v| v.as_str())
            .or_else(|| pkg_table.get("requires-python").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        if let Some(py) = python {
            let mut engines = BTreeMap::new();
            engines.insert("python".to_string(), py);
            graph.compatibility.push(CompatibilityInfo {
                package_name: normalized,
                version: version.to_string(),
                engines,
                peer_deps: BTreeMap::new(),
            });
        }
    }

    // Post-pass: fill `resolved_target_version` from the installed map so
    // the graph API can traverse edges without re-consulting the lockfile.
    for edge in &mut graph.edges {
        edge.resolved_target_version = graph.installed.get(&edge.target_name).cloned();
    }

    Ok(graph)
}

fn parse_poetry_dep_spec(spec: &toml::Value) -> (String, bool) {
    match spec {
        toml::Value::String(s) => (s.clone(), false),
        toml::Value::Table(t) => {
            let range = t
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string();
            let optional = t.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
            (range, optional)
        }
        _ => ("*".to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_poetry_lock_shape() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("poetry.lock");
        std::fs::write(
            &path,
            r#"
[[package]]
name = "Django"
version = "4.2.7"
description = "A web framework"
category = "main"
optional = false

[[package]]
name = "requests"
version = "2.31.0"
"#,
        )
        .unwrap();
        let graph = parse_poetry_lock(&path).unwrap();
        assert_eq!(graph.installed["django"], "4.2.7");
        assert_eq!(graph.installed["requests"], "2.31.0");
    }

    #[test]
    fn parses_uv_lock_shape() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("uv.lock");
        std::fs::write(
            &path,
            r#"
version = 1

[[package]]
name = "Django"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "My_Pkg"
version = "1.0.0"
"#,
        )
        .unwrap();
        let graph = parse_uv_lock(&path).unwrap();
        assert_eq!(graph.installed["django"], "5.0.0");
        assert_eq!(graph.installed["my-pkg"], "1.0.0");
    }

    #[test]
    fn poetry_lock_emits_edges_from_package_dependencies_table() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("poetry.lock");
        std::fs::write(
            &path,
            r#"
[[package]]
name = "Django"
version = "4.2.7"
python-versions = ">=3.9"

[package.dependencies]
sqlparse = ">=0.3.1"
asgiref = { version = ">=3.6", optional = true }

[[package]]
name = "sqlparse"
version = "0.4.4"

[[package]]
name = "asgiref"
version = "3.7.2"
"#,
        )
        .unwrap();
        let graph = parse_poetry_lock(&path).unwrap();
        let edge_for = |child: &str| {
            graph
                .edges
                .iter()
                .find(|e| e.source_name == "django" && e.target_name == child)
                .cloned()
                .unwrap_or_else(|| panic!("missing django → {child}"))
        };
        assert_eq!(
            edge_for("sqlparse").resolved_target_version.as_deref(),
            Some("0.4.4")
        );
        assert_eq!(edge_for("sqlparse").kind, DepKind::Runtime);
        assert_eq!(edge_for("asgiref").kind, DepKind::Optional);
        // python-versions becomes engines["python"] on the compat row.
        let compat = graph
            .compatibility
            .iter()
            .find(|c| c.package_name == "django")
            .expect("django compat row");
        assert_eq!(compat.engines.get("python").unwrap(), ">=3.9");
    }

    #[test]
    fn uv_lock_emits_edges_from_inline_dependency_arrays() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("uv.lock");
        std::fs::write(
            &path,
            r#"
version = 1

[[package]]
name = "httpx"
version = "0.27.0"
requires-python = ">=3.8"
dependencies = [
  { name = "anyio", specifier = ">=3" },
  { name = "certifi" },
]

[[package]]
name = "anyio"
version = "4.3.0"

[[package]]
name = "certifi"
version = "2024.2.2"
"#,
        )
        .unwrap();
        let graph = parse_uv_lock(&path).unwrap();
        let edge = graph
            .edges
            .iter()
            .find(|e| e.source_name == "httpx" && e.target_name == "anyio")
            .expect("httpx → anyio");
        assert_eq!(edge.resolved_target_version.as_deref(), Some("4.3.0"));
        assert_eq!(edge.target_range, ">=3");
        let compat = graph
            .compatibility
            .iter()
            .find(|c| c.package_name == "httpx")
            .expect("httpx compat row");
        assert_eq!(compat.engines.get("python").unwrap(), ">=3.8");
    }
}
