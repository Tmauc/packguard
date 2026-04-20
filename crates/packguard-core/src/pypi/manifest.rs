//! Declared-deps parsers: `pyproject.toml` (PEP 621 + Poetry) and
//! `requirements*.txt` (pip declared-only).

use crate::model::{DepKind, Dependency};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Result of parsing a `pyproject.toml`.
pub struct Pyproject {
    pub name: Option<String>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct PyprojectRaw {
    #[serde(default)]
    project: Option<ProjectSection>,
    #[serde(default, rename = "dependency-groups")]
    dependency_groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    tool: Option<ToolSection>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct ProjectSection {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct ToolSection {
    #[serde(default)]
    poetry: Option<PoetrySection>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct PoetrySection {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    group: BTreeMap<String, PoetryGroup>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct PoetryGroup {
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

pub fn parse_pyproject(path: &Path) -> Result<Pyproject> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let raw: PyprojectRaw = toml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;

    let mut deps = Vec::new();
    let mut name = raw.project.as_ref().and_then(|p| p.name.clone());

    // --- PEP 621 `[project]` ---
    if let Some(project) = &raw.project {
        for spec in &project.dependencies {
            if let Some(d) = parse_pep508_spec(spec, DepKind::Runtime) {
                deps.push(d);
            }
        }
        for specs in project.optional_dependencies.values() {
            for spec in specs {
                if let Some(d) = parse_pep508_spec(spec, DepKind::Optional) {
                    deps.push(d);
                }
            }
        }
    }

    // --- PEP 735 `[dependency-groups]` ---
    for (group, specs) in &raw.dependency_groups {
        let kind = if group.eq_ignore_ascii_case("dev") || group.eq_ignore_ascii_case("test") {
            DepKind::Dev
        } else {
            DepKind::Optional
        };
        for spec in specs {
            if let Some(d) = parse_pep508_spec(spec, kind) {
                deps.push(d);
            }
        }
    }

    // --- Poetry `[tool.poetry]` ---
    if let Some(poetry) = raw.tool.as_ref().and_then(|t| t.poetry.as_ref()) {
        if name.is_none() {
            name = poetry.name.clone();
        }
        add_poetry_deps(&mut deps, &poetry.dependencies, DepKind::Runtime);
        add_poetry_deps(&mut deps, &poetry.dev_dependencies, DepKind::Dev);
        for (group_name, group) in &poetry.group {
            let kind = if group_name.eq_ignore_ascii_case("dev")
                || group_name.eq_ignore_ascii_case("test")
            {
                DepKind::Dev
            } else {
                DepKind::Optional
            };
            add_poetry_deps(&mut deps, &group.dependencies, kind);
        }
    }

    Ok(Pyproject { name, dependencies: deps })
}

fn add_poetry_deps(out: &mut Vec<Dependency>, src: &BTreeMap<String, toml::Value>, kind: DepKind) {
    for (name, value) in src {
        if name == "python" {
            continue;
        }
        let range = match value {
            toml::Value::String(s) => s.clone(),
            toml::Value::Table(t) => t
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string(),
            _ => "*".to_string(),
        };
        out.push(Dependency {
            name: name.clone(),
            declared_range: range,
            installed: None,
            kind,
            source_lockfile: None,
        });
    }
}

/// Very small PEP 508 extractor: pulls `name` and everything after the name
/// as `declared_range`. If the spec has a `==X.Y.Z` pin we also set
/// `installed` so pip-declared-only mode still produces classifications.
pub fn parse_pep508_spec(spec: &str, kind: DepKind) -> Option<Dependency> {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('#') {
        return None;
    }
    // Drop markers (` ; python_version >= "3.10"`).
    let spec = spec.split(';').next().unwrap_or(spec).trim();
    // Split name from spec.
    let name_end = spec
        .find(['[', '=', '<', '>', '!', '~', ' ', '('])
        .unwrap_or(spec.len());
    let name = spec[..name_end].trim().to_string();
    if name.is_empty() {
        return None;
    }
    // Remove extras: strip `[…]` if present after the name.
    let mut rest = spec[name_end..].trim().to_string();
    if rest.starts_with('[') {
        if let Some(close) = rest.find(']') {
            rest = rest[close + 1..].trim().to_string();
        }
    }
    let installed = extract_exact_pin(&rest);

    Some(Dependency {
        name,
        declared_range: if rest.is_empty() { "*".to_string() } else { rest },
        installed,
        kind,
        source_lockfile: None,
    })
}

fn extract_exact_pin(range: &str) -> Option<String> {
    // Accept `==1.2.3` possibly followed by ` ` or `,`. Reject `~=`, `!=`, `>=`, `<=`.
    let range = range.trim();
    let rest = range.strip_prefix("==")?;
    let end = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    let pin = rest[..end].trim();
    if pin.is_empty() {
        return None;
    }
    Some(pin.to_string())
}

/// List every `requirements*.txt` directly under `root`, in a deterministic order.
pub fn find_requirements_files(root: &Path) -> Result<Vec<PathBuf>> {
    let read = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("reading {}", root.display()))),
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("requirements") || !name.ends_with(".txt") {
            continue;
        }
        out.push(entry.path());
    }
    out.sort();
    Ok(out)
}

pub fn parse_requirements_file(path: &Path) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        // Skip flags like `-r`, `-e`, `--index-url`.
        if line.starts_with('-') {
            continue;
        }
        if let Some(dep) = parse_pep508_spec(line, DepKind::Runtime) {
            out.push(dep);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn pep508_name_only() {
        let d = parse_pep508_spec("requests", DepKind::Runtime).unwrap();
        assert_eq!(d.name, "requests");
        assert_eq!(d.declared_range, "*");
        assert!(d.installed.is_none());
    }

    #[test]
    fn pep508_extracts_exact_pin() {
        let d = parse_pep508_spec("django==4.2.7", DepKind::Runtime).unwrap();
        assert_eq!(d.name, "django");
        assert_eq!(d.installed.as_deref(), Some("4.2.7"));
    }

    #[test]
    fn pep508_ignores_non_exact() {
        let d = parse_pep508_spec("django>=4.0,<5", DepKind::Runtime).unwrap();
        assert_eq!(d.name, "django");
        assert!(d.installed.is_none());
    }

    #[test]
    fn pep508_handles_extras_and_markers() {
        let d = parse_pep508_spec(
            "uvicorn[standard]==0.30.0 ; python_version>='3.9'",
            DepKind::Runtime,
        )
        .unwrap();
        assert_eq!(d.name, "uvicorn");
        assert_eq!(d.installed.as_deref(), Some("0.30.0"));
    }

    #[test]
    fn pep508_skips_empty_and_comments() {
        assert!(parse_pep508_spec("", DepKind::Runtime).is_none());
        assert!(parse_pep508_spec("# comment", DepKind::Runtime).is_none());
    }

    #[test]
    fn requirements_file_basic() {
        let tmp = tempdir().unwrap();
        let req = tmp.path().join("requirements.txt");
        std::fs::write(
            &req,
            "# top comment\nrequests==2.31.0\n-r other.txt\ndjango>=4.0\n\n",
        )
        .unwrap();
        let deps = parse_requirements_file(&req).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].installed.as_deref(), Some("2.31.0"));
        assert_eq!(deps[1].name, "django");
    }

    #[test]
    fn find_requirements_orders_results() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("requirements.txt"), "a").unwrap();
        std::fs::write(tmp.path().join("requirements-dev.txt"), "b").unwrap();
        std::fs::write(tmp.path().join("other.txt"), "c").unwrap();
        let found = find_requirements_files(tmp.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["requirements-dev.txt", "requirements.txt"]);
    }

    #[test]
    fn pyproject_pep621() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("pyproject.toml");
        std::fs::write(
            &path,
            r#"
[project]
name = "demo"
dependencies = [
    "django>=4,<5",
    "requests==2.31.0",
]
[project.optional-dependencies]
dev = ["pytest"]

[dependency-groups]
test = ["coverage==7.5.0"]
"#,
        )
        .unwrap();
        let parsed = parse_pyproject(&path).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("demo"));
        let by: BTreeMap<_, _> = parsed
            .dependencies
            .iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        assert_eq!(by["requests"].installed.as_deref(), Some("2.31.0"));
        assert_eq!(by["django"].kind, DepKind::Runtime);
        assert_eq!(by["pytest"].kind, DepKind::Optional);
        assert_eq!(by["coverage"].kind, DepKind::Dev);
    }

    #[test]
    fn pyproject_poetry() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("pyproject.toml");
        std::fs::write(
            &path,
            r#"
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
django = "^4.0"
requests = { version = "2.31.0", extras = ["socks"] }

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"#,
        )
        .unwrap();
        let parsed = parse_pyproject(&path).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("demo"));
        let by: BTreeMap<_, _> = parsed
            .dependencies
            .iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        assert!(!by.contains_key("python"));
        assert_eq!(by["django"].declared_range, "^4.0");
        assert_eq!(by["requests"].declared_range, "2.31.0");
        assert_eq!(by["pytest"].kind, DepKind::Dev);
    }
}
