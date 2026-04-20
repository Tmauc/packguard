//! Resolved-version parsers for `poetry.lock` and `uv.lock`. Both are TOML
//! with `[[package]]` arrays exposing at least `name` + `version`.

use crate::pypi::normalize_name;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, serde::Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Debug, serde::Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
}

pub fn parse_poetry_lock(path: &Path) -> Result<BTreeMap<String, String>> {
    parse_generic(path)
}

pub fn parse_uv_lock(path: &Path) -> Result<BTreeMap<String, String>> {
    parse_generic(path)
}

fn parse_generic(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let parsed: Lockfile = toml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    let mut out = BTreeMap::new();
    for p in parsed.package {
        out.insert(normalize_name(&p.name), p.version);
    }
    Ok(out)
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
        let map = parse_poetry_lock(&path).unwrap();
        assert_eq!(map["django"], "4.2.7");
        assert_eq!(map["requests"], "2.31.0");
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
        let map = parse_uv_lock(&path).unwrap();
        assert_eq!(map["django"], "5.0.0");
        assert_eq!(map["my-pkg"], "1.0.0");
    }
}
