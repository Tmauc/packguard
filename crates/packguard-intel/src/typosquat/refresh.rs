//! Maintenance of the cached top-N reference lists.
//!
//! Two sources today:
//! - **PyPI** — `https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json`
//!   is community-maintained, ships ~5000 packages by 30-day download count,
//!   and updates monthly. We cache the file at
//!   `~/.packguard/cache/reference/pypi-top-packages.json` and refresh on a
//!   7-day TTL.
//! - **npm** — there is no equivalent first-party feed; we ship a curated
//!   baseline (`embedded::NPM_TOP`) inside the binary and merge it with
//!   anything the user drops at
//!   `~/.packguard/cache/reference/npm-top-packages.json`. Future work:
//!   periodic registry-search-ranked refresh.

use crate::typosquat::embedded;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PYPI_URL: &str = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));

/// Default cache directory, e.g. `~/.packguard/cache/reference/`.
pub fn default_cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("resolving home dir for typosquat reference cache")?;
    Ok(home.join(".packguard").join("cache").join("reference"))
}

/// Path of the JSON file holding the top-N list for `ecosystem`.
pub fn cache_path(ecosystem: &str) -> Result<PathBuf> {
    Ok(default_cache_dir()?.join(format!("{ecosystem}-top-packages.json")))
}

/// Load the npm baseline + any user-provided JSON list (one string array
/// per line OR `{ "packages": [...] }`).
pub fn load_npm_top() -> Result<HashSet<String>> {
    let mut out: HashSet<String> = embedded::NPM_TOP.iter().map(|s| s.to_string()).collect();
    if let Ok(path) = cache_path("npm") {
        if path.exists() {
            for name in load_json_list(&path)? {
                out.insert(name);
            }
        }
    }
    Ok(out)
}

/// Load the PyPI cache (the embedded baseline is empty for PyPI; sync is
/// expected to populate the cache).
pub fn load_pypi_top() -> Result<HashSet<String>> {
    let path = cache_path("pypi")?;
    if !path.exists() {
        return Ok(HashSet::new());
    }
    Ok(load_json_list(&path)?.into_iter().collect())
}

/// Download the PyPI top-N list (skips when `cached_at` is younger than
/// `ttl`). Returns the number of names persisted.
pub async fn refresh_pypi(ttl: Duration, cached_at: Option<&str>) -> Result<usize> {
    if let Some(ts) = cached_at.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
        let age = chrono::Utc::now().signed_duration_since(ts.to_utc());
        if age.to_std().unwrap_or_default() < ttl {
            return Ok(0);
        }
    }
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .context("building reqwest client")?;
    let resp = client
        .get(PYPI_URL)
        .send()
        .await
        .with_context(|| format!("GET {PYPI_URL}"))?
        .error_for_status()
        .with_context(|| format!("status for {PYPI_URL}"))?;
    let bytes = resp.bytes().await.context("downloading PyPI top-N JSON")?;
    let names = parse_hugovk_json(&bytes)?;
    write_cache("pypi", &names)?;
    Ok(names.len())
}

fn parse_hugovk_json(bytes: &[u8]) -> Result<Vec<String>> {
    // hugovk's file is `{"last_update": "...", "rows": [{"download_count":N,
    // "project":"name"}, ...]}`. We accept either that shape or a plain
    // ["name", "name", ...] array for forward compatibility.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Shape {
        Hugovk { rows: Vec<Row> },
        Plain(Vec<String>),
    }
    #[derive(serde::Deserialize)]
    struct Row {
        project: String,
    }
    let shape: Shape = serde_json::from_slice(bytes).context("decoding top-N JSON")?;
    Ok(match shape {
        Shape::Hugovk { rows } => rows.into_iter().map(|r| r.project).collect(),
        Shape::Plain(v) => v,
    })
}

fn write_cache(ecosystem: &str, names: &[String]) -> Result<()> {
    let dir = default_cache_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let path = dir.join(format!("{ecosystem}-top-packages.json"));
    let json = serde_json::to_string(names).context("serializing top-N JSON")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn load_json_list(path: &Path) -> Result<Vec<String>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_hugovk_json(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hugovk_shape() {
        let body = r#"{"last_update":"2026-04-01","rows":[
            {"download_count":1234,"project":"requests"},
            {"download_count":1000,"project":"django"}
        ]}"#;
        let names = parse_hugovk_json(body.as_bytes()).unwrap();
        assert_eq!(names, vec!["requests".to_string(), "django".to_string()]);
    }

    #[test]
    fn parses_plain_array_shape() {
        let body = r#"["alpha","beta","gamma"]"#;
        let names = parse_hugovk_json(body.as_bytes()).unwrap();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn npm_baseline_loads_without_cache() {
        let set = load_npm_top().unwrap();
        assert!(set.contains("react"));
        assert!(set.contains("lodash"));
        assert!(set.len() >= 100);
    }
}
