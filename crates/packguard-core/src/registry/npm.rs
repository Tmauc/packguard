//! npm registry client — reads `dist-tags.latest` and the `time` map from
//! `https://registry.npmjs.org/<name>`.

use crate::model::{RemotePackage, RemoteVersion};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_BASE_URL: &str = "https://registry.npmjs.org";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct RegistryResponse {
    #[serde(default, rename = "dist-tags")]
    dist_tags: BTreeMap<String, String>,
    // `time` map mixes per-version strings with objects like
    // `unpublished: { time: ... }`. Use `Value` and filter to strings at
    // lookup time so one weird entry doesn't blow up the whole response.
    #[serde(default)]
    time: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    versions: BTreeMap<String, NpmVersionMeta>,
}

#[derive(Debug, Deserialize, Default)]
struct NpmVersionMeta {
    /// npm's `deprecated` is a free-form string message (non-empty ⇒ deprecated),
    /// occasionally `true` or `null` in the wild.
    #[serde(default)]
    deprecated: Option<serde_json::Value>,
}

impl NpmVersionMeta {
    fn is_deprecated(&self) -> bool {
        match &self.deprecated {
            Some(serde_json::Value::String(s)) => !s.trim().is_empty(),
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Null) | None => false,
            Some(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NpmClient {
    http: reqwest::Client,
    base_url: String,
    concurrency: usize,
}

impl NpmClient {
    pub fn new() -> Result<Self> {
        Self::with_base_url(DEFAULT_BASE_URL.to_string())
    }

    pub fn with_base_url(base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .context("building reqwest client")?;
        Ok(Self {
            http,
            base_url,
            concurrency: 16,
        })
    }

    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }

    pub async fn fetch_one(&self, name: &str) -> Result<RemotePackage> {
        let url = format!("{}/{}", self.base_url, encode_name(name));
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("GET {}", url))?
            .error_for_status()
            .with_context(|| format!("status for {}", url))?;
        let body: RegistryResponse = resp
            .json()
            .await
            .with_context(|| format!("decoding {}", url))?;
        let latest = body.dist_tags.get("latest").cloned();
        let latest_published_at = latest
            .as_ref()
            .and_then(|v| body.time.get(v))
            .and_then(|value| value.as_str().map(str::to_string));
        let versions = body
            .versions
            .iter()
            .map(|(version, meta)| RemoteVersion {
                version: version.clone(),
                published_at: body
                    .time
                    .get(version)
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                deprecated: meta.is_deprecated(),
                // npm has no native yanked flag — the concept lives in `time.unpublished`.
                yanked: false,
            })
            .collect();
        Ok(RemotePackage {
            name: name.to_string(),
            latest,
            latest_published_at,
            versions,
        })
    }

    pub async fn fetch_many<I, S>(&self, names: I) -> Vec<(String, Result<RemotePackage>)>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let names: Vec<String> = names.into_iter().map(Into::into).collect();
        stream::iter(names.into_iter())
            .map(|name| {
                let client = self.clone();
                async move {
                    let result = client.fetch_one(&name).await;
                    (name, result)
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await
    }
}

/// npm allows scoped names (`@scope/pkg`); the `@` and `/` must be percent-encoded
/// as `%40` and `%2f` for the registry URL path.
fn encode_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((scope, pkg)) = rest.split_once('/') {
            return format!("@{}%2f{}", scope, pkg);
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_scoped_names() {
        assert_eq!(encode_name("react"), "react");
        assert_eq!(encode_name("@babel/core"), "@babel%2fcore");
    }
}
