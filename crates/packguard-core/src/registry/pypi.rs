//! PyPI JSON client — `https://pypi.org/pypi/{name}/json`.
//!
//! Returns `RemotePackage::latest` from `info.version`, with the matching
//! `releases[version][0].upload_time_iso_8601` as `latest_published_at`.

use crate::model::{RemotePackage, RemoteVersion};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_BASE_URL: &str = "https://pypi.org/pypi";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct Response {
    info: Info,
    #[serde(default)]
    releases: BTreeMap<String, Vec<ReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct Info {
    version: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    yanked: bool,
}

#[derive(Debug, Clone)]
pub struct PypiClient {
    http: reqwest::Client,
    base_url: String,
    concurrency: usize,
}

impl PypiClient {
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
        let url = format!("{}/{}/json", self.base_url, name);
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("GET {}", url))?
            .error_for_status()
            .with_context(|| format!("status for {}", url))?;
        let body: Response = resp
            .json()
            .await
            .with_context(|| format!("decoding {}", url))?;
        let latest = body.info.version;
        let latest_published_at = body
            .releases
            .get(&latest)
            .and_then(|files| files.first())
            .and_then(|f| f.upload_time_iso_8601.clone());
        let versions = body
            .releases
            .iter()
            .filter(|(_, files)| !files.is_empty()) // skip placeholder keys
            .map(|(version, files)| RemoteVersion {
                version: version.clone(),
                published_at: files.first().and_then(|f| f.upload_time_iso_8601.clone()),
                deprecated: false, // PyPI has no per-version deprecated flag.
                // A release is yanked when every distribution file is yanked.
                yanked: files.iter().all(|f| f.yanked),
            })
            .collect();
        Ok(RemotePackage {
            name: name.to_string(),
            latest: Some(latest),
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
        stream::iter(names)
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
