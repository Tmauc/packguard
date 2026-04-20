//! OSV API `POST /v1/query` fallback.
//!
//! Covers the "we haven't `packguard sync`ed yet / this package isn't in
//! our cached dumps" gap. We send a single `(ecosystem, name, version)`
//! tuple and normalize the returned advisories through the same pipeline
//! as the dump fetcher. Source is tagged `osv-api-live` so callers can
//! tell API-sourced rows apart from dump-sourced ones.

use crate::normalize::normalize;
use anyhow::{Context, Result};
use packguard_core::Vulnerability;
use serde::Serialize;
use std::time::Duration;

const DEFAULT_URL: &str = "https://api.osv.dev/v1/query";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct OsvApiClient {
    http: reqwest::Client,
    url: String,
}

#[derive(Debug, Serialize)]
struct QueryBody<'a> {
    package: QueryPackage<'a>,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct QueryPackage<'a> {
    ecosystem: &'a str,
    name: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<crate::normalize::RawAdvisory>,
}

impl OsvApiClient {
    pub fn new() -> Result<Self> {
        Self::with_url(DEFAULT_URL.to_string())
    }

    pub fn with_url(url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .context("building reqwest client for OSV API")?;
        Ok(Self { http, url })
    }

    /// Query the API for advisories affecting `(ecosystem, name, version)`.
    /// `ecosystem` uses OSV's canonical casing — `npm` lower, `PyPI` mixed.
    pub async fn query(
        &self,
        ecosystem_osv: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>> {
        let body = QueryBody {
            package: QueryPackage {
                ecosystem: ecosystem_osv,
                name,
            },
            version,
        };
        let resp = self
            .http
            .post(&self.url)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.url))?
            .error_for_status()
            .with_context(|| format!("status for {}", self.url))?;
        let body: QueryResponse = resp
            .json()
            .await
            .with_context(|| format!("decoding {}", self.url))?;
        let mut out = Vec::with_capacity(body.vulns.len());
        for raw in body.vulns {
            out.extend(normalize(raw, "osv-api-live"));
        }
        Ok(out)
    }
}

/// Translate an internal ecosystem id (`npm` / `pypi`) to the casing OSV
/// expects on the wire.
pub fn osv_ecosystem(id: &str) -> Option<&'static str> {
    match id {
        "npm" => Some("npm"),
        "pypi" => Some("PyPI"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_ecosystem_casing() {
        assert_eq!(osv_ecosystem("npm"), Some("npm"));
        assert_eq!(osv_ecosystem("pypi"), Some("PyPI"));
        assert_eq!(osv_ecosystem("go"), None);
    }
}
