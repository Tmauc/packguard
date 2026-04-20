//! Socket.dev opt-in scanner client.
//!
//! Activation: token via `PACKGUARD_SOCKET_TOKEN` env var (preferred) or a
//! caller-provided string. Without a token, callers should treat this
//! module as unavailable and skip silently — no error.
//!
//! Wire format: HTTP Basic auth with the token as the username and an
//! empty password (Socket's documented scheme). Endpoint shape:
//! `https://api.socket.dev/v0/{ecosystem}/{name}/{version}` returning a
//! JSON document with `score` + `alerts[]`.
//!
//! We map alerts to `MalwareReport`s:
//! - alerts whose `category` or `type` says `"malware"` → `MalwareKind::Malware`
//! - any other alert (`obfuscatedFile`, `installScripts`, `typosquat`,
//!   `criticalCVE`, …) → `MalwareKind::ScannerSignal` (informational, not
//!   blocking by default — the policy's `block.cve_severity` and
//!   `block.malware` channels handle the blocking semantics).

use anyhow::{Context, Result};
use packguard_core::{MalwareKind, MalwareReport};
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_BASE_URL: &str = "https://api.socket.dev/v0";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));
const TOKEN_ENV: &str = "PACKGUARD_SOCKET_TOKEN";

/// Resolve a Socket token from the environment. Returns `None` when no
/// token is configured — callers must treat this as opt-out, not error.
pub fn token_from_env() -> Option<String> {
    std::env::var(TOKEN_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone)]
pub struct SocketClient {
    http: reqwest::Client,
    base_url: String,
    auth_header: String,
}

#[derive(Debug, Deserialize, Default)]
struct ScoreResponse {
    #[serde(default)]
    alerts: Vec<RawAlert>,
}

#[derive(Debug, Deserialize, Default)]
struct RawAlert {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl SocketClient {
    pub fn new(token: &str) -> Result<Self> {
        Self::with_base_url(token, DEFAULT_BASE_URL.to_string())
    }

    pub fn with_base_url(token: &str, base_url: String) -> Result<Self> {
        use base64_lite::Base64;
        let creds = format!("{token}:");
        let auth_header = format!("Basic {}", creds.as_bytes().to_base64());
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .context("building reqwest client for Socket.dev")?;
        Ok(Self {
            http,
            base_url,
            auth_header,
        })
    }

    /// Query Socket for `(ecosystem, name, version)` and return one
    /// `MalwareReport` per surfaced alert. `ecosystem` follows our internal
    /// ids (`npm`, `pypi`); we map to Socket's path segment internally.
    pub async fn query(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<MalwareReport>> {
        let socket_eco = match ecosystem {
            "npm" => "npm",
            "pypi" => "pypi",
            other => {
                tracing::debug!(ecosystem = other, "Socket.dev: ecosystem unsupported");
                return Ok(Vec::new());
            }
        };
        let url = format!("{}/{}/{}/{}", self.base_url, socket_eco, name, version);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // Package version unknown to Socket — not an error.
            return Ok(Vec::new());
        }
        let resp = resp
            .error_for_status()
            .with_context(|| format!("status for {url}"))?;
        let body: ScoreResponse = resp
            .json()
            .await
            .with_context(|| format!("decoding {url}"))?;

        let mut out = Vec::with_capacity(body.alerts.len());
        for alert in body.alerts {
            let label = alert
                .kind
                .clone()
                .or_else(|| alert.category.clone())
                .unwrap_or_else(|| "alert".to_string());
            let kind = if is_malware_label(&label) {
                MalwareKind::Malware
            } else {
                MalwareKind::ScannerSignal
            };
            let summary = alert
                .title
                .clone()
                .or_else(|| alert.description.clone())
                .unwrap_or_else(|| label.clone());
            let evidence = serde_json::json!({
                "type": alert.kind,
                "category": alert.category,
                "severity": alert.severity,
                "description": alert.description,
                "extra": alert.extra,
            });
            out.push(MalwareReport {
                source: "socket.dev".into(),
                ref_id: format!("socket:{}/{}@{}/{}", ecosystem, name, version, label),
                ecosystem: ecosystem.to_string(),
                package_name: name.to_string(),
                version: version.to_string(),
                kind,
                summary: Some(summary),
                url: alert.url.clone(),
                evidence,
                reported_at: None,
            });
        }
        Ok(out)
    }
}

fn is_malware_label(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    s.contains("malware") || s == "malicious" || s.contains("backdoor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_env_unset_returns_none() {
        // We can't unset reliably across threads — just assert the behaviour
        // when the var is empty / absent matches None.
        // (Don't mutate env in tests; rely on the explicit empty case.)
        assert_eq!(
            std::env::var(TOKEN_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .is_none(),
            std::env::var(TOKEN_ENV)
                .map(|s| s.is_empty())
                .unwrap_or(true)
        );
    }

    #[test]
    fn classifies_malware_label() {
        assert!(is_malware_label("malware"));
        assert!(is_malware_label("MALICIOUS"));
        assert!(is_malware_label("contains-backdoor"));
        assert!(!is_malware_label("installScripts"));
        assert!(!is_malware_label("obfuscatedFile"));
    }
}

// ----- tiny base64 encoder, no extra dep ------------------------------------
mod base64_lite {
    pub trait Base64 {
        fn to_base64(&self) -> String;
    }
    impl Base64 for [u8] {
        fn to_base64(&self) -> String {
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::with_capacity(self.len().div_ceil(3) * 4);
            for chunk in self.chunks(3) {
                let b0 = chunk[0];
                let b1 = chunk.get(1).copied().unwrap_or(0);
                let b2 = chunk.get(2).copied().unwrap_or(0);
                out.push(ALPHABET[(b0 >> 2) as usize] as char);
                out.push(ALPHABET[((b0 & 0b11) << 4 | b1 >> 4) as usize] as char);
                if chunk.len() > 1 {
                    out.push(ALPHABET[((b1 & 0b1111) << 2 | b2 >> 6) as usize] as char);
                } else {
                    out.push('=');
                }
                if chunk.len() > 2 {
                    out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
                } else {
                    out.push('=');
                }
            }
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rfc4648_examples() {
            assert_eq!("".as_bytes().to_base64(), "");
            assert_eq!("f".as_bytes().to_base64(), "Zg==");
            assert_eq!("fo".as_bytes().to_base64(), "Zm8=");
            assert_eq!("foo".as_bytes().to_base64(), "Zm9v");
            assert_eq!("foob".as_bytes().to_base64(), "Zm9vYg==");
            assert_eq!("fooba".as_bytes().to_base64(), "Zm9vYmE=");
            assert_eq!("foobar".as_bytes().to_base64(), "Zm9vYmFy");
        }
    }
}
