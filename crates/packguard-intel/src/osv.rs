//! OSV dump fetcher.
//!
//! Each ecosystem is published as a single zip file containing one JSON
//! advisory per entry. We fetch incrementally with `If-None-Match` /
//! `If-Modified-Since` against the stored sync state, so untouched dumps
//! cost one HTTP HEAD-equivalent and nothing else.

use crate::malware::{is_malware_advisory, to_malware_reports};
use crate::normalize::{normalize, parse_advisory_json_raw};
use crate::{filter_watched, filter_watched_malware, SourceSummary, WatchedPackages};
use anyhow::{Context, Result};
use packguard_core::{MalwareReport, Vulnerability};
use std::io::{Cursor, Read};
use std::time::Duration;

const DUMP_BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const USER_AGENT: &str = concat!("packguard/", env!("CARGO_PKG_VERSION"));

/// One ecosystem's sync invariants.
pub struct Dump {
    /// Short id used as the `sync_log.kind` key (e.g. `osv-npm`).
    pub id: &'static str,
    /// Path segment in the OSV storage URL (e.g. `npm`, `PyPI`).
    pub path: &'static str,
}

pub const NPM: Dump = Dump {
    id: "osv-npm",
    path: "npm",
};
pub const PYPI: Dump = Dump {
    id: "osv-pypi",
    path: "PyPI",
};

/// Prior sync bookkeeping consumed by `fetch_dump` to short-circuit on
/// `304 Not Modified`.
#[derive(Debug, Clone, Default)]
pub struct PriorSyncState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Updated sync bookkeeping returned after a successful fetch.
#[derive(Debug, Clone, Default)]
pub struct UpdatedSyncState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub struct FetchedDump {
    pub vulnerabilities: Vec<Vulnerability>,
    pub malware_reports: Vec<MalwareReport>,
    pub summary: SourceSummary,
    pub updated_state: Option<UpdatedSyncState>,
}

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building reqwest client for OSV dump")
}

/// Fetch + parse one ecosystem's dump, filtering to `watched` packages on
/// the fly. Returns an empty vulnerability list and `skipped_not_modified =
/// true` if the server returned 304.
pub async fn fetch_dump(
    dump: &Dump,
    prior: &PriorSyncState,
    watched: &WatchedPackages,
) -> Result<FetchedDump> {
    let client = build_client()?;
    let url = format!("{}/{}/all.zip", DUMP_BASE_URL, dump.path);
    let mut request = client.get(&url);
    if let Some(etag) = &prior.etag {
        request = request.header("If-None-Match", etag.as_str());
    }
    if let Some(lm) = &prior.last_modified {
        request = request.header("If-Modified-Since", lm.as_str());
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("GET {}", url))?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(FetchedDump {
            vulnerabilities: Vec::new(),
            malware_reports: Vec::new(),
            summary: SourceSummary {
                advisories_scanned: 0,
                advisories_persisted: 0,
                skipped_not_modified: true,
                error: None,
            },
            updated_state: None,
        });
    }

    let response = response
        .error_for_status()
        .with_context(|| format!("status for {}", url))?;
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let last_modified = response
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("downloading {}", url))?;
    tracing::info!(dump = dump.id, bytes = bytes.len(), "OSV dump downloaded");

    let (vulns, malware, scanned) = parse_zip(bytes.as_ref(), watched)?;
    let persisted = vulns.len() + malware.len();
    Ok(FetchedDump {
        vulnerabilities: vulns,
        malware_reports: malware,
        summary: SourceSummary {
            advisories_scanned: scanned,
            advisories_persisted: persisted,
            skipped_not_modified: false,
            error: None,
        },
        updated_state: Some(UpdatedSyncState {
            etag,
            last_modified,
        }),
    })
}

/// Decompress `zip_bytes` and split each entry into either a vuln or a
/// malware report depending on the OSV id / `database_specific` shape.
/// Returns `(filtered_vulns, filtered_malware, total_scanned)`.
pub fn parse_zip(
    zip_bytes: &[u8],
    watched: &WatchedPackages,
) -> Result<(Vec<Vulnerability>, Vec<MalwareReport>, usize)> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(zip_bytes)).context("opening OSV zip dump")?;
    let mut all_vulns: Vec<Vulnerability> = Vec::new();
    let mut all_malware: Vec<MalwareReport> = Vec::new();
    let mut scanned = 0usize;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("reading zip entry {i}"))?;
        if !entry.name().ends_with(".json") {
            continue;
        }
        scanned += 1;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("reading zip entry {}", entry.name()))?;
        let raw = match parse_advisory_json_raw(&buf) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(entry = entry.name(), ?err, "skipping malformed advisory");
                continue;
            }
        };
        if is_malware_advisory(&raw) {
            all_malware.extend(to_malware_reports(&raw));
        } else {
            all_vulns.extend(normalize(raw, "osv"));
        }
    }
    let vulns = filter_watched(all_vulns, watched);
    let malware = filter_watched_malware(all_malware, watched);
    Ok((vulns, malware, scanned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_fixture_zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(body.as_bytes()).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn parse_zip_keeps_only_watched_packages() {
        let adv_a = r#"{
            "id": "A",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.21"}]}]}]
        }"#;
        let adv_b = r#"{
            "id": "B",
            "database_specific": {"severity": "LOW"},
            "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.3.0"}]}]}]
        }"#;
        let zip = build_fixture_zip(&[("A.json", adv_a), ("B.json", adv_b)]);

        let watched: WatchedPackages = Some(
            [("npm".to_string(), "lodash".to_string())]
                .into_iter()
                .collect(),
        );
        let (vulns, malware, scanned) = parse_zip(&zip, &watched).unwrap();
        assert_eq!(scanned, 2);
        assert_eq!(vulns.len(), 1);
        assert!(malware.is_empty());
        assert_eq!(vulns[0].package_name, "lodash");
    }

    #[test]
    fn parse_zip_none_watched_returns_all() {
        let adv = r#"{
            "id": "X",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "foo"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.0.0"}]}]}]
        }"#;
        let zip = build_fixture_zip(&[("x.json", adv)]);
        let (vulns, _malware, scanned) = parse_zip(&zip, &None).unwrap();
        assert_eq!(scanned, 1);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn parse_zip_routes_mal_advisories_to_malware_bucket() {
        let regular = r#"{
            "id": "GHSA-x", "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.21"}]}]}]
        }"#;
        let mal = r#"{
            "id": "MAL-2024-7777", "summary": "malicious package",
            "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"},
                          "versions": ["1.0.0"]}]
        }"#;
        let zip = build_fixture_zip(&[("a.json", regular), ("b.json", mal)]);
        let (vulns, malware, scanned) = parse_zip(&zip, &None).unwrap();
        assert_eq!(scanned, 2);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].package_name, "lodash");
        assert_eq!(malware.len(), 1);
        assert_eq!(malware[0].package_name, "evil-pkg");
        assert_eq!(malware[0].source, "osv-mal");
    }

    #[test]
    fn parse_zip_skips_malformed_entries_without_failing() {
        let good = r#"{
            "id": "G",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "good"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "1.0.0"}]}]}]
        }"#;
        let zip = build_fixture_zip(&[("good.json", good), ("bad.json", "{ this isn't JSON")]);
        let (vulns, _malware, _) = parse_zip(&zip, &None).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].advisory_id, "G");
    }
}
