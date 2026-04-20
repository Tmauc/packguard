//! GitHub Advisory Database ingestion.
//!
//! The repo (`github/advisory-database`) publishes OSV-schema advisories
//! under `advisories/github-reviewed/`. We clone it once and `git pull`
//! thereafter. We shell out to the system `git` binary rather than link
//! libgit2 — the external dep is near-universal on dev + CI boxes and
//! keeps our binary small / build fast. If `git` is missing we surface a
//! clear error and let the user install it or rerun with
//! `--skip-ghsa` (wired in the CLI).

use crate::malware::{is_malware_advisory, to_malware_reports};
use crate::normalize::{normalize, parse_advisory_json_raw};
use crate::{filter_watched, filter_watched_malware, SourceSummary, WatchedPackages};
use anyhow::{bail, Context, Result};
use packguard_core::{MalwareReport, Vulnerability};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

const GHSA_REMOTE: &str = "https://github.com/github/advisory-database.git";

/// Clone / fast-forward the GHSA cache at `cache_dir`. Creates the dir if
/// necessary and returns the HEAD commit SHA for the `sync_log`.
pub fn clone_or_update(cache_dir: &Path) -> Result<String> {
    if cache_dir.join(".git").exists() {
        run_git(cache_dir, &["pull", "--ff-only"]).context("git pull GHSA cache")?;
    } else {
        if let Some(parent) = cache_dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp_dir = cache_dir.display().to_string();
        run_git(
            Path::new("."),
            &[
                "clone",
                "--depth",
                "1",
                "--single-branch",
                GHSA_REMOTE,
                &tmp_dir,
            ],
        )
        .context("git clone GHSA")?;
    }
    head_sha(cache_dir)
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .status()
        .context("spawning `git` — is it installed and on PATH?")?;
    if !status.success() {
        bail!("git {:?} failed with exit {:?}", args, status.code());
    }
    Ok(())
}

fn head_sha(repo: &Path) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("spawning `git rev-parse`")?;
    if !out.status.success() {
        bail!("git rev-parse HEAD failed in {}", repo.display());
    }
    Ok(String::from_utf8(out.stdout)
        .context("git rev-parse HEAD output")?
        .trim()
        .to_string())
}

/// Default on-disk cache location: `~/.packguard/cache/ghsa/advisory-database`.
pub fn default_cache_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("resolving home dir for GHSA cache (set $HOME)")?;
    Ok(home
        .join(".packguard")
        .join("cache")
        .join("ghsa")
        .join("advisory-database"))
}

/// Walk `github-reviewed/` in the cache and split each advisory into a
/// `Vulnerability` or a `MalwareReport` depending on its OSV id /
/// `database_specific` shape.
pub fn parse_cache(
    cache_dir: &Path,
    watched: &WatchedPackages,
) -> Result<(Vec<Vulnerability>, Vec<MalwareReport>, usize)> {
    let reviewed = cache_dir.join("advisories").join("github-reviewed");
    if !reviewed.exists() {
        bail!(
            "GHSA cache at {} does not have advisories/github-reviewed — did clone fail?",
            cache_dir.display()
        );
    }
    let mut scanned = 0usize;
    let mut all_vulns: Vec<Vulnerability> = Vec::new();
    let mut all_malware: Vec<MalwareReport> = Vec::new();
    for entry in WalkDir::new(&reviewed).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("GHSA-") || !name.ends_with(".json") {
            continue;
        }
        scanned += 1;
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(?path, ?err, "skipping unreadable GHSA advisory");
                continue;
            }
        };
        let raw = match parse_advisory_json_raw(&bytes) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(?path, ?err, "skipping malformed GHSA advisory");
                continue;
            }
        };
        if is_malware_advisory(&raw) {
            all_malware.extend(to_malware_reports(&raw));
        } else {
            all_vulns.extend(normalize(raw, "ghsa"));
        }
    }
    Ok((
        filter_watched(all_vulns, watched),
        filter_watched_malware(all_malware, watched),
        scanned,
    ))
}

/// End-to-end: clone/pull then parse. Returns vuln + malware lists + the
/// HEAD SHA to persist in `sync_log`.
pub fn sync(
    cache_dir: &Path,
    watched: &WatchedPackages,
) -> Result<(
    Vec<Vulnerability>,
    Vec<MalwareReport>,
    SourceSummary,
    String,
)> {
    let head = clone_or_update(cache_dir).context("clone/update GHSA cache")?;
    let (vulns, malware, scanned) = parse_cache(cache_dir, watched)?;
    let persisted = vulns.len() + malware.len();
    Ok((
        vulns,
        malware,
        SourceSummary {
            advisories_scanned: scanned,
            advisories_persisted: persisted,
            skipped_not_modified: false,
            error: None,
        },
        head,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_cache_reads_only_reviewed_ghsa_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reviewed = cache
            .join("advisories")
            .join("github-reviewed")
            .join("2024")
            .join("01");
        let unreviewed = cache
            .join("advisories")
            .join("unreviewed")
            .join("2024")
            .join("01");
        fs::create_dir_all(&reviewed).unwrap();
        fs::create_dir_all(&unreviewed).unwrap();

        let ghsa = r#"{
            "id": "GHSA-reviewed",
            "aliases": ["CVE-2024-0001"],
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "npm", "name": "react"},
                          "ranges": [{"type": "SEMVER",
                                       "events": [{"introduced": "0"}, {"fixed": "19.0.0"}]}]}]
        }"#;
        fs::write(reviewed.join("GHSA-reviewed.json"), ghsa).unwrap();

        // An unreviewed file must be ignored entirely.
        fs::write(
            unreviewed.join("GHSA-unreviewed.json"),
            r#"{"id": "GHSA-unreviewed", "affected": [
                {"package": {"ecosystem": "npm", "name": "react"}}
            ]}"#,
        )
        .unwrap();

        // A non-GHSA JSON file must not be picked up.
        fs::write(reviewed.join("README.md"), "stray").unwrap();

        let watched: WatchedPackages = None;
        let (vulns, malware, scanned) = parse_cache(cache, &watched).unwrap();
        assert_eq!(scanned, 1);
        assert_eq!(vulns.len(), 1);
        assert!(malware.is_empty());
        assert_eq!(vulns[0].advisory_id, "GHSA-reviewed");
        assert_eq!(vulns[0].source, "ghsa");
    }
}
