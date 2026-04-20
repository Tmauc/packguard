//! Headless scan orchestration. Mirrors the CLI's `scan` flow without the
//! terminal rendering — same fingerprint short-circuit, same per-project
//! save. Returns a `ScanReport` that the dashboard can show right after the
//! job finishes.

use crate::dto::ScanReport;
use anyhow::Result;
use packguard_core::{default_ecosystems, Ecosystem, Project};
use packguard_store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub async fn run(store: &mut Store, repo_root: &Path) -> Result<ScanReport> {
    let ecosystems = default_ecosystems()?;
    let mut report = ScanReport::default();
    let mut any_detected = false;
    for eco in &ecosystems {
        let projects = eco.detect(repo_root)?;
        if projects.is_empty() {
            continue;
        }
        any_detected = true;
        for project in projects {
            scan_one_project(store, eco.as_ref(), &project, repo_root, &mut report).await?;
        }
    }
    if !any_detected {
        anyhow::bail!("no supported manifest found at {}", repo_root.display());
    }
    Ok(report)
}

async fn scan_one_project(
    store: &mut Store,
    eco: &dyn Ecosystem,
    project: &Project,
    repo_root: &Path,
    report: &mut ScanReport,
) -> Result<()> {
    report.projects_scanned += 1;
    let fingerprint = fingerprint_project(project)?;
    let last_fp = store.last_fingerprint(repo_root, eco.id())?;
    if last_fp.as_deref() == Some(fingerprint.as_str()) {
        // Nothing to do — caller will see `packages_persisted` not move.
        return Ok(());
    }
    let names: Vec<String> = project
        .dependencies
        .iter()
        .map(|d| d.name.clone())
        .collect();
    let results = eco.fetch_latest(names).await;
    let mut remotes = BTreeMap::new();
    for (name, result) in results {
        match result {
            Ok(info) => {
                remotes.insert(name, info);
            }
            Err(err) => {
                report.registry_errors += 1;
                tracing::warn!(%name, ?err, "registry fetch failed");
            }
        }
    }
    let stats = store.save_project(repo_root, project, &remotes, &fingerprint)?;
    report.packages_persisted += stats.packages as u32;
    Ok(())
}

fn fingerprint_project(project: &Project) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(project.ecosystem.as_bytes());
    hasher.update(b"\0");
    hash_file_if_exists(&mut hasher, &project.manifest_path)?;
    let candidates: &[&str] = match project.ecosystem {
        "npm" => &["package-lock.json", "pnpm-lock.yaml"],
        "pypi" => &["uv.lock", "poetry.lock"],
        _ => &[],
    };
    for name in candidates {
        hash_file_if_exists(&mut hasher, &project.root.join(name))?;
    }
    Ok(hex(&hasher.finalize()))
}

fn hash_file_if_exists(hasher: &mut Sha256, path: &Path) -> Result<()> {
    match std::fs::read(path) {
        Ok(bytes) => {
            hasher.update(path.display().to_string().as_bytes());
            hasher.update(b"\0");
            hasher.update(&bytes);
            hasher.update(b"\0");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("hashing {}", path.display()))),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
