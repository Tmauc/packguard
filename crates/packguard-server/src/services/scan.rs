//! Headless scan orchestration. Mirrors the CLI's `scan` flow without the
//! terminal rendering — same fingerprint short-circuit, same per-project
//! save. Returns a `ScanReport` that the dashboard can show right after the
//! job finishes.

use crate::dto::ScanReport;
use anyhow::Result;
use packguard_core::{default_ecosystems, discover, DiscoveryOptions, Ecosystem, Project};
use packguard_store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// Dashboard-driven scan.
///
/// The UI's "Scan" button used to run this against the single path the
/// server was launched with (`ServerConfig.repo_path`) — that was the
/// server's CWD in practice, and was almost never a directory with a
/// scannable manifest (dogfood finding #5: "no supported manifest found
/// at /.../packguard"). Option A per §14.10: re-scan every repo the
/// store already knows about. If the store is empty, fall back to the
/// server's `repo_root` so a fresh install still has a path to try — but
/// the error when that path has no manifest now mentions the alternative
/// (`packguard scan <path>` from the CLI).
///
/// Phase 14.5a (Bug A) — replace the legacy `eco.detect(target)` direct
/// call with the Phase 9a [`packguard_core::discover`] layer the CLI has
/// used since v0.2.0. The legacy path only matched manifests sitting at
/// the *exact* `target` directory; submitting `add_project` against a
/// monorepo root like `/Users/x/Repo/foo` (which is a Rust workspace at
/// the top level but holds a `web/` JS subproject one level down) would
/// silently bail "no supported manifest found". Discovery walks up to
/// `DEFAULT_MAX_DEPTH` levels with the built-in denylist (node_modules,
/// dist, .pnpm, target, …) and surfaces every workspace candidate.
pub async fn run(store: &mut Store, repo_root: &Path) -> Result<ScanReport> {
    let ecosystems = default_ecosystems()?;
    let mut report = ScanReport::default();
    let mut any_detected = false;

    let known_repos = store.distinct_repo_paths()?;
    let targets: Vec<std::path::PathBuf> = if known_repos.is_empty() {
        vec![repo_root.to_path_buf()]
    } else {
        known_repos
    };

    let discovery_opts = DiscoveryOptions::default();
    let mut subdirs_explored = 0usize;
    for target in &targets {
        let outcome = discover(target, &discovery_opts).map_err(|err| {
            anyhow::anyhow!("discovering projects under {}: {err:#}", target.display())
        })?;
        subdirs_explored += outcome.projects.len();
        for discovered in &outcome.projects {
            for eco in &ecosystems {
                let projects = eco.detect(&discovered.path)?;
                if projects.is_empty() {
                    continue;
                }
                any_detected = true;
                for project in projects {
                    scan_one_project(store, eco.as_ref(), &project, &discovered.path, &mut report)
                        .await?;
                }
            }
        }
    }

    if !any_detected {
        let joined = targets
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "no supported manifest found under {joined}. Walked up to {depth} levels deep \
             across {n} candidate subdir{plural} (excluded: node_modules, target, dist, build, \
             .next, .nuxt, .venv, venv, __pycache__, vendor, .git, .turbo, .nx, .svelte-kit, \
             .output). Pass an absolute path to a directory with a package.json / pyproject.toml \
             / requirements.txt under it, or run `packguard scan <path>` from the CLI.",
            depth = packguard_core::DEFAULT_MAX_DEPTH,
            n = subdirs_explored,
            plural = if subdirs_explored == 1 { "" } else { "s" },
        );
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

#[cfg(test)]
mod tests {
    //! Phase 14.5a (Bug A) — scan service must use the same Phase 9a
    //! recursive discovery layer the CLI does, otherwise the dashboard's
    //! "Scan" + the AddProjectModal silently bail on monorepos whose
    //! manifests live in subdirectories.
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    /// Minimal valid package.json the npm ecosystem will parse — name +
    /// version + a single dependency so save_project actually writes a
    /// row. Keeps the registry-fetch surface deterministic by using a
    /// scope that doesn't hit the wire (npm's detect() doesn't perform
    /// any network calls; fetch_latest does, but with no deps to fetch
    /// the call is a no-op).
    const EMPTY_PACKAGE_JSON: &str = r#"{ "name": "fixture", "version": "1.0.0" }"#;

    #[tokio::test]
    async fn scan_recursive_finds_workspace_in_subdir() {
        // /tmp/.../foo/.git/, /foo/web/package.json, /foo/marketing/ (empty).
        // Pre-Bug-A this would bail "no supported manifest found at /foo".
        let tmp = tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        touch(&root.join("web/package.json"), EMPTY_PACKAGE_JSON);
        fs::create_dir_all(root.join("marketing")).unwrap();

        let mut store = Store::open_in_memory().unwrap();
        let report = run(&mut store, &root)
            .await
            .expect("recursive scan should succeed");
        assert!(
            report.projects_scanned >= 1,
            "expected ≥ 1 workspace persisted, got {report:?}",
        );
        // The workspace path persisted should be the subdir, not the root.
        let known = store.distinct_repo_paths().unwrap();
        assert!(
            known.iter().any(|p| p.ends_with("web")),
            "expected /web workspace in store, got {known:?}",
        );
    }

    #[tokio::test]
    async fn scan_recursive_skips_node_modules_and_dist() {
        // First-party manifest at /foo/web; nested junk under /foo/web/node_modules
        // and /foo/web/dist that should NOT be picked up by discovery.
        let tmp = tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        touch(&root.join("web/package.json"), EMPTY_PACKAGE_JSON);
        // Decoy package.json files inside denylisted directories. If
        // discovery doesn't honour BUILTIN_EXCLUDES we'd see 3+ workspaces
        // persisted instead of 1.
        touch(
            &root.join("web/node_modules/foo/package.json"),
            r#"{ "name": "foo", "version": "0.0.0" }"#,
        );
        touch(
            &root.join("web/dist/baz/package.json"),
            r#"{ "name": "baz", "version": "0.0.0" }"#,
        );

        let mut store = Store::open_in_memory().unwrap();
        run(&mut store, &root)
            .await
            .expect("recursive scan should succeed");
        let known = store.distinct_repo_paths().unwrap();
        assert_eq!(
            known.len(),
            1,
            "expected exactly 1 workspace (denylisted dirs ignored), got {known:?}",
        );
        assert!(
            known[0].ends_with("web"),
            "expected /web, got {:?}",
            known[0]
        );
    }

    #[tokio::test]
    async fn scan_fails_with_helpful_error_when_truly_empty() {
        // /foo/.git + /foo/sub/file.txt — no manifests anywhere. The bail
        // message must call out the depth + denylist so the user knows
        // what was searched (and why an obscure subdir might have been
        // skipped).
        let tmp = tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        touch(&root.join("sub/file.txt"), "no manifest here");

        let mut store = Store::open_in_memory().unwrap();
        let err = run(&mut store, &root).await.unwrap_err().to_string();
        assert!(
            err.contains("no supported manifest"),
            "error should still call out the missing-manifest condition: {err}",
        );
        assert!(
            err.contains("levels deep"),
            "error should mention the explored depth: {err}",
        );
        assert!(
            err.contains("node_modules"),
            "error should mention the denylist for context: {err}",
        );
    }
}
