//! Headless sync orchestration. Mirrors `packguard sync` minus terminal
//! rendering. Runs OSV npm + PyPI dumps + GHSA git pull + typosquat list
//! refresh. Returns a `SyncReport` for the dashboard to display.
//!
//! Phase 14.1e.2 — intel-wide writes (sync_log, vulnerabilities,
//! malware_reports) flow into [`IntelStore`] instead of [`Store`].
//! Phase 14.2b.2.4 — `watched_packages` reads now fan out across
//! per-project stores via [`ProjectStoreCache`], replacing the
//! legacy `Store::watched_packages()` call. The legacy `Store` is
//! no longer touched by sync.

use crate::dto::SyncReport;
use anyhow::Result;
use packguard_intel::WatchedPackages;
use packguard_store::{IntelStore, ProjectStoreCache};
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

pub async fn run(intel: &mut IntelStore, project_stores: &ProjectStoreCache) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    let watched_pairs = collect_watched(project_stores).await?;
    let watched: WatchedPackages = Some(watched_pairs.iter().cloned().collect());

    for dump in [&packguard_intel::osv::NPM, &packguard_intel::osv::PYPI] {
        let prior_state = intel.get_sync_state(dump.id)?;
        let prior = packguard_intel::osv::PriorSyncState {
            etag: prior_state.as_ref().and_then(|s| s.etag.clone()),
            last_modified: prior_state.as_ref().and_then(|s| s.last_modified.clone()),
        };
        match packguard_intel::osv::fetch_dump(dump, &prior, &watched).await {
            Ok(fetched) => {
                if !fetched.summary.skipped_not_modified {
                    let v = intel.persist_vulnerabilities(&fetched.vulnerabilities)?;
                    let m = intel.persist_malware_reports(&fetched.malware_reports)?;
                    if dump.id == "osv-npm" {
                        report.osv_npm_persisted += (v + m) as u32;
                    } else {
                        report.osv_pypi_persisted += (v + m) as u32;
                    }
                    if let Some(updated) = fetched.updated_state {
                        let mut state = prior_state.unwrap_or_default();
                        state.etag = updated.etag;
                        state.last_modified = updated.last_modified;
                        state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                        state.record_count = (v + m) as i64;
                        intel.put_sync_state(dump.id, &state)?;
                    }
                }
            }
            Err(err) => tracing::warn!(?err, dump = dump.id, "OSV dump fetch failed"),
        }
    }

    // GHSA — best effort; missing `git` binary should not fail the job.
    if let Ok(cache) = packguard_intel::ghsa::default_cache_dir() {
        match packguard_intel::ghsa::sync(&cache, &watched) {
            Ok((vulns, malware, _summary, head)) => {
                let v = intel.persist_vulnerabilities(&vulns)?;
                let m = intel.persist_malware_reports(&malware)?;
                report.ghsa_persisted += (v + m) as u32;
                let mut state = intel.get_sync_state("ghsa")?.unwrap_or_default();
                state.last_commit = Some(head);
                state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                state.record_count = (v + m) as i64;
                intel.put_sync_state("ghsa", &state)?;
            }
            Err(err) => tracing::warn!(?err, "GHSA sync failed"),
        }
    }

    // Typosquat list refresh + scoring.
    refresh_typosquat(intel).await;
    report.typosquat_suspects = score_typosquat(intel, &watched_pairs)?;

    Ok(report)
}

/// Union of every `(ecosystem, name)` pair tracked across every
/// per-project store. Empty when the registry has no projects yet
/// (a fresh install with no scans).
async fn collect_watched(project_stores: &ProjectStoreCache) -> Result<Vec<(String, String)>> {
    let mut acc: BTreeSet<(String, String)> = BTreeSet::new();
    for (slug, _) in project_stores.slug_paths()? {
        let pstore = project_stores.get_or_open(&slug).await?;
        let pstore = pstore.lock().await;
        for pair in pstore.watched_packages()? {
            acc.insert(pair);
        }
    }
    Ok(acc.into_iter().collect())
}

async fn refresh_typosquat(intel: &mut IntelStore) {
    const KIND: &str = "typosquat-pypi-top";
    let prior = intel.get_sync_state(KIND).ok().flatten();
    let cached_at = prior.as_ref().and_then(|s| s.synced_at.clone());
    if let Ok(n) = packguard_intel::typosquat::refresh::refresh_pypi(
        Duration::from_secs(7 * 24 * 3600),
        cached_at.as_deref(),
    )
    .await
    {
        if n > 0 {
            let mut state = prior.unwrap_or_default();
            state.synced_at = Some(chrono::Utc::now().to_rfc3339());
            state.record_count = n as i64;
            let _ = intel.put_sync_state(KIND, &state);
        }
    }
}

fn score_typosquat(intel: &mut IntelStore, watched: &[(String, String)]) -> Result<u32> {
    if watched.is_empty() {
        return Ok(0);
    }
    let npm: HashSet<String> = packguard_intel::typosquat::refresh::load_npm_top()?;
    let pypi: HashSet<String> = packguard_intel::typosquat::refresh::load_pypi_top()?;
    let scorer_npm = packguard_intel::typosquat::Scorer::new(npm);
    let scorer_pypi = packguard_intel::typosquat::Scorer::new(pypi);
    let mut reports = Vec::new();
    for (eco, name) in watched {
        let hit = match eco.as_str() {
            "npm" => scorer_npm.score(name),
            "pypi" => scorer_pypi.score(name),
            _ => None,
        };
        if let Some(h) = hit {
            reports.push(h.into_malware_report(eco));
        }
    }
    let n = reports.len() as u32;
    if n > 0 {
        intel.persist_malware_reports(&reports)?;
    }
    Ok(n)
}
