//! Headless sync orchestration. Mirrors `packguard sync` minus terminal
//! rendering. Runs OSV npm + PyPI dumps + GHSA git pull + typosquat list
//! refresh. Returns a `SyncReport` for the dashboard to display.

use crate::dto::SyncReport;
use anyhow::Result;
use packguard_intel::WatchedPackages;
use packguard_store::Store;
use std::collections::HashSet;
use std::time::Duration;

pub async fn run(store: &mut Store) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    let watched_pairs = store.watched_packages()?;
    let watched: WatchedPackages = Some(watched_pairs.into_iter().collect());

    for dump in [&packguard_intel::osv::NPM, &packguard_intel::osv::PYPI] {
        let prior_state = store.get_sync_state(dump.id)?;
        let prior = packguard_intel::osv::PriorSyncState {
            etag: prior_state.as_ref().and_then(|s| s.etag.clone()),
            last_modified: prior_state.as_ref().and_then(|s| s.last_modified.clone()),
        };
        match packguard_intel::osv::fetch_dump(dump, &prior, &watched).await {
            Ok(fetched) => {
                if !fetched.summary.skipped_not_modified {
                    let v = store.persist_vulnerabilities(&fetched.vulnerabilities)?;
                    let m = store.persist_malware_reports(&fetched.malware_reports)?;
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
                        store.put_sync_state(dump.id, &state)?;
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
                let v = store.persist_vulnerabilities(&vulns)?;
                let m = store.persist_malware_reports(&malware)?;
                report.ghsa_persisted += (v + m) as u32;
                let mut state = store.get_sync_state("ghsa")?.unwrap_or_default();
                state.last_commit = Some(head);
                state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                state.record_count = (v + m) as i64;
                store.put_sync_state("ghsa", &state)?;
            }
            Err(err) => tracing::warn!(?err, "GHSA sync failed"),
        }
    }

    // Typosquat list refresh + scoring.
    refresh_typosquat(store).await;
    report.typosquat_suspects = score_typosquat(store)?;

    Ok(report)
}

async fn refresh_typosquat(store: &mut Store) {
    const KIND: &str = "typosquat-pypi-top";
    let prior = store.get_sync_state(KIND).ok().flatten();
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
            let _ = store.put_sync_state(KIND, &state);
        }
    }
}

fn score_typosquat(store: &mut Store) -> Result<u32> {
    let watched = store.watched_packages()?;
    if watched.is_empty() {
        return Ok(0);
    }
    let npm: HashSet<String> = packguard_intel::typosquat::refresh::load_npm_top()?;
    let pypi: HashSet<String> = packguard_intel::typosquat::refresh::load_pypi_top()?;
    let scorer_npm = packguard_intel::typosquat::Scorer::new(npm);
    let scorer_pypi = packguard_intel::typosquat::Scorer::new(pypi);
    let mut reports = Vec::new();
    for (eco, name) in &watched {
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
        store.persist_malware_reports(&reports)?;
    }
    Ok(n)
}
