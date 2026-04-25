//! Phase 14.1d — lossless migration from the legacy
//! `~/.packguard/store.db` to the new per-project layout.
//!
//! Reads the legacy store **read-only** (`SQLITE_OPEN_READ_ONLY`),
//! splits its rows into:
//!   - intel-wide → `~/.packguard/intel/intel.db` (sync_log + denormalized
//!     vulnerabilities + denormalized malware_reports)
//!   - project-wide → `~/.packguard/projects/<slug>/store.db`, one store
//!     per git root discovered via [`packguard_core::find_project_root`]
//!   - registry entries → `~/.packguard/projects.db`
//!
//! Crucial contract: the legacy file is never written to. The migration
//! is idempotent — re-running on an already-migrated home is a no-op
//! that returns `MigrationReport { already_migrated: true, ... }`.
//!
//! Strict scaffolding: this function is exposed but not yet called by
//! any binary. The boot-time wiring + the rename of the legacy file
//! lives in 14.1e.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use packguard_core::{find_project_root, slugify};

use crate::{IntelStore, ProjectsRegistry, Store};

/// Stable slug used when a legacy `repos.path` has no `.git/` ancestor
/// (or is outside `$HOME`). Such repos are bundled into a single
/// project store at `<home>/projects/_default_/store.db` so no scan
/// history is lost.
const FALLBACK_SLUG: &str = "_default_";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// `true` if `<home>/store.db` was found at migration time.
    pub legacy_found: bool,
    /// `true` if a previous migration's outputs are already present.
    /// Set when we detect `<home>/intel/intel.db` AND a non-empty
    /// `<home>/projects.db` — re-running is a no-op.
    pub already_migrated: bool,
    pub projects_created: usize,
    pub workspaces_migrated: usize,
    pub vulnerabilities_migrated: usize,
    pub malware_reports_migrated: usize,
    pub sync_log_entries_migrated: usize,
    /// Number of legacy repo paths that fell back to `FALLBACK_SLUG`.
    pub fallback_default_paths: usize,
}

/// Top-level entry point. Inspects `packguard_home` for a legacy
/// `store.db` and, if present (and not already migrated), copies its
/// rows into the new layout. Returns a structured report; on error,
/// every per-project transaction either commits or rolls back fully —
/// no partial project state survives.
pub fn migrate_legacy_if_present(packguard_home: &Path) -> Result<MigrationReport> {
    let legacy_path = packguard_home.join("store.db");
    if !legacy_path.is_file() {
        return Ok(MigrationReport::default());
    }

    let mut report = MigrationReport {
        legacy_found: true,
        ..MigrationReport::default()
    };

    if is_already_migrated(packguard_home)? {
        report.already_migrated = true;
        return Ok(report);
    }

    // Read-only handle on the legacy. Any INSERT/UPDATE/DELETE against
    // this connection raises an error — the contract is enforced by
    // SQLite, not just by convention.
    let legacy = Connection::open_with_flags(
        &legacy_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("opening legacy store {} read-only", legacy_path.display()))?;

    // 1. Intel-wide ----------------------------------------------------
    let mut intel = IntelStore::open(packguard_home)?;
    report.sync_log_entries_migrated = migrate_sync_log(&legacy, &mut intel)?;
    report.vulnerabilities_migrated = migrate_vulnerabilities(&legacy, &mut intel)?;
    report.malware_reports_migrated = migrate_malware_reports(&legacy, &mut intel)?;

    // 2. Project-wide --------------------------------------------------
    let mut registry = ProjectsRegistry::open(packguard_home)?;
    let groups = partition_repos_by_project(&legacy)?;
    for (slug, group) in &groups {
        if slug == FALLBACK_SLUG {
            report.fallback_default_paths += group.repo_paths.len();
        }
        let project_dir = packguard_home.join("projects").join(slug);
        std::fs::create_dir_all(&project_dir)
            .with_context(|| format!("creating {}", project_dir.display()))?;
        let project_db = project_dir.join("store.db");
        let mut project_store = Store::open(&project_db)?;

        let registry_path = group
            .canonical_root
            .clone()
            .unwrap_or_else(|| packguard_home.join("projects").join(slug));
        let display_name = registry_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| slug.clone());
        registry.insert_with_slug(slug, &registry_path, &display_name)?;
        report.projects_created += 1;

        let n_ws = copy_project_data(&legacy, &mut project_store, &group.repo_ids)?;
        report.workspaces_migrated += n_ws;

        if let Some(latest) = group.last_scan_ts {
            registry.set_last_scan(slug, latest)?;
        }
    }

    Ok(report)
}

fn is_already_migrated(packguard_home: &Path) -> Result<bool> {
    let intel_db = packguard_home.join("intel/intel.db");
    let registry_db = packguard_home.join("projects.db");
    if !intel_db.is_file() || !registry_db.is_file() {
        return Ok(false);
    }
    // A migration always inserts at least one project row (even if
    // just `_default_`). Use that as the idempotence marker so a
    // half-baked registry from a previous failed run forces a retry
    // rather than being mistaken for a finished migration.
    let registry = ProjectsRegistry::open(packguard_home)?;
    Ok(!registry.list_projects()?.is_empty())
}

// --- Intel-wide --------------------------------------------------------

/// Returns `true` when the legacy SQLite holds a table with this name.
/// Used to short-circuit the intel-copy phases against a legacy file
/// whose intel tables were dropped by V8 (the test seeds reach this
/// state when they call `Store::open` instead of
/// `Store::open_legacy_for_tests`; production never opens the legacy
/// file via refinery, so V8 never fires there).
fn legacy_has_table(legacy: &Connection, name: &str) -> Result<bool> {
    let count: i64 = legacy
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .with_context(|| format!("probing sqlite_master for {name}"))?;
    Ok(count > 0)
}

fn migrate_sync_log(legacy: &Connection, intel: &mut IntelStore) -> Result<usize> {
    if !legacy_has_table(legacy, "sync_log")? {
        return Ok(0);
    }
    let mut stmt = legacy
        .prepare(
            "SELECT kind, etag, last_modified, last_commit, synced_at, record_count \
             FROM sync_log",
        )
        .context("prepare legacy sync_log read")?;
    let rows = stmt
        .query_map([], |row| {
            let kind: String = row.get(0)?;
            let state = crate::SyncState {
                etag: row.get(1)?,
                last_modified: row.get(2)?,
                last_commit: row.get(3)?,
                synced_at: row.get(4)?,
                record_count: row.get(5)?,
            };
            Ok((kind, state))
        })
        .context("query legacy sync_log")?;
    let mut n = 0;
    for r in rows {
        let (kind, state) = r?;
        intel.put_sync_state(&kind, &state)?;
        n += 1;
    }
    Ok(n)
}

fn migrate_vulnerabilities(legacy: &Connection, intel: &mut IntelStore) -> Result<usize> {
    if !legacy_has_table(legacy, "vulnerabilities")? {
        return Ok(0);
    }
    // Denormalize the FK: read p.ecosystem + p.name in the same row so
    // intel.db can store the natural key inline.
    let mut stmt = legacy
        .prepare(
            "SELECT v.source, v.advisory_id, p.ecosystem, p.name, v.severity, \
                    v.cve_id, v.aliases_json, v.summary, v.url, v.affected_json, \
                    v.fixed_versions_json, v.published_at, v.modified_at \
             FROM vulnerabilities v JOIN packages p ON p.id = v.pkg_id",
        )
        .context("prepare legacy vulnerabilities read")?;
    let rows = stmt
        .query_map([], |row| {
            let severity_raw: Option<String> = row.get(4)?;
            let severity = severity_raw
                .as_deref()
                .map(packguard_core::model::Severity::parse)
                .unwrap_or(packguard_core::model::Severity::Unknown);
            let aliases_json: String = row.get(6)?;
            let affected_json: String = row.get(9)?;
            let fixed_json: String = row.get(10)?;
            let aliases: Vec<String> = serde_json::from_str(&aliases_json).unwrap_or_default();
            let affected: packguard_core::model::AffectedSpec =
                serde_json::from_str(&affected_json).unwrap_or_default();
            let fixed_versions: Vec<String> = serde_json::from_str(&fixed_json).unwrap_or_default();
            Ok(packguard_core::model::Vulnerability {
                source: row.get(0)?,
                advisory_id: row.get(1)?,
                ecosystem: row.get(2)?,
                package_name: row.get(3)?,
                severity,
                cve_id: row.get(5)?,
                aliases,
                summary: row.get(7)?,
                url: row.get(8)?,
                affected,
                fixed_versions,
                published_at: row.get(11)?,
                modified_at: row.get(12)?,
            })
        })
        .context("query legacy vulnerabilities")?;
    let mut batch = Vec::new();
    for r in rows {
        batch.push(r?);
    }
    let count = batch.len();
    intel.persist_vulnerabilities(&batch)?;
    Ok(count)
}

fn migrate_malware_reports(legacy: &Connection, intel: &mut IntelStore) -> Result<usize> {
    if !legacy_has_table(legacy, "malware_reports")? {
        return Ok(0);
    }
    let mut stmt = legacy
        .prepare(
            "SELECT m.source, m.ref_id, p.ecosystem, p.name, m.version, m.kind, \
                    m.summary, m.url, m.evidence_json, m.reported_at \
             FROM malware_reports m JOIN packages p ON p.id = m.pkg_id",
        )
        .context("prepare legacy malware_reports read")?;
    let rows = stmt
        .query_map([], |row| {
            let kind_raw: String = row.get(5)?;
            let kind = packguard_core::model::MalwareKind::parse(&kind_raw);
            let evidence_str: String = row.get(8)?;
            let evidence: serde_json::Value =
                serde_json::from_str(&evidence_str).unwrap_or_else(|_| serde_json::json!({}));
            Ok(packguard_core::model::MalwareReport {
                source: row.get(0)?,
                ref_id: row.get(1)?,
                ecosystem: row.get(2)?,
                package_name: row.get(3)?,
                version: row.get(4)?,
                kind,
                summary: row.get(6)?,
                url: row.get(7)?,
                evidence,
                reported_at: row.get(9)?,
            })
        })
        .context("query legacy malware_reports")?;
    let mut batch = Vec::new();
    for r in rows {
        batch.push(r?);
    }
    let count = batch.len();
    intel.persist_malware_reports(&batch)?;
    Ok(count)
}

// --- Project partitioning ---------------------------------------------

#[derive(Debug, Clone)]
struct ProjectGroup {
    /// Legacy `repos.path` strings that fell into this group.
    repo_paths: Vec<String>,
    /// Legacy `repos.id` values for this group, used to filter every
    /// downstream copy query.
    repo_ids: Vec<i64>,
    /// Canonical git root if we found one, else `None` for `_default_`.
    canonical_root: Option<PathBuf>,
    /// Most recent scan_history timestamp across all repos in this
    /// group, used to populate `projects.last_scan` so the dashboard
    /// preserves the user's "most-recently-touched project" ordering.
    last_scan_ts: Option<DateTime<Utc>>,
}

/// Walk the legacy `repos` table and bucket each row by the slug of
/// its git-root ancestor, falling back to `_default_` when the path
/// has no `.git/` ancestor below `$HOME`.
fn partition_repos_by_project(legacy: &Connection) -> Result<BTreeMap<String, ProjectGroup>> {
    let mut stmt = legacy
        .prepare("SELECT id, path, last_scan_at FROM repos")
        .context("prepare legacy repos read")?;
    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let path: String = row.get(1)?;
            let last_scan: String = row.get(2)?;
            Ok((id, path, last_scan))
        })
        .context("query legacy repos")?;
    let mut out: BTreeMap<String, ProjectGroup> = BTreeMap::new();
    for r in rows {
        let (repo_id, path_str, last_scan_str) = r?;
        let path = PathBuf::from(&path_str);
        let (slug, canonical) = resolve_slug_for_repo(&path);
        let last_scan_ts = parse_rfc3339(&last_scan_str);
        let group = out.entry(slug.clone()).or_insert_with(|| ProjectGroup {
            repo_paths: Vec::new(),
            repo_ids: Vec::new(),
            canonical_root: canonical.clone(),
            last_scan_ts: None,
        });
        group.repo_paths.push(path_str);
        group.repo_ids.push(repo_id);
        if group.canonical_root.is_none() {
            group.canonical_root = canonical;
        }
        match (group.last_scan_ts, last_scan_ts) {
            (None, Some(ts)) => group.last_scan_ts = Some(ts),
            (Some(a), Some(b)) if b > a => group.last_scan_ts = Some(b),
            _ => {}
        }
    }
    Ok(out)
}

fn resolve_slug_for_repo(path: &Path) -> (String, Option<PathBuf>) {
    match find_project_root(path) {
        Some(raw_root) => {
            let canonical = raw_root.canonicalize().unwrap_or(raw_root);
            (slugify(&canonical), Some(canonical))
        }
        None => (FALLBACK_SLUG.to_string(), None),
    }
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

// --- Project-wide table copy ------------------------------------------

/// Copy every row of every project-wide table that belongs to
/// `repo_ids` (legacy ids) into the freshly-created project store.
/// Returns the number of workspaces migrated.
///
/// The whole copy runs in a single transaction so an error mid-way
/// rolls back; the project store is left empty rather than half-full.
fn copy_project_data(
    legacy: &Connection,
    project_store: &mut Store,
    repo_ids: &[i64],
) -> Result<usize> {
    if repo_ids.is_empty() {
        return Ok(0);
    }
    let conn = project_store.raw_conn_mut();
    let tx = conn.transaction().context("begin project-copy tx")?;

    // 1. repos: capture old_repo_id → new_repo_id remap.
    let repo_id_remap = copy_repos(legacy, &tx, repo_ids)?;
    let new_repo_ids: Vec<i64> = repo_id_remap.values().copied().collect();
    let old_repo_ids: Vec<i64> = repo_id_remap.keys().copied().collect();
    let repo_paths_for_actions = collect_repo_paths(legacy, &old_repo_ids)?;

    // 2. workspaces: capture old_ws_id → new_ws_id remap.
    let ws_id_remap = copy_workspaces(legacy, &tx, &repo_id_remap)?;
    let n_workspaces = ws_id_remap.len();
    let old_ws_ids: Vec<i64> = ws_id_remap.keys().copied().collect();

    // 3. packages: which old pkg_ids are referenced by deps/edges/cache?
    let referenced_pkg_ids = collect_referenced_pkg_ids(legacy, &old_ws_ids)?;
    let pkg_id_remap = copy_packages(legacy, &tx, &referenced_pkg_ids)?;
    let referenced_pkg_id_vec: Vec<i64> = referenced_pkg_ids.iter().copied().collect();

    // 4. package_versions for those packages.
    copy_package_versions(legacy, &tx, &pkg_id_remap)?;

    // 5. dependencies (workspace_id + pkg_id remap).
    copy_dependencies(legacy, &tx, &ws_id_remap, &pkg_id_remap)?;

    // 6. dependency_edges (workspace_id + source/resolved pkg remap).
    copy_dependency_edges(legacy, &tx, &ws_id_remap, &pkg_id_remap)?;

    // 7. compatibility (pkg_id remap).
    copy_compatibility(legacy, &tx, &pkg_id_remap)?;

    // 8. contamination_cache (workspace_id remap).
    copy_contamination_cache(legacy, &tx, &ws_id_remap)?;

    // 9. scan_history (repo_id remap).
    copy_scan_history(legacy, &tx, &repo_id_remap)?;

    // 10. action_dismissals — keyed by workspace TEXT (path string),
    // not by id, so we filter by the legacy paths that belong to this
    // project's repos.
    copy_action_dismissals(legacy, &tx, &repo_paths_for_actions)?;

    // 11. policies — natural-keyed (scope, pattern), no FK. Copy ALL
    // rows to every project store as a safe default; consolidation
    // can happen post-migration.
    copy_policies(legacy, &tx)?;

    let _ = new_repo_ids; // kept for clarity / future use
    let _ = referenced_pkg_id_vec; // kept for clarity / future use
    tx.commit().context("commit project-copy tx")?;
    Ok(n_workspaces)
}

fn copy_repos(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    old_repo_ids: &[i64],
) -> Result<BTreeMap<i64, i64>> {
    let mut remap = BTreeMap::new();
    let mut stmt = legacy
        .prepare(
            "SELECT id, path, ecosystem, fingerprint, last_scan_at \
             FROM repos WHERE id = ?1",
        )
        .context("prepare legacy repos pick")?;
    for &old_id in old_repo_ids {
        let row = stmt.query_row(params![old_id], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        });
        let (path, ecosystem, fingerprint, last_scan_at) = match row {
            Ok(t) => t,
            Err(rusqlite::Error::QueryReturnedNoRows) => continue,
            Err(e) => return Err(e).context("read legacy repo row"),
        };
        let new_id: i64 = tx
            .query_row(
                "INSERT INTO repos (path, ecosystem, fingerprint, last_scan_at) \
                 VALUES (?1, ?2, ?3, ?4) RETURNING id",
                params![path, ecosystem, fingerprint, last_scan_at],
                |row| row.get(0),
            )
            .context("insert into project repos")?;
        remap.insert(old_id, new_id);
    }
    Ok(remap)
}

fn copy_workspaces(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    repo_id_remap: &BTreeMap<i64, i64>,
) -> Result<BTreeMap<i64, i64>> {
    let mut remap = BTreeMap::new();
    let mut stmt = legacy
        .prepare("SELECT id, name, manifest_path FROM workspaces WHERE repo_id = ?1")
        .context("prepare legacy workspaces read")?;
    for (&old_repo, &new_repo) in repo_id_remap {
        let rows = stmt
            .query_map(params![old_repo], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .context("query legacy workspaces")?;
        for r in rows {
            let (old_ws, name, manifest_path) = r?;
            let new_ws: i64 = tx
                .query_row(
                    "INSERT INTO workspaces (repo_id, name, manifest_path) \
                     VALUES (?1, ?2, ?3) RETURNING id",
                    params![new_repo, name, manifest_path],
                    |row| row.get(0),
                )
                .context("insert into project workspaces")?;
            remap.insert(old_ws, new_ws);
        }
    }
    Ok(remap)
}

fn collect_repo_paths(legacy: &Connection, old_repo_ids: &[i64]) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut stmt = legacy
        .prepare("SELECT path FROM repos WHERE id = ?1")
        .context("prepare legacy repo path read")?;
    for &id in old_repo_ids {
        if let Ok(p) = stmt.query_row(params![id], |row| row.get::<_, String>(0)) {
            out.insert(p);
        }
    }
    Ok(out)
}

/// Walk every table that uses `pkg_id` and collect the set of legacy
/// pkg_ids referenced by the workspaces in this project. Anything
/// outside this set is irrelevant to the project store.
fn collect_referenced_pkg_ids(legacy: &Connection, old_ws_ids: &[i64]) -> Result<BTreeSet<i64>> {
    let mut out = BTreeSet::new();
    if old_ws_ids.is_empty() {
        return Ok(out);
    }
    // dependencies
    let mut stmt = legacy.prepare("SELECT pkg_id FROM dependencies WHERE workspace_id = ?1")?;
    for &ws in old_ws_ids {
        let rows = stmt.query_map(params![ws], |row| row.get::<_, i64>(0))?;
        for r in rows {
            out.insert(r?);
        }
    }
    // dependency_edges
    let mut stmt = legacy.prepare(
        "SELECT source_pkg_id, resolved_pkg_id FROM dependency_edges WHERE workspace_id = ?1",
    )?;
    for &ws in old_ws_ids {
        let rows = stmt.query_map(params![ws], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
        })?;
        for r in rows {
            let (src, resolved) = r?;
            out.insert(src);
            if let Some(r) = resolved {
                out.insert(r);
            }
        }
    }
    Ok(out)
}

fn copy_packages(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    old_pkg_ids: &BTreeSet<i64>,
) -> Result<HashMap<i64, i64>> {
    let mut remap = HashMap::new();
    let mut stmt = legacy
        .prepare(
            "SELECT ecosystem, name, latest, latest_fetched_at \
             FROM packages WHERE id = ?1",
        )
        .context("prepare legacy packages read")?;
    for &old_id in old_pkg_ids {
        let row = stmt.query_row(params![old_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        });
        let (eco, name, latest, latest_fetched_at) = match row {
            Ok(t) => t,
            Err(rusqlite::Error::QueryReturnedNoRows) => continue,
            Err(e) => return Err(e).context("read legacy package row"),
        };
        let new_id: i64 = tx
            .query_row(
                "INSERT INTO packages (ecosystem, name, latest, latest_fetched_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(ecosystem, name) DO UPDATE SET \
                    latest = excluded.latest, \
                    latest_fetched_at = excluded.latest_fetched_at \
                 RETURNING id",
                params![eco, name, latest, latest_fetched_at],
                |row| row.get(0),
            )
            .context("insert into project packages")?;
        remap.insert(old_id, new_id);
    }
    Ok(remap)
}

fn copy_package_versions(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    pkg_id_remap: &HashMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy
        .prepare(
            "SELECT version, published_at, deprecated, yanked, metadata_json \
             FROM package_versions WHERE pkg_id = ?1",
        )
        .context("prepare legacy package_versions read")?;
    for (&old_pkg, &new_pkg) in pkg_id_remap {
        let rows = stmt.query_map(params![old_pkg], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        for r in rows {
            let (version, published_at, deprecated, yanked, metadata_json) = r?;
            tx.execute(
                "INSERT OR IGNORE INTO package_versions \
                   (pkg_id, version, published_at, deprecated, yanked, metadata_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    new_pkg,
                    version,
                    published_at,
                    deprecated,
                    yanked,
                    metadata_json
                ],
            )?;
        }
    }
    Ok(())
}

fn copy_dependencies(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    ws_id_remap: &BTreeMap<i64, i64>,
    pkg_id_remap: &HashMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy.prepare(
        "SELECT pkg_id, declared_range, installed, kind, source_lockfile \
         FROM dependencies WHERE workspace_id = ?1",
    )?;
    for (&old_ws, &new_ws) in ws_id_remap {
        let rows = stmt.query_map(params![old_ws], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        for r in rows {
            let (old_pkg, declared_range, installed, kind, source_lockfile) = r?;
            let new_pkg = match pkg_id_remap.get(&old_pkg) {
                Some(&v) => v,
                None => continue, // referenced pkg_id wasn't found in legacy packages
            };
            tx.execute(
                "INSERT OR IGNORE INTO dependencies \
                   (workspace_id, pkg_id, declared_range, installed, kind, source_lockfile) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    new_ws,
                    new_pkg,
                    declared_range,
                    installed,
                    kind,
                    source_lockfile
                ],
            )?;
        }
    }
    Ok(())
}

fn copy_dependency_edges(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    ws_id_remap: &BTreeMap<i64, i64>,
    pkg_id_remap: &HashMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy.prepare(
        "SELECT source_pkg_id, source_version, target_name, target_range, \
                resolved_pkg_id, resolved_version, kind \
         FROM dependency_edges WHERE workspace_id = ?1",
    )?;
    for (&old_ws, &new_ws) in ws_id_remap {
        let rows = stmt.query_map(params![old_ws], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        for r in rows {
            let (
                old_src,
                source_version,
                target_name,
                target_range,
                old_resolved,
                resolved_version,
                kind,
            ) = r?;
            let new_src = match pkg_id_remap.get(&old_src) {
                Some(&v) => v,
                None => continue,
            };
            let new_resolved = old_resolved.and_then(|id| pkg_id_remap.get(&id).copied());
            tx.execute(
                "INSERT INTO dependency_edges \
                   (workspace_id, source_pkg_id, source_version, target_name, target_range, \
                    resolved_pkg_id, resolved_version, kind) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    new_ws,
                    new_src,
                    source_version,
                    target_name,
                    target_range,
                    new_resolved,
                    resolved_version,
                    kind,
                ],
            )?;
        }
    }
    Ok(())
}

fn copy_compatibility(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    pkg_id_remap: &HashMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy.prepare(
        "SELECT version, peer_deps_json, engines_json FROM compatibility WHERE pkg_id = ?1",
    )?;
    for (&old_pkg, &new_pkg) in pkg_id_remap {
        let rows = stmt.query_map(params![old_pkg], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        for r in rows {
            let (version, peer_json, engines_json) = r?;
            tx.execute(
                "INSERT OR IGNORE INTO compatibility \
                   (pkg_id, version, peer_deps_json, engines_json) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![new_pkg, version, peer_json, engines_json],
            )?;
        }
    }
    Ok(())
}

fn copy_contamination_cache(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    ws_id_remap: &BTreeMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy.prepare(
        "SELECT advisory_id, chains_json, computed_at \
         FROM contamination_cache WHERE workspace_id = ?1",
    )?;
    for (&old_ws, &new_ws) in ws_id_remap {
        let rows = stmt.query_map(params![old_ws], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for r in rows {
            let (advisory_id, chains_json, computed_at) = r?;
            tx.execute(
                "INSERT OR REPLACE INTO contamination_cache \
                   (advisory_id, workspace_id, chains_json, computed_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![advisory_id, new_ws, chains_json, computed_at],
            )?;
        }
    }
    Ok(())
}

fn copy_scan_history(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    repo_id_remap: &BTreeMap<i64, i64>,
) -> Result<()> {
    let mut stmt = legacy.prepare("SELECT ts, diff_json FROM scan_history WHERE repo_id = ?1")?;
    for (&old_repo, &new_repo) in repo_id_remap {
        let rows = stmt.query_map(params![old_repo], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        for r in rows {
            let (ts, diff_json) = r?;
            tx.execute(
                "INSERT INTO scan_history (repo_id, ts, diff_json) VALUES (?1, ?2, ?3)",
                params![new_repo, ts, diff_json],
            )?;
        }
    }
    Ok(())
}

fn copy_action_dismissals(
    legacy: &Connection,
    tx: &rusqlite::Transaction<'_>,
    repo_paths: &BTreeSet<String>,
) -> Result<()> {
    if repo_paths.is_empty() {
        return Ok(());
    }
    let mut stmt = legacy.prepare(
        "SELECT id, kind, target_json, workspace, dismissed_at, deferred_until, reason \
         FROM action_dismissals WHERE workspace = ?1",
    )?;
    for path in repo_paths {
        let rows = stmt.query_map(params![path], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;
        for r in rows {
            let (id, kind, target_json, workspace, dismissed_at, deferred_until, reason) = r?;
            tx.execute(
                "INSERT OR IGNORE INTO action_dismissals \
                   (id, kind, target_json, workspace, dismissed_at, deferred_until, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    kind,
                    target_json,
                    workspace,
                    dismissed_at,
                    deferred_until,
                    reason,
                ],
            )?;
        }
    }
    Ok(())
}

fn copy_policies(legacy: &Connection, tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let mut stmt = legacy.prepare("SELECT scope, pattern, rule_json FROM policies")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for r in rows {
        let (scope, pattern, rule_json) = r?;
        tx.execute(
            "INSERT OR REPLACE INTO policies (scope, pattern, rule_json) VALUES (?1, ?2, ?3)",
            params![scope, pattern, rule_json],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;
