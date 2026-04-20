//! PackGuard SQLite store — persistence layer for scan results (and, later,
//! vuln intel and policy evaluations).
//!
//! Schema is versioned with refinery (`migrations/VNN__*.sql`). WAL mode is
//! enabled on every connection so scans and UI reads can happen concurrently.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use packguard_core::model::{
    AffectedSpec, DepKind, MalwareKind, MalwareReport, Project, RemotePackage, Severity,
    Vulnerability,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod embedded {
    refinery::embed_migrations!("migrations");
}

pub struct Store {
    conn: Connection,
}

/// Outcome of a single project save — small stats that the CLI can print
/// and the scan_history row already encodes as JSON.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SaveStats {
    pub packages: usize,
    pub dependencies: usize,
    pub updated_latest: usize,
    pub persisted_versions: usize,
}

/// One `package_versions` row as read back by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVersion {
    pub version: String,
    pub published_at: Option<String>,
    pub deprecated: bool,
    pub yanked: bool,
}

/// One vulnerability row with pkg info attached, as returned to the
/// matching engine / CLI audit.
#[derive(Debug, Clone)]
pub struct StoredVulnerability {
    pub source: String,
    pub advisory_id: String,
    pub ecosystem: String,
    pub package_name: String,
    pub severity: Severity,
    pub cve_id: Option<String>,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub affected: AffectedSpec,
    pub fixed_versions: Vec<String>,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
    pub fetched_at: String,
}

/// One `malware_reports` row as read back by the matcher / CLI audit.
#[derive(Debug, Clone)]
pub struct StoredMalware {
    pub source: String,
    pub ref_id: String,
    pub ecosystem: String,
    pub package_name: String,
    pub version: Option<String>,
    pub kind: MalwareKind,
    pub summary: Option<String>,
    pub url: Option<String>,
    pub evidence: serde_json::Value,
    pub reported_at: Option<String>,
    pub fetched_at: String,
}

/// State of a remote intel source — consulted before the next sync pass to
/// skip untouched dumps (ETag / Last-Modified / git commit).
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_commit: Option<String>,
    pub synced_at: Option<String>,
    pub record_count: i64,
}

/// A full dependency row as read back from the store, in display-friendly form.
#[derive(Debug, Clone)]
pub struct StoredDependency {
    pub ecosystem: String,
    pub repo_path: PathBuf,
    pub workspace_name: Option<String>,
    pub manifest_path: PathBuf,
    pub name: String,
    pub declared_range: String,
    pub installed: Option<String>,
    pub kind: DepKind,
    pub source_lockfile: Option<String>,
    pub latest: Option<String>,
    pub latest_published_at: Option<String>,
}

impl Store {
    /// Open (or create) a store at `path`, running migrations to the latest
    /// schema. Parent directories are created as needed.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut conn =
            Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys")?;
        embedded::migrations::runner()
            .run(&mut conn)
            .context("running migrations")?;
        Ok(Self { conn })
    }

    /// Open an in-memory store (tests). Migrations run at open time.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory().context("opening in-memory SQLite")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys")?;
        embedded::migrations::runner()
            .run(&mut conn)
            .context("running migrations")?;
        Ok(Self { conn })
    }

    /// Returns the stored fingerprint for this (path, ecosystem), if any.
    pub fn last_fingerprint(&self, path: &Path, ecosystem: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT fingerprint FROM repos WHERE path = ?1 AND ecosystem = ?2",
                params![path.display().to_string(), ecosystem],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("reading repo fingerprint")
    }

    /// Persist a project + its registry snapshot. Replaces all dependencies
    /// attached to the matching workspace, upserts package rows, writes a
    /// scan_history row, and bumps the repo fingerprint.
    pub fn save_project(
        &mut self,
        repo_path: &Path,
        project: &Project,
        remotes: &BTreeMap<String, RemotePackage>,
        fingerprint: &str,
    ) -> Result<SaveStats> {
        let now = Utc::now();
        let tx = self
            .conn
            .transaction()
            .context("beginning save_project tx")?;

        let repo_id = upsert_repo(&tx, repo_path, project.ecosystem, fingerprint, now)?;
        let workspace_id = upsert_workspace(
            &tx,
            repo_id,
            project.name.as_deref(),
            &project.manifest_path,
        )?;

        // Fresh dep rows for this workspace.
        tx.execute(
            "DELETE FROM dependencies WHERE workspace_id = ?1",
            params![workspace_id],
        )
        .context("clearing previous dependencies")?;

        let mut stats = SaveStats::default();
        for dep in &project.dependencies {
            let pkg_id = upsert_package(&tx, project.ecosystem, &dep.name)?;
            stats.packages += 1;

            if let Some(remote) = remotes.get(&dep.name) {
                if update_package_latest(&tx, pkg_id, remote, now)? {
                    stats.updated_latest += 1;
                }
                if remote.versions.is_empty() {
                    // Fall back to the single `latest` entry when the registry
                    // client didn't surface a history (older code paths, tests).
                    if let (Some(v), published_at) = (&remote.latest, &remote.latest_published_at) {
                        upsert_package_version(
                            &tx,
                            pkg_id,
                            v,
                            published_at.as_deref(),
                            false,
                            false,
                        )?;
                        stats.persisted_versions += 1;
                    }
                } else {
                    for v in &remote.versions {
                        upsert_package_version(
                            &tx,
                            pkg_id,
                            &v.version,
                            v.published_at.as_deref(),
                            v.deprecated,
                            v.yanked,
                        )?;
                        stats.persisted_versions += 1;
                    }
                }
            }

            tx.execute(
                "INSERT INTO dependencies \
                   (workspace_id, pkg_id, declared_range, installed, kind, source_lockfile) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    workspace_id,
                    pkg_id,
                    dep.declared_range,
                    dep.installed,
                    kind_label(dep.kind),
                    dep.source_lockfile,
                ],
            )
            .context("inserting dependency")?;
            stats.dependencies += 1;
        }

        let diff = serde_json::to_string(&stats).context("serializing scan diff")?;
        tx.execute(
            "INSERT INTO scan_history (repo_id, ts, diff_json) VALUES (?1, ?2, ?3)",
            params![repo_id, now.to_rfc3339(), diff],
        )
        .context("writing scan_history row")?;

        tx.commit().context("committing save_project")?;
        Ok(stats)
    }

    /// Read the full version history persisted for `(ecosystem, name)`. Rows
    /// are returned in ascending published_at order (nulls first) so callers
    /// can pick a dialect-aware comparator without another sort pass.
    pub fn load_package_versions(&self, ecosystem: &str, name: &str) -> Result<Vec<StoredVersion>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT pv.version, pv.published_at, pv.deprecated, pv.yanked \
                 FROM package_versions pv \
                 JOIN packages p ON p.id = pv.pkg_id \
                 WHERE p.ecosystem = ?1 AND p.name = ?2 \
                 ORDER BY pv.published_at",
            )
            .context("preparing load_package_versions")?;
        let rows = stmt
            .query_map(params![ecosystem, name], |row| {
                Ok(StoredVersion {
                    version: row.get(0)?,
                    published_at: row.get(1)?,
                    deprecated: row.get::<_, i64>(2)? != 0,
                    yanked: row.get::<_, i64>(3)? != 0,
                })
            })
            .context("querying package_versions")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Read every dependency row stored for the given repo_path across all
    /// workspaces and ecosystems. Used by the `report` command.
    pub fn load_repo_dependencies(&self, repo_path: &Path) -> Result<Vec<StoredDependency>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.ecosystem, r.path, w.name, w.manifest_path, p.name, \
                        d.declared_range, d.installed, d.kind, d.source_lockfile, \
                        p.latest, pv.published_at \
                 FROM dependencies d \
                 JOIN workspaces w ON w.id = d.workspace_id \
                 JOIN repos r ON r.id = w.repo_id \
                 JOIN packages p ON p.id = d.pkg_id \
                 LEFT JOIN package_versions pv ON pv.pkg_id = p.id AND pv.version = p.latest \
                 WHERE r.path = ?1 \
                 ORDER BY r.ecosystem, w.name, p.name",
            )
            .context("preparing load_repo_dependencies")?;
        let rows = stmt
            .query_map(params![repo_path.display().to_string()], |row| {
                Ok(StoredDependency {
                    ecosystem: row.get(0)?,
                    repo_path: PathBuf::from(row.get::<_, String>(1)?),
                    workspace_name: row.get(2)?,
                    manifest_path: PathBuf::from(row.get::<_, String>(3)?),
                    name: row.get(4)?,
                    declared_range: row.get(5)?,
                    installed: row.get(6)?,
                    kind: kind_from_label(&row.get::<_, String>(7)?),
                    source_lockfile: row.get(8)?,
                    latest: row.get(9)?,
                    latest_published_at: row.get(10)?,
                })
            })
            .context("querying dependencies")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Upsert a batch of vulnerabilities into the store. The pkg_id is
    /// resolved for each advisory by `(ecosystem, package_name)`; unknown
    /// packages are created with a `latest` of NULL so the FK resolves but
    /// they're still flagged as "no registry history seen yet" — a
    /// subsequent `scan` will fill that in.
    ///
    /// Returns the number of rows inserted/updated. Idempotent on re-runs
    /// (unique key = `(source, advisory_id, pkg_id)`).
    pub fn persist_vulnerabilities(&mut self, vulns: &[Vulnerability]) -> Result<usize> {
        if vulns.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction().context("begin vuln tx")?;
        let mut count = 0usize;
        for v in vulns {
            let pkg_id = upsert_package(&tx, &v.ecosystem, &v.package_name)?;
            let aliases_json = serde_json::to_string(&v.aliases).context("serializing aliases")?;
            let affected_json =
                serde_json::to_string(&v.affected).context("serializing affected spec")?;
            let fixed_json =
                serde_json::to_string(&v.fixed_versions).context("serializing fixed_versions")?;
            let severity = if matches!(v.severity, Severity::Unknown) {
                None
            } else {
                Some(v.severity.as_str().to_string())
            };
            tx.execute(
                "INSERT INTO vulnerabilities \
                   (source, advisory_id, pkg_id, severity, cve_id, aliases_json, \
                    summary, url, affected_json, fixed_versions_json, \
                    published_at, modified_at, fetched_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
                 ON CONFLICT(source, advisory_id, pkg_id) DO UPDATE SET \
                    severity = excluded.severity, \
                    cve_id = excluded.cve_id, \
                    aliases_json = excluded.aliases_json, \
                    summary = excluded.summary, \
                    url = excluded.url, \
                    affected_json = excluded.affected_json, \
                    fixed_versions_json = excluded.fixed_versions_json, \
                    published_at = excluded.published_at, \
                    modified_at = excluded.modified_at, \
                    fetched_at = excluded.fetched_at",
                params![
                    v.source,
                    v.advisory_id,
                    pkg_id,
                    severity,
                    v.cve_id,
                    aliases_json,
                    v.summary,
                    v.url,
                    affected_json,
                    fixed_json,
                    v.published_at,
                    v.modified_at,
                    now,
                ],
            )
            .context("upsert vulnerability")?;
            count += 1;
        }
        tx.commit().context("commit vuln tx")?;
        Ok(count)
    }

    /// Load every advisory the store has for `(ecosystem, package_name)`.
    /// The matching engine filters further by version.
    pub fn load_vulnerabilities(
        &self,
        ecosystem: &str,
        name: &str,
    ) -> Result<Vec<StoredVulnerability>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.source, v.advisory_id, p.ecosystem, p.name, v.severity, \
                        v.cve_id, v.aliases_json, v.summary, v.url, v.affected_json, \
                        v.fixed_versions_json, v.published_at, v.modified_at, v.fetched_at \
                 FROM vulnerabilities v \
                 JOIN packages p ON p.id = v.pkg_id \
                 WHERE p.ecosystem = ?1 AND p.name = ?2",
            )
            .context("prepare load_vulnerabilities")?;
        let rows = stmt
            .query_map(params![ecosystem, name], read_stored_vulnerability)
            .context("query vulnerabilities")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Dump every advisory in the store grouped by `(ecosystem, package)` —
    /// used by `packguard audit` to stream the last scan's vulns without
    /// re-querying per dep.
    pub fn load_all_vulnerabilities(&self) -> Result<Vec<StoredVulnerability>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.source, v.advisory_id, p.ecosystem, p.name, v.severity, \
                        v.cve_id, v.aliases_json, v.summary, v.url, v.affected_json, \
                        v.fixed_versions_json, v.published_at, v.modified_at, v.fetched_at \
                 FROM vulnerabilities v \
                 JOIN packages p ON p.id = v.pkg_id \
                 ORDER BY p.ecosystem, p.name, v.advisory_id",
            )
            .context("prepare load_all_vulnerabilities")?;
        let rows = stmt
            .query_map([], read_stored_vulnerability)
            .context("query all vulnerabilities")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Every `(ecosystem, name)` pair currently tracked in `packages`. Used
    /// by `packguard sync` to filter OSV/GHSA advisories to what we actually
    /// care about — the full dumps contain hundreds of thousands of entries
    /// most users don't need.
    pub fn watched_packages(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ecosystem, name FROM packages")
            .context("prepare watched_packages")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .context("query watched_packages")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Total advisory count — cheap enough to call for the CLI status line.
    pub fn count_vulnerabilities(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
            .context("count vulnerabilities")
    }

    /// Bulk-upsert malware/typosquat findings. Idempotent on
    /// `(source, ref_id, pkg_id, version)`; the package row is auto-created
    /// when absent. Returns the number of rows touched.
    pub fn persist_malware_reports(&mut self, reports: &[MalwareReport]) -> Result<usize> {
        if reports.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction().context("begin malware tx")?;
        let mut count = 0usize;
        for r in reports {
            let pkg_id = upsert_package(&tx, &r.ecosystem, &r.package_name)?;
            let evidence_str =
                serde_json::to_string(&r.evidence).context("serializing malware evidence")?;
            tx.execute(
                "INSERT INTO malware_reports \
                   (source, ref_id, pkg_id, version, kind, summary, url, evidence_json, \
                    reported_at, fetched_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(source, ref_id, pkg_id, version) DO UPDATE SET \
                    kind = excluded.kind, \
                    summary = excluded.summary, \
                    url = excluded.url, \
                    evidence_json = excluded.evidence_json, \
                    reported_at = excluded.reported_at, \
                    fetched_at = excluded.fetched_at",
                params![
                    r.source,
                    r.ref_id,
                    pkg_id,
                    r.version,
                    r.kind.as_str(),
                    r.summary,
                    r.url,
                    evidence_str,
                    r.reported_at,
                    now,
                ],
            )
            .context("upsert malware_report")?;
            count += 1;
        }
        tx.commit().context("commit malware tx")?;
        Ok(count)
    }

    /// Load malware/typosquat reports for `(ecosystem, package_name)`.
    /// Returns rows in insertion order so callers can prefer the earliest
    /// source in case of ties.
    pub fn load_malware_reports(&self, ecosystem: &str, name: &str) -> Result<Vec<StoredMalware>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.source, m.ref_id, p.ecosystem, p.name, m.version, m.kind, \
                        m.summary, m.url, m.evidence_json, m.reported_at, m.fetched_at \
                 FROM malware_reports m \
                 JOIN packages p ON p.id = m.pkg_id \
                 WHERE p.ecosystem = ?1 AND p.name = ?2 \
                 ORDER BY m.id",
            )
            .context("prepare load_malware_reports")?;
        let rows = stmt
            .query_map(params![ecosystem, name], read_stored_malware)
            .context("query malware_reports")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Dump every malware report — used by `audit --focus malware|typosquat`.
    pub fn load_all_malware_reports(&self) -> Result<Vec<StoredMalware>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.source, m.ref_id, p.ecosystem, p.name, m.version, m.kind, \
                        m.summary, m.url, m.evidence_json, m.reported_at, m.fetched_at \
                 FROM malware_reports m \
                 JOIN packages p ON p.id = m.pkg_id \
                 ORDER BY p.ecosystem, p.name, m.id",
            )
            .context("prepare load_all_malware_reports")?;
        let rows = stmt
            .query_map([], read_stored_malware)
            .context("query malware_reports")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn count_malware_reports(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM malware_reports", [], |row| row.get(0))
            .context("count malware_reports")
    }

    pub fn get_sync_state(&self, kind: &str) -> Result<Option<SyncState>> {
        self.conn
            .query_row(
                "SELECT etag, last_modified, last_commit, synced_at, record_count \
                 FROM sync_log WHERE kind = ?1",
                params![kind],
                |row| {
                    Ok(SyncState {
                        etag: row.get(0)?,
                        last_modified: row.get(1)?,
                        last_commit: row.get(2)?,
                        synced_at: row.get(3)?,
                        record_count: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("get_sync_state")
    }

    pub fn put_sync_state(&mut self, kind: &str, state: &SyncState) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let synced_at = state.synced_at.clone().unwrap_or(now);
        self.conn
            .execute(
                "INSERT INTO sync_log (kind, etag, last_modified, last_commit, synced_at, record_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(kind) DO UPDATE SET \
                    etag = excluded.etag, \
                    last_modified = excluded.last_modified, \
                    last_commit = excluded.last_commit, \
                    synced_at = excluded.synced_at, \
                    record_count = excluded.record_count",
                params![
                    kind,
                    state.etag,
                    state.last_modified,
                    state.last_commit,
                    synced_at,
                    state.record_count,
                ],
            )
            .context("put_sync_state")?;
        Ok(())
    }
}

fn read_stored_vulnerability(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredVulnerability> {
    let aliases_json: String = row.get(6)?;
    let affected_json: String = row.get(9)?;
    let fixed_json: String = row.get(10)?;
    let severity_raw: Option<String> = row.get(4)?;
    let severity = severity_raw
        .as_deref()
        .map(Severity::parse)
        .unwrap_or(Severity::Unknown);
    let aliases: Vec<String> = serde_json::from_str(&aliases_json).unwrap_or_default();
    let affected: AffectedSpec = serde_json::from_str(&affected_json).unwrap_or_default();
    let fixed_versions: Vec<String> = serde_json::from_str(&fixed_json).unwrap_or_default();
    Ok(StoredVulnerability {
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
        fetched_at: row.get(13)?,
    })
}

fn read_stored_malware(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMalware> {
    let evidence_json: String = row.get(8)?;
    let kind_raw: String = row.get(5)?;
    let version_raw: String = row.get(4)?;
    let evidence: serde_json::Value =
        serde_json::from_str(&evidence_json).unwrap_or(serde_json::Value::Null);
    Ok(StoredMalware {
        source: row.get(0)?,
        ref_id: row.get(1)?,
        ecosystem: row.get(2)?,
        package_name: row.get(3)?,
        version: if version_raw.is_empty() {
            None
        } else {
            Some(version_raw)
        },
        kind: MalwareKind::parse(&kind_raw),
        summary: row.get(6)?,
        url: row.get(7)?,
        evidence,
        reported_at: row.get(9)?,
        fetched_at: row.get(10)?,
    })
}

fn upsert_repo(
    tx: &rusqlite::Transaction<'_>,
    path: &Path,
    ecosystem: &str,
    fingerprint: &str,
    now: DateTime<Utc>,
) -> Result<i64> {
    tx.execute(
        "INSERT INTO repos (path, ecosystem, fingerprint, last_scan_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(path, ecosystem) DO UPDATE SET \
            fingerprint = excluded.fingerprint, \
            last_scan_at = excluded.last_scan_at",
        params![
            path.display().to_string(),
            ecosystem,
            fingerprint,
            now.to_rfc3339(),
        ],
    )
    .context("upsert repo")?;
    let id: i64 = tx
        .query_row(
            "SELECT id FROM repos WHERE path = ?1 AND ecosystem = ?2",
            params![path.display().to_string(), ecosystem],
            |row| row.get(0),
        )
        .context("selecting repo id")?;
    Ok(id)
}

fn upsert_workspace(
    tx: &rusqlite::Transaction<'_>,
    repo_id: i64,
    name: Option<&str>,
    manifest_path: &Path,
) -> Result<i64> {
    let manifest = manifest_path.display().to_string();
    tx.execute(
        "INSERT INTO workspaces (repo_id, name, manifest_path) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(repo_id, manifest_path) DO UPDATE SET name = excluded.name",
        params![repo_id, name, manifest],
    )
    .context("upsert workspace")?;
    let id: i64 = tx
        .query_row(
            "SELECT id FROM workspaces WHERE repo_id = ?1 AND manifest_path = ?2",
            params![repo_id, manifest],
            |row| row.get(0),
        )
        .context("selecting workspace id")?;
    Ok(id)
}

fn upsert_package(tx: &rusqlite::Transaction<'_>, ecosystem: &str, name: &str) -> Result<i64> {
    tx.execute(
        "INSERT INTO packages (ecosystem, name) VALUES (?1, ?2) \
         ON CONFLICT(ecosystem, name) DO NOTHING",
        params![ecosystem, name],
    )
    .context("upsert package")?;
    let id: i64 = tx
        .query_row(
            "SELECT id FROM packages WHERE ecosystem = ?1 AND name = ?2",
            params![ecosystem, name],
            |row| row.get(0),
        )
        .context("selecting package id")?;
    Ok(id)
}

fn update_package_latest(
    tx: &rusqlite::Transaction<'_>,
    pkg_id: i64,
    remote: &RemotePackage,
    now: DateTime<Utc>,
) -> Result<bool> {
    let affected = tx
        .execute(
            "UPDATE packages SET latest = ?1, latest_fetched_at = ?2 WHERE id = ?3",
            params![remote.latest, now.to_rfc3339(), pkg_id],
        )
        .context("updating package latest")?;
    Ok(affected > 0)
}

fn upsert_package_version(
    tx: &rusqlite::Transaction<'_>,
    pkg_id: i64,
    version: &str,
    published_at: Option<&str>,
    deprecated: bool,
    yanked: bool,
) -> Result<()> {
    tx.execute(
        "INSERT INTO package_versions (pkg_id, version, published_at, deprecated, yanked) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(pkg_id, version) DO UPDATE SET \
            published_at = excluded.published_at, \
            deprecated = excluded.deprecated, \
            yanked = excluded.yanked",
        params![
            pkg_id,
            version,
            published_at,
            deprecated as i64,
            yanked as i64,
        ],
    )
    .context("upsert package_version")?;
    Ok(())
}

pub fn kind_label(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Runtime => "runtime",
        DepKind::Dev => "dev",
        DepKind::Peer => "peer",
        DepKind::Optional => "optional",
    }
}

pub fn kind_from_label(label: &str) -> DepKind {
    match label {
        "dev" => DepKind::Dev,
        "peer" => DepKind::Peer,
        "optional" => DepKind::Optional,
        _ => DepKind::Runtime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packguard_core::model::Dependency;

    fn sample_project(root: &Path) -> Project {
        Project {
            ecosystem: "npm",
            root: root.to_path_buf(),
            manifest_path: root.join("package.json"),
            name: Some("demo".into()),
            workspace: None,
            dependencies: vec![
                Dependency {
                    name: "react".into(),
                    declared_range: "^18.2.0".into(),
                    installed: Some("18.2.0".into()),
                    kind: DepKind::Runtime,
                    source_lockfile: Some("package-lock.json".into()),
                },
                Dependency {
                    name: "typescript".into(),
                    declared_range: "^5.0.0".into(),
                    installed: Some("5.4.5".into()),
                    kind: DepKind::Dev,
                    source_lockfile: Some("package-lock.json".into()),
                },
            ],
        }
    }

    fn sample_remotes() -> BTreeMap<String, RemotePackage> {
        let mut m = BTreeMap::new();
        m.insert(
            "react".into(),
            RemotePackage {
                name: "react".into(),
                latest: Some("19.0.0".into()),
                latest_published_at: Some("2026-04-08T18:39:24Z".into()),
                versions: vec![
                    packguard_core::model::RemoteVersion {
                        version: "18.2.0".into(),
                        published_at: Some("2022-06-14T00:00:00Z".into()),
                        deprecated: false,
                        yanked: false,
                    },
                    packguard_core::model::RemoteVersion {
                        version: "19.0.0".into(),
                        published_at: Some("2026-04-08T18:39:24Z".into()),
                        deprecated: false,
                        yanked: false,
                    },
                ],
            },
        );
        m
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let root = PathBuf::from("/tmp/demo");
        let project = sample_project(&root);
        let stats = store
            .save_project(&root, &project, &sample_remotes(), "fp-1")
            .unwrap();
        assert_eq!(stats.packages, 2);
        assert_eq!(stats.dependencies, 2);
        assert_eq!(stats.updated_latest, 1);

        let fp = store.last_fingerprint(&root, "npm").unwrap();
        assert_eq!(fp.as_deref(), Some("fp-1"));

        let rows = store.load_repo_dependencies(&root).unwrap();
        assert_eq!(rows.len(), 2);
        let react = rows.iter().find(|r| r.name == "react").unwrap();
        assert_eq!(react.latest.as_deref(), Some("19.0.0"));
        assert_eq!(react.kind, DepKind::Runtime);
        assert_eq!(stats.persisted_versions, 2); // react history only
    }

    #[test]
    fn load_package_versions_returns_full_history() {
        let mut store = Store::open_in_memory().unwrap();
        let root = PathBuf::from("/tmp/demo");
        let project = sample_project(&root);
        store
            .save_project(&root, &project, &sample_remotes(), "fp-hist")
            .unwrap();

        let versions = store.load_package_versions("npm", "react").unwrap();
        let raw: Vec<_> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(raw, vec!["18.2.0", "19.0.0"]);
        assert!(!versions[0].deprecated && !versions[0].yanked);

        // typescript has no remote → no versions persisted.
        let versions = store.load_package_versions("npm", "typescript").unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn upsert_package_version_updates_flags() {
        let mut store = Store::open_in_memory().unwrap();
        let root = PathBuf::from("/tmp/demo");
        let project = sample_project(&root);

        // First save: clean history.
        store
            .save_project(&root, &project, &sample_remotes(), "fp-1")
            .unwrap();

        // Second save: mark 18.2.0 yanked + deprecated.
        let mut remotes = sample_remotes();
        let react = remotes.get_mut("react").unwrap();
        react.versions[0].deprecated = true;
        react.versions[0].yanked = true;
        store
            .save_project(&root, &project, &remotes, "fp-2")
            .unwrap();

        let versions = store.load_package_versions("npm", "react").unwrap();
        let v18 = versions.iter().find(|v| v.version == "18.2.0").unwrap();
        assert!(v18.deprecated);
        assert!(v18.yanked);
    }

    #[test]
    fn save_is_idempotent_on_reruns() {
        let mut store = Store::open_in_memory().unwrap();
        let root = PathBuf::from("/tmp/demo");
        let project = sample_project(&root);
        store
            .save_project(&root, &project, &sample_remotes(), "fp-1")
            .unwrap();
        store
            .save_project(&root, &project, &sample_remotes(), "fp-2")
            .unwrap();

        let fp = store.last_fingerprint(&root, "npm").unwrap();
        assert_eq!(fp.as_deref(), Some("fp-2"));
        let rows = store.load_repo_dependencies(&root).unwrap();
        assert_eq!(rows.len(), 2); // not duplicated
    }

    #[test]
    fn save_replaces_stale_dependencies() {
        let mut store = Store::open_in_memory().unwrap();
        let root = PathBuf::from("/tmp/demo");
        let mut project = sample_project(&root);
        store
            .save_project(&root, &project, &sample_remotes(), "fp-1")
            .unwrap();

        // Remove typescript, keep react.
        project.dependencies.retain(|d| d.name == "react");
        store
            .save_project(&root, &project, &sample_remotes(), "fp-2")
            .unwrap();
        let rows = store.load_repo_dependencies(&root).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "react");
    }

    #[test]
    fn fingerprint_is_none_when_repo_unknown() {
        let store = Store::open_in_memory().unwrap();
        assert!(store
            .last_fingerprint(&PathBuf::from("/nope"), "npm")
            .unwrap()
            .is_none());
    }

    fn sample_vuln() -> Vulnerability {
        use packguard_core::model::{AffectedEvent, AffectedRange, AffectedRangeKind};
        Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-1234-5678-abcd".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            severity: Severity::High,
            cve_id: Some("CVE-2021-23337".into()),
            aliases: vec!["CVE-2021-23337".into(), "GHSA-35jh-r3h4-6jhm".into()],
            summary: Some("Command Injection in lodash".into()),
            url: Some("https://github.com/advisories/GHSA-35jh-r3h4-6jhm".into()),
            affected: AffectedSpec {
                ranges: vec![AffectedRange {
                    kind: AffectedRangeKind::Semver,
                    events: vec![
                        AffectedEvent::Introduced("0.0.0".into()),
                        AffectedEvent::Fixed("4.17.21".into()),
                    ],
                }],
                versions: vec![],
            },
            fixed_versions: vec!["4.17.21".into()],
            published_at: Some("2021-02-15T00:00:00Z".into()),
            modified_at: Some("2023-07-18T00:00:00Z".into()),
        }
    }

    #[test]
    fn persist_and_load_vulnerabilities_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let vuln = sample_vuln();
        let n = store
            .persist_vulnerabilities(std::slice::from_ref(&vuln))
            .unwrap();
        assert_eq!(n, 1);

        let rows = store.load_vulnerabilities("npm", "lodash").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].advisory_id, "GHSA-1234-5678-abcd");
        assert_eq!(rows[0].severity, Severity::High);
        assert_eq!(rows[0].aliases.len(), 2);
        assert_eq!(rows[0].fixed_versions, vec!["4.17.21".to_string()]);
    }

    #[test]
    fn persist_vulnerabilities_is_idempotent_on_reruns() {
        let mut store = Store::open_in_memory().unwrap();
        let vuln = sample_vuln();
        store
            .persist_vulnerabilities(std::slice::from_ref(&vuln))
            .unwrap();
        store
            .persist_vulnerabilities(std::slice::from_ref(&vuln))
            .unwrap();
        assert_eq!(store.count_vulnerabilities().unwrap(), 1);

        // Updating the severity in a re-run is reflected (ON CONFLICT DO UPDATE).
        let mut bumped = vuln;
        bumped.severity = Severity::Critical;
        store
            .persist_vulnerabilities(std::slice::from_ref(&bumped))
            .unwrap();
        let rows = store.load_vulnerabilities("npm", "lodash").unwrap();
        assert_eq!(rows[0].severity, Severity::Critical);
    }

    #[test]
    fn persist_and_load_malware_reports_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        let report = packguard_core::MalwareReport {
            source: "osv-mal".into(),
            ref_id: "MAL-2024-1234".into(),
            ecosystem: "npm".into(),
            package_name: "evil-pkg".into(),
            version: "1.0.0".into(),
            kind: MalwareKind::Malware,
            summary: Some("Cryptominer in postinstall".into()),
            url: Some("https://osv.dev/MAL-2024-1234".into()),
            evidence: serde_json::json!({"id":"MAL-2024-1234"}),
            reported_at: Some("2024-09-01T00:00:00Z".into()),
        };
        let n = store
            .persist_malware_reports(std::slice::from_ref(&report))
            .unwrap();
        assert_eq!(n, 1);

        let rows = store.load_malware_reports("npm", "evil-pkg").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "osv-mal");
        assert_eq!(rows[0].kind, MalwareKind::Malware);
        assert_eq!(rows[0].version.as_deref(), Some("1.0.0"));
        assert_eq!(
            rows[0].summary.as_deref(),
            Some("Cryptominer in postinstall")
        );

        // Re-running with the same key updates rather than duplicates.
        store
            .persist_malware_reports(std::slice::from_ref(&report))
            .unwrap();
        assert_eq!(store.count_malware_reports().unwrap(), 1);
    }

    #[test]
    fn whole_package_typosquat_uses_empty_version_marker() {
        let mut store = Store::open_in_memory().unwrap();
        let report = packguard_core::MalwareReport {
            source: "typosquat-heuristic".into(),
            ref_id: "typo:lodahs".into(),
            ecosystem: "npm".into(),
            package_name: "lodahs".into(),
            version: String::new(), // whole-package suspicion
            kind: MalwareKind::Typosquat,
            summary: None,
            url: None,
            evidence: serde_json::json!({"resembles":"lodash","distance":2,"score":0.7}),
            reported_at: None,
        };
        store
            .persist_malware_reports(std::slice::from_ref(&report))
            .unwrap();
        let rows = store.load_malware_reports("npm", "lodahs").unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].version.is_none(), "empty marker → None on read");
        assert_eq!(rows[0].kind, MalwareKind::Typosquat);
    }

    #[test]
    fn sync_log_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(store.get_sync_state("osv-npm").unwrap().is_none());

        let state = SyncState {
            etag: Some("\"abc123\"".into()),
            last_modified: Some("Wed, 15 Apr 2026 12:00:00 GMT".into()),
            last_commit: None,
            synced_at: Some("2026-04-20T10:00:00Z".into()),
            record_count: 42_000,
        };
        store.put_sync_state("osv-npm", &state).unwrap();
        let got = store.get_sync_state("osv-npm").unwrap().unwrap();
        assert_eq!(got.etag.as_deref(), Some("\"abc123\""));
        assert_eq!(got.record_count, 42_000);

        // Upsert replaces.
        let mut next = state.clone();
        next.record_count = 43_000;
        store.put_sync_state("osv-npm", &next).unwrap();
        assert_eq!(
            store
                .get_sync_state("osv-npm")
                .unwrap()
                .unwrap()
                .record_count,
            43_000,
        );
    }
}
