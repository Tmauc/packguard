//! PackGuard SQLite store — persistence layer for scan results (and, later,
//! vuln intel and policy evaluations).
//!
//! Schema is versioned with refinery (`migrations/VNN__*.sql`). WAL mode is
//! enabled on every connection so scans and UI reads can happen concurrently.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use packguard_core::model::{DepKind, Project, RemotePackage};
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
                if let (Some(v), published_at) = (&remote.latest, &remote.latest_published_at) {
                    upsert_package_version(&tx, pkg_id, v, published_at.as_deref())?;
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
) -> Result<()> {
    tx.execute(
        "INSERT INTO package_versions (pkg_id, version, published_at) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(pkg_id, version) DO UPDATE SET published_at = excluded.published_at",
        params![pkg_id, version, published_at],
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
}
