//! Phase 14.1b — projects registry backing `~/.packguard/projects.db`.
//!
//! Independent from the per-project [`Store`](crate::Store) — different
//! file, different schema chain, different refinery embed. Tracks the
//! list of projects PackGuard knows about so the dashboard / CLI can
//! pick one without scanning the filesystem.
//!
//! No data is migrated from the legacy `~/.packguard/store.db` here.
//! That work lives in 14.1c. This sub-phase only creates the new
//! registry file lazily on first use; everything is additive.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use packguard_core::{find_project_root, slugify};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

mod registry_embedded {
    refinery::embed_migrations!("migrations_registry");
}

/// One row of `~/.packguard/projects.db` returned to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: i64,
    pub slug: String,
    pub path: PathBuf,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_scan: Option<DateTime<Utc>>,
}

pub struct ProjectsRegistry {
    conn: Connection,
}

impl ProjectsRegistry {
    /// Open or create `~/.packguard/projects.db` (and its parent
    /// directory). The file's schema is migrated to the latest
    /// registry version on every open. WAL mode mirrors the per-project
    /// store so dashboard reads and CLI writes don't block each other.
    pub fn open(packguard_home: &Path) -> Result<Self> {
        std::fs::create_dir_all(packguard_home)
            .with_context(|| format!("creating {}", packguard_home.display()))?;
        let db_path = packguard_home.join("projects.db");
        let mut conn =
            Connection::open(&db_path).with_context(|| format!("opening {}", db_path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL on projects registry")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys on projects registry")?;
        registry_embedded::migrations::runner()
            .run(&mut conn)
            .context("running registry migrations")?;
        Ok(Self { conn })
    }

    /// In-memory registry for tests. Same schema, no FS side-effects.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn =
            Connection::open_in_memory().context("opening in-memory projects registry")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys")?;
        registry_embedded::migrations::runner()
            .run(&mut conn)
            .context("running registry migrations")?;
        Ok(Self { conn })
    }

    /// Resolve `path` to its enclosing git root, slugify it, and insert
    /// a new row. Errors if the path is not in a git repo, is a file
    /// instead of a directory, or collides with an existing slug/path.
    pub fn create_project(&mut self, path: &Path) -> Result<Project> {
        if path.exists() && !path.is_dir() {
            return Err(anyhow!("path {} is not a directory", path.display()));
        }
        let raw_root = find_project_root(path).ok_or_else(|| {
            anyhow!(
                "path {} is not inside a git repo (no .git/ ancestor below $HOME)",
                path.display()
            )
        })?;
        // Canonicalize once more after discovery so the stored path /
        // slug stay stable across symlinks and CWD-relative inputs —
        // mirrors `normalize_repo_path` in the per-project store.
        let root = raw_root.canonicalize().unwrap_or_else(|_| raw_root.clone());
        if !root.is_dir() {
            return Err(anyhow!(
                "project root {} is not a directory",
                root.display()
            ));
        }
        let slug = slugify(&root);
        let name = root
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| slug.clone());
        let path_str = root.display().to_string();
        let now_ts = Utc::now().timestamp();
        let id: i64 = self
            .conn
            .query_row(
                "INSERT INTO projects (slug, path, name, created_at, last_scan) \
                 VALUES (?1, ?2, ?3, ?4, NULL) RETURNING id",
                params![slug, path_str, name, now_ts],
                |row| row.get(0),
            )
            .with_context(|| format!("inserting project {} into registry", slug))?;
        Ok(Project {
            id,
            slug,
            path: root,
            name,
            created_at: Utc.timestamp_opt(now_ts, 0).single().unwrap_or_default(),
            last_scan: None,
        })
    }

    /// Low-level insert that bypasses `find_project_root`/`slugify`.
    /// Used by the 14.1d migration to register pre-computed slugs
    /// (e.g. the `_default_` fallback for repos outside any git tree).
    /// Regular consumers should use [`create_project`](Self::create_project).
    pub fn insert_with_slug(&mut self, slug: &str, path: &Path, name: &str) -> Result<Project> {
        let path_str = path.display().to_string();
        let now_ts = Utc::now().timestamp();
        let id: i64 = self
            .conn
            .query_row(
                "INSERT INTO projects (slug, path, name, created_at, last_scan) \
                 VALUES (?1, ?2, ?3, ?4, NULL) RETURNING id",
                params![slug, path_str, name, now_ts],
                |row| row.get(0),
            )
            .with_context(|| format!("inserting project {} into registry", slug))?;
        Ok(Project {
            id,
            slug: slug.into(),
            path: path.to_path_buf(),
            name: name.into(),
            created_at: Utc.timestamp_opt(now_ts, 0).single().unwrap_or_default(),
            last_scan: None,
        })
    }

    /// Race-safe variant of [`insert_with_slug`](Self::insert_with_slug):
    /// `INSERT … ON CONFLICT DO NOTHING`. Returns `Ok(Some(project))`
    /// when a fresh row was inserted, `Ok(None)` when either the slug
    /// or the path was already present (typical singleton-fallback
    /// or parallel-process case).
    ///
    /// Used by the CLI's `ensure_default_registered` so two
    /// `packguard scan` processes sharing the same `PACKGUARD_HOME`
    /// can both succeed under the singleton `_default_` slug instead
    /// of one losing the
    /// `check-then-insert` race against `UNIQUE(slug)` /
    /// `UNIQUE(path)`.
    pub fn try_insert_with_slug(
        &mut self,
        slug: &str,
        path: &Path,
        name: &str,
    ) -> Result<Option<Project>> {
        let path_str = path.display().to_string();
        let now_ts = Utc::now().timestamp();
        // `RETURNING id` only yields a row on actual insert. If the
        // ON CONFLICT branch fires, query_row returns
        // `QueryReturnedNoRows`, which we map to `Ok(None)`.
        let id: Option<i64> = self
            .conn
            .query_row(
                "INSERT INTO projects (slug, path, name, created_at, last_scan) \
                 VALUES (?1, ?2, ?3, ?4, NULL) \
                 ON CONFLICT DO NOTHING RETURNING id",
                params![slug, path_str, name, now_ts],
                |row| row.get(0),
            )
            .optional()
            .with_context(|| format!("inserting project {} into registry", slug))?;
        Ok(id.map(|id| Project {
            id,
            slug: slug.into(),
            path: path.to_path_buf(),
            name: name.into(),
            created_at: Utc.timestamp_opt(now_ts, 0).single().unwrap_or_default(),
            last_scan: None,
        }))
    }

    /// All registered projects, ordered by most-recently-scanned first.
    /// Projects that have never been scanned (NULL last_scan) sort
    /// after every scanned project; ties break by `created_at DESC`.
    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, slug, path, name, created_at, last_scan FROM projects \
             ORDER BY (last_scan IS NULL), last_scan DESC, created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_project)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_by_slug(&self, slug: &str) -> Result<Option<Project>> {
        self.conn
            .query_row(
                "SELECT id, slug, path, name, created_at, last_scan \
                 FROM projects WHERE slug = ?1",
                params![slug],
                row_to_project,
            )
            .optional()
            .context("looking up project by slug")
    }

    /// Walks up from `path` to find a `.git/` ancestor, then resolves
    /// the registry row by slug. Returns `None` for paths outside any
    /// git repo or for projects not yet registered.
    pub fn get_by_path(&self, path: &Path) -> Result<Option<Project>> {
        let Some(raw_root) = find_project_root(path) else {
            return Ok(None);
        };
        let root = raw_root.canonicalize().unwrap_or_else(|_| raw_root.clone());
        let slug = slugify(&root);
        self.get_by_slug(&slug)
    }

    /// Bumps `last_scan` to now (UTC). Errors if no row matches `slug`.
    pub fn touch_last_scan(&mut self, slug: &str) -> Result<()> {
        let now_ts = Utc::now().timestamp();
        self.write_last_scan(slug, now_ts)
    }

    /// Sets `last_scan` to a specific timestamp (unix seconds, UTC).
    /// Used by 14.1d migration so the registry preserves the legacy
    /// store's most-recent scan_history timestamp instead of clobbering
    /// it with the migration's wall clock.
    pub fn set_last_scan(&mut self, slug: &str, ts: DateTime<Utc>) -> Result<()> {
        self.write_last_scan(slug, ts.timestamp())
    }

    fn write_last_scan(&mut self, slug: &str, ts: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE projects SET last_scan = ?1 WHERE slug = ?2",
            params![ts, slug],
        )?;
        if n == 0 {
            return Err(anyhow!("no project registered with slug {}", slug));
        }
        Ok(())
    }

    /// Removes the registry row. Does NOT touch
    /// `~/.packguard/projects/<slug>/store.db` — that lives under
    /// 14.1d's `DELETE /api/projects/{slug}` handler.
    pub fn delete_project(&mut self, slug: &str) -> Result<()> {
        let n = self
            .conn
            .execute("DELETE FROM projects WHERE slug = ?1", params![slug])?;
        if n == 0 {
            return Err(anyhow!("no project registered with slug {}", slug));
        }
        Ok(())
    }
}

fn row_to_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    let id: i64 = row.get(0)?;
    let slug: String = row.get(1)?;
    let path: String = row.get(2)?;
    let name: String = row.get(3)?;
    let created_at: i64 = row.get(4)?;
    let last_scan: Option<i64> = row.get(5)?;
    Ok(Project {
        id,
        slug,
        path: PathBuf::from(path),
        name,
        created_at: Utc
            .timestamp_opt(created_at, 0)
            .single()
            .unwrap_or_default(),
        last_scan: last_scan.and_then(|t| Utc.timestamp_opt(t, 0).single()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_repo(under: &Path, name: &str) -> PathBuf {
        let repo = under.join(name);
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        repo
    }

    #[test]
    fn open_creates_packguard_home_and_db_file() {
        let tmp = tempdir().unwrap();
        let pg_home = tmp.path().join(".packguard");
        assert!(!pg_home.exists(), "guard: home should not exist yet");
        let _registry = ProjectsRegistry::open(&pg_home).unwrap();
        assert!(pg_home.is_dir(), "open() must create the home dir");
        assert!(
            pg_home.join("projects.db").is_file(),
            "open() must create projects.db"
        );
    }

    #[test]
    fn create_project_inserts_row_with_canonical_slug() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "Nalo-monorepo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let project = registry.create_project(&repo).unwrap();
        // Slug is derived from the *canonical* path: on macOS the
        // tempdir lives under /private/var, so the slug starts with
        // `private-var-…`. We assert structure rather than exact bytes
        // to stay portable across CI runners.
        assert!(project.slug.contains("Nalo-monorepo"));
        assert!(!project.slug.starts_with('/'));
        assert!(!project.slug.contains('/'));
        assert_eq!(project.name, "Nalo-monorepo");
        assert_eq!(project.path, repo.canonicalize().unwrap());
        assert!(project.last_scan.is_none());
    }

    #[test]
    fn create_project_rejects_path_with_no_git_ancestor() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("loose-dir");
        std::fs::create_dir(&dir).unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let err = registry.create_project(&dir).unwrap_err();
        assert!(
            err.to_string().contains("not inside a git repo"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn create_project_rejects_file_path() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "repo");
        let file = repo.join("README.md");
        std::fs::write(&file, b"hello").unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let err = registry.create_project(&file).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn create_project_rejects_duplicate() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "repo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        registry.create_project(&repo).unwrap();
        let err = registry.create_project(&repo).unwrap_err();
        // SQLite UNIQUE violation surfaces as a constraint error; the
        // anyhow context mentions the slug.
        assert!(
            err.chain()
                .any(|e| e.to_string().to_lowercase().contains("unique")),
            "expected UNIQUE violation, got: {err:?}"
        );
    }

    #[test]
    fn list_projects_orders_by_last_scan_desc_then_created_at_desc() {
        let tmp = tempdir().unwrap();
        let a = fixture_repo(tmp.path(), "a");
        let b = fixture_repo(tmp.path(), "b");
        let c = fixture_repo(tmp.path(), "c");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let pa = registry.create_project(&a).unwrap();
        let pb = registry.create_project(&b).unwrap();
        let pc = registry.create_project(&c).unwrap();
        // Scan b then a (in that order) so a wins last_scan DESC.
        // c stays NULL → must sort last.
        registry.touch_last_scan(&pb.slug).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        registry.touch_last_scan(&pa.slug).unwrap();
        let listed = registry.list_projects().unwrap();
        assert_eq!(
            listed.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>(),
            vec![pa.slug.as_str(), pb.slug.as_str(), pc.slug.as_str()],
        );
    }

    #[test]
    fn get_by_path_walks_up_to_find_project() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "repo");
        let nested = repo.join("services/api");
        std::fs::create_dir_all(&nested).unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let created = registry.create_project(&repo).unwrap();
        let found = registry
            .get_by_path(&nested)
            .unwrap()
            .expect("walk-up must find the registered project");
        assert_eq!(found.slug, created.slug);
        assert_eq!(found.id, created.id);
    }

    #[test]
    fn delete_project_removes_row() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "repo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let created = registry.create_project(&repo).unwrap();
        registry.delete_project(&created.slug).unwrap();
        assert!(registry.get_by_slug(&created.slug).unwrap().is_none());
        assert!(registry.list_projects().unwrap().is_empty());
        // Second delete fails — no silent no-op.
        let err = registry.delete_project(&created.slug).unwrap_err();
        assert!(err.to_string().contains("no project registered"));
    }

    #[test]
    fn try_insert_with_slug_returns_some_on_first_insert_and_none_on_conflict() {
        let tmp = tempdir().unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let path = tmp.path().join("projects").join("_default_");
        let inserted = registry
            .try_insert_with_slug("_default_", &path, "_default_")
            .unwrap()
            .expect("first insert must report Some");
        assert_eq!(inserted.slug, "_default_");
        // Same slug + same path → silent conflict.
        let dup = registry
            .try_insert_with_slug("_default_", &path, "_default_")
            .unwrap();
        assert!(dup.is_none(), "duplicate slug+path must report None");
        // Same slug, different path → still a conflict (UNIQUE slug);
        // proves the singleton-fallback case the CLI relies on.
        let other_path = tmp.path().join("other").join("_default_");
        let dup_path = registry
            .try_insert_with_slug("_default_", &other_path, "_default_")
            .unwrap();
        assert!(
            dup_path.is_none(),
            "different path with same slug must still no-op",
        );
        // Sanity: only one `_default_` row exists.
        assert_eq!(registry.list_projects().unwrap().len(), 1);
    }

    #[test]
    fn touch_last_scan_updates_timestamp() {
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "repo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        let created = registry.create_project(&repo).unwrap();
        assert!(created.last_scan.is_none());
        registry.touch_last_scan(&created.slug).unwrap();
        let after = registry
            .get_by_slug(&created.slug)
            .unwrap()
            .expect("project still registered");
        let stamped = after.last_scan.expect("last_scan must be set");
        // The bump should be within the same wall second as Utc::now()
        // (or immediately before/after); allow a 5s envelope to absorb
        // CI clock skew without flaking.
        let drift = (Utc::now() - stamped).num_seconds().abs();
        assert!(drift < 5, "last_scan drifted by {drift}s");
    }
}
