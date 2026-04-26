//! Phase 14.2a — per-project [`Store`] handle cache.
//!
//! The 14.1d migration laid out `~/.packguard/projects/<slug>/store.db`
//! per project, but every runtime read/write still goes through the
//! single `~/.packguard/store.db` legacy handle wrapped in `AppState`.
//! 14.2b will switch handlers from "always the legacy store" to
//! "the per-project store keyed by the request's resolved slug" — and
//! that switch needs a place to keep the per-slug `Store` handles
//! warm so a busy dashboard doesn't open + migrate the same SQLite
//! file on every request.
//!
//! This module is the place. It is:
//!
//! - **Strictly additive.** No handler, no CLI command, no job runner
//!   touches it yet. Wire-up lives in 14.2b.
//! - **Lazy.** A slug is opened on first request and cached forever
//!   (or until [`ProjectStoreCache::evict`]). The cache never opens a
//!   store ahead of time.
//! - **Race-safe.** Two concurrent `get_or_open` calls for the same
//!   slug may both reach the SQLite open path; only one handle is
//!   stored, the other is dropped. SQLite + the refinery migration
//!   runner are both idempotent, so the duplicate open is a no-op
//!   beyond a few hundred microseconds of wasted I/O.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use crate::Store;

/// Lock-protected map of `slug → Arc<Mutex<Store>>`. The outer
/// [`Mutex`] guards the map's structure; the inner [`Mutex`] is the
/// existing per-store lock that handlers already hold across an axum
/// request boundary, so consumers in 14.2b don't have to rewrap.
pub struct ProjectStoreCache {
    handles: Mutex<HashMap<String, Arc<Mutex<Store>>>>,
    packguard_home: PathBuf,
}

impl ProjectStoreCache {
    /// Build an empty cache rooted at `packguard_home`. The directory
    /// is **not** created here — `get_or_open` lets [`Store::open`]
    /// create the per-slug parent on first use, and `slug_paths`
    /// tolerates a missing `projects/` directory by returning an
    /// empty list.
    pub fn new(packguard_home: PathBuf) -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
            packguard_home,
        }
    }

    /// Resolve `<home>/projects/<slug>/store.db`, opening it through
    /// [`Store::open`] (which runs every migration V1..V7
    /// idempotently) on a cache miss. The returned `Arc<Mutex<Store>>`
    /// is the cached handle; subsequent calls for the same slug
    /// return the same `Arc` (verifiable via [`Arc::ptr_eq`]).
    ///
    /// Race semantics: if two callers concurrently miss on the same
    /// slug, both open their own [`Store`] outside the cache lock,
    /// then re-acquire the lock and double-check. The first caller
    /// to win the relock inserts its handle; the second caller drops
    /// its now-redundant handle and returns the winner's `Arc`.
    pub async fn get_or_open(&self, slug: &str) -> Result<Arc<Mutex<Store>>> {
        // Fast path: slug already cached.
        {
            let guard = self.handles.lock().await;
            if let Some(handle) = guard.get(slug) {
                return Ok(Arc::clone(handle));
            }
        }

        // Slow path: open outside the cache lock so a slow migration
        // on slug A doesn't block lookups on slug B.
        let store_path = self
            .packguard_home
            .join("projects")
            .join(slug)
            .join("store.db");
        let store = Store::open(&store_path)
            .with_context(|| format!("opening per-project store at {}", store_path.display()))?;
        let candidate = Arc::new(Mutex::new(store));

        // Re-acquire the lock and check for a racer. If another caller
        // beat us to the insert, we return their `Arc` and let our own
        // candidate drop (closing its connection).
        let mut guard = self.handles.lock().await;
        if let Some(existing) = guard.get(slug) {
            return Ok(Arc::clone(existing));
        }
        guard.insert(slug.to_string(), Arc::clone(&candidate));
        Ok(candidate)
    }

    /// Drop a slug's handle from the cache. The next `get_or_open`
    /// for that slug will re-open the underlying file. On-disk data
    /// is untouched. If the slug is not present this is a no-op.
    ///
    /// Used by tests today; in production this is the hook the
    /// upcoming `DELETE /api/projects/{slug}` handler (out of scope
    /// for 14.2a) will reach for so the cache doesn't hold a dead
    /// connection open after the on-disk store has been removed.
    pub async fn evict(&self, slug: &str) {
        self.handles.lock().await.remove(slug);
    }

    /// Phase 14.5a (Bug C) — expose the `~/.packguard/` root the cache
    /// was rooted at. The `add_project` rollback path needs to wipe
    /// `<home>/projects/<slug>/` from disk after a scan failure, so
    /// it asks the cache for the home rather than threading another
    /// PathBuf through `AppState`.
    pub fn home(&self) -> &Path {
        &self.packguard_home
    }

    /// Enumerate `<home>/projects/<slug>/store.db` files currently on
    /// disk, returning `(slug, store_db_path)` pairs sorted by slug
    /// for deterministic ordering. Does NOT open the stores or warm
    /// the cache.
    ///
    /// 14.2b's aggregate handlers (those called with `?project=`
    /// absent) iterate this list to fan out reads across every
    /// registered project's store. A missing `projects/` directory
    /// returns an empty `Vec` so a fresh install — no projects yet —
    /// doesn't error out.
    pub fn slug_paths(&self) -> Result<Vec<(String, PathBuf)>> {
        let projects_dir = self.packguard_home.join("projects");
        if !projects_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&projects_dir)
            .with_context(|| format!("reading {}", projects_dir.display()))?
        {
            let entry = entry.context("reading projects/ directory entry")?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let store_db = path.join("store.db");
            if !store_db.is_file() {
                continue;
            }
            let Some(slug) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            out.push((slug.to_string(), store_db));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn new_creates_empty_cache_without_io() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let _cache = ProjectStoreCache::new(home.clone());
        assert!(
            !home.exists(),
            "ProjectStoreCache::new must not touch the filesystem"
        );
    }

    #[tokio::test]
    async fn get_or_open_creates_store_on_first_call() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let cache = ProjectStoreCache::new(home.clone());

        let _handle = cache.get_or_open("demo").await.unwrap();
        let store_db = home.join("projects/demo/store.db");
        assert!(
            store_db.is_file(),
            "first get_or_open must create {}",
            store_db.display()
        );
    }

    #[tokio::test]
    async fn get_or_open_caches_handle_and_returns_same_arc() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let cache = ProjectStoreCache::new(home);

        let a = cache.get_or_open("demo").await.unwrap();
        let b = cache.get_or_open("demo").await.unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "second get_or_open must return the cached Arc, not re-open"
        );
    }

    #[tokio::test]
    async fn get_or_open_separates_handles_per_slug() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let cache = ProjectStoreCache::new(home);

        let a = cache.get_or_open("alpha").await.unwrap();
        let b = cache.get_or_open("beta").await.unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different slugs must yield different Arc handles"
        );
    }

    #[tokio::test]
    async fn evict_drops_handle_and_next_get_reopens() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let cache = ProjectStoreCache::new(home);

        let first = cache.get_or_open("demo").await.unwrap();
        cache.evict("demo").await;
        let second = cache.get_or_open("demo").await.unwrap();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "evict must drop the cached Arc; next call returns a fresh handle"
        );
    }

    #[tokio::test]
    async fn evict_unknown_slug_is_a_noop() {
        let tmp = tempdir().unwrap();
        let cache = ProjectStoreCache::new(tmp.path().to_path_buf());
        // Should not panic / error.
        cache.evict("never-registered").await;
    }

    #[test]
    fn slug_paths_returns_empty_when_projects_dir_missing() {
        let tmp = tempdir().unwrap();
        let cache = ProjectStoreCache::new(tmp.path().join(".packguard"));
        let paths = cache.slug_paths().unwrap();
        assert!(paths.is_empty(), "absent projects/ dir → empty list");
    }

    #[test]
    fn slug_paths_lists_directories_with_store_db_only_sorted() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let projects = home.join("projects");
        // Three siblings: foo + zeta have a store.db, bar does not.
        for slug in ["foo", "zeta"] {
            let dir = projects.join(slug);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("store.db"), b"").unwrap();
        }
        std::fs::create_dir_all(projects.join("bar")).unwrap();
        std::fs::write(projects.join("bar/garbage.txt"), b"").unwrap();
        // A loose file at the projects root must also be ignored.
        std::fs::write(projects.join("README"), b"").unwrap();

        let cache = ProjectStoreCache::new(home);
        let paths = cache.slug_paths().unwrap();
        let slugs: Vec<&str> = paths.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(
            slugs,
            vec!["foo", "zeta"],
            "only slug dirs with a store.db, sorted alphabetically"
        );
        for (slug, p) in &paths {
            assert!(p.ends_with(format!("{slug}/store.db")));
            assert!(p.is_file());
        }
    }

    #[tokio::test]
    async fn concurrent_get_or_open_yields_one_cached_handle() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join(".packguard");
        let cache = Arc::new(ProjectStoreCache::new(home.clone()));

        // Spawn 16 concurrent calls for the same slug. The race-safe
        // double-check pattern in `get_or_open` may open the underlying
        // SQLite file more than once (one per racer that misses the
        // fast path), but only one `Arc<Mutex<Store>>` ends up cached
        // and every caller observes the same handle.
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache.get_or_open("demo").await.unwrap()
            }));
        }
        let mut arcs: Vec<Arc<Mutex<Store>>> = Vec::new();
        for h in handles {
            arcs.push(h.await.unwrap());
        }
        let first = arcs[0].clone();
        for (i, a) in arcs.iter().enumerate().skip(1) {
            assert!(
                Arc::ptr_eq(&first, a),
                "concurrent caller #{i} must observe the same cached Arc"
            );
        }
        // And the on-disk file exists exactly once.
        assert!(home.join("projects/demo/store.db").is_file());
    }
}
