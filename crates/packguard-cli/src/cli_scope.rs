//! Phase 14.2c — slug resolution for every CLI command.
//!
//! v0.5.x ran all commands against a single global `~/.packguard/store.db`.
//! v0.6.0 splits writes into per-project stores under
//! `~/.packguard/projects/<slug>/store.db`. This module is the single
//! place where the CLI decides which project's store the current
//! invocation should target. Priority order:
//!
//! 1. Explicit `--project <slug-or-path>` flag (path form is deprecated).
//! 2. `PACKGUARD_PROJECT` env var (slug only).
//! 3. Walk-up from a positional path arg or the current working
//!    directory to the first `.git/` ancestor.
//! 4. Fallback `_default_` slug for paths outside any git repo.
//!
//! `resolve_cli_scope` is pure (no side effects on the registry / FS).
//! Callers materialize the `_default_` registry entry on demand via
//! [`ensure_default_registered`] when the resolved source is `Default`.

use anyhow::Result;
use packguard_core::{find_project_root, slugify};
use packguard_store::ProjectsRegistry;
use std::path::{Path, PathBuf};

/// Stable slug used when a path has no `.git/` ancestor. Mirrors the
/// 14.1d migration's `FALLBACK_SLUG` so a CLI invocation in a
/// non-git directory lands in the same `_default_` project the
/// migration would have created for unregistered legacy repos.
pub const DEFAULT_SLUG: &str = "_default_";

/// Where the resolved slug came from. Drives the optional banner and
/// the deprecation warning for the legacy `--project <path>` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSource {
    /// `--project <slug>` (no path-like characters).
    ExplicitFlagSlug,
    /// `--project <path>` (legacy form; deprecation warning fires).
    ExplicitFlagPath(PathBuf),
    /// `PACKGUARD_PROJECT` env var.
    EnvVar,
    /// Walked up from a positional path / cwd to a `.git/` ancestor.
    Cwd(PathBuf),
    /// Nothing resolved — fell through to the `_default_` slug.
    Default,
}

#[derive(Debug, Clone)]
pub struct ResolvedCliScope {
    /// The project slug whose `<home>/projects/<slug>/store.db` the
    /// command should open.
    pub slug: String,
    /// Where the slug came from. The CLI uses this to decide which
    /// banner / warning to print.
    pub source: ScopeSource,
    /// Path the user effectively pointed at (positional arg or
    /// resolved from a `--project <path>`). Carried through so the
    /// existing workspace-filter logic (`store.load_repo_dependencies`,
    /// `graph::build`, …) keeps working — it consumes a workspace path
    /// which is a sub-path of the project root.
    pub workspace_path: Option<PathBuf>,
}

impl ResolvedCliScope {
    /// `true` when the source is the deprecated `--project <path>`
    /// form. CLI prints a one-line stderr warning so users migrate to
    /// the slug form.
    pub fn deprecated(&self) -> bool {
        matches!(self.source, ScopeSource::ExplicitFlagPath(_))
    }
}

/// Heuristic: a slug produced by [`slugify`] never contains `/`, `\`,
/// or a leading `.`. Anything else is treated as a workspace path
/// (legacy `--project <abs-path>` form) so we can walk it up to a
/// `.git/` ancestor.
fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || value.starts_with('.')
}

/// Pure resolver. `flag_value` is the raw `--project` arg (no parsing
/// done by the caller), `positional_path` is the command's positional
/// path argument when one exists, `cwd` is the current working
/// directory of the process. Does **not** mutate `_registry` — kept in
/// the signature so a future revision can swap the slugify fallback
/// for a registry lookup without touching call sites.
pub fn resolve_cli_scope(
    flag_value: Option<&str>,
    positional_path: Option<&Path>,
    _registry: &ProjectsRegistry,
    cwd: &Path,
) -> Result<ResolvedCliScope> {
    // 1. Explicit --project flag.
    if let Some(raw) = flag_value {
        let raw = raw.trim();
        if !raw.is_empty() {
            if looks_like_path(raw) {
                let p = PathBuf::from(raw);
                let slug = slug_for_path(&p);
                return Ok(ResolvedCliScope {
                    slug,
                    source: ScopeSource::ExplicitFlagPath(p.clone()),
                    workspace_path: Some(p),
                });
            }
            return Ok(ResolvedCliScope {
                slug: raw.to_string(),
                source: ScopeSource::ExplicitFlagSlug,
                workspace_path: positional_path.map(|p| p.to_path_buf()),
            });
        }
    }

    // 2. PACKGUARD_PROJECT env var (slug only — paths must go through
    //    the explicit flag so the deprecation chain stays visible).
    if let Ok(env_slug) = std::env::var("PACKGUARD_PROJECT") {
        let env_slug = env_slug.trim().to_string();
        if !env_slug.is_empty() {
            return Ok(ResolvedCliScope {
                slug: env_slug,
                source: ScopeSource::EnvVar,
                workspace_path: positional_path.map(|p| p.to_path_buf()),
            });
        }
    }

    // 3. positional path → walk-up; fallback to cwd.
    let walk_target = positional_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| cwd.to_path_buf());
    if let Some(root) = find_project_root(&walk_target) {
        let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
        let slug = slugify(&canonical);
        return Ok(ResolvedCliScope {
            slug,
            source: ScopeSource::Cwd(canonical),
            workspace_path: positional_path.map(|p| p.to_path_buf()),
        });
    }

    // 4. _default_ fallback. Caller is responsible for ensuring the
    //    registry row exists (see `ensure_default_registered`) — this
    //    function stays free of side effects.
    Ok(ResolvedCliScope {
        slug: DEFAULT_SLUG.into(),
        source: ScopeSource::Default,
        workspace_path: positional_path.map(|p| p.to_path_buf()),
    })
}

fn slug_for_path(p: &Path) -> String {
    if let Some(root) = find_project_root(p) {
        let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
        slugify(&canonical)
    } else {
        DEFAULT_SLUG.into()
    }
}

/// Idempotently insert the `_default_` row into the registry so the
/// dashboard's project list surfaces it. The on-disk store at
/// `<home>/projects/_default_/store.db` is created lazily by
/// [`packguard_store::ProjectStoreCache::get_or_open`] on first use.
///
/// Semantics: `_default_` is a **singleton fallback bucket**, not a
/// per-path row. The first orphan path (no `.git/` ancestor) to land on
/// `_default_` wins the row; subsequent calls — including parallel CLI
/// invocations that share the same `PACKGUARD_HOME` — are silent
/// no-ops. The pre-check `get_by_slug` handles the common
/// already-registered case in one round-trip, and the
/// `try_insert_with_slug` fallback collapses the
/// check-then-insert race into a single
/// `INSERT … ON CONFLICT DO NOTHING` so two processes can both win.
/// This matches the user-mental-model ("everything outside any git
/// tree shares one default project") and naturally defuses the
/// parallel-test `UNIQUE(projects.{slug,path})` race that surfaced in
/// 0.6.0.
pub fn ensure_default_registered(
    registry: &mut ProjectsRegistry,
    packguard_home: &Path,
) -> Result<()> {
    if registry.get_by_slug(DEFAULT_SLUG)?.is_some() {
        // Singleton already exists — keep its current `path` as-is.
        return Ok(());
    }
    let path = packguard_home.join("projects").join(DEFAULT_SLUG);
    // Race-safe insert: between the get_by_slug above and this call,
    // another process may have inserted the `_default_` row. The store
    // helper swallows the UNIQUE violation and reports it, so we just
    // continue.
    registry.try_insert_with_slug(DEFAULT_SLUG, &path, DEFAULT_SLUG)?;
    Ok(())
}

/// Phase 14.5a (Bug B) — idempotently register a project the resolver
/// derived from a real filesystem path. Returns `Some(canonical_root)`
/// the first time the slug is inserted (caller prints a banner) and
/// `None` if the slug was already known (no banner — the dashboard
/// already lists it).
///
/// Slug-form sources (`ExplicitFlagSlug`, `EnvVar`) are intentional
/// no-ops: the user typed a slug they expect to exist, and silently
/// auto-creating one would mask typos. Same for `Default` — that path
/// is owned by [`ensure_default_registered`] which the dispatcher
/// already calls.
///
/// Pre-Bug-B, `packguard scan` from inside an unregistered repo would
/// open `~/.packguard/projects/<slug>/store.db` (created lazily by the
/// store cache) and persist data into it — but never insert the
/// matching `projects.db` row. The dashboard's `/api/projects`
/// returned `[]` and rendered `EmptyProjectGate` despite the data
/// being on disk under that slug.
pub fn ensure_project_registered(
    scope: &ResolvedCliScope,
    registry: &mut ProjectsRegistry,
) -> Result<Option<PathBuf>> {
    let root = match &scope.source {
        // The resolver canonicalised the git root already.
        ScopeSource::Cwd(root) => root.clone(),
        // Legacy `--project <path>` form — re-walk so the inserted
        // path matches what the resolver slugified, even if `path`
        // itself is a workspace subdir.
        ScopeSource::ExplicitFlagPath(path) => {
            let Some(root) = packguard_core::find_project_root(path) else {
                return Ok(None);
            };
            root.canonicalize().unwrap_or(root)
        }
        ScopeSource::ExplicitFlagSlug | ScopeSource::EnvVar | ScopeSource::Default => {
            return Ok(None);
        }
    };
    if registry.get_by_slug(&scope.slug)?.is_some() {
        return Ok(None);
    }
    registry.create_project(&root)?;
    Ok(Some(root))
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

    /// Serialize tests that mutate `PACKGUARD_PROJECT`. Cargo runs unit
    /// tests in parallel by default; without a lock, one test's
    /// `remove_var` can land mid-flight in another's read.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn looks_like_path_classifies_inputs() {
        assert!(looks_like_path("/abs/path"));
        assert!(looks_like_path("./relative"));
        assert!(looks_like_path("../up"));
        assert!(looks_like_path("a/b"));
        assert!(looks_like_path("c:\\windows"));
        assert!(!looks_like_path("Users-mauc-Repo-Nalo-monorepo"));
        assert!(!looks_like_path("_default_"));
    }

    #[test]
    fn explicit_slug_flag_wins_over_env_and_cwd() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::set_var("PACKGUARD_PROJECT", "should-be-ignored");
        let resolved =
            resolve_cli_scope(Some("explicit-slug"), None, &registry, tmp.path()).unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        assert_eq!(resolved.slug, "explicit-slug");
        assert_eq!(resolved.source, ScopeSource::ExplicitFlagSlug);
        assert!(!resolved.deprecated());
    }

    #[test]
    fn explicit_path_flag_walks_up_and_marks_deprecated() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "demo");
        let nested = repo.join("front/vesta");
        std::fs::create_dir_all(&nested).unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        let resolved =
            resolve_cli_scope(Some(nested.to_str().unwrap()), None, &registry, tmp.path()).unwrap();
        assert!(resolved.slug.contains("demo"));
        assert!(
            resolved.deprecated(),
            "legacy path form must mark deprecated"
        );
        match &resolved.source {
            ScopeSource::ExplicitFlagPath(p) => assert_eq!(p, &nested),
            other => panic!("expected ExplicitFlagPath, got {other:?}"),
        }
    }

    #[test]
    fn env_var_used_when_no_flag() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::set_var("PACKGUARD_PROJECT", "from-env");
        let resolved = resolve_cli_scope(None, None, &registry, tmp.path()).unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        assert_eq!(resolved.slug, "from-env");
        assert_eq!(resolved.source, ScopeSource::EnvVar);
    }

    #[test]
    fn cwd_walk_up_finds_git_root_when_no_flag_or_env() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "demo-cwd");
        let nested = repo.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        let resolved = resolve_cli_scope(None, None, &registry, &nested).unwrap();
        assert!(resolved.slug.contains("demo-cwd"));
        match &resolved.source {
            ScopeSource::Cwd(_) => {}
            other => panic!("expected Cwd, got {other:?}"),
        }
        assert!(!resolved.deprecated());
    }

    #[test]
    fn positional_path_takes_precedence_over_cwd_for_walk_up() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let repo_a = fixture_repo(tmp.path(), "repo-a");
        let repo_b = fixture_repo(tmp.path(), "repo-b");
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        // cwd inside repo-a, but positional arg points inside repo-b.
        let resolved = resolve_cli_scope(None, Some(&repo_b), &registry, &repo_a).unwrap();
        assert!(
            resolved.slug.contains("repo-b"),
            "positional path drives walk-up, got slug {}",
            resolved.slug
        );
        assert_eq!(
            resolved.workspace_path.as_deref(),
            Some(repo_b.as_path()),
            "workspace_path mirrors the positional arg"
        );
    }

    #[test]
    fn default_fallback_when_no_git_anywhere() {
        let _g = env_lock();
        // tmpdir has no `.git/` ancestor — the walk reaches the FS
        // root and the resolver falls through to `_default_`.
        let tmp = tempdir().unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        let resolved = resolve_cli_scope(None, None, &registry, tmp.path()).unwrap();
        assert_eq!(resolved.slug, DEFAULT_SLUG);
        assert_eq!(resolved.source, ScopeSource::Default);
        assert!(resolved.workspace_path.is_none());
    }

    #[test]
    fn empty_flag_value_falls_through_to_lower_priority() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::set_var("PACKGUARD_PROJECT", "from-env-when-flag-empty");
        // Trimmed empty flag → ignored, env wins.
        let resolved = resolve_cli_scope(Some("   "), None, &registry, tmp.path()).unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        assert_eq!(resolved.slug, "from-env-when-flag-empty");
        assert_eq!(resolved.source, ScopeSource::EnvVar);
    }

    #[test]
    fn ensure_default_registered_is_idempotent() {
        let tmp = tempdir().unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        ensure_default_registered(&mut registry, tmp.path()).unwrap();
        ensure_default_registered(&mut registry, tmp.path()).unwrap();
        let row = registry
            .get_by_slug(DEFAULT_SLUG)
            .unwrap()
            .expect("row must exist after ensure");
        assert_eq!(row.slug, DEFAULT_SLUG);
        assert_eq!(row.name, DEFAULT_SLUG);
    }

    #[test]
    fn ensure_default_registered_singleton_when_called_with_different_paths() {
        // Regression for v0.6.0 → v0.6.1: parallel CLI invocations
        // sharing the same PACKGUARD_HOME both fall through to the
        // `_default_` fallback. The first one inserts the singleton
        // row; the second must silently no-op instead of failing on
        // `UNIQUE(projects.slug)` / `UNIQUE(projects.path)`. We
        // simulate the race by calling the helper directly with two
        // different `packguard_home` values that map to the same
        // (slug=`_default_`) row but distinct paths.
        let tmp_a = tempdir().unwrap();
        let tmp_b = tempdir().unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        ensure_default_registered(&mut registry, tmp_a.path()).unwrap();
        // Second call, different home → must NOT error and must
        // leave exactly one `_default_` row in place.
        ensure_default_registered(&mut registry, tmp_b.path()).unwrap();
        let rows = registry.list_projects().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "exactly one row must exist after singleton call: {rows:?}",
        );
        let row = &rows[0];
        assert_eq!(row.slug, DEFAULT_SLUG);
        // First-write-wins: the row's path matches tmp_a, not tmp_b.
        assert!(
            row.path.starts_with(tmp_a.path()),
            "first write must win; got path={:?}",
            row.path,
        );
    }

    // ---- Phase 14.5a (Bug B): ensure_project_registered -------------------

    #[test]
    fn ensure_project_registered_inserts_on_first_cwd_resolution() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "fresh-repo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        let scope = resolve_cli_scope(None, None, &registry, &repo).unwrap();
        // Pre-condition: registry empty for this slug.
        assert!(registry.get_by_slug(&scope.slug).unwrap().is_none());
        let inserted = ensure_project_registered(&scope, &mut registry).unwrap();
        assert!(
            inserted.is_some(),
            "first call must report Some(root) so the caller prints a banner",
        );
        // Post-condition: row exists and matches the slug.
        let row = registry
            .get_by_slug(&scope.slug)
            .unwrap()
            .expect("row must be registered");
        assert_eq!(row.slug, scope.slug);
    }

    #[test]
    fn ensure_project_registered_is_idempotent_on_known_slug() {
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let repo = fixture_repo(tmp.path(), "known-repo");
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();
        std::env::remove_var("PACKGUARD_PROJECT");
        let scope = resolve_cli_scope(None, None, &registry, &repo).unwrap();
        ensure_project_registered(&scope, &mut registry).unwrap();
        // Second call: slug already known → returns None (no banner).
        let again = ensure_project_registered(&scope, &mut registry).unwrap();
        assert!(again.is_none(), "second call must be a silent no-op");
    }

    #[test]
    fn ensure_project_registered_skips_slug_form_sources() {
        // Slug-form sources are intentional: the user typed a slug they
        // expect to exist. Auto-creating one would mask typos. Same for
        // EnvVar (PACKGUARD_PROJECT). Default is owned by the
        // ensure_default_registered path, so this helper bails too.
        let _g = env_lock();
        let tmp = tempdir().unwrap();
        let mut registry = ProjectsRegistry::open_in_memory().unwrap();

        // ExplicitFlagSlug
        let scope_slug = ResolvedCliScope {
            slug: "user-typed-slug".into(),
            source: ScopeSource::ExplicitFlagSlug,
            workspace_path: None,
        };
        assert!(ensure_project_registered(&scope_slug, &mut registry)
            .unwrap()
            .is_none());
        assert!(registry.get_by_slug("user-typed-slug").unwrap().is_none());

        // EnvVar
        let scope_env = ResolvedCliScope {
            slug: "env-slug".into(),
            source: ScopeSource::EnvVar,
            workspace_path: None,
        };
        assert!(ensure_project_registered(&scope_env, &mut registry)
            .unwrap()
            .is_none());
        assert!(registry.get_by_slug("env-slug").unwrap().is_none());

        // Default — separately materialized by ensure_default_registered.
        let scope_default = ResolvedCliScope {
            slug: DEFAULT_SLUG.into(),
            source: ScopeSource::Default,
            workspace_path: None,
        };
        assert!(ensure_project_registered(&scope_default, &mut registry)
            .unwrap()
            .is_none());

        // Sanity: passing a Cwd-derived scope WOULD have inserted (proves
        // the helper itself isn't broken).
        let repo = fixture_repo(tmp.path(), "would-insert");
        let canonical = repo.canonicalize().unwrap();
        let scope_cwd = ResolvedCliScope {
            slug: slugify(&canonical),
            source: ScopeSource::Cwd(canonical.clone()),
            workspace_path: None,
        };
        assert!(ensure_project_registered(&scope_cwd, &mut registry)
            .unwrap()
            .is_some());
    }
}
