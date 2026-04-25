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
pub fn ensure_default_registered(
    registry: &mut ProjectsRegistry,
    packguard_home: &Path,
) -> Result<()> {
    if registry.get_by_slug(DEFAULT_SLUG)?.is_some() {
        return Ok(());
    }
    let path = packguard_home.join("projects").join(DEFAULT_SLUG);
    registry.insert_with_slug(DEFAULT_SLUG, &path, DEFAULT_SLUG)?;
    Ok(())
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
}
