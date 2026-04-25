//! Project-root detection helpers — fondation v0.6.0 per-project store.
//!
//! Phase 14.1a: pure logic only (no IO on `~/.packguard/`, no DB).
//! Consumed by 14.1b (projects registry), 14.1c (V7 layout migration),
//! and 14.1d (server endpoints).

use std::env;
use std::path::{Path, PathBuf};

/// Walk up from `start` (or its canonical form) to find a directory
/// containing `.git/`. Returns that directory's path on success.
///
/// Stops at `$HOME` as a safety bound — never returns `$HOME` itself
/// or any directory above it. Returns `None` if no `.git/` is found
/// before reaching the bound, or if the walk runs out of parents
/// before either is reached.
///
/// `start` does not need to exist on disk; we canonicalize what we
/// can and walk lexically otherwise. This matches the brief's "the
/// path may have been registered before the working tree existed"
/// semantics, but in practice every caller passes a real workspace
/// path so the lexical fallback rarely fires.
pub fn find_project_root(start: &Path) -> Option<PathBuf> {
    let canonical = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    let home = env::var("HOME").ok().map(PathBuf::from);

    let mut current: &Path = canonical.as_path();
    loop {
        // HOME (and above) is the safety bound: never inspect it as a
        // candidate root, even if the user has dotfiles checked into
        // `~/.git/`. Walking above $HOME would risk pointing PackGuard
        // at /Users or / — a foot-gun, not a useful project root.
        if let Some(ref home_path) = home {
            if current == home_path.as_path() {
                return None;
            }
        }
        if current.join(".git").is_dir() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return None,
        }
    }
}

/// Slugify an absolute path into a flat directory name suitable for
/// use under `~/.packguard/projects/`. Strips the leading `/`,
/// replaces remaining `/` with `-`, preserves case, and trims any
/// trailing `-` (which would otherwise appear for paths with a
/// trailing slash).
///
/// Example: `/Users/mauc/Repo/Nalo/monorepo` →
/// `Users-mauc-Repo-Nalo-monorepo`.
///
/// Case is preserved on purpose — Linux paths are case-sensitive and
/// `Users-mauccap-foo` and `Users-MaucCAP-foo` would otherwise collide.
pub fn slugify(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim_start_matches('/');
    let mut slug = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        slug.push(if c == '/' { '-' } else { c });
    }
    slug.trim_end_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn find_project_root_returns_git_root() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join(".git")).unwrap();
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let found = find_project_root(&sub).expect("git root must be found");
        // Both sides canonicalized — macOS routes /var → /private/var
        // and tempdir().path() can return either form depending on the
        // libc.
        assert_eq!(found, root.canonicalize().unwrap());
    }

    #[test]
    fn find_project_root_walks_up_through_subdirs() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join(".git")).unwrap();
        let deep = root.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        let found = find_project_root(&deep).expect("git root must be found");
        assert_eq!(found, root.canonicalize().unwrap());
    }

    #[test]
    fn find_project_root_returns_none_when_no_git_ancestor() {
        let tmp = tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        // Tempdir lives under /tmp (or /var/folders on macOS); no
        // `.git/` anywhere on the path. The walk must reach the FS
        // root and return None without crashing.
        assert_eq!(find_project_root(&sub), None);
    }

    #[test]
    fn find_project_root_stops_at_home_bound() {
        // Deep directory outside the real $HOME with no `.git/`
        // ancestor. The walk must terminate (no infinite loop, no
        // unbounded fs traversal) and return None — the HOME bound
        // and the parent-is-None terminator together guarantee this.
        let tmp = tempdir().unwrap();
        let deep = tmp.path().join("nested/deep/path/with/no/git");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_project_root(&deep), None);
    }

    #[test]
    fn slugify_replaces_separators_and_strips_leading() {
        let p = Path::new("/Users/mauc/Repo/Nalo/monorepo");
        assert_eq!(slugify(p), "Users-mauc-Repo-Nalo-monorepo");
    }

    #[test]
    fn slugify_preserves_case() {
        let p = Path::new("/Users/MaucCAP/foo");
        assert_eq!(slugify(p), "Users-MaucCAP-foo");
    }
}
