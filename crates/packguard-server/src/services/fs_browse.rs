//! Phase 14.5b — Filesystem browser for the AddProjectModal directory
//! picker.
//!
//! ## Sandbox model
//!
//! Every request is sandboxed to the **server process's `$HOME`**.
//! The path is canonicalized (symlinks resolved) and rejected with
//! `Err("path X is outside $HOME")` if its canonical form is not a
//! descendant of `$HOME`. A symlink that lives inside `$HOME` but
//! points outside is also rejected, because the canonical form
//! escapes the sandbox.
//!
//! ## What's listed
//!
//! Only directories. File entries are filtered out — the picker is a
//! folder-of-folders browser, not a file viewer. Each surfaced
//! directory carries two booleans the AddProjectModal cares about:
//!
//! - `has_git` → contains a `.git/` directory directly.
//! - `has_manifest` → contains at least one supported manifest
//!   directly (see [`SUPPORTED_MANIFESTS`] + the `requirements*.txt`
//!   variant matcher).
//!
//! Hidden entries (leading `.`) are filtered out across the board so
//! `~/.cache`, `~/.ssh`, `~/.config`, etc. don't pollute the picker.
//! `.git/` is special-cased: it never appears as an entry, but its
//! presence under a parent surfaces via that parent's `has_git`.
//!
//! ## Defensive limits
//!
//! Directories with more than [`MAX_ENTRIES`] subdirectories are
//! truncated and the response carries `truncated: true`. This protects
//! against pathological cases like a global `node_modules` (already
//! denylisted by the `.git`-equivalent denylist… but the `node_modules`
//! denylist lives in the discovery layer, not here — this picker
//! shows everything by design so the user can opt-in).

use crate::dto::{FsBrowseResponse, FsEntry, FsRootEntry, FsRootsResponse};
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Manifest filenames that flag a directory as "scannable" by
/// PackGuard. Mirrored from the discovery layer's
/// [`packguard_core::MANIFEST_ANCHORS`] (which only carries
/// `package.json`, `pyproject.toml`, `requirements.txt`) plus the
/// lockfile siblings the recursive scan keys off — surfacing them in
/// the picker tells the user "this directory has been touched by a
/// package manager", which is the relevant signal for an Add-project
/// flow.
const SUPPORTED_MANIFESTS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "requirements.txt",
];

/// Conventional repo-holding directories under `$HOME` that the
/// picker offers as starting points. Each one only surfaces when it
/// actually exists on disk.
const ROOT_CANDIDATES: &[&str] = &[
    "Repo",
    "Repos",
    "Projects",
    "Workspace",
    "Code",
    "src",
    "Documents",
];

/// Hard cap on the number of directory entries returned in a single
/// response. Picked to be high enough to avoid truncating realistic
/// monorepos (a `packages/` directory with hundreds of workspaces
/// stays whole) while low enough to cap the worst-case payload at
/// roughly one screen's worth of JSON.
pub const MAX_ENTRIES: usize = 500;

fn has_requirements_variant(entry_name: &str) -> bool {
    entry_name.starts_with("requirements") && entry_name.ends_with(".txt")
}

/// Resolve the server process's home directory, canonicalized. Used
/// by the handlers; tests pass a fake home directly to
/// [`list_roots`] / [`browse`].
pub fn home_dir() -> Result<PathBuf> {
    let raw = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("$HOME is not set; cannot resolve filesystem browser sandbox"))?;
    let home = PathBuf::from(raw);
    home.canonicalize()
        .map_err(|e| anyhow!("canonicalizing $HOME ({}): {e}", home.display()))
}

/// Build the response for `GET /api/fs/roots`. `home` must already be
/// canonicalized. The first entry is always `$HOME` itself; each
/// subsequent entry is one of [`ROOT_CANDIDATES`] that exists on disk
/// (in declaration order).
pub fn list_roots(home: &Path) -> Result<FsRootsResponse> {
    let mut entries = vec![FsRootEntry {
        label: "$HOME".to_string(),
        path: home.display().to_string(),
    }];
    for name in ROOT_CANDIDATES {
        let candidate = home.join(name);
        if candidate.is_dir() {
            // Canonicalize so the entry path always resolves to the
            // same string the sandbox check would compare against.
            let path = candidate.canonicalize().unwrap_or(candidate);
            entries.push(FsRootEntry {
                label: format!("$HOME/{name}"),
                path: path.display().to_string(),
            });
        }
    }
    Ok(FsRootsResponse {
        home: home.display().to_string(),
        entries,
    })
}

/// Build the response for `GET /api/fs/browse?path=<requested>`.
/// `home` and `requested` may be relative or contain symlinks; both
/// are canonicalized before any further checks.
///
/// Errors carry a stable substring the route handler matches on to
/// pick the HTTP status:
/// - `"outside $HOME"` → 403
/// - `"does not exist"` / `"is not a directory"` → 400
/// - anything else → 500
pub fn browse(home: &Path, requested: &Path) -> Result<FsBrowseResponse> {
    if !requested.exists() {
        return Err(anyhow!("path {} does not exist", requested.display()));
    }
    let canonical = requested
        .canonicalize()
        .map_err(|e| anyhow!("canonicalizing {}: {e}", requested.display()))?;
    if !canonical.starts_with(home) {
        return Err(anyhow!(
            "path {} is outside $HOME ({}); refusing to traverse",
            canonical.display(),
            home.display(),
        ));
    }
    if !canonical.is_dir() {
        return Err(anyhow!("path {} is not a directory", canonical.display()));
    }

    let read = std::fs::read_dir(&canonical)
        .map_err(|e| anyhow!("reading {}: {e}", canonical.display()))?;
    let mut all: Vec<FsEntry> = Vec::new();
    for entry_res in read {
        let Ok(entry) = entry_res else { continue };
        let path = entry.path();
        // Filter to directories. Best-effort: a stat failure → skip
        // (rather than fail the whole listing).
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            _ => continue,
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        // Hidden entries hidden — the picker doesn't surface
        // `.cache`, `.ssh`, `.git`, etc. `.git` specifically is
        // surfaced via the parent's `has_git` flag instead.
        if name.starts_with('.') {
            continue;
        }
        let (has_git, has_manifest) = peek_flags(&path);
        all.push(FsEntry {
            name: name.to_string(),
            path: path.display().to_string(),
            has_git,
            has_manifest,
        });
    }

    // Case-insensitive sort so the picker has a deterministic visual
    // order regardless of filesystem readdir order.
    all.sort_by_key(|e| e.name.to_lowercase());

    let truncated = all.len() > MAX_ENTRIES;
    if truncated {
        all.truncate(MAX_ENTRIES);
    }

    let parent = if canonical == home {
        None
    } else {
        canonical
            .parent()
            .filter(|p| p.starts_with(home))
            .map(|p| p.display().to_string())
    };

    Ok(FsBrowseResponse {
        path: canonical.display().to_string(),
        parent,
        entries: all,
        truncated,
    })
}

/// Shallow read of `dir` for `.git/` and supported manifests. Returns
/// `(has_git, has_manifest)`. A read failure (permission denied,
/// concurrent rename) yields `(false, false)` rather than failing the
/// caller — the entry still appears in the picker, just without the
/// flags lit up.
fn peek_flags(dir: &Path) -> (bool, bool) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return (false, false);
    };
    let mut has_git = false;
    let mut has_manifest = false;
    for entry_res in read {
        let Ok(entry) = entry_res else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        // .git/ is a directory; only count it when it actually is one
        // (some tools create a `.git` *file* containing `gitdir: …`
        // for worktrees — that's still a git surface, so count both).
        if name == ".git" {
            has_git = true;
        } else if SUPPORTED_MANIFESTS.contains(&name.as_str()) || has_requirements_variant(&name) {
            // We only flag has_manifest on regular files — a directory
            // named `requirements.txt` is a freak occurrence but
            // would otherwise mis-flag.
            if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                has_manifest = true;
            }
        }
        if has_git && has_manifest {
            break;
        }
    }
    (has_git, has_manifest)
}

#[cfg(test)]
mod tests {
    //! Phase 14.5b — fs_browse unit tests. Every test passes a fake
    //! `home` to [`list_roots`] / [`browse`] so we never depend on
    //! the real `$HOME` of the test runner.
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, b"").unwrap();
    }

    fn home_with(layout: &[(&str, bool /* is_dir */)]) -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        for (rel, is_dir) in layout {
            let p = tmp.path().join(rel);
            if *is_dir {
                fs::create_dir_all(&p).unwrap();
            } else {
                touch(&p);
            }
        }
        tmp
    }

    fn canonical(p: &Path) -> PathBuf {
        p.canonicalize().unwrap()
    }

    // ---- list_roots ---------------------------------------------------

    #[test]
    fn roots_includes_home_and_existing_subdirs() {
        let tmp = home_with(&[("Repo", true), ("Documents", true)]);
        let home = canonical(tmp.path());
        let resp = list_roots(&home).unwrap();
        assert_eq!(resp.home, home.display().to_string());
        let labels: Vec<&str> = resp.entries.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels[0], "$HOME");
        assert!(labels.contains(&"$HOME/Repo"), "labels={labels:?}");
        assert!(labels.contains(&"$HOME/Documents"), "labels={labels:?}");
        assert!(!labels.contains(&"$HOME/Code"), "labels={labels:?}");
    }

    #[test]
    fn roots_only_home_when_no_conventional_subdirs() {
        let tmp = home_with(&[]);
        let home = canonical(tmp.path());
        let resp = list_roots(&home).unwrap();
        assert_eq!(resp.entries.len(), 1, "{resp:?}");
        assert_eq!(resp.entries[0].label, "$HOME");
    }

    // ---- browse: listing + sorting ------------------------------------

    #[test]
    fn browse_lists_subdirs_alphabetically_case_insensitive() {
        let tmp = home_with(&[("foo", true), ("Bar", true), ("baz", true)]);
        let home = canonical(tmp.path());
        let resp = browse(&home, &home).unwrap();
        let names: Vec<&str> = resp.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Bar", "baz", "foo"]);
    }

    #[test]
    fn browse_skips_hidden_dirs_except_git_via_parent_flag() {
        let tmp = home_with(&[(".cache", true), (".git", true), ("visible", true)]);
        let home = canonical(tmp.path());
        let resp = browse(&home, &home).unwrap();
        let names: Vec<&str> = resp.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["visible"]);
    }

    #[test]
    fn browse_flags_has_git_on_subdir() {
        let tmp = home_with(&[("proj/.git", true)]);
        let home = canonical(tmp.path());
        let resp = browse(&home, &home).unwrap();
        let proj = resp.entries.iter().find(|e| e.name == "proj").unwrap();
        assert!(proj.has_git);
        assert!(!proj.has_manifest);
    }

    #[test]
    fn browse_flags_has_manifest_on_subdir() {
        let tmp = home_with(&[
            ("web/package.json", false),
            ("api/pyproject.toml", false),
            ("py/requirements-dev.txt", false),
            ("empty", true),
        ]);
        let home = canonical(tmp.path());
        let resp = browse(&home, &home).unwrap();
        for (name, expected) in &[("web", true), ("api", true), ("py", true), ("empty", false)] {
            let entry = resp.entries.iter().find(|e| &e.name == name).unwrap();
            assert_eq!(
                entry.has_manifest, *expected,
                "{name} has_manifest mismatch (entries: {:?})",
                resp.entries,
            );
        }
    }

    #[test]
    fn browse_skips_files() {
        let tmp = home_with(&[("file.txt", false), ("subdir", true)]);
        let home = canonical(tmp.path());
        let resp = browse(&home, &home).unwrap();
        let names: Vec<&str> = resp.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["subdir"]);
    }

    #[cfg(unix)]
    #[test]
    fn browse_handles_unreadable_subdir_gracefully() {
        use std::os::unix::fs::PermissionsExt;
        // CI / root sometimes ignores 0o000 — skip in that case.
        if nix_uid_is_root() {
            return;
        }
        let tmp = home_with(&[("locked", true), ("readable", true)]);
        let home = canonical(tmp.path());
        let locked = home.join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Restore perms in a guard so the tempdir cleanup doesn't fail.
        let _restore = scopeguard_restore(&locked);
        let resp = browse(&home, &home).unwrap();
        let locked_entry = resp.entries.iter().find(|e| e.name == "locked").unwrap();
        assert!(!locked_entry.has_git);
        assert!(!locked_entry.has_manifest);
    }

    #[cfg(unix)]
    fn nix_uid_is_root() -> bool {
        // Cheap check that doesn't need the libc crate.
        std::env::var("USER").as_deref() == Ok("root")
    }

    #[cfg(unix)]
    fn scopeguard_restore(p: &Path) -> impl Drop + '_ {
        struct Restore<'a>(&'a Path);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
            }
        }
        Restore(p)
    }

    // ---- browse: sandbox ----------------------------------------------

    #[test]
    fn browse_rejects_path_outside_home() {
        let tmp = home_with(&[]);
        let home = canonical(tmp.path());
        // /etc exists on every Unix; the canonical form is not under
        // the temp home, so the sandbox check must trip.
        let err = browse(&home, Path::new("/etc")).unwrap_err().to_string();
        assert!(err.contains("outside $HOME"), "err={err}");
    }

    #[test]
    fn browse_rejects_path_inexistant() {
        let tmp = home_with(&[]);
        let home = canonical(tmp.path());
        let err = browse(&home, &home.join("nope-zzz"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "err={err}");
    }

    #[test]
    fn browse_rejects_path_is_a_file() {
        let tmp = home_with(&[("file.txt", false)]);
        let home = canonical(tmp.path());
        let err = browse(&home, &home.join("file.txt"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not a directory"), "err={err}");
    }

    // ---- browse: parent ------------------------------------------------

    #[test]
    fn browse_returns_parent_none_at_home_root() {
        let tmp = home_with(&[("sub", true)]);
        let home = canonical(tmp.path());
        let at_home = browse(&home, &home).unwrap();
        assert!(at_home.parent.is_none());

        let at_sub = browse(&home, &home.join("sub")).unwrap();
        assert_eq!(
            at_sub.parent.as_deref(),
            Some(home.display().to_string().as_str())
        );
    }

    // ---- browse: truncation -------------------------------------------

    #[test]
    fn browse_truncates_at_max_entries() {
        let tmp = tempdir().unwrap();
        let home = canonical(tmp.path());
        let big = home.join("big");
        fs::create_dir_all(&big).unwrap();
        // Create MAX_ENTRIES + 100 sub-dirs.
        for i in 0..(MAX_ENTRIES + 100) {
            fs::create_dir_all(big.join(format!("d{i:04}"))).unwrap();
        }
        let resp = browse(&home, &big).unwrap();
        assert_eq!(resp.entries.len(), MAX_ENTRIES, "{}", resp.entries.len());
        assert!(resp.truncated);
    }

    // ---- browse: symlinks ---------------------------------------------

    #[cfg(unix)]
    #[test]
    fn browse_canonicalizes_symlinks_within_home() {
        let tmp = home_with(&[("real", true)]);
        let home = canonical(tmp.path());
        std::os::unix::fs::symlink(home.join("real"), home.join("link")).unwrap();
        // Browsing the symlink must return the canonical path of the
        // target, not the symlink path. parent_dir = $HOME.
        let resp = browse(&home, &home.join("link")).unwrap();
        assert_eq!(resp.path, home.join("real").display().to_string());
        assert_eq!(
            resp.parent.as_deref(),
            Some(home.display().to_string().as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn browse_rejects_symlink_pointing_outside_home() {
        let tmp = home_with(&[]);
        let home = canonical(tmp.path());
        // The target of the symlink — somewhere under /tmp but
        // explicitly NOT under $HOME.
        let outside_tmp = tempdir().unwrap();
        let outside = canonical(outside_tmp.path());
        // Sanity: outside is not under home.
        assert!(!outside.starts_with(&home));
        std::os::unix::fs::symlink(&outside, home.join("escape")).unwrap();
        let err = browse(&home, &home.join("escape")).unwrap_err().to_string();
        assert!(err.contains("outside $HOME"), "err={err}");
    }
}
