//! Phase 9a — Monorepo auto-discovery.
//!
//! `packguard scan <path>` is recursive by default: point it at a repo
//! root and it finds every scannable project underneath. Two strategies
//! are combined:
//!
//! 1. **Markers** — `pnpm-workspace.yaml`, `package.json#workspaces`,
//!    `lerna.json` — yield explicit workspace globs. Presence-only
//!    signals (`turbo.json`, `nx.json`, `rush.json`) are noted for the
//!    summary but never drive path selection on their own.
//! 2. **Walk** — the `ignore` crate honours `.gitignore` and a built-in
//!    denylist (`node_modules`, `target`, `dist`, …). Any directory that
//!    contains a recognised manifest (`package.json`, `pyproject.toml`,
//!    `requirements*.txt`) becomes a candidate project.
//!
//! Discovery is **decoupled from [`crate::Ecosystem`]**: it returns raw
//! candidate directories, and the CLI then asks each ecosystem to parse
//! what it finds. That keeps this module reusable (dry-run, API surface
//! later) and lets new ecosystems piggy-back without touching discovery.

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Built-in directory names always excluded from the walk, regardless
/// of `.gitignore`. These are the noisy artefact dirs that explode scan
/// times and never hold first-party manifests.
pub const BUILTIN_EXCLUDES: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    "vendor",
    ".git",
    ".turbo",
    ".nx",
    ".svelte-kit",
    ".output",
];

/// Manifest filenames considered a project anchor during the walk. A
/// directory is a candidate iff at least one of these is present.
pub const MANIFEST_ANCHORS: &[&str] = &["package.json", "pyproject.toml", "requirements.txt"];

/// Default `--depth` for the filesystem walk. 4 levels is enough for
/// `apps/*/packages/*` layouts without exploding on pathological repos.
pub const DEFAULT_MAX_DEPTH: usize = 4;

/// Soft safeguard: if we discover more than this many candidates, the
/// CLI asks for confirmation before scanning.
pub const LARGE_COUNT_THRESHOLD: usize = 50;

/// Why a given path ended up in [`DiscoveryOutcome::projects`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSource {
    /// Root had no marker; walk picked it up.
    Walk,
    /// Matched a workspace glob declared in `pnpm-workspace.yaml`.
    PnpmWorkspace,
    /// Matched a workspace glob declared in `package.json#workspaces`.
    NpmWorkspaces,
    /// Matched a workspace glob declared in `lerna.json`.
    LernaPackages,
    /// Root itself had a recognised manifest and the walk added nothing
    /// under it (single-project repo, legacy behaviour preserved).
    RootManifest,
    /// `--no-recursive` path: exact `<path>` only, fail if no manifest.
    Legacy,
}

impl ProjectSource {
    pub fn marker_label(&self) -> Option<&'static str> {
        match self {
            Self::PnpmWorkspace => Some("pnpm-workspace.yaml"),
            Self::NpmWorkspaces => Some("package.json#workspaces"),
            Self::LernaPackages => Some("lerna.json"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredProject {
    /// Absolute path to the project directory.
    pub path: PathBuf,
    /// Path relative to the discovery root, useful for display.
    /// Empty `PathBuf` means "the root itself".
    pub relative: PathBuf,
    pub source: ProjectSource,
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub max_depth: usize,
    pub no_recursive: bool,
    /// Additional include globs (OR'd with manifest detection).
    pub include_globs: Vec<String>,
    /// Additional exclude globs (AND'd over the default excludes).
    pub exclude_globs: Vec<String>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            no_recursive: false,
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryOutcome {
    /// Canonicalised absolute root of the discovery run.
    pub root: PathBuf,
    pub projects: Vec<DiscoveredProject>,
    /// Human-readable markers found at the root (for the summary header).
    pub markers_found: Vec<String>,
    pub warnings: Vec<String>,
}

/// Entry point. `root` must exist; caller is expected to canonicalise
/// before calling if they care about symlink normalisation (we do this
/// here anyway, best-effort).
pub fn discover(root: &Path, opts: &DiscoveryOptions) -> Result<DiscoveryOutcome> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    // --no-recursive short-circuits everything: behave like the legacy
    // scan did — scan exactly `<path>`, fail if no manifest is there.
    if opts.no_recursive {
        let mut outcome = DiscoveryOutcome {
            root: canonical_root.clone(),
            ..Default::default()
        };
        if has_manifest(&canonical_root) {
            outcome.projects.push(DiscoveredProject {
                path: canonical_root.clone(),
                relative: PathBuf::new(),
                source: ProjectSource::Legacy,
            });
        }
        return Ok(outcome);
    }

    let mut projects: std::collections::BTreeMap<PathBuf, ProjectSource> =
        std::collections::BTreeMap::new();
    let mut markers_found: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Phase 1 — marker-driven expansion.
    for marker in parse_markers(&canonical_root, &mut warnings)? {
        markers_found.push(marker.label.clone());
        for path in marker.expand(&canonical_root, &mut warnings) {
            // first writer wins — marker provenance is more informative
            // than a walk hit at the same path.
            projects
                .entry(path)
                .or_insert_with(|| marker.source.clone());
        }
    }

    // Phase 2 — filesystem walk (always runs). A pnpm monorepo whose
    // Python services live outside the pnpm globs needs this to pick
    // them up.
    let walk_hits = walk_for_manifests(&canonical_root, opts)?;
    for path in walk_hits {
        projects.entry(path).or_insert(ProjectSource::Walk);
    }

    // Phase 3 — fallback to the root itself if the walk missed it (can
    // happen when the root has a manifest but the walk's root-level
    // detection never fired for some reason, e.g. gitignored by a stray
    // rule). We want `scan <single-project>` to stay a one-liner.
    if projects.is_empty() && has_manifest(&canonical_root) {
        projects.insert(canonical_root.clone(), ProjectSource::RootManifest);
    }

    let projects: Vec<DiscoveredProject> = projects
        .into_iter()
        .map(|(path, source)| {
            let relative = path
                .strip_prefix(&canonical_root)
                .map(Path::to_path_buf)
                .unwrap_or_else(|_| path.clone());
            DiscoveredProject {
                path,
                relative,
                source,
            }
        })
        .collect();

    Ok(DiscoveryOutcome {
        root: canonical_root,
        projects,
        markers_found,
        warnings,
    })
}

/// `true` iff `dir` contains at least one manifest file recognised by a
/// Tier-1 ecosystem (npm, pypi). Used both as the walk's anchor test
/// and as the fallback-to-root test.
pub fn has_manifest(dir: &Path) -> bool {
    // Exact anchor files.
    for name in MANIFEST_ANCHORS {
        if dir.join(name).is_file() {
            return true;
        }
    }
    // `requirements*.txt` — glob against the directory entries rather
    // than guessing names. Missing / unreadable dir → false.
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("requirements") && name.ends_with(".txt") {
                return true;
            }
        }
    }
    false
}

// ──────────────────────────────────────────────────────────────────────
// Marker parsers
// ──────────────────────────────────────────────────────────────────────

/// A parsed monorepo marker: the label used in the UX summary and the
/// globs (relative to the root) it expands to.
struct Marker {
    label: String,
    source: ProjectSource,
    globs: Vec<String>,
}

impl Marker {
    fn expand(&self, root: &Path, warnings: &mut Vec<String>) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for raw in &self.globs {
            // pnpm supports a `!` negation prefix on workspace globs;
            // stripping the prefix silently is the wrong behaviour (we'd
            // match the directories instead of excluding them). For now
            // skip negations entirely and warn — callers can layer an
            // explicit `--exclude` if they need that semantic.
            if raw.starts_with('!') {
                warnings.push(format!(
                    "{}: ignoring negated workspace glob '{}' (not yet supported)",
                    self.label, raw
                ));
                continue;
            }
            let pattern = root.join(raw);
            let pattern = pattern.to_string_lossy().to_string();
            match glob::glob(&pattern) {
                Ok(paths) => {
                    for path in paths.flatten() {
                        if path.is_dir() && has_manifest(&path) {
                            out.push(path);
                        }
                    }
                }
                Err(err) => {
                    warnings.push(format!("{}: invalid glob '{}': {}", self.label, raw, err))
                }
            }
        }
        out
    }
}

fn parse_markers(root: &Path, warnings: &mut Vec<String>) -> Result<Vec<Marker>> {
    let mut markers = Vec::new();

    // pnpm-workspace.yaml — authoritative for pnpm monorepos.
    let pnpm = root.join("pnpm-workspace.yaml");
    if pnpm.is_file() {
        match parse_pnpm_workspace(&pnpm) {
            Ok(globs) if !globs.is_empty() => markers.push(Marker {
                label: "pnpm-workspace.yaml".to_string(),
                source: ProjectSource::PnpmWorkspace,
                globs,
            }),
            Ok(_) => {}
            Err(e) => warnings.push(format!("pnpm-workspace.yaml: {e:#}")),
        }
    }

    // package.json#workspaces — npm/yarn classic + pnpm fallback.
    let pkg = root.join("package.json");
    if pkg.is_file() {
        match parse_npm_workspaces(&pkg) {
            Ok(Some(globs)) if !globs.is_empty() => markers.push(Marker {
                label: "package.json#workspaces".to_string(),
                source: ProjectSource::NpmWorkspaces,
                globs,
            }),
            Ok(_) => {}
            Err(e) => warnings.push(format!("package.json: {e:#}")),
        }
    }

    // lerna.json — legacy but still encountered.
    let lerna = root.join("lerna.json");
    if lerna.is_file() {
        match parse_lerna_packages(&lerna) {
            Ok(Some(globs)) if !globs.is_empty() => markers.push(Marker {
                label: "lerna.json".to_string(),
                source: ProjectSource::LernaPackages,
                globs,
            }),
            Ok(_) => {}
            Err(e) => warnings.push(format!("lerna.json: {e:#}")),
        }
    }

    Ok(markers)
}

pub fn parse_pnpm_workspace(path: &Path) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        packages: Vec<String>,
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: File =
        serde_yaml::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.packages)
}

pub fn parse_npm_workspaces(path: &Path) -> Result<Option<Vec<String>>> {
    // `workspaces` can be either `["packages/*"]` or
    // `{ "packages": ["packages/*"], "nohoist": [...] }`. Accept both.
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Workspaces {
        List(Vec<String>),
        Object {
            #[serde(default)]
            packages: Vec<String>,
        },
    }
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        workspaces: Option<Workspaces>,
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: File =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.workspaces.map(|w| match w {
        Workspaces::List(v) => v,
        Workspaces::Object { packages } => packages,
    }))
}

pub fn parse_lerna_packages(path: &Path) -> Result<Option<Vec<String>>> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        packages: Option<Vec<String>>,
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: File =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.packages)
}

// ──────────────────────────────────────────────────────────────────────
// Walker
// ──────────────────────────────────────────────────────────────────────

fn walk_for_manifests(root: &Path, opts: &DiscoveryOptions) -> Result<Vec<PathBuf>> {
    // `ignore::WalkBuilder::max_depth(Some(n))` counts the root as depth 0,
    // so we pass N as-is: max_depth=4 allows entries at `root/a/b/c/d/`.
    let mut builder = WalkBuilder::new(root);
    builder
        .max_depth(Some(opts.max_depth))
        .standard_filters(true)
        .git_ignore(true)
        .git_exclude(true)
        .hidden(false)
        .follow_links(false);

    let builtin_excludes: BTreeSet<&str> = BUILTIN_EXCLUDES.iter().copied().collect();
    let extra_excludes = compile_globset(&opts.exclude_globs)?;
    let extra_includes = compile_globset(&opts.include_globs)?;

    // Layer our builtin excludes on top of .gitignore. `filter_entry`
    // prunes before descent so node_modules is never walked.
    builder.filter_entry(move |entry| {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            return true;
        }
        if let Some(name) = entry.file_name().to_str() {
            if builtin_excludes.contains(name) {
                return false;
            }
        }
        true
    });

    let mut hits: Vec<PathBuf> = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let Some(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let path = entry.path();
        // Skip paths explicitly excluded via --exclude.
        if !extra_excludes.is_empty() {
            let rel = path.strip_prefix(root).unwrap_or(path);
            if extra_excludes.iter().any(|g| g.is_match(rel)) {
                continue;
            }
        }
        let is_include = !extra_includes.is_empty() && {
            let rel = path.strip_prefix(root).unwrap_or(path);
            extra_includes.iter().any(|g| g.is_match(rel))
        };
        if has_manifest(path) || is_include {
            hits.push(path.to_path_buf());
        }
    }
    hits.sort();
    Ok(hits)
}

fn compile_globset(patterns: &[String]) -> Result<Vec<globset::GlobMatcher>> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        let g = globset::Glob::new(p).with_context(|| format!("invalid glob pattern '{p}'"))?;
        out.push(g.compile_matcher());
    }
    Ok(out)
}

impl DiscoveryOutcome {
    /// Short, human-readable summary of the markers found at the root,
    /// used in the CLI header. Empty string when nothing notable.
    pub fn marker_summary(&self) -> String {
        if self.markers_found.is_empty() {
            String::new()
        } else {
            self.markers_found.join(", ")
        }
    }

    /// `true` when scanning the returned `projects` would blow past the
    /// `LARGE_COUNT_THRESHOLD` — the CLI uses this to gate a prompt.
    pub fn is_large(&self) -> bool {
        self.projects.len() > LARGE_COUNT_THRESHOLD
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn project_names(outcome: &DiscoveryOutcome) -> Vec<String> {
        outcome
            .projects
            .iter()
            .map(|p| p.relative.display().to_string())
            .collect()
    }

    // ── marker parsers ────────────────────────────────────────────────

    #[test]
    fn pnpm_workspace_parses_packages_list() {
        let tmp = tempdir().unwrap();
        let yaml = tmp.path().join("pnpm-workspace.yaml");
        touch(
            &yaml,
            "packages:\n  - 'apps/*'\n  - 'packages/*'\n  - '!apps/legacy'\n",
        );
        let globs = parse_pnpm_workspace(&yaml).unwrap();
        assert_eq!(globs, vec!["apps/*", "packages/*", "!apps/legacy"]);
    }

    #[test]
    fn pnpm_workspace_missing_packages_returns_empty() {
        let tmp = tempdir().unwrap();
        let yaml = tmp.path().join("pnpm-workspace.yaml");
        touch(&yaml, "other_key: []\n");
        let globs = parse_pnpm_workspace(&yaml).unwrap();
        assert!(globs.is_empty());
    }

    #[test]
    fn npm_workspaces_accepts_array_form() {
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        touch(
            &pkg,
            r#"{"name":"root","workspaces":["apps/*","packages/*"]}"#,
        );
        let globs = parse_npm_workspaces(&pkg).unwrap().unwrap();
        assert_eq!(globs, vec!["apps/*", "packages/*"]);
    }

    #[test]
    fn npm_workspaces_accepts_object_form() {
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        touch(
            &pkg,
            r#"{"name":"root","workspaces":{"packages":["pkgs/*"],"nohoist":["react"]}}"#,
        );
        let globs = parse_npm_workspaces(&pkg).unwrap().unwrap();
        assert_eq!(globs, vec!["pkgs/*"]);
    }

    #[test]
    fn npm_workspaces_missing_returns_none() {
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        touch(&pkg, r#"{"name":"single","dependencies":{}}"#);
        assert!(parse_npm_workspaces(&pkg).unwrap().is_none());
    }

    #[test]
    fn lerna_packages_parses_ok() {
        let tmp = tempdir().unwrap();
        let lerna = tmp.path().join("lerna.json");
        touch(&lerna, r#"{"packages":["libs/*","tools/*"]}"#);
        let globs = parse_lerna_packages(&lerna).unwrap().unwrap();
        assert_eq!(globs, vec!["libs/*", "tools/*"]);
    }

    // ── has_manifest ──────────────────────────────────────────────────

    #[test]
    fn has_manifest_detects_package_json() {
        let tmp = tempdir().unwrap();
        touch(&tmp.path().join("package.json"), "{}");
        assert!(has_manifest(tmp.path()));
    }

    #[test]
    fn has_manifest_detects_pyproject() {
        let tmp = tempdir().unwrap();
        touch(&tmp.path().join("pyproject.toml"), "[project]\nname='x'\n");
        assert!(has_manifest(tmp.path()));
    }

    #[test]
    fn has_manifest_detects_requirements_variant() {
        let tmp = tempdir().unwrap();
        touch(&tmp.path().join("requirements-dev.txt"), "pytest\n");
        assert!(has_manifest(tmp.path()));
    }

    #[test]
    fn has_manifest_returns_false_on_empty_dir() {
        let tmp = tempdir().unwrap();
        assert!(!has_manifest(tmp.path()));
    }

    // ── walker ────────────────────────────────────────────────────────

    #[test]
    fn walker_skips_node_modules_and_target() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("apps/web/package.json"), "{}");
        // Noise that should be pruned.
        touch(&root.join("node_modules/react/package.json"), "{}");
        touch(&root.join("target/debug/pkg/package.json"), "{}");
        touch(&root.join("apps/web/node_modules/dep/package.json"), "{}");

        let hits = walk_for_manifests(root, &DiscoveryOptions::default()).unwrap();
        let rels: Vec<_> = hits
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert!(rels.iter().any(|r| r == "apps/web"));
        assert!(rels.iter().all(|r| !r.contains("node_modules")));
        assert!(rels.iter().all(|r| !r.contains("target")));
    }

    #[test]
    fn walker_respects_max_depth() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("a/b/c/d/package.json"), "{}");

        let opts = DiscoveryOptions {
            max_depth: 2,
            ..Default::default()
        };
        let hits = walk_for_manifests(root, &opts).unwrap();
        // depth=2 means at most `a/b`, so the manifest at `a/b/c/d` is
        // unreachable.
        assert!(hits.is_empty(), "got {:?}", hits);

        let opts = DiscoveryOptions {
            max_depth: 5,
            ..Default::default()
        };
        let hits = walk_for_manifests(root, &opts).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn walker_honours_gitignore() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        // ignore-crate's gitignore handling only kicks in at a git repo
        // root. Use `.ignore` (a peer file it also honours unconditionally).
        touch(&root.join(".ignore"), "hidden/\n");
        touch(&root.join("hidden/package.json"), "{}");
        touch(&root.join("visible/package.json"), "{}");

        let hits = walk_for_manifests(root, &DiscoveryOptions::default()).unwrap();
        let rels: Vec<_> = hits
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert!(rels.iter().any(|r| r == "visible"));
        assert!(rels.iter().all(|r| r != "hidden"));
    }

    #[test]
    fn walker_extra_exclude_glob_prunes() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("front/vesta/package.json"), "{}");
        touch(&root.join("front/phoebus/package.json"), "{}");
        touch(&root.join("services/accounting/pyproject.toml"), "");

        let opts = DiscoveryOptions {
            exclude_globs: vec!["services/**".to_string()],
            ..Default::default()
        };
        let hits = walk_for_manifests(root, &opts).unwrap();
        let rels: Vec<_> = hits
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert!(rels.iter().any(|r| r == "front/vesta"));
        assert!(rels.iter().all(|r| !r.starts_with("services")));
    }

    #[test]
    fn walker_extra_include_glob_keeps_dir_without_manifest() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("odd/no-manifest")).unwrap();

        let opts = DiscoveryOptions {
            include_globs: vec!["odd/*".to_string()],
            ..Default::default()
        };
        let hits = walk_for_manifests(root, &opts).unwrap();
        let rels: Vec<_> = hits
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert!(rels.iter().any(|r| r == "odd/no-manifest"));
    }

    // ── discover() end-to-end ────────────────────────────────────────

    #[test]
    fn discover_single_project_repo_returns_root_once() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("package.json"), "{}");
        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.projects.len(), 1);
        assert_eq!(outcome.projects[0].relative, PathBuf::new());
    }

    #[test]
    fn discover_pnpm_monorepo_expands_globs() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'front/*'\n",
        );
        touch(&root.join("front/vesta/package.json"), "{}");
        touch(&root.join("front/phoebus/package.json"), "{}");
        touch(&root.join("front/mellona/package.json"), "{}");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        let names = project_names(&outcome);
        assert!(names.iter().any(|n| n == "front/vesta"));
        assert!(names.iter().any(|n| n == "front/phoebus"));
        assert!(names.iter().any(|n| n == "front/mellona"));
        assert!(outcome
            .markers_found
            .iter()
            .any(|m| m == "pnpm-workspace.yaml"));
        // All npm member projects should be tagged via the marker.
        for p in &outcome.projects {
            if p.relative.starts_with("front/") {
                assert_eq!(p.source, ProjectSource::PnpmWorkspace);
            }
        }
    }

    #[test]
    fn discover_combines_pnpm_marker_with_python_walk() {
        // The marker only knows about front/*; Poetry services under
        // services/ must be picked up by the walk, not dropped.
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'front/*'\n",
        );
        touch(&root.join("front/vesta/package.json"), "{}");
        touch(&root.join("services/incentive/pyproject.toml"), "");
        touch(&root.join("services/accounting/pyproject.toml"), "");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        let names = project_names(&outcome);
        assert!(names.iter().any(|n| n == "front/vesta"));
        assert!(names.iter().any(|n| n == "services/incentive"));
        assert!(names.iter().any(|n| n == "services/accounting"));
        // Python services come from the walk, not the marker.
        for p in &outcome.projects {
            if p.relative.starts_with("services/") {
                assert_eq!(p.source, ProjectSource::Walk);
            }
        }
    }

    #[test]
    fn discover_no_recursive_short_circuits() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("package.json"), "{}");
        touch(&root.join("nested/package.json"), "{}");
        let opts = DiscoveryOptions {
            no_recursive: true,
            ..Default::default()
        };
        let outcome = discover(root, &opts).unwrap();
        assert_eq!(outcome.projects.len(), 1);
        assert_eq!(outcome.projects[0].source, ProjectSource::Legacy);
    }

    #[test]
    fn discover_no_recursive_without_manifest_returns_empty() {
        let tmp = tempdir().unwrap();
        let opts = DiscoveryOptions {
            no_recursive: true,
            ..Default::default()
        };
        let outcome = discover(tmp.path(), &opts).unwrap();
        assert!(outcome.projects.is_empty());
    }

    #[test]
    fn discover_empty_repo_returns_nothing() {
        let tmp = tempdir().unwrap();
        let outcome = discover(tmp.path(), &DiscoveryOptions::default()).unwrap();
        assert!(outcome.projects.is_empty());
    }

    #[test]
    fn discover_dedups_marker_and_walk_hits() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n",
        );
        touch(&root.join("apps/web/package.json"), "{}");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.projects.len(), 1);
        // Marker provenance wins over the walk hit at the same path.
        assert_eq!(outcome.projects[0].source, ProjectSource::PnpmWorkspace);
    }

    #[test]
    fn discover_pnpm_negation_globs_emit_warning() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(
            &root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n  - '!apps/legacy'\n",
        );
        touch(&root.join("apps/web/package.json"), "{}");
        touch(&root.join("apps/legacy/package.json"), "{}");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.contains("negated workspace glob")));
        // Until we honour negations, the legacy workspace is still picked
        // up via the walk — documented caveat, flagged by the warning.
        assert_eq!(outcome.projects.len(), 2);
    }

    #[test]
    fn discover_npm_workspaces_object_form_works() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(
            &root.join("package.json"),
            r#"{"name":"root","workspaces":{"packages":["pkgs/*"]}}"#,
        );
        touch(&root.join("pkgs/ui/package.json"), "{}");
        touch(&root.join("pkgs/core/package.json"), "{}");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        let names = project_names(&outcome);
        assert!(names.iter().any(|n| n == "pkgs/ui"));
        assert!(names.iter().any(|n| n == "pkgs/core"));
        for p in &outcome.projects {
            if p.relative.starts_with("pkgs/") {
                assert_eq!(p.source, ProjectSource::NpmWorkspaces);
            }
        }
    }

    #[test]
    fn discover_root_manifest_with_nested_children_still_finds_both() {
        // A repo where the root itself is a project AND has children —
        // e.g. a library whose `examples/` folder has its own package.
        // The walk hits both.
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("package.json"), r#"{"name":"lib"}"#);
        touch(&root.join("examples/demo/package.json"), "{}");

        let outcome = discover(root, &DiscoveryOptions::default()).unwrap();
        let names = project_names(&outcome);
        assert!(names.iter().any(|n| n.is_empty()));
        assert!(names.iter().any(|n| n == "examples/demo"));
    }

    #[test]
    fn discover_canonicalises_root() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("package.json"), "{}");

        // A relative path via `.` should still canonicalise.
        let cwd_path = PathBuf::from(".");
        let cd = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let outcome = discover(&cwd_path, &DiscoveryOptions::default()).unwrap();
        std::env::set_current_dir(cd).unwrap();
        assert!(outcome.root.is_absolute());
    }

    #[test]
    fn is_large_threshold() {
        let mut outcome = DiscoveryOutcome::default();
        for i in 0..51 {
            outcome.projects.push(DiscoveredProject {
                path: PathBuf::from(format!("/tmp/p{i}")),
                relative: PathBuf::from(format!("p{i}")),
                source: ProjectSource::Walk,
            });
        }
        assert!(outcome.is_large());
    }

    #[test]
    fn marker_summary_joins_labels() {
        let outcome = DiscoveryOutcome {
            markers_found: vec!["pnpm-workspace.yaml".to_string(), "lerna.json".to_string()],
            ..Default::default()
        };
        assert_eq!(outcome.marker_summary(), "pnpm-workspace.yaml, lerna.json");
    }

    #[test]
    fn project_source_marker_label_only_for_markers() {
        assert_eq!(
            ProjectSource::PnpmWorkspace.marker_label(),
            Some("pnpm-workspace.yaml")
        );
        assert_eq!(
            ProjectSource::NpmWorkspaces.marker_label(),
            Some("package.json#workspaces")
        );
        assert_eq!(
            ProjectSource::LernaPackages.marker_label(),
            Some("lerna.json")
        );
        assert_eq!(ProjectSource::Walk.marker_label(), None);
        assert_eq!(ProjectSource::RootManifest.marker_label(), None);
        assert_eq!(ProjectSource::Legacy.marker_label(), None);
    }
}
