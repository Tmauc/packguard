//! Phase 10b — policy cascade from the project path upward.
//!
//! # Resolution order
//!
//! ```text
//! Level 0 : built-in conservative defaults (baked into the binary)
//! Level 1 : ~/.packguard.yml                                   (user-wide, optional)
//! Level 2 : <repo root>/.packguard.yml                         (monorepo root)
//!               → root detected by: first `.git/` seen during the walk,
//!                 OR a `.packguard.yml` with `root: true`,
//!                 OR reaching the home directory (safety).
//! Level 3 : <intermediate dirs>/.packguard.yml                 (groups, ex: front/)
//! Level 4 : <scan path>/.packguard.yml                         (project-level)
//! ```
//!
//! Deep merge, later layers override earlier ones key-by-key. Arrays
//! (`block.cve_severity`, `overrides`, `groups`) are **replaced**, not
//! concatenated — the ESLint / Prettier / tsconfig convention. To inherit
//! a parent's `overrides` list, use `extends: "…"` explicitly.
//!
//! # `extends`
//!
//! When a layer declares `extends: "path/to/other.yml"`, that file is
//! loaded and inserted into the chain **immediately before** the declaring
//! file. Relative paths are resolved against the declaring file's
//! directory. Cascade is permitted (A extends B extends C); cycles are
//! detected by tracking visited absolute paths and produce an error.
//!
//! # Provenance
//!
//! Every key in the effective policy is tagged with the index of the
//! source that last set it (0-based into [`ResolvedPolicyFile::sources`]),
//! plus the best-effort 1-based line number. Provenance is computed once
//! during merge — downstream code (CLI `--show-policy`, dashboard Policy
//! eval tab) just reads it back.

use crate::model::Policy;
use crate::parse::{parse_policy, CONSERVATIVE_DEFAULTS_YAML};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A single contributor to the effective policy. The order in
/// [`ResolvedPolicyFile::sources`] matches merge order (lowest priority
/// first), so the last source that sets a given key wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySource {
    pub kind: SourceKind,
    /// Absolute path when the source is a file; `None` for the built-in
    /// defaults.
    pub path: Option<PathBuf>,
    /// Short user-facing label: "built-in default", "~/.packguard.yml",
    /// or the absolute file path.
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    BuiltIn,
    UserWide,
    /// A `.packguard.yml` discovered by the upward walk.
    File,
    /// A file pulled in via an `extends:` directive in another layer.
    Extends,
}

/// Per-key provenance. Keys use dot-notation (`offset.major`,
/// `block.cve_severity`, …). Top-level compound lists (`overrides`,
/// `groups`) record a single entry pointing at the source that last set
/// them, since arrays are replaced as a whole.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Provenance {
    pub keys: BTreeMap<String, ProvenanceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenanceEntry {
    /// Index into [`ResolvedPolicyFile::sources`].
    pub source_index: usize,
    /// Best-effort 1-based YAML line where the key is set. `None` for
    /// built-in defaults, inline-mapping values (`offset: { major: -1 }`
    /// where only the outer `offset:` line is resolvable), or anything
    /// the line scanner can't pin-point.
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedPolicyFile {
    pub policy: Policy,
    pub sources: Vec<PolicySource>,
    pub provenance: Provenance,
}

/// The set of top-level dot-notation keys the cascade tracks for
/// provenance. Kept explicit (rather than walking the Policy struct
/// reflectively) because the list rarely changes and the explicit form
/// is easier to audit + extend.
const TRACKED_KEYS: &[&str] = &[
    "defaults.offset.major",
    "defaults.offset.minor",
    "defaults.offset.patch",
    "defaults.allow_patch",
    "defaults.allow_security_patch",
    "defaults.stability",
    "defaults.min_age_days",
    "defaults.pin",
    "defaults.block.cve_severity",
    "defaults.block.malware",
    "defaults.block.deprecated",
    "defaults.block.yanked",
    "defaults.block.typosquat",
    "overrides",
    "groups",
];

/// Resolve the effective policy for `project_path`. Uses the real
/// `$HOME` for the user-wide layer; prefer
/// [`resolve_policy_with_home`] in tests so they don't depend on the
/// runner's environment.
pub fn resolve_policy(project_path: &Path) -> Result<ResolvedPolicyFile> {
    resolve_policy_with_home(project_path, default_home())
}

/// Resolve with an explicit home directory (or `None` to skip the
/// user-wide layer entirely).
pub fn resolve_policy_with_home(
    project_path: &Path,
    home: Option<PathBuf>,
) -> Result<ResolvedPolicyFile> {
    let start = project_path
        .canonicalize()
        .unwrap_or_else(|_| project_path.to_path_buf());
    let home_canonical = home
        .as_ref()
        .and_then(|h| h.canonicalize().ok().or_else(|| Some(h.clone())));

    // --- Phase 1: walk upward from project_path. ---
    let file_layers = walk_up(&start, home_canonical.as_deref())?;

    // --- Phase 2: user-wide layer, after built-in but before the walk. ---
    let mut chain: Vec<LoadedLayer> = Vec::new();
    chain.push(builtin_layer()?);

    if let Some(home) = &home_canonical {
        let user_wide_path = home.join(".packguard.yml");
        if user_wide_path.exists()
            && !file_layers
                .iter()
                .any(|l| l.source.path.as_deref() == Some(user_wide_path.as_path()))
        {
            let mut visiting = BTreeSet::new();
            chain.extend(load_layer_with_extends(
                &user_wide_path,
                SourceKind::UserWide,
                &mut visiting,
            )?);
        }
    }

    chain.extend(file_layers);

    // --- Phase 3: deep-merge layers left → right (later = higher priority). ---
    let merged = merge_chain(&chain)?;
    Ok(merged)
}

struct LoadedLayer {
    source: PolicySource,
    /// The YAML mapping as parsed. We merge at the Value level so that
    /// "key absent" stays distinguishable from "key explicitly set to
    /// the type default" (e.g., `block.malware: false`). The final
    /// merged Value is re-parsed into a typed `Policy` at the end.
    value: serde_yaml::Value,
    /// Raw YAML text for line-number lookup. `None` for built-in.
    raw_yaml: Option<String>,
}

fn builtin_layer() -> Result<LoadedLayer> {
    let value: serde_yaml::Value = serde_yaml::from_str(CONSERVATIVE_DEFAULTS_YAML)
        .context("parsing built-in conservative defaults")?;
    // Validate it round-trips cleanly before anyone downstream trips on it.
    parse_policy(CONSERVATIVE_DEFAULTS_YAML)?;
    Ok(LoadedLayer {
        source: PolicySource {
            kind: SourceKind::BuiltIn,
            path: None,
            label: "built-in default".to_string(),
        },
        value,
        raw_yaml: None,
    })
}

/// Walk up the directory tree collecting `.packguard.yml` files, ordered
/// from shallowest ancestor to the project path (so later layers override
/// earlier ones when merged left-to-right).
///
/// Stops at:
///   1. A `.packguard.yml` that declares `root: true` (explicit).
///   2. The first directory that contains a `.git/` entry (implicit repo
///      boundary). The `.packguard.yml` at that level IS included.
///   3. The home directory (safety — never walk into `$HOME`'s ancestors).
///   4. Filesystem root (`/`).
fn walk_up(start: &Path, home: Option<&Path>) -> Result<Vec<LoadedLayer>> {
    let mut collected_descending: Vec<PathBuf> = Vec::new();
    let mut current = Some(start.to_path_buf());

    while let Some(dir) = current {
        let candidate = dir.join(".packguard.yml");
        let has_git = dir.join(".git").exists();
        let mut has_root_marker = false;
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate)
                .with_context(|| format!("reading {}", candidate.display()))?;
            let peek =
                parse_policy(&text).with_context(|| format!("parsing {}", candidate.display()))?;
            if peek.root {
                has_root_marker = true;
            }
            collected_descending.push(candidate);
        }

        if has_root_marker || has_git {
            break;
        }
        if let Some(h) = home {
            if dir == h {
                break;
            }
        }
        current = dir.parent().map(|p| p.to_path_buf());
    }

    // `collected_descending` is [project, parent, grandparent, ...] —
    // reverse to [root, ..., project] so the merge direction is correct.
    collected_descending.reverse();

    let mut layers: Vec<LoadedLayer> = Vec::new();
    let mut visiting: BTreeSet<PathBuf> = BTreeSet::new();
    for file in collected_descending {
        layers.extend(load_layer_with_extends(
            &file,
            SourceKind::File,
            &mut visiting,
        )?);
    }
    Ok(layers)
}

/// Load a policy file and recursively expand its `extends:` chain. The
/// extended file goes BEFORE the file that declares it in the returned
/// vector (so the declaring file's keys override the extended file's
/// when merged).
fn load_layer_with_extends(
    path: &Path,
    kind: SourceKind,
    visiting: &mut BTreeSet<PathBuf>,
) -> Result<Vec<LoadedLayer>> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visiting.insert(canonical.clone()) {
        anyhow::bail!(
            "extends: cycle detected — {} already in the load chain",
            canonical.display()
        );
    }

    let text = std::fs::read_to_string(&canonical)
        .with_context(|| format!("reading {}", canonical.display()))?;
    let policy = parse_policy(&text).with_context(|| format!("parsing {}", canonical.display()))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("loading {} as yaml value", canonical.display()))?;

    let mut out: Vec<LoadedLayer> = Vec::new();
    if let Some(rel) = &policy.extends {
        let base = canonical.parent().unwrap_or_else(|| Path::new(""));
        let ext_path = base.join(rel);
        out.extend(load_layer_with_extends(
            &ext_path,
            SourceKind::Extends,
            visiting,
        )?);
    }

    let label = match kind {
        SourceKind::UserWide => "~/.packguard.yml".to_string(),
        SourceKind::BuiltIn => "built-in default".to_string(),
        SourceKind::File | SourceKind::Extends => canonical.display().to_string(),
    };
    out.push(LoadedLayer {
        source: PolicySource {
            kind,
            path: Some(canonical.clone()),
            label,
        },
        value,
        raw_yaml: Some(text),
    });

    visiting.remove(&canonical);
    Ok(out)
}

fn merge_chain(chain: &[LoadedLayer]) -> Result<ResolvedPolicyFile> {
    let sources: Vec<PolicySource> = chain.iter().map(|l| l.source.clone()).collect();

    // --- Deep-merge YAML values left → right. ---
    let mut merged_value = serde_yaml::Value::Mapping(Default::default());
    for layer in chain {
        merge_yaml_values(&mut merged_value, &layer.value);
    }

    // --- Provenance: for each tracked key, last layer that set it wins. ---
    let mut provenance = Provenance::default();
    for (idx, layer) in chain.iter().enumerate() {
        for key in TRACKED_KEYS {
            if yaml_path_exists(&layer.value, key) {
                let line = layer
                    .raw_yaml
                    .as_deref()
                    .and_then(|text| find_key_line(text, key));
                provenance.keys.insert(
                    (*key).to_string(),
                    ProvenanceEntry {
                        source_index: idx,
                        line,
                    },
                );
            }
        }
    }

    // --- Strip cascade-meta fields, then parse the merged YAML. ---
    if let serde_yaml::Value::Mapping(m) = &mut merged_value {
        m.remove(serde_yaml::Value::String("extends".into()));
        m.remove(serde_yaml::Value::String("root".into()));
    }
    let merged_yaml =
        serde_yaml::to_string(&merged_value).context("serializing merged policy cascade")?;
    let policy = parse_policy(&merged_yaml).context("parsing merged policy cascade")?;

    Ok(ResolvedPolicyFile {
        policy,
        sources,
        provenance,
    })
}

/// Deep-merge `src` into `dst`:
///   - Both mappings: recursive per-key.
///   - Anything else: `src` replaces `dst`. This includes arrays —
///     child's list fully replaces parent's, by design (ESLint-style).
fn merge_yaml_values(dst: &mut serde_yaml::Value, src: &serde_yaml::Value) {
    use serde_yaml::Value;
    match (dst, src) {
        (Value::Mapping(dst_map), Value::Mapping(src_map)) => {
            for (k, v) in src_map {
                match dst_map.get_mut(k) {
                    Some(existing) => merge_yaml_values(existing, v),
                    None => {
                        dst_map.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (dst_slot, src_val) => {
            *dst_slot = src_val.clone();
        }
    }
}

fn yaml_path_exists(root: &serde_yaml::Value, dotted_key: &str) -> bool {
    let mut cur = root;
    for part in dotted_key.split('.') {
        match cur {
            serde_yaml::Value::Mapping(map) => {
                let key = serde_yaml::Value::String(part.to_string());
                match map.get(&key) {
                    Some(v) => cur = v,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    true
}

/// Best-effort 1-based line lookup for a dotted YAML key. Handles the
/// canonical 2-space indented block style used by `packguard init`;
/// inline-mapping and oddly-indented files may degrade to `None`.
pub(crate) fn find_key_line(text: &str, dotted_key: &str) -> Option<u32> {
    let parts: Vec<&str> = dotted_key.split('.').collect();
    let lines: Vec<&str> = text.lines().collect();
    let mut start = 0usize;
    let mut expected_indent: Option<usize> = Some(0);
    let mut last_line: Option<u32> = None;

    for (depth, part) in parts.iter().enumerate() {
        let mut found: Option<usize> = None;
        for (idx, raw) in lines.iter().enumerate().skip(start) {
            let trimmed_end = raw.trim_end_matches('\r');
            let trimmed = trimmed_end.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = trimmed_end.len() - trimmed.len();
            let target = format!("{part}:");
            if !trimmed.starts_with(&target) && !trimmed.starts_with(&format!("{part} :")) {
                continue;
            }
            if let Some(want) = expected_indent {
                if depth == 0 && indent != want {
                    continue;
                }
                if depth > 0 && indent < want {
                    // We walked out of the block we were descending into.
                    return None;
                }
            }
            found = Some(idx);
            break;
        }
        let idx = found?;
        last_line = Some((idx + 1) as u32);
        start = idx + 1;
        let current_indent = lines[idx].len() - lines[idx].trim_start().len();
        // Next nested key must sit strictly deeper than the current line.
        expected_indent = Some(current_indent + 2);
    }
    last_line
}

fn default_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_key_line_top_level() {
        let text = "\
defaults:
  offset:
    major: 0
    minor: -1
    patch: 0
  stability: stable
";
        assert_eq!(find_key_line(text, "defaults"), Some(1));
        assert_eq!(find_key_line(text, "defaults.offset"), Some(2));
        assert_eq!(find_key_line(text, "defaults.offset.minor"), Some(4));
        assert_eq!(find_key_line(text, "defaults.stability"), Some(6));
        assert_eq!(find_key_line(text, "defaults.min_age_days"), None);
    }

    #[test]
    fn find_key_line_skips_comments_and_blank_lines() {
        let text = "\
# a header
defaults:

  # nested comment
  offset:
    major: -1
";
        assert_eq!(find_key_line(text, "defaults.offset.major"), Some(6));
    }

    #[test]
    fn yaml_path_exists_detects_nested_key() {
        let v: serde_yaml::Value =
            serde_yaml::from_str("defaults:\n  offset:\n    minor: -1\n").unwrap();
        assert!(yaml_path_exists(&v, "defaults.offset.minor"));
        assert!(yaml_path_exists(&v, "defaults.offset"));
        assert!(!yaml_path_exists(&v, "defaults.offset.patch"));
        assert!(!yaml_path_exists(&v, "groups"));
    }
}
