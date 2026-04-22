//! Phase 10b — policy cascade integration tests.
//!
//! Build a tmp monorepo tree, exercise `resolve_policy_with_home` on
//! various leaf paths, assert both the effective policy and the
//! provenance map. `with_home` is used everywhere so tests never depend
//! on the runner's real `$HOME`.

use packguard_policy::{resolve_policy_with_home, Offset, SourceKind, Stability};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// Build a four-level fixture:
///
/// ```text
/// <root>/
///   .git/                          (git marker)
///   .packguard.yml                 root: true, offset.major: -1, block.cve_severity: [high]
///   front/
///     .packguard.yml               offset.minor: -1
///     vesta/
///       .packguard.yml             block.typosquat: strict
///       package.json               (placeholder so the path resolves)
///   services/
///     incentive/
///       package.json               (no .packguard.yml here)
/// ```
fn build_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();

    std::fs::create_dir_all(root.join(".git")).unwrap();

    write(
        &root.join(".packguard.yml"),
        r#"root: true
defaults:
  offset:
    major: -1
    minor: 0
    patch: 0
  stability: stable
  min_age_days: 7
  block:
    cve_severity: [high, critical]
    malware: true
    typosquat: warn
"#,
    );

    // front/ only sets offset.minor and min_age — the other fields should
    // inherit from root/built-in via deep-merge.
    write(
        &root.join("front/.packguard.yml"),
        r#"defaults:
  offset:
    minor: -1
  min_age_days: 0
"#,
    );

    write(
        &root.join("front/vesta/.packguard.yml"),
        r#"defaults:
  block:
    typosquat: strict
"#,
    );

    write(&root.join("front/vesta/package.json"), "{}");
    write(&root.join("services/incentive/package.json"), "{}");

    (dir, root)
}

#[test]
fn cascade_resolves_full_chain_at_vesta() {
    let (_guard, root) = build_fixture();
    let resolved = resolve_policy_with_home(&root.join("front/vesta"), None).unwrap();

    // Effective policy: major from `root/` (-1), minor from `front/` (-1),
    // patch from root/built-in (0), typosquat from `vesta/` (strict),
    // cve_severity from root, malware from root.
    assert_eq!(
        resolved.policy.defaults.offset,
        Offset::from_axes(-1, -1, 0)
    );
    assert_eq!(resolved.policy.defaults.min_age_days, 0);
    assert_eq!(resolved.policy.defaults.stability, Stability::Stable);
    assert_eq!(
        resolved.policy.defaults.block.cve_severity,
        vec!["high".to_string(), "critical".to_string()]
    );
    assert!(resolved.policy.defaults.block.malware);
    assert_eq!(
        resolved.policy.defaults.block.typosquat,
        packguard_policy::TyposquatPolicy::Strict
    );

    // Sources in merge order: built-in, root/.packguard.yml,
    // front/.packguard.yml, front/vesta/.packguard.yml.
    assert_eq!(resolved.sources.len(), 4);
    assert_eq!(resolved.sources[0].kind, SourceKind::BuiltIn);
    assert!(resolved.sources[1].label.ends_with(".packguard.yml"));
    assert!(resolved.sources[1]
        .path
        .as_ref()
        .unwrap()
        .ends_with(".packguard.yml"));

    // Provenance pins each key to the right source.
    let prov = &resolved.provenance;
    let entry = prov.keys.get("defaults.offset.major").expect("major key");
    assert_eq!(entry.source_index, 1, "major comes from root policy");
    let entry = prov.keys.get("defaults.offset.minor").expect("minor key");
    assert_eq!(entry.source_index, 2, "minor comes from front/");
    let entry = prov
        .keys
        .get("defaults.block.cve_severity")
        .expect("cve_severity key");
    assert_eq!(entry.source_index, 1, "cve_severity comes from root");
    let entry = prov
        .keys
        .get("defaults.block.typosquat")
        .expect("typosquat key");
    assert_eq!(entry.source_index, 3, "typosquat comes from vesta/");
}

#[test]
fn cascade_at_bare_project_without_local_policy_still_inherits() {
    let (_guard, root) = build_fixture();
    let resolved = resolve_policy_with_home(&root.join("services/incentive"), None).unwrap();

    // No file at services/incentive/ — walks up to root (`.git` stops it).
    // Only root policy + built-in contribute; front/ is not in the walk.
    assert_eq!(resolved.policy.defaults.offset, Offset::from_axes(-1, 0, 0));
    assert_eq!(resolved.policy.defaults.min_age_days, 7);
    assert_eq!(resolved.sources.len(), 2);
    assert_eq!(resolved.sources[0].kind, SourceKind::BuiltIn);
    assert_eq!(resolved.sources[1].kind, SourceKind::File);
}

#[test]
fn root_true_stops_walk_even_without_git_marker() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    // Intentionally NO .git here.
    write(
        &root.join(".packguard.yml"),
        r#"root: true
defaults:
  offset: { major: -2 }
"#,
    );
    write(&root.join("child/grandchild/package.json"), "{}");

    let resolved = resolve_policy_with_home(&root.join("child/grandchild"), None).unwrap();
    // Root sets major:-2 but not minor; built-in's minor:-1 persists via
    // deep-merge on the nested `offset` mapping.
    assert_eq!(
        resolved.policy.defaults.offset,
        Offset::from_axes(-2, -1, 0)
    );
    // Only root file + built-in — no walk past it.
    assert_eq!(resolved.sources.len(), 2);
}

#[test]
fn extends_pulls_in_referenced_file() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();

    write(
        &root.join("presets/security.yml"),
        r#"defaults:
  offset:
    major: 0
    minor: 0
    patch: 0
  stability: stable
  block:
    cve_severity: [critical]
    malware: true
"#,
    );

    write(&root.join(".git/stub"), "");
    write(
        &root.join(".packguard.yml"),
        r#"extends: "presets/security.yml"
defaults:
  min_age_days: 14
"#,
    );
    write(&root.join("app/package.json"), "{}");

    let resolved = resolve_policy_with_home(&root.join("app"), None).unwrap();
    // Security preset supplied the offset & cve_severity; root added min_age.
    assert_eq!(resolved.policy.defaults.offset, Offset::ZERO);
    assert_eq!(resolved.policy.defaults.min_age_days, 14);
    assert_eq!(
        resolved.policy.defaults.block.cve_severity,
        vec!["critical".to_string()]
    );
    // Sources: built-in, extended preset, root policy.
    assert_eq!(resolved.sources.len(), 3);
    assert_eq!(resolved.sources[1].kind, SourceKind::Extends);
}

#[test]
fn extends_cycle_is_an_error() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();

    write(
        &root.join("a.yml"),
        r#"extends: "b.yml"
defaults: { offset: { major: -1 } }
"#,
    );
    write(
        &root.join("b.yml"),
        r#"extends: "a.yml"
defaults: { offset: { major: -2 } }
"#,
    );
    write(&root.join(".git/stub"), "");
    write(
        &root.join(".packguard.yml"),
        r#"extends: "a.yml"
"#,
    );
    write(&root.join("app/package.json"), "{}");

    let err = resolve_policy_with_home(&root.join("app"), None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "{msg}");
}

#[test]
fn deep_merge_arrays_replace_not_concat() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join(".git/stub"), "");
    write(
        &root.join(".packguard.yml"),
        r#"defaults:
  block:
    cve_severity: [high, critical]
"#,
    );
    write(
        &root.join("child/.packguard.yml"),
        r#"defaults:
  block:
    cve_severity: [critical]
"#,
    );
    write(&root.join("child/package.json"), "{}");

    let resolved = resolve_policy_with_home(&root.join("child"), None).unwrap();
    assert_eq!(
        resolved.policy.defaults.block.cve_severity,
        vec!["critical".to_string()],
        "child replaces parent list, not concatenates"
    );
}

#[test]
fn no_policy_anywhere_falls_back_to_builtin() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join(".git/stub"), "");
    write(&root.join("app/package.json"), "{}");

    let resolved = resolve_policy_with_home(&root.join("app"), None).unwrap();
    // Only the built-in layer.
    assert_eq!(resolved.sources.len(), 1);
    assert_eq!(resolved.sources[0].kind, SourceKind::BuiltIn);
    // Built-in is the conservative template — `minor: -1` canonical posture.
    assert_eq!(resolved.policy.defaults.offset, Offset::from_axes(0, -1, 0));
}

#[test]
fn user_wide_policy_merged_when_present() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    let fake_home = dir.path().join("fake-home");
    std::fs::create_dir_all(&fake_home).unwrap();
    write(
        &fake_home.join(".packguard.yml"),
        r#"defaults:
  min_age_days: 30
"#,
    );
    write(&root.join(".git/stub"), "");
    write(
        &root.join(".packguard.yml"),
        r#"defaults:
  offset: { major: -1 }
"#,
    );
    write(&root.join("app/package.json"), "{}");

    let resolved = resolve_policy_with_home(&root.join("app"), Some(fake_home.clone())).unwrap();
    // Root sets major:-1, deep-merge keeps built-in's minor:-1, user-wide
    // sets min_age_days.
    assert_eq!(
        resolved.policy.defaults.offset,
        Offset::from_axes(-1, -1, 0)
    );
    assert_eq!(resolved.policy.defaults.min_age_days, 30);

    // built-in, user-wide, root file.
    assert_eq!(resolved.sources.len(), 3);
    assert_eq!(resolved.sources[0].kind, SourceKind::BuiltIn);
    assert_eq!(resolved.sources[1].kind, SourceKind::UserWide);
    assert_eq!(resolved.sources[1].label, "~/.packguard.yml");
}

#[test]
fn git_root_stops_walk_even_when_parent_has_policy() {
    let dir = TempDir::new().unwrap();
    let outer = dir.path().to_path_buf();
    // Outer level with a policy that should NOT be picked up.
    write(
        &outer.join(".packguard.yml"),
        r#"defaults:
  min_age_days: 90
"#,
    );
    // Inner is the git root — walk stops here.
    let inner = outer.join("repo");
    std::fs::create_dir_all(inner.join(".git")).unwrap();
    write(
        &inner.join(".packguard.yml"),
        r#"defaults:
  offset: { major: -1 }
  min_age_days: 7
"#,
    );
    write(&inner.join("app/package.json"), "{}");

    let resolved = resolve_policy_with_home(&inner.join("app"), None).unwrap();
    assert_eq!(resolved.policy.defaults.min_age_days, 7);
    assert_eq!(resolved.sources.len(), 2, "outer policy must be excluded");
}
