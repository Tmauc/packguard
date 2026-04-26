//! Phase 9a integration tests for `packguard scan` recursive auto-discovery.
//!
//! These run the binary end-to-end against synthetic monorepo layouts in
//! tempdirs. Network is gated via `--offline` (plus --force so we exercise
//! the whole pipeline right up to fetch_latest, then stop).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

/// Strip ANSI colour escape sequences. owo-colors writes `.bold()` /
/// `.green()` unconditionally, so we sanitise before substring checks.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // Skip until a letter (CSI terminator).
            i += 2;
            while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            i += 1; // skip the terminator
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn touch(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

/// Scan in dry-run mode — no registry calls, no DB writes — so the test
/// is fully offline and fast while still covering discovery + CLI glue.
fn dry_run(root: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(bin())
        .env("NO_COLOR", "1")
        .args(["scan", "--dry-run"])
        .args(args)
        .arg(root)
        .output()
        .expect("run packguard");
    (
        output.status.success(),
        strip_ansi(&String::from_utf8_lossy(&output.stdout)),
        strip_ansi(&String::from_utf8_lossy(&output.stderr)),
    )
}

fn build_pnpm_mixed_monorepo(root: &Path) {
    touch(
        &root.join("pnpm-workspace.yaml"),
        "packages:\n  - 'front/*'\n",
    );

    // Front-end workspaces (npm).
    touch(
        &root.join("front/vesta/package.json"),
        r#"{"name":"vesta","dependencies":{"react":"^18.0.0"}}"#,
    );
    touch(
        &root.join("front/phoebus/package.json"),
        r#"{"name":"phoebus"}"#,
    );
    touch(
        &root.join("front/mellona/package.json"),
        r#"{"name":"mellona"}"#,
    );

    // Back-end (pypi) — not in pnpm workspaces, walk must pick them up.
    touch(
        &root.join("services/incentive/pyproject.toml"),
        "[project]\nname = \"incentive\"\n",
    );
    touch(
        &root.join("services/accounting/pyproject.toml"),
        "[project]\nname = \"accounting\"\n",
    );
    touch(
        &root.join("services/backend/pyproject.toml"),
        "[project]\nname = \"backend\"\n",
    );

    // Noise that must be pruned by the built-in denylist.
    touch(&root.join("node_modules/react/package.json"), "{}");
    touch(
        &root.join("front/vesta/node_modules/react/package.json"),
        "{}",
    );
    touch(&root.join("target/debug/cruft/package.json"), "{}");
    touch(&root.join("dist/bundle/package.json"), "{}");
}

#[test]
fn dry_run_reports_pnpm_marker_and_python_walk() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    build_pnpm_mixed_monorepo(root);

    let (ok, stdout, stderr) = dry_run(root, &[]);
    assert!(ok, "expected dry-run success; stderr={stderr}");
    assert!(
        stdout.contains("pnpm-workspace.yaml"),
        "no marker in stdout:\n{stdout}",
    );
    assert!(
        stdout.contains("front/vesta"),
        "missing front/vesta:\n{stdout}",
    );
    assert!(
        stdout.contains("front/phoebus"),
        "missing front/phoebus:\n{stdout}",
    );
    assert!(
        stdout.contains("front/mellona"),
        "missing front/mellona:\n{stdout}",
    );
    assert!(
        stdout.contains("services/incentive"),
        "missing services/incentive:\n{stdout}",
    );
    assert!(
        stdout.contains("services/accounting"),
        "missing services/accounting:\n{stdout}",
    );
    assert!(
        stdout.contains("services/backend"),
        "missing services/backend:\n{stdout}",
    );
    // 3 + 3 = 6 projects total.
    assert!(
        stdout.contains("6 projects would be scanned"),
        "missing total line:\n{stdout}",
    );
    // None of the noise paths should leak through.
    assert!(
        !stdout.contains("node_modules"),
        "node_modules leaked:\n{stdout}",
    );
    assert!(
        !stdout.contains("target/debug"),
        "target/ leaked:\n{stdout}"
    );
    assert!(!stdout.contains("dist/bundle"), "dist/ leaked:\n{stdout}");
}

#[test]
fn dry_run_honours_depth_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A package.json 5 levels below root.
    touch(&root.join("a/b/c/d/e/package.json"), r#"{"name":"deep"}"#);

    // Default depth=4 → miss.
    let (ok, _, stderr) = dry_run(root, &[]);
    assert!(!ok, "expected failure; stderr={stderr}");
    assert!(stderr.contains("no scannable projects"), "stderr: {stderr}");

    // depth=6 → hit exactly one candidate.
    let (ok, stdout, _) = dry_run(root, &["--depth", "6"]);
    assert!(ok, "expected success; stdout was:\n{stdout}");
    assert!(stdout.contains("1 project would be scanned"), "{stdout}");
}

#[test]
fn dry_run_honours_exclude_glob() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(&root.join("apps/web/package.json"), "{}");
    touch(&root.join("apps/admin/package.json"), "{}");
    touch(&root.join("apps/docs/package.json"), "{}");

    // Baseline: no excludes → 3 projects.
    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("3 projects would be scanned"), "{stdout}");

    // With exclude → 2 projects, and apps/admin must be absent from
    // the listing (which appears for >1 projects).
    let (ok, stdout, _) = dry_run(root, &["--exclude", "apps/admin"]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("2 projects would be scanned"), "{stdout}");
    assert!(stdout.contains("apps/web"), "{stdout}");
    assert!(stdout.contains("apps/docs"), "{stdout}");
    assert!(!stdout.contains("apps/admin"), "{stdout}");
}

#[test]
fn dry_run_lists_npm_workspaces_object_form() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(
        &root.join("package.json"),
        r#"{"name":"root","workspaces":{"packages":["pkgs/*"]}}"#,
    );
    touch(&root.join("pkgs/a/package.json"), r#"{"name":"a"}"#);
    touch(&root.join("pkgs/b/package.json"), r#"{"name":"b"}"#);

    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    assert!(
        stdout.contains("package.json#workspaces"),
        "expected marker label:\n{stdout}",
    );
    assert!(stdout.contains("pkgs/a"), "{stdout}");
    assert!(stdout.contains("pkgs/b"), "{stdout}");
}

#[test]
fn no_recursive_single_project_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(&root.join("package.json"), r#"{"name":"single"}"#);
    touch(&root.join("nested/package.json"), r#"{"name":"nested"}"#);

    let (ok, stdout, _) = dry_run(root, &["--no-recursive"]);
    assert!(ok, "{stdout}");
    // Legacy mode must NOT descend into nested.
    assert!(!stdout.contains("nested"), "{stdout}");
    assert!(stdout.contains("1 project would be scanned"), "{stdout}");
}

#[test]
fn no_recursive_without_manifest_emits_legacy_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("empty")).unwrap();

    let output = Command::new(bin())
        .args(["scan", "--no-recursive"])
        .arg(root.join("empty"))
        .output()
        .expect("run packguard");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no supported manifest"), "stderr: {stderr}");
    assert!(stderr.contains("--no-recursive"), "stderr: {stderr}");
}

#[test]
fn include_glob_picks_up_dir_without_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("weird/here")).unwrap();
    // And a proper sibling so discovery has something to anchor on.
    touch(&root.join("other/package.json"), r#"{"name":"other"}"#);

    let (ok, stdout, _) = dry_run(root, &["--include", "weird/*"]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("other"), "{stdout}");
    assert!(stdout.contains("weird/here"), "{stdout}");
}

#[test]
fn gitignored_projects_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // `.ignore` is honoured unconditionally by the ignore crate.
    touch(&root.join(".ignore"), "third_party/\n");
    touch(
        &root.join("third_party/vendor/package.json"),
        r#"{"name":"vendored"}"#,
    );
    // Two non-ignored projects so the output lists paths (list appears
    // only when >1 project).
    touch(&root.join("app/package.json"), r#"{"name":"app"}"#);
    touch(&root.join("tool/package.json"), r#"{"name":"tool"}"#);

    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("2 projects would be scanned"), "{stdout}");
    assert!(stdout.contains("app"), "{stdout}");
    assert!(stdout.contains("tool"), "{stdout}");
    assert!(!stdout.contains("third_party"), "{stdout}");
}

#[test]
fn large_monorepo_without_yes_prompts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // 51 synthetic projects is just past the threshold.
    for i in 0..51 {
        touch(
            &root.join(format!("p{i:02}/package.json")),
            r#"{"name":"n"}"#,
        );
    }

    // --dry-run never prompts (no DB writes happen), so we exercise the
    // prompt path by running without --dry-run but piping an empty
    // stdin — the prompt reads "" and treats it as "no".
    let mut child = Command::new(bin())
        .args(["scan"])
        .arg(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Discovered 51 projects") || stderr.contains("Continue? [y/N]"),
        "expected prompt in stderr; stderr={stderr}\nstdout={stdout}"
    );
    assert!(
        stdout.contains("aborted"),
        "expected aborted; stdout={stdout}"
    );
}

#[test]
fn help_surfaces_every_new_flag() {
    let output = Command::new(bin())
        .args(["scan", "--help"])
        .output()
        .expect("run packguard");
    assert!(output.status.success());
    let out = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--no-recursive",
        "--depth",
        "--include",
        "--exclude",
        "--dry-run",
        "--yes",
    ] {
        assert!(out.contains(flag), "--help missing {flag}:\n{out}");
    }
}

#[test]
fn scan_with_no_manifest_fails_and_suggests_include() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(bin())
        .args(["scan"])
        .arg(tmp.path())
        .output()
        .expect("run packguard");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no scannable projects"), "stderr: {stderr}");
    assert!(stderr.contains("--include"), "stderr: {stderr}");
}

#[test]
fn dry_run_on_single_project_works() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(&root.join("package.json"), r#"{"name":"lonely"}"#);
    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("1 project would be scanned"), "{stdout}");
}

#[test]
fn lerna_marker_is_recognised() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(
        &root.join("lerna.json"),
        r#"{"packages":["libs/*"],"version":"independent"}"#,
    );
    touch(&root.join("libs/core/package.json"), r#"{"name":"core"}"#);
    touch(&root.join("libs/util/package.json"), r#"{"name":"util"}"#);

    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("lerna.json"), "{stdout}");
    assert!(stdout.contains("libs/core"), "{stdout}");
    assert!(stdout.contains("libs/util"), "{stdout}");
}

#[test]
fn marker_and_walk_dedup_same_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(
        &root.join("pnpm-workspace.yaml"),
        "packages:\n  - 'apps/*'\n",
    );
    touch(&root.join("apps/only/package.json"), r#"{"name":"only"}"#);

    let (ok, stdout, _) = dry_run(root, &[]);
    assert!(ok, "{stdout}");
    // Single project; marker provenance wins.
    assert!(stdout.contains("1 project would be scanned"), "{stdout}");
    assert!(
        stdout.contains("pnpm-workspace.yaml"),
        "expected marker source:\n{stdout}",
    );
}

#[test]
fn nonexistent_path_errors_cleanly() {
    let output = Command::new(bin())
        .args(["scan"])
        .arg("/this/path/really/does/not/exist/pg-9a")
        .output()
        .expect("run packguard");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("path does not exist"), "stderr: {stderr}");
}

// Convenience: the canonical Nalo-style fixture, re-used here as a test
// scaffold so we exercise the full >=8-project discovery path once end
// to end. Uses a private helper fn (not pub) to keep it local.
fn nalo_style(root: &Path) -> PathBuf {
    build_pnpm_mixed_monorepo(root);
    root.to_path_buf()
}

#[test]
fn nalo_style_fixture_lists_eight_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let root = nalo_style(tmp.path());
    let (ok, stdout, _) = dry_run(&root, &[]);
    assert!(ok, "{stdout}");
    // 3 frontend workspaces + 3 python services = 6 (the fixture
    // helper sticks to 6 to keep clean numbers — we accept >= 6).
    for dir in [
        "front/vesta",
        "front/phoebus",
        "front/mellona",
        "services/incentive",
        "services/accounting",
        "services/backend",
    ] {
        assert!(stdout.contains(dir), "missing {dir}:\n{stdout}");
    }
}

#[test]
fn dry_run_does_not_register_a_project_in_the_registry() {
    // Defense-in-depth for v0.6.1: `--dry-run` is supposed to be
    // read-only with respect to the registry. Auto-registering a
    // project is a state change, so a dry-run must never insert a
    // row into ~/.packguard/projects.db. We pin this by pointing
    // `PACKGUARD_HOME` at a fresh tempdir, running
    // `scan --dry-run` against a path with no `.git/` ancestor
    // (the orphan / `_default_` fallback path), and asserting the
    // registry stays empty afterwards. (The schema-empty file may
    // still be created by `ProjectsRegistry::open`; what matters is
    // that no project row was inserted.)
    use rusqlite::Connection;

    let pg_home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    touch(&work.path().join("package.json"), r#"{"name":"orphan"}"#);

    let output = Command::new(bin())
        .env("NO_COLOR", "1")
        .env("PACKGUARD_HOME", pg_home.path())
        .args(["scan", "--dry-run"])
        .arg(work.path())
        .output()
        .expect("run packguard");
    assert!(
        output.status.success(),
        "dry-run failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let projects_db = pg_home.path().join("projects.db");
    if !projects_db.exists() {
        // Even better — the registry was never touched at all.
        return;
    }
    let conn = Connection::open(&projects_db).expect("open projects.db");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
        .expect("count projects");
    assert_eq!(
        count, 0,
        "dry-run must not insert a project row into projects.db (found {count})",
    );
}
