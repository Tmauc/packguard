//! Integration tests for `packguard init`.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn run_init(args: &[&str], dir: &PathBuf) -> (bool, String, String) {
    let mut cmd = Command::new(bin());
    cmd.args(["init"]).args(args).arg(dir);
    let output = cmd.output().expect("run packguard init");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn init_writes_conservative_yml() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, _stdout, stderr) = run_init(&[], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    let yml = std::fs::read_to_string(dir.path().join(".packguard.yml")).unwrap();
    assert!(yml.contains("offset: -1"));
    assert!(yml.contains("allow_patch: true"));
    assert!(yml.contains("cve_severity"));
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join(".packguard.yml");
    std::fs::write(&target, "# existing\n").unwrap();
    let (ok, _stdout, stderr) = run_init(&[], &dir.path().to_path_buf());
    assert!(!ok);
    assert!(stderr.contains("already exists"), "stderr: {stderr}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "# existing\n");
}

#[test]
fn init_with_force_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join(".packguard.yml");
    std::fs::write(&target, "# existing\n").unwrap();
    let (ok, _stdout, stderr) = run_init(&["--force"], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    let contents = std::fs::read_to_string(&target).unwrap();
    assert_ne!(contents, "# existing\n");
    assert!(contents.contains("offset: -1"));
}

#[test]
fn init_detects_ecosystems_from_fixtures() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("npm-basic");
    let dir = tempfile::tempdir().unwrap();
    // Copy fixture into temp dir (so the generated .packguard.yml doesn't
    // pollute the source tree).
    for entry in std::fs::read_dir(&fixture).unwrap() {
        let e = entry.unwrap();
        std::fs::copy(e.path(), dir.path().join(e.file_name())).unwrap();
    }
    let (ok, stdout, _stderr) = run_init(&[], &dir.path().to_path_buf());
    assert!(ok);
    assert!(stdout.contains("npm"), "stdout: {stdout}");
}

// ---- Phase 8.5 `--with-ci` -----------------------------------------

#[test]
fn init_with_ci_gitlab_writes_snippet_and_points_at_doc() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, stdout, stderr) = run_init(&["--with-ci", "gitlab"], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    let snippet = dir.path().join(".packguard/ci/gitlab.yml");
    let body = std::fs::read_to_string(&snippet).expect("snippet written");
    // Snippet must reference the generic container image, not a Nalo path.
    assert!(body.contains("ghcr.io/tmauc/packguard"));
    assert!(body.contains("packguard scan ."));
    assert!(body.contains("--fail-on-violation"));
    // Stdout points the user at the full doc.
    assert!(
        stdout.contains("docs/integrations/gitlab-ci.md"),
        "stdout: {stdout}",
    );
}

#[test]
fn init_with_ci_github_writes_under_packguard_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, _stdout, stderr) = run_init(&["--with-ci", "github"], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    let snippet = dir.path().join(".packguard/ci/github.yml");
    let body = std::fs::read_to_string(&snippet).expect("snippet written");
    assert!(body.contains("actions/cache@v4"));
    assert!(body.contains("packguard report . --format sarif --fail-on-violation"));
}

#[test]
fn init_with_ci_jenkins_writes_jenkinsfile() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, _stdout, stderr) = run_init(&["--with-ci", "jenkins"], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    let snippet = dir.path().join(".packguard/ci/Jenkinsfile");
    let body = std::fs::read_to_string(&snippet).expect("Jenkinsfile written");
    assert!(body.contains("stage('packguard')"));
    assert!(body.contains("packguard audit . --fail-on critical --fail-on-malware"));
}

#[test]
fn init_without_with_ci_autodetects_github_layout() {
    let dir = tempfile::tempdir().unwrap();
    // Simulate an existing GitHub Actions repo.
    std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    std::fs::write(dir.path().join(".github/workflows/ci.yml"), "# hi\n").unwrap();
    let (ok, stdout, stderr) = run_init(&[], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    assert!(
        stdout.contains("detected github"),
        "stdout should flag github: {stdout}"
    );
    assert!(stdout.contains("--with-ci github"));
    // The hint must not have generated a file — auto-detect never writes.
    assert!(!dir.path().join(".packguard/ci/github.yml").exists());
}

#[test]
fn init_without_with_ci_autodetects_gitlab_layout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitlab-ci.yml"), "stages: [build]\n").unwrap();
    let (ok, stdout, stderr) = run_init(&[], &dir.path().to_path_buf());
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains("detected gitlab"), "stdout: {stdout}");
    assert!(!dir.path().join(".packguard/ci/gitlab.yml").exists());
}

#[test]
fn init_with_ci_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".packguard/ci")).unwrap();
    std::fs::write(dir.path().join(".packguard/ci/gitlab.yml"), "# existing\n").unwrap();
    let (ok, _stdout, stderr) = run_init(&["--with-ci", "gitlab"], &dir.path().to_path_buf());
    assert!(!ok);
    assert!(stderr.contains("already exists"), "stderr: {stderr}");
    // Existing snippet must be untouched.
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".packguard/ci/gitlab.yml")).unwrap(),
        "# existing\n"
    );
}
