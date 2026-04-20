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
