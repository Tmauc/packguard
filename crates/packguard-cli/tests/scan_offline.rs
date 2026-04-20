//! Offline smoke tests. No network.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

/// Running `scan --offline` against an empty store must fail cleanly with a
/// message that tells the user what to do (§14 exit criterion).
#[test]
fn offline_scan_errors_cleanly_on_empty_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.db");
    let output = Command::new(bin())
        .arg("--store")
        .arg(&store)
        .args(["scan", "--offline"])
        .arg(fixtures_root().join("npm-basic"))
        .output()
        .expect("run packguard");
    assert!(
        !output.status.success(),
        "expected failure; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("offline scan requires a populated cache"),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("packguard scan"), "stderr was: {stderr}");
}

#[test]
fn scan_errors_cleanly_on_unknown_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.db");
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let output = Command::new(bin())
        .arg("--store")
        .arg(&store)
        .args(["scan"])
        .arg(&empty)
        .output()
        .expect("run packguard");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no supported manifest"), "stderr: {stderr}");
}
