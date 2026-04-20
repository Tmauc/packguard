//! Offline smoke test: `packguard scan --offline` against the fixture.
//! Avoids network; validates CLI wiring end-to-end.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("npm-basic")
}

#[test]
fn scan_offline_prints_expected_packages() {
    let output = Command::new(bin())
        .args(["scan", "--offline"])
        .arg(fixture_path())
        .output()
        .expect("run packguard");

    assert!(
        output.status.success(),
        "exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("packguard-fixture-npm-basic"), "stdout: {stdout}");
    assert!(stdout.contains("react"), "stdout: {stdout}");
    assert!(stdout.contains("18.2.0"), "stdout: {stdout}");
    assert!(stdout.contains("@babel/core"), "stdout: {stdout}");
    assert!(stdout.contains("typescript"), "stdout: {stdout}");
}
