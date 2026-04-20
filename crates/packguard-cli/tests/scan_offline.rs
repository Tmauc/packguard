//! Offline smoke tests: `packguard scan --offline` against fixtures.
//! Avoids network; validates CLI wiring end-to-end per ecosystem.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn fixtures_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn run_offline(subdir: &str) -> (bool, String, String) {
    let output = Command::new(bin())
        .args(["scan", "--offline"])
        .arg(fixtures_root().join(subdir))
        .output()
        .expect("run packguard");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn scan_offline_npm_basic() {
    let (ok, stdout, stderr) = run_offline("npm-basic");
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("packguard-fixture-npm-basic"), "stdout: {stdout}");
    assert!(stdout.contains("react"));
    assert!(stdout.contains("18.2.0"));
    assert!(stdout.contains("@babel/core"));
    assert!(stdout.contains("typescript"));
}

#[test]
fn scan_offline_pypi_poetry() {
    let (ok, stdout, stderr) = run_offline("pypi-poetry");
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("packguard-fixture-pypi-poetry"));
    assert!(stdout.contains("django"));
    assert!(stdout.contains("4.2.7"));
    assert!(stdout.contains("pytest"));
}

#[test]
fn scan_offline_pypi_uv() {
    let (ok, stdout, stderr) = run_offline("pypi-uv");
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("fastapi"));
    assert!(stdout.contains("0.110.0"));
    assert!(stdout.contains("pydantic"));
    assert!(stdout.contains("2.5.0"));
}

#[test]
fn scan_offline_pypi_pip_declared_only() {
    let (ok, stdout, stderr) = run_offline("pypi-pip");
    assert!(ok, "stderr={stderr}");
    // == pins resolve as installed
    assert!(stdout.contains("django"));
    assert!(stdout.contains("4.2.7"));
    assert!(stdout.contains("requests"));
    // flake8>=7.0 has no installed version (declared-only limitation)
    assert!(stdout.contains("flake8"));
}
