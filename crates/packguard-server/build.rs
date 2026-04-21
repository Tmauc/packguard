//! Build script for the `ui-embed` feature. Runs `pnpm --dir <dashboard>
//! build` so the release binary carries a fresh Vite bundle. Skipped in
//! every case where rebuilding the front-end would either be wasteful
//! (debug profile, feature off) or already handled outside cargo
//! (`PACKGUARD_SKIP_UI_BUILD=1` in CI pipelines that pre-build the UI).

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Re-run the script when these inputs change. We deliberately do not
    // watch the entire dashboard source tree — that would slow down
    // incremental rebuilds for every CSS tweak. The build runs once per
    // release profile and is invalidated manually via `cargo clean`.
    println!("cargo:rerun-if-env-changed=PACKGUARD_SKIP_UI_BUILD");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-changed=build.rs");

    // Only invoke pnpm when the feature is enabled AND we're in a release
    // profile. Debug builds use the Vite dev server at localhost:5173.
    if std::env::var_os("CARGO_FEATURE_UI_EMBED").is_none() {
        return;
    }
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    if std::env::var_os("PACKGUARD_SKIP_UI_BUILD").is_some() {
        println!(
            "cargo:warning=PACKGUARD_SKIP_UI_BUILD set — skipping pnpm build, \
             trusting a pre-built dashboard/dist/"
        );
        return;
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dashboard = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("dashboard"))
        .expect("locating workspace root from packguard-server");

    let dist = dashboard.join("dist");
    if dist.join("index.html").exists() && std::env::var_os("PACKGUARD_REBUILD_UI").is_none() {
        println!(
            "cargo:warning=dashboard/dist already present — skipping pnpm build \
             (set PACKGUARD_REBUILD_UI=1 to force)"
        );
        return;
    }

    println!(
        "cargo:warning=running pnpm build in {}",
        dashboard.display()
    );
    let status = Command::new("pnpm")
        .arg("--dir")
        .arg(&dashboard)
        .arg("build")
        .status()
        .expect("pnpm not available — install it or set PACKGUARD_SKIP_UI_BUILD=1");
    if !status.success() {
        panic!("pnpm build failed with status {status}");
    }
}
