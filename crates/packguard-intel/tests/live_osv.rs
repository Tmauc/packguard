//! Live tests that hit real remote endpoints (api.osv.dev,
//! registry.npmjs.org, pypi.org, osv-vulnerabilities.storage.googleapis.com,
//! GitHub). They are opt-in via `PACKGUARD_LIVE_TESTS=1` so the default
//! `cargo test` stays offline-friendly and CI doesn't flake on the network.
//!
//! Resolves tech-debt #4 (Phase 1 report).

use packguard_intel::osv_api::OsvApiClient;

fn live_enabled() -> bool {
    matches!(std::env::var("PACKGUARD_LIVE_TESTS").as_deref(), Ok("1"))
}

#[tokio::test]
async fn live_osv_api_returns_known_lodash_cve() {
    if !live_enabled() {
        eprintln!("skipping (set PACKGUARD_LIVE_TESTS=1 to run)");
        return;
    }
    let client = OsvApiClient::new().expect("build client");
    let vulns = client
        .query("npm", "lodash", "4.17.20")
        .await
        .expect("query OSV API");
    // lodash 4.17.20 is publicly known to have CVE-2021-23337 — the API
    // should return at least one advisory with that alias.
    assert!(
        vulns
            .iter()
            .any(|v| v.aliases.iter().any(|a| a == "CVE-2021-23337")
                || v.cve_id.as_deref() == Some("CVE-2021-23337")),
        "expected CVE-2021-23337 in live OSV response, got {vulns:?}"
    );
}

#[tokio::test]
async fn live_osv_api_returns_empty_for_clean_version() {
    if !live_enabled() {
        eprintln!("skipping (set PACKGUARD_LIVE_TESTS=1 to run)");
        return;
    }
    let client = OsvApiClient::new().expect("build client");
    // A non-existent name on npm should yield no advisories.
    let vulns = client
        .query("npm", "packguard-probably-never-published-abc123", "1.0.0")
        .await
        .expect("query OSV API");
    assert!(vulns.is_empty(), "expected empty but got {vulns:?}");
}
