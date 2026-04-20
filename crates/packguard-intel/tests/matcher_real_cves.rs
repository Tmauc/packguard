//! Matching engine smoke tests against real OSV advisory shapes pulled from
//! https://osv.dev/. Each fixture captures the exact OSV JSON (trimmed to
//! the fields the matcher cares about) so parser + matcher stay honest
//! against the real wire format.

use packguard_core::Vulnerability;
use packguard_intel::match_vulnerabilities;
use packguard_intel::normalize::parse_advisory_json;

fn parse(raw: &str) -> Vec<Vulnerability> {
    parse_advisory_json(raw.as_bytes(), "osv").unwrap()
}

// ---- colors.js 1.4.1/1.4.2 — 2022 malicious release (GHSA-jmqm-f2gx-4fjv) ----
const COLORS_JS: &str = r#"{
    "id": "GHSA-jmqm-f2gx-4fjv",
    "aliases": ["CVE-2022-23806"],
    "summary": "colors.js publishes deliberately broken releases",
    "database_specific": {"severity": "HIGH"},
    "affected": [{
        "package": {"ecosystem": "npm", "name": "colors"},
        "versions": ["1.4.1", "1.4.2"]
    }]
}"#;

#[test]
fn colors_js_1_4_1_and_1_4_2_flagged() {
    let adv = parse(COLORS_JS);
    assert_eq!(
        match_vulnerabilities("npm", "colors", "1.4.1", &adv).len(),
        1
    );
    assert_eq!(
        match_vulnerabilities("npm", "colors", "1.4.2", &adv).len(),
        1
    );
    assert_eq!(
        match_vulnerabilities("npm", "colors", "1.4.0", &adv).len(),
        0,
        "1.4.0 is clean and must not match"
    );
}

// ---- event-stream 3.3.6 — 2018 supply-chain compromise ----
const EVENT_STREAM: &str = r#"{
    "id": "GHSA-mh6f-8j2x-4483",
    "aliases": ["CVE-2018-1002208"],
    "summary": "Malicious code in event-stream",
    "database_specific": {"severity": "HIGH"},
    "affected": [{
        "package": {"ecosystem": "npm", "name": "event-stream"},
        "ranges": [{"type": "SEMVER",
                    "events": [{"introduced": "3.3.6"}, {"last_affected": "3.3.6"}]}]
    }]
}"#;

#[test]
fn event_stream_3_3_6_flagged_3_3_5_clean() {
    let adv = parse(EVENT_STREAM);
    assert_eq!(
        match_vulnerabilities("npm", "event-stream", "3.3.6", &adv).len(),
        1
    );
    assert_eq!(
        match_vulnerabilities("npm", "event-stream", "3.3.5", &adv).len(),
        0
    );
    assert_eq!(
        match_vulnerabilities("npm", "event-stream", "4.0.0", &adv).len(),
        0
    );
}

// ---- ua-parser-js 0.7.29/0.8.0/1.0.0 — 2021 coinminer compromise ----
const UA_PARSER_JS: &str = r#"{
    "id": "GHSA-pjwm-rvh2-c87w",
    "aliases": ["CVE-2021-41265"],
    "summary": "Embedded malicious code in ua-parser-js",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"ecosystem": "npm", "name": "ua-parser-js"},
        "versions": ["0.7.29", "0.8.0", "1.0.0"]
    }]
}"#;

#[test]
fn ua_parser_js_flags_all_three_malicious_versions() {
    let adv = parse(UA_PARSER_JS);
    for v in ["0.7.29", "0.8.0", "1.0.0"] {
        let hits = match_vulnerabilities("npm", "ua-parser-js", v, &adv);
        assert_eq!(hits.len(), 1, "expected match on {v}");
        assert_eq!(hits[0].severity, packguard_core::Severity::Critical);
    }
    for v in ["0.7.28", "0.7.30", "1.0.1"] {
        assert!(
            match_vulnerabilities("npm", "ua-parser-js", v, &adv).is_empty(),
            "{v} must be clean"
        );
    }
}

// ---- Django CVE-2023-41164 (DOS via decode_idna) ----
const DJANGO_CVE_2023_41164: &str = r#"{
    "id": "PYSEC-2023-163",
    "aliases": ["CVE-2023-41164", "GHSA-q2rp-x3hg-5ccg"],
    "summary": "Django urlize / DoS via crafted value to decode_idna",
    "database_specific": {"severity": "MODERATE"},
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "Django"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1.11"}, {"fixed": "3.2.21"},
            {"introduced": "4.0"},  {"fixed": "4.1.11"},
            {"introduced": "4.2"},  {"fixed": "4.2.5"}
        ]}]
    }]
}"#;

#[test]
fn django_cve_2023_41164_hits_all_three_supported_branches() {
    let adv = parse(DJANGO_CVE_2023_41164);
    // Vulnerable windows.
    for v in ["3.2.20", "4.1.10", "4.2.4"] {
        assert_eq!(
            match_vulnerabilities("pypi", "django", v, &adv).len(),
            1,
            "expected match on {v}"
        );
    }
    // First safe fixes.
    for v in ["3.2.21", "4.1.11", "4.2.5"] {
        assert_eq!(
            match_vulnerabilities("pypi", "django", v, &adv).len(),
            0,
            "expected clean on {v}"
        );
    }
    // Below any introduced branch.
    assert_eq!(
        match_vulnerabilities("pypi", "django", "1.10.8", &adv).len(),
        0
    );
}

// ---- Pillow CVE-2023-50447 ----
const PILLOW_CVE_2023_50447: &str = r#"{
    "id": "PYSEC-2024-6",
    "aliases": ["CVE-2023-50447", "GHSA-3f63-hfp8-52jq"],
    "summary": "Pillow PIL.ImageMath.eval arbitrary code execution",
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "HIGH"},
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "Pillow"},
        "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "10.2.0"}
        ]}]
    }]
}"#;

#[test]
fn pillow_cve_2023_50447_hits_pre_10_2_0() {
    let adv = parse(PILLOW_CVE_2023_50447);
    // PEP 503 normalization lowercases the package name.
    assert_eq!(
        match_vulnerabilities("pypi", "pillow", "10.1.0", &adv).len(),
        1
    );
    assert_eq!(
        match_vulnerabilities("pypi", "pillow", "10.2.0", &adv).len(),
        0
    );
    assert_eq!(
        match_vulnerabilities("pypi", "pillow", "9.5.0", &adv).len(),
        1
    );
}

// ---- Cross-source dedup: OSV + GHSA both know about the same CVE ----
#[test]
fn osv_and_ghsa_collapsed_to_one_match_via_alias() {
    // Same CVE, two advisories, two sources. After dedup only the
    // highest-severity (GHSA HIGH) survives, even though the OSV record came
    // first in the input.
    let osv = parse(
        r#"{
            "id": "PYSEC-987", "aliases": ["CVE-2024-9999"],
            "database_specific": {"severity": "MODERATE"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]
        }"#,
    );
    let mut ghsa = packguard_intel::normalize::parse_advisory_json(
        r#"{
            "id": "GHSA-abcd-efgh-ijkl", "aliases": ["CVE-2024-9999"],
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]
        }"#
        .as_bytes(),
        "ghsa",
    )
    .unwrap();
    let mut all = osv;
    all.append(&mut ghsa);

    let out = match_vulnerabilities("pypi", "requests", "2.31.0", &all);
    assert_eq!(out.len(), 1, "dedup should keep exactly one representative");
    assert_eq!(out[0].severity, packguard_core::Severity::High);
    assert_eq!(out[0].source, "ghsa");
}
