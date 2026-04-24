//! Integration tests for `packguard actions` (Phase 12c).
//!
//! Seeds a tiny store with:
//!   - lodash@4.17.20 affected by a HIGH CVE (fixed in 4.17.21)
//!   - posthog-js@1.82.0 flagged as malware
//!
//! Then invokes the CLI binary and asserts on output shape.

use packguard_core::model::{
    AffectedEvent, AffectedRange, AffectedRangeKind, AffectedSpec, DepKind, Dependency,
    MalwareKind, MalwareReport, Project, RemotePackage, Severity, Vulnerability,
};
use packguard_store::Store;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const PERMISSIVE_POLICY_YAML: &str = "defaults:\n  offset:\n    major: 0\n    minor: 0\n    patch: 0\n  stability: stable\n  min_age_days: 0\n  block:\n    cve_severity: [high, critical]\n    malware: true\n    deprecated: true\n    yanked: true\n    typosquat: warn\n";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn seed(store_path: &Path, repo: &Path) {
    // Drop lockfile + permissive policy so the generator emits actions
    // with a concrete suggested_command (pnpm) and actual recommended
    // versions instead of InsufficientCandidates.
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    std::fs::write(repo.join(".packguard.yml"), PERMISSIVE_POLICY_YAML).unwrap();

    let mut store = Store::open(store_path).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo.to_path_buf(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![
            Dependency {
                name: "lodash".into(),
                declared_range: "^4.17.0".into(),
                installed: Some("4.17.20".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("pnpm-lock.yaml".into()),
            },
            Dependency {
                name: "posthog-js".into(),
                declared_range: "^1.82.0".into(),
                installed: Some("1.82.0".into()),
                kind: DepKind::Runtime,
                source_lockfile: Some("pnpm-lock.yaml".into()),
            },
        ],
        edges: Vec::new(),
        compatibility: Vec::new(),
    };
    let mut remotes = BTreeMap::new();
    remotes.insert(
        "lodash".into(),
        RemotePackage {
            name: "lodash".into(),
            latest: Some("4.17.21".into()),
            latest_published_at: Some("2024-06-01T00:00:00Z".into()),
            versions: vec![
                packguard_core::RemoteVersion {
                    version: "4.17.20".into(),
                    published_at: Some("2020-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
                packguard_core::RemoteVersion {
                    version: "4.17.21".into(),
                    published_at: Some("2021-03-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
            ],
        },
    );
    remotes.insert(
        "posthog-js".into(),
        RemotePackage {
            name: "posthog-js".into(),
            latest: Some("1.83.1".into()),
            latest_published_at: Some("2024-01-01T00:00:00Z".into()),
            versions: vec![
                packguard_core::RemoteVersion {
                    version: "1.82.0".into(),
                    published_at: Some("2023-12-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
                packguard_core::RemoteVersion {
                    version: "1.83.1".into(),
                    published_at: Some("2024-01-01T00:00:00Z".into()),
                    deprecated: false,
                    yanked: false,
                },
            ],
        },
    );
    store
        .save_project(repo, &project, &remotes, "fp-1")
        .unwrap();

    let vuln = Vulnerability {
        source: "osv".into(),
        advisory_id: "GHSA-35jh-r3h4-6jhm".into(),
        ecosystem: "npm".into(),
        package_name: "lodash".into(),
        severity: Severity::High,
        cve_id: Some("CVE-2021-23337".into()),
        aliases: vec!["CVE-2021-23337".into()],
        summary: Some("Command Injection in lodash".into()),
        url: Some("https://github.com/advisories/GHSA-35jh-r3h4-6jhm".into()),
        affected: AffectedSpec {
            ranges: vec![AffectedRange {
                kind: AffectedRangeKind::Semver,
                events: vec![
                    AffectedEvent::Introduced("0.0.0".into()),
                    AffectedEvent::Fixed("4.17.21".into()),
                ],
            }],
            versions: vec![],
        },
        fixed_versions: vec!["4.17.21".into()],
        published_at: Some("2021-02-15T00:00:00Z".into()),
        modified_at: None,
    };
    store.persist_vulnerabilities(&[vuln]).unwrap();

    let malware = MalwareReport {
        source: "osv-mal".into(),
        ref_id: "MAL-2026-12".into(),
        ecosystem: "npm".into(),
        package_name: "posthog-js".into(),
        version: "1.82.0".into(),
        kind: MalwareKind::Malware,
        summary: Some("Compromised release".into()),
        url: None,
        evidence: serde_json::json!({}),
        reported_at: None,
    };
    store.persist_malware_reports(&[malware]).unwrap();
}

struct Env {
    _tmp: tempfile::TempDir,
    store: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store.db");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    seed(&store, &repo);
    Env { _tmp: tmp, store }
}

fn run_actions(env: &Env, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .arg("--store")
        .arg(&env.store)
        .arg("actions")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_actions_list_default_table_format_renders_severity_groups() {
    let env = env();
    let out = run_actions(&env, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    // Severity group headers for the seeded fixture (1 malware, 1 high
    // cve). Phase 12-fix: FixMalware lives on its own top tier above
    // Critical now.
    assert!(
        s.contains("MALWARE"),
        "expected MALWARE severity group: {s}"
    );
    assert!(s.contains("HIGH"), "expected HIGH severity group: {s}");
    assert!(s.contains("lodash"));
    assert!(s.contains("posthog-js"));
    // Severity column renders the plain label.
    assert!(s.contains("malware") && s.contains("high"));
    // Footer line with the dismiss hint.
    assert!(
        s.contains("packguard actions dismiss"),
        "expected footer hint: {s}"
    );
}

#[test]
fn cli_actions_list_json_format_includes_all_fields() {
    let env = env();
    let out = run_actions(&env, &["--format", "json"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let actions = parsed["actions"].as_array().unwrap();
    assert!(
        actions.iter().any(|a| a["kind"] == "FixCveHigh"),
        "expected FixCveHigh in json: {parsed}"
    );
    assert!(
        actions.iter().any(|a| a["kind"] == "FixMalware"),
        "expected FixMalware in json: {parsed}"
    );
    // Every row carries the DTO fields ts-rs generates against.
    for a in actions {
        assert!(a["id"].is_string());
        assert!(a["severity"].is_string());
        assert!(a["workspace"].is_string());
        assert!(a["target"].is_object());
        assert!(a["title"].is_string());
    }
    // `total` mirrors /api/actions.
    assert_eq!(parsed["total"], actions.len() as i64);
}

#[test]
fn cli_actions_list_sarif_emits_valid_v2_1_schema() {
    let env = env();
    let out = run_actions(&env, &["--format", "sarif"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif-schema-2.1.0"));
    let runs = parsed["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["tool"]["driver"]["name"], "packguard");
    let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(
        rules.iter().any(|r| r["id"] == "packguard/fix-cve-high"),
        "expected packguard/fix-cve-high rule: {parsed}"
    );
    let results = runs[0]["results"].as_array().unwrap();
    assert!(!results.is_empty(), "sarif results should not be empty");
    for r in results {
        // Every result has a ruleId, level, and at least one location.
        assert!(r["ruleId"].as_str().unwrap().starts_with("packguard/"));
        assert!(r["level"].is_string());
        assert!(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string());
    }
}

#[test]
fn cli_actions_list_sarif_level_mapping_matches_severity() {
    let env = env();
    let out = run_actions(&env, &["--format", "sarif"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    for r in results {
        let rule = r["ruleId"].as_str().unwrap();
        let level = r["level"].as_str().unwrap();
        // Per brief: Malware/Critical/High → error, Medium → warning,
        // Low/Info → note. Our fixture exercises critical (malware),
        // high (cve-high), and info (refresh-sync never triggers in
        // this fixture since sync_log is empty — a `never-synced`
        // refresh also maps to Info).
        let expected = match rule {
            "packguard/fix-malware" | "packguard/fix-cve-critical" | "packguard/fix-cve-high" => {
                "error"
            }
            "packguard/clear-violation" | "packguard/resolve-insufficient" => "warning",
            _ => "note",
        };
        assert_eq!(level, expected, "wrong level for {rule}: {r}");
    }
}

#[test]
fn cli_actions_list_sarif_partial_fingerprints_includes_cve_id_for_cve_actions() {
    let env = env();
    let out = run_actions(&env, &["--format", "sarif"]);
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    let cve_result = results
        .iter()
        .find(|r| r["ruleId"] == "packguard/fix-cve-high")
        .expect("fixture seeds one FixCveHigh action");
    let fp = &cve_result["partialFingerprints"];
    assert!(
        fp["packguard.actionId"].is_string(),
        "every result carries actionId: {cve_result}"
    );
    // CVE-2021-23337 is pulled from the title `{name}@{ver} → fix CVE-...`.
    assert_eq!(
        fp["cveId"].as_str(),
        Some("CVE-2021-23337"),
        "cveId missing for CVE action: {cve_result}"
    );
    // Malware action has no CVE id — the key should be absent (not null).
    let mal_result = results
        .iter()
        .find(|r| r["ruleId"] == "packguard/fix-malware")
        .expect("fixture seeds one FixMalware action");
    assert!(
        mal_result["partialFingerprints"]["cveId"].is_null(),
        "malware result should not carry cveId: {mal_result}"
    );
}

#[test]
fn cli_actions_list_min_severity_filter_drops_lower_rows_from_output() {
    // Fixture has one Malware (FixMalware) and one High (FixCveHigh).
    // `--min-severity malware` should leave only the malware row in
    // the JSON payload.
    let env = env();
    let out = run_actions(&env, &["--format", "json", "--min-severity", "malware"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let actions = parsed["actions"].as_array().unwrap();
    assert!(!actions.is_empty());
    assert!(
        actions.iter().all(|a| a["severity"] == "Malware"),
        "min_severity=malware leaked non-malware rows: {parsed}"
    );
}

// ---- Phase 12c commit 3: dismiss / defer / restore + fail-on-severity -----

fn first_action_id(env: &Env) -> String {
    let out = run_actions(env, &["--format", "json"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    parsed["actions"][0]["id"].as_str().unwrap().to_string()
}

#[test]
fn cli_actions_dismiss_by_prefix_exact_match_succeeds() {
    let env = env();
    let id = first_action_id(&env);
    let prefix = &id[..8];
    let out = run_actions(&env, &["dismiss", prefix, "--reason", "accepted risk"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("dismissed"),
        "expected dismiss banner: {stdout}"
    );
    // The dismissed action should be gone from the default list.
    let list = run_actions(&env, &["--format", "json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        parsed["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["id"] != id),
        "dismissed action must not resurface: {parsed}"
    );
    // But --include-dismissed brings it back.
    let list = run_actions(&env, &["--format", "json", "--include-dismissed"]);
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        parsed["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == id && !a["dismissed_at"].is_null()),
        "dismissed row missing dismissed_at in --include-dismissed mode: {parsed}"
    );
}

#[test]
fn cli_actions_dismiss_by_prefix_no_match_errors_with_exit_1() {
    let env = env();
    let out = run_actions(&env, &["dismiss", "deadbeefcafe"]);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no action matches prefix"),
        "expected no-match error: {stderr}"
    );
}

#[test]
fn cli_actions_dismiss_by_prefix_too_short_errors() {
    // Under 6 chars — the CLI should refuse rather than trust whatever
    // lands.
    let env = env();
    let out = run_actions(&env, &["dismiss", "abc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("at least 6 hex"),
        "expected too-short error: {stderr}"
    );
}

#[test]
fn cli_actions_defer_sets_deferred_until_in_future() {
    let env = env();
    let id = first_action_id(&env);
    let prefix = &id[..8];
    let out = run_actions(&env, &["defer", prefix, "--days", "7"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Default list now hides the deferred row.
    let list = run_actions(&env, &["--format", "json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(parsed["actions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["id"] != id));
    // `--include-deferred` surfaces it with deferred_until populated.
    let list = run_actions(&env, &["--format", "json", "--include-deferred"]);
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let row = parsed["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == id)
        .expect("deferred row missing");
    let until = row["deferred_until"]
        .as_str()
        .expect("deferred_until must be a RFC3339 string");
    let parsed_until = chrono::DateTime::parse_from_rfc3339(until).expect("valid RFC3339");
    assert!(
        parsed_until.to_utc() > chrono::Utc::now(),
        "deferred_until must lie in the future: {until}"
    );
}

#[test]
fn cli_actions_restore_clears_dismissal() {
    let env = env();
    let id = first_action_id(&env);
    let prefix = &id[..8];
    // Dismiss then restore.
    let out = run_actions(&env, &["dismiss", prefix]);
    assert!(out.status.success());
    let out = run_actions(&env, &["restore", prefix]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The action must be back in the default (non-archived) list.
    let list = run_actions(&env, &["--format", "json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        parsed["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == id),
        "restored action must resurface: {parsed}"
    );
}

#[test]
fn cli_actions_fail_on_severity_high_exits_1_when_high_action_present() {
    let env = env();
    let out = run_actions(&env, &["--fail-on-severity", "high"]);
    assert!(!out.status.success(), "expected non-zero exit");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn cli_actions_fail_on_severity_malware_exits_0_when_no_malware_rows_remain() {
    // Fixture ships 1 malware + 1 high cve. Dismiss the malware →
    // remaining max severity = high → `--fail-on-severity malware`
    // should pass (exit 0). Proves Phase 12-fix commit 1 gave malware
    // its own CI gate independent of Critical.
    let env = env();
    let out = run_actions(&env, &["--format", "json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let malware_id = parsed["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["severity"] == "Malware")
        .expect("fixture seeds a malware row")["id"]
        .as_str()
        .unwrap()
        .to_string();

    let out = run_actions(&env, &["dismiss", &malware_id[..8]]);
    assert!(out.status.success());

    let out = run_actions(&env, &["--fail-on-severity", "malware"]);
    assert!(
        out.status.success(),
        "with no malware rows left, the gate must pass; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_actions_fail_on_severity_malware_exits_1_when_malware_active() {
    // Fixture has 1 active malware → gate fires.
    let env = env();
    let out = run_actions(&env, &["--fail-on-severity", "malware"]);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
}
