//! Phase 14.2c — end-to-end coverage of the slug-resolution chain.
//!
//! Each test boots the actual `packguard` binary against a clean
//! `PACKGUARD_HOME` and asserts on stderr (banners + deprecation
//! warnings) and on which on-disk store the CLI ended up writing to.
//! The legacy `<home>/store.db` MD5 is checked at the end of every
//! test that exercises a write path, so a regression where any CLI
//! command sneaks back to the legacy file fails loudly.

use packguard_core::model::{DepKind, Dependency, Project, RemotePackage};
use packguard_store::{ProjectsRegistry, Store};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_packguard")
}

fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// MD5 of a file's bytes, hex-encoded. The smoke step #6 in the brief
/// uses `md5(1)` for the same purpose; we want a pure-Rust check here
/// so the test is portable. Implemented manually because there's no md5
/// crate in the workspace and the zero-new-dep policy stands.
fn file_md5(path: &Path) -> String {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .expect("open file for md5")
        .read_to_end(&mut bytes)
        .expect("read file for md5");
    md5_hex(&bytes)
}

/// Toy MD5 — we only use it as a tamper-evident fingerprint, not for
/// any cryptographic purpose. The test fails the same way whether
/// the legacy store changed by one byte or by one megabyte; we just
/// need a stable hash that's cheaper to write than vendoring a crate.
fn md5_hex(input: &[u8]) -> String {
    use std::fmt::Write;
    // Standard MD5 constants.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let original_len_bits = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&original_len_bits.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) =
        (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f);
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = String::with_capacity(32);
    for word in [a0, b0, c0, d0] {
        for byte in word.to_le_bytes() {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out
}

/// Seed a legacy `<home>/store.db` with one repo + one dep so the
/// boot-time migration creates a populated `_default_` per-project
/// store on first CLI run. Returns the home + repo paths.
fn seed_legacy_with_default_repo(home: &Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(home).unwrap();
    let store_path = home.join("store.db");
    // The repo lives outside any git tree on purpose so the migration
    // partitions it into the `_default_` slug — matching how a v0.5.x
    // user with non-git scan paths gets folded into `_default_`.
    let repo = home.join("legacy-repo");
    std::fs::create_dir_all(&repo).unwrap();

    let mut store = Store::open(&store_path).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo.clone(),
        manifest_path: repo.join("package.json"),
        name: Some("legacy-demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "lodash".into(),
            declared_range: "^4.17.0".into(),
            installed: Some("4.17.20".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("package-lock.json".into()),
        }],
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
            versions: vec![],
        },
    );
    store
        .save_project(&repo, &project, &remotes, "fp-legacy-seed")
        .unwrap();
    (store_path, repo)
}

#[test]
fn cli_audit_uses_slug_from_explicit_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let (store_path, _repo) = seed_legacy_with_default_repo(tmp.path());

    // First invocation: triggers boot migration → `_default_` per-project
    // store now holds the seeded scan. Use `audit` to confirm the slug
    // we passed actually drives the lookup.
    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .args(["--project", "_default_"])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("project _default_") && stderr.contains("explicit slug"),
        "expected explicit-slug banner: {stderr}"
    );
}

#[test]
fn cli_audit_uses_slug_from_env_var_when_no_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let (store_path, _repo) = seed_legacy_with_default_repo(tmp.path());

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .current_dir(tmp.path())
        .env("PACKGUARD_PROJECT", "_default_")
        .output()
        .unwrap();
    assert!(out.status.success(), "audit failed: {:?}", out.stderr);
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("from PACKGUARD_PROJECT"),
        "expected env-var banner: {stderr}"
    );
}

#[test]
fn cli_scan_walks_up_cwd_to_detect_project_slug() {
    // Build a tempdir hierarchy with a `.git/` at the top so the
    // resolver picks a non-`_default_` slug. The scan target is a
    // subdirectory of that repo.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("pg-home");
    std::fs::create_dir_all(&home).unwrap();
    let repo = tmp.path().join("git-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"demo","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();
    let store_path = home.join("store.db");

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["scan", repo.to_str().unwrap()])
        .current_dir(&repo)
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    // The slug is derived from the canonical repo path (under
    // /private/var on macOS); we just check the human-readable last
    // path segment lands in the slug.
    assert!(
        stderr.contains("git-repo") && stderr.contains("auto-detected from cwd"),
        "expected cwd-walk-up banner: {stderr}"
    );
    // And the per-project store landed under the expected slug —
    // `<home>/projects/<contains-git-repo>/store.db`.
    let projects_dir = home.join("projects");
    let entries: Vec<_> = std::fs::read_dir(&projects_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|s| s.contains("git-repo")),
        "expected a slug dir containing 'git-repo': {entries:?}"
    );
}

#[test]
fn cli_audit_falls_back_to_default_slug_when_no_git_ancestor() {
    let tmp = tempfile::tempdir().unwrap();
    let (store_path, _repo) = seed_legacy_with_default_repo(tmp.path());

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(out.status.success(), "audit failed: {:?}", out.stderr);
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("project _default_") && stderr.contains("fallback (no .git/ ancestor)"),
        "expected default-fallback banner: {stderr}"
    );
}

#[test]
fn cli_audit_with_legacy_path_flag_emits_deprecation_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let (store_path, repo) = seed_legacy_with_default_repo(tmp.path());

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .arg("--project")
        .arg(&repo)
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(out.status.success(), "audit failed: {:?}", out.stderr);
    let stderr = strip_ansi(&String::from_utf8(out.stderr).unwrap());
    assert!(
        stderr.contains("(deprecated path form)"),
        "expected deprecated path form banner: {stderr}"
    );
    assert!(
        stderr.contains("`--project <path>` is deprecated"),
        "expected deprecation warning: {stderr}"
    );
}

#[test]
fn cli_audit_reads_per_project_store_via_resolved_slug() {
    // Seed the per-project store directly (no legacy file at all) and
    // make sure the resolver's output drives the read path.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let store_path = home.join("store.db");
    let repo = home.join("repo");
    std::fs::create_dir_all(&repo).unwrap();

    // Mark the home as already-migrated so the boot migration is a
    // no-op (no legacy file to copy from anyway).
    let _intel = packguard_store::IntelStore::open(home).unwrap();
    let mut registry = ProjectsRegistry::open(home).unwrap();
    registry
        .insert_with_slug("_default_", home, "_default_")
        .unwrap();
    let project_db = home.join("projects/_default_/store.db");
    std::fs::create_dir_all(project_db.parent().unwrap()).unwrap();
    let mut pstore = Store::open(&project_db).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo.clone(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "lodash".into(),
            declared_range: "^4.17.0".into(),
            installed: Some("4.17.20".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("package-lock.json".into()),
        }],
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
            versions: vec![],
        },
    );
    pstore
        .save_project(&repo, &project, &remotes, "fp-pp")
        .unwrap();
    drop(pstore);

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .arg(&repo)
        .current_dir(home)
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Output is JSON — parse to confirm the resolver actually opened
    // the per-project store (otherwise the audit would have errored
    // with "no cached scan").
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        parsed.get("cve").is_some(),
        "audit JSON missing `cve` key — resolver likely opened the wrong store: {parsed}"
    );
}

#[test]
fn cli_does_not_touch_legacy_store_db_after_scan_audit_dismiss() {
    // Smoke #6 + #7 from the brief, narrowed to a single test process:
    // record the legacy MD5, run a representative read + write loop,
    // and assert the bytes never change. After 14.2d.3 the first CLI
    // boot also renames `<home>/store.db` → `<home>/store.db.v0.5-backup`,
    // so the byte-identity check tracks whichever path currently holds
    // the legacy bytes (helper below).
    let tmp = tempfile::tempdir().unwrap();
    let (store_path, _repo) = seed_legacy_with_default_repo(tmp.path());
    let baseline = file_md5(&store_path);

    // 1. read path: scans (fans out across per-project stores).
    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["scans", "--json"])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scans failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        legacy_md5(tmp.path()),
        baseline,
        "scans changed the legacy bytes",
    );

    // 2. read path: audit on the seeded `_default_` project.
    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["audit", "--no-live-fallback", "--format", "json"])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        legacy_md5(tmp.path()),
        baseline,
        "audit changed the legacy bytes",
    );

    // 3. write path: re-scan a non-git dir under tmp. The CLI must
    //    update the per-project store, never the legacy.
    let scan_target = tmp.path().join("rescan");
    std::fs::create_dir_all(&scan_target).unwrap();
    std::fs::write(
        scan_target.join("package.json"),
        r#"{"name":"x","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        scan_target.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["scan", scan_target.to_str().unwrap()])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        legacy_md5(tmp.path()),
        baseline,
        "scan changed the legacy bytes",
    );
}

/// Returns the MD5 of whichever path currently holds the legacy bytes
/// — `<home>/store.db` before the cutover, `<home>/store.db.v0.5-backup`
/// after 14.2d.3 has run. Either way the bytes themselves never change.
fn legacy_md5(home: &Path) -> String {
    let backup = home.join("store.db.v0.5-backup");
    if backup.is_file() {
        return file_md5(&backup);
    }
    file_md5(&home.join("store.db"))
}

#[test]
fn cli_actions_dismiss_writes_to_per_project_store_only() {
    // Pre-seed the per-project store with a CVE-bearing dep so the
    // actions engine emits at least one row to dismiss.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let store_path = home.join("store.db");
    let repo = home.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("pnpm-lock.yaml"), b"").unwrap();
    std::fs::write(
        repo.join(".packguard.yml"),
        "defaults:\n  block:\n    cve_severity: [high, critical]\n    malware: true\n",
    )
    .unwrap();

    let _intel_init = packguard_store::IntelStore::open(home).unwrap();
    let mut registry = ProjectsRegistry::open(home).unwrap();
    registry
        .insert_with_slug("_default_", home, "_default_")
        .unwrap();
    let project_db = home.join("projects/_default_/store.db");
    std::fs::create_dir_all(project_db.parent().unwrap()).unwrap();
    let mut pstore = Store::open(&project_db).unwrap();
    let project = Project {
        ecosystem: "npm",
        root: repo.clone(),
        manifest_path: repo.join("package.json"),
        name: Some("demo".into()),
        workspace: None,
        dependencies: vec![Dependency {
            name: "lodash".into(),
            declared_range: "^4.17.0".into(),
            installed: Some("4.17.20".into()),
            kind: DepKind::Runtime,
            source_lockfile: Some("pnpm-lock.yaml".into()),
        }],
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
            versions: vec![packguard_core::RemoteVersion {
                version: "4.17.21".into(),
                published_at: Some("2021-03-01T00:00:00Z".into()),
                deprecated: false,
                yanked: false,
            }],
        },
    );
    pstore
        .save_project(&repo, &project, &remotes, "fp-pp-dismiss")
        .unwrap();
    drop(pstore);

    // Seed a HIGH advisory in IntelStore so the actions engine has
    // something to surface for the lodash@4.17.20 row.
    let mut intel = packguard_store::IntelStore::open(home).unwrap();
    intel
        .persist_vulnerabilities(&[packguard_core::Vulnerability {
            source: "osv".into(),
            advisory_id: "GHSA-pp-only-1".into(),
            ecosystem: "npm".into(),
            package_name: "lodash".into(),
            severity: packguard_core::Severity::High,
            cve_id: Some("CVE-2021-23337".into()),
            aliases: vec!["CVE-2021-23337".into()],
            summary: Some("dismiss-me".into()),
            url: None,
            affected: packguard_core::model::AffectedSpec {
                ranges: vec![packguard_core::model::AffectedRange {
                    kind: packguard_core::model::AffectedRangeKind::Semver,
                    events: vec![
                        packguard_core::model::AffectedEvent::Introduced("0.0.0".into()),
                        packguard_core::model::AffectedEvent::Fixed("4.17.21".into()),
                    ],
                }],
                versions: vec![],
            },
            fixed_versions: vec!["4.17.21".into()],
            published_at: None,
            modified_at: None,
        }])
        .unwrap();

    // Touch the legacy store path with a sentinel byte so we can
    // detect any write — `--store` derives the home from this path's
    // parent, but no command should ever open it for write.
    std::fs::write(&store_path, b"sentinel").unwrap();
    let baseline = file_md5(&store_path);

    // List actions to grab a real id prefix.
    let list = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["actions", "--format", "json"])
        .current_dir(home)
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "actions list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let id = parsed["actions"][0]["id"]
        .as_str()
        .expect("at least one action expected from the seeded HIGH CVE")
        .to_string();
    let prefix = &id[..8];

    let dismiss = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["actions", "dismiss", prefix])
        .current_dir(home)
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        dismiss.status.success(),
        "dismiss failed: {}",
        String::from_utf8_lossy(&dismiss.stderr)
    );

    // The sentinel bytes must survive the boot (rename moves them to
    // `.v0.5-backup` post-14.2d.3, but never modifies the content).
    assert_eq!(
        legacy_md5(home),
        baseline,
        "actions dismiss changed the legacy bytes",
    );

    // The per-project store must hold the new dismissal row — verify
    // by opening it directly and counting active dismissals.
    let pstore = Store::open(&project_db).unwrap();
    let active = pstore
        .load_active_dismissals(None, chrono::Utc::now().timestamp())
        .unwrap();
    assert!(
        active.iter().any(|d| d.id == id),
        "dismissed action missing from per-project store: {active:?}"
    );
}

#[test]
fn cli_scan_falls_back_to_default_when_no_git_ancestor_creates_default_registry_row() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("pg-home");
    std::fs::create_dir_all(&home).unwrap();
    let repo = tmp.path().join("loose-dir");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"x","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
    )
    .unwrap();
    let store_path = home.join("store.db");

    let out = Command::new(bin())
        .arg("--store")
        .arg(&store_path)
        .args(["scan", repo.to_str().unwrap()])
        .current_dir(tmp.path())
        .env_remove("PACKGUARD_PROJECT")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // After the scan, the registry must have a `_default_` row even
    // though no legacy migration ran (fresh home, no `<home>/store.db`
    // to start with — the file is created by `Store::open` in the
    // scan path, but the migration's idempotence marker is the
    // registry row itself).
    let registry = ProjectsRegistry::open(&home).unwrap();
    let row = registry.get_by_slug("_default_").unwrap();
    assert!(
        row.is_some(),
        "ensure_default_registered must have inserted `_default_`"
    );
}
