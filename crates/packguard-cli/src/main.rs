use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_core::model::{Delta, DepKind, Project, RemotePackage};
use packguard_core::{default_ecosystems, Ecosystem};
use packguard_intel::{match_vulnerabilities, MatchedVuln};
use packguard_policy::{
    evaluate_dependency_with_vulns, parse_policy, Compliance, Dialect, Policy, ReleaseInfo,
    VulnsByVersion,
};
use packguard_store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "packguard",
    version,
    about = "Local package version governance"
)]
struct Cli {
    /// SQLite store location. Defaults to `~/.packguard/store.db`.
    #[arg(long, global = true)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a `.packguard.yml` with conservative defaults.
    Init {
        /// Path to the project root. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Overwrite an existing `.packguard.yml`.
        #[arg(long)]
        force: bool,
    },
    /// Render a compliance report from the SQLite store. Zero network.
    Report {
        /// Path to the repo root whose cached scan should be reported on.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ReportFormat::Table)]
        format: ReportFormat,
        /// Exit with status 1 when at least one blocking violation exists.
        #[arg(long)]
        fail_on_violation: bool,
    },
    /// Refresh vulnerability intel (OSV dumps + GHSA git repo) into the store.
    Sync {
        /// Skip the OSV HTTP dumps (useful when only GHSA is wanted).
        #[arg(long)]
        skip_osv: bool,
        /// Skip the GHSA git clone/pull (useful when `git` is unavailable
        /// or the cache lives on a read-only volume).
        #[arg(long)]
        skip_ghsa: bool,
        /// Override the GHSA cache location. Defaults to
        /// `~/.packguard/cache/ghsa/advisory-database`.
        #[arg(long)]
        ghsa_cache: Option<PathBuf>,
        /// Do not filter advisories to locally-tracked packages — persist
        /// everything OSV/GHSA know about (warning: balloons the DB).
        #[arg(long)]
        all: bool,
    },
    /// Scan a project, query registries, and persist the result to SQLite.
    Scan {
        /// Path to the project root. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Skip network calls. Errors if the cache has never been populated.
        #[arg(long)]
        offline: bool,
        /// Re-fetch even if the manifest fingerprint matches the stored one.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let store_path = resolve_store_path(cli.store)?;

    match cli.command {
        Cmd::Init { path, force } => init(path, force),
        Cmd::Report {
            path,
            format,
            fail_on_violation,
        } => report(path, format, fail_on_violation, &store_path),
        Cmd::Scan {
            path,
            offline,
            force,
        } => scan(path, offline, force, &store_path).await,
        Cmd::Sync {
            skip_osv,
            skip_ghsa,
            ghsa_cache,
            all,
        } => sync(skip_osv, skip_ghsa, ghsa_cache, all, &store_path).await,
    }
}

async fn sync(
    skip_osv: bool,
    skip_ghsa: bool,
    ghsa_cache: Option<PathBuf>,
    include_all: bool,
    store_path: &Path,
) -> Result<()> {
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;

    let watched: packguard_intel::WatchedPackages = if include_all {
        None
    } else {
        let pairs = store.watched_packages()?;
        if pairs.is_empty() {
            eprintln!(
                "{} no packages tracked yet — run `packguard scan` first, or use `--all`",
                "warn".yellow()
            );
        }
        Some(pairs.into_iter().collect())
    };

    if !skip_osv {
        for dump in [&packguard_intel::osv::NPM, &packguard_intel::osv::PYPI] {
            let prior_state = store.get_sync_state(dump.id)?;
            let prior = packguard_intel::osv::PriorSyncState {
                etag: prior_state.as_ref().and_then(|s| s.etag.clone()),
                last_modified: prior_state.as_ref().and_then(|s| s.last_modified.clone()),
            };
            match packguard_intel::osv::fetch_dump(dump, &prior, &watched).await {
                Ok(fetched) => {
                    if fetched.summary.skipped_not_modified {
                        println!(
                            "{} {} — not modified since last sync (skipped)",
                            "=".dimmed(),
                            dump.id
                        );
                    } else {
                        let persisted = store.persist_vulnerabilities(&fetched.vulnerabilities)?;
                        if let Some(updated) = fetched.updated_state {
                            let mut state = prior_state.unwrap_or_default();
                            state.etag = updated.etag;
                            state.last_modified = updated.last_modified;
                            state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                            state.record_count = persisted as i64;
                            store.put_sync_state(dump.id, &state)?;
                        }
                        println!(
                            "{} {} — scanned {}, persisted {} {}",
                            "✓".green(),
                            dump.id,
                            fetched.summary.advisories_scanned,
                            persisted,
                            if watched.is_none() {
                                "(all)"
                            } else {
                                "(watched)"
                            },
                        );
                    }
                }
                Err(err) => {
                    eprintln!("{} {}: {:#}", "warn".yellow(), dump.id, err);
                }
            }
        }
    }

    if !skip_ghsa {
        let cache = ghsa_cache
            .map(Ok)
            .unwrap_or_else(packguard_intel::ghsa::default_cache_dir)?;
        match packguard_intel::ghsa::sync(&cache, &watched) {
            Ok((vulns, summary, head)) => {
                let persisted = store.persist_vulnerabilities(&vulns)?;
                let mut state = store.get_sync_state("ghsa")?.unwrap_or_default();
                state.last_commit = Some(head);
                state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                state.record_count = persisted as i64;
                store.put_sync_state("ghsa", &state)?;
                println!(
                    "{} ghsa — scanned {}, persisted {}",
                    "✓".green(),
                    summary.advisories_scanned,
                    persisted,
                );
            }
            Err(err) => {
                eprintln!("{} ghsa: {:#}", "warn".yellow(), err);
            }
        }
    }

    let total = store.count_vulnerabilities()?;
    println!("{} store holds {} advisories", "📚".dimmed(), total);
    Ok(())
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ReportFormat {
    Table,
    Json,
    Sarif,
}

fn init(path: PathBuf, force: bool) -> Result<()> {
    let ecosystems = default_ecosystems()?;
    let detected: Vec<&'static str> = ecosystems
        .iter()
        .filter_map(|e| match e.detect(&path) {
            Ok(projects) if !projects.is_empty() => Some(e.id()),
            _ => None,
        })
        .collect();

    let target = path.join(".packguard.yml");
    if target.exists() && !force {
        anyhow::bail!(
            "{} already exists; rerun with --force to overwrite",
            target.display()
        );
    }
    std::fs::write(&target, packguard_policy::CONSERVATIVE_DEFAULTS_YAML)
        .with_context(|| format!("writing {}", target.display()))?;

    println!(
        "{} wrote {}",
        "✓".green(),
        target.display().to_string().bold()
    );
    if detected.is_empty() {
        println!(
            "{} no supported ecosystems detected under {}",
            "!".yellow(),
            path.display()
        );
    } else {
        println!(
            "{} detected ecosystems: {}",
            "•".dimmed(),
            detected.join(", ").bold()
        );
    }
    Ok(())
}

fn resolve_store_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let home = dirs::home_dir().context("resolving home directory for default store path")?;
    Ok(home.join(".packguard").join("store.db"))
}

async fn scan(path: PathBuf, offline: bool, force: bool, store_path: &Path) -> Result<()> {
    let ecosystems = default_ecosystems()?;
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let mut any_detected = false;

    for eco in &ecosystems {
        let projects = eco.detect(&path)?;
        if projects.is_empty() {
            continue;
        }
        any_detected = true;
        for project in projects {
            handle_project(&mut store, &**eco, &project, &path, offline, force).await?;
        }
    }

    if !any_detected {
        anyhow::bail!("no supported manifest found at {}", path.display());
    }
    Ok(())
}

async fn handle_project(
    store: &mut Store,
    eco: &dyn Ecosystem,
    project: &Project,
    repo_root: &Path,
    offline: bool,
    force: bool,
) -> Result<()> {
    let fingerprint = fingerprint_project(project)?;
    let last_fp = store.last_fingerprint(repo_root, eco.id())?;
    let unchanged = last_fp.as_deref() == Some(fingerprint.as_str());

    if unchanged && !force {
        println!(
            "{} {} {} — no changes since last scan (fingerprint {}…)",
            "✓".green(),
            format!("[{}]", eco.id()).dimmed(),
            project.name.as_deref().unwrap_or("<unnamed>").bold(),
            &fingerprint[..8],
        );
        return Ok(());
    }

    let remotes = if offline {
        if last_fp.is_none() {
            anyhow::bail!(
                "offline scan requires a populated cache for {} at {}; \
                 run `packguard scan` online at least once first",
                eco.id(),
                repo_root.display(),
            );
        }
        BTreeMap::new()
    } else {
        let names: Vec<String> = project
            .dependencies
            .iter()
            .map(|d| d.name.clone())
            .collect();
        let results = eco.fetch_latest(names).await;
        let mut map = BTreeMap::new();
        for (name, result) in results {
            match result {
                Ok(info) => {
                    map.insert(name, info);
                }
                Err(err) => {
                    eprintln!("{} {}: {:#}", "warn".yellow(), name, err);
                }
            }
        }
        map
    };

    // Persist before rendering so crashes mid-print don't lose data.
    let stats = store.save_project(repo_root, project, &remotes, &fingerprint)?;
    tracing::debug!(?stats, "persisted project");

    render_project(eco, project, &remotes);
    Ok(())
}

fn fingerprint_project(project: &Project) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(project.ecosystem.as_bytes());
    hasher.update(b"\0");
    hash_file_if_exists(&mut hasher, &project.manifest_path)?;

    // Lockfiles: best-effort — include ones relevant to this ecosystem if present.
    let candidates: &[&str] = match project.ecosystem {
        "npm" => &["package-lock.json"],
        "pypi" => &["uv.lock", "poetry.lock"],
        _ => &[],
    };
    for name in candidates {
        hash_file_if_exists(&mut hasher, &project.root.join(name))?;
    }
    Ok(hex(&hasher.finalize()))
}

fn hash_file_if_exists(hasher: &mut Sha256, path: &Path) -> Result<()> {
    match std::fs::read(path) {
        Ok(bytes) => {
            hasher.update(path.display().to_string().as_bytes());
            hasher.update(b"\0");
            hasher.update(&bytes);
            hasher.update(b"\0");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("hashing {}", path.display()))),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn render_project(
    eco: &dyn Ecosystem,
    project: &Project,
    remotes: &BTreeMap<String, RemotePackage>,
) {
    println!(
        "{} {} {} — {} direct deps",
        "📦".dimmed(),
        format!("[{}]", eco.id()).dimmed(),
        project.name.as_deref().unwrap_or("<unnamed>").bold(),
        project.dependencies.len(),
    );

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("Package"),
            header("Kind"),
            header("Installed"),
            header("Latest"),
            header("Δ"),
            header("Released"),
        ]);

    for dep in &project.dependencies {
        let remote = remotes.get(&dep.name);
        let latest = remote.and_then(|r| r.latest.as_deref());
        let released_at = remote.and_then(|r| r.latest_published_at.as_deref());
        let delta = eco.classify(dep.installed.as_deref(), latest);

        table.add_row(vec![
            Cell::new(&dep.name),
            Cell::new(kind_str(dep.kind)).fg(Color::DarkGrey),
            Cell::new(dep.installed.as_deref().unwrap_or("-")),
            Cell::new(latest.unwrap_or("-")),
            delta_cell(delta),
            Cell::new(released_at.unwrap_or("-")).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}");
}

fn header(s: &str) -> Cell {
    Cell::new(s).add_attribute(Attribute::Bold)
}

fn kind_str(k: DepKind) -> &'static str {
    match k {
        DepKind::Runtime => "dep",
        DepKind::Dev => "dev",
        DepKind::Peer => "peer",
        DepKind::Optional => "opt",
    }
}

fn delta_cell(d: Delta) -> Cell {
    match d {
        Delta::Current => Cell::new("current").fg(Color::Green),
        Delta::Patch => Cell::new("patch").fg(Color::Yellow),
        Delta::Minor => Cell::new("minor").fg(Color::DarkYellow),
        Delta::Major => Cell::new("major").fg(Color::Red),
        Delta::Unknown => Cell::new("?").fg(Color::DarkGrey),
    }
}

/// One row in the report, already evaluated against the policy.
struct ReportRow {
    ecosystem: String,
    workspace: Option<String>,
    package: String,
    kind: DepKind,
    installed: Option<String>,
    latest: Option<String>,
    latest_published_at: Option<String>,
    compliance: Compliance,
}

struct ReportSummary {
    compliant: usize,
    warnings: usize,
    violations: usize,
    insufficient: usize,
}

fn report(
    path: PathBuf,
    format: ReportFormat,
    fail_on_violation: bool,
    store_path: &Path,
) -> Result<()> {
    let store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let dependencies = store.load_repo_dependencies(&path)?;
    if dependencies.is_empty() {
        anyhow::bail!(
            "no cached scan for {}; run `packguard scan` first",
            path.display()
        );
    }

    let policy = load_project_policy(&path)?;
    let now = Utc::now();

    let mut rows: Vec<ReportRow> = dependencies
        .into_iter()
        .map(|dep| {
            // Full history from the store. Falls back to the single latest
            // row when history is absent (older stores / caches).
            let releases: Vec<ReleaseInfo> =
                match store.load_package_versions(&dep.ecosystem, &dep.name) {
                    Ok(history) if !history.is_empty() => history
                        .into_iter()
                        .map(|v| ReleaseInfo {
                            version: v.version,
                            published_at: v.published_at,
                            deprecated: v.deprecated,
                            yanked: v.yanked,
                        })
                        .collect(),
                    _ => match dep.latest.clone() {
                        Some(v) => vec![ReleaseInfo {
                            version: v,
                            published_at: dep.latest_published_at.clone(),
                            deprecated: false,
                            yanked: false,
                        }],
                        None => Vec::new(),
                    },
                };
            let dialect = Dialect::for_ecosystem(&dep.ecosystem);
            let resolved = policy.resolve(&dep.name);
            let vulns_by_version =
                build_vulns_by_version(&store, &dep.ecosystem, &dep.name, &releases);
            let compliance = evaluate_dependency_with_vulns(
                &dep.name,
                dep.installed.as_deref(),
                &resolved,
                &releases,
                &vulns_by_version,
                dialect,
                now,
            );
            ReportRow {
                ecosystem: dep.ecosystem,
                workspace: dep.workspace_name,
                package: dep.name,
                kind: dep.kind,
                installed: dep.installed,
                latest: dep.latest,
                latest_published_at: dep.latest_published_at,
                compliance,
            }
        })
        .collect();

    rows.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then(a.workspace.cmp(&b.workspace))
            .then(a.package.cmp(&b.package))
    });

    let summary = summarize(&rows);

    match format {
        ReportFormat::Table => render_table(&rows, &summary, &path),
        ReportFormat::Json => render_json(&rows, &summary)?,
        ReportFormat::Sarif => render_sarif(&rows)?,
    }

    if fail_on_violation && summary.violations > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn build_vulns_by_version(
    store: &Store,
    ecosystem: &str,
    name: &str,
    releases: &[ReleaseInfo],
) -> VulnsByVersion {
    let stored = match store.load_vulnerabilities(ecosystem, name) {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%ecosystem, %name, ?err, "failed to load vulnerabilities");
            return VulnsByVersion::new();
        }
    };
    if stored.is_empty() {
        return VulnsByVersion::new();
    }
    // Convert the store's StoredVulnerability into core's Vulnerability for
    // the matching engine.
    let advisories: Vec<packguard_core::Vulnerability> = stored
        .into_iter()
        .map(|s| packguard_core::Vulnerability {
            source: s.source,
            advisory_id: s.advisory_id,
            ecosystem: s.ecosystem,
            package_name: s.package_name,
            severity: s.severity,
            cve_id: s.cve_id,
            aliases: s.aliases,
            summary: s.summary,
            url: s.url,
            affected: s.affected,
            fixed_versions: s.fixed_versions,
            published_at: s.published_at,
            modified_at: s.modified_at,
        })
        .collect();

    let mut by_version: VulnsByVersion = VulnsByVersion::new();
    for rel in releases {
        let matches: Vec<MatchedVuln> =
            match_vulnerabilities(ecosystem, name, &rel.version, &advisories);
        if !matches.is_empty() {
            by_version.insert(rel.version.clone(), matches);
        }
    }
    by_version
}

fn load_project_policy(path: &Path) -> Result<Policy> {
    let candidate = path.join(".packguard.yml");
    if !candidate.exists() {
        tracing::debug!(
            "no .packguard.yml at {}; using built-in defaults",
            path.display()
        );
        return parse_policy(packguard_policy::CONSERVATIVE_DEFAULTS_YAML);
    }
    let text = std::fs::read_to_string(&candidate)
        .with_context(|| format!("reading {}", candidate.display()))?;
    parse_policy(&text)
}

fn summarize(rows: &[ReportRow]) -> ReportSummary {
    let mut s = ReportSummary {
        compliant: 0,
        warnings: 0,
        violations: 0,
        insufficient: 0,
    };
    for r in rows {
        match &r.compliance {
            Compliance::Compliant => s.compliant += 1,
            Compliance::Warning(_) => s.warnings += 1,
            Compliance::Violation(_) => s.violations += 1,
            // A VulnerabilityViolation is semantically a blocking
            // violation — fold it into the violation counter so
            // --fail-on-violation keeps working.
            Compliance::VulnerabilityViolation(_) => s.violations += 1,
            Compliance::InsufficientCandidates(_) => s.insufficient += 1,
        }
    }
    s
}

fn render_table(rows: &[ReportRow], summary: &ReportSummary, path: &Path) {
    println!(
        "{} {}",
        "📊".dimmed(),
        format!("PackGuard report — {}", path.display()).bold()
    );

    // Group by ecosystem > workspace.
    let mut current_eco: Option<&str> = None;
    let mut current_ws: Option<&Option<String>> = None;
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("Package"),
            header("Kind"),
            header("Installed"),
            header("Latest"),
            header("Policy"),
        ]);

    for row in rows {
        if current_eco != Some(row.ecosystem.as_str()) {
            if !table.is_empty() {
                println!("{table}");
                table = Table::new();
                table
                    .load_preset(UTF8_FULL_CONDENSED)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec![
                        header("Package"),
                        header("Kind"),
                        header("Installed"),
                        header("Latest"),
                        header("Policy"),
                    ]);
            }
            current_eco = Some(row.ecosystem.as_str());
            println!(
                "\n{} {}",
                "▸".dimmed(),
                format!("[{}]", row.ecosystem).bold()
            );
            current_ws = None;
        }
        if current_ws.is_none() || current_ws.unwrap() != &row.workspace {
            let ws = row.workspace.as_deref().unwrap_or("<root>");
            println!("  {} {}", "◦".dimmed(), ws);
            current_ws = Some(&row.workspace);
        }

        let (badge, badge_color) = compliance_badge(&row.compliance);
        table.add_row(vec![
            Cell::new(&row.package),
            Cell::new(kind_str(row.kind)).fg(Color::DarkGrey),
            Cell::new(row.installed.as_deref().unwrap_or("-")),
            Cell::new(row.latest.as_deref().unwrap_or("-")),
            Cell::new(badge).fg(badge_color),
        ]);
    }
    if !table.is_empty() {
        println!("{table}");
    }

    println!(
        "\n{} {}  {}  {}  {}",
        "Summary:".bold(),
        format!("✅ {} compliant", summary.compliant).green(),
        format!("⚠️  {} warnings", summary.warnings).yellow(),
        format!("❌ {} violations", summary.violations).red(),
        format!("❓ {} insufficient", summary.insufficient).magenta(),
    );
    let _ = path;
}

fn vuln_violation_message(package: &str, vulns: &[MatchedVuln]) -> String {
    let ids = vulns
        .iter()
        .map(|v| v.cve_id.clone().unwrap_or_else(|| v.advisory_id.clone()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}: {} blocking CVE(s): {}", package, vulns.len(), ids)
}

fn json_row_for(r: &ReportRow) -> serde_json::Value {
    use serde_json::json;
    let (status, message): (&str, Option<String>) = match &r.compliance {
        Compliance::Compliant => ("compliant", None),
        Compliance::Warning(m) => ("warning", Some(m.clone())),
        Compliance::Violation(m) => ("violation", Some(m.clone())),
        Compliance::VulnerabilityViolation(vulns) => (
            "cve-violation",
            Some(vuln_violation_message(&r.package, vulns)),
        ),
        Compliance::InsufficientCandidates(m) => ("insufficient", Some(m.clone())),
    };
    let cve_ids: Vec<String> = match &r.compliance {
        Compliance::VulnerabilityViolation(vulns) => vulns
            .iter()
            .map(|v| v.cve_id.clone().unwrap_or_else(|| v.advisory_id.clone()))
            .collect(),
        _ => Vec::new(),
    };
    json!({
        "ecosystem": r.ecosystem,
        "workspace": r.workspace,
        "package": r.package,
        "kind": kind_str(r.kind),
        "installed": r.installed,
        "latest": r.latest,
        "latest_published_at": r.latest_published_at,
        "status": status,
        "message": message,
        "cve_ids": cve_ids,
    })
}

fn compliance_badge(c: &Compliance) -> (&'static str, Color) {
    match c {
        Compliance::Compliant => ("compliant", Color::Green),
        Compliance::Warning(_) => ("warning", Color::Yellow),
        Compliance::Violation(_) => ("violation", Color::Red),
        Compliance::VulnerabilityViolation(_) => ("cve-violation", Color::Red),
        Compliance::InsufficientCandidates(_) => ("insufficient", Color::Magenta),
    }
}

fn render_json(rows: &[ReportRow], summary: &ReportSummary) -> Result<()> {
    use serde_json::json;
    let out = json!({
        "summary": {
            "compliant": summary.compliant,
            "warnings": summary.warnings,
            "violations": summary.violations,
            "insufficient": summary.insufficient,
        },
        "rows": rows.iter().map(json_row_for).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Minimal SARIF 2.1.0 — only blocking violations are emitted as results.
/// Both plain `Violation` (policy pin / major-behind) and
/// `VulnerabilityViolation` (blocking CVE) show up as `level: error`.
fn render_sarif(rows: &[ReportRow]) -> Result<()> {
    use serde_json::json;
    let results: Vec<_> = rows
        .iter()
        .filter_map(|r| match &r.compliance {
            Compliance::Violation(msg) => Some((r, msg.clone())),
            Compliance::VulnerabilityViolation(vulns) => {
                Some((r, vuln_violation_message(&r.package, vulns)))
            }
            _ => None,
        })
        .map(|(r, msg)| {
            json!({
                "ruleId": "packguard.policy.violation",
                "level": "error",
                "message": { "text": msg },
                "properties": {
                    "ecosystem": r.ecosystem,
                    "package": r.package,
                    "installed": r.installed,
                    "latest": r.latest,
                },
            })
        })
        .collect();
    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "packguard",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/nalo/packguard",
                    "rules": [{
                        "id": "packguard.policy.violation",
                        "shortDescription": { "text": "Dependency violates the repo policy" },
                    }],
                }
            },
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}
