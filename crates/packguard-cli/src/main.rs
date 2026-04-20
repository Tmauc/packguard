use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_core::model::{Delta, DepKind, Project, RemotePackage};
use packguard_core::{default_ecosystems, Ecosystem};
use packguard_policy::{
    evaluate_dependency, parse_policy, Compliance, Dialect, Policy, ReleaseInfo,
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
    }
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
            let compliance = evaluate_dependency(
                &dep.name,
                dep.installed.as_deref(),
                &resolved,
                &releases,
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
        match r.compliance {
            Compliance::Compliant => s.compliant += 1,
            Compliance::Warning(_) => s.warnings += 1,
            Compliance::Violation(_) => s.violations += 1,
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

fn compliance_badge(c: &Compliance) -> (&'static str, Color) {
    match c {
        Compliance::Compliant => ("compliant", Color::Green),
        Compliance::Warning(_) => ("warning", Color::Yellow),
        Compliance::Violation(_) => ("violation", Color::Red),
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
        "rows": rows.iter().map(|r| {
            let (status, message) = match &r.compliance {
                Compliance::Compliant => ("compliant", None),
                Compliance::Warning(m) => ("warning", Some(m.as_str())),
                Compliance::Violation(m) => ("violation", Some(m.as_str())),
                Compliance::InsufficientCandidates(m) => ("insufficient", Some(m.as_str())),
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
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Minimal SARIF 2.1.0 — only blocking violations are emitted as results.
fn render_sarif(rows: &[ReportRow]) -> Result<()> {
    use serde_json::json;
    let results: Vec<_> = rows
        .iter()
        .filter_map(|r| match &r.compliance {
            Compliance::Violation(msg) => Some((r, msg.clone())),
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
