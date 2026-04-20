use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_core::model::{Delta, DepKind, Project, RemotePackage};
use packguard_core::Severity;
use packguard_core::{default_ecosystems, Ecosystem};
use packguard_intel::{match_vulnerabilities, MatchedVuln};
use packguard_policy::{
    evaluate_dependency_full, parse_policy, Compliance, Dialect, Policy, ReleaseInfo,
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
    /// List every matched vulnerability for the cached scan at `path`.
    Audit {
        /// Path to the repo root whose cached scan should be audited.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Only show vulns at or above one of these severities (repeatable).
        /// Comma-separated; accepts `critical|high|medium|low`.
        #[arg(long, value_delimiter = ',')]
        severity: Vec<String>,
        /// Exit 1 if at least one CVE match reaches this severity.
        #[arg(long)]
        fail_on: Option<String>,
        /// Exit 1 if at least one matched malware record exists.
        #[arg(long)]
        fail_on_malware: bool,
        /// Restrict the output to one risk category.
        #[arg(long, value_enum, default_value_t = AuditFocus::All)]
        focus: AuditFocus,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ReportFormat::Table)]
        format: ReportFormat,
        /// Disable the live OSV API fallback. By default, packages with no
        /// cached advisories (or a >24h-old lookup) are queried against
        /// api.osv.dev on the fly.
        #[arg(long)]
        no_live_fallback: bool,
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
    /// Boot the local dashboard. Phase 4a: serves the REST API on
    /// `--port` (default 5174); the Vite dev server (port 5173) proxies
    /// `/api/*` here. Phase 4b will embed the built assets so the same
    /// command serves both API + UI in release.
    Ui {
        /// Path the server uses as the project root for scan operations.
        /// Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// TCP port to bind. Default 5174 (matches the Vite proxy in
        /// `dashboard/vite.config.ts`).
        #[arg(long, default_value_t = 5174)]
        port: u16,
        /// Bind address. Default 127.0.0.1 — Phase 4a is local-only,
        /// the `serve` mode (v2) will widen this safely with auth.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Skip the auto-open browser step. Recommended when running
        /// alongside `pnpm dev` (the Vite server is the user-facing
        /// URL during dev; the Rust server is the API the proxy calls).
        #[arg(long)]
        no_open: bool,
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
        Cmd::Audit {
            path,
            severity,
            fail_on,
            fail_on_malware,
            focus,
            format,
            no_live_fallback,
        } => {
            audit(
                path,
                severity,
                fail_on,
                fail_on_malware,
                focus,
                format,
                no_live_fallback,
                &store_path,
            )
            .await
        }
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
        Cmd::Ui {
            path,
            port,
            host,
            no_open,
        } => ui(path, port, host, no_open, &store_path).await,
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
                        let persisted_v =
                            store.persist_vulnerabilities(&fetched.vulnerabilities)?;
                        let persisted_m =
                            store.persist_malware_reports(&fetched.malware_reports)?;
                        let persisted = persisted_v + persisted_m;
                        if let Some(updated) = fetched.updated_state {
                            let mut state = prior_state.unwrap_or_default();
                            state.etag = updated.etag;
                            state.last_modified = updated.last_modified;
                            state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                            state.record_count = persisted as i64;
                            store.put_sync_state(dump.id, &state)?;
                        }
                        println!(
                            "{} {} — scanned {}, persisted {} vuln + {} malware {}",
                            "✓".green(),
                            dump.id,
                            fetched.summary.advisories_scanned,
                            persisted_v,
                            persisted_m,
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
            Ok((vulns, malware, summary, head)) => {
                let persisted_v = store.persist_vulnerabilities(&vulns)?;
                let persisted_m = store.persist_malware_reports(&malware)?;
                let persisted = persisted_v + persisted_m;
                let mut state = store.get_sync_state("ghsa")?.unwrap_or_default();
                state.last_commit = Some(head);
                state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                state.record_count = persisted as i64;
                store.put_sync_state("ghsa", &state)?;
                println!(
                    "{} ghsa — scanned {}, persisted {} vuln + {} malware",
                    "✓".green(),
                    summary.advisories_scanned,
                    persisted_v,
                    persisted_m,
                );
            }
            Err(err) => {
                eprintln!("{} ghsa: {:#}", "warn".yellow(), err);
            }
        }
    }

    let total = store.count_vulnerabilities()?;
    // ---- typosquat refresh + scoring ----
    refresh_typosquat_lists(&mut store).await;
    let typosquat_persisted = score_typosquat_against_watched(&mut store)?;
    if typosquat_persisted > 0 {
        println!(
            "{} typosquat — {} suspect package(s) flagged",
            "✓".green(),
            typosquat_persisted
        );
    }

    let mal_total = store.count_malware_reports()?;
    println!(
        "{} store holds {} advisories + {} malware reports",
        "📚".dimmed(),
        total,
        mal_total,
    );
    Ok(())
}

/// Refresh the PyPI top-N reference list when the cache is older than 7
/// days. Failures are non-fatal — typosquat scoring will fall back to the
/// embedded npm baseline + whatever the cache already holds.
async fn refresh_typosquat_lists(store: &mut Store) {
    const KIND: &str = "typosquat-pypi-top";
    let prior = match store.get_sync_state(KIND) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(?err, "typosquat sync_log read failed");
            None
        }
    };
    let cached_at = prior.as_ref().and_then(|s| s.synced_at.clone());
    match packguard_intel::typosquat::refresh::refresh_pypi(
        std::time::Duration::from_secs(7 * 24 * 3600),
        cached_at.as_deref(),
    )
    .await
    {
        Ok(0) => {
            // Cache hit (no refresh needed) → no output.
        }
        Ok(n) => {
            let mut state = prior.unwrap_or_default();
            state.synced_at = Some(Utc::now().to_rfc3339());
            state.record_count = n as i64;
            if let Err(err) = store.put_sync_state(KIND, &state) {
                tracing::warn!(?err, "typosquat sync_log write failed");
            }
            println!(
                "{} typosquat-pypi-top — refreshed ({} entries cached)",
                "✓".green(),
                n
            );
        }
        Err(err) => {
            eprintln!(
                "{} typosquat PyPI list refresh failed: {:#}",
                "warn".yellow(),
                err
            );
        }
    }
}

/// Score every watched package and persist the suspects.
fn score_typosquat_against_watched(store: &mut Store) -> Result<usize> {
    let watched = store.watched_packages()?;
    if watched.is_empty() {
        return Ok(0);
    }
    let npm = packguard_intel::typosquat::refresh::load_npm_top()?;
    let pypi = packguard_intel::typosquat::refresh::load_pypi_top()?;
    let scorer_npm = packguard_intel::typosquat::Scorer::new(npm);
    let scorer_pypi = packguard_intel::typosquat::Scorer::new(pypi);
    let mut reports: Vec<packguard_core::MalwareReport> = Vec::new();
    for (eco, name) in &watched {
        let hit = match eco.as_str() {
            "npm" => scorer_npm.score(name),
            "pypi" => scorer_pypi.score(name),
            _ => None,
        };
        if let Some(h) = hit {
            reports.push(h.into_malware_report(eco));
        }
    }
    if reports.is_empty() {
        return Ok(0);
    }
    store.persist_malware_reports(&reports)?;
    Ok(reports.len())
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ReportFormat {
    Table,
    Json,
    Sarif,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum AuditFocus {
    All,
    Cve,
    Malware,
    Typosquat,
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

async fn ui(
    path: PathBuf,
    port: u16,
    host: String,
    no_open: bool,
    store_path: &Path,
) -> Result<()> {
    let store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let repo_path = path.canonicalize().unwrap_or_else(|_| path.clone());
    let app = packguard_server::router(packguard_server::ServerConfig { repo_path, store });
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("parsing bind address {host}:{port}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    let bound = listener.local_addr()?;
    let url = format!("http://{}", bound);
    println!(
        "{} {} on {}",
        "🚀".dimmed(),
        "PackGuard server".bold(),
        url.cyan()
    );
    println!(
        "{} dev front-end: {} (run `pnpm dev` in dashboard/)",
        "→".dimmed(),
        "http://127.0.0.1:5173".cyan()
    );
    if !no_open {
        if let Err(err) = open::that_detached(&url) {
            tracing::warn!(?err, "could not auto-open browser");
        }
    }
    println!("{} press Ctrl+C to stop\n", "•".dimmed());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\n{} shutting down…", "⏹".dimmed());
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
    /// CVE counts on the installed version — surfaces in the report table
    /// and footer even when the policy doesn't block them.
    cve_counts: SeverityCounts,
    malware_confirmed: usize,
    typosquat_suspects: usize,
}

struct ReportSummary {
    compliant: usize,
    warnings: usize,
    violations: usize,
    insufficient: usize,
    cve_counts: SeverityCounts,
    malware_confirmed: usize,
    typosquat_suspects: usize,
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
            let vulns_by_version = build_vulns_by_version(
                &store,
                &dep.ecosystem,
                &dep.name,
                dep.installed.as_deref(),
                &releases,
            );
            let malware = store
                .load_malware_reports(&dep.ecosystem, &dep.name)
                .unwrap_or_default();
            let malware_core: Vec<packguard_core::MalwareReport> = malware
                .iter()
                .map(|m| packguard_core::MalwareReport {
                    source: m.source.clone(),
                    ref_id: m.ref_id.clone(),
                    ecosystem: m.ecosystem.clone(),
                    package_name: m.package_name.clone(),
                    version: m.version.clone().unwrap_or_default(),
                    kind: m.kind,
                    summary: m.summary.clone(),
                    url: m.url.clone(),
                    evidence: m.evidence.clone(),
                    reported_at: m.reported_at.clone(),
                })
                .collect();
            let compliance = evaluate_dependency_full(
                &dep.name,
                dep.installed.as_deref(),
                &resolved,
                &releases,
                &vulns_by_version,
                &malware_core,
                dialect,
                now,
            );
            let cve_counts = match &dep.installed {
                Some(v) => severity_counts(
                    vulns_by_version
                        .get(v)
                        .map(|list| list.iter().map(|mv| mv.severity).collect::<Vec<_>>())
                        .unwrap_or_default(),
                ),
                None => SeverityCounts::default(),
            };
            let installed_str = dep.installed.clone().unwrap_or_default();
            let malware_confirmed = malware
                .iter()
                .filter(|m| matches!(m.kind, packguard_core::MalwareKind::Malware))
                .filter(|m| {
                    m.version.as_deref() == Some(installed_str.as_str()) || m.version.is_none()
                })
                .count();
            let typosquat_suspects = malware
                .iter()
                .filter(|m| matches!(m.kind, packguard_core::MalwareKind::Typosquat))
                .count();
            ReportRow {
                ecosystem: dep.ecosystem,
                workspace: dep.workspace_name,
                package: dep.name,
                kind: dep.kind,
                installed: dep.installed,
                latest: dep.latest,
                latest_published_at: dep.latest_published_at,
                compliance,
                cve_counts,
                malware_confirmed,
                typosquat_suspects,
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
    installed: Option<&str>,
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

    let mut versions: Vec<String> = releases.iter().map(|r| r.version.clone()).collect();
    // The installed version may predate the history the store currently
    // holds — make sure we still look up its vulns so the CVE block check
    // in evaluate_dependency fires.
    if let Some(v) = installed {
        if !versions.iter().any(|x| x == v) {
            versions.push(v.to_string());
        }
    }

    let mut by_version: VulnsByVersion = VulnsByVersion::new();
    for version in versions {
        let matches: Vec<MatchedVuln> =
            match_vulnerabilities(ecosystem, name, &version, &advisories);
        if !matches.is_empty() {
            by_version.insert(version, matches);
        }
    }
    by_version
}

#[derive(Debug, Clone)]
struct AuditRow {
    ecosystem: String,
    workspace: Option<String>,
    package: String,
    installed: String,
    vuln: MatchedVuln,
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    path: PathBuf,
    severity_filter: Vec<String>,
    fail_on: Option<String>,
    fail_on_malware: bool,
    focus: AuditFocus,
    format: ReportFormat,
    no_live_fallback: bool,
    store_path: &Path,
) -> Result<()> {
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let dependencies = store.load_repo_dependencies(&path)?;
    if dependencies.is_empty() {
        anyhow::bail!(
            "no cached scan for {}; run `packguard scan` first",
            path.display()
        );
    }

    // Normalize the filter to a Severity set. Unknown strings are ignored.
    let filter_set: Vec<Severity> = severity_filter
        .iter()
        .map(|s| Severity::parse(s))
        .filter(|s| !matches!(s, Severity::Unknown))
        .collect();

    // Opt-in live fallback: hit api.osv.dev for packages we don't have
    // cached advisories on (or haven't queried in 24h). Single client is
    // cheap; we'll consult it per-dep below.
    let live_client = if no_live_fallback {
        None
    } else {
        match packguard_intel::OsvApiClient::new() {
            Ok(c) => Some(c),
            Err(err) => {
                eprintln!(
                    "{} OSV API client init failed ({:#}) — disabling fallback",
                    "warn".yellow(),
                    err
                );
                None
            }
        }
    };

    // Opt-in Socket.dev scanner: only active when PACKGUARD_SOCKET_TOKEN is
    // set in the env. Silent skip otherwise — supply-chain scanners are
    // genuinely opt-in. Same TTL bookkeeping as the OSV fallback.
    let socket_client = if no_live_fallback {
        None
    } else {
        packguard_intel::socket::token_from_env().and_then(|tok| {
            match packguard_intel::socket::SocketClient::new(&tok) {
                Ok(c) => {
                    eprintln!(
                        "{} Socket.dev token detected — supplementing audit with scanner alerts",
                        "•".dimmed()
                    );
                    Some(c)
                }
                Err(err) => {
                    eprintln!(
                        "{} Socket.dev client init failed ({:#}) — skipping",
                        "warn".yellow(),
                        err
                    );
                    None
                }
            }
        })
    };

    let mut rows: Vec<AuditRow> = Vec::new();
    for dep in dependencies {
        let Some(installed) = dep.installed.as_deref() else {
            continue;
        };
        let stored = store.load_vulnerabilities(&dep.ecosystem, &dep.name)?;

        // Socket scanner enrichment: persist its alerts as MalwareReports.
        // 24h TTL via sync_log key `socket:{eco}:{name}@{version}`.
        if let Some(client) = &socket_client {
            let key = format!("socket:{}:{}@{}", dep.ecosystem, dep.name, installed);
            let stale = store
                .get_sync_state(&key)?
                .and_then(|s| s.synced_at)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|ts| Utc::now().signed_duration_since(ts.to_utc()).num_hours() >= 24)
                .unwrap_or(true);
            if stale {
                match client.query(&dep.ecosystem, &dep.name, installed).await {
                    Ok(reports) => {
                        if !reports.is_empty() {
                            store.persist_malware_reports(&reports)?;
                        }
                        let state = packguard_store::SyncState {
                            synced_at: Some(Utc::now().to_rfc3339()),
                            record_count: reports.len() as i64,
                            ..Default::default()
                        };
                        store.put_sync_state(&key, &state)?;
                    }
                    Err(err) => {
                        eprintln!(
                            "{} Socket query for {}@{}: {:#}",
                            "warn".yellow(),
                            dep.name,
                            installed,
                            err
                        );
                    }
                }
            }
        }

        // Live fallback: empty cache OR stale lookup (>24h) → POST /v1/query.
        // Results are persisted with source="osv-api-live"; a sync_log entry
        // keyed `osv-api:{eco}:{name}` tracks the last successful query time.
        let stored = if let Some(client) = &live_client {
            let key = format!("osv-api:{}:{}", dep.ecosystem, dep.name);
            let stale = store
                .get_sync_state(&key)?
                .and_then(|s| s.synced_at)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|ts| Utc::now().signed_duration_since(ts.to_utc()).num_hours() >= 24)
                .unwrap_or(true);
            if stored.is_empty() || stale {
                if let Some(ecosystem_osv) = packguard_intel::osv_ecosystem(&dep.ecosystem) {
                    match client.query(ecosystem_osv, &dep.name, installed).await {
                        Ok(vulns) => {
                            if !vulns.is_empty() {
                                let n = store.persist_vulnerabilities(&vulns)?;
                                tracing::info!(
                                    %dep.ecosystem, %dep.name, %installed, added = n,
                                    "live OSV fallback returned advisories"
                                );
                            }
                            let mut state = packguard_store::SyncState {
                                synced_at: Some(Utc::now().to_rfc3339()),
                                record_count: vulns.len() as i64,
                                ..Default::default()
                            };
                            // Preserve any prior record_count / commit.
                            if let Some(prior) = store.get_sync_state(&key)? {
                                state.record_count = prior.record_count + vulns.len() as i64;
                            }
                            store.put_sync_state(&key, &state)?;
                            // Re-read combined (cached + live) set for the matcher.
                            store.load_vulnerabilities(&dep.ecosystem, &dep.name)?
                        }
                        Err(err) => {
                            eprintln!(
                                "{} OSV live query failed for {}: {:#}",
                                "warn".yellow(),
                                dep.name,
                                err
                            );
                            stored
                        }
                    }
                } else {
                    stored
                }
            } else {
                stored
            }
        } else {
            stored
        };

        if stored.is_empty() {
            continue;
        }
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
        let matches = match_vulnerabilities(&dep.ecosystem, &dep.name, installed, &advisories);
        for v in matches {
            if !filter_set.is_empty() && !filter_set.contains(&v.severity) {
                continue;
            }
            rows.push(AuditRow {
                ecosystem: dep.ecosystem.clone(),
                workspace: dep.workspace_name.clone(),
                package: dep.name.clone(),
                installed: installed.to_string(),
                vuln: v,
            });
        }
    }

    rows.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then(a.workspace.cmp(&b.workspace))
            .then(a.package.cmp(&b.package))
            .then_with(|| b.vuln.severity.cmp(&a.vuln.severity))
    });

    let counts = severity_counts(rows.iter().map(|r| r.vuln.severity));

    // Collect malware + typosquat rows from the store. We re-walk the deps
    // already loaded above so the store query stays cheap.
    let mut malware_rows: Vec<MalwareAuditRow> = Vec::new();
    let mut typosquat_rows: Vec<MalwareAuditRow> = Vec::new();
    for (eco, name, installed) in dep_keys_for_audit(&store, &path)? {
        for r in store.load_malware_reports(&eco, &name)? {
            // Match malware records by version (or whole-package empty).
            let version_matches = r.version.is_none()
                || r.version.as_deref() == Some(installed.as_deref().unwrap_or(""));
            if !version_matches {
                continue;
            }
            let row = MalwareAuditRow {
                ecosystem: eco.clone(),
                package: name.clone(),
                installed: installed.clone(),
                report: r.clone(),
            };
            match r.kind {
                packguard_core::MalwareKind::Malware
                | packguard_core::MalwareKind::ScannerSignal => malware_rows.push(row),
                packguard_core::MalwareKind::Typosquat => typosquat_rows.push(row),
            }
        }
    }

    let show_cve = matches!(focus, AuditFocus::All | AuditFocus::Cve);
    let show_mal = matches!(focus, AuditFocus::All | AuditFocus::Malware);
    let show_typo = matches!(focus, AuditFocus::All | AuditFocus::Typosquat);

    match format {
        ReportFormat::Table => {
            if show_cve {
                render_audit_table(&rows, &counts, &path);
            }
            if show_mal && !malware_rows.is_empty() {
                render_malware_section(&malware_rows);
            }
            if show_typo && !typosquat_rows.is_empty() {
                render_typosquat_section(&typosquat_rows);
            }
            if rows.is_empty() && malware_rows.is_empty() && typosquat_rows.is_empty() {
                println!(
                    "{} {}",
                    "✓".green(),
                    "no risks detected for the requested focus".bold()
                );
            }
        }
        ReportFormat::Json => render_audit_json_full(
            show_cve.then_some((&rows[..], &counts)),
            show_mal.then_some(&malware_rows[..]),
            show_typo.then_some(&typosquat_rows[..]),
        )?,
        ReportFormat::Sarif => render_audit_sarif_full(
            show_cve.then_some(&rows[..]),
            show_mal.then_some(&malware_rows[..]),
        )?,
    }

    // Exit gates.
    if let Some(threshold_raw) = fail_on {
        let threshold = Severity::parse(&threshold_raw);
        if matches!(threshold, Severity::Unknown) {
            anyhow::bail!(
                "unknown --fail-on severity `{}` (expected critical|high|medium|low)",
                threshold_raw
            );
        }
        if rows.iter().any(|r| r.vuln.severity >= threshold) {
            std::process::exit(1);
        }
    }
    if fail_on_malware
        && malware_rows
            .iter()
            .any(|r| matches!(r.report.kind, packguard_core::MalwareKind::Malware))
    {
        std::process::exit(1);
    }
    Ok(())
}

/// Re-fetch (eco, name, installed) tuples for the audit's malware pass.
/// Cheaper than threading them through from the CVE loop.
fn dep_keys_for_audit(store: &Store, path: &Path) -> Result<Vec<(String, String, Option<String>)>> {
    Ok(store
        .load_repo_dependencies(path)?
        .into_iter()
        .map(|d| (d.ecosystem, d.name, d.installed))
        .collect())
}

#[derive(Debug, Clone)]
struct MalwareAuditRow {
    ecosystem: String,
    package: String,
    installed: Option<String>,
    report: packguard_store::StoredMalware,
}

#[derive(Debug, Default, Clone)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

fn severity_counts(iter: impl IntoIterator<Item = Severity>) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for s in iter {
        match s {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Unknown => c.unknown += 1,
        }
    }
    c
}

fn severity_color(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::Red,
        Severity::High => Color::DarkRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Green,
        Severity::Unknown => Color::DarkGrey,
    }
}

fn format_affected_window(vuln: &MatchedVuln) -> String {
    // We intentionally don't reload affected_json here — MatchedVuln already
    // carries fixed_versions, and `affected_json` would require plumbing
    // StoredVulnerability all the way through. The human-readable window is
    // "everything up to the first fix".
    match vuln.fixed_versions.first() {
        Some(v) => format!("< {v}"),
        None => "unbounded".into(),
    }
}

fn advisory_label(v: &MatchedVuln) -> String {
    v.cve_id.clone().unwrap_or_else(|| v.advisory_id.clone())
}

fn render_audit_table(rows: &[AuditRow], counts: &SeverityCounts, path: &Path) {
    println!(
        "{} {}",
        "🛡️".dimmed(),
        format!("PackGuard audit — {}", path.display()).bold()
    );
    if rows.is_empty() {
        println!("\n{} no matched vulnerabilities.", "✓".green());
        return;
    }

    let mut current_eco: Option<&str> = None;
    let mut current_ws: Option<&Option<String>> = None;
    let mut table = new_audit_table();
    for row in rows {
        if current_eco != Some(row.ecosystem.as_str()) {
            if !table.is_empty() {
                println!("{table}");
                table = new_audit_table();
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
        table.add_row(vec![
            Cell::new(&row.package),
            Cell::new(&row.installed),
            Cell::new(advisory_label(&row.vuln)),
            Cell::new(row.vuln.severity.as_str()).fg(severity_color(row.vuln.severity)),
            Cell::new(format_affected_window(&row.vuln)),
            Cell::new(
                row.vuln
                    .fixed_versions
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "—".into()),
            ),
        ]);
    }
    if !table.is_empty() {
        println!("{table}");
    }

    println!(
        "\n{} {}  {}  {}  {}",
        "Summary:".bold(),
        format!("🔴 {} critical", counts.critical).red(),
        format!("🟠 {} high", counts.high).red(),
        format!("🟡 {} medium", counts.medium).yellow(),
        format!("🟢 {} low", counts.low).green(),
    );
}

fn render_malware_section(rows: &[MalwareAuditRow]) {
    println!("\n{} {}", "🏴‍☠️".dimmed(), "Malware".bold().red());
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("Package"),
            header("Installed"),
            header("Source"),
            header("Ref"),
            header("Evidence"),
        ]);
    for r in rows {
        table.add_row(vec![
            Cell::new(format!("[{}] {}", r.ecosystem, r.package)),
            Cell::new(r.installed.as_deref().unwrap_or("-")),
            Cell::new(&r.report.source).fg(Color::DarkGrey),
            Cell::new(&r.report.ref_id),
            Cell::new(r.report.summary.as_deref().unwrap_or("(no summary)")),
        ]);
    }
    println!("{table}");
}

fn render_typosquat_section(rows: &[MalwareAuditRow]) {
    println!(
        "\n{} {}",
        "⚠️".dimmed(),
        "Typosquat suspects".bold().yellow()
    );
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("Package"),
            header("Resembles"),
            header("Distance"),
            header("Score"),
            header("Reason"),
        ]);
    for r in rows {
        let resembles = r
            .report
            .evidence
            .get("resembles")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let distance = r
            .report
            .evidence
            .get("distance")
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
        let score = r
            .report
            .evidence
            .get("score")
            .and_then(|v| v.as_f64())
            .map(|n| format!("{:.2}", n))
            .unwrap_or_else(|| "-".into());
        let reason = r
            .report
            .evidence
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        table.add_row(vec![
            Cell::new(format!("[{}] {}", r.ecosystem, r.package)),
            Cell::new(resembles).fg(Color::Cyan),
            Cell::new(distance),
            Cell::new(score),
            Cell::new(reason).fg(Color::DarkGrey),
        ]);
    }
    println!("{table}");
}

fn render_audit_json_full(
    cve: Option<(&[AuditRow], &SeverityCounts)>,
    malware: Option<&[MalwareAuditRow]>,
    typosquat: Option<&[MalwareAuditRow]>,
) -> Result<()> {
    use serde_json::json;
    let mut out = serde_json::Map::new();
    if let Some((rows, counts)) = cve {
        out.insert(
            "cve".into(),
            json!({
                "summary": {
                    "critical": counts.critical,
                    "high": counts.high,
                    "medium": counts.medium,
                    "low": counts.low,
                    "unknown": counts.unknown,
                },
                "matches": rows.iter().map(|r| json!({
                    "ecosystem": r.ecosystem,
                    "workspace": r.workspace,
                    "package": r.package,
                    "installed": r.installed,
                    "advisory_id": r.vuln.advisory_id,
                    "cve_id": r.vuln.cve_id,
                    "source": r.vuln.source,
                    "severity": r.vuln.severity.as_str(),
                    "summary": r.vuln.summary,
                    "url": r.vuln.url,
                    "fixed_versions": r.vuln.fixed_versions,
                    "aliases": r.vuln.aliases,
                    "published_at": r.vuln.published_at,
                })).collect::<Vec<_>>(),
            }),
        );
    }
    if let Some(m) = malware {
        out.insert(
            "malware".into(),
            json!(m
                .iter()
                .map(|r| json!({
                    "ecosystem": r.ecosystem,
                    "package": r.package,
                    "installed": r.installed,
                    "source": r.report.source,
                    "ref_id": r.report.ref_id,
                    "kind": r.report.kind.as_str(),
                    "summary": r.report.summary,
                    "url": r.report.url,
                    "evidence": r.report.evidence,
                }))
                .collect::<Vec<_>>()),
        );
    }
    if let Some(t) = typosquat {
        out.insert(
            "typosquat".into(),
            json!(t
                .iter()
                .map(|r| json!({
                    "ecosystem": r.ecosystem,
                    "package": r.package,
                    "evidence": r.report.evidence,
                    "summary": r.report.summary,
                }))
                .collect::<Vec<_>>()),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(out))?
    );
    Ok(())
}

fn render_audit_sarif_full(
    cve: Option<&[AuditRow]>,
    malware: Option<&[MalwareAuditRow]>,
) -> Result<()> {
    use serde_json::json;
    let mut results: Vec<serde_json::Value> = Vec::new();
    if let Some(rows) = cve {
        for r in rows {
            results.push(json!({
                "ruleId": "packguard.cve",
                "level": match r.vuln.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": r.vuln.summary.clone().unwrap_or_else(|| advisory_label(&r.vuln)) },
                "properties": {
                    "ecosystem": r.ecosystem,
                    "package": r.package,
                    "installed": r.installed,
                    "advisory_id": r.vuln.advisory_id,
                    "cve_id": r.vuln.cve_id,
                    "severity": r.vuln.severity.as_str(),
                    "fixed_versions": r.vuln.fixed_versions,
                    "url": r.vuln.url,
                },
            }));
        }
    }
    if let Some(rows) = malware {
        for r in rows {
            let level = match r.report.kind {
                packguard_core::MalwareKind::Malware => "error",
                _ => "warning",
            };
            results.push(json!({
                "ruleId": "packguard.malware",
                "level": level,
                "message": { "text": r.report.summary.clone().unwrap_or_else(|| r.report.ref_id.clone()) },
                "properties": {
                    "ecosystem": r.ecosystem,
                    "package": r.package,
                    "installed": r.installed,
                    "source": r.report.source,
                    "ref_id": r.report.ref_id,
                    "kind": r.report.kind.as_str(),
                    "url": r.report.url,
                },
            }));
        }
    }
    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "packguard",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/nalo/packguard",
                "rules": [
                    { "id": "packguard.cve", "shortDescription": { "text": "Installed dependency has a known CVE" } },
                    { "id": "packguard.malware", "shortDescription": { "text": "Installed dependency was flagged by a supply-chain scanner" } },
                ],
            }},
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn new_audit_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("Package"),
            header("Installed"),
            header("Advisory"),
            header("Severity"),
            header("Range"),
            header("Fix"),
        ]);
    table
}

// (Phase 2 single-section json/sarif renderers replaced by
// `render_audit_json_full` / `render_audit_sarif_full` in 2.5.4.)

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
        cve_counts: SeverityCounts::default(),
        malware_confirmed: 0,
        typosquat_suspects: 0,
    };
    for r in rows {
        match &r.compliance {
            Compliance::Compliant => s.compliant += 1,
            Compliance::Warning(_) => s.warnings += 1,
            Compliance::Violation(_) => s.violations += 1,
            // VulnerabilityViolation + MalwareViolation fold into the
            // violation counter so --fail-on-violation catches them too.
            Compliance::VulnerabilityViolation(_) => s.violations += 1,
            Compliance::MalwareViolation(_) => s.violations += 1,
            // TyposquatWarning is non-blocking — surfaced in warnings.
            Compliance::TyposquatWarning(_) => s.warnings += 1,
            Compliance::InsufficientCandidates(_) => s.insufficient += 1,
        }
        s.cve_counts.critical += r.cve_counts.critical;
        s.cve_counts.high += r.cve_counts.high;
        s.cve_counts.medium += r.cve_counts.medium;
        s.cve_counts.low += r.cve_counts.low;
        s.cve_counts.unknown += r.cve_counts.unknown;
        s.malware_confirmed += r.malware_confirmed;
        s.typosquat_suspects += r.typosquat_suspects;
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
            header("Risk"),
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
            Cell::new(risk_badge(
                &row.cve_counts,
                row.malware_confirmed,
                row.typosquat_suspects,
            )),
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
    let c = &summary.cve_counts;
    if c.critical + c.high + c.medium + c.low > 0 {
        println!(
            "{} {}  {}  {}  {}",
            "Vulnerabilities:".bold(),
            format!("🔴 {} critical", c.critical).red(),
            format!("🟠 {} high", c.high).red(),
            format!("🟡 {} medium", c.medium).yellow(),
            format!("🟢 {} low", c.low).green(),
        );
    }
    if summary.malware_confirmed + summary.typosquat_suspects > 0 {
        println!(
            "{} {}  {}",
            "Supply-chain:".bold(),
            format!("🏴‍☠️ {} malware confirmed", summary.malware_confirmed).red(),
            format!("⚠️  {} typosquat suspect(s)", summary.typosquat_suspects).yellow(),
        );
    }
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
        Compliance::MalwareViolation(reports) => (
            "malware",
            Some(format!(
                "{}: {} malware report(s) match installed",
                r.package,
                reports.len()
            )),
        ),
        Compliance::TyposquatWarning(reports) => (
            "typosquat",
            Some(format!(
                "{}: {} typosquat suspicion(s)",
                r.package,
                reports.len()
            )),
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

fn risk_badge(counts: &SeverityCounts, malware: usize, typosquat: usize) -> String {
    let mut parts = Vec::new();
    if counts.critical > 0 {
        parts.push(format!("{}🔴", counts.critical));
    }
    if counts.high > 0 {
        parts.push(format!("{}🟠", counts.high));
    }
    if counts.medium > 0 {
        parts.push(format!("{}🟡", counts.medium));
    }
    if counts.low > 0 {
        parts.push(format!("{}🟢", counts.low));
    }
    if malware > 0 {
        parts.push(format!("{}🏴‍☠️", malware));
    }
    if typosquat > 0 {
        parts.push(format!("{}⚠", typosquat));
    }
    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(" · ")
    }
}

fn compliance_badge(c: &Compliance) -> (&'static str, Color) {
    match c {
        Compliance::Compliant => ("compliant", Color::Green),
        Compliance::Warning(_) => ("warning", Color::Yellow),
        Compliance::Violation(_) => ("violation", Color::Red),
        Compliance::VulnerabilityViolation(_) => ("cve-violation", Color::Red),
        Compliance::MalwareViolation(_) => ("malware", Color::Red),
        Compliance::TyposquatWarning(_) => ("typosquat", Color::Yellow),
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
            "vulnerabilities": {
                "critical": summary.cve_counts.critical,
                "high": summary.cve_counts.high,
                "medium": summary.cve_counts.medium,
                "low": summary.cve_counts.low,
                "unknown": summary.cve_counts.unknown,
            },
            "malware": {
                "confirmed": summary.malware_confirmed,
                "suspected_typosquat": summary.typosquat_suspects,
            },
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
            Compliance::MalwareViolation(reports) => Some((
                r,
                format!(
                    "{}: {} malware report(s) match installed",
                    r.package,
                    reports.len()
                ),
            )),
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
