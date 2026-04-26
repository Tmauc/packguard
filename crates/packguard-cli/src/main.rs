mod actions_cli;
mod cli_scope;

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
    evaluate_dependency_full, Compliance, Dialect, Policy, ReleaseInfo, VulnsByVersion,
};
use packguard_store::{IntelStore, ProjectStoreCache, ProjectsRegistry, Store};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::cli_scope::{
    ensure_default_registered, ensure_project_registered, resolve_cli_scope, ResolvedCliScope,
    ScopeSource,
};

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
        /// Also write a ready-to-paste CI snippet for the named
        /// provider. Output lands in `.packguard/ci/<provider>.yml`
        /// alongside a one-line pointer to the full recipe under
        /// `docs/integrations/`. When omitted, the command still
        /// detects an existing `.gitlab-ci.yml` / `.github/workflows/`
        /// layout and prints a suggestion — it never touches existing
        /// pipeline files.
        #[arg(long, value_enum)]
        with_ci: Option<CiProvider>,
    },
    /// Render a compliance report from the SQLite store. Zero network.
    Report {
        /// Path to the repo root whose cached scan should be reported on.
        /// Omitted (and no `--project`) → pick the most recent scan from
        /// the project store (Phase 7a consistency with `packguard ui`).
        path: Option<PathBuf>,
        /// Project to scope the report to. Accepts a slug
        /// (`Users-mauc-Repo-Nalo-monorepo`) or, for v0.5.x backcompat,
        /// an absolute workspace path (deprecated — emits a warning).
        /// When omitted, the slug is auto-detected via cwd walk-up.
        #[arg(long)]
        project: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ReportFormat::Table)]
        format: ReportFormat,
        /// Exit with status 1 when at least one blocking violation exists.
        #[arg(long)]
        fail_on_violation: bool,
        /// Phase 10b — print the resolved policy with per-key provenance
        /// (which file / line each value came from) and exit, instead of
        /// rendering the package table. Useful for debugging monorepo
        /// policy cascades.
        #[arg(long)]
        show_policy: bool,
    },
    /// List every matched vulnerability for the cached scan at `path`.
    Audit {
        /// Path to the repo root whose cached scan should be audited.
        /// Omitted (and no `--project`) → pick the most recent scan in
        /// the resolved project store.
        path: Option<PathBuf>,
        /// Project slug (or legacy workspace path — deprecated). When
        /// omitted, the slug is auto-detected via cwd walk-up.
        #[arg(long)]
        project: Option<String>,
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
        /// When omitted, `packguard ui` picks the most recent scan in
        /// the resolved project's store. Empty-store case: server still
        /// boots, the UI shows a "no scans yet" placeholder.
        path: Option<PathBuf>,
        /// Project slug (or legacy workspace path — deprecated). When
        /// omitted, the slug is auto-detected via cwd walk-up.
        #[arg(long)]
        project: Option<String>,
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
    /// Print the transitive dependency graph as ASCII, DOT, or JSON.
    /// Zero network — reads only the SQLite store (populate with `scan`).
    Graph {
        /// Path to the project root (same shape as `scan`). Omitted (and
        /// no `--project`) → pick the most recent scan in the resolved
        /// project store.
        path: Option<PathBuf>,
        /// Project slug (or legacy workspace path — deprecated). When
        /// omitted, the slug is auto-detected via cwd walk-up.
        #[arg(long)]
        project: Option<String>,
        /// Manifest path of the workspace to restrict to (e.g.
        /// `/abs/path/package.json`). Omit to include every workspace of the
        /// repo.
        #[arg(long)]
        workspace: Option<String>,
        /// Narrow the output to the subtree rooted at this package id
        /// (`ecosystem:name@version`). Cheaper than piping through grep
        /// when the repo is large.
        #[arg(long)]
        focus: Option<String>,
        /// Instead of the full graph, print every root→hit chain for the
        /// given advisory id (CVE / GHSA / alias). Overrides `--focus`.
        #[arg(long)]
        contaminated_by: Option<String>,
        /// Max BFS depth from direct deps. Clamped to 32 server-side.
        #[arg(long)]
        max_depth: Option<u32>,
        /// Comma-separated kinds (`runtime,dev,peer,optional`).
        #[arg(long)]
        kind: Option<String>,
        /// Output format.
        #[arg(long, default_value = "ascii")]
        format: GraphFormat,
    },
    /// Scan a project, query registries, and persist the result to SQLite.
    ///
    /// Phase 9a: recursive auto-discovery is the default. Point at a
    /// monorepo root and every `package.json` / `pyproject.toml` it
    /// finds under pnpm/npm/lerna workspaces or the walk becomes its
    /// own scan. Use `--no-recursive` for legacy single-project mode.
    Scan {
        /// Path to the project root. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Project slug to write into. When omitted, the slug is
        /// derived from `<path>` via `.git/` walk-up (or `_default_`
        /// for paths outside any git repo).
        #[arg(long)]
        project: Option<String>,
        /// Skip network calls. Errors if the cache has never been populated.
        #[arg(long)]
        offline: bool,
        /// Re-fetch even if the manifest fingerprint matches the stored one.
        #[arg(long)]
        force: bool,
        /// Disable auto-discovery — scan exactly `<path>` and fail if
        /// there is no manifest there (legacy pre-0.2.0 behaviour).
        #[arg(long)]
        no_recursive: bool,
        /// Max depth for the filesystem walk when no monorepo marker
        /// is present. Counts the root as depth 0.
        #[arg(long, default_value_t = packguard_core::DEFAULT_MAX_DEPTH)]
        depth: usize,
        /// Additional glob (relative to `<path>`) to include as a
        /// project candidate. Repeatable.
        #[arg(long = "include", value_name = "GLOB")]
        include_globs: Vec<String>,
        /// Additional glob (relative to `<path>`) to exclude from the
        /// walk. Layered on top of the built-in denylist. Repeatable.
        #[arg(long = "exclude", value_name = "GLOB")]
        exclude_globs: Vec<String>,
        /// List the projects discovery would scan and exit — no
        /// registry calls, no DB writes.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt when more than 50 projects are
        /// discovered. Useful in CI.
        #[arg(long)]
        yes: bool,
    },
    /// List every repo the store knows about (path, ecosystem, last scan,
    /// fingerprint, dep count). Useful when `report`/`audit`/`graph` bails
    /// with "no cached scan" and you've forgotten where you ran the scan
    /// from.
    Scans {
        /// Emit JSON instead of the default table layout.
        #[arg(long)]
        json: bool,
    },
    /// Prioritized list of remediation actions (read-only + copy-paste).
    /// Phase 12c — mirrors the `/actions` dashboard page: same data,
    /// same priority order. Subcommands `dismiss` / `defer` / `restore`
    /// share the dashboard's SQLite persistence so a CLI dismiss is
    /// respected in the UI and vice-versa.
    Actions(actions_cli::ActionsArgs),
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
    let packguard_home = home_from_store_path(&store_path);

    // Run the legacy-store layout migration once before any command
    // touches the store. Idempotent — a no-op on already-migrated
    // homes (the common case after first boot) and on fresh installs
    // (no legacy file). The banner only fires on the actual cutover.
    let migration_report = packguard_store::migration::migrate_legacy_if_present(&packguard_home)
        .context("running legacy-layout migration")?;
    if migration_report.legacy_found && !migration_report.already_migrated {
        let plural = if migration_report.projects_created == 1 {
            ""
        } else {
            "s"
        };
        eprintln!(
            "{} Migrated to per-project layout: {} project{}, {} workspaces, {} CVEs.",
            "✓".green(),
            migration_report.projects_created,
            plural,
            migration_report.workspaces_migrated,
            migration_report.vulnerabilities_migrated,
        );
    }

    // Phase 14.2d.3 — once the per-project layout is fully populated,
    // retire the legacy `~/.packguard/store.db` by renaming it to
    // `.v0.5-backup`. Idempotent: re-runs after the first cutover
    // see `AlreadyRenamed` / `NoLegacyPresent` and stay silent.
    use packguard_store::migration::LegacyRenameOutcome;
    match packguard_store::migration::rename_legacy_if_migration_complete(&packguard_home)
        .context("renaming legacy store to .v0.5-backup")?
    {
        LegacyRenameOutcome::Renamed => {
            eprintln!(
                "{} Renamed {}/store.db → store.db.v0.5-backup (legacy retired, per-project layer is now the source of truth).",
                "✓".green(),
                packguard_home.display(),
            );
            eprintln!("  You can delete the backup once you're confident in the v0.6.0 migration.");
        }
        LegacyRenameOutcome::BackupAlreadyExists => {
            eprintln!(
                "{} Both {}/store.db and store.db.v0.5-backup exist — refusing to clobber. \
                 Inspect manually and delete the stale file before re-launching.",
                "warn".yellow(),
                packguard_home.display(),
            );
        }
        LegacyRenameOutcome::AlreadyRenamed
        | LegacyRenameOutcome::NoLegacyPresent
        | LegacyRenameOutcome::MigrationIncomplete => {
            // Silent — common cases on every subsequent boot.
        }
    }

    let mut registry = ProjectsRegistry::open(&packguard_home).with_context(|| {
        format!(
            "opening projects registry under {}",
            packguard_home.display()
        )
    })?;
    let project_stores = Arc::new(ProjectStoreCache::new(packguard_home.clone()));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match cli.command {
        Cmd::Init {
            path,
            force,
            with_ci,
        } => init(path, force, with_ci),
        Cmd::Audit {
            path,
            project,
            severity,
            fail_on,
            fail_on_malware,
            focus,
            format,
            no_live_fallback,
        } => {
            let scope = resolve_scope_or_default(
                project.as_deref(),
                path.as_deref(),
                &mut registry,
                &packguard_home,
                &cwd,
            )?;
            announce_scope(&scope, "audit");
            let pstore = project_stores.get_or_open(&scope.slug).await?;
            let workspace =
                resolve_workspace_in_project(&pstore, scope.workspace_path.clone(), "audit")
                    .await?;
            audit(
                workspace,
                severity,
                fail_on,
                fail_on_malware,
                focus,
                format,
                no_live_fallback,
                &pstore,
                &packguard_home,
            )
            .await
        }
        Cmd::Report {
            path,
            project,
            format,
            fail_on_violation,
            show_policy,
        } => {
            let scope = resolve_scope_or_default(
                project.as_deref(),
                path.as_deref(),
                &mut registry,
                &packguard_home,
                &cwd,
            )?;
            announce_scope(&scope, "report");
            let pstore = project_stores.get_or_open(&scope.slug).await?;
            let workspace =
                resolve_workspace_in_project(&pstore, scope.workspace_path.clone(), "report")
                    .await?;
            if show_policy {
                return render_show_policy(&workspace);
            }
            report(
                workspace,
                format,
                fail_on_violation,
                &pstore,
                &packguard_home,
            )
            .await
        }
        Cmd::Scan {
            path,
            project,
            offline,
            force,
            no_recursive,
            depth,
            include_globs,
            exclude_globs,
            dry_run,
            yes,
        } => {
            let scope = resolve_scope_or_default(
                project.as_deref(),
                Some(&path),
                &mut registry,
                &packguard_home,
                &cwd,
            )?;
            announce_scope(&scope, "scan");
            let pstore = project_stores.get_or_open(&scope.slug).await?;
            scan(
                path,
                ScanOptions {
                    offline,
                    force,
                    no_recursive,
                    depth,
                    include_globs,
                    exclude_globs,
                    dry_run,
                    yes,
                },
                &pstore,
            )
            .await
        }
        Cmd::Ui {
            path,
            project,
            port,
            host,
            no_open,
        } => {
            let scope = resolve_scope_or_default(
                project.as_deref(),
                path.as_deref(),
                &mut registry,
                &packguard_home,
                &cwd,
            )?;
            announce_scope(&scope, "ui");
            let pstore = project_stores.get_or_open(&scope.slug).await?;
            ui(
                scope.workspace_path.clone(),
                port,
                host,
                no_open,
                &packguard_home,
                &pstore,
                project_stores.clone(),
            )
            .await
        }
        Cmd::Sync {
            skip_osv,
            skip_ghsa,
            ghsa_cache,
            all,
        } => sync(skip_osv, skip_ghsa, ghsa_cache, all, &packguard_home).await,
        Cmd::Graph {
            path,
            project,
            workspace,
            focus,
            contaminated_by,
            max_depth,
            kind,
            format,
        } => {
            let scope = resolve_scope_or_default(
                project.as_deref(),
                path.as_deref(),
                &mut registry,
                &packguard_home,
                &cwd,
            )?;
            announce_scope(&scope, "graph");
            let pstore = project_stores.get_or_open(&scope.slug).await?;
            let repo_path =
                resolve_workspace_in_project(&pstore, scope.workspace_path.clone(), "graph")
                    .await?;
            graph(
                repo_path,
                workspace.as_deref(),
                focus.as_deref(),
                contaminated_by.as_deref(),
                max_depth,
                kind.as_deref(),
                format,
                &pstore,
                &packguard_home,
            )
            .await
        }
        Cmd::Scans { json } => scans(json, project_stores.clone()).await,
        Cmd::Actions(args) => {
            actions_cli::run(
                args,
                &mut registry,
                project_stores.clone(),
                &packguard_home,
                &cwd,
            )
            .await
        }
    }
}

/// Wrapper around [`resolve_cli_scope`] that also materializes the
/// matching registry row. Keeps every command's dispatch arm one line
/// lighter.
///
/// - `_default_` (no `.git/` ancestor) → [`ensure_default_registered`].
/// - Path-derived sources (cwd walk-up, legacy `--project <path>`) →
///   [`ensure_project_registered`] (Phase 14.5a / Bug B). When the row
///   is freshly created, prints a one-line stderr banner so the user
///   knows their first scan in a new repo just registered the project.
/// - Slug-form sources (`--project <slug>`, `PACKGUARD_PROJECT`) →
///   no auto-register; a typo there should fail loudly downstream
///   when the per-project store is empty.
fn resolve_scope_or_default(
    flag: Option<&str>,
    positional: Option<&Path>,
    registry: &mut ProjectsRegistry,
    packguard_home: &Path,
    cwd: &Path,
) -> Result<ResolvedCliScope> {
    let scope = resolve_cli_scope(flag, positional, registry, cwd)?;
    if matches!(scope.source, ScopeSource::Default) {
        ensure_default_registered(registry, packguard_home)?;
    } else if let Some(root) = ensure_project_registered(&scope, registry)? {
        eprintln!(
            "{} Registered project: {} ({})",
            "✓".green(),
            scope.slug.cyan(),
            root.display(),
        );
    }
    Ok(scope)
}

/// One-line stderr banner so the user always knows which project a
/// command landed on, plus the deprecation warning for the legacy
/// `--project <path>` form.
fn announce_scope(scope: &ResolvedCliScope, command: &str) {
    let suffix = match &scope.source {
        ScopeSource::ExplicitFlagSlug => "explicit slug",
        ScopeSource::ExplicitFlagPath(_) => "from --project (deprecated path form)",
        ScopeSource::EnvVar => "from PACKGUARD_PROJECT",
        ScopeSource::Cwd(_) => "auto-detected from cwd",
        ScopeSource::Default => "fallback (no .git/ ancestor)",
    };
    eprintln!(
        "{} {command}: project {} ({})",
        "ⓘ".dimmed(),
        scope.slug.cyan(),
        suffix.dimmed(),
    );
    if scope.deprecated() {
        eprintln!(
            "{} `--project <path>` is deprecated; use the slug form \
             (`--project {}`) or rely on cwd auto-detection.",
            "warn".yellow(),
            scope.slug,
        );
    }
}

/// Resolve a workspace filter inside an already-opened project store.
/// Mirrors the v0.5.x `resolve_project_for_command` semantics — pick
/// the most-recent scan as the default — but scoped to the project
/// store so a user with multiple projects never accidentally sees
/// scans from a different repo.
async fn resolve_workspace_in_project(
    pstore: &Arc<Mutex<Store>>,
    explicit: Option<PathBuf>,
    command_name: &str,
) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let store = pstore.lock().await;
    let scans = store.scans_index().unwrap_or_default();
    let Some(first) = scans.into_iter().next() else {
        anyhow::bail!(
            "no cached scan found for `packguard {command_name}` in this project. \
             Run `packguard scan <path>` first, then re-try — or pass an explicit \
             path / --project argument.",
        );
    };
    eprintln!(
        "{} {command_name}: defaulting to {} {}",
        "ⓘ".dimmed(),
        first.path.display().to_string().cyan(),
        "(most recent scan in this project; pass a path to override)".dimmed()
    );
    Ok(first.path)
}

async fn sync(
    skip_osv: bool,
    skip_ghsa: bool,
    ghsa_cache: Option<PathBuf>,
    include_all: bool,
    packguard_home: &Path,
) -> Result<()> {
    // Phase 14.2b.2.4 — sync's project-layer reads (`watched_packages`)
    // fan out across every per-project store. The legacy `Store` is
    // no longer opened by the sync flow.
    let home = packguard_home.to_path_buf();
    let mut intel = IntelStore::open(&home)
        .with_context(|| format!("opening intel store under {}", home.display()))?;
    let project_stores = packguard_store::ProjectStoreCache::new(home.clone());

    let watched: packguard_intel::WatchedPackages = if include_all {
        None
    } else {
        let pairs = collect_watched_across_projects(&project_stores).await?;
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
            let prior_state = intel.get_sync_state(dump.id)?;
            let prior = packguard_intel::osv::PriorSyncState {
                etag: prior_state.as_ref().and_then(|s| s.etag.clone()),
                last_modified: prior_state.as_ref().and_then(|s| s.last_modified.clone()),
            };
            match packguard_intel::osv::fetch_dump(dump, &prior, &watched).await {
                Ok(fetched) => {
                    if fetched.summary.skipped_not_modified {
                        // 304 Not Modified — the dump hasn't changed
                        // since last sync, but we've *verified* that.
                        // Bump `synced_at` so `RefreshSync` (generator)
                        // doesn't treat the CI-run as "never re-checked"
                        // while keeping etag/last_modified/record_count
                        // so the next If-None-Match keeps short-circuiting.
                        // See `packguard-intel/src/osv.rs:89-101` for
                        // the 304 branch that returns
                        // `updated_state: None`.
                        let state = refreshed_sync_state_for_304(prior_state, Utc::now());
                        intel.put_sync_state(dump.id, &state)?;
                        println!(
                            "{} {} — not modified since last sync (re-checked)",
                            "=".dimmed(),
                            dump.id
                        );
                    } else {
                        let persisted_v =
                            intel.persist_vulnerabilities(&fetched.vulnerabilities)?;
                        let persisted_m =
                            intel.persist_malware_reports(&fetched.malware_reports)?;
                        let persisted = persisted_v + persisted_m;
                        if let Some(updated) = fetched.updated_state {
                            let mut state = prior_state.unwrap_or_default();
                            state.etag = updated.etag;
                            state.last_modified = updated.last_modified;
                            state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                            state.record_count = persisted as i64;
                            intel.put_sync_state(dump.id, &state)?;
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
                let persisted_v = intel.persist_vulnerabilities(&vulns)?;
                let persisted_m = intel.persist_malware_reports(&malware)?;
                let persisted = persisted_v + persisted_m;
                let mut state = intel.get_sync_state("ghsa")?.unwrap_or_default();
                state.last_commit = Some(head);
                state.synced_at = Some(chrono::Utc::now().to_rfc3339());
                state.record_count = persisted as i64;
                intel.put_sync_state("ghsa", &state)?;
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

    let total = intel.count_vulnerabilities()?;
    // ---- typosquat refresh + scoring ----
    refresh_typosquat_lists(&mut intel).await;
    let watched_pairs = collect_watched_across_projects(&project_stores).await?;
    let typosquat_persisted = score_typosquat_against_watched(&mut intel, &watched_pairs)?;
    if typosquat_persisted > 0 {
        println!(
            "{} typosquat — {} suspect package(s) flagged",
            "✓".green(),
            typosquat_persisted
        );
    }

    let mal_total = intel.count_malware_reports()?;
    println!(
        "{} store holds {} advisories + {} malware reports",
        "📚".dimmed(),
        total,
        mal_total,
    );
    Ok(())
}

/// Build the refreshed `sync_log` row when OSV returned `304 Not
/// Modified`. Keeps `etag` / `last_modified` / `record_count` as they
/// were (the upstream dump is byte-identical to last sync) and bumps
/// only `synced_at` so the `RefreshSync` generator sees the
/// re-verification. Extracted so the unit tests below can assert the
/// semantics without spinning up a mock HTTP server.
fn refreshed_sync_state_for_304(
    prior: Option<packguard_store::SyncState>,
    now: chrono::DateTime<chrono::Utc>,
) -> packguard_store::SyncState {
    let mut state = prior.unwrap_or_default();
    state.synced_at = Some(now.to_rfc3339());
    state
}

/// Refresh the PyPI top-N reference list when the cache is older than 7
/// days. Failures are non-fatal — typosquat scoring will fall back to the
/// embedded npm baseline + whatever the cache already holds.
async fn refresh_typosquat_lists(intel: &mut IntelStore) {
    const KIND: &str = "typosquat-pypi-top";
    let prior = match intel.get_sync_state(KIND) {
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
            if let Err(err) = intel.put_sync_state(KIND, &state) {
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

/// Score every watched package and persist the suspects to IntelStore.
/// 14.2b.2.4 — `watched` is now collected across every per-project
/// store via [`ProjectStoreCache::slug_paths`]; the legacy `Store`
/// is no longer the source of truth.
fn score_typosquat_against_watched(
    intel: &mut IntelStore,
    watched: &[(String, String)],
) -> Result<usize> {
    if watched.is_empty() {
        return Ok(0);
    }
    let npm = packguard_intel::typosquat::refresh::load_npm_top()?;
    let pypi = packguard_intel::typosquat::refresh::load_pypi_top()?;
    let scorer_npm = packguard_intel::typosquat::Scorer::new(npm);
    let scorer_pypi = packguard_intel::typosquat::Scorer::new(pypi);
    let mut reports: Vec<packguard_core::MalwareReport> = Vec::new();
    for (eco, name) in watched {
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
    intel.persist_malware_reports(&reports)?;
    Ok(reports.len())
}

/// Phase 14.2b.2.4 — union of every `(ecosystem, name)` pair tracked
/// across every per-project store under `<home>/projects/<slug>/`.
/// Empty when the registry has no projects yet.
async fn collect_watched_across_projects(
    project_stores: &packguard_store::ProjectStoreCache,
) -> Result<Vec<(String, String)>> {
    let mut acc: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for (slug, _) in project_stores.slug_paths()? {
        let pstore = project_stores.get_or_open(&slug).await?;
        let pstore = pstore.lock().await;
        for pair in pstore.watched_packages()? {
            acc.insert(pair);
        }
    }
    Ok(acc.into_iter().collect())
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

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum GraphFormat {
    /// Indented tree — sensible default for terminal use.
    Ascii,
    /// Graphviz DOT — pipe into `dot -Tsvg` for a rendered graph.
    Dot,
    /// Raw `GraphResponse` / `ContaminationResult` JSON.
    Json,
}

/// Phase 8.5 — CI snippet providers `packguard init --with-ci` can
/// emit. Kept tight on purpose: each variant maps to a recipe under
/// `docs/integrations/` that this command only needs to point at, not
/// replicate in full.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum CiProvider {
    Gitlab,
    Github,
    Jenkins,
}

fn init(path: PathBuf, force: bool, with_ci: Option<CiProvider>) -> Result<()> {
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

    // Phase 8.5 — CI snippet emission. Explicit --with-ci always writes;
    // otherwise we only hint based on the VCS layout (.gitlab-ci.yml
    // present → suggest gitlab, .github/workflows/ → suggest github).
    if let Some(provider) = with_ci {
        emit_ci_snippet(&path, provider, force)?;
    } else {
        hint_ci_provider(&path);
    }
    Ok(())
}

/// Write `.packguard/ci/<provider>.yml` — a minimal, copy-pasteable
/// snippet. The full recipe (cache tuning, MR-only gates, SARIF
/// upload, …) stays in `docs/integrations/<provider>*.md`; this file
/// exists so the user can pipe it into their pipeline without leaving
/// the repo.
fn emit_ci_snippet(path: &Path, provider: CiProvider, force: bool) -> Result<()> {
    let (filename, body, doc_link) = match provider {
        CiProvider::Gitlab => (
            "gitlab.yml",
            GITLAB_CI_SNIPPET,
            "docs/integrations/gitlab-ci.md",
        ),
        CiProvider::Github => (
            "github.yml",
            GITHUB_ACTIONS_SNIPPET,
            "docs/integrations/github-actions.md",
        ),
        CiProvider::Jenkins => (
            "Jenkinsfile",
            JENKINS_SNIPPET,
            "docs/integrations/pre-commit.md",
        ),
    };

    let dir = path.join(".packguard").join("ci");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let target = dir.join(filename);
    if target.exists() && !force {
        anyhow::bail!(
            "{} already exists; rerun with --force to overwrite",
            target.display()
        );
    }
    std::fs::write(&target, body).with_context(|| format!("writing {}", target.display()))?;
    println!(
        "{} wrote {} — paste into your pipeline (full recipe: {})",
        "✓".green(),
        target.display().to_string().bold(),
        doc_link
    );
    Ok(())
}

/// No explicit --with-ci: detect the repo's VCS layout and print a
/// single hint pointing at the right provider + doc. Never writes.
fn hint_ci_provider(path: &Path) {
    let has_gitlab = path.join(".gitlab-ci.yml").exists();
    let has_github = path.join(".github").join("workflows").is_dir();
    let (provider, doc_link) = match (has_gitlab, has_github) {
        (true, _) => ("gitlab", "docs/integrations/gitlab-ci.md"),
        (_, true) => ("github", "docs/integrations/github-actions.md"),
        _ => return,
    };
    println!(
        "{} detected {} — run `packguard init --with-ci {}` to emit a snippet ({})",
        "•".dimmed(),
        provider,
        provider,
        doc_link
    );
}

const GITLAB_CI_SNIPPET: &str = r#"# .packguard/ci/gitlab.yml
# Paste under your existing `stages:` + adjust the image tag if you've
# pinned a specific PackGuard version. Full recipe:
# https://github.com/Tmauc/packguard/blob/main/docs/integrations/gitlab-ci.md
#
# - scan walks lockfiles and persists deps into the cached SQLite store.
# - sync refreshes OSV + GHSA + malware intel (network-heavy; consider
#   moving it to a scheduled pipeline if your MR turnaround needs to
#   stay under 30s).
# - report --format sarif --fail-on-violation exits non-zero on a
#   blocking CVE and feeds the Security panel via `reports.sast`.

packguard:
  stage: security
  image: ghcr.io/tmauc/packguard:latest
  variables:
    HOME: "$CI_PROJECT_DIR/.packguard-cache"
  cache:
    key:
      files:
        - package-lock.json
        - pnpm-lock.yaml
        - yarn.lock
        - poetry.lock
        - uv.lock
        - requirements.txt
    paths:
      - .packguard-cache/
  before_script:
    - mkdir -p "$HOME/.packguard"
  script:
    - packguard scan .
    - packguard sync
    - packguard report . --format sarif --fail-on-violation > packguard.sarif
  artifacts:
    when: always
    expire_in: 30 days
    paths:
      - packguard.sarif
    reports:
      sast: packguard.sarif
"#;

const GITHUB_ACTIONS_SNIPPET: &str = r#"# .packguard/ci/github.yml
# Paste into .github/workflows/. Full recipe:
# https://github.com/Tmauc/packguard/blob/main/docs/integrations/github-actions.md

name: packguard
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  packguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: install packguard
        run: |
          curl -fsSL https://raw.githubusercontent.com/Tmauc/packguard/main/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - uses: actions/cache@v4
        with:
          path: ~/.packguard
          key: packguard-${{ runner.os }}-${{ hashFiles('**/package-lock.json', '**/pnpm-lock.yaml', '**/yarn.lock', '**/poetry.lock', '**/uv.lock', '**/requirements*.txt') }}
          restore-keys: |
            packguard-${{ runner.os }}-
      - run: packguard scan .
      - run: packguard sync
      - run: packguard report . --format sarif --fail-on-violation > packguard.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: packguard.sarif
          category: packguard
"#;

const JENKINS_SNIPPET: &str = r#"// .packguard/ci/Jenkinsfile
// Declarative stage — drop inside your existing `stages { ... }` block.
// No official Jenkins-specific recipe yet; the generic scan → sync →
// audit sequence works identically to the shell step below.

stage('packguard') {
  agent {
    docker { image 'ghcr.io/tmauc/packguard:latest' }
  }
  environment {
    HOME = "${WORKSPACE}/.packguard-cache"
  }
  steps {
    sh 'mkdir -p "$HOME/.packguard"'
    sh 'packguard scan .'
    sh 'packguard sync'
    sh 'packguard audit . --fail-on critical --fail-on-malware'
  }
  post {
    always {
      archiveArtifacts artifacts: 'packguard.sarif', allowEmptyArchive: true
    }
  }
}
"#;

async fn ui(
    path: Option<PathBuf>,
    port: u16,
    host: String,
    no_open: bool,
    packguard_home: &Path,
    pstore: &Arc<Mutex<Store>>,
    project_stores: Arc<ProjectStoreCache>,
) -> Result<()> {
    // 14.2d — `ServerConfig` no longer carries a legacy `Store` field;
    // jobs moved to IntelStore and aggregate reads route exclusively
    // through `project_stores`. The CLI hands the server only the
    // intel handle + the per-project cache.
    let intel = IntelStore::open(packguard_home)
        .with_context(|| format!("opening intel store under {}", packguard_home.display()))?;
    let projects = ProjectsRegistry::open(packguard_home).with_context(|| {
        format!(
            "opening projects registry under {}",
            packguard_home.display()
        )
    })?;

    // Resolve the server's view root from the per-project store:
    //  - explicit path → canonicalize + use as-is.
    //  - no path + project store has scans → most recent one.
    //  - no path + empty project store → CWD sentinel + "no scans" banner.
    let recent: Option<PathBuf> = {
        let store = pstore.lock().await;
        store
            .scans_index()
            .unwrap_or_default()
            .into_iter()
            .next()
            .map(|r| r.path)
    };
    let (repo_path, resolution_note): (PathBuf, String) = match (path, recent) {
        (Some(p), _) => {
            let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
            (
                canonical.clone(),
                format!(
                    "{} workspace: {}",
                    "→".dimmed(),
                    canonical.display().to_string().cyan()
                ),
            )
        }
        (None, Some(first)) => (
            first.clone(),
            format!(
                "{} workspace: {} {} (override with `packguard ui <path>`)",
                "→".dimmed(),
                first.display().to_string().cyan(),
                "(most recent scan in this project)".dimmed(),
            ),
        ),
        (None, None) => (
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            format!(
                "{} no scans yet — run `{}` to register one",
                "ⓘ".yellow(),
                "packguard scan <path>".cyan()
            ),
        ),
    };

    let app = packguard_server::router(packguard_server::ServerConfig {
        repo_path: repo_path.clone(),
        intel,
        projects,
        project_stores,
    });
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
    println!("{resolution_note}");
    // Banner + auto-open honor the `ui-embed` feature:
    // - feature ON → the binary itself serves `/` (and SPA routes). Point
    //   the browser at `url`, print an affirmative embed line so users
    //   don't expect a separate dev server.
    // - feature OFF → the Rust server only exposes `/api/*`. The dashboard
    //   runs in Vite at :5173 which proxies `/api/*` back here; the
    //   browser must open :5173, not the API port.
    let (banner_url, dashboard_line) = if cfg!(feature = "ui-embed") {
        (
            url.clone(),
            format!(
                "{} dashboard served inline (ui-embed feature)",
                "→".dimmed()
            ),
        )
    } else {
        (
            "http://127.0.0.1:5173".to_string(),
            format!(
                "{} dashboard: {} (run `pnpm --dir dashboard dev` to start Vite)",
                "→".dimmed(),
                "http://127.0.0.1:5173".cyan()
            ),
        )
    };
    println!("{dashboard_line}");
    if !no_open {
        if let Err(err) = open::that_detached(&banner_url) {
            tracing::warn!(?err, "could not auto-open browser");
        }
    }
    println!("{} press Ctrl+C to stop\n", "•".dimmed());
    // Flush so the banner lands in piped stdout (tests, CI) before we
    // hand control to axum — otherwise a hard kill in the middle of
    // `serve` can drop buffered bytes on the floor.
    use std::io::Write;
    let _ = std::io::stdout().flush();
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

#[allow(clippy::too_many_arguments)]
async fn graph(
    path: PathBuf,
    workspace: Option<&str>,
    focus: Option<&str>,
    contaminated_by: Option<&str>,
    max_depth: Option<u32>,
    kind: Option<&str>,
    format: GraphFormat,
    pstore: &Arc<Mutex<Store>>,
    packguard_home: &Path,
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let store = pstore.lock().await;
    let intel = IntelStore::open(packguard_home).with_context(|| "opening IntelStore")?;
    let repo_path = path.canonicalize().unwrap_or(path);

    // Honest error when the repo hasn't been scanned. The graph service
    // silently returns empty in that case, which is technically correct
    // but not actionable — surface the "available scans" hint so users
    // don't think the feature is broken.
    if store.load_repo_dependencies(&repo_path)?.is_empty() {
        anyhow::bail!(
            "no cached scan for {}; run `packguard scan` first{}",
            repo_path.display(),
            available_scans_hint(&store),
        );
    }

    // Branch: contamination view overrides focus + graph.
    if let Some(advisory) = contaminated_by {
        let result = packguard_server::services::graph::contaminated_chains(
            &store,
            &intel,
            Some(&repo_path),
            advisory,
        )?;
        match format {
            GraphFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            GraphFormat::Dot => {
                print_contamination_dot(advisory, &result);
                return Ok(());
            }
            GraphFormat::Ascii => {
                print_contamination_ascii(advisory, &result);
                return Ok(());
            }
        }
    }

    let response = packguard_server::services::graph::build(
        &store,
        &intel,
        Some(&repo_path),
        workspace,
        max_depth,
        kind,
    )?;

    // Optional `--focus` narrows to the forward-reachable subtree from a
    // single node. Cheaper + more ergonomic than piping through grep.
    let (nodes, edges) = if let Some(anchor) = focus {
        narrow_to_subtree(&response, anchor)
    } else {
        (response.nodes.to_vec(), response.edges.to_vec())
    };

    match format {
        GraphFormat::Json => {
            let narrowed = packguard_server::dto::GraphResponse {
                nodes: nodes.clone(),
                edges: edges.clone(),
                oversize_warning: response.oversize_warning.clone(),
            };
            println!("{}", serde_json::to_string_pretty(&narrowed)?);
        }
        GraphFormat::Dot => print_graph_dot(&nodes, &edges),
        GraphFormat::Ascii => print_graph_ascii(&nodes, &edges),
    }

    // --- nested helpers — kept local so the top of the file stays readable.

    fn narrow_to_subtree(
        resp: &packguard_server::dto::GraphResponse,
        anchor: &str,
    ) -> (
        Vec<packguard_server::dto::GraphNode>,
        Vec<packguard_server::dto::GraphEdge>,
    ) {
        let mut by_source: BTreeMap<&str, Vec<&packguard_server::dto::GraphEdge>> = BTreeMap::new();
        for e in &resp.edges {
            by_source.entry(e.source.as_str()).or_default().push(e);
        }
        let mut keep_nodes: BTreeSet<String> = BTreeSet::new();
        let mut keep_edges: Vec<packguard_server::dto::GraphEdge> = Vec::new();
        let mut queue: VecDeque<String> = VecDeque::from([anchor.to_string()]);
        while let Some(id) = queue.pop_front() {
            if !keep_nodes.insert(id.clone()) {
                continue;
            }
            if let Some(children) = by_source.get(id.as_str()) {
                for e in children {
                    keep_edges.push((*e).clone());
                    queue.push_back(e.target.clone());
                }
            }
        }
        let nodes: Vec<_> = resp
            .nodes
            .iter()
            .filter(|n| keep_nodes.contains(&n.id))
            .cloned()
            .collect();
        (nodes, keep_edges)
    }

    fn print_graph_ascii(
        nodes: &[packguard_server::dto::GraphNode],
        edges: &[packguard_server::dto::GraphEdge],
    ) {
        use owo_colors::OwoColorize;
        let mut children: BTreeMap<&str, Vec<&packguard_server::dto::GraphEdge>> = BTreeMap::new();
        for e in edges {
            children.entry(e.source.as_str()).or_default().push(e);
        }
        for v in children.values_mut() {
            v.sort_by(|a, b| a.target.cmp(&b.target));
        }
        let roots: Vec<&packguard_server::dto::GraphNode> =
            nodes.iter().filter(|n| n.is_root).collect();
        if roots.is_empty() {
            println!("{}", "(no roots in the narrowed graph)".dimmed());
            return;
        }
        let mut visited: BTreeSet<String> = BTreeSet::new();
        for root in roots {
            print_ascii_node(root, &children, nodes, "", true, &mut visited);
        }
    }

    fn print_ascii_node(
        node: &packguard_server::dto::GraphNode,
        children: &BTreeMap<&str, Vec<&packguard_server::dto::GraphEdge>>,
        all_nodes: &[packguard_server::dto::GraphNode],
        prefix: &str,
        last: bool,
        visited: &mut BTreeSet<String>,
    ) {
        use owo_colors::OwoColorize;
        let connector = if prefix.is_empty() {
            ""
        } else if last {
            "└── "
        } else {
            "├── "
        };
        let mut label = format!("{}@{}", node.name, node.version);
        if let Some(sev) = &node.cve_severity {
            label = format!("{} {}", label, format!("({sev} CVE)").red());
        }
        if node.has_malware {
            label = format!("{} {}", label, "(malware)".purple());
        }
        if node.is_root {
            label = format!("{}", label.bold());
        }
        println!("{prefix}{connector}{label}");
        if !visited.insert(node.id.clone()) {
            return;
        }
        let Some(outs) = children.get(node.id.as_str()) else {
            return;
        };
        for (i, e) in outs.iter().enumerate() {
            let is_last = i + 1 == outs.len();
            let child_prefix = if prefix.is_empty() {
                if is_last {
                    "   ".to_string()
                } else {
                    "│  ".to_string()
                }
            } else if last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            // Since Polish-bis-1 the backend emits a placeholder node for
            // every unresolved edge target, so `all_nodes.find()` now
            // succeeds even for peer/optional deps absent from the
            // lockfile. We still want the ascii output to call them out
            // as "(unresolved peer)" rather than treat them as first-
            // class children — the flag carried on the node itself.
            let connector = if is_last { "└── " } else { "├── " };
            let resolved_child = all_nodes.iter().find(|n| n.id == e.target);
            if let Some(child) = resolved_child {
                if child.is_unresolved || e.unresolved {
                    println!(
                        "{child_prefix}{connector}{} {}",
                        e.target,
                        "(unresolved peer)".yellow()
                    );
                } else {
                    print_ascii_node(child, children, all_nodes, &child_prefix, is_last, visited);
                }
            } else if e.unresolved {
                // Safety net for older servers that never emit the
                // placeholder node — we still show the warning.
                println!(
                    "{child_prefix}{connector}{} {}",
                    e.target,
                    "(unresolved peer)".yellow()
                );
            }
        }
    }

    fn print_graph_dot(
        nodes: &[packguard_server::dto::GraphNode],
        edges: &[packguard_server::dto::GraphEdge],
    ) {
        println!("digraph packguard {{");
        println!("  rankdir=LR;");
        println!("  node [shape=box, style=rounded, fontname=\"Helvetica\"];");
        for n in nodes {
            let fill = match n.ecosystem.as_str() {
                "npm" => "#dbeafe",
                "pypi" => "#dcfce7",
                _ => "#f4f4f5",
            };
            let mut extra = String::new();
            if n.cve_severity.is_some() {
                extra.push_str(" color=\"#dc2626\" penwidth=2");
            }
            if n.has_malware {
                extra.push_str(" color=\"#a855f7\" penwidth=2");
            }
            if n.is_root {
                extra.push_str(" fontname=\"Helvetica-Bold\"");
            }
            println!(
                "  \"{}\" [label=\"{}\\n{}\", fillcolor=\"{}\", style=\"rounded,filled\"{}];",
                dot_escape(&n.id),
                dot_escape(&n.name),
                dot_escape(&n.version),
                fill,
                extra,
            );
        }
        for e in edges {
            let style = match e.kind.as_str() {
                "dev" => " color=\"#3b82f6\"",
                "peer" => " color=\"#f97316\", style=dashed",
                "optional" => " color=\"#a1a1aa\", style=dotted",
                _ => "",
            };
            println!(
                "  \"{}\" -> \"{}\" [label=\"{}\"{}];",
                dot_escape(&e.source),
                dot_escape(&e.target),
                dot_escape(&e.kind),
                style,
            );
        }
        println!("}}");
    }

    fn dot_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn print_contamination_ascii(
        advisory: &str,
        result: &packguard_server::dto::ContaminationResult,
    ) {
        use owo_colors::OwoColorize;
        println!(
            "{} — {} hit(s), {} chain(s){}",
            advisory.bold(),
            result.hits.len(),
            result.chains.len(),
            if result.from_cache {
                " · cached".dimmed().to_string()
            } else {
                String::new()
            },
        );
        if result.hits.is_empty() {
            println!(
                "  {}",
                "no installed package matches this advisory".dimmed()
            );
            return;
        }
        for (i, chain) in result.chains.iter().enumerate() {
            println!("\n  chain {}: {}", i + 1, chain.workspace.dimmed());
            for (j, id) in chain.path.iter().enumerate() {
                let marker = if j == 0 {
                    "┌"
                } else if j + 1 == chain.path.len() {
                    "└"
                } else {
                    "│"
                };
                let painted = if j + 1 == chain.path.len() {
                    id.red().to_string()
                } else {
                    id.clone()
                };
                println!("    {marker}── {painted}");
            }
        }
    }

    fn print_contamination_dot(
        advisory: &str,
        result: &packguard_server::dto::ContaminationResult,
    ) {
        println!("digraph contamination {{");
        println!("  rankdir=LR;");
        println!("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];");
        println!(
            "  label=\"{} — {} chain(s)\";",
            dot_escape(advisory),
            result.chains.len()
        );
        let hit_ids: BTreeSet<String> = result
            .hits
            .iter()
            .map(|h| format!("{}:{}@{}", h.ecosystem, h.name, h.version))
            .collect();
        let mut emitted_nodes: BTreeSet<String> = BTreeSet::new();
        for chain in &result.chains {
            for (i, id) in chain.path.iter().enumerate() {
                if emitted_nodes.insert(id.clone()) {
                    let fill = if hit_ids.contains(id) {
                        "#fecaca"
                    } else {
                        "#f4f4f5"
                    };
                    println!(
                        "  \"{}\" [label=\"{}\", fillcolor=\"{}\"];",
                        dot_escape(id),
                        dot_escape(id),
                        fill
                    );
                }
                if i > 0 {
                    println!(
                        "  \"{}\" -> \"{}\" [color=\"#dc2626\"];",
                        dot_escape(&chain.path[i - 1]),
                        dot_escape(id),
                    );
                }
            }
        }
        println!("}}");
    }

    Ok(())
}

/// Dump every registered scan (path, ecosystem, last scan, dep count) so
/// the user can see what they've already scanned when report/audit/graph
/// bail with "no cached scan". `--json` for machine parsing.
///
/// 14.2c — fans out across every per-project store via
/// [`ProjectStoreCache::slug_paths`], so a user with multiple registered
/// projects sees the union of their scans without ever touching the
/// legacy `~/.packguard/store.db`.
async fn scans(as_json: bool, project_stores: Arc<ProjectStoreCache>) -> Result<()> {
    let mut rows: Vec<packguard_store::ScanIndexRow> = Vec::new();
    for (slug, _) in project_stores.slug_paths()? {
        let pstore = project_stores.get_or_open(&slug).await?;
        let store = pstore.lock().await;
        rows.extend(store.scans_index()?);
    }
    // Same ordering as the legacy single-store impl: most-recent first
    // (`last_scan_at DESC`), tie-break on path for deterministic output.
    rows.sort_by(|a, b| {
        b.last_scan_at
            .cmp(&a.last_scan_at)
            .then(a.path.cmp(&b.path))
    });
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &rows
                    .iter()
                    .map(|r| serde_json::json!({
                        "path": r.path,
                        "ecosystem": r.ecosystem,
                        "last_scan_at": r.last_scan_at,
                        "fingerprint": r.fingerprint,
                        "dependency_count": r.dependency_count,
                    }))
                    .collect::<Vec<_>>(),
            )?
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!(
            "{} no scans in store — run `packguard scan <path>` to register one",
            "ⓘ".dimmed(),
        );
        return Ok(());
    }
    let mut table = comfy_table::Table::new();
    table.set_header(vec![
        "Path",
        "Ecosystem",
        "Deps",
        "Last scan",
        "Fingerprint",
    ]);
    for r in rows {
        let fp_short: String = r.fingerprint.chars().take(12).collect();
        table.add_row(vec![
            r.path.display().to_string(),
            r.ecosystem,
            r.dependency_count.to_string(),
            r.last_scan_at,
            format!("{fp_short}…"),
        ]);
    }
    println!("{table}");
    Ok(())
}

/// Format an "available scans" hint for error messages when a command
/// lands on an unknown path. Returns an empty string when the store is
/// also empty so we don't recommend nothing.
fn available_scans_hint(store: &Store) -> String {
    let rows = match store.scans_index() {
        Ok(r) => r,
        Err(_) => return String::new(),
    };
    if rows.is_empty() {
        return "\n  (no scans in store — run `packguard scan <path>` first)".to_string();
    }
    let mut out = String::from("\n  Available scans:\n");
    for r in rows.iter().take(10) {
        out.push_str(&format!(
            "    - {} [{}] · {} deps · last scan {}\n",
            r.path.display(),
            r.ecosystem,
            r.dependency_count,
            r.last_scan_at,
        ));
    }
    if rows.len() > 10 {
        out.push_str(&format!(
            "    … {} more (packguard scans)\n",
            rows.len() - 10
        ));
    }
    out.push_str("  Run `packguard scans` to list the full set.");
    out
}

fn resolve_store_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    Ok(resolve_packguard_home_default()?.join("store.db"))
}

/// Default packguard home: `$PACKGUARD_HOME` if set (used by tests +
/// smoke), else `~/.packguard/`. Callers that already have an
/// explicit `--store` flag should derive home from
/// `store_path.parent()` instead so the override applies to every
/// new file (intel.db, projects.db, projects/<slug>/store.db).
fn resolve_packguard_home_default() -> Result<PathBuf> {
    if let Ok(env_home) = std::env::var("PACKGUARD_HOME") {
        return Ok(PathBuf::from(env_home));
    }
    let home = dirs::home_dir().context("resolving home directory for default packguard home")?;
    Ok(home.join(".packguard"))
}

/// Derive the packguard home from a fully-resolved store path. The
/// store always lives at `<home>/store.db`, so `parent()` is the
/// authoritative source — works for `--store`, `PACKGUARD_HOME`, and
/// the default path alike.
fn home_from_store_path(store_path: &Path) -> PathBuf {
    store_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[derive(Debug, Clone)]
struct ScanOptions {
    offline: bool,
    force: bool,
    no_recursive: bool,
    depth: usize,
    include_globs: Vec<String>,
    exclude_globs: Vec<String>,
    dry_run: bool,
    yes: bool,
}

/// Short summary returned by `handle_project` so the caller can print
/// the per-project progress line without re-traversing the project.
#[derive(Debug, Clone, Copy, Default)]
struct ScanProjectSummary {
    deps: usize,
    skipped_unchanged: bool,
}

async fn scan(path: PathBuf, opts: ScanOptions, pstore: &Arc<Mutex<Store>>) -> Result<()> {
    use packguard_core::DiscoveryOptions;

    let discovery_opts = DiscoveryOptions {
        max_depth: opts.depth,
        no_recursive: opts.no_recursive,
        include_globs: opts.include_globs.clone(),
        exclude_globs: opts.exclude_globs.clone(),
    };

    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    println!(
        "{} Discovering projects under {} …",
        "🔍".dimmed(),
        path.display().to_string().bold(),
    );
    let outcome = packguard_core::discover(&path, &discovery_opts)
        .with_context(|| format!("discovering projects under {}", path.display()))?;

    for warn in &outcome.warnings {
        eprintln!("{} {}", "warn".yellow(), warn);
    }

    if outcome.projects.is_empty() {
        if opts.no_recursive {
            anyhow::bail!(
                "no supported manifest at {} (try dropping --no-recursive)",
                path.display(),
            );
        }
        anyhow::bail!(
            "no scannable projects found under {}. \
             Point at a project root, or pass `--include '<glob>'` to widen discovery.",
            path.display(),
        );
    }

    // Pretty discovery summary.
    print_discovery_summary(&outcome);

    if opts.dry_run {
        println!(
            "\n{} {} project{} would be scanned.",
            "→".dimmed(),
            outcome.projects.len().to_string().bold(),
            if outcome.projects.len() == 1 { "" } else { "s" },
        );
        return Ok(());
    }

    if outcome.is_large() && !opts.yes && !prompt_continue(outcome.projects.len())? {
        println!("{} aborted.", "✕".red());
        return Ok(());
    }

    let ecosystems = default_ecosystems()?;
    let mut store = pstore.lock().await;

    let multi = outcome.projects.len() > 1;
    let mut scanned = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<(PathBuf, anyhow::Error)> = Vec::new();

    if multi {
        println!("\n{}", "Scanning…".bold());
    }

    for discovered in &outcome.projects {
        let label = project_label(discovered);
        let mut any_eco_hit = false;

        for eco in &ecosystems {
            let projects = match eco.detect(&discovered.path) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!(
                        "{} {} detect failed: {:#}",
                        "warn".yellow(),
                        format!("[{}]", eco.id()).dimmed(),
                        err,
                    );
                    continue;
                }
            };
            if projects.is_empty() {
                continue;
            }
            any_eco_hit = true;
            for project in projects {
                let outcome = handle_project(
                    &mut store,
                    &**eco,
                    &project,
                    &discovered.path,
                    opts.offline,
                    opts.force,
                    multi,
                )
                .await;
                match outcome {
                    Ok(summary) => {
                        if multi {
                            let marker = discovered
                                .source
                                .marker_label()
                                .map(|m| format!(" · {m}"))
                                .unwrap_or_default();
                            let status = if summary.skipped_unchanged {
                                "↺ cached".dimmed().to_string()
                            } else {
                                format!("{} deps", summary.deps)
                            };
                            println!(
                                "  {} {}  {}  ({}{})",
                                "✓".green(),
                                label.clone().bold(),
                                status,
                                eco.id(),
                                marker,
                            );
                        }
                        if summary.skipped_unchanged {
                            skipped += 1;
                        } else {
                            scanned += 1;
                        }
                    }
                    Err(err) => {
                        if multi {
                            println!("  {} {}  — {:#}", "✗".red(), label.clone().bold(), err);
                        }
                        failed.push((discovered.path.clone(), err));
                    }
                }
            }
        }

        if !any_eco_hit && multi {
            // Discovery said "candidate" (e.g. an --include glob) but
            // no ecosystem actually knew how to parse it. Warn softly.
            eprintln!(
                "  {} {}  — no ecosystem recognised the manifest",
                "⋯".yellow(),
                label.clone(),
            );
        }
    }

    if multi {
        let total = outcome.projects.len();
        println!(
            "\n{} project{} scanned{}. Run `{}` or `{}`.",
            scanned.to_string().bold(),
            if total == 1 { "" } else { "s" },
            if skipped > 0 {
                format!(", {skipped} unchanged")
            } else {
                String::new()
            },
            "packguard report".cyan(),
            "packguard ui".cyan(),
        );
        if !failed.is_empty() {
            anyhow::bail!(
                "{} project{} failed to scan (see above)",
                failed.len(),
                if failed.len() == 1 { "" } else { "s" },
            );
        }
    } else if let Some((_, err)) = failed.into_iter().next() {
        // Single-project mode: we suppressed the per-project line
        // (compact=false means handle_project would have printed its
        // own status), so surface the failure as a normal error.
        return Err(err);
    }

    Ok(())
}

fn print_discovery_summary(outcome: &packguard_core::DiscoveryOutcome) {
    use packguard_core::ProjectSource;

    // Single-project-at-root cases (legacy `--no-recursive` or the
    // repo just happens to have one manifest at the root). Skip the
    // noisy "walked filesystem" header.
    let single_root = outcome.projects.len() == 1
        && outcome.projects[0].relative.as_os_str().is_empty()
        && outcome.markers_found.is_empty();

    // Header: marker(s) used, or "walk only".
    if single_root {
        // Nothing to say — the scan command itself will print a line
        // per project below, and for a single project that's enough.
    } else if outcome.markers_found.is_empty() {
        println!(
            "{} walked filesystem — {} candidate{} found",
            "→".dimmed(),
            outcome.projects.len().to_string().bold(),
            if outcome.projects.len() == 1 { "" } else { "s" },
        );
    } else {
        let marker_hits = outcome
            .projects
            .iter()
            .filter(|p| p.source.marker_label().is_some())
            .count();
        let walk_hits = outcome.projects.len() - marker_hits;
        println!(
            "{} markers: {} — {} project{} from markers",
            "→".dimmed(),
            outcome.marker_summary().bold(),
            marker_hits.to_string().bold(),
            if marker_hits == 1 { "" } else { "s" },
        );
        if walk_hits > 0 {
            println!(
                "{} {} additional project{} found by filesystem walk",
                "→".dimmed(),
                walk_hits.to_string().bold(),
                if walk_hits == 1 { "" } else { "s" },
            );
        }
    }

    // Only list projects when we have more than one — keeps the
    // single-project case as quiet as before.
    if outcome.projects.len() > 1 {
        println!();
        let name_width = outcome
            .projects
            .iter()
            .map(|p| project_label(p).chars().count())
            .max()
            .unwrap_or(0)
            .max(20);
        for p in &outcome.projects {
            let label = project_label(p);
            let pad = name_width.saturating_sub(label.chars().count());
            let spaces = " ".repeat(pad + 2);
            let source = match &p.source {
                ProjectSource::PnpmWorkspace => "pnpm-workspace.yaml".to_string(),
                ProjectSource::NpmWorkspaces => "package.json#workspaces".to_string(),
                ProjectSource::LernaPackages => "lerna.json".to_string(),
                ProjectSource::Walk => "walk".to_string(),
                ProjectSource::RootManifest => "root".to_string(),
                ProjectSource::Legacy => "legacy".to_string(),
            };
            println!("    {}{}({})", label.bold(), spaces, source.dimmed());
        }
    }
}

fn project_label(p: &packguard_core::DiscoveredProject) -> String {
    if p.relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        p.relative.display().to_string()
    }
}

fn prompt_continue(count: usize) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    eprint!(
        "\n{} Discovered {} projects (>{}). Continue? [y/N] ",
        "?".yellow(),
        count,
        packguard_core::LARGE_COUNT_THRESHOLD,
    );
    io::stderr().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

async fn handle_project(
    store: &mut Store,
    eco: &dyn Ecosystem,
    project: &Project,
    repo_root: &Path,
    offline: bool,
    force: bool,
    compact: bool,
) -> Result<ScanProjectSummary> {
    let fingerprint = fingerprint_project(project)?;
    let last_fp = store.last_fingerprint(repo_root, eco.id())?;
    let unchanged = last_fp.as_deref() == Some(fingerprint.as_str());

    // Schema drift detection (Polish-2, finding #4b): if the schema has
    // evolved since this repo was last scanned, the new tables
    // (e.g. V5's `dependency_edges`) will be empty and everything
    // downstream — graph, compatibility tab, contamination chains — will
    // look empty. Force a rescan in that case, even when the manifest
    // fingerprint matches, and tell the user why.
    let schema_drifted = if unchanged {
        match (
            store.latest_migration_at().ok().flatten(),
            store.last_scan_at(repo_root, eco.id()).ok().flatten(),
        ) {
            (Some(migrated), Some(scanned)) => migrated > scanned,
            _ => false,
        }
    } else {
        false
    };

    if unchanged && !force && !schema_drifted {
        if !compact {
            println!(
                "{} {} {} — no changes since last scan (fingerprint {}…). \
                 Pass {} to re-fetch anyway.",
                "✓".green(),
                format!("[{}]", eco.id()).dimmed(),
                project.name.as_deref().unwrap_or("<unnamed>").bold(),
                &fingerprint[..8],
                "--force".cyan(),
            );
        }
        return Ok(ScanProjectSummary {
            deps: project.dependencies.len(),
            skipped_unchanged: true,
        });
    }
    if schema_drifted && !compact {
        println!(
            "{} {} {} — store schema evolved since last scan, re-scanning to \
             populate the new tables.",
            "⚙".yellow(),
            format!("[{}]", eco.id()).dimmed(),
            project.name.as_deref().unwrap_or("<unnamed>").bold(),
        );
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

    if !compact {
        render_project(eco, project, &remotes);
    }
    Ok(ScanProjectSummary {
        deps: project.dependencies.len(),
        skipped_unchanged: false,
    })
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

async fn report(
    path: PathBuf,
    format: ReportFormat,
    fail_on_violation: bool,
    pstore: &Arc<Mutex<Store>>,
    packguard_home: &Path,
) -> Result<()> {
    let store = pstore.lock().await;
    let intel = IntelStore::open(packguard_home).with_context(|| "opening IntelStore")?;
    let dependencies = store.load_repo_dependencies(&path)?;
    if dependencies.is_empty() {
        anyhow::bail!(
            "no cached scan for {}; run `packguard scan` first{}",
            path.display(),
            available_scans_hint(&store),
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
                &intel,
                &dep.ecosystem,
                &dep.name,
                dep.installed.as_deref(),
                &releases,
            );
            let malware = intel
                .load_malware_reports_for(&dep.ecosystem, &dep.name)
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
    intel: &IntelStore,
    ecosystem: &str,
    name: &str,
    installed: Option<&str>,
    releases: &[ReleaseInfo],
) -> VulnsByVersion {
    let stored = match intel.load_vulnerabilities_for(ecosystem, name) {
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
    pstore: &Arc<Mutex<Store>>,
    packguard_home: &Path,
) -> Result<()> {
    let store = pstore.lock().await;
    let mut intel = IntelStore::open(packguard_home).with_context(|| "opening IntelStore")?;
    let dependencies = store.load_repo_dependencies(&path)?;
    if dependencies.is_empty() {
        let hint = available_scans_hint(&store);
        anyhow::bail!(
            "no cached scan for {}; run `packguard scan` first{}",
            path.display(),
            hint,
        );
    }

    // Phase 10c — pre-run guidance when the store has no advisory data.
    // The audit will run correctly (possibly with live OSV fallback) but
    // the user should know the local cache is empty so they can `sync`.
    let cached_advisories = intel.count_vulnerabilities()?;
    if cached_advisories == 0 {
        eprintln!(
            "{} Store has 0 advisories — nothing local to match against your scans.\n  \
             Run {} to fetch the CVE database (OSV + GHSA),\n  \
             then re-run audit.",
            "⚠".yellow().bold(),
            "'packguard sync'".bold(),
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
        let stored = intel.load_vulnerabilities_for(&dep.ecosystem, &dep.name)?;

        // Socket scanner enrichment: persist its alerts as MalwareReports.
        // 24h TTL via sync_log key `socket:{eco}:{name}@{version}`.
        if let Some(client) = &socket_client {
            let key = format!("socket:{}:{}@{}", dep.ecosystem, dep.name, installed);
            let stale = intel
                .get_sync_state(&key)?
                .and_then(|s| s.synced_at)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|ts| Utc::now().signed_duration_since(ts.to_utc()).num_hours() >= 24)
                .unwrap_or(true);
            if stale {
                match client.query(&dep.ecosystem, &dep.name, installed).await {
                    Ok(reports) => {
                        if !reports.is_empty() {
                            intel.persist_malware_reports(&reports)?;
                        }
                        let state = packguard_store::SyncState {
                            synced_at: Some(Utc::now().to_rfc3339()),
                            record_count: reports.len() as i64,
                            ..Default::default()
                        };
                        intel.put_sync_state(&key, &state)?;
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
            let stale = intel
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
                                let n = intel.persist_vulnerabilities(&vulns)?;
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
                            if let Some(prior) = intel.get_sync_state(&key)? {
                                state.record_count = prior.record_count + vulns.len() as i64;
                            }
                            intel.put_sync_state(&key, &state)?;
                            // Re-read combined (cached + live) set for the matcher.
                            intel.load_vulnerabilities_for(&dep.ecosystem, &dep.name)?
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
        for r in intel.load_malware_reports_for(&eco, &name)? {
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
                // Phase 10c — distinguish "empty store (nothing to match
                // against)" from "store has advisories and none hit".
                // The pre-run stderr warning already fired on the empty
                // case, so we only double down on the clean message.
                if cached_advisories > 0 {
                    println!(
                        "{} No matches — your installed versions are clean against the \
                         {} cached advisor{} in the store.",
                        "✓".green().bold(),
                        cached_advisories,
                        if cached_advisories == 1 { "y" } else { "ies" },
                    );
                } else {
                    println!(
                        "{} {}",
                        "✓".green(),
                        "no risks detected for the requested focus".bold()
                    );
                }
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
                "informationUri": "https://github.com/Tmauc/packguard",
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
    Ok(load_project_policy_resolved(path)?.policy)
}

/// Phase 10b — full cascade resolve, including the sources chain + per-key
/// provenance. Used by the `--show-policy` flag and by the normal `report`
/// flow (which just takes `.policy` from the result).
fn load_project_policy_resolved(path: &Path) -> Result<packguard_policy::ResolvedPolicyFile> {
    packguard_policy::resolve_policy_cascade(path)
        .with_context(|| format!("resolving policy cascade for {}", path.display()))
}

/// Phase 10b — `packguard report --show-policy <path>` output. Sources list
/// first (merge order, lowest → highest priority), then the effective
/// policy serialised as YAML with a provenance comment on each tracked key.
fn render_show_policy(path: &Path) -> Result<()> {
    let resolved = load_project_policy_resolved(path)?;
    println!("# Effective policy for {}", path.display());
    println!("# Sources (merge order — later wins):");
    for (i, src) in resolved.sources.iter().enumerate() {
        println!("#   [{i}] {}", src.label);
    }
    println!();
    render_provenance_table(&resolved);
    Ok(())
}

fn render_provenance_table(resolved: &packguard_policy::ResolvedPolicyFile) {
    let policy = &resolved.policy;
    let rows: Vec<(&'static str, String)> = vec![
        (
            "defaults.offset.major",
            signed_axis(policy.defaults.offset.major),
        ),
        (
            "defaults.offset.minor",
            signed_axis(policy.defaults.offset.minor),
        ),
        (
            "defaults.offset.patch",
            signed_axis(policy.defaults.offset.patch),
        ),
        (
            "defaults.allow_patch",
            policy.defaults.allow_patch.to_string(),
        ),
        (
            "defaults.allow_security_patch",
            policy.defaults.allow_security_patch.to_string(),
        ),
        (
            "defaults.stability",
            match policy.defaults.stability {
                packguard_policy::Stability::Stable => "stable".into(),
                packguard_policy::Stability::Prerelease => "prerelease".into(),
            },
        ),
        (
            "defaults.min_age_days",
            policy.defaults.min_age_days.to_string(),
        ),
        (
            "defaults.pin",
            policy.defaults.pin.as_deref().unwrap_or("—").to_string(),
        ),
        (
            "defaults.block.cve_severity",
            format!("[{}]", policy.defaults.block.cve_severity.join(", ")),
        ),
        (
            "defaults.block.malware",
            policy.defaults.block.malware.to_string(),
        ),
        (
            "defaults.block.deprecated",
            policy.defaults.block.deprecated.to_string(),
        ),
        (
            "defaults.block.yanked",
            policy.defaults.block.yanked.to_string(),
        ),
        (
            "defaults.block.typosquat",
            match policy.defaults.block.typosquat {
                packguard_policy::TyposquatPolicy::Strict => "strict".into(),
                packguard_policy::TyposquatPolicy::Warn => "warn".into(),
                packguard_policy::TyposquatPolicy::Off => "off".into(),
            },
        ),
        ("overrides", format!("{} rule(s)", policy.overrides.len())),
        ("groups", format!("{} rule(s)", policy.groups.len())),
    ];
    let key_width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let val_width = rows.iter().map(|(_, v)| v.len()).max().unwrap_or(0).min(24);
    for (key, value) in rows {
        let prov = resolved
            .provenance
            .keys
            .get(key)
            .map(|entry| format_provenance(entry, resolved))
            .unwrap_or_else(|| "(unset — falls through to downstream default)".to_string());
        println!("{key:<key_width$}  = {value:<val_width$}  ({prov})");
    }
}

fn signed_axis(magnitude: u32) -> String {
    if magnitude == 0 {
        "0".to_string()
    } else {
        format!("-{magnitude}")
    }
}

fn format_provenance(
    entry: &packguard_policy::ProvenanceEntry,
    resolved: &packguard_policy::ResolvedPolicyFile,
) -> String {
    let source = &resolved.sources[entry.source_index];
    match (entry.line, &source.path) {
        (Some(line), Some(_)) => format!("from {}:L{line}", source.label),
        (None, Some(_)) => format!("from {}", source.label),
        (_, None) => format!("from {}", source.label),
    }
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

    // Phase 10c — pedagogical footer that bridges report ↔ audit and
    // points users at --show-policy when the cascade is the reason for
    // insufficient candidates.
    println!();
    println!(
        "→ Run {} to see CVE/malware details for this scan.",
        "'packguard audit'".bold()
    );
    if summary.insufficient > 0 {
        println!(
            "→ {} packages show 'insufficient'. Run {} to see which \
             rule prevents resolution.",
            summary.insufficient,
            format!("'packguard report {} --show-policy'", path.display()).bold(),
        );
    }
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
                    "informationUri": "https://github.com/Tmauc/packguard",
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

#[cfg(test)]
mod sync_tests {
    use super::*;
    use packguard_store::SyncState;

    #[test]
    fn osv_sync_updates_synced_at_on_304_not_modified() {
        // Prior sync stamped etag/last_modified/record_count on 2026-04-14.
        let prior = SyncState {
            etag: Some("\"abc123\"".to_string()),
            last_modified: Some("Mon, 14 Apr 2026 10:00:00 GMT".to_string()),
            last_commit: None,
            synced_at: Some("2026-04-14T10:00:00+00:00".to_string()),
            record_count: 1481,
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-24T12:34:56+00:00")
            .unwrap()
            .to_utc();

        let refreshed = refreshed_sync_state_for_304(Some(prior.clone()), now);

        // synced_at bumps forward…
        assert_eq!(
            refreshed.synced_at.as_deref(),
            Some("2026-04-24T12:34:56+00:00")
        );
        // …and the etag / last_modified / record_count survive so the
        // next If-None-Match keeps short-circuiting upstream.
        assert_eq!(refreshed.etag, prior.etag);
        assert_eq!(refreshed.last_modified, prior.last_modified);
        assert_eq!(refreshed.record_count, prior.record_count);
    }

    #[test]
    fn osv_sync_304_handles_missing_prior_state_gracefully() {
        // First-ever sync that immediately returns 304 is a degenerate
        // case (we wouldn't have an etag to send) but make sure the
        // helper doesn't panic: it should just produce a row with only
        // synced_at populated.
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-24T12:34:56+00:00")
            .unwrap()
            .to_utc();
        let refreshed = refreshed_sync_state_for_304(None, now);
        assert!(refreshed.synced_at.is_some());
        assert_eq!(refreshed.etag, None);
        assert_eq!(refreshed.last_modified, None);
        assert_eq!(refreshed.record_count, 0);
    }
}
