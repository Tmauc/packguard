use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_core::model::{Delta, DepKind, Project, RemotePackage};
use packguard_core::{Ecosystem, default_ecosystems};
use packguard_store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "packguard", version, about = "Local package version governance")]
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
        Cmd::Scan { path, offline, force } => scan(path, offline, force, &store_path).await,
    }
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
        let names: Vec<String> = project.dependencies.iter().map(|d| d.name.clone()).collect();
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
        Err(e) => {
            Err(anyhow::Error::from(e).context(format!("hashing {}", path.display())))
        }
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

fn render_project(eco: &dyn Ecosystem, project: &Project, remotes: &BTreeMap<String, RemotePackage>) {
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
