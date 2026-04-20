use anyhow::Result;
use clap::{Parser, Subcommand};
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_core::model::{Delta, DepKind, Project};
use packguard_core::{Ecosystem, Npm};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "packguard", version, about = "Local package version governance")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a project, query the registry, and render a table of outdated deps.
    Scan {
        /// Path to the project root. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Skip network calls; only show parsed manifest data.
        #[arg(long)]
        offline: bool,
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
    match cli.command {
        Cmd::Scan { path, offline } => scan(path, offline).await,
    }
}

fn default_ecosystems() -> Result<Vec<Arc<dyn Ecosystem>>> {
    Ok(vec![Arc::new(Npm::new()?)])
}

async fn scan(path: PathBuf, offline: bool) -> Result<()> {
    let ecosystems = default_ecosystems()?;
    let mut any_detected = false;

    for eco in &ecosystems {
        let projects = eco.detect(&path)?;
        if projects.is_empty() {
            continue;
        }
        any_detected = true;
        for project in projects {
            render_project(&**eco, &project, offline).await?;
        }
    }

    if !any_detected {
        anyhow::bail!(
            "no supported manifest found at {}",
            path.display()
        );
    }
    Ok(())
}

async fn render_project(eco: &dyn Ecosystem, project: &Project, offline: bool) -> Result<()> {
    println!(
        "{} {} {} — {} direct deps",
        "📦".dimmed(),
        format!("[{}]", eco.id()).dimmed(),
        project.name.as_deref().unwrap_or("<unnamed>").bold(),
        project.dependencies.len(),
    );

    let latest_map = if offline {
        Default::default()
    } else {
        let names: Vec<String> = project.dependencies.iter().map(|d| d.name.clone()).collect();
        let results = eco.fetch_latest(names).await;
        let mut map = std::collections::BTreeMap::new();
        for (name, result) in results {
            match result {
                Ok(info) => {
                    map.insert(name, (info.latest, info.latest_published_at));
                }
                Err(err) => {
                    eprintln!("{} {}: {:#}", "warn".yellow(), name, err);
                }
            }
        }
        map
    };

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
        let (latest, released_at) = latest_map
            .get(&dep.name)
            .cloned()
            .unwrap_or((None, None));

        let delta = eco.classify(dep.installed.as_deref(), latest.as_deref());

        table.add_row(vec![
            Cell::new(&dep.name),
            Cell::new(kind_str(dep.kind)).fg(Color::DarkGrey),
            Cell::new(dep.installed.as_deref().unwrap_or("-")),
            Cell::new(latest.as_deref().unwrap_or("-")),
            delta_cell(delta),
            Cell::new(released_at.as_deref().unwrap_or("-")).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}");
    Ok(())
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
