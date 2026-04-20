use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "packguard", version, about = "Local package version governance")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a project for direct dependencies (Phase 0: npm only, no network yet).
    Scan {
        /// Path to the project root. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Scan { path } => {
            let project = packguard_core::npm::scan(&path)?;
            println!(
                "scanned {} ({} direct deps)",
                project.name.as_deref().unwrap_or("<unnamed>"),
                project.dependencies.len()
            );
            for dep in &project.dependencies {
                println!(
                    "  {:?} {} {} (installed: {})",
                    dep.kind,
                    dep.name,
                    dep.declared_range,
                    dep.installed.as_deref().unwrap_or("-"),
                );
            }
        }
    }
    Ok(())
}
