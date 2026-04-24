//! CLI layer for `packguard actions` — mirrors the dashboard page added
//! in Phase 12b. Lives next to `main.rs` to keep the top-level binary
//! readable now that every PackGuard command has its own render path.
//!
//! All subcommands share a single code path into `packguard-actions`
//! (no HTTP round-trip), so a dismiss issued from the CLI is respected
//! by the dashboard on the next refresh and vice-versa.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use packguard_actions::{
    collect_all, dismiss_raw, filter_min_severity, restore, Action, ActionKind, ActionSeverity,
    ActionTarget,
};
use packguard_store::Store;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ActionsArgs {
    /// Use a subcommand or omit for the default listing.
    #[command(subcommand)]
    pub subcommand: Option<ActionsSub>,

    /// Flags for the default (list) mode.
    #[command(flatten)]
    pub list: ActionsListArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ActionsListArgs {
    /// Restrict the listing to this workspace (repo root). Defaults to
    /// "everything in the store". Matches the existing `--project` flag
    /// across `report` / `audit` / `graph`.
    #[arg(long)]
    pub project: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = ActionsFormat::Table)]
    pub format: ActionsFormat,
    /// Minimum severity to include. Accepts `critical|high|medium|low|info`.
    /// Default: `info` (every row).
    #[arg(long)]
    pub min_severity: Option<String>,
    /// Include permanently-dismissed rows in the output (with a
    /// `[dismissed]` marker). Default: hidden.
    #[arg(long)]
    pub include_dismissed: bool,
    /// Include actively-deferred rows in the output (with a
    /// `[deferred Nd]` marker). Default: hidden.
    #[arg(long)]
    pub include_deferred: bool,
    /// CI gate — exit 1 if at least one *active* (non-dismissed,
    /// non-deferred) action reaches this severity or above. Does not
    /// affect the rendered output.
    #[arg(long)]
    pub fail_on_severity: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ActionsSub {
    /// List every action the engine generated (same as no subcommand).
    List(ActionsListArgs),
    /// Dismiss an action by id prefix (min 6 hex chars, git-style).
    Dismiss {
        id_prefix: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Defer an action by id prefix until `now + --days`. After that,
    /// the action resurfaces automatically.
    Defer {
        id_prefix: String,
        #[arg(long)]
        days: i64,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Restore a previously dismissed / deferred action by id prefix.
    Restore { id_prefix: String },
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ActionsFormat {
    Table,
    Json,
    Sarif,
}

pub fn run(args: ActionsArgs, store_path: &Path) -> Result<()> {
    match args.subcommand {
        None => list(args.list, store_path),
        Some(ActionsSub::List(list_args)) => list(list_args, store_path),
        Some(ActionsSub::Dismiss { id_prefix, reason }) => {
            dismiss_cmd(&id_prefix, reason.as_deref(), store_path)
        }
        Some(ActionsSub::Defer {
            id_prefix,
            days,
            reason,
        }) => defer_cmd(&id_prefix, days, reason.as_deref(), store_path),
        Some(ActionsSub::Restore { id_prefix }) => restore_cmd(&id_prefix, store_path),
    }
}

// ---- list -----------------------------------------------------------------

fn list(args: ActionsListArgs, store_path: &Path) -> Result<()> {
    let store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let now = Utc::now();

    let mut actions = collect_all(
        &store,
        args.project.as_deref(),
        now,
        args.include_dismissed,
        args.include_deferred,
    )?;
    if let Some(raw) = args.min_severity.as_deref() {
        if let Some(threshold) = ActionSeverity::parse(raw) {
            filter_min_severity(&mut actions, threshold);
        }
    }

    match args.format {
        ActionsFormat::Table => render_table(&actions),
        ActionsFormat::Json => render_json(&actions)?,
        ActionsFormat::Sarif => render_sarif(&store, &actions)?,
    }

    if let Some(raw) = args.fail_on_severity.as_deref() {
        let threshold = ActionSeverity::parse(raw).with_context(|| {
            format!(
                "invalid --fail-on-severity value '{raw}' (expected critical|high|medium|low|info)"
            )
        })?;
        let hit = actions
            .iter()
            .filter(|a| a.dismissed_at.is_none() && a.deferred_until.is_none())
            .any(|a| a.severity >= threshold);
        if hit {
            std::process::exit(1);
        }
    }
    Ok(())
}

fn render_table(actions: &[Action]) {
    if actions.is_empty() {
        println!(
            "{} no actions — either everything is clean or nothing scanned yet",
            "ⓘ".dimmed(),
        );
        return;
    }

    // `collect_all` already sorts by (severity desc, workspace, kind, target).
    // We just walk the list and add a blank row between severity blocks so
    // the CLI mirrors the dashboard's grouping without a second pass.
    let mut prev_severity: Option<ActionSeverity> = None;
    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            header("ID"),
            header("Severity"),
            header("Kind"),
            header("Workspace"),
            header("Target"),
            header("Command"),
        ]);

    for action in actions {
        // Group header on severity transition.
        if prev_severity != Some(action.severity) {
            let count = actions
                .iter()
                .filter(|a| a.severity == action.severity)
                .count();
            let label = format!(
                "── {} · {count} ──",
                action.severity.as_str().to_uppercase()
            );
            table.add_row(vec![Cell::new(label)
                .fg(severity_color(action.severity))
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Left)]);
            prev_severity = Some(action.severity);
        }

        let id_cell = Cell::new(id_prefix(&action.id, 8));
        let sev_cell = Cell::new(action.severity.as_str()).fg(severity_color(action.severity));
        let kind_cell = Cell::new(action.kind.as_str());
        let workspace_cell = Cell::new(short_workspace(&action.workspace));
        let target_cell = Cell::new(render_target(&action.target));
        let command_cell = Cell::new(
            action
                .suggested_command
                .clone()
                .unwrap_or_else(|| "(see advisory)".dimmed().to_string()),
        );

        let archived_marker = if action.dismissed_at.is_some() && action.deferred_until.is_none() {
            " [dismissed]".dimmed().to_string()
        } else if let Some(until) = action.deferred_until.as_deref() {
            format!(" [deferred{}]", format_defer_remaining(until))
                .dimmed()
                .to_string()
        } else {
            String::new()
        };

        // Concat the marker on the workspace cell so the overall column
        // count stays at 6 (prevents comfy-table alignment weirdness when
        // only some rows carry a marker).
        let workspace_with_marker = if archived_marker.is_empty() {
            workspace_cell
        } else {
            Cell::new(format!(
                "{}{}",
                short_workspace(&action.workspace),
                archived_marker
            ))
        };

        let row: Vec<Cell> = if action.dismissed_at.is_some() || action.deferred_until.is_some() {
            vec![
                id_cell.fg(Color::DarkGrey),
                sev_cell.fg(Color::DarkGrey),
                kind_cell.fg(Color::DarkGrey),
                workspace_with_marker.fg(Color::DarkGrey),
                target_cell.fg(Color::DarkGrey),
                command_cell.fg(Color::DarkGrey),
            ]
        } else {
            vec![
                id_cell,
                sev_cell,
                kind_cell,
                workspace_with_marker,
                target_cell,
                command_cell,
            ]
        };
        table.add_row(row);
    }

    println!("{table}");

    let total = actions.len();
    let active = actions
        .iter()
        .filter(|a| a.dismissed_at.is_none() && a.deferred_until.is_none())
        .count();
    let footer = if active == total {
        format!(
            "{total} action{} · run `{}` to dismiss one",
            if total == 1 { "" } else { "s" },
            "packguard actions dismiss <id>".cyan()
        )
    } else {
        format!(
            "{active} active · {total} total (incl. archived) · run `{}` to dismiss one",
            "packguard actions dismiss <id>".cyan()
        )
    };
    println!("{footer}");
}

fn header(s: &str) -> Cell {
    Cell::new(s).add_attribute(Attribute::Bold)
}

fn severity_color(sev: ActionSeverity) -> Color {
    match sev {
        ActionSeverity::Critical => Color::Red,
        ActionSeverity::High => Color::DarkRed,
        ActionSeverity::Medium => Color::Yellow,
        ActionSeverity::Low => Color::Cyan,
        ActionSeverity::Info => Color::DarkGrey,
    }
}

fn id_prefix(id: &str, n: usize) -> String {
    id.chars().take(n).collect()
}

fn short_workspace(ws: &str) -> String {
    // _global actions keep that literal, everything else gets shortened to
    // the last path segment so the column does not dominate the row on
    // monorepo setups.
    if ws == "_global" {
        return ws.to_string();
    }
    Path::new(ws)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| ws.to_string())
}

fn render_target(t: &ActionTarget) -> String {
    match t {
        ActionTarget::Package {
            ecosystem,
            name,
            version,
        } => format!("{ecosystem}:{name}@{version}"),
        ActionTarget::Workspace => "(workspace)".to_string(),
    }
}

fn format_defer_remaining(until_rfc3339: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(until_rfc3339) {
        Ok(dt) => {
            let delta = dt.to_utc() - Utc::now();
            let days = delta.num_days();
            if days <= 0 {
                " <1d".to_string()
            } else {
                format!(" {days}d")
            }
        }
        Err(_) => String::new(),
    }
}

// ---- json -----------------------------------------------------------------

fn render_json(actions: &[Action]) -> Result<()> {
    // Wrap in `{actions: [...], total: N}` to match the /api/actions
    // response shape so downstream tooling built against the HTTP API
    // can reuse the same parser against the CLI output.
    let out = json!({
        "actions": actions,
        "total": actions.len(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

// ---- sarif ----------------------------------------------------------------

fn render_sarif(store: &Store, actions: &[Action]) -> Result<()> {
    // Pre-resolve a workspace → lockfile relative URI map so a SARIF
    // `result.locations[0]` points at a real file GitHub Code Scanning /
    // GitLab can navigate to. Falls back to the workspace path itself
    // for `_global` actions.
    let workspace_uris = workspace_uri_map(store, actions);

    // `ActionKind` isn't `Ord` — dedup via the rule-id string so SARIF
    // ruleIds stay unique without imposing a sort order on the enum.
    let mut seen_rules: BTreeSet<String> = BTreeSet::new();
    let mut rules: Vec<Value> = Vec::new();
    for a in actions {
        let id = rule_id(a.kind);
        if seen_rules.insert(id.clone()) {
            rules.push(json!({
                "id": id,
                "shortDescription": { "text": rule_short(a.kind) },
                "help": { "text": rule_help(a.kind) },
            }));
        }
    }

    let results: Vec<Value> = actions
        .iter()
        .map(|a| build_sarif_result(a, &workspace_uris))
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
                    "rules": rules,
                }
            },
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

/// Map `(workspace, ecosystem)` → relative lockfile path, chosen via
/// `pm_detect`. Package actions carry their own ecosystem on the target
/// so a Python package living in a mixed JS/Py workspace picks
/// `poetry.lock` / `uv.lock` instead of the workspace's default
/// `package-lock.json`. `_global` (RefreshSync) points at the workspace
/// root — there is no lockfile.
fn workspace_uri_map(_store: &Store, actions: &[Action]) -> BTreeMap<(String, String), String> {
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    let needed: BTreeSet<(String, String)> = actions
        .iter()
        .map(|a| {
            let eco = match &a.target {
                ActionTarget::Package { ecosystem, .. } => ecosystem.clone(),
                ActionTarget::Workspace => "npm".to_string(),
            };
            (a.workspace.clone(), eco)
        })
        .collect();
    for (ws, eco) in needed {
        if ws == "_global" {
            out.insert((ws, eco), ".".to_string());
            continue;
        }
        let path = PathBuf::from(&ws);
        let pm = packguard_actions::detect_package_manager(&path, &eco);
        let lockfile = match pm {
            packguard_actions::PackageManager::Pnpm => "pnpm-lock.yaml",
            packguard_actions::PackageManager::Yarn => "yarn.lock",
            packguard_actions::PackageManager::Npm => "package-lock.json",
            packguard_actions::PackageManager::Poetry => "poetry.lock",
            packguard_actions::PackageManager::Uv => "uv.lock",
            packguard_actions::PackageManager::Pdm => "pdm.lock",
            packguard_actions::PackageManager::Pip => "requirements.txt",
        };
        out.insert((ws.clone(), eco), format!("{ws}/{lockfile}"));
    }
    out
}

fn build_sarif_result(
    action: &Action,
    workspace_uris: &BTreeMap<(String, String), String>,
) -> Value {
    let eco = match &action.target {
        ActionTarget::Package { ecosystem, .. } => ecosystem.clone(),
        ActionTarget::Workspace => "npm".to_string(),
    };
    let uri = workspace_uris
        .get(&(action.workspace.clone(), eco))
        .cloned()
        .unwrap_or_else(|| action.workspace.clone());
    let mut fingerprints = serde_json::Map::new();
    fingerprints.insert(
        "packguard.actionId".to_string(),
        Value::String(action.id.clone()),
    );
    if let Some(cve) = extract_cve_id(&action.title) {
        fingerprints.insert("cveId".to_string(), Value::String(cve));
    }
    let text = format!("{} — {}", action.title, action.explanation);
    let markdown = match &action.suggested_command {
        Some(cmd) => format!(
            "**{}**\n\n{}\n\n```\n{}\n```",
            action.title, action.explanation, cmd
        ),
        None => format!("**{}**\n\n{}", action.title, action.explanation),
    };
    json!({
        "ruleId": rule_id(action.kind),
        "level": sarif_level(action.severity),
        "message": {
            "text": text,
            "markdown": markdown,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri }
            }
        }],
        "partialFingerprints": Value::Object(fingerprints),
    })
}

fn rule_id(kind: ActionKind) -> String {
    let slug = match kind {
        ActionKind::FixMalware => "fix-malware",
        ActionKind::FixCveCritical => "fix-cve-critical",
        ActionKind::FixCveHigh => "fix-cve-high",
        ActionKind::ClearViolation => "clear-violation",
        ActionKind::ResolveInsufficient => "resolve-insufficient",
        ActionKind::WhitelistTyposquat => "whitelist-typosquat",
        ActionKind::RefreshSync => "refresh-sync",
        ActionKind::RescanStale => "rescan-stale",
    };
    format!("packguard/{slug}")
}

fn rule_short(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::FixMalware => "Installed package flagged as malware",
        ActionKind::FixCveCritical => "Installed version affected by a Critical advisory",
        ActionKind::FixCveHigh => "Installed version affected by a High advisory",
        ActionKind::ClearViolation => "Installed version breaks repo policy",
        ActionKind::ResolveInsufficient => "No candidate survives the current policy",
        ActionKind::WhitelistTyposquat => "Package name resembles a popular package",
        ActionKind::RefreshSync => "Advisory cache is stale",
        ActionKind::RescanStale => "Workspace scan is stale",
    }
}

fn rule_help(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::FixMalware => "Bump to a non-malware release or remove the dep entirely.",
        ActionKind::FixCveCritical => "Upgrade to a fixed version listed by the advisory.",
        ActionKind::FixCveHigh => "Upgrade to a fixed version listed by the advisory.",
        ActionKind::ClearViolation => {
            "Pin or loosen the offset so the installed version respects policy."
        }
        ActionKind::ResolveInsufficient => {
            "Loosen the offset or pin explicitly — no candidate satisfied the policy."
        }
        ActionKind::WhitelistTyposquat => "Allow-list the package or switch to the legitimate one.",
        ActionKind::RefreshSync => "Run `packguard sync` to refresh the OSV + GHSA mirrors.",
        ActionKind::RescanStale => "Run `packguard scan` to pick up new advisories.",
    }
}

fn sarif_level(sev: ActionSeverity) -> &'static str {
    match sev {
        ActionSeverity::Critical | ActionSeverity::High => "error",
        ActionSeverity::Medium => "warning",
        ActionSeverity::Low | ActionSeverity::Info => "note",
    }
}

/// Extract a CVE id from a title / explanation by searching for the
/// first `CVE-YYYY-NNNNN` pattern. Best-effort — SARIF
/// `partialFingerprints.cveId` is optional so a missed match only
/// degrades cross-run dedup, never invalidates the report.
fn extract_cve_id(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let needle = b"CVE-";
    for (i, window) in bytes.windows(needle.len()).enumerate() {
        if window != needle {
            continue;
        }
        // Consume CVE-YYYY-N+ (4 digits, dash, >= 4 digits).
        let rest = &bytes[i + needle.len()..];
        let year_end = rest.iter().position(|b| !b.is_ascii_digit()).unwrap_or(0);
        if year_end < 4 || rest.get(year_end) != Some(&b'-') {
            continue;
        }
        let after_dash = &rest[year_end + 1..];
        let seq_end = after_dash
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(after_dash.len());
        if seq_end < 4 {
            continue;
        }
        let total = needle.len() + year_end + 1 + seq_end;
        return Some(String::from_utf8_lossy(&bytes[i..i + total]).to_string());
    }
    None
}

// ---- dismiss / defer / restore --------------------------------------------

fn dismiss_cmd(id_prefix: &str, reason: Option<&str>, store_path: &Path) -> Result<()> {
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let action = resolve_prefix(&store, id_prefix)?;
    let now = Utc::now();
    dismiss_raw(
        &mut store,
        &action.id,
        action.kind,
        &action.target,
        &action.workspace,
        now,
        None,
        reason,
    )?;
    println!(
        "{} dismissed {} ({}) — id {}",
        "✓".green(),
        render_target(&action.target).bold(),
        action.kind.as_str(),
        id_prefix_render(&action.id),
    );
    Ok(())
}

fn defer_cmd(id_prefix: &str, days: i64, reason: Option<&str>, store_path: &Path) -> Result<()> {
    if days <= 0 {
        bail!("--days must be a positive integer");
    }
    let days = days.clamp(1, 365);
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let action = resolve_prefix(&store, id_prefix)?;
    let now = Utc::now();
    let until = dismiss_raw(
        &mut store,
        &action.id,
        action.kind,
        &action.target,
        &action.workspace,
        now,
        Some(days),
        reason,
    )?
    .expect("defer returns a deadline when days is Some");
    println!(
        "{} deferred {} ({}) for {} day(s) — resurfaces {} — id {}",
        "✓".green(),
        render_target(&action.target).bold(),
        action.kind.as_str(),
        days,
        until.to_rfc3339().dimmed(),
        id_prefix_render(&action.id),
    );
    Ok(())
}

fn restore_cmd(id_prefix: &str, store_path: &Path) -> Result<()> {
    let mut store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let action = resolve_prefix(&store, id_prefix)?;
    restore(&mut store, &action.id)?;
    println!(
        "{} restored {} ({}) — id {}",
        "✓".green(),
        render_target(&action.target).bold(),
        action.kind.as_str(),
        id_prefix_render(&action.id),
    );
    Ok(())
}

fn id_prefix_render(id: &str) -> String {
    id.chars().take(8).collect::<String>().cyan().to_string()
}

/// Pure prefix-match outcome — extracted from `resolve_prefix` so the
/// (non-exit) test cases can assert on it without spawning a
/// subprocess. The CLI wrapper handles exit codes.
#[derive(Debug)]
enum PrefixMatch {
    TooShort(usize),
    None,
    Single(Box<Action>),
    Ambiguous(Vec<Action>),
}

/// Classify `id_prefix` against an action set. Git-style semantics: a
/// minimum-6-hex prefix, single exact match, or the sorted list of
/// colliding full ids. The caller owns the user-facing rendering +
/// exit codes.
fn match_prefix(actions: &[Action], id_prefix: &str) -> PrefixMatch {
    if id_prefix.len() < 6 {
        return PrefixMatch::TooShort(id_prefix.len());
    }
    let mut matches: Vec<Action> = actions
        .iter()
        .filter(|a| a.id.starts_with(id_prefix))
        .cloned()
        .collect();
    matches.sort_by(|a, b| a.id.cmp(&b.id));
    match matches.len() {
        0 => PrefixMatch::None,
        1 => PrefixMatch::Single(Box::new(matches.into_iter().next().unwrap())),
        _ => PrefixMatch::Ambiguous(matches),
    }
}

/// Git-style prefix resolution: 0 matches → exit 1, 1 match → use it,
/// 2+ → exit 2 and print the full ids. Pulls the full set (active +
/// dismissed + deferred) so a user can restore a dismissed action by
/// prefix without juggling flags.
fn resolve_prefix(store: &Store, id_prefix: &str) -> Result<Action> {
    let now = Utc::now();
    let all = collect_all(store, None, now, true, true)?;
    match match_prefix(&all, id_prefix) {
        PrefixMatch::TooShort(n) => {
            bail!("id prefix must be at least 6 hex characters (got {})", n);
        }
        PrefixMatch::None => {
            eprintln!(
                "{} no action matches prefix {}",
                "✗".red(),
                id_prefix.bold()
            );
            std::process::exit(1);
        }
        PrefixMatch::Single(a) => Ok(*a),
        PrefixMatch::Ambiguous(matches) => {
            eprintln!(
                "{} ambiguous prefix {} — {} actions match. Full ids:",
                "✗".red(),
                id_prefix.bold(),
                matches.len()
            );
            for a in &matches {
                eprintln!(
                    "  {}  ({}, {})",
                    a.id,
                    a.kind.as_str(),
                    render_target(&a.target)
                );
            }
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_action(id: &str) -> Action {
        Action {
            id: id.to_string(),
            kind: ActionKind::FixCveHigh,
            severity: ActionSeverity::High,
            workspace: "/tmp/ws".to_string(),
            target: ActionTarget::Package {
                ecosystem: "npm".into(),
                name: "x".into(),
                version: "1.0.0".into(),
            },
            title: "t".into(),
            explanation: "e".into(),
            suggested_command: None,
            recommended_version: None,
            dismissed_at: None,
            deferred_until: None,
        }
    }

    #[test]
    fn match_prefix_single_exact_match_returns_single() {
        let actions = vec![
            fake_action("03232f8200000000"),
            fake_action("aabbccdd00000000"),
        ];
        let m = match_prefix(&actions, "03232f");
        match m {
            PrefixMatch::Single(a) => assert!(a.id.starts_with("03232f")),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn match_prefix_too_short_under_six_chars_is_too_short() {
        let actions = vec![fake_action("03232f82aabbcc")];
        let m = match_prefix(&actions, "0323");
        match m {
            PrefixMatch::TooShort(n) => assert_eq!(n, 4),
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    #[test]
    fn match_prefix_no_hit_returns_none() {
        let actions = vec![fake_action("03232f82aabbcc")];
        let m = match_prefix(&actions, "deadbe");
        match m {
            PrefixMatch::None => {}
            other => panic!("expected None, got {other:?}"),
        }
    }

    #[test]
    fn match_prefix_multiple_hits_returns_ambiguous_sorted() {
        let actions = vec![
            fake_action("0323aaaabb"),
            fake_action("0323bbbbbb"),
            fake_action("ffffffffff"),
        ];
        let m = match_prefix(&actions, "0323aa");
        match m {
            PrefixMatch::Single(_) => {} // only one matches at 6 chars
            other => panic!("expected Single on 6-char unique prefix, got {other:?}"),
        }

        // Lower prefix boundary at 6 chars with explicit 6-char shared
        // prefix: both seeded ids start with "0323aa" / "0323bb", so
        // "0323" (4 chars) is too-short. Craft the ambiguous scenario
        // at 6 chars:
        let actions = vec![
            fake_action("0323aabbbb0000"),
            fake_action("0323aabbcc1111"),
            fake_action("ffffffffff"),
        ];
        let m = match_prefix(&actions, "0323aa");
        match m {
            PrefixMatch::Ambiguous(list) => {
                assert_eq!(list.len(), 2);
                assert!(list[0].id < list[1].id, "must be sorted by full id");
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }
}
