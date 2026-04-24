//! Dismiss / defer persistence — thin wrapper around the store helpers
//! added in commit 1. Kept in this crate (not in the server) so the CLI
//! path can respect the same state without wiring through axum.
//!
//! The `id` is the stable hash produced by `model::stable_action_id`, so
//! the same `(kind, target, workspace)` triplet always addresses the
//! same row whether the caller came from the CLI or the dashboard.

use crate::model::{Action, ActionKind, ActionTarget};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use packguard_store::Store;

/// Permanently dismiss an action. Callers typically pass the action's
/// `id` as returned by `collect_all`; `reason` is free-form and shown
/// as a tooltip in the dashboard.
pub fn dismiss(
    store: &mut Store,
    action: &Action,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<()> {
    let target_json = serde_json::to_string(&action.target)?;
    store.upsert_action_dismissal(
        &action.id,
        action.kind.as_str(),
        &target_json,
        &action.workspace,
        now.timestamp(),
        None,
        reason,
    )
}

/// Defer an action for `days`. Re-surfaces automatically once `now >=
/// deferred_until` — the filter lives in
/// `Store::load_active_dismissals`, no background job required.
pub fn defer(
    store: &mut Store,
    action: &Action,
    days: i64,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let until = now + Duration::days(days);
    let target_json = serde_json::to_string(&action.target)?;
    store.upsert_action_dismissal(
        &action.id,
        action.kind.as_str(),
        &target_json,
        &action.workspace,
        now.timestamp(),
        Some(until.timestamp()),
        reason,
    )?;
    Ok(until)
}

/// Undo a dismissal/defer for the given action id. Idempotent — succeeds
/// even when the row was already gone.
pub fn restore(store: &mut Store, action_id: &str) -> Result<()> {
    store.delete_action_dismissal(action_id)?;
    Ok(())
}

/// Alternate entry point for callers that only know the stable id (e.g.
/// the HTTP handler before it re-materializes the `Action`). The
/// payload is rebuilt from the supplied `(kind, target, workspace)`
/// so the row retains enough context for a future "recently dismissed"
/// view.
#[allow(clippy::too_many_arguments)]
pub fn dismiss_raw(
    store: &mut Store,
    id: &str,
    kind: ActionKind,
    target: &ActionTarget,
    workspace: &str,
    now: DateTime<Utc>,
    deferred_days: Option<i64>,
    reason: Option<&str>,
) -> Result<Option<DateTime<Utc>>> {
    let target_json = serde_json::to_string(target)?;
    let until = deferred_days.map(|d| now + Duration::days(d));
    store.upsert_action_dismissal(
        id,
        kind.as_str(),
        &target_json,
        workspace,
        now.timestamp(),
        until.map(|u| u.timestamp()),
        reason,
    )?;
    Ok(until)
}
