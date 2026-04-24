-- Phase 12a — Page Actions engine: dismissal / defer persistence.
--
-- The action id is a deterministic hash of (kind, target, workspace) so a
-- dismissal survives a rescan when the same finding re-surfaces on the same
-- (package, version). If the installed version changes the id changes too —
-- the action re-appears, which is what we want.
--
-- Timestamps are stored as unix seconds (UTC) for trivial comparisons in
-- `is_active_dismissal` / `purge_expired_defers`. `deferred_until = NULL`
-- means a permanent dismissal; any value means "re-surface after that ts".

CREATE TABLE IF NOT EXISTS action_dismissals (
    id              TEXT    PRIMARY KEY,
    kind            TEXT    NOT NULL,
    target_json     TEXT    NOT NULL,
    workspace       TEXT    NOT NULL,
    dismissed_at    INTEGER NOT NULL,
    deferred_until  INTEGER,
    reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_action_dismissals_workspace
    ON action_dismissals(workspace);
