-- Phase 14.2d.2 — async job tracking moves from the per-project store
-- (V4 there) to the cross-project IntelStore.
--
-- Rationale: jobs are a global runtime concern (the dashboard's Scan /
-- Sync buttons, the `POST /api/scan` and `POST /api/sync` handlers,
-- the `JobAccepted { id }` payload + `GET /api/jobs/:id` polling).
-- Wiring them through `state.store` was the last reason `AppState`
-- still carried the legacy `Store` handle. With the table here, the
-- legacy file can be retired (renamed to `.v0.5-backup` in 14.2d.3).
--
-- Schema mirrors the original `migrations/V4__jobs.sql` byte-for-byte
-- so the per-project layer's serialization code keeps working
-- unchanged: same column names, same types, same indexes.

CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT    NOT NULL PRIMARY KEY,         -- UUID v4, server-issued
    kind          TEXT    NOT NULL,                     -- "scan" | "sync" | "add_project"
    status        TEXT    NOT NULL,                     -- "pending" | "running" | "succeeded" | "failed"
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    result_json   TEXT,                                 -- JSON payload (ScanReport / SyncReport / AddProjectReport)
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_intel_jobs_status     ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_intel_jobs_started_at ON jobs(started_at);
