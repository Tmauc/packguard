-- Phase 4a — async job tracking for the dashboard's Scan / Sync buttons.
--
-- One row per asynchronous unit of work the server starts. We persist enough
-- state to survive a restart (status + final payload) so the dashboard can
-- still display the result of a job that completed while the user was away.

CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT    NOT NULL PRIMARY KEY,         -- UUID v4, server-issued
    kind          TEXT    NOT NULL,                     -- "scan" | "sync"
    status        TEXT    NOT NULL,                     -- "pending" | "running" | "succeeded" | "failed"
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    result_json   TEXT,                                 -- JSON payload (ScanReport / SyncReport)
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_started_at ON jobs(started_at);
