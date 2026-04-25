-- Phase 14.2d — drop the intel-only tables from the per-project store schema.
--
-- Background: V1 created `vulnerabilities` and `malware_reports` and V2 added
-- `sync_log`; V2 then rebuilt `vulnerabilities`, V3 rebuilt `malware_reports`.
-- All three are now owned by `IntelStore` (`<home>/intel/intel.db`) since
-- 14.1c-e — every runtime read/write goes there. The 14.1d migration did
-- not drop the legacy tables in the per-project stores it created, so
-- they sit empty (or hold a stale, unread copy of the legacy data).
-- V8 cleans them up so the per-project store schema reflects what the
-- code actually consumes.
--
-- This migration only ever runs against per-project stores (the ones
-- under `<home>/projects/<slug>/store.db`). The legacy
-- `<home>/store.db` is renamed to `<home>/store.db.v0.5-backup` at boot
-- in the same release, and refinery never matches that path — the
-- backup file's schema is frozen at V7 forever.
--
-- The DROPs are guarded with IF EXISTS so the migration also lands
-- cleanly on per-project stores that were created from scratch by the
-- 14.2c CLI (those stores never had any of these tables to begin with —
-- migrations V1..V7 always ran in lockstep).

DROP INDEX IF EXISTS idx_vulns_pkg;
DROP INDEX IF EXISTS idx_vulns_advisory;
DROP INDEX IF EXISTS idx_malware_pkg;
DROP INDEX IF EXISTS idx_malware_kind;

DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS malware_reports;
DROP TABLE IF EXISTS sync_log;
