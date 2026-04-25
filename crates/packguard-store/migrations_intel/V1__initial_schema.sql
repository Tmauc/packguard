-- Phase 14.1c — IntelStore V1 schema (~/.packguard/intel/intel.db).
--
-- Diverges intentionally from the per-project Store's V1-V2 schema for
-- `vulnerabilities` and `malware_reports`: the legacy tables FK to
-- `packages(id)` (a project-specific row), which would break the
-- "shared catalog across all projects" intent. IntelStore stores the
-- natural keys (ecosystem, package_name) inline so the catalog is
-- self-contained. The 14.1d data migration must JOIN the legacy
-- store's `packages` table to denormalize the FK before insert here.

CREATE TABLE sync_log (
    kind           TEXT    NOT NULL PRIMARY KEY,   -- "osv-npm" | "osv-pypi" | "ghsa"
    etag           TEXT,
    last_modified  TEXT,
    last_commit    TEXT,
    synced_at      TEXT    NOT NULL,
    record_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE vulnerabilities (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    source               TEXT    NOT NULL,        -- "osv" | "ghsa" | "osv-api-live"
    advisory_id          TEXT    NOT NULL,        -- GHSA-xxx / PYSEC-xxx / CVE-yyy
    ecosystem            TEXT    NOT NULL,        -- natural key (replaces pkg_id FK)
    package_name         TEXT    NOT NULL,        -- natural key (replaces pkg_id FK)
    severity             TEXT,                    -- "critical" | "high" | "medium" | "low" | NULL
    cve_id               TEXT,
    aliases_json         TEXT    NOT NULL DEFAULT '[]',
    summary              TEXT,
    url                  TEXT,
    affected_json        TEXT    NOT NULL,
    fixed_versions_json  TEXT    NOT NULL DEFAULT '[]',
    published_at         TEXT,
    modified_at          TEXT,
    fetched_at           TEXT    NOT NULL,
    UNIQUE(source, advisory_id, ecosystem, package_name)
);

CREATE INDEX idx_vulns_eco_name ON vulnerabilities(ecosystem, package_name);
CREATE INDEX idx_vulns_advisory ON vulnerabilities(advisory_id);

CREATE TABLE malware_reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source         TEXT    NOT NULL,              -- "osv-mal" | "ghsa-malware" | "typosquat-heuristic" | etc.
    ref_id         TEXT    NOT NULL,              -- advisory id / heuristic key / scanner record id
    ecosystem      TEXT    NOT NULL,              -- natural key (replaces pkg_id FK)
    package_name   TEXT    NOT NULL,              -- natural key (replaces pkg_id FK)
    version        TEXT    NOT NULL DEFAULT '',   -- '' = whole-package finding (typosquat)
    kind           TEXT    NOT NULL,              -- "malware" | "typosquat" | "scanner_signal"
    summary        TEXT,
    url            TEXT,
    evidence_json  TEXT    NOT NULL DEFAULT '{}',
    reported_at    TEXT,
    fetched_at     TEXT    NOT NULL,
    UNIQUE(source, ref_id, ecosystem, package_name, version)
);

CREATE INDEX idx_malware_eco_name ON malware_reports(ecosystem, package_name);
CREATE INDEX idx_malware_kind     ON malware_reports(kind);
