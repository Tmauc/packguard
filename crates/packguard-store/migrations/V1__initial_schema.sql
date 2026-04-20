CREATE TABLE IF NOT EXISTS repos (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    path           TEXT    NOT NULL,
    ecosystem      TEXT    NOT NULL,
    fingerprint    TEXT    NOT NULL,
    last_scan_at   TEXT    NOT NULL,
    UNIQUE(path, ecosystem)
);

CREATE TABLE IF NOT EXISTS workspaces (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id        INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    name           TEXT,
    manifest_path  TEXT    NOT NULL,
    UNIQUE(repo_id, manifest_path)
);

CREATE TABLE IF NOT EXISTS packages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem          TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    latest             TEXT,
    latest_fetched_at  TEXT,
    UNIQUE(ecosystem, name)
);

CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(ecosystem, name);

CREATE TABLE IF NOT EXISTS package_versions (
    pkg_id         INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version        TEXT    NOT NULL,
    published_at   TEXT,
    deprecated     INTEGER NOT NULL DEFAULT 0,
    yanked         INTEGER NOT NULL DEFAULT 0,
    metadata_json  TEXT,
    PRIMARY KEY (pkg_id, version)
);

CREATE TABLE IF NOT EXISTS dependencies (
    workspace_id     INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    pkg_id           INTEGER NOT NULL REFERENCES packages(id),
    declared_range   TEXT    NOT NULL,
    installed        TEXT,
    kind             TEXT    NOT NULL,
    source_lockfile  TEXT,
    PRIMARY KEY (workspace_id, pkg_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_deps_workspace ON dependencies(workspace_id);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL,
    pkg_id          INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    affected_range  TEXT    NOT NULL,
    severity        TEXT,
    cve_id          TEXT,
    published_at    TEXT,
    url             TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_pkg ON vulnerabilities(pkg_id);

CREATE TABLE IF NOT EXISTS malware_reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pkg_id       INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version      TEXT,
    source       TEXT    NOT NULL,
    reported_at  TEXT    NOT NULL,
    evidence     TEXT
);

CREATE TABLE IF NOT EXISTS compatibility (
    pkg_id          INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version         TEXT    NOT NULL,
    peer_deps_json  TEXT,
    engines_json    TEXT,
    PRIMARY KEY (pkg_id, version)
);

CREATE TABLE IF NOT EXISTS policies (
    scope      TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    rule_json  TEXT NOT NULL,
    PRIMARY KEY (scope, pattern)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id    INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ts         TEXT    NOT NULL,
    diff_json  TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id       INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    type          TEXT    NOT NULL,
    payload_json  TEXT    NOT NULL,
    seen_at       TEXT
);
