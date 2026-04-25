-- Phase 14.1b — projects registry (~/.packguard/projects.db).
-- Schema chain is independent from the per-project store schema; the
-- two SQLite files share nothing but a parent directory.

CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,         -- slugify(canonical_path)
    path TEXT UNIQUE NOT NULL,         -- canonical absolute path
    name TEXT NOT NULL,                -- last segment of path; user-editable later
    created_at INTEGER NOT NULL,       -- unix seconds, UTC
    last_scan INTEGER                  -- unix seconds, NULL until first scan completes
);

CREATE INDEX idx_projects_slug ON projects(slug);
CREATE INDEX idx_projects_path ON projects(path);
