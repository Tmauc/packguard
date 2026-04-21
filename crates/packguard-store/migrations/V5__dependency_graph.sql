-- Phase 5: transitive dependency edges + contamination cache.
--
-- Edges live per-workspace because a package can resolve differently across
-- workspaces of the same monorepo. The `source_pkg_id`/`source_version`
-- pair identifies the *installed* parent; `target_name`/`target_range`
-- carries the declared child requirement; `resolved_pkg_id`/
-- `resolved_version` is filled when the lockfile pinned the child and left
-- NULL for unresolved peer dependencies (standard package-manager
-- behaviour — they surface as warnings in the graph view).
--
-- Invariant: `save_project` clears every edge for the workspace before
-- inserting the fresh set, so we never hold stale edges between scans.

CREATE TABLE IF NOT EXISTS dependency_edges (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id      INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    source_pkg_id     INTEGER NOT NULL REFERENCES packages(id),
    source_version    TEXT    NOT NULL,
    target_name       TEXT    NOT NULL,
    target_range      TEXT    NOT NULL,
    resolved_pkg_id   INTEGER REFERENCES packages(id),
    resolved_version  TEXT,
    kind              TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_workspace
    ON dependency_edges(workspace_id);

CREATE INDEX IF NOT EXISTS idx_edges_source
    ON dependency_edges(source_pkg_id, source_version);

-- Reverse-lookup index for contamination BFS: "who depends on (pkg, ver)?"
CREATE INDEX IF NOT EXISTS idx_edges_resolved
    ON dependency_edges(resolved_pkg_id, resolved_version);

-- Contamination cache: BFS results keyed by (advisory_id, workspace). Rows
-- are evicted when `save_project` runs for that workspace so a new scan
-- always recomputes from the fresh edges.
CREATE TABLE IF NOT EXISTS contamination_cache (
    advisory_id    TEXT    NOT NULL,
    workspace_id   INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    chains_json    TEXT    NOT NULL,
    computed_at    TEXT    NOT NULL,
    PRIMARY KEY (advisory_id, workspace_id)
);
