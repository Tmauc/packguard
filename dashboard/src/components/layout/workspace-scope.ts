import { useEffect, useMemo, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import type { ProjectDto } from "@/api/types/ProjectDto";

/// Phase 14.3 scope keys. The workspace key bumps to `.v2` so any v0.5
/// localStorage value (which lived under `packguard.workspaceScope` and
/// shared the URL slot with what is now the project slug) is silently
/// dropped on first boot — paths that were valid then are still valid
/// now, but the URL contract changed and forcing a re-pick is cheaper
/// than disambiguating a stale entry post-hoc.
export const WORKSPACE_SCOPE_STORAGE_KEY = "packguard.workspaceScope.v2";
export const PROJECT_SCOPE_STORAGE_KEY = "packguard.projectScope";

/**
 * Read the workspace scope from the URL — `?workspace=<absolute path>`.
 * Returns `undefined` when the route is in aggregate mode (no
 * `?workspace=` param).
 *
 * The value is returned verbatim — canonicalization + validation live
 * on the backend (`resolve_scope`). The UI only ever writes a path it
 * already received from `/api/workspaces`, so a round-trip through this
 * hook is a string-identity operation.
 */
export function useWorkspaceScope(): string | undefined {
  const [params] = useSearchParams();
  const raw = params.get("workspace");
  return raw && raw.length > 0 ? raw : undefined;
}

/**
 * Imperative writer for the workspace scope. Preserves every other
 * query param so callers don't wipe the Packages table filters / Graph
 * focus state when they change workspace. Also persists to localStorage
 * under [`WORKSPACE_SCOPE_STORAGE_KEY`].
 */
export function useSetWorkspaceScope() {
  const [, setParams] = useSearchParams();
  return (next: string | undefined) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next && next.length > 0) {
        p.set("workspace", next);
      } else {
        p.delete("workspace");
      }
      return p;
    });
    if (typeof window !== "undefined") {
      if (next && next.length > 0) {
        window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, next);
      } else {
        window.localStorage.removeItem(WORKSPACE_SCOPE_STORAGE_KEY);
      }
    }
  };
}

/**
 * Restore the last workspace the user picked when the URL arrives
 * without a `?workspace=` param and the value is still in the set of
 * known workspace paths. If the stored value is gone (db wiped, repo
 * renamed), we clear localStorage and fall back to aggregate.
 *
 * `known` is the list of paths returned by `/api/workspaces`;
 * `skipRestore` is flipped to `true` for the short window before that
 * fetch lands, so we never accidentally write a stale scope.
 */
export function useRestoreWorkspaceScopeFromStorage(
  known: string[] | undefined,
  skipRestore: boolean,
): void {
  const [params, setParams] = useSearchParams();
  const current = params.get("workspace");
  const knownSet = useMemo(() => new Set(known ?? []), [known]);
  useEffect(() => {
    if (skipRestore || !known || current) return;
    if (typeof window === "undefined") return;
    const stored = window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY);
    if (!stored) return;
    if (knownSet.has(stored)) {
      const next = new URLSearchParams(params);
      next.set("workspace", stored);
      setParams(next, { replace: true });
    } else {
      window.localStorage.removeItem(WORKSPACE_SCOPE_STORAGE_KEY);
    }
    // setParams + params are stable-by-content; we intentionally only fire
    // when the store data arrives or when the URL scope clears.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [known, current, skipRestore]);
}

/**
 * Read the project scope from the URL — `?project=<slug>`. The slug
 * discriminator is "does NOT start with `/`" so the legacy v0.5
 * `?project=<workspace path>` form does not mis-parse as a project slug
 * (paths always start with `/`; slugs come from
 * [`packguard_core::slugify`] which dash-separates path segments and
 * strips the leading slash). Returns `undefined` when the param is
 * absent or looks like a legacy path.
 */
export function useProjectScope(): string | undefined {
  const [params] = useSearchParams();
  const raw = params.get("project");
  if (!raw || raw.length === 0) return undefined;
  if (raw.startsWith("/")) return undefined;
  return raw;
}

/**
 * Imperative writer for the project scope. Persists to localStorage
 * under [`PROJECT_SCOPE_STORAGE_KEY`]. Preserves every other query
 * param so changing project doesn't clobber the active workspace,
 * filters, or graph focus state — that's the caller's responsibility
 * if a project switch should also reset the workspace.
 */
export function useSetProjectScope() {
  const [, setParams] = useSearchParams();
  return (next: string | undefined) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next && next.length > 0) {
        p.set("project", next);
      } else {
        p.delete("project");
      }
      return p;
    });
    if (typeof window !== "undefined") {
      if (next && next.length > 0) {
        window.localStorage.setItem(PROJECT_SCOPE_STORAGE_KEY, next);
      } else {
        window.localStorage.removeItem(PROJECT_SCOPE_STORAGE_KEY);
      }
    }
  };
}

/**
 * Restore the last project the user picked when the URL arrives
 * without a `?project=<slug>` param and the value is still in the set
 * of known project slugs. Mirrors the workspace version's contract.
 */
export function useRestoreProjectScopeFromStorage(
  known: string[] | undefined,
  skipRestore: boolean,
): void {
  const [params, setParams] = useSearchParams();
  const rawCurrent = params.get("project");
  // Only consider the URL "scoped" when the value looks like a slug
  // (legacy paths must trigger the redirect hook instead of stalling
  // restoration here).
  const current =
    rawCurrent && rawCurrent.length > 0 && !rawCurrent.startsWith("/")
      ? rawCurrent
      : null;
  const knownSet = useMemo(() => new Set(known ?? []), [known]);
  useEffect(() => {
    if (skipRestore || !known || current) return;
    if (typeof window === "undefined") return;
    const stored = window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY);
    if (!stored) return;
    if (knownSet.has(stored)) {
      const next = new URLSearchParams(params);
      next.set("project", stored);
      setParams(next, { replace: true });
    } else {
      window.localStorage.removeItem(PROJECT_SCOPE_STORAGE_KEY);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [known, current, skipRestore]);
}

/**
 * Backcompat for v0.5 bookmarks of the form `?project=<absolute path>`.
 * When the URL still carries a leading-`/` value AND the projects
 * registry has loaded, we walk every known project root and pick the
 * deepest ancestor of the legacy path (longest match wins so nested
 * git repos resolve to the most specific project). The URL is
 * rewritten in place to `?project=<slug>&workspace=<legacy path>` and
 * a one-shot toast tells the user the URL changed under them — the
 * back button still works and the scope they wanted is preserved.
 *
 * If no project root matches the legacy path, we leave the URL alone:
 * the backend will respond with a 404 + the list of known projects,
 * which is the surface the user needs to recover (likely scan the
 * project first).
 */
export function useLegacyProjectRedirect(
  projects: ProjectDto[] | undefined,
): void {
  const [params, setParams] = useSearchParams();
  const raw = params.get("project");
  // Refs guard against re-firing the toast/redirect on the same URL
  // across re-renders — `setParams` triggers a re-render which would
  // otherwise loop us through this effect a second time before the
  // legacy `raw` value clears.
  const handled = useRef<string | null>(null);
  useEffect(() => {
    if (!raw || !raw.startsWith("/") || !projects) return;
    if (handled.current === raw) return;
    handled.current = raw;
    // Pick the deepest project root that is an ancestor of the legacy
    // path. We compare with trailing-slash semantics so a project at
    // `/a/b` does not falsely match `/a/bcd`.
    const legacy = raw.endsWith("/") ? raw : `${raw}/`;
    let best: ProjectDto | undefined;
    for (const proj of projects) {
      const root = proj.path.endsWith("/") ? proj.path : `${proj.path}/`;
      if (legacy === root || legacy.startsWith(root)) {
        if (!best || proj.path.length > best.path.length) {
          best = proj;
        }
      }
    }
    if (!best) return;
    const next = new URLSearchParams(params);
    next.set("project", best.slug);
    next.set("workspace", raw);
    setParams(next, { replace: true });
    toast.message("URL updated", {
      description:
        "Bookmarked URLs from previous versions now use ?project=<slug>&workspace=<path>.",
    });
    // params + setParams are stable-by-content; we only react to the
    // raw value flipping or the projects list arriving.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [raw, projects]);
}

/**
 * Friendly label for a repo path. The selector dropdown shows the last
 * path segment (e.g. the project-name tail) with the full path as a
 * tooltip — that's what the Phase 7b brief asked for.
 */
export function scopeLabel(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  const segments = trimmed.split(/[\\/]/);
  const tail = segments.pop();
  return tail && tail.length > 0 ? tail : path;
}
