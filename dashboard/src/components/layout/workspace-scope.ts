import { useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export const WORKSPACE_SCOPE_STORAGE_KEY = "packguard.workspaceScope";

/**
 * Read the Phase 7b scope from the current URL. Returns `undefined`
 * when the route is in aggregate mode (no `?project=` param).
 *
 * The value is returned verbatim — canonicalization + validation live
 * on the backend (`resolve_project_filter`). The UI only ever writes a
 * path it already received from `/api/workspaces`, so a round-trip
 * through this hook is a string-identity operation.
 */
export function useScope(): string | undefined {
  const [params] = useSearchParams();
  const raw = params.get("project");
  return raw && raw.length > 0 ? raw : undefined;
}

/**
 * Imperative writer for the workspace scope. Preserves every other
 * query param so callers don't wipe the Packages table filters / Graph
 * focus state when they change workspace.
 */
export function useSetScope() {
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
        window.localStorage.setItem(WORKSPACE_SCOPE_STORAGE_KEY, next);
      } else {
        window.localStorage.removeItem(WORKSPACE_SCOPE_STORAGE_KEY);
      }
    }
  };
}

/**
 * Restore the last workspace the user picked when the URL arrives
 * without a `?project=` param and the value is still in the set of
 * known workspaces. If the stored value is gone (db wiped, repo
 * renamed), we clear localStorage and fall back to aggregate.
 *
 * `known` is the list of paths returned by `/api/workspaces`;
 * `skipRestore` is flipped to `true` for the short window before that
 * fetch lands, so we never accidentally write a stale scope.
 */
export function useRestoreScopeFromStorage(
  known: string[] | undefined,
  skipRestore: boolean,
): void {
  const [params, setParams] = useSearchParams();
  const current = params.get("project");
  const knownSet = useMemo(() => new Set(known ?? []), [known]);
  useEffect(() => {
    if (skipRestore || !known || current) return;
    if (typeof window === "undefined") return;
    const stored = window.localStorage.getItem(WORKSPACE_SCOPE_STORAGE_KEY);
    if (!stored) return;
    if (knownSet.has(stored)) {
      const next = new URLSearchParams(params);
      next.set("project", stored);
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
