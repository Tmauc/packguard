import { useCallback, useEffect, useState } from "react";

export const COLLAPSED_FOLDERS_STORAGE_KEY = "packguard.workspace-tree-collapsed";

/// Persist workspace-tree folder-collapse state across reloads.
///
/// Stored as a JSON array of folder IDs (stable keys produced by
/// buildWorkspaceTree()). Reads once on mount; writes on every change
/// via a useEffect on the set membership. A corrupted value is
/// silently replaced with the supplied `seed` — better UX than dumping
/// a blank tree on a user who just upgraded to a build with a parser
/// change.
export function useCollapsedFolders(seed: string[]): {
  collapsed: Set<string>;
  toggle: (id: string) => void;
  seedFrom: (ids: string[]) => void;
} {
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set(seed);
    try {
      const raw = window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY);
      if (!raw) return new Set(seed);
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return new Set(parsed.filter((x): x is string => typeof x === "string"));
      }
      return new Set(seed);
    } catch {
      return new Set(seed);
    }
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      COLLAPSED_FOLDERS_STORAGE_KEY,
      JSON.stringify([...collapsed].sort()),
    );
  }, [collapsed]);

  const toggle = useCallback((id: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // Default newly scanned folders to collapsed, but never override
  // what the user already toggled open. Called from the selector on
  // every /api/workspaces refresh.
  const seedFrom = useCallback((ids: string[]) => {
    setCollapsed((prev) => {
      let changed = false;
      const next = new Set(prev);
      for (const id of ids) {
        if (!prev.has(id)) {
          next.add(id);
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, []);

  return { collapsed, toggle, seedFrom };
}
