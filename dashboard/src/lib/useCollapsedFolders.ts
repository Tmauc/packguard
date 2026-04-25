import { useCallback, useEffect, useState } from "react";

export const COLLAPSED_FOLDERS_STORAGE_KEY = "packguard.workspace-tree-collapsed";

/// Persist workspace-tree folder-collapse state across reloads.
///
/// Stored as a JSON array of folder IDs (stable keys produced by
/// buildWorkspaceTree()). Reads once on mount; writes on every change
/// via a useEffect on the set membership. The set holds *only* the
/// folders the user explicitly collapsed — anything absent renders
/// expanded, including newly scanned folders. A corrupted localStorage
/// value falls back to an empty set for the same reason: a fresh user
/// should see the whole tree, not a blank one.
export function useCollapsedFolders(): {
  collapsed: Set<string>;
  toggle: (id: string) => void;
} {
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set();
    try {
      const raw = window.localStorage.getItem(COLLAPSED_FOLDERS_STORAGE_KEY);
      if (!raw) return new Set();
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return new Set(parsed.filter((x): x is string => typeof x === "string"));
      }
      return new Set();
    } catch {
      return new Set();
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

  return { collapsed, toggle };
}
