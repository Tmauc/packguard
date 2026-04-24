import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  FolderIcon,
  FolderTreeIcon,
  PackageIcon,
  SearchIcon,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useCollapsedFolders } from "@/lib/useCollapsedFolders";
import {
  buildWorkspaceTree,
  foldersWithMatches,
  leavesMatching,
  type FolderNode,
  type TreeNode,
  type WorkspaceLeaf,
} from "@/lib/workspaceTree";
import {
  scopeLabel,
  useRestoreScopeFromStorage,
  useScope,
  useSetScope,
} from "./workspace-scope";

/**
 * Tree-view workspace selector. Replaces the earlier flat `<select>`
 * which became unreadable on 20+ workspace monorepos. Clicking the
 * trigger opens a popover with:
 *  - an "All workspaces" aggregate entry (always at the top, never
 *    filtered by the search box),
 *  - a search input (case-insensitive substring match against every
 *    leaf's full path; matches auto-expand their ancestor folders),
 *  - the tree itself, rendered from buildWorkspaceTree() which strips
 *    the common prefix and collapses single-child folders.
 *
 * Scoped URL + localStorage wiring is unchanged — selecting a leaf
 * still pushes `?project=<path>` and persists via useSetScope().
 */
export function WorkspaceSelector() {
  const scope = useScope();
  const setScope = useSetScope();
  const query = useQuery({
    queryKey: ["workspaces"],
    queryFn: api.workspaces,
    refetchInterval: 10_000,
  });

  // `query.data?.workspaces ?? []` creates a fresh [] every render when
  // the query hasn't resolved yet, which makes knownPaths (and everything
  // memoised below it) look changed and ticks a setState-in-effect loop.
  // Pin the fallback behind a useMemo keyed on the query snapshot so the
  // reference stays stable across renders.
  const workspaces = useMemo(
    () => query.data?.workspaces ?? [],
    [query.data],
  );
  const knownPaths = useMemo(() => workspaces.map((w) => w.path), [workspaces]);
  useRestoreScopeFromStorage(query.data ? knownPaths : undefined, query.isLoading);

  const empty = !query.isLoading && workspaces.length === 0;
  const tree = useMemo(() => buildWorkspaceTree(knownPaths), [knownPaths]);

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  // Collapse state hydrates from localStorage once on mount (see
  // useCollapsedFolders) and persists any user toggle on the way out.
  // Newly scanned folders default to collapsed via seedFrom().
  const { collapsed, toggle: toggleFolder, seedFrom } = useCollapsedFolders(
    collectFolderIds(tree),
  );
  useEffect(() => {
    seedFrom(collectFolderIds(tree));
  }, [tree, seedFrom]);

  const popoverRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  // Click-outside + Escape close the popover. Scoped to open state so
  // we don't pay the listener cost when the popover is idle.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Autofocus the search box on open so the user can just start typing.
  useEffect(() => {
    if (open) {
      searchRef.current?.focus();
      setSearch("");
    }
  }, [open]);

  const lowered = search.trim().toLowerCase();
  const openFolders = useMemo(
    () => (lowered === "" ? null : foldersWithMatches(tree, lowered)),
    [tree, lowered],
  );
  const hitCount = useMemo(
    () => (lowered === "" ? knownPaths.length : leavesMatching(tree, lowered).length),
    [tree, lowered, knownPaths.length],
  );

  const triggerLabel = empty
    ? "No scans yet"
    : scope
      ? scopeLabel(scope)
      : "All workspaces";

  const pick = (path: string | undefined) => {
    setScope(path);
    setOpen(false);
  };

  return (
    <div className="relative" ref={popoverRef}>
      <button
        type="button"
        onClick={() => !empty && setOpen((v) => !v)}
        disabled={empty}
        data-testid="workspace-selector"
        aria-haspopup="dialog"
        aria-expanded={open}
        title={
          empty
            ? "No scans yet — run `packguard scan <path>` to register a workspace"
            : scope ?? "All scanned workspaces (aggregate view)"
        }
        className={cn(
          "inline-flex h-8 max-w-72 items-center gap-2 rounded-md border px-2 text-sm",
          "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900",
          "text-zinc-900 dark:text-zinc-100",
          "hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:outline-2 focus:outline-zinc-900",
          empty && "cursor-not-allowed opacity-60",
        )}
      >
        <FolderTreeIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
        <span className="font-medium text-zinc-700 dark:text-zinc-300">Workspace</span>
        <span className="truncate text-zinc-500 dark:text-zinc-400">{triggerLabel}</span>
        <ChevronDownIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
      </button>

      {open && !empty && (
        <div
          role="dialog"
          aria-label="Workspace picker"
          data-testid="workspace-picker"
          className={cn(
            "absolute left-0 top-10 z-50 w-96 overflow-hidden rounded-md border shadow-lg",
            "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
          )}
        >
          <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-2 py-1.5">
            <SearchIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
            <input
              ref={searchRef}
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter workspaces…"
              data-testid="workspace-search"
              className={cn(
                "h-7 w-full bg-transparent text-sm outline-none",
                "text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-600",
              )}
            />
          </div>
          <div className="max-h-96 overflow-y-auto p-1">
            <AggregateRow
              active={!scope}
              workspaceCount={workspaces.length}
              onPick={() => pick(undefined)}
            />
            <div className="my-1 border-t border-zinc-200 dark:border-zinc-800" />
            {tree.map((node) => (
              <TreeRenderer
                key={keyOf(node)}
                node={node}
                depth={0}
                scope={scope}
                collapsed={collapsed}
                openFolders={openFolders}
                needle={lowered}
                onToggleFolder={toggleFolder}
                onPickLeaf={pick}
              />
            ))}
            {lowered !== "" && hitCount === 0 && (
              <div
                data-testid="workspace-empty-state"
                className="px-3 py-4 text-center text-xs text-zinc-500 dark:text-zinc-400"
              >
                No workspace matches {JSON.stringify(search)}.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function keyOf(node: TreeNode): string {
  return node.kind === "leaf" ? `leaf:${node.path}` : `folder:${node.id}`;
}

function collectFolderIds(nodes: TreeNode[]): string[] {
  const out: string[] = [];
  function walk(n: TreeNode) {
    if (n.kind === "folder") {
      out.push(n.id);
      for (const c of n.children) walk(c);
    }
  }
  for (const n of nodes) walk(n);
  return out;
}

function AggregateRow({
  active,
  workspaceCount,
  onPick,
}: {
  active: boolean;
  workspaceCount: number;
  onPick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onPick}
      data-testid="workspace-aggregate"
      className={cn(
        "flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm",
        active
          ? "bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
          : "text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800",
      )}
    >
      <FolderTreeIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
      <span className="flex-1 font-medium">All workspaces (aggregate)</span>
      <span className="text-xs text-zinc-500 dark:text-zinc-400">
        {workspaceCount} total
      </span>
    </button>
  );
}

type TreeRendererProps = {
  node: TreeNode;
  depth: number;
  scope: string | undefined;
  collapsed: Set<string>;
  /// When non-null, a search is active — collapse state is bypassed
  /// and only folders in this set are rendered open.
  openFolders: Set<string> | null;
  needle: string;
  onToggleFolder: (id: string) => void;
  onPickLeaf: (path: string) => void;
};

function TreeRenderer(props: TreeRendererProps) {
  const { node, needle, scope, depth, onPickLeaf } = props;
  if (node.kind === "leaf") {
    if (needle !== "" && !node.path.toLowerCase().includes(needle)) {
      return null;
    }
    return (
      <LeafRow
        node={node}
        depth={depth}
        active={scope === node.path}
        needle={needle}
        onPick={() => onPickLeaf(node.path)}
      />
    );
  }
  return <FolderRow {...props} node={node} />;
}

type FolderRowProps = Omit<TreeRendererProps, "node"> & { node: FolderNode };

function FolderRow({
  node,
  depth,
  scope,
  collapsed,
  openFolders,
  needle,
  onToggleFolder,
  onPickLeaf,
}: FolderRowProps) {
  // Search mode: ignore collapse state entirely — show folders only if
  // they contain at least one match, and render them expanded.
  if (openFolders !== null) {
    if (!openFolders.has(node.id)) return null;
  }
  const isOpen = openFolders !== null ? true : !collapsed.has(node.id);
  return (
    <div>
      <button
        type="button"
        onClick={() => onToggleFolder(node.id)}
        data-testid={`workspace-folder-${node.id}`}
        data-expanded={isOpen}
        className={cn(
          "flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-xs",
          "text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800",
        )}
        style={{ paddingLeft: 8 + depth * 14 }}
      >
        {isOpen ? (
          <ChevronDownIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
        ) : (
          <ChevronRightIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
        )}
        <FolderIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
        <span className="font-medium">{node.label}</span>
        <span className="text-[10px] text-zinc-400 dark:text-zinc-500">
          {countLeaves(node)}
        </span>
      </button>
      {isOpen &&
        node.children.map((child) => (
          <TreeRenderer
            key={keyOf(child)}
            node={child}
            depth={depth + 1}
            scope={scope}
            collapsed={collapsed}
            openFolders={openFolders}
            needle={needle}
            onToggleFolder={onToggleFolder}
            onPickLeaf={onPickLeaf}
          />
        ))}
    </div>
  );
}

function countLeaves(node: FolderNode): number {
  let n = 0;
  for (const c of node.children) {
    if (c.kind === "leaf") n += 1;
    else n += countLeaves(c);
  }
  return n;
}

function LeafRow({
  node,
  depth,
  active,
  needle,
  onPick,
}: {
  node: WorkspaceLeaf;
  depth: number;
  active: boolean;
  needle: string;
  onPick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onPick}
      data-testid={`workspace-leaf-${node.path}`}
      title={node.path}
      className={cn(
        "flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-sm",
        active
          ? "bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
          : "text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800",
      )}
      style={{ paddingLeft: 8 + depth * 14 }}
    >
      <PackageIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
      <span className="truncate font-mono text-xs">
        <HighlightedLabel text={node.label} needle={needle} />
      </span>
    </button>
  );
}

function HighlightedLabel({ text, needle }: { text: string; needle: string }) {
  if (needle === "") return <>{text}</>;
  const i = text.toLowerCase().indexOf(needle);
  if (i < 0) return <>{text}</>;
  return (
    <>
      {text.slice(0, i)}
      <mark className="bg-amber-200 text-zinc-900 dark:bg-amber-500/40 dark:text-zinc-100">
        {text.slice(i, i + needle.length)}
      </mark>
      {text.slice(i + needle.length)}
    </>
  );
}
