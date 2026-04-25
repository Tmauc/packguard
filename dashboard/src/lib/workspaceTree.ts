/// Build a navigable tree from a flat list of workspace paths.
///
/// Flat list on 20+ Nalo-style monorepos is a scroll-wall. The paths
/// share structure (front/vesta, front/mellona, services/backend…) so
/// collapsing by common prefix and grouping siblings under folders is
/// a cheap visual upgrade that costs no backend work.
///
/// Algorithm (bottom-up):
///  1. Strip the longest prefix shared by every input path.
///  2. Split each remainder by `/` to produce trie segments.
///  3. Walk the trie; any folder with exactly one child is collapsed
///     into its child (the labels merge: `services/api-only`). Folders
///     with ≥ 2 children remain so sibling workspaces group visually.
///  4. Alphabetical sort at each level keeps ordering predictable
///     across refreshes (backend sort-by-last-scan matters on the flat
///     list, but inside a tree the shuffle would be disorienting).

export type WorkspaceLeaf = {
  kind: "leaf";
  /// Segment(s) displayed at this level — may be compound after
  /// single-child collapse (e.g. `services/api-only`).
  label: string;
  /// Full absolute path — what ends up in `?project=…`.
  path: string;
  /// Trail of folder labels from the tree root down to (but not
  /// including) this leaf. Used for the collapse-state expansion check
  /// during fuzzy search.
  ancestors: string[];
};

export type FolderNode = {
  kind: "folder";
  label: string;
  /// Folder path reconstructed from the root of the stripped tree
  /// (e.g. `front` or `services/subdir`). Stable across renders — used
  /// as the identity key for collapse-state persistence.
  id: string;
  children: TreeNode[];
};

export type TreeNode = WorkspaceLeaf | FolderNode;

function splitPath(p: string): string[] {
  return p.split("/").filter(Boolean);
}

/// Longest common prefix across every path's segment list. Bounded so
/// we never strip the final segment — a lone workspace still needs
/// *something* to show as its label.
function longestCommonPrefix(allParts: string[][]): string[] {
  if (allParts.length === 0) return [];
  const max = Math.min(...allParts.map((p) => Math.max(0, p.length - 1)));
  const prefix: string[] = [];
  for (let i = 0; i < max; i += 1) {
    const candidate = allParts[0][i];
    const matchesAll = allParts.every((p) => p[i] === candidate);
    if (!matchesAll) break;
    prefix.push(candidate);
  }
  return prefix;
}

type MutableFolder = {
  kind: "folder";
  label: string;
  id: string;
  children: Map<string, MutableFolder | WorkspaceLeaf>;
};

function ensureFolder(
  parent: MutableFolder,
  segment: string,
  idPrefix: string,
): MutableFolder {
  const existing = parent.children.get(segment);
  if (existing && existing.kind === "folder") return existing;
  const fresh: MutableFolder = {
    kind: "folder",
    label: segment,
    id: idPrefix === "" ? segment : `${idPrefix}/${segment}`,
    children: new Map(),
  };
  // Turborepo-style: a previous insertion registered this segment as a
  // leaf workspace, but a subsequent path needs the same segment to act
  // as a folder ancestor. Promote — keep the leaf reachable inside the
  // new folder under a sentinel key with the (root) marker label.
  if (existing && existing.kind === "leaf") {
    fresh.children.set("__self__", {
      ...existing,
      label: "(root)",
    });
  }
  parent.children.set(segment, fresh);
  return fresh;
}

/// Recursively collapse: any folder with exactly one child merges its
/// label into that child. The brief's rule is "folder appears only if
/// it has ≥ 2 children"; anything else is cosmetic overhead.
/// Root is special-cased (empty label) — a root with a single child
/// just returns that child verbatim instead of prefixing `/`.
function collapse(node: MutableFolder | WorkspaceLeaf): TreeNode {
  if (node.kind === "leaf") return node;
  const children = Array.from(node.children.values())
    .map(collapse)
    // Alphabetical sort within each folder — leaves and folders are
    // interleaved, keeping the listing predictable. The (root) self-leaf
    // marker (set when a workspace path is also a folder ancestor) sorts
    // first so users find the parent workspace before its sub-workspaces.
    .sort((a, b) => {
      if (a.label === "(root)") return -1;
      if (b.label === "(root)") return 1;
      return a.label.localeCompare(b.label);
    });

  if (children.length === 1) {
    const only = children[0];
    if (node.label === "") return only;
    // A `(root)` self-leaf signals "this folder is also a workspace" —
    // merging into a `front/(root)` compound label would erase that
    // semantic, so keep the folder explicit.
    if (only.kind === "leaf" && only.label === "(root)") {
      return {
        kind: "folder",
        label: node.label,
        id: node.id,
        children,
      };
    }
    return {
      ...only,
      label: `${node.label}/${only.label}`,
    };
  }
  return {
    kind: "folder",
    label: node.label,
    id: node.id,
    children,
  };
}

/// Walk a collapsed tree and stamp each leaf with its ancestor folder
/// labels so the UI can auto-expand the right folders during search.
function stampAncestors(nodes: TreeNode[], trail: string[]): TreeNode[] {
  return nodes.map((n) => {
    if (n.kind === "leaf") return { ...n, ancestors: trail };
    return {
      ...n,
      children: stampAncestors(n.children, [...trail, n.id]),
    };
  });
}

export function buildWorkspaceTree(paths: string[]): TreeNode[] {
  if (paths.length === 0) return [];
  const allParts = paths.map(splitPath);
  const prefix = longestCommonPrefix(allParts);
  const root: MutableFolder = {
    kind: "folder",
    label: "",
    id: "",
    children: new Map(),
  };
  for (let i = 0; i < paths.length; i += 1) {
    const remainder = allParts[i].slice(prefix.length);
    if (remainder.length === 0) continue;
    let cursor = root;
    for (let j = 0; j < remainder.length - 1; j += 1) {
      cursor = ensureFolder(cursor, remainder[j], cursor.id);
    }
    const leafLabel = remainder[remainder.length - 1];
    const existing = cursor.children.get(leafLabel);
    if (existing && existing.kind === "folder") {
      // The segment was already promoted to a folder by a previously
      // inserted descendant path. Register the current workspace as the
      // folder's (root) self-leaf instead of clobbering its sub-workspaces.
      existing.children.set("__self__", {
        kind: "leaf",
        label: "(root)",
        path: paths[i],
        ancestors: [],
      });
    } else {
      cursor.children.set(leafLabel, {
        kind: "leaf",
        label: leafLabel,
        path: paths[i],
        ancestors: [],
      });
    }
  }
  const collapsed = collapse(root);
  if (collapsed.kind === "leaf") {
    // Happens only when the full input collapses to one leaf — rare
    // enough but keep shape consistent.
    return [collapsed];
  }
  return stampAncestors(collapsed.children, []);
}

/// Returns the set of folder IDs that must be visible + expanded so
/// every leaf whose full path matches `needle` is reachable. Called
/// when the fuzzy-search query is non-empty so collapse state is
/// bypassed around matches.
export function foldersWithMatches(
  nodes: TreeNode[],
  needle: string,
): Set<string> {
  const lowered = needle.toLowerCase();
  const open = new Set<string>();
  function walk(n: TreeNode): boolean {
    if (n.kind === "leaf") return n.path.toLowerCase().includes(lowered);
    let any = false;
    for (const child of n.children) {
      if (walk(child)) any = true;
    }
    if (any) open.add(n.id);
    return any;
  }
  for (const n of nodes) walk(n);
  return open;
}

/// Flatten the tree into an in-order list of leaves that match the
/// needle. The UI uses this for keyboard nav + empty-state detection.
export function leavesMatching(
  nodes: TreeNode[],
  needle: string,
): WorkspaceLeaf[] {
  const lowered = needle.toLowerCase();
  const out: WorkspaceLeaf[] = [];
  function walk(n: TreeNode) {
    if (n.kind === "leaf") {
      if (lowered === "" || n.path.toLowerCase().includes(lowered)) out.push(n);
      return;
    }
    for (const child of n.children) walk(child);
  }
  for (const n of nodes) walk(n);
  return out;
}
