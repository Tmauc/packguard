import { describe, expect, it } from "vitest";
import {
  buildWorkspaceTree,
  foldersWithMatches,
  leavesMatching,
  type FolderNode,
  type WorkspaceLeaf,
} from "@/lib/workspaceTree";

function flattenLabels(nodes: ReturnType<typeof buildWorkspaceTree>): string[] {
  const out: string[] = [];
  function walk(n: (typeof nodes)[number], depth: number) {
    out.push(`${"  ".repeat(depth)}${n.kind === "folder" ? "[f]" : "[l]"} ${n.label}`);
    if (n.kind === "folder") for (const c of n.children) walk(c, depth + 1);
  }
  for (const n of nodes) walk(n, 0);
  return out;
}

describe("buildWorkspaceTree", () => {
  it("returns an empty tree for an empty input", () => {
    expect(buildWorkspaceTree([])).toEqual([]);
  });

  it("renders a lone workspace as a flat leaf using just its basename", () => {
    const tree = buildWorkspaceTree(["/Users/mauc/Repo/foo"]);
    expect(tree).toHaveLength(1);
    expect(tree[0].kind).toBe("leaf");
    expect(tree[0].label).toBe("foo");
    expect((tree[0] as WorkspaceLeaf).path).toBe("/Users/mauc/Repo/foo");
  });

  it("strips the longest common prefix across all paths", () => {
    // All three share /Users/mauc/Repo/Nalo/ — that prefix vanishes
    // from the labels; only the monorepo-relative part survives.
    const tree = buildWorkspaceTree([
      "/Users/mauc/Repo/Nalo/front/vesta",
      "/Users/mauc/Repo/Nalo/front/mellona",
      "/Users/mauc/Repo/Nalo/services/backend",
    ]);
    const labels = flattenLabels(tree);
    // The prefix shouldn't appear anywhere in the rendered labels.
    expect(labels.join("\n")).not.toMatch(/Users|mauc|Repo|Nalo/);
    // Structure: `front` folder with 2 leaves + bare `services/backend` leaf.
    expect(tree[0].kind).toBe("folder");
    expect(tree[0].label).toBe("front");
    expect((tree[0] as FolderNode).children).toHaveLength(2);
  });

  it("keeps a folder visible when it groups ≥ 2 sibling workspaces", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/services/backend",
      "/repo/services/accounting",
    ]);
    expect(tree).toHaveLength(2);
    for (const node of tree) {
      expect(node.kind).toBe("folder");
      expect((node as FolderNode).children.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("collapses a single-child folder into its child (compound label)", () => {
    // `services/` contains only `api-only/` which contains only `core`.
    // Both the `services` wrapper and the `api-only` wrapper are
    // cosmetic — the leaf should surface with label `services/api-only/core`.
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/services/api-only/core",
    ]);
    // Two top-level nodes: the `front` folder (kept) + the collapsed
    // `services/api-only/core` leaf.
    expect(tree).toHaveLength(2);
    const collapsed = tree.find((n) => n.kind === "leaf") as WorkspaceLeaf;
    expect(collapsed).toBeDefined();
    expect(collapsed.label).toBe("services/api-only/core");
    expect(collapsed.path).toBe("/repo/services/api-only/core");
  });

  it("sorts children alphabetically at every level", () => {
    // The leading `/repo/` is the common prefix and gets stripped; the
    // trailing `services/backend` forces `front` to survive as a
    // folder (otherwise the whole `front/` prefix would be stripped
    // too, leaving bare leaves).
    const tree = buildWorkspaceTree([
      "/repo/front/zebra",
      "/repo/front/apple",
      "/repo/front/mango",
      "/repo/services/backend",
    ]);
    const frontFolder = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    expect(frontFolder.children.map((c) => c.label)).toEqual([
      "apple",
      "mango",
      "zebra",
    ]);
  });

  it("handles a path that is both a folder ancestor and a leaf workspace (Turborepo)", () => {
    // pnpm/Turborepo monorepos can register `front` as a workspace and
    // `front/vesta`, `front/mellona` as nested workspaces. The tree must
    // show `front` as a folder containing a `(root)` self-leaf alongside
    // its sub-workspaces — never clobber one with the other.
    const tree = buildWorkspaceTree([
      "/repo/front",
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/services/backend",
    ]);
    const front = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    expect(front).toBeDefined();
    expect(front.children).toHaveLength(3);
    const labels = front.children.map((c) => c.label);
    expect(labels).toContain("(root)");
    expect(labels).toContain("vesta");
    expect(labels).toContain("mellona");
    const rootLeaf = front.children.find(
      (c) => c.kind === "leaf" && c.label === "(root)",
    ) as WorkspaceLeaf;
    expect(rootLeaf.path).toBe("/repo/front");
  });

  it("works regardless of insertion order (leaf first vs descendant first)", () => {
    // Same shape as the Turborepo case but `/repo/front` arrives last,
    // forcing the leaf-into-existing-folder branch instead of the
    // promote-folder-from-existing-leaf branch.
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/front",
      "/repo/services/backend",
    ]);
    const front = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    expect(front).toBeDefined();
    expect(front.children).toHaveLength(3);
    const rootLeaf = front.children.find(
      (c) => c.kind === "leaf" && c.label === "(root)",
    ) as WorkspaceLeaf;
    expect(rootLeaf.path).toBe("/repo/front");
  });

  it("sorts the (root) self-leaf first within its folder", () => {
    const tree = buildWorkspaceTree([
      "/repo/front",
      "/repo/front/aaa",
      "/repo/front/zzz",
      "/repo/services/backend",
    ]);
    const front = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    expect(front.children.map((c) => c.label)).toEqual(["(root)", "aaa", "zzz"]);
  });

  it("does not collapse a (root) self-leaf into a compound folder label", () => {
    // The single-child collapse rule normally folds `front/{vesta}` into
    // a `front/vesta` leaf, but a (root) self-leaf carries semantic
    // information that the merge would erase — keep the folder explicit.
    const tree = buildWorkspaceTree([
      "/repo/front",
      "/repo/front/vesta",
      "/repo/services/backend",
    ]);
    const front = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    expect(front.kind).toBe("folder");
    expect(front.children).toHaveLength(2);
    expect(front.children.map((c) => c.label)).toEqual(["(root)", "vesta"]);
  });

  it("stamps every leaf with the folder IDs on its path from the tree root", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/services/backend",
      "/repo/services/accounting",
    ]);
    const frontFolder = tree.find(
      (n) => n.kind === "folder" && n.label === "front",
    ) as FolderNode;
    const vesta = frontFolder.children.find(
      (c) => c.kind === "leaf" && c.label === "vesta",
    ) as WorkspaceLeaf;
    expect(vesta.ancestors).toEqual(["front"]);
  });
});

describe("foldersWithMatches", () => {
  it("returns the folder IDs required to reveal matching leaves", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
      "/repo/services/backend",
    ]);
    const open = foldersWithMatches(tree, "vesta");
    // The `front` folder has `vesta` inside → open it; `services` has
    // no match → stays shut.
    expect(open.has("front")).toBe(true);
    expect(open.has("services")).toBe(false);
  });

  it("returns an empty set when nothing matches", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
    ]);
    expect(foldersWithMatches(tree, "nonexistent").size).toBe(0);
  });
});

describe("leavesMatching", () => {
  it("returns every leaf when the needle is empty", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/vesta",
      "/repo/front/mellona",
    ]);
    expect(leavesMatching(tree, "")).toHaveLength(2);
  });

  it("filters by substring match against the full path (case-insensitive)", () => {
    const tree = buildWorkspaceTree([
      "/repo/front/VESTA",
      "/repo/front/mellona",
      "/repo/services/backend",
    ]);
    const hits = leavesMatching(tree, "vesta");
    expect(hits.map((h) => h.path)).toEqual(["/repo/front/VESTA"]);
  });
});
