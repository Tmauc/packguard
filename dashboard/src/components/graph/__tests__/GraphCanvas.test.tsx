/// Polish-bis-1 safety-net regression. Feeds the canvas a malformed
/// GraphResponse where an edge points at a node that isn't in `nodes[]`
/// (the exact shape that used to crash Cytoscape at mount before the
/// backend started emitting placeholder nodes). The frontend filter
/// must drop that edge so the canvas still renders.
///
/// We don't need a real Cytoscape instance for the assertion — what we
/// care about is that `CytoscapeComponent` receives a sane element set
/// (every edge's source + target present in the nodes). We intercept
/// the component at import time and inspect its `elements` prop.

import { render } from "@testing-library/react";
import { vi } from "vitest";
import type { GraphResponse } from "@/api/types/GraphResponse";
import { GraphCanvas } from "@/components/graph/GraphCanvas";

type Element = { data: Record<string, unknown> };
const received: Element[][] = [];

vi.mock("react-cytoscapejs", () => ({
  default: ({ elements }: { elements: Element[] }) => {
    received.push(elements);
    return <div data-testid="stub-cy">{elements.length} elements</div>;
  },
}));

const ORPHAN_GRAPH: GraphResponse = {
  nodes: [
    {
      id: "npm:vesta@1.0.0",
      ecosystem: "npm",
      name: "vesta",
      version: "1.0.0",
      is_root: true,
      cve_severity: null,
      has_malware: false,
      has_typosquat: false,
      compliance: null,
      is_unresolved: false,
    },
    {
      id: "npm:lodash@4.17.23",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.23",
      is_root: false,
      cve_severity: null,
      has_malware: false,
      has_typosquat: false,
      compliance: null,
      is_unresolved: false,
    },
  ],
  edges: [
    // Valid edge — should be forwarded.
    {
      source: "npm:vesta@1.0.0",
      target: "npm:lodash@4.17.23",
      range: "^4.17.0",
      kind: "runtime",
      unresolved: false,
    },
    // Orphan edge — target missing from nodes[]. Pre-fix this crashed
    // Cytoscape at mount. The frontend filter must drop it.
    {
      source: "npm:vesta@1.0.0",
      target: "npm:scheduler@unresolved",
      range: "^0.23.0",
      kind: "peer",
      unresolved: true,
    },
    // Orphan edge with orphaned source (harder to hit but possible if
    // the backend ever breaks in a different direction).
    {
      source: "npm:ghost@1.0.0",
      target: "npm:vesta@1.0.0",
      range: "*",
      kind: "runtime",
      unresolved: false,
    },
  ],
  oversize_warning: null,
};

describe("GraphCanvas", () => {
  beforeEach(() => {
    received.length = 0;
  });

  it("drops orphan edges before feeding Cytoscape — Polish-bis-1 safety net", () => {
    render(
      <GraphCanvas
        graph={ORPHAN_GRAPH}
        layout="dagre"
        highlight={{ kind: "none" }}
        selectedId={null}
        onSelect={() => {}}
      />,
    );
    const elements = received.at(-1) ?? [];
    const nodeIds = new Set(
      elements
        .filter((el) => typeof el.data.id === "string" && !("source" in el.data))
        .map((el) => el.data.id as string),
    );
    const edges = elements.filter((el) => "source" in el.data);
    expect(nodeIds).toEqual(
      new Set(["npm:vesta@1.0.0", "npm:lodash@4.17.23"]),
    );
    // Exactly one edge must survive the filter.
    expect(edges).toHaveLength(1);
    expect(edges[0].data.source).toBe("npm:vesta@1.0.0");
    expect(edges[0].data.target).toBe("npm:lodash@4.17.23");
    // Every surviving edge has a landing in the node set.
    for (const e of edges) {
      expect(nodeIds.has(e.data.source as string)).toBe(true);
      expect(nodeIds.has(e.data.target as string)).toBe(true);
    }
  });

  it("forwards placeholder unresolved nodes as regular elements", () => {
    const graph: GraphResponse = {
      nodes: [
        ORPHAN_GRAPH.nodes[0]!,
        {
          id: "npm:scheduler@unresolved",
          ecosystem: "npm",
          name: "scheduler",
          version: "unresolved",
          is_root: false,
          cve_severity: null,
          has_malware: false,
          has_typosquat: false,
          compliance: null,
          is_unresolved: true,
        },
      ],
      edges: [
        {
          source: "npm:vesta@1.0.0",
          target: "npm:scheduler@unresolved",
          range: "^0.23.0",
          kind: "peer",
          unresolved: true,
        },
      ],
      oversize_warning: null,
    };
    render(
      <GraphCanvas
        graph={graph}
        layout="dagre"
        highlight={{ kind: "none" }}
        selectedId={null}
        onSelect={() => {}}
      />,
    );
    const elements = received.at(-1) ?? [];
    const placeholder = elements.find(
      (el) => el.data.id === "npm:scheduler@unresolved",
    );
    expect(placeholder?.data.is_unresolved).toBe("1");
    // Edge survives now that its target exists in nodes[].
    const edges = elements.filter((el) => "source" in el.data);
    expect(edges).toHaveLength(1);
  });
});
