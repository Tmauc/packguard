import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import type { GraphResponse } from "@/api/types/GraphResponse";
import type { ContaminationResult } from "@/api/types/ContaminationResult";

vi.mock("@/lib/api", () => ({
  api: {
    graph: vi.fn(),
    contaminated: vi.fn(),
    graphVulnerabilities: vi.fn(),
  },
}));

// Cytoscape hits canvas / ResizeObserver code paths that happy-dom doesn't
// simulate cleanly; stub the wrapper with a deterministic DOM surface so we
// can exercise the page state machine (filters, highlight overlay, node
// selection) without a real graph renderer.
vi.mock("@/components/graph/GraphCanvas", () => {
  const COLORS = { highlight: "#dc2626" };
  type Props = {
    graph: GraphResponse;
    onSelect: (id: string | null) => void;
    highlight: { kind: string };
    hidden?: Set<string>;
    layout?: string;
  };
  return {
    COLORS,
    // Surface `graph.nodes.length` + the `hidden` prop as DOM attributes so
    // tests can assert "Graph page passed every node through and drove the
    // hide via the prop" (Phase 11.4 finding B regression guard).
    GraphCanvas: ({ graph, onSelect, highlight, hidden, layout }: Props) => (
      <div
        data-testid="graph-canvas"
        data-mode={highlight.kind}
        data-node-count={String(graph.nodes.length)}
        data-hidden={[...(hidden ?? [])].sort().join(",")}
        data-layout={layout ?? ""}
      >
        {graph.nodes.map((n) => (
          <button
            key={n.id}
            type="button"
            data-testid={`node-${n.id}`}
            onClick={() => onSelect(n.id)}
          >
            {n.name}
          </button>
        ))}
      </div>
    ),
  };
});

import { api } from "@/lib/api";
import { GraphPage } from "@/pages/Graph";

const GRAPH: GraphResponse = {
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
      cve_severity: "high",
      has_malware: false,
      has_typosquat: false,
      compliance: null,
      is_unresolved: false,
    },
  ],
  edges: [
    {
      source: "npm:vesta@1.0.0",
      target: "npm:lodash@4.17.23",
      range: "^4.17.0",
      kind: "runtime",
      unresolved: false,
    },
  ],
  oversize_warning: null,
};

const CONTAMINATION: ContaminationResult = {
  hits: [{ ecosystem: "npm", name: "lodash", version: "4.17.23" }],
  chains: [
    { workspace: "vesta", path: ["npm:vesta@1.0.0", "npm:lodash@4.17.23"] },
  ],
  from_cache: false,
};

function wrap(initialEntries: string[] = ["/graph"]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/graph" element={<GraphPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  (api.graph as ReturnType<typeof vi.fn>).mockReset();
  (api.contaminated as ReturnType<typeof vi.fn>).mockReset();
  (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockReset();
  (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue({
    entries: [
      {
        advisory_id: "GHSA-seed",
        cve_id: "CVE-2026-4800",
        ecosystem: "npm",
        package_name: "lodash",
        package_version: "4.17.23",
        severity: "high",
        summary: null,
      },
    ],
  });
});

describe("GraphPage", () => {
  it("renders nodes + edge count from the API response", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    expect(await screen.findByTestId("node-npm:lodash@4.17.23")).toBeInTheDocument();
    expect(screen.getByText(/2 nodes · 1 edges/i)).toBeInTheDocument();
  });

  it("toggles a kind filter and re-queries the API", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await screen.findByTestId("graph-canvas");
    const user = userEvent.setup();
    // Deselect `dev` — button is rendered in the filter bar.
    await user.click(screen.getByRole("button", { name: /^dev$/i }));
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: "runtime,peer,optional" }),
        undefined,
      );
    });
  });

  it("scopes graph + contamination fetches to the URL workspace", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    (api.contaminated as ReturnType<typeof vi.fn>).mockResolvedValue(CONTAMINATION);
    wrap(["/graph?workspace=/tmp/alpha&focus_cve=CVE-X"]);
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(expect.any(Object), "/tmp/alpha");
    });
    await waitFor(() => {
      expect(api.contaminated).toHaveBeenLastCalledWith("CVE-X", "/tmp/alpha");
    });
  });

  it("activates contamination mode when a CVE is picked from the palette", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    (api.contaminated as ReturnType<typeof vi.fn>).mockResolvedValue(CONTAMINATION);
    wrap();
    await screen.findByTestId("graph-canvas");
    const user = userEvent.setup();
    await user.click(screen.getByTestId("open-cve-palette"));
    const row = await screen.findByTestId("cve-palette-row-CVE-2026-4800");
    await user.click(row);
    await waitFor(() => {
      expect(api.contaminated).toHaveBeenCalledWith("CVE-2026-4800", undefined);
    });
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas.getAttribute("data-mode")).toBe("contamination");
    expect(screen.getByText(/1 contamination chain/i)).toBeInTheDocument();
  });

  it("opens the CVE palette via the Cmd+K / Ctrl+K shortcut", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await screen.findByTestId("graph-canvas");
    expect(screen.queryByTestId("cve-palette")).not.toBeInTheDocument();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(await screen.findByTestId("cve-palette")).toBeInTheDocument();
    // Toggle closes it again.
    fireEvent.keyDown(window, { key: "k", metaKey: true });
    await waitFor(() => {
      expect(screen.queryByTestId("cve-palette")).not.toBeInTheDocument();
    });
  });

  it("opens the palette via click on the Focus CVE trigger", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await screen.findByTestId("graph-canvas");
    const user = userEvent.setup();
    await user.click(screen.getByTestId("open-cve-palette"));
    expect(await screen.findByTestId("cve-palette")).toBeInTheDocument();
  });

  it("opens the side panel with package detail link when a node is clicked", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    const node = await screen.findByTestId("node-npm:lodash@4.17.23");
    const user = userEvent.setup();
    await user.click(node);
    const link = await screen.findByRole("link", { name: /Open detail/i });
    expect(link).toHaveAttribute("href", "/packages/npm/lodash");
  });

  it("defaults max_depth to 2 when the URL has no depth param", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ max_depth: 2 }),
        undefined,
      );
    });
    expect(screen.getByRole("spinbutton")).toHaveValue(2);
  });

  it("respects an explicit ?max_depth=5 URL override", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap(["/graph?max_depth=5"]);
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ max_depth: 5 }),
        undefined,
      );
    });
    expect(screen.getByRole("spinbutton")).toHaveValue(5);
  });

  it("keeps the depth input in sync with the URL after a user edit", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await screen.findByTestId("graph-canvas");
    fireEvent.change(screen.getByRole("spinbutton"), { target: { value: "3" } });
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ max_depth: 3 }),
        undefined,
      );
    });
    expect(screen.getByRole("spinbutton")).toHaveValue(3);
  });

  it("legend only shows categories actually present in the rendered graph", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    const legend = await screen.findByTestId("graph-legend");
    // Present in GRAPH: npm ecosystem, CVE (lodash high), root (vesta),
    // runtime edges. Absent: pypi, malware, typosquat, dev/peer/optional.
    expect(legend).toHaveTextContent(/npm/i);
    expect(legend).toHaveTextContent(/CVE/i);
    expect(legend).toHaveTextContent(/root/i);
    expect(legend).toHaveTextContent(/runtime/i);
    expect(legend).not.toHaveTextContent(/pypi/i);
    expect(legend).not.toHaveTextContent(/malware/i);
    expect(legend).not.toHaveTextContent(/typosquat/i);
    expect(legend).not.toHaveTextContent(/\bdev\b/i);
    expect(legend).not.toHaveTextContent(/\bpeer\b/i);
    expect(legend).not.toHaveTextContent(/optional/i);
  });

  it("legend surfaces every category when a mixed graph shows them all", async () => {
    const MIXED: GraphResponse = {
      nodes: [
        {
          id: "npm:root@1.0.0",
          ecosystem: "npm",
          name: "root",
          version: "1.0.0",
          is_root: true,
          cve_severity: null,
          has_malware: false,
          has_typosquat: false,
          compliance: null,
          is_unresolved: false,
        },
        {
          id: "pypi:evil@0.1.0",
          ecosystem: "pypi",
          name: "evil",
          version: "0.1.0",
          is_root: false,
          cve_severity: "critical",
          has_malware: true,
          has_typosquat: true,
          compliance: null,
          is_unresolved: false,
        },
      ],
      edges: [
        {
          source: "npm:root@1.0.0",
          target: "pypi:evil@0.1.0",
          range: "*",
          kind: "runtime",
          unresolved: false,
        },
        {
          source: "npm:root@1.0.0",
          target: "pypi:evil@0.1.0",
          range: "*",
          kind: "dev",
          unresolved: false,
        },
        {
          source: "npm:root@1.0.0",
          target: "pypi:evil@0.1.0",
          range: "*",
          kind: "peer",
          unresolved: false,
        },
        {
          source: "npm:root@1.0.0",
          target: "pypi:evil@0.1.0",
          range: "*",
          kind: "optional",
          unresolved: false,
        },
      ],
      oversize_warning: null,
    };
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(MIXED);
    wrap();
    const legend = await screen.findByTestId("graph-legend");
    for (const label of [
      "npm",
      "pypi",
      "CVE",
      "malware",
      "typosquat",
      "root",
      "runtime",
      "dev",
      "peer",
      "optional",
    ]) {
      expect(legend).toHaveTextContent(new RegExp(label, "i"));
    }
  });

  it("click on a legend swatch toggles the corresponding hide URL param", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-hidden", "");
    const user = userEvent.setup();
    // Hide the CVE category. Post-Phase-11.4 the node stays in the DOM
    // (Cytoscape-side display:none preserves layout positions); we
    // verify the hide by checking the `hidden` prop threaded through to
    // the canvas, plus the swatch's aria-pressed toggle.
    await user.click(screen.getByTestId("legend-status:cve"));
    await waitFor(() => {
      expect(screen.getByTestId("graph-canvas")).toHaveAttribute(
        "data-hidden",
        "status:cve",
      );
    });
    expect(screen.getByTestId("legend-status:cve")).toHaveAttribute("aria-pressed", "false");
  });

  it("clicking a hidden legend item restores it", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap(["/graph?hide=status:cve"]);
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-hidden", "status:cve");
    const swatch = screen.getByTestId("legend-status:cve");
    expect(swatch).toHaveAttribute("aria-pressed", "false");
    const user = userEvent.setup();
    await user.click(swatch);
    await waitFor(() => {
      expect(screen.getByTestId("graph-canvas")).toHaveAttribute("data-hidden", "");
    });
    expect(screen.getByTestId("legend-status:cve")).toHaveAttribute("aria-pressed", "true");
  });

  it("legend edge items stay in sync with the kind filter checkboxes (URL is source of truth)", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    // URL deselects `dev` via the existing kind filter. The legend must
    // reflect that by rendering `dev` desaturated even though it's not
    // in the current DOM.
    wrap(["/graph?kind=runtime,peer,optional"]);
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: "runtime,peer,optional" }),
        undefined,
      );
    });
    const legendDev = await screen.findByTestId("legend-edge-dev");
    expect(legendDev).toHaveAttribute("aria-pressed", "false");
    const legendRuntime = screen.getByTestId("legend-edge-runtime");
    expect(legendRuntime).toHaveAttribute("aria-pressed", "true");
    // Click legend `runtime` to toggle it off — same URL param that the
    // filter bar button writes to. The kind row button for runtime also
    // flips to the inactive style because it reads from the same URL.
    const user = userEvent.setup();
    await user.click(legendRuntime);
    await waitFor(() => {
      expect(api.graph).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: "peer,optional" }),
        undefined,
      );
    });
    expect(screen.getByTestId("legend-edge-runtime")).toHaveAttribute("aria-pressed", "false");
  });

  it("legend stays hidden when the graph has no nodes", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue({
      nodes: [],
      edges: [],
      oversize_warning: null,
    } satisfies GraphResponse);
    wrap();
    // Wait for the empty-state to render so the query has settled.
    await screen.findByText(/No dependency edges/i);
    expect(screen.queryByTestId("graph-legend")).not.toBeInTheDocument();
  });

  it("toggling a legend category does not shrink the graph passed to the canvas", async () => {
    // Regression guard for Phase 11.4 finding B: pre-fix, clicking
    // `cve` in the legend filtered the node array at the data layer,
    // which Cytoscape treats as a graph change → positions reset to
    // origin. After the fix the full node set is always handed to the
    // canvas and the hide drives a CSS class, not a data edit.
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-node-count", "2");
    const user = userEvent.setup();
    await user.click(screen.getByTestId("legend-status:cve"));
    await waitFor(() => {
      expect(screen.getByTestId("graph-canvas")).toHaveAttribute(
        "data-hidden",
        "status:cve",
      );
    });
    // Same count: lodash didn't get pulled from the element set.
    expect(screen.getByTestId("graph-canvas")).toHaveAttribute("data-node-count", "2");
    // And the reported "X nodes · Y edges" label tracks visible-only
    // state, so the legend toggle still feels like it did something.
    expect(screen.getByText(/1 nodes · 0 edges/i)).toBeInTheDocument();
  });

  it("initial mount with ?hide=… still hands the full graph to the canvas", async () => {
    // Cytoscape needs every node on the first layout run to compute
    // positions — if we short-circuit the pre-hidden ones at the data
    // layer on mount, they pop back to (0,0) the moment the user
    // clicks the swatch to reveal them.
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap(["/graph?hide=status:cve"]);
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-node-count", "2");
    expect(canvas).toHaveAttribute("data-hidden", "status:cve");
  });

  it("defaults the graph layout to cose-bilkent when the URL has none", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-layout", "cose-bilkent");
  });

  it("respects an explicit ?layout=dagre override", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap(["/graph?layout=dagre"]);
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas).toHaveAttribute("data-layout", "dagre");
  });

  it("shows a helpful empty-state when the advisory hits nothing", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    (api.contaminated as ReturnType<typeof vi.fn>).mockResolvedValue({
      hits: [],
      chains: [],
      from_cache: false,
    } satisfies ContaminationResult);
    wrap(["/graph?focus_cve=CVE-NONE"]);
    expect(
      await screen.findByText(/no installed package is affected/i),
    ).toBeInTheDocument();
  });

  it("renders hover-tooltips on the Kind filter buttons and legend swatches", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    wrap();
    await screen.findByTestId("graph-canvas");
    // Kind buttons — the Kind filter runtime button carries the
    // "alongside your app" phrasing; the edge legend's runtime button
    // carries a different title, so the match is unambiguous.
    expect(
      screen.getByTitle(/shipped to production alongside your app/i).textContent,
    ).toMatch(/runtime/i);
    // Legend swatches — CVE swatch explains the ring-intensity mapping.
    expect(
      screen.getByTestId("legend-status:cve").getAttribute("title"),
    ).toMatch(/severity/i);
    // Edge legend — runtime edge title distinguishes edges from the Kind row.
    expect(
      screen.getByTestId("legend-edge-runtime").getAttribute("title"),
    ).toMatch(/runtime dependency edge/i);
    // Focus CVE trigger — mentions ⌘K / Ctrl+K shortcut.
    expect(
      screen.getByTestId("open-cve-palette").getAttribute("title"),
    ).toMatch(/⌘K|Ctrl\+K/);
  });
});
