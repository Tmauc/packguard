import { render, screen, waitFor } from "@testing-library/react";
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
  };
  return {
    COLORS,
    GraphCanvas: ({ graph, onSelect, highlight }: Props) => (
      <div data-testid="graph-canvas" data-mode={highlight.kind}>
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
      );
    });
  });

  it("activates contamination mode when a CVE is typed + Trace is clicked", async () => {
    (api.graph as ReturnType<typeof vi.fn>).mockResolvedValue(GRAPH);
    (api.contaminated as ReturnType<typeof vi.fn>).mockResolvedValue(CONTAMINATION);
    wrap();
    await screen.findByTestId("graph-canvas");
    const user = userEvent.setup();
    await user.type(
      screen.getByPlaceholderText(/Focus CVE/i),
      "CVE-2026-4800",
    );
    await user.click(screen.getByRole("button", { name: /^Trace$/i }));
    await waitFor(() => {
      expect(api.contaminated).toHaveBeenCalledWith("CVE-2026-4800");
    });
    const canvas = await screen.findByTestId("graph-canvas");
    expect(canvas.getAttribute("data-mode")).toBe("contamination");
    expect(
      screen.getByText(/1 contamination chain/i),
    ).toBeInTheDocument();
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
});
