import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { Layout } from "@/components/Layout";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import type { Action } from "@/api/types/Action";
import type { ActionSeverity } from "@/api/types/ActionSeverity";

// happy-dom doesn't implement matchMedia; stub it so ThemeProvider's
// system-resolve doesn't blow up in tests that mount <Layout />.
beforeAll(() => {
  window.matchMedia = vi.fn().mockReturnValue({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }) as unknown as typeof window.matchMedia;
});

// Stub every api method Layout touches so we can keep the render
// hermetic. Only `actions` is interesting for this test.
vi.mock("@/lib/api", () => ({
  api: {
    actions: vi.fn(),
    startScan: vi.fn().mockResolvedValue({ id: "x" }),
    startSync: vi.fn().mockResolvedValue({ id: "x" }),
    workspaces: vi.fn().mockResolvedValue({ workspaces: [] }),
    job: vi.fn().mockResolvedValue({
      id: "x",
      kind: "scan",
      status: "succeeded",
      started_at: "2026-04-24T12:00:00Z",
      finished_at: "2026-04-24T12:00:00Z",
      result: null,
      error: null,
    }),
  },
}));

import { api } from "@/lib/api";

function action(id: string, severity: ActionSeverity): Action {
  return {
    id,
    kind: "FixCveHigh",
    severity,
    workspace: "/repo/app",
    target: {
      kind: "Package",
      ecosystem: "npm",
      name: "lodash",
      version: "4.17.20",
    },
    title: "lodash fix",
    explanation: "",
    suggested_command: null,
    recommended_version: null,
    dismissed_at: null,
    deferred_until: null,
  };
}

function wrap() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <Layout />
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  );
}

beforeEach(() => {
  (api.actions as ReturnType<typeof vi.fn>).mockReset();
});

describe("ActionsNavBadge", () => {
  it("renders a count + highest-severity dot when actions exist", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue({
      actions: [
        action("a", "Low"),
        action("b", "Critical"),
        action("c", "Medium"),
      ],
      total: 3,
    });
    wrap();
    // aria-label encodes the count + highest severity so one assertion
    // covers both signals.
    const badge = await screen.findByLabelText(
      /3 pending actions, highest severity Critical/i,
    );
    expect(badge).toHaveTextContent("3");
  });

  it("hides the badge when there are zero actions", async () => {
    (api.actions as ReturnType<typeof vi.fn>).mockResolvedValue({
      actions: [],
      total: 0,
    });
    wrap();
    await waitFor(() => {
      // Actions nav link is still rendered but no badge attached.
      expect(screen.getByRole("link", { name: /^Actions/i })).toBeInTheDocument();
    });
    expect(
      screen.queryByLabelText(/pending actions/i),
    ).not.toBeInTheDocument();
  });
});
