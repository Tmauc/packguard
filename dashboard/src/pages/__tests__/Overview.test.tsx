import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { OverviewPage } from "@/pages/Overview";
import { vi } from "vitest";
import type { Overview } from "@/api/types/Overview";

vi.mock("@/lib/api", () => ({ api: { overview: vi.fn() } }));

import { api } from "@/lib/api";

function wrap(ui: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("OverviewPage", () => {
  it("shows the empty-state callout when the store has no packages", async () => {
    (api.overview as ReturnType<typeof vi.fn>).mockResolvedValue({
      health_score: null,
      last_scan_at: null,
      last_sync_at: null,
      packages_total: 0,
      packages_by_ecosystem: [],
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      malware: { confirmed: 0, typosquat_suspects: 0 },
      compliance: {
        compliant: 0,
        warnings: 0,
        violations: 0,
        insufficient: 0,
      },
      top_risks: [],
    } satisfies Overview);
    wrap(<OverviewPage />);
    expect(await screen.findByText(/No scan yet/i)).toBeInTheDocument();
  });

  it("renders the stat cards + top-risks list when data is present", async () => {
    (api.overview as ReturnType<typeof vi.fn>).mockResolvedValue({
      health_score: 67,
      last_scan_at: "2026-04-21T09:00:00Z",
      last_sync_at: "2026-04-20T18:00:00Z",
      packages_total: 27,
      packages_by_ecosystem: [{ ecosystem: "pypi", count: 27 }],
      vulnerabilities: { critical: 0, high: 3, medium: 2, low: 0, unknown: 0 },
      malware: { confirmed: 0, typosquat_suspects: 1 },
      compliance: {
        compliant: 18,
        warnings: 5,
        violations: 4,
        insufficient: 0,
      },
      top_risks: [
        {
          ecosystem: "pypi",
          name: "pillow",
          installed: "12.0.0",
          score: 10,
          reason: "2 crit/high CVE",
        },
      ],
    } satisfies Overview);
    wrap(<OverviewPage />);
    expect(await screen.findByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("67%")).toBeInTheDocument(); // health score
    // Stat cards.
    expect(screen.getByText("Health score")).toBeInTheDocument();
    expect(screen.getByText("CVE matches")).toBeInTheDocument();
    expect(screen.getByText("Supply chain")).toBeInTheDocument();
    // Top risk row.
    await waitFor(() =>
      expect(screen.getByText("pillow")).toBeInTheDocument(),
    );
    expect(screen.getByText(/2 crit\/high CVE/)).toBeInTheDocument();
  });
});
