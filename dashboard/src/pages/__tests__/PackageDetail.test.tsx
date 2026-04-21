import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { PackageDetailPage } from "@/pages/PackageDetail";
import type { PackageDetail } from "@/api/types/PackageDetail";

vi.mock("@/lib/api", () => ({ api: { packageDetail: vi.fn() } }));

import { api } from "@/lib/api";

function wrap(detail: PackageDetail) {
  (api.packageDetail as ReturnType<typeof vi.fn>).mockResolvedValue(detail);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/packages/${detail.ecosystem}/${detail.name}`]}>
        <Routes>
          <Route
            path="/packages/:ecosystem/:name"
            element={<PackageDetailPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fixture(overrides: Partial<PackageDetail> = {}): PackageDetail {
  return {
    ecosystem: "npm",
    name: "lodash",
    installed: "4.17.20",
    latest: "4.17.21",
    last_scanned_at: null,
    compliance: "cve-violation",
    risk: {
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      malware_confirmed: 0,
      typosquat_suspects: 0,
    },
    versions: [
      { version: "4.17.20", published_at: null, deprecated: false, yanked: false, severity: "high" },
      { version: "4.17.21", published_at: null, deprecated: false, yanked: false, severity: null },
    ],
    vulnerabilities: [
      {
        source: "osv",
        advisory_id: "GHSA-test",
        cve_id: "CVE-2021-23337",
        severity: "high",
        summary: "Command injection in lodash",
        url: "https://example/cve",
        fixed_versions: ["4.17.21"],
        affects_installed: true,
      },
    ],
    malware: [],
    policy_trace: {
      offset: 1,
      pin: null,
      stability: "stable",
      min_age_days: 7,
      recommended: "4.17.21",
      reason: "installed 4.17.20 has a blocking CVE — upgrade to 4.17.21",
    },
    ...overrides,
  };
}

beforeEach(() => {
  (api.packageDetail as ReturnType<typeof vi.fn>).mockReset();
});

describe("PackageDetailPage", () => {
  it("renders header + meta bar from the API response", async () => {
    wrap(fixture());
    expect(await screen.findByText("lodash")).toBeInTheDocument();
    // `4.17.20` appears in both the meta bar and the Versions table.
    expect(screen.getAllByText("4.17.20").length).toBeGreaterThan(0);
    expect(screen.getByText("cve-violation")).toBeInTheDocument();
    // Recommended version surfaces in the meta bar.
    expect(screen.getAllByText("4.17.21").length).toBeGreaterThan(0);
  });

  it("highlights the affecting CVE in the Vulnerabilities tab", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Vulnerabilities/i }));
    expect(
      screen.getByText(/Installed version is affected/i),
    ).toBeInTheDocument();
    expect(screen.getByText("CVE-2021-23337")).toBeInTheDocument();
    expect(screen.getByText(/Command injection in lodash/i)).toBeInTheDocument();
  });

  it("shows an empty-state when no malware is on record", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /^Malware/i }));
    expect(
      screen.getByText(/No malware or typosquat signals/i),
    ).toBeInTheDocument();
  });

  it("surfaces the policy trace reason in the Policy tab", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /^Policy/i }));
    expect(
      screen.getByText(/blocking CVE — upgrade to 4\.17\.21/i),
    ).toBeInTheDocument();
  });

  it("defers the changelog to a later phase but still renders the tab", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Changelog/i }));
    expect(
      screen.getByText(/Inline changelog lazy-fetch lands in Phase 5/i),
    ).toBeInTheDocument();
  });
});
