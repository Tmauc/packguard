import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { PackageDetailPage } from "@/pages/PackageDetail";
import type { PackageDetail } from "@/api/types/PackageDetail";

vi.mock("@/lib/api", () => ({
  api: {
    packageDetail: vi.fn(),
    packageCompat: vi.fn(),
  },
}));

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
      offset: { major: 1, minor: 0, patch: 0 },
      pin: null,
      stability: "stable",
      min_age_days: 7,
      recommended: "4.17.21",
      reason: "installed 4.17.20 has a blocking CVE — upgrade to 4.17.21",
      cascade: [
        "offset.major=-1 → (4, ∞, ∞)",
        "offset.minor=0 → inactive",
        "offset.patch=0 → inactive",
        "effective bound = (4, ∞, ∞) (latest = (5, 0, 0))",
        "max version ≤ bound = 4.17.21 → picked 4.17.21",
      ],
    },
    policy_sources: [],
    policy_provenance: [],
    ...overrides,
  };
}

beforeEach(() => {
  (api.packageDetail as ReturnType<typeof vi.fn>).mockReset();
  (api.packageCompat as ReturnType<typeof vi.fn>).mockReset();
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

  it("renders the Policy sources panel when cascade data is present", async () => {
    wrap(
      fixture({
        policy_sources: [
          {
            kind: "built_in",
            label: "built-in default",
            path: null,
          },
          {
            kind: "file",
            label: "/repo/.packguard.yml",
            path: "/repo/.packguard.yml",
          },
          {
            kind: "file",
            label: "/repo/front/vesta/.packguard.yml",
            path: "/repo/front/vesta/.packguard.yml",
          },
        ],
        policy_provenance: [
          { key: "defaults.offset.major", source_index: 1, line: 4 },
          { key: "defaults.offset.minor", source_index: 1, line: 5 },
          { key: "defaults.offset.patch", source_index: 0, line: null },
          { key: "defaults.min_age_days", source_index: 2, line: 3 },
          { key: "defaults.stability", source_index: 0, line: null },
        ],
      }),
    );
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /^Policy/i }));
    expect(screen.getByText("Policy sources")).toBeInTheDocument();
    // Merge-order list renders each contributor.
    expect(screen.getByText("built-in default")).toBeInTheDocument();
    expect(screen.getByText("/repo/.packguard.yml")).toBeInTheDocument();
    expect(
      screen.getByText("/repo/front/vesta/.packguard.yml"),
    ).toBeInTheDocument();
    // Per-key provenance column points at the right source + line.
    expect(
      screen.getByText(/from \/repo\/\.packguard\.yml:L4/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/from \/repo\/front\/vesta\/\.packguard\.yml:L3/),
    ).toBeInTheDocument();
  });

  it("renders the three-axis offset cascade in the Policy tab", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /^Policy/i }));
    // Three axis labels.
    expect(screen.getByText("major")).toBeInTheDocument();
    expect(screen.getByText("minor")).toBeInTheDocument();
    expect(screen.getByText("patch")).toBeInTheDocument();
    // Lex-bound trace is rendered one line per step.
    expect(screen.getByText("Cascade trace")).toBeInTheDocument();
    expect(
      screen.getByText(/offset\.major=-1 → \(4, ∞, ∞\)/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/max version ≤ bound = 4\.17\.21/i),
    ).toBeInTheDocument();
  });

  it("defers the changelog to a later phase but still renders the tab", async () => {
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Changelog/i }));
    expect(
      screen.getByText(/Inline changelog lazy-fetch lands in Phase 6/i),
    ).toBeInTheDocument();
  });

  it("renders peer deps + engines + dependents on the Compatibility tab", async () => {
    // Polish-bis-3 regression: the dogfood reported "Used by (0)" on
    // lodash even though the backend had 5 dependents. Root cause was
    // Polish-bis-2 (ui defaulting to wrong path), not a UI bug — but we
    // still want a defensive Vitest that exercises the "≥5 dependents
    // render" path so a future field-rename or iteration bug gets
    // caught before shipping.
    (api.packageCompat as ReturnType<typeof vi.fn>).mockResolvedValue({
      ecosystem: "npm",
      name: "lodash",
      installed: "4.17.20",
      rows: [
        {
          version: "4.17.20",
          engines: { node: ">=14" },
          peer_deps: {
            react: { range: "^18", optional: false },
            tslib: { range: "*", optional: true },
          },
        },
      ],
      dependents: [
        {
          ecosystem: "npm",
          name: "@acme/host-app",
          version: "2026.4.16",
          range: "4.17.23",
          kind: "runtime",
          workspace: "/tmp/workspace-a",
        },
        {
          ecosystem: "npm",
          name: "@textlint/linter-formatter",
          version: "15.5.2",
          range: "4.17.23",
          kind: "runtime",
          workspace: "/tmp/workspace-a",
        },
        {
          ecosystem: "npm",
          name: "@visx/responsive",
          version: "3.12.0",
          range: "4.17.23",
          kind: "runtime",
          workspace: "/tmp/workspace-a",
        },
        {
          ecosystem: "npm",
          name: "@visx/shape",
          version: "3.12.0",
          range: "4.17.23",
          kind: "runtime",
          workspace: "/tmp/workspace-a",
        },
        {
          ecosystem: "npm",
          name: "@visx/text",
          version: "3.12.0",
          range: "4.17.23",
          kind: "runtime",
          workspace: "/tmp/workspace-a",
        },
      ],
    });
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Compatibility/i }));
    // peer deps with status glyphs
    expect(await screen.findByText(/react/)).toBeInTheDocument();
    expect(screen.getByText(/required · see graph/i)).toBeInTheDocument();
    expect(screen.getAllByText(/optional/i).length).toBeGreaterThan(0);
    // engines
    expect(screen.getByText("node")).toBeInTheDocument();
    expect(screen.getByText(">=14")).toBeInTheDocument();
    // Every one of the 5 dependents must land in the DOM — not just the
    // header count. Pre-Polish-bis-3 the dogfood saw "Used by (0)"
    // despite a populated API response.
    const expectedDeps = [
      "@acme/host-app",
      "@textlint/linter-formatter",
      "@visx/responsive",
      "@visx/shape",
      "@visx/text",
    ];
    for (const name of expectedDeps) {
      expect(screen.getByText(name)).toBeInTheDocument();
    }
    // Section header reflects the real length.
    expect(screen.getByText(/Used by/i)).toBeInTheDocument();
    expect(screen.getByText(/\(5\)/)).toBeInTheDocument();
    // deep link to graph
    const graphLink = screen.getByRole("link", { name: /Open in graph/i });
    expect(graphLink.getAttribute("href")).toContain("/graph?focus=");
  });

  it("shows a graceful notice when no compat row matches the installed version", async () => {
    (api.packageCompat as ReturnType<typeof vi.fn>).mockResolvedValue({
      ecosystem: "npm",
      name: "lodash",
      installed: "4.17.20",
      rows: [],
      dependents: [],
    });
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Compatibility/i }));
    // Polish-bis-4: "no rows at all" → honest "this package doesn't
    // declare..." banner rather than a generic "metadata missing"
    // message that users read as a parser failure.
    expect(
      await screen.findByText(/doesn.t declare any peer dependencies/i),
    ).toBeInTheDocument();
  });

  it("disambiguates 'installed row missing' from 'package has no metadata'", async () => {
    // When rows exist but none match `installed`, the amber notice
    // should call that out — it's the 'rescan' hint path, not the
    // 'package ships no metadata' path.
    (api.packageCompat as ReturnType<typeof vi.fn>).mockResolvedValue({
      ecosystem: "npm",
      name: "lodash",
      installed: "4.17.20",
      rows: [
        {
          version: "4.17.21",
          engines: { node: ">=14" },
          peer_deps: {},
        },
      ],
      dependents: [],
    });
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Compatibility/i }));
    expect(
      await screen.findByText(/No compatibility metadata for the installed version/i),
    ).toBeInTheDocument();
  });

  it("groups 'Used by' by workspace and shows a per-workspace parent count", async () => {
    // Phase 7b: each dependent is tagged with the repo it came from so
    // the UI can explain "this package is pulled in by X in workspace A
    // and Y in workspace B" — the aggregate-only view pre-7b hid that.
    (api.packageCompat as ReturnType<typeof vi.fn>).mockResolvedValue({
      ecosystem: "npm",
      name: "lodash",
      installed: "4.17.20",
      rows: [],
      dependents: [
        {
          ecosystem: "npm",
          name: "alpha-parent",
          version: "1.0.0",
          range: "^4",
          kind: "runtime",
          workspace: "/repos/alpha",
        },
        {
          ecosystem: "npm",
          name: "alpha-parent-2",
          version: "1.0.0",
          range: "^4",
          kind: "runtime",
          workspace: "/repos/alpha",
        },
        {
          ecosystem: "npm",
          name: "beta-parent",
          version: "2.0.0",
          range: "^4",
          kind: "dev",
          workspace: "/repos/beta",
        },
      ],
    });
    wrap(fixture());
    const user = userEvent.setup();
    await screen.findByText("lodash");
    await user.click(screen.getByRole("button", { name: /Compatibility/i }));
    // Section header reflects workspace count.
    expect(
      await screen.findByText(/Used by · 2 workspaces/i),
    ).toBeInTheDocument();
    // Both workspace group badges render with the tail segment.
    expect(screen.getByTestId("used-by-group-/repos/alpha")).toBeInTheDocument();
    expect(screen.getByTestId("used-by-group-/repos/beta")).toBeInTheDocument();
    // Group summary reports the per-workspace parent count.
    expect(screen.getByText(/2 parents/)).toBeInTheDocument();
    expect(screen.getByText(/1 parent\b/)).toBeInTheDocument();
  });
});
