import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useSearchParams } from "react-router-dom";
import { vi } from "vitest";
import { PackagesPage } from "@/pages/Packages";
import type { PackagesPage as PackagesPageDTO } from "@/api/types/PackagesPage";

vi.mock("@/lib/api", () => ({ api: { packages: vi.fn() } }));

import { api } from "@/lib/api";

function wrap(initialEntries: string[] = ["/packages"]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/packages" element={<PackagesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fixture(rows: PackagesPageDTO["rows"]): PackagesPageDTO {
  return { total: rows.length, page: 1, per_page: 50, rows };
}

beforeEach(() => {
  (api.packages as ReturnType<typeof vi.fn>).mockReset();
});

describe("PackagesPage", () => {
  it("renders rows from the API call", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(
      fixture([
        {
          ecosystem: "npm",
          name: "lodash",
          installed: "4.17.20",
          latest: "4.17.21",
          kind: "dep",
          compliance: "cve-violation",
          risk: {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            malware_confirmed: 0,
            typosquat_suspects: 0,
          },
          last_scanned_at: null,
        },
      ]),
    );
    wrap();
    expect(await screen.findByText("lodash")).toBeInTheDocument();
    expect(screen.getByText("cve-violation")).toBeInTheDocument();
    expect(screen.getByText("1🟠")).toBeInTheDocument();
  });

  it("propagates filter changes into the URL", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(fixture([]));
    wrap();
    const user = userEvent.setup();
    const ecoSelect = await screen.findByLabelText(/Ecosystem/i);
    await user.selectOptions(ecoSelect, "npm");
    await waitFor(() => {
      expect(api.packages).toHaveBeenLastCalledWith(
        expect.objectContaining({ ecosystem: "npm", page: 1 }),
        undefined,
      );
    });
  });

  it("toggles the malware chip into the query", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(fixture([]));
    wrap();
    const user = userEvent.setup();
    const malwareChip = await screen.findByRole("button", { name: /Has malware/i });
    await user.click(malwareChip);
    await waitFor(() => {
      expect(api.packages).toHaveBeenLastCalledWith(
        expect.objectContaining({ has_malware: true }),
        undefined,
      );
    });
  });

  it("hydrates filters from the initial URL", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(fixture([]));
    wrap(["/packages?ecosystem=pypi&status=cve-violation&page=2"]);
    await waitFor(() => {
      expect(api.packages).toHaveBeenLastCalledWith(
        expect.objectContaining({
          ecosystem: "pypi",
          status: "cve-violation",
          page: 2,
        }),
        undefined,
      );
    });
  });

  it("threads the workspace scope into the API call", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(fixture([]));
    wrap(["/packages?project=/tmp/repo-a"]);
    await waitFor(() => {
      expect(api.packages).toHaveBeenLastCalledWith(
        expect.any(Object),
        "/tmp/repo-a",
      );
    });
  });

  it("shows the empty-state copy when no rows match", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(fixture([]));
    wrap();
    expect(
      await screen.findByText(/No packages match the current filters/i),
    ).toBeInTheDocument();
  });

  it("routes insufficient rows to the Policy eval cascade anchor", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(
      fixture([
        {
          ecosystem: "pypi",
          name: "aiohttp",
          installed: "3.10.11",
          latest: "3.11.14",
          kind: "dep",
          compliance: "insufficient",
          risk: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            malware_confirmed: 0,
            typosquat_suspects: 0,
          },
          last_scanned_at: null,
        },
      ]),
    );
    wrap();
    const badge = await screen.findByText("insufficient");
    // Tooltip text explains the verdict without having to open the tab.
    expect(badge.getAttribute("title")).toMatch(
      /no release satisfies.*offset bound/i,
    );
    const link = badge.closest("a");
    expect(link).not.toBeNull();
    expect(link?.getAttribute("href")).toBe(
      "/packages/pypi/aiohttp?tab=policy#cascade",
    );
  });

  it("renders tooltips on the Compliance and Risk column headers", async () => {
    (api.packages as ReturnType<typeof vi.fn>).mockResolvedValue(
      fixture([
        {
          ecosystem: "npm",
          name: "lodash",
          installed: "4.17.20",
          latest: "4.17.21",
          kind: "dep",
          compliance: "compliant",
          risk: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            malware_confirmed: 0,
            typosquat_suspects: 0,
          },
          last_scanned_at: null,
        },
      ]),
    );
    wrap();
    const compliance = await screen.findByText("Compliance");
    const risk = screen.getByText("Risk");
    expect(compliance.closest("th")?.getAttribute("title")).toMatch(
      /compliant.*insufficient/i,
    );
    expect(risk.closest("th")?.getAttribute("title")).toMatch(
      /critical.*malware/i,
    );
  });
});

// Tiny sanity check on useSearchParams usage so the test infra itself
// doesn't silently regress (catches the case where a future router upgrade
// breaks initial-entries hydration).
describe("router test infra", () => {
  function ReadParam() {
    const [params] = useSearchParams();
    return <div>got:{params.get("ecosystem")}</div>;
  }
  it("hydrates search params from MemoryRouter initialEntries", () => {
    render(
      <MemoryRouter initialEntries={["/?ecosystem=npm"]}>
        <Routes>
          <Route path="/" element={<ReadParam />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("got:npm")).toBeInTheDocument();
  });
});
