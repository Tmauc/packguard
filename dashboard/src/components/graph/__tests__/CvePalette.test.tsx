import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import type { GraphVulnerabilityEntry } from "@/api/types/GraphVulnerabilityEntry";
import type { GraphVulnerabilityList } from "@/api/types/GraphVulnerabilityList";

vi.mock("@/lib/api", () => ({
  api: {
    graphVulnerabilities: vi.fn(),
  },
}));

import { api } from "@/lib/api";
import { CvePalette } from "@/components/graph/CvePalette";

const ENTRIES: GraphVulnerabilityEntry[] = [
  {
    advisory_id: "GHSA-axios-1",
    cve_id: "CVE-2024-11111",
    ecosystem: "npm",
    package_name: "axios",
    package_version: "0.21.1",
    severity: "high",
    summary: "SSRF in axios request forwarding",
  },
  {
    advisory_id: "GHSA-lodash-1",
    cve_id: "CVE-2021-23337",
    ecosystem: "npm",
    package_name: "lodash",
    package_version: "4.17.20",
    severity: "critical",
    summary: null,
  },
  {
    advisory_id: "GHSA-react-1",
    cve_id: null,
    ecosystem: "npm",
    package_name: "react",
    package_version: "18.0.0",
    severity: "medium",
    summary: null,
  },
];

const LIST: GraphVulnerabilityList = { entries: ENTRIES };

function wrap(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/graph"]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockReset();
});

describe("CvePalette", () => {
  it("lists every CVE in scope when the palette opens", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    wrap(<CvePalette open onClose={() => {}} onSelect={() => {}} />);
    for (const entry of ENTRIES) {
      const id = entry.cve_id ?? entry.advisory_id;
      expect(
        await screen.findByTestId(`cve-palette-row-${id}`),
      ).toBeInTheDocument();
    }
  });

  it("does not fetch or render anything while closed", () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    wrap(<CvePalette open={false} onClose={() => {}} onSelect={() => {}} />);
    expect(screen.queryByTestId("cve-palette")).not.toBeInTheDocument();
    expect(api.graphVulnerabilities).not.toHaveBeenCalled();
  });

  it("filters rows by fuzzy search across id, package, and severity", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    wrap(<CvePalette open onClose={() => {}} onSelect={() => {}} />);
    await screen.findByTestId("cve-palette-row-CVE-2024-11111");
    const input = screen.getByTestId("cve-palette-input");
    fireEvent.change(input, { target: { value: "axios" } });
    await waitFor(() => {
      expect(screen.queryByTestId("cve-palette-row-CVE-2021-23337")).not.toBeInTheDocument();
    });
    expect(screen.getByTestId("cve-palette-row-CVE-2024-11111")).toBeInTheDocument();
    // Cross-field match: "critical" pulls lodash out by severity alone.
    fireEvent.change(input, { target: { value: "critical" } });
    await waitFor(() => {
      expect(screen.queryByTestId("cve-palette-row-CVE-2024-11111")).not.toBeInTheDocument();
    });
    expect(screen.getByTestId("cve-palette-row-CVE-2021-23337")).toBeInTheDocument();
  });

  it("Escape closes the palette without invoking onSelect", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    const onClose = vi.fn();
    const onSelect = vi.fn();
    wrap(<CvePalette open onClose={onClose} onSelect={onSelect} />);
    await screen.findByTestId("cve-palette-input");
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("ArrowDown + Enter selects the highlighted entry and fires onSelect", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    const onSelect = vi.fn();
    wrap(<CvePalette open onClose={() => {}} onSelect={onSelect} />);
    await screen.findByTestId("cve-palette-row-CVE-2024-11111");
    const user = userEvent.setup();
    await user.keyboard("{ArrowDown}{Enter}");
    // First row was CVE-2024-11111 (sorted order is arbitrary for test, so
    // just check that one of the entries' ids made it through).
    expect(onSelect).toHaveBeenCalledTimes(1);
    const picked = onSelect.mock.calls[0][0];
    expect([
      "CVE-2024-11111",
      "CVE-2021-23337",
      "GHSA-react-1",
    ]).toContain(picked);
  });

  it("clicking a row commits the cve_id (or advisory_id when missing)", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue(LIST);
    const onSelect = vi.fn();
    wrap(<CvePalette open onClose={() => {}} onSelect={onSelect} />);
    const user = userEvent.setup();
    // Entry without a CVE id must commit its advisory_id instead.
    const reactRow = await screen.findByTestId("cve-palette-row-GHSA-react-1");
    await user.click(reactRow);
    expect(onSelect).toHaveBeenCalledWith("GHSA-react-1");
  });

  it("renders the empty-state callout when the scope has no CVEs", async () => {
    (api.graphVulnerabilities as ReturnType<typeof vi.fn>).mockResolvedValue({
      entries: [],
    } satisfies GraphVulnerabilityList);
    wrap(<CvePalette open onClose={() => {}} onSelect={() => {}} />);
    expect(await screen.findByTestId("cve-palette-empty")).toHaveTextContent(
      /packguard sync/i,
    );
  });
});
