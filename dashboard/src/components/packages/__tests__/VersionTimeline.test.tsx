import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VersionTimeline } from "@/components/packages/VersionTimeline";
import type { VersionRow } from "@/api/types/VersionRow";
import type { MalwareEntry } from "@/api/types/MalwareEntry";

function row(
  version: string,
  iso: string | null,
  extra: Partial<VersionRow> = {},
): VersionRow {
  return {
    version,
    published_at: iso,
    deprecated: false,
    yanked: false,
    severity: null,
    ...extra,
  };
}

/// Deterministic, evenly-spaced dates so clustering stays reproducible.
function fakeDates(count: number, startYear = 2018): string[] {
  const step = (365 * 24 * 60 * 60 * 1000) / 6; // ~2 months apart
  const base = Date.UTC(startYear, 0, 1);
  return Array.from({ length: count }, (_, i) =>
    new Date(base + i * step).toISOString(),
  );
}

describe("VersionTimeline", () => {
  it("renders in full mode when the release list fits under the threshold", () => {
    const dates = fakeDates(6);
    const versions = dates.map((d, i) => row(`1.${i}.0`, d));
    render(<VersionTimeline versions={versions} />);
    const svg = screen.getByTestId("version-timeline");
    expect(svg.getAttribute("data-mode")).toBe("full");
    expect(svg.getAttribute("aria-label")).toMatch(/6 versions/);
    expect(svg.getAttribute("aria-label")).not.toMatch(/clusters/);
  });

  it("switches to clustered mode once the release list crosses 200", () => {
    const dates = fakeDates(260);
    const versions = dates.map((d, i) => row(`1.${i}.0`, d));
    render(<VersionTimeline versions={versions} />);
    const svg = screen.getByTestId("version-timeline");
    expect(svg.getAttribute("data-mode")).toBe("clustered");
    expect(svg.getAttribute("aria-label")).toMatch(/clusters/);
  });

  it("zooms into a cluster when clicked and exposes a reset affordance", async () => {
    const dates = fakeDates(260);
    const versions = dates.map((d, i) => row(`1.${i}.0`, d));
    render(<VersionTimeline versions={versions} />);
    const svg = screen.getByTestId("version-timeline");
    expect(svg.getAttribute("data-mode")).toBe("clustered");
    // Each cluster marker is a <g style="cursor: pointer"> with a +N label.
    const clusterLabel = screen.getAllByText(/^\+\d+$/)[0];
    const clusterGroup = clusterLabel.closest("g");
    expect(clusterGroup).not.toBeNull();

    const user = userEvent.setup();
    await user.click(clusterGroup!);
    // After zoom the Reset button shows up. We can't assert the mode flipped
    // because the cluster might still exceed 200 markers depending on the
    // bucket split — the Reset button is the user-visible contract.
    expect(
      screen.getByRole("button", { name: /Reset zoom/i }),
    ).toBeInTheDocument();
  });

  it("colours a version as malware when the report targets that version", () => {
    const versions = [
      row("1.0.0", "2024-01-01T00:00:00Z"),
      row("1.0.1", "2024-02-01T00:00:00Z"),
    ];
    const malware: MalwareEntry[] = [
      {
        source: "osv-mal",
        ref_id: "MAL-1",
        kind: "malware",
        version: "1.0.1",
        summary: null,
        url: null,
        reported_at: null,
      },
    ];
    const { container } = render(
      <VersionTimeline versions={versions} malware={malware} />,
    );
    // Two circles drawn (one per version). One should carry the malware fill.
    const circles = container.querySelectorAll("circle");
    const fills = Array.from(circles).map((c) => c.getAttribute("fill"));
    expect(fills).toContain("#a855f7");
  });

  it("draws the reset button only after zoom, not on first render", () => {
    const versions = fakeDates(6).map((d, i) => row(`1.${i}.0`, d));
    render(<VersionTimeline versions={versions} />);
    expect(
      screen.queryByRole("button", { name: /Reset zoom/i }),
    ).not.toBeInTheDocument();
  });

  it("falls back to an empty-state when no versions have published dates", () => {
    const versions = [row("1.0.0", null)];
    render(<VersionTimeline versions={versions} />);
    expect(
      screen.getByText(/No published dates on file/i),
    ).toBeInTheDocument();
  });
});
