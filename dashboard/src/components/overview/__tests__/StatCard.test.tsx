import { render, screen } from "@testing-library/react";
import { StatCard } from "@/components/overview/StatCard";

describe("StatCard", () => {
  it("renders label, value, and sub", () => {
    render(<StatCard label="Health score" value="92%" sub="3 ecosystems" />);
    expect(screen.getByText("Health score")).toBeInTheDocument();
    expect(screen.getByText("92%")).toBeInTheDocument();
    expect(screen.getByText("3 ecosystems")).toBeInTheDocument();
  });

  it("applies tone-specific styling to the value", () => {
    render(<StatCard label="CVE matches" value={4} tone="bad" />);
    const value = screen.getByTestId("stat-value");
    expect(value.className).toMatch(/text-red/);
  });

  it("uses neutral tone by default", () => {
    render(<StatCard label="Packages" value={120} />);
    const value = screen.getByTestId("stat-value");
    expect(value.className).toMatch(/text-zinc-900/);
  });
});
