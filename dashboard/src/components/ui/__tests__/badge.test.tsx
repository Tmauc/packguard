import { render, screen } from "@testing-library/react";
import { Badge } from "@/components/ui/badge";

describe("Badge", () => {
  it("renders the label", () => {
    render(<Badge>compliant</Badge>);
    expect(screen.getByText("compliant")).toBeInTheDocument();
  });

  it("applies the requested tone classes", () => {
    render(<Badge tone="cve">2 CVEs</Badge>);
    const node = screen.getByText("2 CVEs");
    expect(node.className).toMatch(/bg-orange/);
    expect(node.className).toMatch(/text-orange/);
  });
});
